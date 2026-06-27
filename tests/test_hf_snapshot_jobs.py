import sys
import types
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_hf_snapshot_job_archives_hashes_persists_and_cleans_tmpdir(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api.models import _register_hf_snapshot_job
    from aiaf.data.store import DataStore

    observed = {}

    def fake_snapshot_download(repo_id, token=None, cache_dir=None):
        observed["repo_id"] = repo_id
        observed["token"] = token
        observed["cache_dir"] = cache_dir
        snapshot_dir = Path(cache_dir) / "models--acme--tiny" / "snapshots" / "abc123"
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "config.json").write_text('{"model_type": "tiny"}', encoding="utf-8")
        (snapshot_dir / "weights.bin").write_bytes(b"tiny weights")
        (snapshot_dir / "requirements.txt").write_text(
            "transformers==4.40.0\ntorch>=2.3\n", encoding="utf-8"
        )
        return str(snapshot_dir)

    monkeypatch.setitem(
        sys.modules,
        "huggingface_hub",
        types.SimpleNamespace(snapshot_download=fake_snapshot_download),
    )
    monkeypatch.setenv("HF_TOKEN", "test-token")

    store = DataStore(db_path=str(tmp_path / "aiaf.db"))
    job_id = store.create_job()

    _register_hf_snapshot_job(
        store,
        job_id,
        "https://huggingface.co/acme/tiny/tree/main",
        "security-team",
    )

    job = store.get_job(job_id)
    assert job["status"] == "COMPLETED"
    assert job["result"]["repo_id"] == "acme/tiny"
    assert len(job["result"]["sha256"]) == 64

    assert observed["repo_id"] == "acme/tiny"
    assert observed["token"] == "test-token"
    assert observed["cache_dir"] is not None
    assert not Path(observed["cache_dir"]).exists()

    model = store.get_model(job["result"]["model_id"])
    assert model["source"] == "huggingface"
    assert model["source_url"] == "https://huggingface.co/acme/tiny/tree/main"
    assert model["registered_by"] == "security-team"
    assert model["metadata"]["artifact_kind"] == "huggingface_snapshot_archive"
    assert model["metadata"]["archive_format"] == "gztar"
    assert model["metadata"]["repo_id"] == "acme/tiny"
    assert model["dependency_discovery"]["manifest_paths"] == ["requirements.txt"]
    # Only exact coordinates enter the matched inventory; the torch>=2.3 range is
    # preserved as unresolved discovery coverage rather than scanned as exact.
    assert {item["name"] for item in model["dependencies"]} == {"transformers"}
    assert model["dependency_discovery"]["unresolved_dependency_count"] >= 1
    assert model["vulnerability_scan"]["status"] == "NO_ADVISORY_DATA"

    store.close()

import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _model_record():
    return {
        "model_id": "model-attested-1",
        "model_name": "attested-model",
        "version": "1.0",
        "source": "upload",
        "source_url": "https://example.test/model.bin",
        "publisher": "Example AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "dependencies": ["transformers==4.40.0"],
        "training_artifacts": [{"name": "dataset", "sha256": "b" * 64}],
        "deployment_pipeline": {"environment": "production"},
        "metadata": {},
    }


def test_dependency_discovery_reads_python_and_node_manifests(tmp_path):
    ensure_src()
    from aiaf.registry import discover_dependencies

    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\ntorch>=2.3\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"4.17.21"},"devDependencies":{"vitest":"^1.6.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests==2.31.0", "httpx==0.27.0"]\n',
        encoding="utf-8",
    )

    discovery = discover_dependencies(str(tmp_path))
    dependencies = {
        (item["ecosystem"], item["name"], item["version"])
        for item in discovery["dependencies"]
    }

    assert ("pypi", "requests", "==2.31.0") in dependencies
    assert ("pypi", "torch", ">=2.3") in dependencies
    assert ("pypi", "httpx", "==0.27.0") in dependencies
    assert ("npm", "lodash", "4.17.21") in dependencies
    assert discovery["dependency_count"] == 5
    assert discovery["manifests"] == ["package.json", "pyproject.toml", "requirements.txt"]


def test_dependency_discovery_uses_original_name_for_uploaded_manifest(tmp_path):
    ensure_src()
    from aiaf.registry import discover_dependencies

    upload = tmp_path / "upload-without-extension"
    upload.write_text("transformers==4.40.0\n", encoding="utf-8")

    discovery = discover_dependencies(str(upload), artifact_name="requirements.txt")

    assert discovery["dependencies"][0]["name"] == "transformers"
    assert discovery["manifests"] == ["requirements.txt"]


def test_dependency_merge_deduplicates_declared_and_discovered_records():
    ensure_src()
    from aiaf.registry import merge_dependencies

    merged = merge_dependencies(
        ["transformers==4.40.0"],
        [
            {"name": "transformers", "version": "==4.40.0", "ecosystem": "pypi"},
            {"name": "torch", "version": "==2.3.0", "ecosystem": "pypi"},
        ],
    )

    assert len(merged) == 2
    assert merged[0] == "transformers==4.40.0"


def test_provenance_attestation_detects_signature_and_model_tampering():
    ensure_src()
    from aiaf.registry import (
        create_provenance_attestation,
        verify_provenance_attestation,
    )

    model = _model_record()
    attestation = create_provenance_attestation(model, "test-signing-key", "test-key")

    verified = verify_provenance_attestation(
        attestation, "test-signing-key", expected_model=model
    )
    assert verified["verified"] is True
    assert all(verified["checks"].values())

    tampered = {**attestation, "signature": "0" * 64}
    assert verify_provenance_attestation(tampered, "test-signing-key")["verified"] is False

    changed_model = {**model, "sha256": "c" * 64}
    changed = verify_provenance_attestation(
        attestation, "test-signing-key", expected_model=changed_model
    )
    assert changed["verified"] is False
    assert changed["checks"]["artifact_hash_matches"] is False

    wrong_key_id = verify_provenance_attestation(
        attestation,
        "test-signing-key",
        expected_model=model,
        expected_key_id="different-key",
    )
    assert wrong_key_id["verified"] is False
    assert wrong_key_id["checks"]["key_id_matches"] is False


def test_attestation_api_persists_lists_and_verifies_evidence(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import models as models_api
    from aiaf.api.app import app
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "registry.db"))
    store.save_model(_model_record())
    monkeypatch.setattr(models_api, "get_store", lambda: store)
    # Schema-2 attestations require a >=32-byte signing key with sufficient entropy.
    monkeypatch.setenv("AIAF_ATTESTATION_KEY", "attestation-signing-key-0123456789abcdef")
    monkeypatch.setenv("AIAF_ATTESTATION_KEY_ID", "test-key")

    created = models_api.create_model_attestation(
        "model-attested-1", api_key="dev-key"
    )
    listed = models_api.list_model_attestations(
        "model-attested-1", api_key="dev-key"
    )
    verified = models_api.verify_model_attestation(
        "model-attested-1", created["attestation"], api_key="dev-key"
    )

    assert created["attestation"]["key_id"] == "test-key"
    assert len(listed["attestations"]) == 1
    assert verified["verified"] is True
    assert "/models/{model_id}/attestations" in app.openapi()["paths"]
    assert "/models/{model_id}/attestations/verify" in app.openapi()["paths"]
    store.close()

import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_registry_flow(tmp_path):
    ensure_src()
    from aiaf.data.store import DataStore
    from aiaf.registry import (
        ModelRecord,
        SourceTracker,
        assess_provenance_v2,
        calculate_sha256,
        determine_provenance_risk,
        generate_mbom,
        verify_model,
    )

    # create a small temp file to hash
    f = tmp_path / "model.bin"
    f.write_bytes(b"dummy-model-content")

    sha = calculate_sha256(str(f))
    assert isinstance(sha, str) and len(sha) == 64
    assert verify_model(str(f), sha)

    tracker = SourceTracker()
    meta = tracker.capture_source("https://huggingface.co/meta-llama/Llama-3-8B")
    assert meta["provider"] == "huggingface"

    rec = ModelRecord.create(
        model_name="Llama-3-8B",
        version="1.0",
        source=meta["provider"],
        source_url=meta["source_url"],
        sha256=sha,
        publisher="Meta",
        license="llama3",
        dependencies=["transformers==4.40.0", "torch==2.3.0"],
        training_artifacts=[
            {
                "name": "public-pretraining-corpus",
                "source_url": "https://example.test/data/corpus.jsonl",
                "sha256": "f" * 64,
            }
        ],
        deployment_pipeline={
            "environment": "staging",
            "artifact_ref": "registry.example.test/llama@sha256:abc",
            "approval_gate": "CAB-999",
        },
    )

    assessment = assess_provenance_v2(rec.to_dict())
    score = int(round(assessment["provenance_score"]))
    risk = assessment["risk_level"]
    assert risk == determine_provenance_risk(score)
    assert 0 <= score <= 100

    ds = DataStore(db_path=str(tmp_path / "aiaf.db"))
    recd = rec.to_dict()
    recd["provenance_score"] = score
    recd["risk_level"] = risk
    ds.save_model(recd)
    stored = ds.get_model(rec.model_id)
    assert stored["dependencies"] == ["transformers==4.40.0", "torch==2.3.0"]
    assert stored["training_artifacts"][0]["name"] == "public-pretraining-corpus"
    assert stored["deployment_pipeline"]["approval_gate"] == "CAB-999"

    mbom = generate_mbom(stored)
    assert mbom["model_name"] == "Llama-3-8B"
    assert mbom["dependencies"] == ["transformers==4.40.0", "torch==2.3.0"]
    assert mbom["training_artifacts"][0]["sha256"] == "f" * 64
    assert mbom["deployment_pipeline"]["environment"] == "staging"
    assert mbom["bom_format"] == "AIAF AI-BOM"
    assert mbom["spec_version"] == "1.0"
    assert mbom["model_id"] == rec.model_id
    ds.close()


def test_registration_metadata_parses_supply_chain_fields():
    ensure_src()
    from aiaf.api.models import _registration_metadata

    metadata = _registration_metadata(
        publisher="Acme AI",
        license="apache-2.0",
        dependencies="transformers==4.40.0\ntorch==2.3.0",
        training_artifacts='[{"name": "dataset-a", "source_url": "https://example.test/data.jsonl", "sha256": "a"}]',
        deployment_pipeline='{"environment": "prod", "artifact_ref": "registry.example.test/acme/tiny@sha256:abc", "approval_gate": "CAB-1"}',
        version="2.0",
    )

    assert metadata["publisher"] == "Acme AI"
    assert metadata["dependencies"] == ["transformers==4.40.0", "torch==2.3.0"]
    assert metadata["training_artifacts"][0]["name"] == "dataset-a"
    assert metadata["deployment_pipeline"]["approval_gate"] == "CAB-1"
    assert metadata["version"] == "2.0"

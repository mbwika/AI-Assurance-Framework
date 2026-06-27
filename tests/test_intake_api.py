import sys
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _register_url_only_model(store, tmp_path, **metadata):
    """Register a model the way the API does, from a file + source URL."""
    from aiaf.api import models as models_api

    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"fake-model-weights")
    rec = models_api._register_from_file(
        str(artifact),
        "https://huggingface.co/acme/demo-model",
        registered_by="tester",
        metadata=metadata,
        artifact_name="model.bin",
    )
    models_api._save_registered_model(store, rec)
    return rec


def test_registration_records_origin_tagged_evidence_ledger(tmp_path):
    ensure_src()
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    rec = _register_url_only_model(store, tmp_path, publisher="ACME")

    ledger = rec.metadata["evidence_ledger"]
    by_name = {f["name"]: f for f in ledger}
    # The SHA-256 AIAF computed is locally observed; operator inputs are user-entered.
    assert by_name["sha256"]["origin"] == "locally_observed"
    assert by_name["source_url"]["origin"] == "user_entered"
    assert by_name["publisher"]["origin"] == "user_entered"


def test_triage_returns_conservative_verdict_for_url_only_model(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")

    out = intake_api.triage_model(
        TriageRequest(model_id=rec.model_id), api_key="dev-key"
    )

    # An unknown model whose only identity evidence is operator-typed cannot earn
    # a clean approval.
    assert out["verdict"] in {
        "DO_NOT_APPROVE",
        "INSUFFICIENT_EVIDENCE",
        "PILOT_ONLY",
    }
    assert out["verdict"] != "APPROVE_FOR_SCOPED_USE"
    assert out["evidence_gaps"], "expected explicit evidence gaps"
    # Evidence origins flow through to the verdict's summary.
    summary = out["evidence_origin_summary"]
    assert "user_entered" in summary
    assert "locally_observed" in summary
    assert out["scoring_version"]
    assert out["unknown_model_assurance"]["model_id"] == rec.model_id
    assert out["unknown_model_assurance"]["artifact_identity"]["source_url"] == rec.source_url
    assert out["unknown_model_assurance"]["evidence_gaps"]
    assert out["unknown_model_probe"]["status"]
    assert out["unknown_model_assurance"]["unknown_model_probe"]["status"] == out["unknown_model_probe"]["status"]


def test_latest_recommendation_persists_and_is_retrievable(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    triaged = intake_api.triage_model(
        TriageRequest(model_id=rec.model_id, persist=True), api_key="dev-key"
    )

    latest = intake_api.latest_recommendation(rec.model_id, api_key="dev-key")
    assert latest["verdict"] == triaged["verdict"]
    assert latest["model_id"] == rec.model_id
    assert latest["unknown_model_assurance"]["model_id"] == rec.model_id
    assert latest["unknown_model_probe"]["status"] == triaged["unknown_model_probe"]["status"]


def test_model_assurance_endpoint_returns_persisted_unknown_model_assurance(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    intake_api.triage_model(
        TriageRequest(model_id=rec.model_id, persist=True), api_key="dev-key"
    )

    payload = models_api.get_unknown_model_assurance(rec.model_id, api_key="dev-key")
    assert payload["model_id"] == rec.model_id
    assert payload["unknown_model_assurance"]["artifact_identity"]["source_url"] == rec.source_url
    assert payload["unknown_model_assurance"]["unknown_model_probe"]["status"]


def test_latest_recommendation_404_before_triage(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    with pytest.raises(HTTPException) as exc:
        intake_api.latest_recommendation(rec.model_id, api_key="dev-key")
    assert exc.value.status_code == 404


def test_triage_404_for_unknown_model(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import intake as intake_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)

    with pytest.raises(HTTPException) as exc:
        intake_api.triage_model(TriageRequest(model_id="nope"), api_key="dev-key")
    assert exc.value.status_code == 404


def test_triage_policy_context_flows_into_response(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    out = intake_api.triage_model(
        TriageRequest(
            model_id=rec.model_id,
            policy_context={
                "use_case": "healthcare",
                "data_classification": "phi",
                "deployment_exposure": "public",
            },
        ),
        api_key="dev-key",
    )

    assert out["policy"]["context"]["use_case"] == "healthcare"
    assert out["policy"]["context"]["data_classification"] == "phi"
    assert out["policy"]["context"]["deployment_exposure"] == "public"
    assert "behavioral_probes" in out["policy"]["missing_required_evidence"]


def test_triage_passes_endpoint_context_into_unknown_model_probe(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    captured = {}

    def fake_run_probes(*args, **kwargs):
        return {
            "status": "COMPLETED",
            "probe_failures": 0,
            "probes_run": 0,
            "probe_results": [],
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_category": {},
            "assessment_complete": True,
            "summary": {},
        }

    def fake_unknown_probe(model_record, **kwargs):
        captured.update(kwargs)
        return {
            "probe_version": "test",
            "status": "CLEAR",
            "finding_count": 0,
            "findings": [],
            "evidence_available": {},
            "runtime_probes": {"status": "COMPLETED", "probe_results": [], "triggered_count": 0},
            "probed_at": "2026-06-23T00:00:00Z",
        }

    monkeypatch.setattr(intake_api, "run_probes", fake_run_probes)
    monkeypatch.setattr(intake_api, "probe_unknown_model", fake_unknown_probe)

    intake_api.triage_model(
        TriageRequest(
            model_id=rec.model_id,
            endpoint_url="http://localhost:11434",
            endpoint_api_key="secret-token",
            endpoint_model_name="demo-model",
        ),
        api_key="dev-key",
    )

    assert captured["endpoint_url"] == "http://localhost:11434"
    assert captured["endpoint_api_key"] == "secret-token"
    assert captured["endpoint_model_name"] == "demo-model"


def test_triage_ignores_weight_paths_outside_approved_roots(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import intake as intake_api
    from aiaf.api import models as models_api
    from aiaf.api.intake import TriageRequest
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "intake.db"))
    monkeypatch.setattr(intake_api, "get_store", lambda: store)
    monkeypatch.setattr(models_api, "get_store", lambda: store)

    rec = _register_url_only_model(store, tmp_path, publisher="ACME")
    metadata = dict(rec.metadata)
    metadata["file_path"] = str(tmp_path / "outside-approved-roots.bin")
    rec.metadata = metadata
    store.save_model(rec.to_dict())

    out = intake_api.triage_model(
        TriageRequest(model_id=rec.model_id), api_key="dev-key"
    )

    assert out["unknown_model_assurance"]["model_id"] == rec.model_id
    refreshed = store.get_model(rec.model_id)
    assert "weight_inspection" not in (refreshed or {}).get("metadata", {})

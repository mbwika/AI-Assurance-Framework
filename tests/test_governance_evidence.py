import sys
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _submit(engine, **overrides):
    values = {
        "artifact_id": "model-1",
        "control_id": "AIAF-SC-002",
        "evidence_fields": ["sha256"],
        "evidence_type": "ATTESTATION",
        "reference": "s3://assurance/model-1/checksum.json",
        "sha256": "a" * 64,
        "submitted_by": "evidence-collector",
        "expires_at": "2099-01-01T00:00:00Z",
        "metadata": {"collector": "ci-pipeline"},
    }
    values.update(overrides)
    return engine.submit(**values)


def test_only_independently_approved_evidence_closes_control_gaps(tmp_path):
    ensure_src()
    from aiaf.core import GovernanceEngine, GovernanceEvidenceEngine, ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "evidence.db"))
    evidence_engine = GovernanceEvidenceEngine(store)
    evidence = _submit(evidence_engine)

    pending = GovernanceEngine(store).evaluate({"id": "model-1"})
    pending_control = next(
        control for control in pending["controls"] if control["id"] == "AIAF-SC-002"
    )
    assert pending_control["status"] == "missing"

    with pytest.raises(ValueError, match="cannot review their own"):
        evidence_engine.review(
            evidence["id"],
            decision="APPROVED",
            reviewer="evidence-collector",
            rationale="Self approval",
        )

    approved = evidence_engine.review(
        evidence["id"],
        decision="APPROVED",
        reviewer="independent-reviewer",
        rationale="Checksum attestation was independently verified.",
    )
    result = GovernanceEngine(store).evaluate({"id": "model-1"})
    control = next(
        item for item in result["controls"] if item["id"] == "AIAF-SC-002"
    )

    assert approved["status"] == "APPROVED"
    assert control["status"] == "satisfied"
    assert control["provided_evidence"] == ["sha256"]
    assert control["evidence_record_ids"] == [evidence["id"]]
    assert evidence["id"] in result["evidence"]["applied_evidence_ids"]
    compliance = ReportingEngine(store).compliance()
    matrix_control = next(
        item
        for item in compliance["frameworks"]["NIST AI RMF"]["control_evidence"]
        if item["control_id"] == "AIAF-SC-002"
    )
    assert matrix_control["evidence_record_ids"] == [evidence["id"]]
    assert store.list_audit_logs()[0]["event_type"] == "governance_evaluation"
    assert any(
        event["event_type"] == "control_evidence_reviewed"
        for event in store.list_audit_logs()
    )
    store.close()


def test_rejected_and_expired_evidence_do_not_count_as_assurance(tmp_path):
    ensure_src()
    from aiaf.core import GovernanceEvidenceEngine
    from aiaf.core.evidence_engine import approved_evidence, evidence_summary
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "evidence.db"))
    engine = GovernanceEvidenceEngine(store)
    rejected = _submit(engine)
    engine.review(
        rejected["id"],
        decision="REJECTED",
        reviewer="reviewer",
        rationale="Digest does not match the referenced artifact.",
    )
    expired = {
        **rejected,
        "id": "expired",
        "status": "APPROVED",
        "expires_at": "2026-01-01T00:00:00Z",
    }

    assert approved_evidence([expired, engine.get(rejected["id"])], "2026-06-18T00:00:00Z") == []
    summary = evidence_summary(
        [expired, engine.get(rejected["id"])], "2026-06-18T00:00:00Z"
    )
    assert summary["rejected_evidence"] == 1
    assert summary["expired_approved_evidence"] == 1

    with pytest.raises(ValueError, match="not valid"):
        _submit(engine, evidence_fields=["publisher"])
    with pytest.raises(ValueError, match="future"):
        _submit(engine, expires_at="2020-01-01T00:00:00Z")
    store.close()


def test_governance_evidence_reporting_and_api_workflow(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import governance as governance_api
    from aiaf.api.app import app
    from aiaf.core import GovernanceEvidenceEngine, ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "evidence.db"))
    monkeypatch.setattr(governance_api, "get_store", lambda: store)
    submitted = governance_api.submit_control_evidence(
        governance_api.EvidenceSubmission(
            artifact_id="model-api",
            control_id="AIAF-SC-002",
            evidence_fields=["sha256"],
            evidence_type="ATTESTATION",
            reference="https://evidence.test/model-api/checksum",
            sha256="b" * 64,
            submitted_by="collector",
            expires_at="2099-01-01T00:00:00Z",
        ),
        api_key="dev-key",
    )
    pending_report = ReportingEngine(store).assurance_report()
    alert_ids = {
        alert["id"] for alert in pending_report["monitoring_alerts"]["alerts"]
    }
    reviewed = governance_api.review_control_evidence(
        submitted["id"],
        governance_api.EvidenceReview(
            decision="APPROVED",
            reviewer="reviewer",
            rationale="Verified against immutable build output.",
        ),
        api_key="dev-key",
    )
    listed = governance_api.list_control_evidence(
        artifact_id="model-api", status="APPROVED", api_key="dev-key"
    )
    routes = set(app.openapi()["paths"])

    assert "control_evidence_pending_review" in alert_ids
    assert pending_report["evidence_inventory"]["control_evidence"] == 1
    assert reviewed["status"] == "APPROVED"
    assert listed["count"] == 1
    assert GovernanceEvidenceEngine(store).summary()["approved_evidence"] == 1
    assert "/v1/governance/evidence" in routes
    assert "/v1/governance/evidence/{evidence_id}" in routes
    assert "/v1/governance/evidence/{evidence_id}/review" in routes
    store.close()

import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _ledger(*facts):
    ensure_src()
    from aiaf.registry.evidence_origin import FactLedger

    ledger = FactLedger()
    for name, value, origin in facts:
        ledger.add(name, value, origin)
    return ledger.to_list()


def _model(ledger_facts):
    return {"model_id": "policy-m1", "metadata": {"evidence_ledger": ledger_facts}}


def _prov(risk_level="LOW", score=92, confidence=0.92, complete=True):
    return {
        "risk_level": risk_level,
        "provenance_score": score,
        "confidence": confidence,
        "assessment_complete": complete,
        "trust_caps": [],
    }


def _gov(gaps=None):
    return {"status": "PASS", "gaps": gaps or []}


def _vuln():
    return {
        "status": "NO_KNOWN_VULNERABILITIES",
        "by_severity": {},
        "assessment_complete": True,
        "match_count": 0,
        "unresolved_dependencies": [],
    }


def _serial_clean():
    return {
        "status": "CLEAN",
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "match_count": 0,
        "assessment_complete": True,
    }


def _probes_clean():
    return {
        "status": "COMPLETED",
        "probe_failures": 0,
        "probes_run": 8,
        "probe_results": [],
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "assessment_complete": True,
    }


def _verified_identity():
    from aiaf.registry.evidence_origin import EvidenceOrigin

    return _ledger(
        ("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED),
        ("source_url", "https://huggingface.co/acme/m", EvidenceOrigin.USER_ENTERED),
        ("provenance_attestation", "att-1", EvidenceOrigin.INDEPENDENTLY_VERIFIED),
    )


def test_policy_engine_requires_live_and_artifact_evidence_for_public_sensitive_use():
    ensure_src()
    from aiaf.core.org_policy_engine import evaluate_org_policy

    policy = evaluate_org_policy(
        _model(_verified_identity()),
        policy_context={
            "use_case": "healthcare",
            "data_classification": "phi",
            "deployment_exposure": "public",
        },
        provenance_assessment=_prov(),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
        serialization_scan=None,
        behavioral_probes=None,
    )

    assert policy["posture"]["level"] == "critical"
    assert "serialization_scan" in policy["missing_required_evidence"]
    assert "behavioral_probes" in policy["missing_required_evidence"]
    assert any(cap["verdict"] == "INSUFFICIENT_EVIDENCE" for cap in policy["caps"])


def test_policy_engine_emits_pilot_scope_for_critical_context():
    ensure_src()
    from aiaf.core.org_policy_engine import evaluate_org_policy

    policy = evaluate_org_policy(
        _model(_verified_identity()),
        policy_context={
            "use_case": "healthcare",
            "data_classification": "phi",
            "deployment_exposure": "public",
        },
        provenance_assessment=_prov(),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
        serialization_scan=_serial_clean(),
        behavioral_probes=_probes_clean(),
    )

    assert policy["approval_scope"]["allowed_exposure"] == "internal_pilot"
    assert policy["approval_scope"]["deployment_exposure"] == "public"
    assert any(cap["verdict"] == "APPROVE_WITH_CONDITIONS" for cap in policy["caps"])

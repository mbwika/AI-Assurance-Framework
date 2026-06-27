import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _ledger(*facts):
    """facts: tuples of (name, value, EvidenceOrigin)."""
    ensure_src()
    from aiaf.registry.evidence_origin import FactLedger

    ledger = FactLedger()
    for name, value, origin in facts:
        ledger.add(name, value, origin)
    return ledger.to_list()


def _model(ledger_facts):
    return {"model_id": "m1", "metadata": {"evidence_ledger": ledger_facts}}


def _risk(severity="LOW", score=0.0, findings=None, trust_level="HIGH",
          trust_score=90, trust_conf=0.85):
    findings = findings or []
    return {
        "score": score,
        "risk_aggregation": {"severity": severity, "finding_count": len(findings)},
        "findings": findings,
        "trustworthiness": {
            "level": trust_level,
            "trustworthiness_score": trust_score,
            "confidence": trust_conf,
        },
    }


def _prov(risk_level="LOW", score=90, confidence=0.85, complete=True, trust_caps=None):
    return {
        "risk_level": risk_level,
        "provenance_score": score,
        "confidence": confidence,
        "assessment_complete": complete,
        "trust_caps": trust_caps or [],
    }


def _gov(status="PASS", gaps=None):
    return {"status": status, "gaps": gaps or []}


def _vuln(status="NO_KNOWN_VULNERABILITIES", by_severity=None, complete=True,
          match_count=0, unresolved=None):
    return {
        "status": status,
        "by_severity": by_severity or {},
        "assessment_complete": complete,
        "match_count": match_count,
        "unresolved_dependencies": unresolved or [],
    }


def _verified_identity():
    from aiaf.registry.evidence_origin import EvidenceOrigin

    return _ledger(
        ("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED),
        ("source_url", "https://huggingface.co/acme/m", EvidenceOrigin.USER_ENTERED),
        ("provenance_attestation", "att-1", EvidenceOrigin.INDEPENDENTLY_VERIFIED),
    )


def _user_entered_identity():
    from aiaf.registry.evidence_origin import EvidenceOrigin

    return _ledger(
        ("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED),
        ("source_url", "https://huggingface.co/acme/m", EvidenceOrigin.USER_ENTERED),
        ("publisher", "ACME", EvidenceOrigin.USER_ENTERED),
    )


def test_active_high_severity_finding_blocks_adoption():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(
            severity="HIGH",
            score=7.0,
            findings=[{"type": "prompt_injection", "severity": "HIGH"}],
        ),
        provenance_assessment=_prov(),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "DO_NOT_APPROVE"
    assert any(r["category"] == "active_threat" for r in out["reasons"])


def test_critical_dependency_vulnerability_blocks_adoption():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(status="VULNERABLE", by_severity={"CRITICAL": 1}, match_count=1),
    )
    assert out["verdict"] == "DO_NOT_APPROVE"
    assert any(r["category"] == "dependency_vulnerability" for r in out["reasons"])


def test_incomplete_assessment_yields_insufficient_evidence():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(complete=False),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert out["evidence_gaps"]


def test_low_confidence_yields_insufficient_evidence():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(confidence=0.2),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_user_entered_identity_caps_at_pilot_only():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_user_entered_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(
            risk_level="HIGH",
            score=60,
            trust_caps=[{"gate": "no_verified_signed_provenance", "maximum_score": 75.0}],
        ),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "PILOT_ONLY"
    assert any(r["category"] == "identity_origin" for r in out["reasons"])
    # The weak identity reason carries the (weak) origin that produced it.
    origins = {r.get("origin") for r in out["reasons"]}
    assert "user_entered" in origins


def test_trust_caps_never_reach_scoped_approval():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_user_entered_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(
            risk_level="LOW",
            score=90,
            trust_caps=[{"gate": "no_verified_signed_provenance", "maximum_score": 75.0}],
        ),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] != "APPROVE_FOR_SCOPED_USE"


def test_governance_gaps_yield_approve_with_conditions():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(risk_level="MEDIUM", score=75),
        governance_summary=_gov(
            status="NEEDS_REVIEW",
            gaps=[{"id": "AIAF-RISK-001", "title": "Model risk eval", "missing_evidence": ["safety_eval"]}],
        ),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "APPROVE_WITH_CONDITIONS"
    assert out["conditions"]


def test_clean_evidence_with_verified_identity_is_scoped_approval():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(risk_level="LOW", score=92, confidence=0.9),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert out["verdict"] == "APPROVE_FOR_SCOPED_USE"
    assert out["reasons"] == []
    assert out["confidence"] > 0.0


def test_origin_weighting_verified_beats_user_entered():
    """Same model, stronger evidence origin -> a stronger (or equal) verdict."""
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    weak = recommend_adoption(
        _model(_user_entered_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(
            risk_level="HIGH", score=60,
            trust_caps=[{"gate": "no_verified_signed_provenance", "maximum_score": 75.0}],
        ),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    strong = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(risk_level="LOW", score=92, confidence=0.9),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
    )
    assert strong["verdict_rank"] > weak["verdict_rank"]


def test_phase4_public_sensitive_context_requires_more_evidence():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(risk_level="LOW", score=92, confidence=0.9),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
        policy_context={
            "use_case": "healthcare",
            "data_classification": "phi",
            "deployment_exposure": "public",
        },
    )
    assert out["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert out["policy"]["posture"]["level"] == "critical"
    assert "behavioral_probes" in out["policy"]["missing_required_evidence"]
    assert any(r["category"] == "org_policy" for r in out["reasons"])


def test_phase4_critical_context_with_required_evidence_stays_conditioned():
    ensure_src()
    from aiaf.core.adoption_engine import recommend_adoption

    serial = {
        "status": "CLEAN",
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "match_count": 0,
        "assessment_complete": True,
    }
    probes = {
        "status": "COMPLETED",
        "probe_failures": 0,
        "probes_run": 6,
        "probe_results": [],
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "assessment_complete": True,
    }
    out = recommend_adoption(
        _model(_verified_identity()),
        risk_record=_risk(),
        provenance_assessment=_prov(risk_level="LOW", score=92, confidence=0.9),
        governance_summary=_gov(),
        vulnerability_scan=_vuln(),
        serialization_scan=serial,
        behavioral_probes=probes,
        policy_context={
            "use_case": "healthcare",
            "data_classification": "phi",
            "deployment_exposure": "public",
        },
    )
    assert out["verdict"] == "APPROVE_WITH_CONDITIONS"
    assert out["policy"]["approval_scope"]["allowed_exposure"] == "internal_pilot"
    assert any(r["category"] == "approval_scope" for r in out["reasons"])

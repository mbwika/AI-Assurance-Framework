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


def _model(ledger_facts, **metadata):
    meta = {"evidence_ledger": ledger_facts, **metadata}
    return {
        "model_id": "model-123",
        "model_name": "Acme Tiny",
        "source": "huggingface",
        "source_url": "https://huggingface.co/acme/tiny",
        "publisher": "acme",
        "license": metadata.get("license"),
        "metadata": meta,
    }


def _prov(score=78, risk_level="MEDIUM", confidence=0.71, trust_caps=None):
    return {
        "provenance_score": score,
        "risk_level": risk_level,
        "confidence": confidence,
        "trust_caps": trust_caps or [],
    }


def _serial(status="CLEAN", by_severity=None, match_count=0):
    return {
        "status": status,
        "by_severity": by_severity or {},
        "match_count": match_count,
    }


def _weights(status="INSPECTED", fmt="safetensors", **derived):
    return {
        "status": status,
        "format_detected": fmt,
        "derived_facts": {
            "architecture_family": "transformer",
            "layer_count": 32,
            "hidden_size": 4096,
            "vocab_size": 32000,
            "parameter_count_estimate": 7_000_000_000,
            "parameter_count_exact": True,
            "quantization": "bf16",
            **derived,
        },
    }


def _fact_rec(pir=0.5, contradictions=None, confirmations=None, unverifiable=None):
    return {
        "provenance_independence_ratio": pir,
        "contradictions": contradictions or [],
        "confirmations": confirmations or [],
        "unverifiable_facts": unverifiable or [],
        "decidability_bounds": [{"category": "training_data"}],
    }


def test_artifact_observed_posture_when_identity_is_not_verified():
    ensure_src()
    from aiaf.core.unknown_model_assurance import build_unknown_model_assurance
    from aiaf.registry.evidence_origin import EvidenceOrigin

    ledger = _ledger(
        ("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED),
        ("source_url", "https://huggingface.co/acme/tiny", EvidenceOrigin.USER_ENTERED),
        ("license", "apache-2.0", EvidenceOrigin.PROVIDER_DECLARED),
        ("model_type", "llama", EvidenceOrigin.PROVIDER_DECLARED),
        ("serialization_scan", "CLEAN", EvidenceOrigin.LOCALLY_OBSERVED),
    )
    model = _model(
        ledger,
        hf_model_card={"license": "apache-2.0", "model_type": "llama", "publisher": "acme"},
        repo_id="acme/tiny",
        license="apache-2.0",
    )

    result = build_unknown_model_assurance(
        model,
        provenance_assessment=_prov(trust_caps=[{"gate": "no_verified_signed_provenance"}]),
        serialization_scan=_serial(),
        weight_inspection=_weights(),
        fact_reconciliation=_fact_rec(
            pir=0.52,
            confirmations=[{"fact_name": "model_type", "value": "llama"}],
        ),
    )

    assert result["posture"] == "ARTIFACT_OBSERVED"
    assert result["artifact_identity"]["identity_status"] == "DECLARATION_HEAVY"
    assert result["artifact_inspection"]["architecture_family"] == "transformer"
    assert result["model_card_consistency"]["status"] == "ARTIFACT_CONFIRMED"
    assert result["license_posture"]["status"] == "PERMISSIVE_DECLARED"
    assert "Independent identity/provenance verification is still missing." in result["evidence_gaps"]


def test_do_not_trust_when_contradictions_or_unsafe_patterns_exist():
    ensure_src()
    from aiaf.core.unknown_model_assurance import build_unknown_model_assurance
    from aiaf.registry.evidence_origin import EvidenceOrigin

    ledger = _ledger(
        ("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED),
        ("source_url", "https://huggingface.co/acme/tiny", EvidenceOrigin.USER_ENTERED),
    )
    contradictions = [
        {
            "fact_name": "architecture_family",
            "declared_value": "transformer",
            "derived_value": "diffusion",
            "severity": "CRITICAL",
        }
    ]

    result = build_unknown_model_assurance(
        _model(ledger),
        recommendation={"reasons": [{"verdict": "DO_NOT_APPROVE", "category": "serialization_scan"}]},
        provenance_assessment=_prov(score=12, risk_level="CRITICAL"),
        serialization_scan=_serial(
            status="UNSAFE_PATTERNS_FOUND",
            by_severity={"CRITICAL": 1},
            match_count=1,
        ),
        weight_inspection=_weights(),
        fact_reconciliation=_fact_rec(pir=0.25, contradictions=contradictions),
        vulnerability_scan={"by_severity": {"HIGH": 1}},
    )

    assert result["posture"] == "DO_NOT_TRUST"
    assert result["security_flags"]["dangerous_serialization"] is True
    assert result["security_flags"]["high_confidence_contradictions"]
    assert result["recommended_next_steps"]

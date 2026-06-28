import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from aiaf.analysis.model_risk_v2 import (  # noqa: E402
    MODEL_RISK_SCORING_VERSION,
    PROVIDER_RISK_INTELLIGENCE_VERSION,
    assess_provider_risk_intelligence,
    estimate_model_risk_v2,
)


def _verified_control():
    return {
        "enabled": True,
        "method": "documented-policy",
        "tested": True,
        "verified": True,
    }


def _profile(**overrides):
    profile = {
        "impact_level": "moderate",
        "domain": "productivity",
        "deployment_exposure": "internal",
        "user_access": "authenticated",
        "data_classification": "internal",
        "decision_authority": "assistive",
        "reversibility": "reversible",
        "safety_criticality": "none",
        "deployment_scale": "limited",
        "capabilities": ["text_generation"],
        "safety_evaluations": _verified_control(),
    }
    profile.update(overrides)
    return profile


def _artifact(**profile_overrides):
    return {
        "model_name": "assessed-model",
        "model_risk_profile": _profile(**profile_overrides),
    }


def _indicators(result):
    return set(result["indicators"])


def _gate_names(result):
    return {gate["gate"] for gate in result["score_gates"]}


def test_result_is_versioned_deterministic_bounded_and_json_safe():
    artifact = _artifact()

    first = estimate_model_risk_v2(artifact)
    second = estimate_model_risk_v2(artifact)

    assert first == second
    assert first["assessment_version"] == MODEL_RISK_SCORING_VERSION == "2.0"
    assert first["score_scale"] == {"minimum": 0.0, "maximum": 10.0}
    assert 0 <= first["lower_confidence_bound"] <= first["residual_risk_score"]
    assert first["residual_risk_score"] <= first["upper_confidence_bound"] <= 10
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert first["provider_risk_intelligence"]["assessment_version"] == PROVIDER_RISK_INTELLIGENCE_VERSION


def test_malformed_artifact_and_profile_fail_closed():
    malformed_artifact = estimate_model_risk_v2("not-an-object")
    malformed_profile = estimate_model_risk_v2(
        {"model_name": "x", "model_risk_profile": ["not-an-object"]}
    )

    assert malformed_artifact["assessment_complete"] is False
    assert malformed_artifact["severity"] in {"HIGH", "CRITICAL"}
    assert "malformed_model_artifact" in _indicators(malformed_artifact)
    assert malformed_profile["assessment_complete"] is False
    assert "malformed_model_risk_profile" in _indicators(malformed_profile)


def test_missing_profile_widens_uncertainty_instead_of_assuming_benign_defaults():
    result = estimate_model_risk_v2({"model_name": "undocumented-model"})

    assert result["assessment_complete"] is False
    assert result["uncertainty_margin"] >= 2.5
    assert result["risk_score"] > result["residual_risk_score"]
    assert result["severity"] == "HIGH"


def test_inherent_risk_is_monotonic_with_impact():
    low = estimate_model_risk_v2(_artifact(impact_level="low"))
    high = estimate_model_risk_v2(_artifact(impact_level="high"))
    critical = estimate_model_risk_v2(_artifact(impact_level="critical"))

    assert low["inherent_risk_score"] < high["inherent_risk_score"]
    assert high["inherent_risk_score"] < critical["inherent_risk_score"]


def test_inherent_risk_is_monotonic_with_exposure_and_scale():
    internal = estimate_model_risk_v2(
        _artifact(deployment_exposure="internal", affected_users=100)
    )
    public = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="public",
            user_access="anonymous",
            affected_users=10_000_000,
        )
    )

    assert public["dimensions"]["exposure"]["score"] > internal["dimensions"]["exposure"]["score"]
    assert public["inherent_risk_score"] > internal["inherent_risk_score"]


def test_adding_a_lower_risk_capability_cannot_reduce_capability_risk():
    severe = estimate_model_risk_v2(_artifact(capabilities=["code_execution"]))
    expanded = estimate_model_risk_v2(
        _artifact(capabilities=["code_execution", "text_generation"])
    )

    assert expanded["dimensions"]["capability"]["score"] >= severe["dimensions"]["capability"]["score"]
    assert expanded["inherent_risk_score"] >= severe["inherent_risk_score"]


def test_controls_reduce_residual_but_never_rewrite_inherent_risk():
    weak = _artifact(
        impact_level="high",
        deployment_exposure="external",
        capabilities=["tool_use"],
    )
    strong = json.loads(json.dumps(weak))
    strong["model_risk_profile"].update(
        {
            name: _verified_control()
            for name in (
                "safety_evaluations",
                "continuous_monitoring",
                "incident_response",
                "audit_logging",
                "access_controls",
                "output_validation",
                "human_oversight",
                "fail_safe",
                "capability_constraints",
                "rate_limits",
            )
        }
    )

    weak_result = estimate_model_risk_v2(weak)
    strong_result = estimate_model_risk_v2(strong)

    assert weak_result["inherent_risk_score"] == strong_result["inherent_risk_score"]
    assert strong_result["residual_risk_score"] < weak_result["residual_risk_score"]
    assert strong_result["upper_confidence_bound"] < weak_result["upper_confidence_bound"]
    assert strong_result["control_assessment"]["effectiveness"] == 1.0


def test_disabled_control_strings_receive_no_effectiveness_credit():
    result = estimate_model_risk_v2(
        _artifact(
            impact_level="high",
            deployment_exposure="external",
            access_controls="disabled",
            output_validation="off",
            human_oversight="false",
        )
    )
    controls = {
        control["control"]: control
        for control in result["control_assessment"]["controls"]
    }

    assert controls["access_controls"]["strength"] == 0
    assert controls["output_validation"]["strength"] == 0
    assert controls["human_oversight"]["strength"] == 0


def test_failed_safety_evaluation_cannot_be_offset_by_other_evaluations():
    result = estimate_model_risk_v2(
        _artifact(
            safety_evaluations=[
                {"name": "baseline", "passed": True, "verified": True},
                {"name": "critical-abuse-case", "passed": False},
            ]
        )
    )
    safety = next(
        control
        for control in result["control_assessment"]["controls"]
        if control["control"] == "safety_evaluations"
    )

    assert safety["status"] == "FAILED"
    assert safety["strength"] == 0
    assert "failed_safety_evaluations" in _indicators(result)


def test_public_code_execution_creates_a_critical_floor():
    result = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="public",
            user_access="anonymous",
            capabilities=["code_execution"],
        )
    )

    assert "public_code_execution_coupling" in _indicators(result)
    assert "public_code_execution" in _gate_names(result)
    assert result["risk_score"] >= 7.5
    assert result["severity"] == "CRITICAL"


def test_autonomous_financial_authority_has_a_critical_floor():
    result = estimate_model_risk_v2(
        _artifact(capabilities=["autonomous_actions", "financial_transactions"])
    )

    assert "autonomous_financial_action_coupling" in _indicators(result)
    assert "autonomous_financial_transactions" in _gate_names(result)
    assert result["risk_score"] >= 8.5


def test_high_impact_decision_requires_verified_human_oversight():
    unguarded = estimate_model_risk_v2(
        _artifact(
            impact_level="high",
            domain="healthcare",
            decision_authority="automated_decision",
            capabilities=["medical_decisions"],
        )
    )
    guarded = estimate_model_risk_v2(
        _artifact(
            impact_level="high",
            domain="healthcare",
            decision_authority="automated_decision",
            capabilities=["medical_decisions"],
            human_oversight=_verified_control(),
        )
    )

    gate = "high_impact_decision_without_verified_oversight"
    assert gate in _gate_names(unguarded)
    assert gate not in _gate_names(guarded)


def test_sensitive_external_system_requires_verified_access_control():
    unguarded = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="external",
            data_classification="phi",
        )
    )
    guarded = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="external",
            data_classification="phi",
            access_controls=_verified_control(),
        )
    )

    gate = "sensitive_external_system_without_verified_access_control"
    assert gate in _gate_names(unguarded)
    assert gate not in _gate_names(guarded)


def test_low_declared_impact_cannot_hide_high_consequence_evidence():
    result = estimate_model_risk_v2(
        _artifact(
            impact_level="low",
            domain="law_enforcement",
            decision_authority="automated_decision",
            capabilities=["identity_decisions"],
        )
    )

    assert result["assessment_complete"] is False
    assert "declared_impact_underclassification" in _indicators(result)
    assert result["dimensions"]["impact"]["score"] >= 7


def test_cross_field_data_and_access_contradictions_are_detected():
    result = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="internal",
            user_access="anonymous",
            data_classification="internal",
            handles_sensitive_data=True,
        )
    )

    assert {
        "deployment_access_inconsistency",
        "data_classification_inconsistency",
    }.issubset(_indicators(result))
    assert result["assessment_complete"] is False


def test_operational_tools_infer_undeclared_capabilities():
    artifact = _artifact(capabilities=[])
    artifact["tools"] = ["shell", "email"]

    result = estimate_model_risk_v2(artifact)

    assert "undeclared_high_risk_capability" in _indicators(result)
    assert {"code_execution", "external_communications", "tool_use"}.issubset(
        result["evidence"]["capabilities"]
    )


def test_unknown_categories_and_malformed_counts_reduce_confidence():
    result = estimate_model_risk_v2(
        _artifact(
            deployment_exposure="everywhere-ish",
            affected_users=-1,
            capabilities=[f"cap-{index}" for index in range(101)],
        )
    )

    assert result["assessment_complete"] is False
    assert {
        "unknown_deployment_exposure",
        "malformed_affected_user_count",
        "malformed_or_excessive_capability_inventory",
    }.issubset(_indicators(result))
    assert result["confidence"] < 0.8


def test_tool_and_control_evidence_truncation_is_explicit():
    artifact = _artifact(
        safety_evaluations=[
            {"name": f"evaluation-{index}", "passed": True}
            for index in range(101)
        ]
    )
    artifact["tools"] = [f"tool-{index}" for index in range(101)]

    result = estimate_model_risk_v2(artifact)

    assert result["assessment_complete"] is False
    assert {
        "tool_capability_inference_limit_exceeded",
        "control_evidence_limit_exceeded",
    }.issubset(_indicators(result))


def test_custom_domain_taxonomy_changes_risk_without_code_changes():
    artifact = _artifact(domain="orbital_navigation")
    baseline = estimate_model_risk_v2(artifact)
    customized = estimate_model_risk_v2(
        artifact,
        {"domain_risk_scores": {"orbital_navigation": 9.5}},
    )

    assert customized["dimensions"]["impact"]["score"] > baseline["dimensions"]["impact"]["score"]
    assert "declared_impact_underclassification" in _indicators(customized)


def test_malformed_custom_taxonomy_fails_closed():
    result = estimate_model_risk_v2(
        _artifact(),
        {
            "domain_risk_scores": {"custom": 12},
            "control_reduction_cap": 0.9,
        },
    )

    assert result["assessment_complete"] is False
    assert "malformed_model_risk_context" in _indicators(result)


def test_provider_risk_intelligence_is_additive_for_existing_model_risk_assessments():
    result = estimate_model_risk_v2(_artifact())
    assert result["assessment_complete"] is True
    assert "provider_risk_intelligence" in result
    assert result["provider_risk_intelligence"]["overall_risk_score"] >= 0


def test_provider_risk_intelligence_rewards_disclosed_stable_provider_evidence():
    artifact = _artifact()
    artifact.update(
        {
            "source": "huggingface",
            "source_url": "https://huggingface.co/acme-labs/secure-model",
            "publisher": "acme-labs",
            "license": "apache-2.0",
            "attestations": [{"statement": {"attestation_id": "att-1"}}],
            "metadata": {
                "provider": "huggingface",
                "hf_model_card": {
                    "status": "SUCCESS",
                    "publisher": "acme-labs",
                    "license": "apache-2.0",
                    "model_type": "llama",
                    "pipeline_tag": "text-generation",
                    "architectures": ["LlamaForCausalLM"],
                    "model_card_signals": {
                        "sections_present": [
                            "intended use",
                            "training data",
                            "evaluation",
                            "limitations",
                            "safety",
                            "privacy",
                        ],
                        "dataset_disclosure_present": True,
                        "evaluation_disclosure_present": True,
                        "limitations_disclosure_present": True,
                        "intended_use_present": True,
                        "safety_disclosure_present": True,
                        "privacy_disclosure_present": True,
                    },
                },
                "adoption_velocity_assessment": {
                    "risk_level": "NORMAL",
                    "anomalies": [],
                    "velocity_profile": {"current_velocity_per_hour": 3.0},
                },
                "provenance_assessment": {
                    "provenance_score": 92,
                    "assessment_complete": True,
                    "confidence": 0.95,
                },
            },
        }
    )

    result = assess_provider_risk_intelligence(artifact)

    assert result["assessment_version"] == PROVIDER_RISK_INTELLIGENCE_VERSION
    assert result["overall_risk_score"] < 4.5
    assert result["severity"] in {"LOW", "MEDIUM"}
    assert result["assessment_complete"] is True


def test_provider_risk_intelligence_flags_conflicts_and_adoption_anomalies():
    artifact = _artifact()
    artifact.update(
        {
            "source": "github",
            "source_url": "https://huggingface.co/acme-labs/volatile-model",
            "publisher": "registry-publisher",
            "license": "mit",
            "metadata": {
                "provider": "github",
                "hf_model_card": {
                    "status": "SUCCESS",
                    "publisher": "different-publisher",
                    "license": "llama3",
                    "model_card_signals": {
                        "sections_present": ["overview"],
                        "dataset_disclosure_present": False,
                        "evaluation_disclosure_present": False,
                        "limitations_disclosure_present": False,
                        "intended_use_present": False,
                        "safety_disclosure_present": False,
                        "privacy_disclosure_present": False,
                    },
                },
                "adoption_velocity_assessment": {
                    "risk_level": "CRITICAL",
                    "anomalies": [{"signal": "COLD_START_SURGE", "severity": "CRITICAL"}],
                    "velocity_profile": {"current_velocity_per_hour": 400.0},
                },
                "provenance_assessment": {
                    "provenance_score": 10,
                    "assessment_complete": False,
                    "confidence": 0.2,
                },
            },
        }
    )

    provider = assess_provider_risk_intelligence(artifact)
    full = estimate_model_risk_v2(artifact)

    assert {
        "provider_identity_conflict",
        "publisher_identity_conflict",
        "license_identity_conflict",
        "adoption_velocity_anomaly",
    }.issubset(set(provider["indicators"]))
    assert provider["overall_risk_score"] >= 7.5
    assert "provider_supply_chain_risk" in _indicators(full)

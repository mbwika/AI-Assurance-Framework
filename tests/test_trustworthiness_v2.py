import json

import pytest

from aiaf.analysis.trustworthiness import (
    TRUSTWORTHINESS_SCORING_VERSION,
    score_trustworthiness,
)


def _complete_artifact(**overrides):
    artifact = {
        "source_url": "https://example.test/model",
        "publisher": "Acme AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "dependencies": ["transformers==4.40.0"],
        "training_artifacts": [
            {
                "name": "dataset-a",
                "source_url": "https://example.test/data",
                "sha256": "b" * 64,
            }
        ],
        "deployment_pipeline": {
            "environment": "production",
            "approval_gate": "CAB-123",
        },
        "provenance_attestations": [
            {"algorithm": "HMAC-SHA256", "signature": "c" * 64}
        ],
        "owner": "AI Platform",
        "risk_owner": "Security Governance",
        "compliance_scope": ["NIST AI RMF"],
        "documentation_url": "https://example.test/model-card",
        "monitoring_enabled": True,
        "assessment_frequency": "weekly",
        "adversarial_tests": [{"name": "baseline", "passed": True}],
    }
    artifact.update(overrides)
    return artifact


def _complete_agent(**overrides):
    artifact = _complete_artifact(
        tools=["shell"],
        permissions=["execute"],
        autonomy_level="high",
        human_review_required=True,
        workflow_steps=[{"id": "execute", "tool": "shell"}],
        agent_policy={
            "allowed_tools": ["shell"],
            "allowed_permissions": ["execute"],
            "require_approval_for_actions": ["execute"],
        },
        operational_constraints={"network": "restricted"},
        runtime_tool_authorization=True,
    )
    artifact.update(overrides)
    return artifact


def _complete_reliability(**overrides):
    artifact = _complete_artifact(
        safety_evaluations=[{"name": "safety", "passed": True}],
        factuality_evaluation={
            "validated": True,
            "sample_size": 500,
            "total_claims": 500,
            "correct_claims": 480,
            "factual_accuracy": 0.96,
            "citation_precision": 0.95,
            "evaluation_id": "fact-2026-01",
            "dataset_sha256": "d" * 64,
            "evaluated_at": "2026-06-01T00:00:00Z",
        },
        bias_evaluation={
            "reviewed": True,
            "sample_size": 500,
            "demographic_parity_difference": 0.05,
            "disparate_impact_ratio": 0.91,
            "equal_opportunity_difference": 0.04,
            "false_positive_rate_gap": 0.03,
            "groups_evaluated": 4,
            "evaluation_id": "bias-2026-01",
            "dataset_sha256": "e" * 64,
            "evaluated_at": "2026-06-01T00:00:00Z",
        },
        human_oversight=True,
        output_validation="policy_filter",
        calibration_evidence={
            "validated": True,
            "sample_size": 500,
            "expected_calibration_error": 0.03,
            "test_cases": 500,
            "passed_cases": 485,
            "evaluation_id": "cal-2026-01",
            "dataset_sha256": "f" * 64,
            "evaluated_at": "2026-06-01T00:00:00Z",
        },
    )
    artifact.update(overrides)
    return artifact


def test_complete_evidence_scores_high_with_versioned_explainability():
    result = score_trustworthiness(_complete_artifact(), risk_score=0.0, findings=[])

    assert result["trustworthiness_score"] >= 90.0
    assert result["level"] == "HIGH"
    assert result["confidence"] == 1.0
    assert result["scoring_version"] == TRUSTWORTHINESS_SCORING_VERSION
    assert result["dimensions"]["supply_chain_integrity"]["status"] == "PASS"
    assert result["dimensions"]["agentic_safeguards"]["status"] == "NOT_APPLICABLE"
    assert result["dimensions"]["model_reliability"]["status"] == "NOT_APPLICABLE"
    assert sum(result["weights"].values()) == pytest.approx(1.0, abs=0.00001)


def test_sparse_artifact_cannot_inherit_trust_from_absent_dimensions():
    result = score_trustworthiness({}, risk_score=0.0, findings=[])

    assert result["level"] == "LOW"
    assert result["trustworthiness_score"] < 40.0
    assert result["confidence"] < 0.35
    assert "insufficient_assurance_confidence" in {
        gate["gate"] for gate in result["score_gates"]
    }
    assert "missing evidence: sha256" in result["evidence_gaps"]
    assert "missing evidence: monitoring_enabled" in result["evidence_gaps"]


def test_structural_quality_beats_presence_only_supply_chain_evidence():
    strong = score_trustworthiness(_complete_artifact(), findings=[])
    weak = score_trustworthiness(
        _complete_artifact(
            source_url="http://example.test/model",
            sha256="not-a-digest",
            license="unknown",
            dependencies=["transformers>=4"],
            training_artifacts=[{"name": "dataset-a"}],
            deployment_pipeline={"environment": "production"},
            provenance_attestations=[{"algorithm": "unknown"}],
        ),
        findings=[],
    )

    strong_dimension = strong["dimensions"]["supply_chain_integrity"]
    weak_dimension = weak["dimensions"]["supply_chain_integrity"]
    assert strong_dimension["score"] > weak_dimension["score"]
    assert weak_dimension["evidence_quality"]["sha256"] == 0.25
    assert weak_dimension["evidence_quality"]["dependencies"] == 0.5
    assert "weak evidence: sha256" in weak_dimension["gaps"]


def test_pinned_dependencies_score_higher_than_unpinned_dependencies():
    pinned = score_trustworthiness(
        _complete_artifact(dependencies=["torch==2.5.1", "transformers==4.48.0"])
    )
    unpinned = score_trustworthiness(
        _complete_artifact(dependencies=["torch>=2", "transformers"])
    )

    pinned_quality = pinned["dimensions"]["supply_chain_integrity"][
        "evidence_quality"
    ]["dependencies"]
    unpinned_quality = unpinned["dimensions"]["supply_chain_integrity"][
        "evidence_quality"
    ]["dependencies"]
    assert pinned_quality == 1.0
    assert unpinned_quality == 0.5


def test_structured_attestation_and_digest_bound_deployment_improve_quality():
    baseline = score_trustworthiness(_complete_artifact())
    strengthened = score_trustworthiness(
        _complete_artifact(
            deployment_pipeline={
                "environment": "production",
                "artifact_ref": "registry.example/model@sha256:" + "d" * 64,
                "approval_gate": "CAB-123",
            },
            provenance_attestations=[
                {
                    "algorithm": "HMAC-SHA256",
                    "signature": "c" * 64,
                    "subject": "model",
                    "verified": True,
                }
            ],
        )
    )

    baseline_supply = baseline["dimensions"]["supply_chain_integrity"]
    strong_supply = strengthened["dimensions"]["supply_chain_integrity"]
    assert strong_supply["score"] > baseline_supply["score"]
    assert strong_supply["evidence_quality"]["deployment_pipeline"] == 1.0
    assert strong_supply["evidence_quality"]["provenance_attestations"] == 0.6


def test_inline_attestation_verification_cannot_inflate_trust():
    attestation = {
        "algorithm": "HMAC-SHA256",
        "signature": "c" * 64,
        "subject": "model",
    }
    baseline = score_trustworthiness(
        _complete_artifact(provenance_attestations=[attestation])
    )
    asserted = score_trustworthiness(
        _complete_artifact(
            provenance_attestations=[
                {**attestation, "verified": True, "status": "verified"}
            ]
        )
    )

    baseline_quality = baseline["dimensions"]["supply_chain_integrity"][
        "evidence_quality"
    ]["provenance_attestations"]
    asserted_quality = asserted["dimensions"]["supply_chain_integrity"][
        "evidence_quality"
    ]["provenance_attestations"]
    assert asserted_quality == baseline_quality == 0.6


def test_active_critical_finding_caps_otherwise_high_trust():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[{"type": "prompt_injection", "severity": "CRITICAL"}],
    )

    assert result["raw_trustworthiness_score"] > 80.0
    assert result["trustworthiness_score"] == 49.0
    assert result["level"] == "LOW"
    assert "active_critical_finding" in {gate["gate"] for gate in result["score_gates"]}
    assert result["dimensions"]["security_posture"]["status"] == "NEEDS_REVIEW"


def test_critical_supply_chain_finding_applies_stricter_integrity_cap():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[{"type": "supply_chain", "severity": "CRITICAL"}],
    )

    assert result["trustworthiness_score"] == 39.0
    assert "critical_supply_chain_integrity" in {
        gate["gate"] for gate in result["score_gates"]
    }
    assert result["dimensions"]["supply_chain_integrity"]["status"] == "NEEDS_REVIEW"


@pytest.mark.parametrize("status", ["resolved", "closed", "remediated", "fixed"])
def test_resolved_critical_findings_no_longer_cap_current_posture(status):
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[
            {"type": "prompt_injection", "severity": "CRITICAL", "status": status}
        ],
    )

    assert result["trustworthiness_score"] > 90.0
    assert result["score_gates"] == []
    assert result["finding_summary"]["resolved"] == 1


def test_risk_acceptance_does_not_erase_active_security_risk():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[
            {
                "type": "prompt_injection",
                "severity": "CRITICAL",
                "status": "accepted",
            }
        ],
    )

    assert result["trustworthiness_score"] == 49.0
    assert result["finding_summary"]["active"] == 1


def test_multiple_high_findings_cap_moderate_trust():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[
            {"type": "prompt_injection", "severity": "HIGH"},
            {"type": "jailbreak", "severity": "HIGH"},
        ],
    )

    assert result["trustworthiness_score"] == 64.0
    assert "multiple_active_high_findings" in {
        gate["gate"] for gate in result["score_gates"]
    }


def test_critical_aggregate_risk_caps_composite_even_without_findings():
    result = score_trustworthiness(_complete_artifact(), risk_score=8.0, findings=[])

    assert result["trustworthiness_score"] == 39.0
    assert "critical_aggregate_risk" in {
        gate["gate"] for gate in result["score_gates"]
    }


@pytest.mark.parametrize("risk_score", ["not-a-number", float("nan"), True, 11.0, -1.0])
def test_malformed_or_out_of_range_risk_fails_conservatively(risk_score):
    result = score_trustworthiness(
        _complete_artifact(), risk_score=risk_score, findings=[]
    )

    assert result["trustworthiness_score"] <= 39.0
    assert result["warnings"]
    assert result["dimensions"]["security_posture"]["confidence"] < 1.0


def test_malformed_finding_collection_is_bounded_by_evidence_gate():
    result = score_trustworthiness(_complete_artifact(), findings={"type": "bad"})

    assert result["finding_summary"]["invalid"] == 1
    assert result["trustworthiness_score"] <= 64.0
    assert "incomplete_finding_evidence" in {
        gate["gate"] for gate in result["score_gates"]
    }


def test_unknown_finding_severity_is_treated_as_high_not_low():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[{"type": "unknown_detector", "severity": "impossible"}],
    )

    security = result["dimensions"]["security_posture"]
    assert security["evidence"]["severity_counts"]["HIGH"] == 1
    assert result["finding_summary"]["invalid"] == 1
    assert result["warnings"]


def test_findings_are_bounded_without_echoing_arbitrary_detail():
    sensitive_detail = "do-not-return-this-finding-detail"
    findings = [
        {
            "type": "low_signal",
            "severity": "LOW",
            "detail": sensitive_detail,
        }
        for _ in range(1_001)
    ]
    result = score_trustworthiness(_complete_artifact(), findings=findings)
    serialized = json.dumps(result)

    assert result["finding_summary"]["provided"] == 1_001
    assert result["finding_summary"]["analyzed"] == 1_000
    assert result["finding_summary"]["truncated"] is True
    assert sensitive_detail not in serialized


def test_findings_are_attributed_once_to_their_owning_dimension():
    result = score_trustworthiness(
        _complete_agent(),
        findings=[{"type": "agent_risk", "severity": "HIGH"}],
    )

    assert result["dimensions"]["security_posture"]["evidence"]["finding_count"] == 0
    assert result["dimensions"]["agentic_safeguards"]["finding_evidence"][
        "finding_count"
    ] == 1
    assert "severe finding: agent_risk" in result["evidence_gaps"]


def test_risk_and_finding_penalties_use_the_more_conservative_signal_once():
    result = score_trustworthiness(
        _complete_artifact(),
        risk_score=5.0,
        findings=[{"type": "prompt_injection", "severity": "HIGH"}],
    )

    security = result["dimensions"]["security_posture"]
    assert security["evidence"]["risk_penalty"] == 40.0
    assert security["evidence"]["finding_penalty"] == 14.0
    assert security["score"] == 60.0


def test_explicit_non_agentic_artifact_keeps_agent_dimension_not_applicable():
    result = score_trustworthiness(_complete_artifact(agentic=False), findings=[])

    assert result["dimensions"]["agentic_safeguards"]["status"] == "NOT_APPLICABLE"
    assert result["weights"]["agentic_safeguards"] == 0.0


def test_partial_agent_evidence_exposes_safeguard_gaps():
    result = score_trustworthiness(
        _complete_artifact(tools=["shell"], autonomy_level="high"), findings=[]
    )

    agent = result["dimensions"]["agentic_safeguards"]
    assert agent["applicable"] is True
    assert agent["status"] == "NEEDS_REVIEW"
    assert "missing evidence: agent_policy" in agent["gaps"]
    assert "missing evidence: operational_constraints" in agent["gaps"]
    assert "missing evidence: runtime_tool_authorization" in agent["gaps"]


def test_complete_agent_safeguards_pass():
    result = score_trustworthiness(_complete_agent(), findings=[])

    agent = result["dimensions"]["agentic_safeguards"]
    assert agent["status"] == "PASS"
    assert agent["score"] >= 90.0
    assert result["weights"]["agentic_safeguards"] > 0.0


def test_reliability_dimension_is_conditionally_applicable():
    absent = score_trustworthiness(_complete_artifact(), findings=[])
    present = score_trustworthiness(_complete_reliability(), findings=[])

    assert absent["dimensions"]["model_reliability"]["status"] == "NOT_APPLICABLE"
    assert present["dimensions"]["model_reliability"]["status"] == "PASS"
    assert present["dimensions"]["model_reliability"]["score"] >= 90.0
    assert present["dimensions"]["model_reliability"]["evidence_quality"][
        "factuality_evaluation"
    ] <= 0.85


def test_declaration_only_reliability_evidence_cannot_score_as_verified():
    declared = score_trustworthiness(
        _complete_artifact(
            factuality_evaluation={"validated": True},
            bias_evaluation={"reviewed": True},
            calibration_evidence={
                "validated": True,
                "arbitrary_metric": 999,
                "sample_size": float("nan"),
            },
        )
    )

    quality = declared["dimensions"]["model_reliability"]["evidence_quality"]
    assert quality["factuality_evaluation"] == 0.3
    assert quality["bias_evaluation"] == 0.3
    assert quality["calibration_evidence"] == 0.3
    assert declared["dimensions"]["model_reliability"]["status"] == "NEEDS_REVIEW"


def test_reliability_finding_requires_evidence_and_review():
    result = score_trustworthiness(
        _complete_artifact(),
        findings=[{"type": "hallucination_risk", "severity": "HIGH"}],
    )

    reliability = result["dimensions"]["model_reliability"]
    assert reliability["applicable"] is True
    assert reliability["score"] == 0.0
    assert reliability["status"] == "NEEDS_REVIEW"
    assert "missing evidence: factuality_evaluation" in reliability["gaps"]
    assert "severe finding: hallucination_risk" in reliability["gaps"]


def test_false_human_oversight_is_evidence_of_missing_safeguard():
    result = score_trustworthiness(
        _complete_artifact(human_oversight=False), findings=[]
    )

    reliability = result["dimensions"]["model_reliability"]
    assert reliability["applicable"] is True
    assert reliability["evidence_quality"]["human_oversight"] == 0.0
    assert "missing evidence: human_oversight" in reliability["gaps"]


def test_failed_adversarial_evidence_reduces_operational_dimension():
    result = score_trustworthiness(
        _complete_artifact(
            adversarial_tests=[{"name": "baseline", "passed": False}]
        ),
        findings=[],
    )

    operational = result["dimensions"]["operational_monitoring"]
    assert operational["score"] == 60.0
    assert operational["status"] == "NEEDS_REVIEW"


def test_insecure_documentation_url_is_present_but_weak_governance_evidence():
    result = score_trustworthiness(
        _complete_artifact(documentation_url="http://example.test/model-card")
    )

    governance = result["dimensions"]["governance_evidence"]
    assert governance["evidence_quality"]["documentation_url"] == 0.4
    assert "weak evidence: documentation_url" in governance["gaps"]


def test_result_is_deterministic_json_safe_and_arithmetically_explainable():
    artifact = _complete_reliability()
    first = score_trustworthiness(artifact, risk_score=1.5, findings=[])
    second = score_trustworthiness(artifact, risk_score=1.5, findings=[])
    contribution_sum = sum(item["contribution"] for item in first["score_breakdown"])

    assert first == second
    assert first["raw_trustworthiness_score"] == pytest.approx(
        contribution_sum, abs=0.02
    )
    assert first["trustworthiness_score"] <= first["raw_trustworthiness_score"]
    assert first["scoring_version"] == TRUSTWORTHINESS_SCORING_VERSION
    json.dumps(first)

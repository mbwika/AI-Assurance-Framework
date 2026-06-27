"""Tests for src/aiaf/analysis/frontier_eval.py."""

import pytest
from aiaf.analysis.frontier_eval import (
    assess_frontier_capabilities,
    map_to_gpai_commitments,
    get_capability_taxonomy,
    FRONTIER_EVAL_VERSION,
    CAP_CYBER_OFFENSE,
    CAP_CBRN_UPLIFT,
    CAP_AUTONOMY_SELF_REPLICATION,
    CAP_DECEPTION,
    CAP_PERSUASION_MANIPULATION,
    CAP_CRITICAL_INFRASTRUCTURE,
    CAP_POWER_SEEKING,
    CAPABILITY_CATEGORIES,
    EVIDENCE_CONFIRMED,
    EVIDENCE_PROBABLE,
    EVIDENCE_POSSIBLE,
    EVIDENCE_INSUFFICIENT,
    EVIDENCE_NOT_EVALUATED,
    VERDICT_SAFE,
    VERDICT_CONDITIONAL,
    VERDICT_UNSAFE,
    VERDICT_INSUFFICIENT_EVIDENCE,
    GPAI_COMMITMENTS,
    SYSTEMIC_RISK_FLOP_THRESHOLD,
    FrontierEvalError,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(
    capability,
    strength=EVIDENCE_NOT_EVALUATED,
    origin="LOCALLY_OBSERVED",
    safeguard=False,
    method="probe",
    description="Test finding.",
    mitigation=None,
):
    return {
        "capability": capability,
        "evidence_strength": strength,
        "evidence_origin": origin,
        "safeguard_present": safeguard,
        "method": method,
        "description": description,
        "mitigation": mitigation,
    }


# ── assess_frontier_capabilities — return shape ───────────────────────────────

class TestReturnShape:
    def test_returns_dict(self):
        result = assess_frontier_capabilities("model-a", [])
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        result = assess_frontier_capabilities("model-a", [])
        for key in ("model_id", "frontier_eval_version", "systemic_risk_classification",
                    "overall_verdict", "per_capability", "gpai_commitment_gaps",
                    "required_safeguards", "evidence_completeness_pct",
                    "evidence_origin", "assessed_at"):
            assert key in result

    def test_model_id_propagated(self):
        result = assess_frontier_capabilities("model-frontier-x", [])
        assert result["model_id"] == "model-frontier-x"

    def test_version_present(self):
        result = assess_frontier_capabilities("m", [])
        assert result["frontier_eval_version"] == FRONTIER_EVAL_VERSION

    def test_evidence_origin(self):
        result = assess_frontier_capabilities("m", [])
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_assessed_at_utc(self):
        result = assess_frontier_capabilities("m", [])
        assert result["assessed_at"].endswith("Z")

    def test_per_capability_covers_all_categories(self):
        result = assess_frontier_capabilities("m", [])
        for cat in CAPABILITY_CATEGORIES:
            assert cat in result["per_capability"]

    def test_context_forwarded(self):
        result = assess_frontier_capabilities("m", [], context="EU AI Act assessment")
        assert result["context"] == "EU AI Act assessment"


# ── No findings — insufficient evidence ───────────────────────────────────────

class TestNoFindings:
    def test_overall_verdict_insufficient_with_no_findings(self):
        result = assess_frontier_capabilities("m", [])
        assert result["overall_verdict"] == VERDICT_INSUFFICIENT_EVIDENCE

    def test_all_caps_not_evaluated(self):
        result = assess_frontier_capabilities("m", [])
        for cap_data in result["per_capability"].values():
            assert cap_data["evidence_strength"] == EVIDENCE_NOT_EVALUATED

    def test_completeness_zero(self):
        result = assess_frontier_capabilities("m", [])
        assert result["evidence_completeness_pct"] == pytest.approx(0.0)


# ── Single UNSAFE finding ─────────────────────────────────────────────────────

class TestUnsafeFinding:
    def test_confirmed_no_safeguard_is_unsafe(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        assert result["per_capability"][CAP_CYBER_OFFENSE]["verdict"] == VERDICT_UNSAFE

    def test_probable_no_safeguard_is_unsafe(self):
        findings = [_finding(CAP_CBRN_UPLIFT, strength=EVIDENCE_PROBABLE, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        assert result["per_capability"][CAP_CBRN_UPLIFT]["verdict"] == VERDICT_UNSAFE

    def test_unsafe_escalates_overall(self):
        findings = [_finding(CAP_DECEPTION, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        assert result["overall_verdict"] == VERDICT_UNSAFE

    def test_confirmed_with_safeguard_is_conditional(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=True)]
        result = assess_frontier_capabilities("m", findings)
        assert result["per_capability"][CAP_CYBER_OFFENSE]["verdict"] == VERDICT_CONDITIONAL

    def test_probable_with_safeguard_is_conditional(self):
        findings = [_finding(CAP_CBRN_UPLIFT, strength=EVIDENCE_PROBABLE, safeguard=True)]
        result = assess_frontier_capabilities("m", findings)
        assert result["per_capability"][CAP_CBRN_UPLIFT]["verdict"] == VERDICT_CONDITIONAL

    def test_possible_is_conditional(self):
        findings = [_finding(CAP_AUTONOMY_SELF_REPLICATION, strength=EVIDENCE_POSSIBLE)]
        result = assess_frontier_capabilities("m", findings)
        assert result["per_capability"][CAP_AUTONOMY_SELF_REPLICATION]["verdict"] == VERDICT_CONDITIONAL

    def test_possible_escalates_overall_to_conditional(self):
        findings = [_finding(CAP_DECEPTION, strength=EVIDENCE_POSSIBLE)]
        result = assess_frontier_capabilities("m", findings)
        assert result["overall_verdict"] in (VERDICT_CONDITIONAL, VERDICT_INSUFFICIENT_EVIDENCE)


# ── All evaluated, all safe ────────────────────────────────────────────────────

class TestAllSafe:
    def test_all_insufficient_evidence_overall(self):
        findings = [
            _finding(cat, strength=EVIDENCE_INSUFFICIENT)
            for cat in CAPABILITY_CATEGORIES
        ]
        result = assess_frontier_capabilities("m", findings)
        # All insufficient → INSUFFICIENT_EVIDENCE overall
        assert result["overall_verdict"] == VERDICT_INSUFFICIENT_EVIDENCE

    def test_completeness_100_when_all_evaluated(self):
        findings = [
            _finding(cat, strength=EVIDENCE_CONFIRMED, safeguard=True)
            for cat in CAPABILITY_CATEGORIES
        ]
        result = assess_frontier_capabilities("m", findings)
        assert result["evidence_completeness_pct"] == pytest.approx(100.0)

    def test_overall_safe_when_all_confirmed_safeguarded(self):
        # CONFIRMED + safeguard_present → CONDITIONAL per-cap (not SAFE)
        # So overall should be CONDITIONAL
        findings = [
            _finding(cat, strength=EVIDENCE_CONFIRMED, safeguard=True)
            for cat in CAPABILITY_CATEGORIES
        ]
        result = assess_frontier_capabilities("m", findings)
        assert result["overall_verdict"] == VERDICT_CONDITIONAL

    def test_overall_safe_when_all_insufficient_with_no_evaluated(self):
        # No findings at all → INSUFFICIENT_EVIDENCE
        result = assess_frontier_capabilities("m", [])
        assert result["overall_verdict"] == VERDICT_INSUFFICIENT_EVIDENCE


# ── Systemic risk classification ───────────────────────────────────────────────

class TestSystemicRisk:
    def test_no_flops_not_systemic(self):
        result = assess_frontier_capabilities("m", [])
        assert result["systemic_risk_classification"] is False

    def test_above_threshold_is_systemic(self):
        result = assess_frontier_capabilities(
            "m", [], training_flops=1e25
        )
        assert result["systemic_risk_classification"] is True

    def test_below_threshold_not_systemic(self):
        result = assess_frontier_capabilities(
            "m", [], training_flops=1e24
        )
        assert result["systemic_risk_classification"] is False

    def test_1t_params_proxy_systemic(self):
        result = assess_frontier_capabilities(
            "m", [], parameter_count=1e12
        )
        assert result["systemic_risk_classification"] is True

    def test_small_params_not_systemic(self):
        result = assess_frontier_capabilities(
            "m", [], parameter_count=7e9
        )
        assert result["systemic_risk_classification"] is False

    def test_flops_stored_in_result(self):
        result = assess_frontier_capabilities("m", [], training_flops=1e26)
        assert result["training_flops"] == pytest.approx(1e26)

    def test_systemic_risk_reason_present(self):
        result = assess_frontier_capabilities("m", [], training_flops=1e26)
        assert result["systemic_risk_reason"] is not None
        assert "10^25" in result["systemic_risk_reason"]


# ── GPAI commitment gaps ───────────────────────────────────────────────────────

class TestGPAICommitmentGaps:
    def test_no_findings_no_gaps(self):
        result = assess_frontier_capabilities("m", [])
        # No unsafe/conditional capabilities → no gaps triggered
        assert result["gpai_gap_count"] == 0

    def test_cyber_offense_triggers_s3(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        gap_ids = {g["commitment_id"] for g in result["gpai_commitment_gaps"]}
        assert "S3" in gap_ids

    def test_cbrn_triggers_s2(self):
        findings = [_finding(CAP_CBRN_UPLIFT, strength=EVIDENCE_PROBABLE, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        gap_ids = {g["commitment_id"] for g in result["gpai_commitment_gaps"]}
        assert "S2" in gap_ids

    def test_autonomy_triggers_s4(self):
        findings = [_finding(CAP_AUTONOMY_SELF_REPLICATION, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        gap_ids = {g["commitment_id"] for g in result["gpai_commitment_gaps"]}
        assert "S4" in gap_ids

    def test_gaps_have_eu_ai_act_ref(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        for gap in result["gpai_commitment_gaps"]:
            assert "eu_ai_act_ref" in gap
            assert "Article" in gap["eu_ai_act_ref"]


# ── Required safeguards ────────────────────────────────────────────────────────

class TestRequiredSafeguards:
    def test_no_unsafe_no_safeguards_required(self):
        result = assess_frontier_capabilities("m", [])
        assert result["required_safeguards"] == []

    def test_unsafe_cyber_requires_safeguard(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        assert len(result["required_safeguards"]) > 0
        combined = " ".join(result["required_safeguards"]).lower()
        assert "cyber" in combined or "cybersecev" in combined or "refusal" in combined

    def test_unsafe_cbrn_requires_safeguard(self):
        findings = [_finding(CAP_CBRN_UPLIFT, strength=EVIDENCE_PROBABLE, safeguard=False)]
        result = assess_frontier_capabilities("m", findings)
        combined = " ".join(result["required_safeguards"]).lower()
        assert "cbrn" in combined

    def test_safeguard_present_no_requirement(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=True)]
        result = assess_frontier_capabilities("m", findings)
        # safeguard present → CONDITIONAL but no safeguard requirement in required_safeguards
        cyber_recs = [s for s in result["required_safeguards"]
                      if "cyber" in s.lower() or "cybersecev" in s.lower()]
        assert len(cyber_recs) == 0


# ── Input validation ───────────────────────────────────────────────────────────

class TestInputValidation:
    def test_unknown_capability_raises(self):
        with pytest.raises(FrontierEvalError):
            assess_frontier_capabilities("m", [{"capability": "UNKNOWN_CAP",
                                                "evidence_strength": EVIDENCE_CONFIRMED}])

    def test_unknown_evidence_strength_raises(self):
        with pytest.raises(FrontierEvalError):
            assess_frontier_capabilities("m", [{"capability": CAP_DECEPTION,
                                                "evidence_strength": "SUPER_CONFIRMED"}])

    def test_empty_findings_list_ok(self):
        result = assess_frontier_capabilities("m", [])
        assert result["overall_verdict"] == VERDICT_INSUFFICIENT_EVIDENCE

    def test_none_capability_field_ignored(self):
        # Findings with missing/None capability should still be handled
        result = assess_frontier_capabilities("m", [
            {"capability": None, "evidence_strength": EVIDENCE_NOT_EVALUATED}
        ])
        assert isinstance(result, dict)


# ── Evidence origin weighting ──────────────────────────────────────────────────

class TestEvidenceWeighting:
    def test_independently_verified_preferred_over_provider_declared(self):
        findings = [
            _finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_POSSIBLE,
                     origin="PROVIDER_DECLARED", safeguard=True),
            _finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED,
                     origin="INDEPENDENTLY_VERIFIED", safeguard=False),
        ]
        result = assess_frontier_capabilities("m", findings)
        # Independently verified CONFIRMED with no safeguard → UNSAFE
        assert result["per_capability"][CAP_CYBER_OFFENSE]["verdict"] == VERDICT_UNSAFE


# ── map_to_gpai_commitments ────────────────────────────────────────────────────

class TestMapToGPAICommitments:
    def test_returns_dict_with_model_id(self):
        assessment = assess_frontier_capabilities("model-x", [])
        result = map_to_gpai_commitments(assessment)
        assert result["model_id"] == "model-x"

    def test_gpai_commitments_key_present(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        assert "gpai_commitments" in result

    def test_all_commitment_ids_present(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        for cid in GPAI_COMMITMENTS:
            assert cid in result["gpai_commitments"]

    def test_s6_always_applies(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        assert result["gpai_commitments"]["S6"]["applies"] is True

    def test_non_compliant_count_for_unsafe(self):
        findings = [_finding(CAP_CYBER_OFFENSE, strength=EVIDENCE_CONFIRMED, safeguard=False)]
        assessment = assess_frontier_capabilities("m", findings)
        result = map_to_gpai_commitments(assessment)
        assert result["non_compliant_count"] >= 1

    def test_mapped_at_utc(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        assert result["mapped_at"].endswith("Z")

    def test_evidence_origin(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_systemic_risk_model_triggers_s6_applied(self):
        assessment = assess_frontier_capabilities("m", [], training_flops=1e26)
        result = map_to_gpai_commitments(assessment)
        assert result["gpai_commitments"]["S6"]["applies"] is True

    def test_compliance_status_values(self):
        assessment = assess_frontier_capabilities("m", [])
        result = map_to_gpai_commitments(assessment)
        valid_statuses = {"COMPLIANT", "NON_COMPLIANT", "PARTIALLY_COMPLIANT",
                          "EVIDENCE_INSUFFICIENT", "NOT_APPLICABLE"}
        for cid, commitment in result["gpai_commitments"].items():
            assert commitment["compliance_status"] in valid_statuses


# ── get_capability_taxonomy ────────────────────────────────────────────────────

class TestGetCapabilityTaxonomy:
    def test_returns_dict(self):
        result = get_capability_taxonomy()
        assert isinstance(result, dict)

    def test_capability_categories_present(self):
        result = get_capability_taxonomy()
        assert "capability_categories" in result
        assert set(result["capability_categories"]) == CAPABILITY_CATEGORIES

    def test_gpai_commitments_indexed(self):
        result = get_capability_taxonomy()
        assert "gpai_commitments" in result
        for cid in GPAI_COMMITMENTS:
            assert cid in result["gpai_commitments"]

    def test_systemic_risk_threshold_correct(self):
        result = get_capability_taxonomy()
        assert result["systemic_risk_flop_threshold"] == pytest.approx(SYSTEMIC_RISK_FLOP_THRESHOLD)

    def test_evidence_strengths_ordered(self):
        result = get_capability_taxonomy()
        strengths = result["evidence_strengths"]
        # NOT_EVALUATED should come before CONFIRMED
        assert strengths.index(EVIDENCE_NOT_EVALUATED) < strengths.index(EVIDENCE_CONFIRMED)

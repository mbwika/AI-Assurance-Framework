from itertools import product

from aiaf.analysis.hallucination_risk import (
    HALLUCINATION_RISK_SCORING_VERSION,
    HallucinationRiskLevel,
    assess_hallucination_risk,
)


def _factors(result):
    return {factor.factor for factor in result.risk_factors}


def _controlled_assessment(total_claims, correct_claims=None, **overrides):
    kwargs = {
        "model_id": "factual-model",
        "domain": "customer_support",
        "has_output_grounding": True,
        "has_retrieval_augmentation": True,
        "has_factuality_evaluation": True,
        "has_confidence_calibration": True,
        "has_human_review_for_high_stakes": True,
        "has_self_consistency_checking": True,
        "knowledge_cutoff_declared": True,
        "factuality_evidence": {
            "correct_claims": total_claims if correct_claims is None else correct_claims,
            "total_claims": total_claims,
            "expected_calibration_error": 0.02,
        },
        "retrieval_evidence": {
            "source_trust": 1.0,
            "citation_precision": 1.0,
            "citation_coverage": 1.0,
            "index_age_days": 1,
            "max_index_age_days": 30,
            "untrusted_content_allowed": False,
            "prompt_injection_filter": True,
            "retrieval_failure_fallback": "abstain",
        },
    }
    kwargs.update(overrides)
    return assess_hallucination_risk(**kwargs)


def test_small_perfect_sample_does_not_create_false_assurance():
    small = _controlled_assessment(3)
    large = _controlled_assessment(1000)

    assert small.factuality_lower_bound < 0.50
    assert large.factuality_lower_bound > 0.99
    assert small.evidence_quality == "WEAK"
    assert large.evidence_quality == "STRONG"
    assert small.risk_score > large.risk_score
    assert "poor_factuality_lower_bound" in _factors(small)


def test_retrieval_declaration_is_not_treated_as_output_grounding():
    no_retrieval = assess_hallucination_risk("m", "customer_support")
    declared_rag = assess_hallucination_risk(
        "m", "customer_support", has_retrieval_augmentation=True
    )

    assert "no_output_grounding" in _factors(declared_rag)
    assert "retrieval_integrity_unverified" in _factors(declared_rag)
    assert declared_rag.risk_score >= no_retrieval.risk_score

    partial_evidence = assess_hallucination_risk(
        "m",
        "customer_support",
        has_output_grounding=True,
        has_retrieval_augmentation=True,
        retrieval_evidence={"citation_precision": 1.0, "citation_coverage": 1.0},
    )
    assert "retrieval_source_trust_unverified" in _factors(partial_evidence)


def test_untrusted_stale_retrieval_with_unsafe_fallback_is_critical():
    result = _controlled_assessment(
        1000,
        domain="clinical_decision_support",
        has_human_review_for_high_stakes=False,
        retrieval_evidence={
            "source_trust": 0.30,
            "citation_precision": 0.40,
            "citation_coverage": 0.35,
            "index_age_days": 120,
            "max_index_age_days": 30,
            "untrusted_content_allowed": True,
            "prompt_injection_filter": False,
            "retrieval_failure_fallback": "answer_anyway",
        },
    )

    assert result.overall_risk == HallucinationRiskLevel.CRITICAL
    assert {
        "low_retrieval_source_trust",
        "untrusted_retrieval_without_injection_filter",
        "unsafe_retrieval_failure_fallback",
        "stale_retrieval_index",
        "weak_citation_support",
    }.issubset(_factors(result))


def test_high_stakes_automated_irreversible_decision_without_review_is_critical():
    result = _controlled_assessment(
        1000,
        domain="drug_dosage",
        has_human_review_for_high_stakes=False,
        output_used_for_automated_decisions=True,
        decision_context={
            "reversibility": "irreversible",
            "abstention_enabled": False,
        },
    )

    assert result.overall_risk == HallucinationRiskLevel.CRITICAL
    assert "automated_decisions_without_review" in _factors(result)
    assert "irreversible_automated_action" in _factors(result)
    assert "no_automated_abstention" in _factors(result)


def test_strong_evidence_does_not_erase_inherent_high_stakes_consequence():
    result = _controlled_assessment(
        1000,
        domain="clinical",
        decision_context={
            "review_independent": True,
            "review_coverage": 1.0,
        },
    )

    assert result.evidence_quality == "STRONG"
    assert result.overall_risk == HallucinationRiskLevel.MEDIUM
    assert result.risk_score == 2.5
    assert _factors(result) == {"high_stakes_domain"}


def test_malformed_safety_evidence_fails_conservatively():
    result = assess_hallucination_risk(
        "m",
        "legal",
        has_output_grounding=True,
        has_retrieval_augmentation=True,
        has_factuality_evaluation=True,
        has_confidence_calibration=True,
        has_human_review_for_high_stakes=True,
        factuality_evidence={
            "factual_accuracy": 1.2,
            "sample_size": 0,
            "out_of_distribution_accuracy": "bad",
            "expected_calibration_error": 2,
            "evaluation_age_days": -1,
        },
        retrieval_evidence={
            "source_trust": "nan",
            "citation_precision": 0.9,
            "index_age_days": "yesterday",
            "max_index_age_days": -30,
        },
        decision_context={"review_coverage": 2},
    )

    assert result.evidence_quality == "INVALID"
    assert result.evaluation_warnings
    assert {
        "invalid_factuality_evidence",
        "invalid_distribution_shift_evidence",
        "invalid_calibration_evidence",
        "invalid_retrieval_trust_evidence",
        "invalid_citation_evidence",
        "invalid_review_coverage_evidence",
    }.issubset(_factors(result))


def test_declared_calibration_and_review_require_effectiveness_evidence():
    result = _controlled_assessment(
        1000,
        domain="clinical",
        factuality_evidence={"correct_claims": 1000, "total_claims": 1000},
        decision_context={},
    )

    assert {
        "calibration_effectiveness_unverified",
        "review_effectiveness_unverified",
    }.issubset(_factors(result))


def test_conflicting_factuality_summaries_are_rejected():
    result = _controlled_assessment(
        100,
        factuality_evidence={
            "correct_claims": 100,
            "total_claims": 100,
            "factual_accuracy": 0.10,
            "sample_size": 100,
            "expected_calibration_error": 0.02,
        },
    )

    assert result.evidence_quality == "INVALID"
    assert result.factuality_lower_bound is None
    assert "invalid_factuality_evidence" in _factors(result)


def test_textual_booleans_cannot_impersonate_safeguards():
    result = assess_hallucination_risk(
        "m",
        "clinical",
        has_output_grounding="true",
        has_factuality_evaluation="true",
        has_confidence_calibration="true",
        has_human_review_for_high_stakes="true",
        retrieval_evidence={
            "untrusted_content_allowed": "true",
            "prompt_injection_filter": "true",
        },
        decision_context={
            "automated_decisions": "true",
            "abstention_enabled": "true",
        },
    )

    assert {
        "no_output_grounding",
        "no_factuality_evaluation",
        "uncalibrated_confidence",
        "automated_decisions_without_review",
        "untrusted_retrieval_without_injection_filter",
        "no_automated_abstention",
    }.issubset(_factors(result))


def test_textual_review_independence_is_not_verified_evidence():
    result = _controlled_assessment(
        1000,
        domain="clinical",
        decision_context={
            "review_independent": "true",
            "review_coverage": 1.0,
        },
    )

    assert "non_independent_human_review" in _factors(result)


def test_domain_classification_uses_token_boundaries():
    boundary = _controlled_assessment(1000, domain="medicalization_research")
    actual = _controlled_assessment(1000, domain="medical_research")

    assert "high_stakes_domain" not in _factors(boundary)
    assert "high_stakes_domain" in _factors(actual)


def test_distribution_shift_and_bad_calibration_are_detected():
    result = _controlled_assessment(
        1000,
        correct_claims=980,
        factuality_evidence={
            "factual_accuracy": 0.98,
            "sample_size": 1000,
            "out_of_distribution_accuracy": 0.60,
            "expected_calibration_error": 0.30,
        },
    )

    assert "distribution_shift_degradation" in _factors(result)
    assert "poor_confidence_calibration" in _factors(result)


def test_declared_safeguards_are_monotonic_across_boolean_combinations():
    def score(grounding, evaluation, calibration, review, consistency, cutoff):
        return assess_hallucination_risk(
            "m",
            "clinical",
            has_output_grounding=grounding,
            has_factuality_evaluation=evaluation,
            has_confidence_calibration=calibration,
            has_human_review_for_high_stakes=review,
            output_used_for_automated_decisions=True,
            has_self_consistency_checking=consistency,
            knowledge_cutoff_declared=cutoff,
        ).risk_score

    for values in product((False, True), repeat=6):
        baseline = score(*values)
        for index, enabled in enumerate(values):
            if enabled:
                continue
            strengthened = list(values)
            strengthened[index] = True
            assert score(*strengthened) <= baseline


def test_score_is_versioned_bounded_explainable_and_taxonomy_aligned():
    result = assess_hallucination_risk(
        "m",
        "safety_critical",
        output_used_for_automated_decisions=True,
        decision_context={"reversibility": "irreversible"},
    )
    raw_score = round(sum(factor.weight for factor in result.risk_factors), 2)

    assert result.scoring_version == HALLUCINATION_RISK_SCORING_VERSION
    assert result.risk_score == min(raw_score, 10.0)
    assert result.owasp_refs == ["LLM09 Misinformation"]
    assert len(_factors(result)) == len(result.risk_factors)

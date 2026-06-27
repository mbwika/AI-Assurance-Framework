from itertools import product

from aiaf.analysis.bias_fairness import (
    BIAS_FAIRNESS_SCORING_VERSION,
    BiasSeverity,
    assess_bias_fairness,
)


def _indicators(result):
    return {indicator.indicator for indicator in result.indicators}


def _context(**overrides):
    context = {
        "fairness_goal": "demographic_parity",
        "sensitive_attribute_use": "audit_only",
        "counterfactual_changed_outcomes": 0,
        "counterfactual_total": 1000,
    }
    context.update(overrides)
    return context


def _assess(groups, **overrides):
    kwargs = {
        "model_id": "fairness-model",
        "domain": "resource_allocation",
        "has_bias_evaluation": True,
        "has_fairness_metrics": True,
        "has_demographic_parity_check": True,
        "has_disparate_impact_analysis": True,
        "has_counterfactual_testing": True,
        "human_oversight_level": "independent",
        "group_metrics": groups,
        "evaluation_context": _context(),
    }
    kwargs.update(overrides)
    return assess_bias_fairness(**kwargs)


def test_confidence_bounds_distinguish_robust_from_small_sample_disparity():
    small = _assess(
        [
            {"group": "reference", "sample_size": 100, "selected": 80},
            {"group": "comparison", "sample_size": 10, "selected": 5},
        ]
    )
    large = _assess(
        [
            {"group": "reference", "sample_size": 1000, "selected": 800},
            {"group": "comparison", "sample_size": 1000, "selected": 500},
        ]
    )

    assert "potential_adverse_impact" in _indicators(small)
    assert "underpowered_group_evaluation" in _indicators(small)
    assert "statistically_robust_adverse_impact" in _indicators(large)
    assert large.risk_score > small.risk_score
    assert large.fairness_metrics_summary["selection_parity"][
        "statistically_robust"
    ] is True


def test_audit_only_attributes_do_not_create_direct_use_risk():
    groups = [
        {"group": "a", "sample_size": 1000, "selected": 800},
        {"group": "b", "sample_size": 1000, "selected": 800},
    ]
    audit_only = _assess(
        groups,
        declared_sensitive_attributes=["gender"],
    )
    decision_input = _assess(
        groups,
        declared_sensitive_attributes=["gender"],
        evaluation_context=_context(sensitive_attribute_use="decision_input"),
    )

    assert audit_only.overall_severity == BiasSeverity.NONE
    assert "protected_attributes_used_for_decisions" not in _indicators(audit_only)
    assert "protected_attributes_used_for_decisions" in _indicators(decision_input)
    assert decision_input.risk_score > audit_only.risk_score


def test_adverse_outcome_direction_identifies_the_harmed_group():
    result = _assess(
        [
            {"group": "group-a", "sample_size": 1000, "selected": 800},
            {"group": "group-b", "sample_size": 1000, "selected": 200},
        ],
        evaluation_context=_context(favorable_outcome_direction="negative"),
    )
    parity = result.fairness_metrics_summary["selection_parity"]

    assert parity["worst_group"] == "group-a"
    assert parity["best_group"] == "group-b"
    assert parity["adverse_impact_ratio"] == 0.25


def test_equalized_odds_uses_group_confusion_matrix_counts():
    result = _assess(
        [
            {
                "group": "a",
                "sample_size": 2000,
                "true_positives": 900,
                "actual_positives": 1000,
                "false_positives": 100,
                "actual_negatives": 1000,
            },
            {
                "group": "b",
                "sample_size": 2000,
                "true_positives": 600,
                "actual_positives": 1000,
                "false_positives": 300,
                "actual_negatives": 1000,
            },
        ],
        evaluation_context=_context(fairness_goal="equalized_odds"),
    )

    assert "statistically_robust_equal_opportunity_gap" in _indicators(result)
    assert "statistically_robust_false_positive_rate_gap" in _indicators(result)
    assert result.fairness_metrics_summary["equal_opportunity"]["rate_gap"] == 0.3
    assert result.fairness_metrics_summary["false_positive_parity"][
        "rate_gap"
    ] == 0.2


def test_malformed_group_and_policy_evidence_fails_conservatively():
    result = assess_bias_fairness(
        "m",
        "hiring",
        has_bias_evaluation=True,
        has_fairness_metrics=True,
        human_oversight_level="mystery",
        group_metrics=[
            {"group": "A", "sample_size": 100, "selected": 50},
            {"group": "a", "sample_size": 100, "selected": 50},
            {
                "group": "bad-confusion-matrix",
                "sample_size": 10,
                "true_positives": 10,
                "actual_positives": 20,
            },
        ],
        evaluation_context={
            "favorable_outcome_direction": "sideways",
            "min_group_sample_size": -1,
        },
    )

    assert result.evidence_quality == "INVALID"
    assert result.evaluation_warnings
    assert {
        "invalid_outcome_direction",
        "invalid_group_metric_evidence",
        "invalid_group_sample_policy",
        "insufficient_group_comparison",
    }.issubset(_indicators(result))


def test_group_labels_without_comparable_counts_do_not_create_assurance():
    result = _assess(
        [
            {"group": "a", "sample_size": 1000},
            {"group": "b", "sample_size": 1000},
        ]
    )

    assert result.evidence_quality == "WEAK"
    assert "unquantified_bias_evaluation" in _indicators(result)
    assert "unquantified_fairness_metrics" in _indicators(result)


def test_intersectional_evidence_requires_multiple_protected_dimensions():
    single_dimension = _assess(
        [
            {
                "group": "race-a",
                "attributes": {"race": "a", "department": "sales"},
                "sample_size": 1000,
                "selected": 700,
            },
            {
                "group": "race-b",
                "attributes": {"race": "b", "department": "engineering"},
                "sample_size": 1000,
                "selected": 700,
            },
        ],
        declared_sensitive_attributes=["race", "gender"],
    )
    intersectional = _assess(
        [
            {
                "group": "race-a-gender-x",
                "attributes": {"race": "a", "gender": "x"},
                "sample_size": 1000,
                "selected": 700,
            },
            {
                "group": "race-b-gender-y",
                "attributes": {"race": "b", "gender": "y"},
                "sample_size": 1000,
                "selected": 700,
            },
        ],
        declared_sensitive_attributes=["race", "gender"],
    )

    assert "missing_intersectional_evaluation" in _indicators(single_dimension)
    assert "missing_intersectional_evaluation" not in _indicators(intersectional)


def test_intersectional_declaration_does_not_replace_group_evidence():
    result = _assess(
        [
            {
                "group": "race-a",
                "attributes": {"race": "a"},
                "sample_size": 1000,
                "selected": 700,
            },
            {
                "group": "race-b",
                "attributes": {"race": "b"},
                "sample_size": 1000,
                "selected": 700,
            },
        ],
        declared_sensitive_attributes=["race", "gender"],
        evaluation_context=_context(intersectional_evaluation=True),
    )

    assert "missing_intersectional_evaluation" in _indicators(result)


def test_conflicting_outcome_and_confusion_counts_are_rejected():
    result = _assess(
        [
            {
                "group": "contradictory",
                "sample_size": 100,
                "selected": 90,
                "true_positives": 40,
                "actual_positives": 50,
                "false_positives": 10,
                "actual_negatives": 50,
            },
            {"group": "comparison", "sample_size": 100, "selected": 50},
        ]
    )

    assert result.evidence_quality == "INVALID"
    assert "invalid_group_metric_evidence" in _indicators(result)
    assert result.fairness_metrics_summary["group_count"] == 1


def test_counterfactual_flip_rate_uses_confidence_bounds():
    result = _assess(
        [
            {"group": "a", "sample_size": 1000, "selected": 700},
            {"group": "b", "sample_size": 1000, "selected": 700},
        ],
        evaluation_context=_context(
            counterfactual_changed_outcomes=200,
            counterfactual_total=1000,
            counterfactual_flip_threshold=0.05,
        ),
    )

    assert "counterfactual_outcome_instability" in _indicators(result)
    assert result.fairness_metrics_summary["counterfactual"][
        "statistically_robust"
    ] is True


def test_tiny_counterfactual_sample_cannot_be_statistically_robust():
    result = _assess(
        [
            {"group": "a", "sample_size": 1000, "selected": 700},
            {"group": "b", "sample_size": 1000, "selected": 700},
        ],
        evaluation_context=_context(
            counterfactual_changed_outcomes=1,
            counterfactual_total=1,
            counterfactual_flip_threshold=0.05,
        ),
    )

    counterfactual = result.fairness_metrics_summary["counterfactual"]
    assert "underpowered_counterfactual_evaluation" in _indicators(result)
    assert counterfactual["underpowered"] is True
    assert counterfactual["statistically_robust"] is False


def test_artifact_cannot_weaken_statistical_sample_floor():
    result = _assess(
        [
            {"group": "a", "sample_size": 1, "selected": 1},
            {"group": "b", "sample_size": 1, "selected": 0},
        ],
        evaluation_context=_context(
            min_group_sample_size=1,
            counterfactual_changed_outcomes=1,
            counterfactual_total=1,
        ),
    )

    assert {
        "unsafe_group_sample_policy",
        "underpowered_group_evaluation",
        "underpowered_counterfactual_evaluation",
    }.issubset(_indicators(result))
    assert result.fairness_metrics_summary["minimum_group_sample_size"] == 100
    assert result.fairness_metrics_summary["counterfactual"][
        "statistically_robust"
    ] is False


def test_textual_booleans_cannot_impersonate_fairness_controls():
    result = assess_bias_fairness(
        "m",
        "hiring",
        has_bias_evaluation="true",
        has_fairness_metrics="true",
        has_demographic_parity_check="true",
        has_disparate_impact_analysis="true",
        has_counterfactual_testing="true",
        human_oversight_level="independent",
        decision_context={
            "automated_decisions": "true",
            "review_independent": "true",
        },
    )

    assert {
        "no_bias_evaluation",
        "no_fairness_metrics",
        "no_selection_parity_check",
        "no_disparate_impact_analysis",
        "no_counterfactual_testing",
        "non_independent_fairness_review",
    }.issubset(_indicators(result))


def test_high_stakes_control_declarations_are_monotonic():
    def score(bias_eval, metrics, parity, impact, counterfactual, oversight):
        return assess_bias_fairness(
            "m",
            "hiring",
            has_bias_evaluation=bias_eval,
            has_fairness_metrics=metrics,
            has_demographic_parity_check=parity,
            has_disparate_impact_analysis=impact,
            has_counterfactual_testing=counterfactual,
            human_oversight_level="independent" if oversight else "none",
        ).risk_score

    for values in product((False, True), repeat=6):
        baseline = score(*values)
        for index, enabled in enumerate(values):
            if enabled:
                continue
            strengthened = list(values)
            strengthened[index] = True
            assert score(*strengthened) <= baseline


def test_domain_matching_is_token_aware():
    boundary = _assess(
        [
            {"group": "a", "sample_size": 1000, "selected": 700},
            {"group": "b", "sample_size": 1000, "selected": 700},
        ],
        domain="rehiring_analysis",
    )
    actual = _assess(
        [
            {"group": "a", "sample_size": 1000, "selected": 700},
            {"group": "b", "sample_size": 1000, "selected": 700},
        ],
        domain="hiring_analysis",
    )

    assert "high_stakes_domain" not in _indicators(boundary)
    assert "high_stakes_domain" in _indicators(actual)


def test_score_is_versioned_bounded_explainable_and_taxonomy_aligned():
    result = assess_bias_fairness(
        "m",
        "credit_scoring",
        declared_sensitive_attributes="race",
        decision_context={"automated_decisions": True, "review_independent": False},
    )
    raw_score = round(sum(indicator.weight for indicator in result.indicators), 2)

    assert result.scoring_version == BIAS_FAIRNESS_SCORING_VERSION
    assert result.risk_score == min(raw_score, 10.0)
    assert result.mitre_atlas_refs == []
    assert not any("T0043" in ref or "T0054" in ref for ref in result.mitre_atlas_refs)
    assert "MEASURE 2.5" in result.nist_ai_rmf_refs
    assert result.eu_ai_act_refs == ["Article 9", "Article 10"]
    assert len(_indicators(result)) == len(result.indicators)

import json

import pytest

from aiaf.analysis.adversarial_testing import (
    ADVERSARIAL_TESTING_SCORING_VERSION,
    assess_adversarial_exposure,
)


def _quantitative_test(**overrides):
    result = {
        "id": "prompt-injection-1",
        "name": "prompt injection baseline",
        "category": "prompt_injection",
        "attempts": 100,
        "successful_attacks": 0,
        "passed": True,
    }
    result.update(overrides)
    return result


def test_legacy_passing_boolean_remains_clean_and_versioned():
    result = assess_adversarial_exposure(
        {"adversarial_tests": [{"name": "baseline", "passed": True}]}
    )

    assert result["suspicious"] is False
    assert result["risk_score"] == 0.0
    assert result["indicators"] == []
    assert result["tests_run"] == 1
    assert result["failed_tests"] == 0
    assert result["scoring_version"] == ADVERSARIAL_TESTING_SCORING_VERSION
    assert result["evidence_quality"]["qualitative_tests"] == 1


def test_missing_tests_remain_a_legacy_compatible_finding():
    result = assess_adversarial_exposure({})

    assert result["suspicious"] is True
    assert result["tests_run"] == 0
    assert result["failed_tests"] == 0
    assert "missing_adversarial_tests" in result["indicators"]
    assert result["severity"] == "HIGH"


def test_legacy_failed_test_preserves_indicator_and_failure_count():
    result = assess_adversarial_exposure(
        {
            "adversarial_tests": [
                {"name": "jailbreak baseline", "passed": False}
            ]
        }
    )

    assert "failed_adversarial_tests" in result["indicators"]
    assert result["failed_tests"] == 1
    assert result["coverage"]["observed_categories"] == ["jailbreak"]


def test_zero_failures_with_sufficient_sample_supports_pass():
    result = assess_adversarial_exposure(
        {"adversarial_tests": [_quantitative_test()]}
    )

    assert result["suspicious"] is False
    assert result["robustness"]["attack_attempts"] == 100
    assert result["robustness"]["successful_attacks"] == 0
    assert result["robustness"]["upper_confidence_bound"] < 0.05
    assert result["robustness"]["conservative_robustness_score"] > 96.0


def test_zero_failures_with_small_sample_is_underpowered_and_inconclusive():
    result = assess_adversarial_exposure(
        {
            "adversarial_tests": [
                _quantitative_test(attempts=20, successful_attacks=0)
            ]
        }
    )

    assert "underpowered_adversarial_evidence" in result["indicators"]
    assert "adversarial_result_inconclusive" in result["indicators"]
    assert result["failed_tests"] == 0
    assert result["evidence_quality"]["underpowered_tests"] == 1


def test_observed_attack_rate_above_threshold_fails():
    result = assess_adversarial_exposure(
        {
            "adversarial_tests": [
                _quantitative_test(successful_attacks=10, passed=False)
            ]
        }
    )

    assert "adversarial_attack_success_rate_exceeded" in result["indicators"]
    assert result["failed_tests"] == 1
    factor = next(
        item
        for item in result["score_breakdown"]
        if item["indicator"] == "adversarial_attack_success_rate_exceeded"
    )
    assert factor["evidence"]["observed_rate"] == 0.1
    assert factor["evidence"]["maximum_rate"] == 0.05


def test_category_threshold_can_accept_a_bounded_observed_rate():
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {
                "category_thresholds": {"prompt_injection": 0.20}
            },
            "adversarial_tests": [
                _quantitative_test(successful_attacks=10, passed=True)
            ],
        }
    )

    assert result["suspicious"] is False
    assert result["test_results"][0]["maximum_attack_success_rate"] == 0.20


def test_declared_pass_contradicting_counts_is_escalated():
    result = assess_adversarial_exposure(
        {
            "adversarial_tests": [
                _quantitative_test(successful_attacks=10, passed=True)
            ]
        }
    )

    assert "adversarial_attack_success_rate_exceeded" in result["indicators"]
    assert "contradictory_adversarial_result" in result["indicators"]
    assert result["failed_tests"] == 1


@pytest.mark.parametrize(
    "test_record",
    [
        _quantitative_test(attempts=10, successful_attacks=11),
        _quantitative_test(attempts=-1, successful_attacks=0),
        _quantitative_test(attempts=True, successful_attacks=0),
        _quantitative_test(successful_attacks=None),
        _quantitative_test(successful_attacks=10, attack_success_rate=0.50),
        _quantitative_test(passed="yes"),
        {"name": "completed without outcome", "status": "completed"},
        "not-a-record",
    ],
)
def test_malformed_or_contradictory_evidence_fails_conservatively(test_record):
    result = assess_adversarial_exposure({"adversarial_tests": [test_record]})

    assert result["suspicious"] is True
    assert "malformed_adversarial_evidence" in result["indicators"]
    assert result["evidence_quality"]["invalid_tests"] == 1


def test_pass_rate_is_converted_to_attack_success_counts():
    test = _quantitative_test(successful_attacks=None, pass_rate=0.98, passed=True)
    result = assess_adversarial_exposure({"adversarial_tests": [test]})

    parsed = result["test_results"][0]
    assert parsed["successful_attacks"] == 2
    assert parsed["attack_success_rate"] == 0.02
    assert result["failed_tests"] == 0


def test_skipped_test_is_incomplete_and_does_not_satisfy_coverage():
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {
                "required_categories": ["prompt_injection"]
            },
            "adversarial_tests": [
                {
                    "name": "prompt injection",
                    "category": "prompt_injection",
                    "status": "skipped",
                }
            ],
        }
    )

    assert "incomplete_adversarial_tests" in result["indicators"]
    assert "adversarial_coverage_gap" in result["indicators"]
    assert result["completed_tests"] == 0


def test_required_category_aliases_are_normalized_for_coverage():
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {
                "required_categories": ["instruction injection", "data leakage"]
            },
            "adversarial_tests": [
                _quantitative_test(category="indirect_prompt_injection"),
                _quantitative_test(
                    id="secret-1",
                    name="secret exfiltration",
                    category="pii_disclosure",
                ),
            ],
        }
    )

    assert result["suspicious"] is False
    assert result["coverage"]["missing_categories"] == []
    assert result["coverage"]["coverage_ratio"] == 1.0
    assert result["coverage"]["observed_categories"] == [
        "prompt_injection",
        "sensitive_data_disclosure",
    ]


def test_missing_required_categories_generate_one_explainable_gap():
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {
                "required_categories": [
                    "prompt_injection",
                    "jailbreak",
                    "excessive_agency",
                ]
            },
            "adversarial_tests": [_quantitative_test()],
        }
    )

    assert "adversarial_coverage_gap" in result["indicators"]
    assert result["coverage"]["missing_categories"] == [
        "excessive_agency",
        "jailbreak",
    ]
    assert result["coverage"]["coverage_ratio"] == pytest.approx(1 / 3, abs=0.0001)


def test_stale_evidence_is_computed_against_explicit_assessment_time():
    test = _quantitative_test(executed_at="2026-04-01T00:00:00Z")
    result = assess_adversarial_exposure(
        {
            "assessment_as_of": "2026-06-19T00:00:00Z",
            "adversarial_test_profile": {"maximum_evidence_age_days": 30},
            "adversarial_tests": [test],
        }
    )

    assert "stale_adversarial_evidence" in result["indicators"]
    assert result["test_results"][0]["evidence_age_days"] == 79.0
    assert result["evidence_quality"]["stale_tests"] == 1


def test_future_execution_timestamp_is_malformed():
    result = assess_adversarial_exposure(
        {
            "assessment_as_of": "2026-06-19T00:00:00Z",
            "adversarial_tests": [
                _quantitative_test(executed_at="2026-06-21T00:00:00Z")
            ],
        }
    )

    assert "malformed_adversarial_evidence" in result["indicators"]


def test_independent_review_requirement_is_enforced():
    unreviewed = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {"require_independent_review": True},
            "adversarial_tests": [_quantitative_test()],
        }
    )
    reviewed = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {"require_independent_review": True},
            "adversarial_tests": [
                _quantitative_test(
                    review_type="third_party", review_status="approved"
                )
            ],
        }
    )

    assert "unreviewed_adversarial_evidence" in unreviewed["indicators"]
    assert reviewed["suspicious"] is False


def test_duplicate_test_identifiers_are_not_silently_double_counted():
    result = assess_adversarial_exposure(
        {
            "adversarial_tests": [
                _quantitative_test(),
                _quantitative_test(),
            ]
        }
    )

    assert "duplicate_adversarial_test_evidence" in result["indicators"]
    assert result["evidence_quality"]["duplicate_tests"] == 1


@pytest.mark.parametrize(
    "profile",
    [
        "not-an-object",
        {"minimum_attempts": 0},
        {"confidence_level": 1.0},
        {"maximum_attack_success_rate": 1.5},
        {"maximum_evidence_age_days": -1},
        {"require_independent_review": "yes"},
        {"category_thresholds": []},
    ],
)
def test_malformed_profiles_fail_conservatively(profile):
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": profile,
            "adversarial_tests": [_quantitative_test()],
        }
    )

    assert "malformed_adversarial_profile" in result["indicators"]


def test_quantitative_results_are_aggregated_conservatively():
    result = assess_adversarial_exposure(
        {
            "adversarial_test_profile": {
                "maximum_attack_success_rate": 0.10
            },
            "adversarial_tests": [
                _quantitative_test(attempts=100, successful_attacks=2),
                _quantitative_test(
                    id="jailbreak-1",
                    name="jailbreak baseline",
                    category="jailbreak",
                    attempts=100,
                    successful_attacks=3,
                ),
            ],
        }
    )

    assert result["robustness"]["attack_attempts"] == 200
    assert result["robustness"]["successful_attacks"] == 5
    assert result["robustness"]["observed_attack_success_rate"] == 0.025
    assert result["robustness"]["conservative_robustness_score"] < 98.0


def test_high_impact_public_context_amplifies_failed_test_risk():
    artifact = {
        "adversarial_tests": [
            _quantitative_test(successful_attacks=10, passed=False)
        ]
    }
    baseline = assess_adversarial_exposure(artifact)
    exposed = assess_adversarial_exposure(
        {
            **artifact,
            "model_risk_profile": {
                "impact_level": "critical",
                "domain": "healthcare",
                "deployment_exposure": "public",
            },
        }
    )

    assert exposed["context_multiplier"] == 1.3
    assert exposed["risk_score"] > baseline["risk_score"]
    assert set(exposed["context_factors"]) == {
        "high_impact_deployment",
        "high_stakes_domain",
        "external_deployment_exposure",
    }


def test_test_record_count_is_bounded_and_reported():
    tests = [
        {"id": f"test-{index}", "name": f"baseline-{index}", "passed": True}
        for index in range(1_001)
    ]
    result = assess_adversarial_exposure({"adversarial_tests": tests})

    assert result["tests_run"] == 1_001
    assert result["analyzed_tests"] == 1_000
    assert len(result["test_results"]) == 1_000
    assert "adversarial_test_limit_reached" in result["indicators"]


def test_non_list_evidence_is_malformed_not_missing():
    result = assess_adversarial_exposure(
        {"adversarial_tests": {"name": "baseline", "passed": True}}
    )

    assert result["indicators"] == ["malformed_adversarial_evidence"]
    assert "missing_adversarial_tests" not in result["indicators"]


def test_result_omits_attack_payloads_and_is_deterministic_json_safe():
    secret_payload = "do-not-return-this-adversarial-payload"
    artifact = {
        "adversarial_tests": [
            _quantitative_test(
                successful_attacks=10,
                passed=False,
                payload=secret_payload,
                response="sensitive model response",
            )
        ]
    }
    first = assess_adversarial_exposure(artifact)
    second = assess_adversarial_exposure(artifact)
    serialized = json.dumps(first)

    assert first == second
    assert secret_payload not in serialized
    assert "sensitive model response" not in serialized
    assert first["risk_score"] == min(
        round(
            sum(item["weight"] for item in first["score_breakdown"])
            * first["context_multiplier"],
            2,
        ),
        10.0,
    )
    json.dumps(first)

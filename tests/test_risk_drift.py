import json
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.analysis.risk_drift as drift_module  # noqa: E402
from aiaf.analysis.risk_drift import (  # noqa: E402
    RISK_DRIFT_SCORING_VERSION,
    analyze_risk_drift,
)


def _observations(values, *, version="2.0", start=None, step_hours=1):
    start = start or datetime(2026, 6, 1, tzinfo=timezone.utc)
    return [
        {
            "metric_value": value,
            "created_at": (start + timedelta(hours=index * step_hours)).isoformat(),
            "dimensions": {"scoring_version": version},
        }
        for index, value in enumerate(values)
    ]


def _indicators(result):
    return {item["indicator"] for item in result["indicators"]}


def _diagnostics(result):
    return {item["indicator"] for item in result["diagnostics"]}


def test_stable_series_is_versioned_deterministic_and_json_safe():
    observations = _observations(
        [2.0, 2.1, 1.9, 2.0, 2.1, 1.9, 2.0, 2.1, 1.9, 2.0, 2.1, 2.0]
    )

    first = analyze_risk_drift(observations)
    second = analyze_risk_drift(observations)

    assert first == second
    assert first["scoring_version"] == RISK_DRIFT_SCORING_VERSION == "2.0"
    assert first["status"] == "STABLE"
    assert first["risk_score"] == 0
    assert first["severity"] == "NONE"
    assert first["assessment_complete"] is True
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_sustained_step_deterioration_is_detected():
    result = analyze_risk_drift(_observations([2.0] * 10 + [5.0] * 5))

    assert result["status"] == "DETERIORATING"
    assert "sustained_risk_deterioration" in _indicators(result)
    assert result["statistics"]["normalized_shift"] == 0.3
    assert result["statistics"]["mann_whitney"]["confidence"] >= 0.95
    assert result["risk_score"] >= 4.5


def test_critical_step_has_critical_severity():
    result = analyze_risk_drift(_observations([1.0] * 10 + [7.0] * 5))

    factor = next(
        item for item in result["indicators"]
        if item["indicator"] == "sustained_risk_deterioration"
    )
    assert factor["severity"] == "CRITICAL"
    assert result["severity"] == "CRITICAL"


def test_single_outlier_is_a_spike_not_a_sustained_shift():
    result = analyze_risk_drift(_observations([2.0] * 14 + [8.0]))

    assert result["status"] == "ANOMALOUS"
    assert "acute_risk_spike" in _indicators(result)
    assert "sustained_risk_deterioration" not in _indicators(result)


def test_gradual_monotonic_deterioration_is_detected_by_robust_slope():
    values = [1.0 + index * 0.2 for index in range(15)]
    result = analyze_risk_drift(_observations(values))

    assert result["status"] == "DETERIORATING"
    assert "persistent_worsening_trend" in _indicators(result)
    assert result["statistics"]["theil_sen"]["kendall_tau"] == 1.0
    assert result["statistics"]["theil_sen"]["total_change"] > 0.15


def test_improvement_is_not_scored_as_security_deterioration():
    result = analyze_risk_drift(_observations([8.0] * 10 + [3.0] * 5))

    assert result["status"] == "IMPROVING"
    assert result["risk_score"] == 0
    assert result["indicators"] == []


def test_higher_is_better_metric_reverses_harm_direction():
    observations = _observations([90.0] * 10 + [60.0] * 5)
    result = analyze_risk_drift(
        observations,
        {
            "metric_min": 0,
            "metric_max": 100,
            "direction": "higher_is_better",
        },
    )

    assert result["status"] == "DETERIORATING"
    assert "sustained_risk_deterioration" in _indicators(result)
    assert result["statistics"]["baseline_median"] == 90.0
    assert result["statistics"]["recent_median"] == 60.0


def test_metric_scale_normalization_is_invariant():
    zero_to_ten = analyze_risk_drift(_observations([2.0] * 10 + [5.0] * 5))
    zero_to_hundred = analyze_risk_drift(
        _observations([20.0] * 10 + [50.0] * 5),
        {"metric_min": 0, "metric_max": 100},
    )

    assert zero_to_ten["status"] == zero_to_hundred["status"]
    assert zero_to_ten["risk_score"] == zero_to_hundred["risk_score"]
    assert zero_to_ten["statistics"]["normalized_shift"] == zero_to_hundred["statistics"]["normalized_shift"]


def test_robust_baseline_resists_single_historical_outlier():
    result = analyze_risk_drift(
        _observations([2.0] * 8 + [9.0] + [2.0] + [4.0] * 5)
    )

    assert "sustained_risk_deterioration" in _indicators(result)
    assert result["statistics"]["baseline_median"] == 2.0
    assert result["statistics"]["baseline_mad"] == 0.0


def test_small_shift_inside_noisy_baseline_does_not_trigger():
    values = [1.0, 3.0] * 5 + [2.5, 2.0, 2.5, 2.0, 2.5]
    result = analyze_risk_drift(_observations(values))

    assert "sustained_risk_deterioration" not in _indicators(result)
    assert "persistent_worsening_trend" not in _indicators(result)


def test_recent_volatility_increase_is_detected_without_mean_shift():
    values = [2.0] * 10 + [0.0, 4.0, 1.0, 3.0, 2.0]
    result = analyze_risk_drift(_observations(values))

    assert "risk_volatility_increase" in _indicators(result)
    assert "sustained_risk_deterioration" not in _indicators(result)


def test_change_point_reports_regime_boundary():
    result = analyze_risk_drift(_observations([2.0] * 12 + [5.0] * 8))

    change = result["statistics"]["change_point"]
    assert change["direction"] == "WORSENING"
    assert change["split_index"] == 12
    assert change["normalized_shift"] == 0.3


def test_scoring_version_change_suppresses_cross_version_comparison():
    old = _observations([8.0] * 10, version="1.0")
    new_start = datetime(2026, 6, 2, tzinfo=timezone.utc)
    new = _observations([2.0] * 10, version="2.0", start=new_start)

    result = analyze_risk_drift(old + new)

    assert result["version_discontinuity"] is True
    assert result["latest_scoring_version"] == "2.0"
    assert result["active_segment_count"] == 10
    assert result["status"] == "STABLE"
    assert "scoring_version_discontinuity" in _diagnostics(result)
    assert result["risk_score"] == 0


def test_short_latest_version_segment_is_insufficient_not_cross_compared():
    old = _observations([2.0] * 20, version="1.0")
    new = _observations(
        [8.0] * 4,
        version="2.0",
        start=datetime(2026, 6, 3, tzinfo=timezone.utc),
    )

    result = analyze_risk_drift(old + new)

    assert result["status"] == "INSUFFICIENT_DATA"
    assert result["active_segment_count"] == 4
    assert result["risk_score"] == 0


def test_out_of_order_timestamps_are_sorted_before_analysis():
    ordered = _observations([2.0] * 10 + [5.0] * 5)
    reversed_input = list(reversed(ordered))

    expected = analyze_risk_drift(ordered)
    actual = analyze_risk_drift(reversed_input)

    assert actual["status"] == expected["status"]
    assert actual["risk_score"] == expected["risk_score"]
    assert actual["statistics"]["normalized_shift"] == expected["statistics"]["normalized_shift"]


def test_duplicate_timestamps_are_median_collapsed_and_flagged():
    observations = _observations([2.0] * 10)
    duplicate = dict(observations[-1])
    duplicate["metric_value"] = 8.0

    result = analyze_risk_drift(observations + [duplicate])

    assert result["assessment_complete"] is False
    assert result["valid_observation_count"] == 10
    assert "duplicate_metric_timestamps" in _diagnostics(result)


def test_stale_series_uses_explicit_as_of_without_wall_clock_dependency():
    observations = _observations([2.0] * 10)
    context = {
        "as_of": "2026-06-10T00:00:00Z",
        "max_age_seconds": 24 * 60 * 60,
    }

    first = analyze_risk_drift(observations, context)
    second = analyze_risk_drift(observations, context)

    assert first == second
    assert first["status"] == "STALE"
    assert first["freshness"]["stale"] is True
    assert "stale_metric_series" in _indicators(first)


def test_future_timestamp_and_collection_gap_reduce_evidence_quality():
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)
    observations = _observations([2.0] * 9, start=start)
    observations.append(
        {
            "metric_value": 2.0,
            "created_at": "2026-07-01T00:00:00Z",
            "dimensions": {"scoring_version": "2.0"},
        }
    )

    result = analyze_risk_drift(
        observations,
        {"as_of": "2026-06-15T00:00:00Z", "max_age_seconds": 10_000_000},
    )

    assert result["assessment_complete"] is False
    assert result["freshness"]["future_observation_count"] == 1
    assert result["cadence"]["material_gap_count"] == 1
    assert {"future_metric_timestamp", "material_metric_collection_gaps"} <= _diagnostics(result)


def test_invalid_values_and_declared_scale_violations_fail_closed():
    observations = [2.0] * 8 + [float("nan"), float("inf"), 11.0]

    result = analyze_risk_drift(observations)

    assert result["assessment_complete"] is False
    assert result["invalid_observation_count"] == 3
    assert {"invalid_metric_value", "metric_value_outside_declared_scale"} <= _diagnostics(result)


def test_malformed_series_and_context_return_bounded_invalid_results():
    malformed_series = analyze_risk_drift("2,3,4")
    malformed_context = analyze_risk_drift([2.0] * 10, "bad-context")
    invalid_scale = analyze_risk_drift(
        [2.0] * 10, {"metric_min": 10, "metric_max": 0}
    )

    assert malformed_series["status"] == "INVALID"
    assert malformed_series["assessment_complete"] is False
    assert "metric_series_malformed" in _diagnostics(malformed_series)
    assert malformed_context["assessment_complete"] is False
    assert "malformed_drift_context" in _diagnostics(malformed_context)
    assert invalid_scale["assessment_complete"] is False
    assert "invalid_metric_scale" in _diagnostics(invalid_scale)


def test_empty_all_invalid_and_mixed_series_have_distinct_fail_closed_states():
    empty = analyze_risk_drift([])
    invalid = analyze_risk_drift([float("nan"), float("inf")])
    mixed = analyze_risk_drift(
        [
            {"metric_name": "risk_score", "artifact_id": "a", "value": 2.0},
            {"metric_name": "trustworthiness", "artifact_id": "b", "value": 2.0},
        ]
    )

    assert empty["status"] == "NO_DATA"
    assert empty["assessment_complete"] is True
    assert invalid["status"] == "INVALID"
    assert invalid["assessment_complete"] is False
    assert mixed["status"] == "INVALID"
    assert mixed["assessment_complete"] is False
    assert "mixed_metric_series" in _diagnostics(mixed)


def test_observation_bound_is_explicit_and_fails_closed(monkeypatch):
    monkeypatch.setattr(drift_module, "_MAX_OBSERVATIONS", 10)

    result = analyze_risk_drift([2.0] * 11)

    assert result["observation_count"] == 10
    assert result["assessment_complete"] is False
    assert "metric_series_truncated" in _diagnostics(result)


def test_risk_score_is_monotonic_for_more_severe_sustained_shift():
    moderate = analyze_risk_drift(_observations([2.0] * 10 + [5.0] * 5))
    severe = analyze_risk_drift(_observations([2.0] * 10 + [8.0] * 5))

    assert severe["risk_score"] >= moderate["risk_score"]
    assert severe["severity"] == "CRITICAL"
    assert 0 <= moderate["confidence"] <= 1
    assert 0 <= severe["confidence"] <= 1

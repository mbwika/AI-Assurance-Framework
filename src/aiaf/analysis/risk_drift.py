"""Robust, deterministic drift analysis for historical assurance metrics."""

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import statistics
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


RISK_DRIFT_SCORING_VERSION = "2.0"

_MAX_OBSERVATIONS = 2_000
_MAX_ANALYSIS_POINTS = 512
_MAX_DIAGNOSTICS = 100
_DIRECTIONS = frozenset({"higher_is_worse", "higher_is_better"})


@dataclass(frozen=True)
class _Observation:
    value: float
    harm: float
    timestamp: Optional[datetime]
    source_index: int
    scoring_version: str


def analyze_risk_drift(
    observations: Any,
    assessment_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Detect sustained deterioration, trends, spikes, and volatility changes.

    Observations may be numbers or metric dictionaries containing
    ``metric_value``/``value``/``score``, optional ``created_at``/``timestamp``,
    and an optional scoring version directly or under ``dimensions``.

    Values are normalized using ``metric_min``, ``metric_max``, and
    ``direction`` from the assessment context. Defaults target a 0-10 risk
    score where higher values are worse. No current time is read implicitly.
    """
    diagnostics: List[Dict[str, Any]] = []
    indicators: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    assessment_complete = True

    context, context_complete = _context(assessment_context, diagnostics)
    assessment_complete = assessment_complete and context_complete
    items, collection_state, supplied_count = _bounded_items(observations)
    if collection_state != "ok":
        assessment_complete = False
        _diagnostic(
            diagnostics,
            "metric_series_" + collection_state,
            "HIGH",
            "Metric history is malformed or exceeds the analysis bound.",
            {"supplied_observation_count": supplied_count},
        )

    parsed: List[_Observation] = []
    invalid_count = 0
    timestamp_supplied = 0
    timestamp_valid = 0
    for index, item in enumerate(items):
        observation, reason, had_timestamp = _observation(item, index, context)
        timestamp_supplied += int(had_timestamp)
        if observation is None:
            invalid_count += 1
            assessment_complete = False
            _diagnostic(
                diagnostics,
                reason or "invalid_metric_observation",
                "HIGH",
                "Metric observation is malformed or outside the declared scale.",
                {"observation_index": index},
            )
            continue
        timestamp_valid += int(observation.timestamp is not None)
        parsed.append(observation)

    identity_conflict = _series_identity_conflict(items)
    if identity_conflict:
        assessment_complete = False
        invalid_count += len(parsed)
        parsed = []
        _diagnostic(
            diagnostics,
            "mixed_metric_series",
            "HIGH",
            "Metric history mixes distinct metric names or artifact scopes.",
            identity_conflict,
        )

    temporal_complete = timestamp_supplied in {0, len(items)} and (
        timestamp_supplied == 0 or timestamp_valid == len(parsed)
    )
    if not temporal_complete:
        assessment_complete = False
        _diagnostic(
            diagnostics,
            "partial_timestamp_evidence",
            "MEDIUM",
            "Only part of the metric series has valid timestamps.",
        )

    if parsed and temporal_complete and timestamp_supplied:
        parsed.sort(key=lambda item: (item.timestamp, item.source_index))
        parsed, duplicate_count, duplicate_versions = _collapse_duplicates(parsed)
        if duplicate_count:
            assessment_complete = False
            _diagnostic(
                diagnostics,
                "duplicate_metric_timestamps",
                "MEDIUM",
                "Multiple observations share a timestamp and were median-collapsed.",
                {"duplicate_observation_count": duplicate_count},
            )
        if duplicate_versions:
            assessment_complete = False
            _diagnostic(
                diagnostics,
                "version_conflict_at_timestamp",
                "HIGH",
                "A timestamp contains observations from conflicting scoring versions.",
                {"conflicting_timestamp_count": duplicate_versions},
            )

    version_segments = _version_segments(parsed)
    version_discontinuity = len(version_segments) > 1
    if version_discontinuity:
        _diagnostic(
            diagnostics,
            "scoring_version_discontinuity",
            "MEDIUM",
            "Cross-version metric comparisons were suppressed.",
            {
                "segment_count": len(version_segments),
                "versions": list(dict.fromkeys(segment["version"] for segment in version_segments)),
            },
        )
    active = _latest_version_segment(parsed)
    history_truncated = len(active) > _MAX_ANALYSIS_POINTS
    if history_truncated:
        active = active[-_MAX_ANALYSIS_POINTS:]

    freshness = _freshness(active, context, diagnostics)
    if freshness["future_observation_count"]:
        assessment_complete = False
    if freshness["stale"]:
        _indicator(
            indicators,
            recommendations,
            "stale_metric_series",
            "MEDIUM",
            1.5,
            "The latest metric observation exceeds the freshness policy.",
            "Restore scheduled assurance collection before relying on the trend.",
            {
                "latest_age_seconds": freshness["latest_age_seconds"],
                "maximum_age_seconds": context["max_age_seconds"],
            },
        )

    cadence = _cadence(active, context, diagnostics)
    if cadence["material_gap_count"]:
        assessment_complete = False

    minimum = context["minimum_points"]
    latest_version = active[-1].scoring_version if active else None
    if len(active) < minimum:
        if not items and collection_state == "ok":
            status = "NO_DATA"
        elif not parsed:
            status = "INVALID"
        else:
            status = "INSUFFICIENT_DATA"
        risk_score = round(sum(item["weight"] for item in indicators), 2)
        return _result(
            status=status,
            risk_score=risk_score,
            assessment_complete=assessment_complete,
            observations=items,
            parsed=parsed,
            active=active,
            invalid_count=invalid_count,
            latest_version=latest_version,
            version_segments=version_segments,
            version_discontinuity=version_discontinuity,
            history_truncated=history_truncated,
            freshness=freshness,
            cadence=cadence,
            indicators=indicators,
            recommendations=recommendations,
            diagnostics=diagnostics,
            statistics_summary={},
            context=context,
        )

    recent_count = min(context["recent_window"], max(3, len(active) // 3))
    recent_count = min(recent_count, len(active) - context["minimum_baseline"])
    baseline = active[:-recent_count]
    recent = active[-recent_count:]
    if len(baseline) > context["maximum_baseline"]:
        baseline = baseline[-context["maximum_baseline"]:]

    baseline_values = [item.harm for item in baseline]
    recent_values = [item.harm for item in recent]
    active_values = [item.harm for item in active]
    baseline_median = _median(baseline_values)
    recent_median = _median(recent_values)
    delta = recent_median - baseline_median
    baseline_mad = _mad(baseline_values)
    recent_mad = _mad(recent_values)
    robust_sigma = max(1.4826 * baseline_mad, context["noise_floor"])
    standardized_shift = delta / robust_sigma
    separation = _mann_whitney(baseline_values, recent_values)
    trend = _theil_sen(active_values)
    change_point = _change_point(active_values, context)
    latest_deviation = active_values[-1] - baseline_median
    latest_z = latest_deviation / robust_sigma

    shift_detected = (
        delta >= context["shift_threshold"]
        and standardized_shift >= context["minimum_effect"]
        and separation["confidence"] >= context["minimum_confidence"]
    )
    trend_detected = (
        trend["total_change"] >= context["trend_threshold"]
        and trend["kendall_tau"] >= context["minimum_trend_consistency"]
    )
    change_detected = (
        change_point["direction"] == "WORSENING"
        and change_point["absolute_shift"] >= context["shift_threshold"]
        and change_point["standardized_shift"] >= context["minimum_effect"]
    )
    isolated_spike = (
        latest_deviation >= context["spike_threshold"]
        and latest_z >= context["minimum_effect"]
        and not shift_detected
    )
    volatility_detected = (
        recent_mad >= context["minimum_volatility"]
        and recent_mad >= baseline_mad * context["volatility_ratio"]
        and recent_mad - baseline_mad >= context["noise_floor"]
    )

    if shift_detected:
        severity = "CRITICAL" if delta >= context["critical_shift"] else "HIGH"
        weight = 6.0 if severity == "CRITICAL" else 4.5
        _indicator(
            indicators,
            recommendations,
            "sustained_risk_deterioration",
            severity,
            weight,
            "Recent risk observations are materially worse than the robust baseline.",
            "Investigate the change point, deployment changes, and newly failing controls.",
            {
                "normalized_shift": round(delta, 6),
                "standardized_shift": round(standardized_shift, 3),
                "statistical_confidence": separation["confidence"],
                "baseline_count": len(baseline_values),
                "recent_count": len(recent_values),
            },
        )
    if trend_detected:
        _indicator(
            indicators,
            recommendations,
            "persistent_worsening_trend",
            "HIGH",
            3.0,
            "The robust metric slope shows persistent deterioration.",
            "Review cumulative risk drivers before the metric crosses an operational threshold.",
            {
                "normalized_slope_per_observation": trend["slope"],
                "normalized_total_change": trend["total_change"],
                "kendall_tau": trend["kendall_tau"],
            },
        )
    if change_detected and not shift_detected:
        _indicator(
            indicators,
            recommendations,
            "risk_regime_change",
            "HIGH",
            3.5,
            "A robust change-point scan found a sustained worse risk regime.",
            "Correlate the detected boundary with model, policy, data, and deployment changes.",
            change_point,
        )
    if isolated_spike:
        _indicator(
            indicators,
            recommendations,
            "acute_risk_spike",
            "MEDIUM",
            2.0,
            "The latest observation is an acute risk outlier above the baseline.",
            "Validate the observation promptly and inspect the triggering assessment evidence.",
            {
                "normalized_deviation": round(latest_deviation, 6),
                "robust_z_score": round(latest_z, 3),
            },
        )
    if volatility_detected:
        _indicator(
            indicators,
            recommendations,
            "risk_volatility_increase",
            "MEDIUM",
            1.5,
            "Recent risk observations are materially less stable than the baseline.",
            "Investigate unstable controls, evaluation variance, and intermittent exposure.",
            {
                "baseline_mad": round(baseline_mad, 6),
                "recent_mad": round(recent_mad, 6),
                "mad_ratio": round(recent_mad / max(baseline_mad, context["noise_floor"]), 3),
            },
        )

    improving = (
        delta <= -context["shift_threshold"]
        and separation["confidence"] >= context["minimum_confidence"]
    ) or (
        trend["total_change"] <= -context["trend_threshold"]
        and trend["kendall_tau"] <= -context["minimum_trend_consistency"]
    )
    risk_score = min(10.0, round(sum(item["weight"] for item in indicators), 2))
    drift_indicators = [
        item for item in indicators if item["indicator"] != "stale_metric_series"
    ]
    if drift_indicators:
        status = "DETERIORATING" if any(
            item["indicator"] in {
                "sustained_risk_deterioration",
                "persistent_worsening_trend",
                "risk_regime_change",
            }
            for item in drift_indicators
        ) else "ANOMALOUS"
    elif freshness["stale"]:
        status = "STALE"
    elif improving:
        status = "IMPROVING"
    else:
        status = "STABLE"

    statistics_summary = {
        "baseline_count": len(baseline_values),
        "recent_count": len(recent_values),
        "baseline_median": round(_denormalize(baseline_median, context), 6),
        "recent_median": round(_denormalize(recent_median, context), 6),
        "normalized_shift": round(delta, 6),
        "baseline_mad": round(baseline_mad, 6),
        "recent_mad": round(recent_mad, 6),
        "standardized_shift": round(standardized_shift, 3),
        "mann_whitney": separation,
        "theil_sen": trend,
        "change_point": change_point,
        "latest_robust_z_score": round(latest_z, 3),
    }
    return _result(
        status=status,
        risk_score=risk_score,
        assessment_complete=assessment_complete,
        observations=items,
        parsed=parsed,
        active=active,
        invalid_count=invalid_count,
        latest_version=latest_version,
        version_segments=version_segments,
        version_discontinuity=version_discontinuity,
        history_truncated=history_truncated,
        freshness=freshness,
        cadence=cadence,
        indicators=indicators,
        recommendations=recommendations,
        diagnostics=diagnostics,
        statistics_summary=statistics_summary,
        context=context,
    )


def _context(value, diagnostics):
    result = {
        "metric_min": 0.0,
        "metric_max": 10.0,
        "direction": "higher_is_worse",
        "minimum_points": 8,
        "minimum_baseline": 5,
        "maximum_baseline": 100,
        "recent_window": 5,
        "noise_floor": 0.02,
        "shift_threshold": 0.10,
        "critical_shift": 0.40,
        "trend_threshold": 0.15,
        "spike_threshold": 0.20,
        "minimum_effect": 2.5,
        "minimum_confidence": 0.95,
        "minimum_trend_consistency": 0.60,
        "minimum_volatility": 0.04,
        "volatility_ratio": 3.0,
        "as_of": None,
        "max_age_seconds": None,
        "max_gap_multiplier": 4.0,
    }
    if value is None:
        return result, True
    if not isinstance(value, dict):
        _diagnostic(
            diagnostics,
            "malformed_drift_context",
            "HIGH",
            "Risk drift assessment context must be an object.",
        )
        return result, False
    complete = True
    for key in ("metric_min", "metric_max"):
        if key in value:
            parsed = _finite(value.get(key))
            if parsed is None:
                complete = False
                _diagnostic(diagnostics, "invalid_metric_scale", "HIGH", "Metric scale bounds must be finite numbers.")
            else:
                result[key] = parsed
    if result["metric_max"] <= result["metric_min"]:
        complete = False
        result["metric_min"], result["metric_max"] = 0.0, 10.0
        _diagnostic(diagnostics, "invalid_metric_scale", "HIGH", "Metric maximum must exceed its minimum.")
    if "direction" in value:
        direction = str(value.get("direction") or "").strip().lower()
        if direction not in _DIRECTIONS:
            complete = False
            _diagnostic(diagnostics, "invalid_metric_direction", "HIGH", "Metric direction must declare whether higher values are better or worse.")
        else:
            result["direction"] = direction

    integer_bounds = {
        "minimum_points": (6, 200),
        "minimum_baseline": (3, 100),
        "maximum_baseline": (5, 500),
        "recent_window": (3, 100),
    }
    for key, bounds in integer_bounds.items():
        if key in value:
            parsed = _integer(value.get(key))
            if parsed is None or not bounds[0] <= parsed <= bounds[1]:
                complete = False
                _diagnostic(diagnostics, "invalid_drift_policy", "HIGH", f"{key} is outside its supported bound.")
            else:
                result[key] = parsed
    if result["minimum_points"] < result["minimum_baseline"] + 3:
        complete = False
        result["minimum_points"] = result["minimum_baseline"] + 3
        _diagnostic(diagnostics, "invalid_drift_policy", "HIGH", "Minimum points must leave at least three recent observations.")

    ratio_fields = {
        "noise_floor": (0.0001, 0.25),
        "shift_threshold": (0.01, 1.0),
        "critical_shift": (0.05, 1.0),
        "trend_threshold": (0.01, 1.0),
        "spike_threshold": (0.01, 1.0),
        "minimum_confidence": (0.5, 0.9999),
        "minimum_trend_consistency": (0.0, 1.0),
        "minimum_volatility": (0.001, 1.0),
    }
    positive_fields = {
        "minimum_effect": (0.1, 20.0),
        "volatility_ratio": (1.0, 100.0),
        "max_gap_multiplier": (1.0, 100.0),
    }
    for key, bounds in {**ratio_fields, **positive_fields}.items():
        if key in value:
            parsed = _finite(value.get(key))
            if parsed is None or not bounds[0] <= parsed <= bounds[1]:
                complete = False
                _diagnostic(diagnostics, "invalid_drift_policy", "HIGH", f"{key} is outside its supported bound.")
            else:
                result[key] = parsed
    if result["critical_shift"] < result["shift_threshold"]:
        complete = False
        result["critical_shift"] = max(0.4, result["shift_threshold"])
        _diagnostic(diagnostics, "invalid_drift_policy", "HIGH", "Critical shift must not be below the ordinary shift threshold.")

    if value.get("as_of") is not None:
        result["as_of"] = _parse_time(value.get("as_of"))
        if result["as_of"] is None:
            complete = False
            _diagnostic(diagnostics, "invalid_drift_as_of", "HIGH", "Assessment time must be timezone-aware ISO-8601.")
    if value.get("max_age_seconds") is not None:
        age = _finite(value.get("max_age_seconds"))
        if age is None or age <= 0:
            complete = False
            _diagnostic(diagnostics, "invalid_drift_freshness_policy", "HIGH", "Maximum metric age must be positive.")
        else:
            result["max_age_seconds"] = age
    return result, complete


def _observation(value, index, context):
    timestamp_raw = None
    version = "UNSPECIFIED"
    if isinstance(value, dict):
        raw_value = value.get("metric_value")
        if raw_value is None:
            raw_value = value.get("value")
        if raw_value is None:
            raw_value = value.get("score")
        timestamp_raw = value.get("created_at") or value.get("timestamp")
        dimensions = value.get("dimensions") if isinstance(value.get("dimensions"), dict) else {}
        version = str(
            value.get("scoring_version")
            or dimensions.get("scoring_version")
            or dimensions.get("assessment_version")
            or "UNSPECIFIED"
        ).strip()[:64] or "UNSPECIFIED"
    else:
        raw_value = value
    parsed_value = _finite(raw_value)
    if parsed_value is None:
        return None, "invalid_metric_value", timestamp_raw is not None
    if not context["metric_min"] <= parsed_value <= context["metric_max"]:
        return None, "metric_value_outside_declared_scale", timestamp_raw is not None
    timestamp = _parse_time(timestamp_raw) if timestamp_raw is not None else None
    if timestamp_raw is not None and timestamp is None:
        return None, "invalid_metric_timestamp", True
    normalized = (parsed_value - context["metric_min"]) / (
        context["metric_max"] - context["metric_min"]
    )
    harm = normalized if context["direction"] == "higher_is_worse" else 1.0 - normalized
    return _Observation(parsed_value, harm, timestamp, index, version), None, timestamp_raw is not None


def _collapse_duplicates(observations):
    result = []
    duplicate_count = 0
    version_conflicts = 0
    index = 0
    while index < len(observations):
        timestamp = observations[index].timestamp
        end = index + 1
        while end < len(observations) and observations[end].timestamp == timestamp:
            end += 1
        group = observations[index:end]
        if len(group) == 1:
            result.append(group[0])
        else:
            duplicate_count += len(group) - 1
            versions = {item.scoring_version for item in group}
            version_conflicts += int(len(versions) > 1)
            result.append(
                _Observation(
                    value=_median([item.value for item in group]),
                    harm=_median([item.harm for item in group]),
                    timestamp=timestamp,
                    source_index=max(item.source_index for item in group),
                    scoring_version=group[-1].scoring_version if len(versions) == 1 else "CONFLICTING",
                )
            )
        index = end
    return result, duplicate_count, version_conflicts


def _version_segments(observations):
    segments = []
    for item in observations:
        if not segments or segments[-1]["version"] != item.scoring_version:
            segments.append(
                {
                    "version": item.scoring_version,
                    "count": 1,
                    "start_index": item.source_index,
                    "end_index": item.source_index,
                }
            )
        else:
            segments[-1]["count"] += 1
            segments[-1]["end_index"] = item.source_index
    return segments


def _latest_version_segment(observations):
    if not observations:
        return []
    latest = observations[-1].scoring_version
    start = len(observations) - 1
    while start > 0 and observations[start - 1].scoring_version == latest:
        start -= 1
    return observations[start:]


def _freshness(observations, context, diagnostics):
    result = {
        "evaluated": False,
        "stale": False,
        "latest_age_seconds": None,
        "future_observation_count": 0,
    }
    as_of = context["as_of"]
    if not observations or as_of is None or observations[-1].timestamp is None:
        return result
    result["evaluated"] = True
    future = sum(item.timestamp > as_of for item in observations)
    result["future_observation_count"] = future
    if future:
        _diagnostic(
            diagnostics,
            "future_metric_timestamp",
            "HIGH",
            "Metric history contains observations later than the assessment time.",
            {"future_observation_count": future},
        )
    age = (as_of - observations[-1].timestamp).total_seconds()
    result["latest_age_seconds"] = round(age, 3)
    if context["max_age_seconds"] is not None and age > context["max_age_seconds"]:
        result["stale"] = True
    return result


def _cadence(observations, context, diagnostics):
    result = {
        "evaluated": False,
        "median_interval_seconds": None,
        "maximum_interval_seconds": None,
        "material_gap_count": 0,
    }
    if len(observations) < 3 or any(item.timestamp is None for item in observations):
        return result
    intervals = [
        (right.timestamp - left.timestamp).total_seconds()
        for left, right in zip(observations, observations[1:])
    ]
    positive = [value for value in intervals if value > 0]
    if not positive:
        return result
    median_interval = _median(positive)
    threshold = median_interval * context["max_gap_multiplier"]
    gaps = [value for value in positive if value > threshold]
    result.update(
        {
            "evaluated": True,
            "median_interval_seconds": round(median_interval, 3),
            "maximum_interval_seconds": round(max(positive), 3),
            "material_gap_count": len(gaps),
        }
    )
    if gaps:
        _diagnostic(
            diagnostics,
            "material_metric_collection_gaps",
            "MEDIUM",
            "Metric history contains collection gaps that weaken drift inference.",
            {"gap_count": len(gaps), "maximum_interval_seconds": round(max(gaps), 3)},
        )
    return result


def _mann_whitney(left, right):
    n_left = len(left)
    n_right = len(right)
    combined = [(value, 0) for value in left] + [(value, 1) for value in right]
    combined.sort(key=lambda item: item[0])
    rank_sum_right = 0.0
    tie_term = 0.0
    index = 0
    while index < len(combined):
        end = index + 1
        while end < len(combined) and combined[end][0] == combined[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2.0
        rank_sum_right += average_rank * sum(item[1] == 1 for item in combined[index:end])
        tie_size = end - index
        tie_term += tie_size**3 - tie_size
        index = end
    u = rank_sum_right - n_right * (n_right + 1) / 2.0
    mean = n_left * n_right / 2.0
    total = n_left + n_right
    variance = n_left * n_right / 12.0 * (
        total + 1 - tie_term / (total * (total - 1))
    ) if total > 1 else 0.0
    if variance <= 0:
        z_score = 0.0
        p_value = 1.0
    else:
        correction = 0.5 if u > mean else -0.5 if u < mean else 0.0
        z_score = (u - mean - correction) / math.sqrt(variance)
        p_value = math.erfc(abs(z_score) / math.sqrt(2.0))
    return {
        "u_statistic": round(u, 3),
        "z_score": round(z_score, 3),
        "p_value_two_sided": round(p_value, 6),
        "confidence": round(1.0 - p_value, 6),
    }


def _theil_sen(values):
    slopes = []
    positive = 0
    negative = 0
    for left in range(len(values) - 1):
        for right in range(left + 1, len(values)):
            difference = values[right] - values[left]
            slopes.append(difference / (right - left))
            positive += int(difference > 0)
            negative += int(difference < 0)
    slope = _median(slopes) if slopes else 0.0
    pairs = len(slopes)
    tau = (positive - negative) / pairs if pairs else 0.0
    return {
        "slope": round(slope, 8),
        "total_change": round(slope * max(0, len(values) - 1), 6),
        "kendall_tau": round(tau, 6),
        "pair_count": pairs,
    }


def _change_point(values, context):
    minimum = max(3, min(context["minimum_baseline"], len(values) // 3))
    best = None
    global_median = _median(values)
    global_loss = sum(abs(value - global_median) for value in values)
    for split in range(minimum, len(values) - minimum + 1):
        left = values[:split]
        right = values[split:]
        left_median = _median(left)
        right_median = _median(right)
        shift = right_median - left_median
        pooled_mad = _median(
            [abs(value - left_median) for value in left]
            + [abs(value - right_median) for value in right]
        )
        standardized = abs(shift) / max(1.4826 * pooled_mad, context["noise_floor"])
        balance = 2.0 * min(len(left), len(right)) / len(values)
        segmented_loss = sum(abs(value - left_median) for value in left) + sum(
            abs(value - right_median) for value in right
        )
        loss_reduction = max(0.0, global_loss - segmented_loss)
        score = loss_reduction * standardized * balance
        candidate = {
            "split_index": split,
            "direction": "WORSENING" if shift > 0 else "IMPROVING" if shift < 0 else "STABLE",
            "normalized_shift": round(shift, 6),
            "absolute_shift": round(abs(shift), 6),
            "standardized_shift": round(standardized, 3),
            "l1_loss_reduction": round(loss_reduction, 6),
            "balance": round(balance, 3),
            "score": round(score, 6),
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate
    return best or {
        "split_index": None,
        "direction": "STABLE",
        "normalized_shift": 0.0,
        "absolute_shift": 0.0,
        "standardized_shift": 0.0,
        "l1_loss_reduction": 0.0,
        "balance": 0.0,
        "score": 0.0,
    }


def _result(
    *, status, risk_score, assessment_complete, observations, parsed, active,
    invalid_count, latest_version, version_segments, version_discontinuity,
    history_truncated, freshness, cadence, indicators, recommendations,
    diagnostics, statistics_summary, context,
):
    confidence = _evidence_confidence(
        len(active), len(observations), invalid_count, version_discontinuity,
        cadence["material_gap_count"], bool(context["as_of"] and freshness["evaluated"]),
    )
    return {
        "scoring_version": RISK_DRIFT_SCORING_VERSION,
        "methodology": "robust_version_segmented_temporal_drift",
        "status": status,
        "severity": _severity(risk_score),
        "risk_score": min(10.0, round(risk_score, 2)),
        "assessment_complete": assessment_complete,
        "confidence": confidence,
        "direction": context["direction"],
        "metric_scale": {
            "minimum": context["metric_min"],
            "maximum": context["metric_max"],
        },
        "observation_count": len(observations),
        "valid_observation_count": len(parsed),
        "active_segment_count": len(active),
        "invalid_observation_count": invalid_count,
        "latest_scoring_version": latest_version,
        "version_discontinuity": version_discontinuity,
        "version_segments": version_segments,
        "history_window_truncated": history_truncated,
        "freshness": freshness,
        "cadence": cadence,
        "statistics": statistics_summary,
        "indicators": indicators,
        "recommendations": recommendations,
        "diagnostics": diagnostics,
    }


def _evidence_confidence(active_count, supplied_count, invalid_count, version_change, gap_count, freshness_evaluated):
    sample = min(1.0, active_count / 30.0)
    validity = 1.0 - invalid_count / max(1, supplied_count)
    score = 0.55 * sample + 0.35 * validity + 0.10 * int(freshness_evaluated)
    if version_change:
        score *= 0.9
    if gap_count:
        score *= 0.85
    return round(max(0.0, min(1.0, score)), 3)


def _indicator(indicators, recommendations, indicator, severity, weight, detail, recommendation, evidence):
    if any(item["indicator"] == indicator for item in indicators):
        return
    indicators.append(
        {
            "indicator": indicator,
            "severity": severity,
            "weight": weight,
            "detail": detail,
            "evidence": evidence,
        }
    )
    if recommendation not in recommendations:
        recommendations.append(recommendation)


def _diagnostic(diagnostics, indicator, severity, detail, evidence=None):
    if len(diagnostics) >= _MAX_DIAGNOSTICS:
        return
    candidate = {"indicator": indicator, "severity": severity, "detail": detail}
    if evidence is not None:
        candidate["evidence"] = evidence
    if candidate not in diagnostics:
        diagnostics.append(candidate)


def _bounded_items(value):
    if value in (None, ""):
        return [], "ok", 0
    if isinstance(value, dict):
        contained = value.get("items")
        if not isinstance(contained, (list, tuple)):
            return [], "malformed", 1
        items = list(contained)
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return [], "malformed", 1
    supplied = len(items)
    return items[:_MAX_OBSERVATIONS], "truncated" if supplied > _MAX_OBSERVATIONS else "ok", supplied


def _series_identity_conflict(items):
    metric_names = {
        str(item.get("metric_name")).strip()
        for item in items
        if isinstance(item, dict) and item.get("metric_name") not in (None, "")
    }
    artifact_ids = {
        str(item.get("artifact_id")).strip()
        for item in items
        if isinstance(item, dict) and item.get("artifact_id") not in (None, "")
    }
    if len(metric_names) <= 1 and len(artifact_ids) <= 1:
        return None
    return {
        "metric_name_count": len(metric_names),
        "artifact_scope_count": len(artifact_ids),
    }


def _parse_time(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _finite(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) else None


def _integer(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if str(value).strip() == str(parsed) or isinstance(value, int) else None


def _median(values: Sequence[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def _mad(values: Sequence[float]) -> float:
    center = _median(values)
    return _median([abs(value - center) for value in values])


def _denormalize(harm, context):
    normalized = harm if context["direction"] == "higher_is_worse" else 1.0 - harm
    return context["metric_min"] + normalized * (context["metric_max"] - context["metric_min"])


def _severity(score):
    if score <= 0:
        return "NONE"
    if score < 1.0:
        return "LOW"
    if score < 3.0:
        return "MEDIUM"
    if score < 6.0:
        return "HIGH"
    return "CRITICAL"

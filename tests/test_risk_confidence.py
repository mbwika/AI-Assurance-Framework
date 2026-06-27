"""Tests for core.risk_confidence (Phase E)."""

import math
import pytest
from aiaf.core.risk_confidence import (
    CONFIDENCE_VERSION,
    ORIGIN_WEIGHTS,
    CONFIDENCE_HIGH, CONFIDENCE_MODERATE, CONFIDENCE_LOW, CONFIDENCE_INSUFFICIENT,
    ORIGIN_INDEPENDENTLY_VERIFIED, ORIGIN_ARTIFACT_DERIVED,
    ORIGIN_LOCALLY_OBSERVED, ORIGIN_PROVIDER_DECLARED, ORIGIN_USER_ENTERED,
    RiskConfidenceError,
    compute_risk_confidence,
    _origin_weight,
    _classify_confidence,
)


# ── Origin weights ─────────────────────────────────────────────────────────────

def test_origin_weight_order():
    assert ORIGIN_WEIGHTS[ORIGIN_INDEPENDENTLY_VERIFIED] > ORIGIN_WEIGHTS[ORIGIN_ARTIFACT_DERIVED]
    assert ORIGIN_WEIGHTS[ORIGIN_ARTIFACT_DERIVED] > ORIGIN_WEIGHTS[ORIGIN_LOCALLY_OBSERVED]
    assert ORIGIN_WEIGHTS[ORIGIN_LOCALLY_OBSERVED] > ORIGIN_WEIGHTS[ORIGIN_PROVIDER_DECLARED]
    assert ORIGIN_WEIGHTS[ORIGIN_PROVIDER_DECLARED] > ORIGIN_WEIGHTS[ORIGIN_USER_ENTERED]


def test_independently_verified_weight_1():
    assert _origin_weight(ORIGIN_INDEPENDENTLY_VERIFIED) == pytest.approx(1.0)


def test_unknown_origin_fallback():
    assert _origin_weight("NONEXISTENT") == pytest.approx(0.25)


# ── Classification ─────────────────────────────────────────────────────────────

def test_classify_no_evidence():
    assert _classify_confidence(0.0, 0.0, 0) == CONFIDENCE_INSUFFICIENT


def test_classify_high():
    assert _classify_confidence(0.5, 0.9, 5) == CONFIDENCE_HIGH


def test_classify_moderate():
    assert _classify_confidence(2.0, 0.6, 3) == CONFIDENCE_MODERATE


def test_classify_low():
    assert _classify_confidence(5.0, 0.3, 1) == CONFIDENCE_LOW


# ── No evidence ────────────────────────────────────────────────────────────────

def test_empty_list_insufficient():
    result = compute_risk_confidence([])
    assert result["uncertainty_class"] == CONFIDENCE_INSUFFICIENT
    assert result["point_estimate"] is None
    assert result["evidence_count"] == 0


def test_zero_weight_items_excluded():
    items = [{"name": "a", "value": 5.0, "weight": 0.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED}]
    result = compute_risk_confidence(items)
    assert result["uncertainty_class"] == CONFIDENCE_INSUFFICIENT


def test_not_list_raises():
    with pytest.raises(RiskConfidenceError):
        compute_risk_confidence("not a list")


# ── Point estimate math ────────────────────────────────────────────────────────

def test_single_item_point_estimate():
    items = [{"name": "x", "value": 7.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED}]
    result = compute_risk_confidence(items)
    # Single item: variance = 0, point_estimate = 7.0
    assert result["point_estimate"] == pytest.approx(7.0, abs=0.01)


def test_equal_weight_mean():
    # Three equal-weight items same origin → mean = (8+6+4)/3 = 6.0
    items = [
        {"name": "a", "value": 8.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "b", "value": 6.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "c", "value": 4.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
    ]
    result = compute_risk_confidence(items)
    assert result["point_estimate"] == pytest.approx(6.0, abs=0.01)


def test_higher_weight_dominates():
    # value 8 has weight 10; value 2 has weight 1 — mean should be close to 8
    items = [
        {"name": "a", "value": 8.0, "weight": 10.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "b", "value": 2.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
    ]
    result = compute_risk_confidence(items)
    assert result["point_estimate"] > 7.0


def test_lower_origin_weight_downgrades_contribution():
    # Both value = 7.0 but different origins; high-origin item should dominate
    items = [
        {"name": "a", "value": 7.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "b", "value": 3.0, "weight": 1.0, "origin": ORIGIN_USER_ENTERED},
    ]
    result = compute_risk_confidence(items)
    # Since INDEPENDENTLY_VERIFIED has weight 1.0 and USER_ENTERED 0.25,
    # the result should be weighted toward the first item's value
    assert result["point_estimate"] > 5.0  # closer to 7 than 3


# ── Confidence intervals ───────────────────────────────────────────────────────

def test_ci_lower_less_than_upper():
    items = [
        {"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED},
        {"name": "b", "value": 8.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED},
    ]
    result = compute_risk_confidence(items)
    assert result["confidence_lower"] <= result["confidence_upper"]


def test_ci_clamped_to_0_10():
    items = [{"name": "a", "value": 10.0, "weight": 1.0, "origin": ORIGIN_USER_ENTERED}]
    result = compute_risk_confidence(items)
    assert 0.0 <= result["confidence_lower"] <= 10.0
    assert 0.0 <= result["confidence_upper"] <= 10.0


def test_point_estimate_within_ci():
    items = [
        {"name": "a", "value": 3.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED},
        {"name": "b", "value": 7.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED},
    ]
    result = compute_risk_confidence(items)
    assert result["confidence_lower"] <= result["point_estimate"] <= result["confidence_upper"]


# ── Evidence quality ───────────────────────────────────────────────────────────

def test_quality_score_range():
    items = [{"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED}]
    result = compute_risk_confidence(items)
    assert 0.0 <= result["evidence_quality_score"] <= 1.0


def test_high_origin_higher_quality():
    items_iv = [{"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED}]
    items_ue = [{"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_USER_ENTERED}]
    r_iv = compute_risk_confidence(items_iv)
    r_ue = compute_risk_confidence(items_ue)
    assert r_iv["evidence_quality_score"] > r_ue["evidence_quality_score"]


# ── Confidence classes ─────────────────────────────────────────────────────────

def test_all_independently_verified_high_confidence():
    items = [
        {"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED, "confidence": 1.0},
        {"name": "b", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED, "confidence": 1.0},
        {"name": "c", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED, "confidence": 1.0},
    ]
    result = compute_risk_confidence(items)
    # All same value → zero variance → very low uncertainty → HIGH_CONFIDENCE
    assert result["uncertainty_class"] == CONFIDENCE_HIGH


def test_user_entered_low_confidence():
    items = [{"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_USER_ENTERED, "confidence": 0.2}]
    result = compute_risk_confidence(items)
    assert result["uncertainty_class"] in (CONFIDENCE_LOW, CONFIDENCE_INSUFFICIENT)


# ── Origin breakdown ───────────────────────────────────────────────────────────

def test_origin_breakdown_counts():
    items = [
        {"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "b", "value": 5.0, "weight": 1.0, "origin": ORIGIN_INDEPENDENTLY_VERIFIED},
        {"name": "c", "value": 5.0, "weight": 1.0, "origin": ORIGIN_PROVIDER_DECLARED},
    ]
    result = compute_risk_confidence(items)
    assert result["origin_breakdown"][ORIGIN_INDEPENDENTLY_VERIFIED] == 2
    assert result["origin_breakdown"][ORIGIN_PROVIDER_DECLARED] == 1


# ── Metadata ───────────────────────────────────────────────────────────────────

def test_version_and_origin():
    result = compute_risk_confidence([
        {"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED}
    ])
    assert result["confidence_version"] == CONFIDENCE_VERSION
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"


def test_scored_at_present():
    result = compute_risk_confidence([
        {"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED}
    ])
    assert "scored_at" in result


def test_item_confidence_defaults_to_1():
    # Item without "confidence" key should work (defaults to 1.0)
    items = [{"name": "a", "value": 5.0, "weight": 1.0, "origin": ORIGIN_LOCALLY_OBSERVED}]
    result = compute_risk_confidence(items)
    assert result["evidence_count"] == 1

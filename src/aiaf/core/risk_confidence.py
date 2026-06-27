"""Formal Risk Confidence Scoring.

Computes origin-weighted, uncertainty-aware confidence bounds on a
composite risk score assembled from multiple evidence items.

Evidence items
--------------
Each item is a dict:
    {
        "name":       str,   # e.g. "provenance_score"
        "value":      float, # 0–10 risk magnitude
        "weight":     float, # caller-assigned importance (> 0)
        "origin":     str,   # evidence origin (see ORIGIN_WEIGHTS)
        "confidence": float, # 0–1 item-specific reliability
    }

Algorithm
---------
1. Compute effective_weight_i = weight_i × origin_weight_i × confidence_i
2. point_estimate = Σ(value_i × ew_i) / Σ(ew_i)
3. evidence_quality_score = Σ(ew_i) / Σ(weight_i)  ∈ [0, 1]
4. weighted_variance = Σ(ew_i × (value_i − μ)²) / Σ(ew_i)
5. uncertainty = σ_values × (1 + 2·(1−q)) × (1 + 1/(n+1))
6. CI = [μ − uncertainty, μ + uncertainty] clamped to [0, 10]
7. Classify uncertainty_class by σ and q thresholds.

Evidence origin
---------------
The module itself emits LOCALLY_OBSERVED; individual evidence items
carry their own origins.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

CONFIDENCE_VERSION = "1.0"

# ── Origin trust weights ───────────────────────────────────────────────────────
ORIGIN_INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"
ORIGIN_ARTIFACT_DERIVED = "ARTIFACT_DERIVED"
ORIGIN_LOCALLY_OBSERVED = "LOCALLY_OBSERVED"
ORIGIN_PROVIDER_DECLARED = "PROVIDER_DECLARED"
ORIGIN_USER_ENTERED = "USER_ENTERED"

ORIGIN_WEIGHTS: dict[str, float] = {
    ORIGIN_INDEPENDENTLY_VERIFIED: 1.00,
    ORIGIN_ARTIFACT_DERIVED: 0.85,
    ORIGIN_LOCALLY_OBSERVED: 0.70,
    ORIGIN_PROVIDER_DECLARED: 0.40,
    ORIGIN_USER_ENTERED: 0.25,
}

# ── Confidence classes ─────────────────────────────────────────────────────────
CONFIDENCE_HIGH = "HIGH_CONFIDENCE"
CONFIDENCE_MODERATE = "MODERATE_CONFIDENCE"
CONFIDENCE_LOW = "LOW_CONFIDENCE"
CONFIDENCE_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"


class RiskConfidenceError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clamp(value: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, value))


def _origin_weight(origin: str) -> float:
    return ORIGIN_WEIGHTS.get(str(origin).upper().strip(), 0.25)


def _classify_confidence(
    uncertainty: float, quality: float, n: int
) -> str:
    if n == 0:
        return CONFIDENCE_INSUFFICIENT
    if uncertainty < 1.5 and quality >= 0.70:
        return CONFIDENCE_HIGH
    if uncertainty < 3.0 and quality >= 0.40:
        return CONFIDENCE_MODERATE
    if n >= 1:
        return CONFIDENCE_LOW
    return CONFIDENCE_INSUFFICIENT


# ── Public API ─────────────────────────────────────────────────────────────────

def compute_risk_confidence(
    evidence_items: list[dict[str, Any]],
    *,
    store: Any = None,
) -> dict[str, Any]:
    """Compute a calibrated, origin-weighted confidence score.

    Parameters
    ----------
    evidence_items:
        List of evidence dicts (see module docstring).  Each must have
        at least ``name``, ``value`` (0–10), ``weight`` (> 0), ``origin``.
        ``confidence`` defaults to 1.0 if absent.
    store:
        Optional AIAF persistence store (currently unused; reserved for
        caching future results).

    Returns
    -------
    Dict with ``point_estimate``, ``confidence_lower``,
    ``confidence_upper``, ``uncertainty``, ``uncertainty_class``,
    ``evidence_quality_score``, ``evidence_count``, and
    ``origin_breakdown``.
    """
    if not isinstance(evidence_items, list):
        raise RiskConfidenceError("evidence_items must be a list")

    valid = []
    for item in evidence_items:
        w = float(item.get("weight") or 0)
        if w <= 0:
            continue
        v = float(item.get("value") or 0)
        c = float(item.get("confidence") if item.get("confidence") is not None else 1.0)
        c = max(0.0, min(1.0, c))
        o = str(item.get("origin") or ORIGIN_USER_ENTERED)
        ow = _origin_weight(o)
        ew = w * ow * c
        valid.append({"name": item.get("name", ""), "value": v, "weight": w, "ew": ew, "origin": o})

    n = len(valid)
    origin_breakdown: dict[str, int] = {}
    for it in valid:
        origin_breakdown[it["origin"]] = origin_breakdown.get(it["origin"], 0) + 1

    if n == 0:
        return {
            "confidence_version": CONFIDENCE_VERSION,
            "point_estimate": None,
            "confidence_lower": None,
            "confidence_upper": None,
            "uncertainty": None,
            "uncertainty_class": CONFIDENCE_INSUFFICIENT,
            "evidence_quality_score": 0.0,
            "evidence_count": 0,
            "origin_breakdown": origin_breakdown,
            "evidence_origin": "LOCALLY_OBSERVED",
            "scored_at": _utc_now(),
        }

    sum_ew = sum(it["ew"] for it in valid)
    sum_w = sum(it["weight"] for it in valid)

    point_estimate = sum(it["value"] * it["ew"] for it in valid) / sum_ew
    evidence_quality = sum_ew / sum_w  # ∈ (0, 1]

    # Weighted variance
    w_var = sum(it["ew"] * (it["value"] - point_estimate) ** 2 for it in valid) / sum_ew
    sigma_values = math.sqrt(w_var)

    # Total uncertainty (penalises low quality and few items)
    uncertainty = sigma_values * (1 + 2 * (1 - evidence_quality)) * (1 + 1 / (n + 1))

    lower = _clamp(point_estimate - uncertainty)
    upper = _clamp(point_estimate + uncertainty)
    uc = _classify_confidence(uncertainty, evidence_quality, n)

    return {
        "confidence_version": CONFIDENCE_VERSION,
        "point_estimate": round(point_estimate, 3),
        "confidence_lower": round(lower, 3),
        "confidence_upper": round(upper, 3),
        "uncertainty": round(uncertainty, 3),
        "uncertainty_class": uc,
        "evidence_quality_score": round(evidence_quality, 3),
        "evidence_count": n,
        "origin_breakdown": origin_breakdown,
        "evidence_origin": "LOCALLY_OBSERVED",
        "scored_at": _utc_now(),
    }

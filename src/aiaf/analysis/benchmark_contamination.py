"""Benchmark Contamination Detection.

Detects signs that a model's claimed benchmark scores may be inflated
because the benchmark test set appeared in the model's training data.

Analysis heuristics:
  H1 score_outlier — z-score vs population (high score suggests contamination)
  H2 temporal_contamination — training cutoff after benchmark release + high score
  H3 score_inconsistency — anomalous spread across related benchmarks
  H4 claimed_vs_verified_gap — large gap between self-reported and reproduced scores

A benchmark_score entry has the form:
    {
        "benchmark_name": str,
        "score": float,                 # 0–100 (percentage correct)
        "population_mean": float,       # mean across comparable models
        "population_std": float,        # std across comparable models
        "benchmark_release_date": str,  # ISO date when benchmark was published
        "verified_score": float | None, # independently reproduced score (optional)
    }

Evidence origin
---------------
LOCALLY_OBSERVED — z-scores and date comparisons are computed locally
from the caller-provided statistics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

CONTAMINATION_VERSION = "1.0"

# ── Status ─────────────────────────────────────────────────────────────────────
STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_CONTAMINATION_LIKELY = "CONTAMINATION_LIKELY"
STATUS_CONTAMINATION_CONFIRMED = "CONTAMINATION_CONFIRMED"

_STATUS_RANK: dict[str, int] = {
    STATUS_CONTAMINATION_CONFIRMED: 3,
    STATUS_CONTAMINATION_LIKELY: 2,
    STATUS_SUSPICIOUS: 1,
    STATUS_CLEAN: 0,
}

_Z_SCORE_SUSPICIOUS = 2.0
_Z_SCORE_LIKELY = 3.0
_CLAIMED_VS_VERIFIED_GAP = 5.0  # percentage points
_SCORE_RANGE_SUSPICIOUS = 40.0  # max–min spread within a single model


class ContaminationError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _worst_status(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _z_score(score: float, mean: float, std: float) -> float:
    if std <= 0:
        return 0.0
    return (score - mean) / std


# ── Heuristics ─────────────────────────────────────────────────────────────────

def _h1_score_outlier(entry: dict[str, Any]) -> dict[str, Any] | None:
    """H1: z-score above suspicious/likely threshold."""
    score = entry.get("score")
    mean = entry.get("population_mean")
    std = entry.get("population_std")
    if score is None or mean is None or std is None:
        return None
    z = _z_score(float(score), float(mean), float(std))
    if z >= _Z_SCORE_LIKELY:
        severity, status = "HIGH", STATUS_CONTAMINATION_LIKELY
    elif z >= _Z_SCORE_SUSPICIOUS:
        severity, status = "MEDIUM", STATUS_SUSPICIOUS
    else:
        return None
    return {
        "heuristic": "H1",
        "type": "score_outlier",
        "benchmark": entry.get("benchmark_name"),
        "z_score": round(z, 2),
        "severity": severity,
        "contamination_status": status,
        "detail": (
            f"{entry.get('benchmark_name')}: score {score:.1f} is {z:.1f}σ above population "
            f"mean {mean:.1f} (std {std:.1f})."
        ),
        "evidence_origin": "LOCALLY_OBSERVED",
    }


def _h2_temporal_contamination(
    entry: dict[str, Any], training_cutoff: datetime | None
) -> dict[str, Any] | None:
    """H2: training cutoff after benchmark publication + high z-score."""
    if training_cutoff is None:
        return None
    release = _parse_date(entry.get("benchmark_release_date"))
    if release is None:
        return None
    score = entry.get("score")
    mean = entry.get("population_mean")
    std = entry.get("population_std")
    if score is None or mean is None or std is None:
        return None
    z = _z_score(float(score), float(mean), float(std))
    if training_cutoff >= release and z >= _Z_SCORE_SUSPICIOUS:
        return {
            "heuristic": "H2",
            "type": "temporal_contamination_risk",
            "benchmark": entry.get("benchmark_name"),
            "z_score": round(z, 2),
            "severity": "HIGH",
            "contamination_status": STATUS_CONTAMINATION_LIKELY,
            "detail": (
                f"{entry.get('benchmark_name')} released {release.date()} — "
                f"training cutoff {training_cutoff.date()} is AFTER release. "
                f"Score is {z:.1f}σ above mean."
            ),
            "evidence_origin": "LOCALLY_OBSERVED",
        }
    return None


def _h3_score_inconsistency(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """H3: anomalous spread — very high on some benchmarks, very low on others."""
    scores = [float(e["score"]) for e in entries if e.get("score") is not None]
    if len(scores) < 3:
        return None
    spread = max(scores) - min(scores)
    if spread >= _SCORE_RANGE_SUSPICIOUS:
        return {
            "heuristic": "H3",
            "type": "score_inconsistency",
            "severity": "MEDIUM",
            "contamination_status": STATUS_SUSPICIOUS,
            "detail": (
                f"Score range {spread:.1f}pp across {len(scores)} benchmarks — "
                "extreme within-model variation may indicate selective contamination."
            ),
            "evidence_origin": "LOCALLY_OBSERVED",
        }
    return None


def _h4_claimed_vs_verified_gap(entry: dict[str, Any]) -> dict[str, Any] | None:
    """H4: large gap between self-reported score and independently reproduced score."""
    claimed = entry.get("score")
    verified = entry.get("verified_score")
    if claimed is None or verified is None:
        return None
    gap = float(claimed) - float(verified)
    if gap >= _CLAIMED_VS_VERIFIED_GAP:
        return {
            "heuristic": "H4",
            "type": "claimed_vs_verified_gap",
            "benchmark": entry.get("benchmark_name"),
            "gap_percentage_points": round(gap, 2),
            "severity": "HIGH",
            "contamination_status": STATUS_CONTAMINATION_LIKELY,
            "detail": (
                f"{entry.get('benchmark_name')}: claimed {claimed:.1f} vs "
                f"verified {verified:.1f} ({gap:+.1f}pp gap)."
            ),
            "evidence_origin": "LOCALLY_OBSERVED",
        }
    return None


# ── Public API ─────────────────────────────────────────────────────────────────

def check_contamination(
    model_record: dict[str, Any],
    benchmark_scores: list[dict[str, Any]],
    store: Any,
    *,
    model_id: str | None = None,
) -> dict[str, Any]:
    """Check benchmark scores for contamination indicators.

    Parameters
    ----------
    model_record:
        Model registry dict.  Used to extract training_cutoff for H2.
    benchmark_scores:
        List of benchmark score dicts (see module docstring for schema).
    store:
        AIAF persistence store.
    model_id:
        Override model_id.
    """
    if not isinstance(benchmark_scores, list):
        raise ContaminationError("benchmark_scores must be a list")

    mid = model_id or (model_record.get("model_id") or model_record.get("id") or "unknown")
    meta = model_record.get("metadata") or {}
    cutoff_str = meta.get("training_cutoff") or meta.get("training_data_cutoff")
    training_cutoff = _parse_date(cutoff_str)

    findings: list[dict[str, Any]] = []
    overall = STATUS_CLEAN

    for entry in benchmark_scores:
        for finding in (
            _h1_score_outlier(entry),
            _h2_temporal_contamination(entry, training_cutoff),
            _h4_claimed_vs_verified_gap(entry),
        ):
            if finding:
                findings.append(finding)
                cs = finding.get("contamination_status", STATUS_SUSPICIOUS)
                overall = _worst_status(overall, cs)

    g_finding = _h3_score_inconsistency(benchmark_scores)
    if g_finding:
        findings.append(g_finding)
        overall = _worst_status(overall, g_finding.get("contamination_status", STATUS_SUSPICIOUS))

    return {
        "model_id": mid,
        "contamination_version": CONTAMINATION_VERSION,
        "status": overall,
        "finding_count": len(findings),
        "findings": findings,
        "benchmark_count": len(benchmark_scores),
        "training_cutoff_used": cutoff_str,
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }

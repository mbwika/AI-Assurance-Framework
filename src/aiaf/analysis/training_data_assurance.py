"""Training-data assurance heuristics.

Assesses whether AIAF has enough trustworthy evidence about a model's training
data lineage, governance, and contamination controls to support higher-trust
adoption decisions. This is intentionally evidence-aware rather than purely
performance-aware.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

TRAINING_DATA_ASSURANCE_VERSION = "1.0"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _lineage_sources(meta: dict[str, Any]) -> list[Any]:
    if isinstance(meta.get("training_data_sources"), list):
        return list(meta.get("training_data_sources") or [])
    if isinstance(meta.get("training_artifacts"), list):
        return list(meta.get("training_artifacts") or [])
    return []


def _add_finding(findings: list[dict[str, Any]], score_delta: int, severity: str, ftype: str, detail: str) -> None:
    findings.append({
        "type": ftype,
        "severity": severity,
        "score_delta": score_delta,
        "detail": detail,
        "evidence_origin": "LOCALLY_OBSERVED",
    })


def _risk_from_score(score: float) -> str:
    if score >= 75:
        return RISK_LOW
    if score >= 50:
        return RISK_MEDIUM
    if score >= 25:
        return RISK_HIGH
    return RISK_CRITICAL


def assess_training_data_assurance(
    model_record: dict[str, Any],
    store: Any,
    *,
    model_id: str | None = None,
) -> dict[str, Any]:
    meta = model_record.get("metadata") or {}
    mid = model_id or model_record.get("model_id") or model_record.get("id") or "unknown"
    findings: list[dict[str, Any]] = []
    score = 100

    training_data = meta.get("training_data")
    lineage = _lineage_sources(meta)

    if not training_data:
        score -= 30
        _add_finding(
            findings,
            -30,
            "HIGH",
            "training_data_undeclared",
            "No training-data description is recorded for this model.",
        )

    if not lineage:
        score -= 20
        _add_finding(
            findings,
            -20,
            "HIGH",
            "training_lineage_missing",
            "No dataset lineage or training-artifact inventory is recorded.",
        )
    else:
        unpinned = []
        for item in lineage:
            if not isinstance(item, dict):
                continue
            if (item.get("source_url") or item.get("repository") or item.get("uri")) and not (
                item.get("revision") or item.get("commit") or item.get("sha256") or item.get("digest")
            ):
                unpinned.append(item.get("name") or item.get("repository") or item.get("source_url"))
        if unpinned:
            score -= 15
            _add_finding(
                findings,
                -15,
                "MEDIUM",
                "training_lineage_unpinned",
                f"Training lineage includes repository-backed sources without immutable revision evidence: {unpinned[:5]}",
            )

    if not meta.get("license"):
        score -= 10
        _add_finding(
            findings,
            -10,
            "MEDIUM",
            "training_data_license_unknown",
            "No license or usage basis is recorded for the model or its training data.",
        )

    if not (meta.get("privacy_reviewed") or meta.get("personal_data_reviewed")):
        score -= 15
        _add_finding(
            findings,
            -15,
            "MEDIUM",
            "personal_data_governance_missing",
            "No training-data privacy or personal-data governance review is recorded.",
        )

    if not meta.get("benchmark_contamination_reviewed"):
        score -= 10
        _add_finding(
            findings,
            -10,
            "LOW",
            "contamination_controls_missing",
            "No benchmark contamination review is recorded for the training corpus.",
        )

    if not (meta.get("provenance_attestations") or meta.get("sigstore_verification")):
        score -= 10
        _add_finding(
            findings,
            -10,
            "LOW",
            "training_provenance_not_bound",
            "No signed provenance evidence was recorded for the artifact or training lineage.",
        )

    score = max(0, float(score))
    return {
        "model_id": mid,
        "training_data_assurance_version": TRAINING_DATA_ASSURANCE_VERSION,
        "score": round(score, 1),
        "overall_risk": _risk_from_score(score),
        "finding_count": len(findings),
        "findings": findings,
        "lineage_source_count": len(lineage),
        "training_data_declared": bool(training_data),
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }

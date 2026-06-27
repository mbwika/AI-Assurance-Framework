"""Backdoor / Trojan Heuristic Analyser.

Estimates the probability that a model's weights have been tampered with via
a backdoor or trojan implant — without executing the model.

Approach
--------
Full tensor-level statistical detection (SVD rank analysis, activation
steering vector norms, embedding outlier detection) requires loading the full
model into GPU memory and is therefore out of scope for pre-adoption triage.
Instead, this module applies seven heuristics that combine signals already
computed by other AIAF modules (weight_inspector, lineage_graph,
fact_reconciler, provenance_v2) to produce a graded risk estimate.

Evidence is tagged LOCALLY_OBSERVED at MEDIUM confidence for metadata-based
heuristics (we derived the finding; it is not independently verified).  Each
finding includes an explicit ``confidence`` bound and ``refs`` mapping to
MITRE ATLAS and OWASP LLM Top-10.

Heuristics (ordered by severity tier)
--------------------------------------
H1  fine_tuned_from_unverified_source   HIGH  — lineage shows fine-tuning from
    a component with provenance_score < 30 or unverifiable origin; this is the
    most common vector (DataPoisoning + PEFT trojan injection).
H2  merge_component_unverified          HIGH  — lineage shows a MergeKit or
    TIES merge where ≥1 component has no verified provenance; merged weights
    are opaque to manual inspection.
H3  provenance_score_critically_low     HIGH  — provenance_score < 15 and
    weights are present; an artifact that we cannot trace at all but is
    available locally is the highest-risk configuration.
H4  parameter_count_contradiction       MEDIUM — fact_reconciliation reports a
    contradiction in parameter_count; a mismatch between declared and derived
    counts suggests the weights may not match the claimed checkpoint.
H5  dtype_anomaly                       MEDIUM — weight inspection shows a dtype
    distribution inconsistent with any known quantisation scheme (e.g. BF16
    mixed with INT4 without a quantisation metadata key).
H6  lineage_unverifiable                MEDIUM — lineage_graph returned
    UNVERIFIABLE for base-model detection; we cannot confirm what the model
    was trained or fine-tuned from.
H7  low_provenance_with_artifact        LOW   — weights are locally present but
    provenance_score < 30; less severe than H3 but still warrants monitoring.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ANALYSIS_VERSION = "1.0"

_KNOWN_QUANT_SCHEMES = frozenset({
    "gguf", "ggml", "gptq", "awq", "exl2", "squeezellm",
    "smoothquant", "int8", "nf4", "fp4",
})

_LINEAGE_UNVERIFIABLE = "UNVERIFIABLE"
_PROV_CRITICALLY_LOW = 15
_PROV_LOW = 30


# ── Public constants (status) ─────────────────────────────────────────────────

STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_HIGH_RISK = "HIGH_RISK"
STATUS_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
STATUS_ERROR = "ANALYSIS_ERROR"


# ── Finding builder ───────────────────────────────────────────────────────────

def _finding(
    heuristic_id: str,
    severity: str,
    confidence: float,
    description: str,
    refs: Optional[List[str]] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "heuristic_id": heuristic_id,
        "severity": severity,
        "confidence": round(confidence, 3),
        "description": description,
        "evidence_origin": "LOCALLY_OBSERVED",
        "refs": refs or [],
        "detail": detail or {},
    }


# ── Individual heuristics ─────────────────────────────────────────────────────

def _h1_finetuned_unverified(
    lineage: Dict[str, Any],
    provenance_assessment: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """H1: fine-tuned from a component with unverifiable/low-provenance origin."""
    flags = lineage.get("flags") or []
    lineage_source = str(lineage.get("lineage_source") or "").upper()

    is_finetuned = "merge_detected" not in flags and lineage_source in (
        "HF_MODEL_CARD", "SAFETENSORS_METADATA", "GGUF_METADATA",
    )
    prov_score = _safe_float(provenance_assessment.get("provenance_score"))

    if is_finetuned and prov_score is not None and prov_score < _PROV_LOW:
        return _finding(
            "fine_tuned_from_unverified_source",
            severity="HIGH",
            confidence=0.65,
            description=(
                f"Model appears to be fine-tuned (lineage_source={lineage_source!r}) "
                f"but provenance_score is {prov_score:.0f}/100 (<{_PROV_LOW}). "
                "Fine-tuned models from unverifiable origins are the primary vector "
                "for data-poisoning and PEFT-based trojan implants."
            ),
            refs=["AML.T0018", "AML.T0020", "OWASP-LLM03"],
            detail={"lineage_source": lineage_source, "provenance_score": prov_score},
        )
    return None


def _h2_merge_component_unverified(lineage: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """H2: MergeKit/TIES merge where ≥1 component has unverified provenance."""
    flags = lineage.get("flags") or []
    if "merge_detected" not in flags:
        return None
    components = lineage.get("merge_components") or []
    unverified = [c for c in components if not c.get("verified", False)]
    n_unverified = len(unverified) if unverified else (1 if not components else 0)
    if n_unverified > 0:
        return _finding(
            "merge_component_unverified",
            severity="HIGH",
            confidence=0.70,
            description=(
                f"Model is a merge of {len(components) or 'multiple'} components, "
                f"of which {n_unverified} have unverified provenance. "
                "Merged weight spaces are opaque; a malicious component "
                "can survive merging via low-rank subspace injection."
            ),
            refs=["AML.T0020", "OWASP-LLM03"],
            detail={"merge_flags": flags, "unverified_count": n_unverified},
        )
    return None


def _h3_provenance_critically_low(
    provenance_assessment: Dict[str, Any],
    weight_inspection: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """H3: provenance_score < PROV_CRITICALLY_LOW with weights locally available."""
    prov_score = _safe_float(provenance_assessment.get("provenance_score"))
    weights_present = (
        weight_inspection is not None
        and weight_inspection.get("status") not in (None, "ERROR", "UNSUPPORTED")
    )
    if prov_score is not None and prov_score < _PROV_CRITICALLY_LOW and weights_present:
        return _finding(
            "provenance_score_critically_low",
            severity="HIGH",
            confidence=0.75,
            description=(
                f"Provenance score is critically low ({prov_score:.0f}/100, "
                f"threshold: {_PROV_CRITICALLY_LOW}) yet model weights are locally "
                "present and loadable.  A weight artifact we cannot trace at all "
                "is the highest-risk configuration for a pre-implanted backdoor."
            ),
            refs=["AML.T0018", "OWASP-LLM03", "NIST-AI-RMF-MS-2.5"],
            detail={"provenance_score": prov_score, "weights_present": True},
        )
    return None


def _h4_parameter_count_contradiction(
    fact_reconciliation: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """H4: fact_reconciliation found a parameter-count contradiction."""
    if not fact_reconciliation:
        return None
    comparisons = fact_reconciliation.get("comparisons") or []
    for comp in comparisons:
        if comp.get("field") == "parameter_count" and comp.get("verdict") == "CONTRADICTION":
            declared = comp.get("declared_value")
            derived = comp.get("derived_value")
            return _finding(
                "parameter_count_contradiction",
                severity="MEDIUM",
                confidence=0.80,
                description=(
                    f"Fact reconciliation found a CONTRADICTION in parameter_count: "
                    f"declared={declared}, derived={derived}. "
                    "A mismatch of this kind indicates the loaded weights may not "
                    "correspond to the claimed checkpoint — a known signal for "
                    "checkpoint-swap or weight-replacement attacks."
                ),
                refs=["AML.T0018", "OWASP-LLM03"],
                detail={"declared": declared, "derived": derived},
            )
    return None


def _h5_dtype_anomaly(weight_inspection: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """H5: unexpected dtype mix inconsistent with any known quantisation scheme."""
    if not weight_inspection:
        return None
    format_detected = str(weight_inspection.get("format_detected") or "").lower()
    derived_facts = weight_inspection.get("derived_facts") or {}
    dtype_summary = derived_facts.get("dtype_summary") or {}
    quant = str(derived_facts.get("quantization") or "").lower()

    if not dtype_summary or len(dtype_summary) < 2:
        return None

    dtypes = set(dtype_summary.keys())
    int_types = {d for d in dtypes if re.match(r"^(u?int|q\d)", d, re.I)}
    float_types = {d for d in dtypes if re.match(r"^(float|bf|fp|f)\d", d, re.I)}

    known_quant = any(sch in quant for sch in _KNOWN_QUANT_SCHEMES) or any(
        sch in format_detected for sch in _KNOWN_QUANT_SCHEMES
    )

    if int_types and float_types and not known_quant:
        return _finding(
            "dtype_anomaly",
            severity="MEDIUM",
            confidence=0.55,
            description=(
                f"Weight inspection found mixed dtypes ({sorted(dtypes)}) combining "
                f"integer types ({sorted(int_types)}) with float types "
                f"({sorted(float_types)}) but no recognized quantisation scheme "
                f"was detected (format={format_detected!r}, quant={quant!r}). "
                "Unexpected precision mixing can indicate low-rank weight patches "
                "applied post-training to encode backdoor triggers."
            ),
            refs=["AML.T0020"],
            detail={"dtypes": sorted(dtypes), "int_types": sorted(int_types),
                    "float_types": sorted(float_types), "format": format_detected},
        )
    return None


def _h6_lineage_unverifiable(lineage: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """H6: lineage_graph could not determine the base model."""
    if not lineage:
        return None
    arch_consistency = str(lineage.get("architecture_consistency") or "").upper()
    lineage_source = str(lineage.get("lineage_source") or "").upper()
    if arch_consistency == _LINEAGE_UNVERIFIABLE or lineage_source == _LINEAGE_UNVERIFIABLE:
        return _finding(
            "lineage_unverifiable",
            severity="MEDIUM",
            confidence=0.60,
            description=(
                "Lineage graph could not determine the base model family or verify "
                f"architecture consistency (consistency={arch_consistency!r}, "
                f"source={lineage_source!r}). "
                "Without a known lineage we cannot bound the training provenance, "
                "which is prerequisite to evaluating fine-tuning attack surface."
            ),
            refs=["AML.T0018", "OWASP-LLM03"],
            detail={"arch_consistency": arch_consistency, "lineage_source": lineage_source},
        )
    return None


def _h7_low_provenance_with_artifact(
    provenance_assessment: Dict[str, Any],
    weight_inspection: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """H7: weights present but provenance_score < PROV_LOW (lower severity than H3)."""
    prov_score = _safe_float(provenance_assessment.get("provenance_score"))
    weights_present = (
        weight_inspection is not None
        and weight_inspection.get("status") not in (None, "ERROR", "UNSUPPORTED")
    )
    if (
        prov_score is not None
        and _PROV_CRITICALLY_LOW <= prov_score < _PROV_LOW
        and weights_present
    ):
        return _finding(
            "low_provenance_with_artifact",
            severity="LOW",
            confidence=0.50,
            description=(
                f"Provenance score is low ({prov_score:.0f}/100) yet model weights "
                "are locally present.  Recommend obtaining a verified provenance "
                "chain before production deployment."
            ),
            refs=["OWASP-LLM03"],
            detail={"provenance_score": prov_score},
        )
    return None


# ── Aggregation ───────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _aggregate_status(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return STATUS_CLEAN
    worst = max(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 0))
    sev = worst["severity"]
    if sev == "HIGH":
        return STATUS_HIGH_RISK
    if sev == "MEDIUM":
        return STATUS_SUSPICIOUS
    return STATUS_CLEAN  # LOW only → CLEAN (just a gap, not a finding)


def _by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    result: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f["severity"]
        result[sev] = result.get(sev, 0) + 1
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def analyse(
    model_record: Dict[str, Any],
    *,
    weight_inspection: Optional[Dict[str, Any]] = None,
    lineage: Optional[Dict[str, Any]] = None,
    provenance_assessment: Optional[Dict[str, Any]] = None,
    fact_reconciliation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run backdoor/trojan heuristic analysis and return a structured report.

    All inputs are optional; the analysis degrades gracefully when upstream
    modules did not run, and ``assessment_complete`` is set to ``False`` when
    critical inputs are missing.

    Parameters
    ----------
    model_record:
        Registered model dict (must be provided; other fields may be empty).
    weight_inspection:
        Output of ``aiaf.registry.weight_inspector.inspect_file``.
    lineage:
        Output of ``aiaf.registry.lineage_graph.derive_lineage``.
    provenance_assessment:
        Output of ``aiaf.registry.provenance_v2.assess_provenance_v2``.
    fact_reconciliation:
        Output of ``aiaf.registry.fact_reconciler.reconcile``.
    """
    model_record = model_record if isinstance(model_record, dict) else {}
    provenance_assessment = provenance_assessment or {}
    lineage = lineage or {}

    findings: List[Dict[str, Any]] = []
    assessment_complete = True

    # Determine how much evidence we actually have
    has_weights = weight_inspection is not None
    has_lineage = bool(lineage)
    has_provenance = bool(provenance_assessment)
    has_reconciliation = fact_reconciliation is not None

    if not has_provenance:
        assessment_complete = False

    # Run heuristics — each returns a finding dict or None
    candidates = [
        _h1_finetuned_unverified(lineage, provenance_assessment) if has_lineage and has_provenance else None,
        _h2_merge_component_unverified(lineage) if has_lineage else None,
        _h3_provenance_critically_low(provenance_assessment, weight_inspection) if has_provenance else None,
        _h4_parameter_count_contradiction(fact_reconciliation) if has_reconciliation else None,
        _h5_dtype_anomaly(weight_inspection) if has_weights else None,
        _h6_lineage_unverifiable(lineage) if has_lineage else None,
        _h7_low_provenance_with_artifact(provenance_assessment, weight_inspection) if has_provenance else None,
    ]
    findings = [f for f in candidates if f is not None]

    # Determine overall status
    if not has_provenance and not has_weights and not has_lineage:
        status = STATUS_INSUFFICIENT_DATA
        assessment_complete = False
    else:
        status = _aggregate_status(findings)

    # Aggregate confidence: pessimistic (min across high/medium findings, or 0.5 if none)
    high_med = [f for f in findings if f["severity"] in ("HIGH", "MEDIUM")]
    if high_med:
        confidence = round(min(f["confidence"] for f in high_med), 3)
    elif findings:
        confidence = round(min(f["confidence"] for f in findings), 3)
    else:
        confidence = 1.0 if (has_provenance or has_weights) else 0.0

    return {
        "analysis_version": ANALYSIS_VERSION,
        "status": status,
        "finding_count": len(findings),
        "findings": sorted(
            findings,
            key=lambda f: (-_SEVERITY_RANK.get(f["severity"], 0), f["heuristic_id"]),
        ),
        "by_severity": _by_severity(findings),
        "evidence_origin": "LOCALLY_OBSERVED",
        "confidence": confidence,
        "assessment_complete": assessment_complete,
        "inputs_available": {
            "weight_inspection": has_weights,
            "lineage": has_lineage,
            "provenance_assessment": has_provenance,
            "fact_reconciliation": has_reconciliation,
        },
        "analysed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _safe_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

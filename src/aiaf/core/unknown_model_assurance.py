"""Unknown-model assurance assembly for external model intake.

This module answers the question a cautious operator actually has when they
find a third-party model on the internet:

What does AIAF know from the artifact itself, what still rests on declarations,
and what currently blocks trust?

The output is intentionally explainable rather than clever. It packages the
signals AIAF already computes into one focused view for unknown-model review.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..registry.evidence_origin import EvidenceOrigin, coerce_origin, ledger_from_list


UNKNOWN_MODEL_ASSURANCE_VERSION = "1.0"

_HIGH_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
_PERMISSIVE_LICENSES = frozenset(
    {
        "apache-2.0",
        "mit",
        "bsd-2-clause",
        "bsd-3-clause",
        "isc",
        "unlicense",
        "mpl-2.0",
    }
)
_RESTRICTIVE_LICENSE_MARKERS = (
    "gpl",
    "agpl",
    "lgpl",
    "openrail",
    "rail",
    "llama",
    "gemma",
    "noncommercial",
    "non-commercial",
    "research",
    "cc-by-nc",
)


def build_unknown_model_assurance(
    model_record: Dict[str, Any],
    *,
    recommendation: Optional[Dict[str, Any]] = None,
    provenance_assessment: Optional[Dict[str, Any]] = None,
    serialization_scan: Optional[Dict[str, Any]] = None,
    weight_inspection: Optional[Dict[str, Any]] = None,
    lineage: Optional[Dict[str, Any]] = None,
    fact_reconciliation: Optional[Dict[str, Any]] = None,
    vulnerability_scan: Optional[Dict[str, Any]] = None,
    backdoor_heuristics: Optional[Dict[str, Any]] = None,
    unknown_model_probe: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble a first-class assurance view for an unknown external model."""
    model_record = model_record if isinstance(model_record, dict) else {}
    recommendation = recommendation or {}
    provenance_assessment = provenance_assessment or {}
    serialization_scan = serialization_scan or {}
    weight_inspection = weight_inspection or {}
    lineage = lineage or {}
    fact_reconciliation = fact_reconciliation or {}
    vulnerability_scan = vulnerability_scan or {}
    backdoor_heuristics = backdoor_heuristics or {}
    unknown_model_probe = unknown_model_probe or {}

    metadata = model_record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    hf_card = metadata.get("hf_model_card") or {}
    ledger = ledger_from_list(metadata.get("evidence_ledger"))
    ledger_entries = ledger.to_list()
    origin_summary = ledger.by_origin()

    contradictions = fact_reconciliation.get("contradictions") or []
    confirmations = fact_reconciliation.get("confirmations") or []
    decidability_bounds = fact_reconciliation.get("decidability_bounds") or []
    trust_caps = provenance_assessment.get("trust_caps") or []
    provenance_score = _safe_number(provenance_assessment.get("provenance_score"))
    provenance_conf = _safe_number(provenance_assessment.get("confidence"))
    pir = _safe_number(fact_reconciliation.get("provenance_independence_ratio")) or 0.0

    identity = _identity_posture(
        ledger_entries, provenance_assessment=provenance_assessment, pir=pir
    )
    artifact_inspection = _artifact_inspection(serialization_scan, weight_inspection)
    model_card_consistency = _model_card_consistency(
        hf_card,
        contradictions=contradictions,
        confirmations=confirmations,
        unverifiable=fact_reconciliation.get("unverifiable_facts") or [],
    )
    license_posture = _license_posture(
        model_record,
        hf_card=hf_card,
        ledger_entries=ledger_entries,
    )
    security_flags = _security_flags(
        recommendation=recommendation,
        serialization_scan=serialization_scan,
        vulnerability_scan=vulnerability_scan,
        backdoor_heuristics=backdoor_heuristics,
        contradictions=contradictions,
        unknown_model_probe=unknown_model_probe,
    )
    evidence_gaps = _evidence_gaps(
        recommendation=recommendation,
        weight_inspection=weight_inspection,
        serialization_scan=serialization_scan,
        provenance_assessment=provenance_assessment,
        hf_card=hf_card,
    )
    next_steps = _next_steps(
        identity=identity,
        model_card_consistency=model_card_consistency,
        security_flags=security_flags,
        evidence_gaps=evidence_gaps,
        artifact_inspection=artifact_inspection,
    )
    posture = _overall_posture(
        identity=identity,
        artifact_inspection=artifact_inspection,
        model_card_consistency=model_card_consistency,
        security_flags=security_flags,
        provenance_score=provenance_score,
    )

    return {
        "version": UNKNOWN_MODEL_ASSURANCE_VERSION,
        "model_id": model_record.get("model_id") or model_record.get("id"),
        "posture": posture,
        "summary": _summary(
            posture,
            identity=identity,
            security_flags=security_flags,
            artifact_inspection=artifact_inspection,
        ),
        "artifact_identity": {
            "model_name": model_record.get("model_name"),
            "source": model_record.get("source"),
            "source_url": model_record.get("source_url"),
            "publisher": model_record.get("publisher") or hf_card.get("publisher"),
            "repo_id": metadata.get("repo_id"),
            "identity_status": identity["status"],
            "identity_reason": identity["reason"],
            "provenance_score": provenance_score,
            "provenance_risk_level": provenance_assessment.get("risk_level"),
            "provenance_confidence": provenance_conf,
            "provenance_independence_ratio": round(pir, 3),
            "trust_caps": trust_caps,
        },
        "artifact_inspection": artifact_inspection,
        "model_card_consistency": model_card_consistency,
        "lineage": {
            "base_model": lineage.get("base_model"),
            "lineage_source": lineage.get("lineage_source"),
            "lineage_depth": lineage.get("lineage_depth"),
            "lineage_completeness": lineage.get("lineage_completeness"),
            "architecture_consistency": lineage.get("architecture_consistency"),
            "flags": lineage.get("flags") or [],
            "cannot_verify": lineage.get("cannot_verify") or [],
        },
        "license_posture": license_posture,
        "security_flags": security_flags,
        "unknown_model_probe": unknown_model_probe,
        "evidence_profile": {
            "origins": origin_summary,
            "self_observed_facts": _dedupe(
                (origin_summary.get(EvidenceOrigin.ARTIFACT_DERIVED.value) or [])
                + (origin_summary.get(EvidenceOrigin.LOCALLY_OBSERVED.value) or [])
                + (origin_summary.get(EvidenceOrigin.INDEPENDENTLY_VERIFIED.value) or [])
            ),
            "declared_only_facts": _dedupe(
                (origin_summary.get(EvidenceOrigin.USER_ENTERED.value) or [])
                + (origin_summary.get(EvidenceOrigin.PROVIDER_DECLARED.value) or [])
            ),
            "decidability_bounds": decidability_bounds,
        },
        "evidence_gaps": evidence_gaps,
        "recommended_next_steps": next_steps,
    }


def _identity_posture(
    ledger_entries: List[Dict[str, Any]],
    *,
    provenance_assessment: Dict[str, Any],
    pir: float,
) -> Dict[str, str]:
    verified_names = {"provenance_attestation", "sigstore_verification"}
    verified_identity = any(
        entry.get("name") in verified_names
        and coerce_origin(entry.get("origin")) == EvidenceOrigin.INDEPENDENTLY_VERIFIED
        for entry in ledger_entries
    )
    if verified_identity:
        return {
            "status": "INDEPENDENTLY_VERIFIED",
            "reason": "Identity is bound by independently verified provenance evidence.",
        }

    if pir >= 0.6:
        return {
            "status": "ARTIFACT_OBSERVED",
            "reason": "Most decision-driving facts come from artifact inspection or local observation, but identity is not independently verified.",
        }

    if provenance_assessment.get("trust_caps"):
        return {
            "status": "DECLARATION_HEAVY",
            "reason": "Identity and provenance remain capped by missing independent verification.",
        }

    return {
        "status": "DECLARATION_HEAVY",
        "reason": "Identity still rests mainly on operator or publisher declarations.",
    }


def _artifact_inspection(
    serialization_scan: Dict[str, Any],
    weight_inspection: Dict[str, Any],
) -> Dict[str, Any]:
    derived = weight_inspection.get("derived_facts") or {}
    return {
        "artifact_present": bool(serialization_scan or weight_inspection),
        "serialization_status": serialization_scan.get("status"),
        "serialization_findings": serialization_scan.get("match_count"),
        "serialization_high_or_critical": _sum_counts(
            serialization_scan.get("by_severity"), _HIGH_SEVERITIES
        ),
        "weight_inspection_status": weight_inspection.get("status"),
        "format_detected": weight_inspection.get("format_detected"),
        "architecture_family": derived.get("architecture_family"),
        "architecture_name": derived.get("architecture_name"),
        "layer_count": derived.get("layer_count"),
        "hidden_size": derived.get("hidden_size"),
        "vocab_size": derived.get("vocab_size"),
        "parameter_count_estimate": derived.get("parameter_count_estimate"),
        "parameter_count_exact": derived.get("parameter_count_exact"),
        "quantization": derived.get("quantization"),
    }


def _model_card_consistency(
    hf_card: Dict[str, Any],
    *,
    contradictions: List[Dict[str, Any]],
    confirmations: List[Dict[str, Any]],
    unverifiable: List[str],
) -> Dict[str, Any]:
    if contradictions:
        status = "CONTRADICTIONS_FOUND"
    elif confirmations:
        status = "ARTIFACT_CONFIRMED"
    elif hf_card:
        status = "DECLARED_ONLY"
    else:
        status = "NO_MODEL_CARD"

    return {
        "status": status,
        "publisher_declared_fields": sorted(
            [
                field
                for field in (
                    "license",
                    "pipeline_tag",
                    "language",
                    "base_model",
                    "publisher",
                    "model_type",
                    "architectures",
                    "tokenizer_class",
                )
                if hf_card.get(field) is not None
            ]
        ),
        "confirmed_facts": [
            {"fact_name": item.get("fact_name"), "value": item.get("value")}
            for item in confirmations[:12]
        ],
        "contradictions": contradictions[:12],
        "unverifiable_facts": unverifiable,
    }


def _license_posture(
    model_record: Dict[str, Any],
    *,
    hf_card: Dict[str, Any],
    ledger_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    declared_license = (
        model_record.get("license")
        or hf_card.get("license")
        or (model_record.get("metadata") or {}).get("license")
    )
    license_origin = _fact_origin("license", ledger_entries)

    if not declared_license:
        return {
            "status": "LICENSE_MISSING",
            "declared_license": None,
            "origin": license_origin,
            "note": "No license declaration was available for this artifact.",
        }

    normalized = str(declared_license).strip().lower()
    if normalized in _PERMISSIVE_LICENSES:
        status = "PERMISSIVE_DECLARED"
        note = "A permissive license was declared, but AIAF does not independently verify legal grant or downstream obligations."
    elif any(marker in normalized for marker in _RESTRICTIVE_LICENSE_MARKERS):
        status = "RESTRICTED_DECLARED"
        note = "A potentially restrictive or use-limited license was declared; legal review is still required."
    else:
        status = "CUSTOM_OR_UNKNOWN"
        note = "A non-standard or unknown license string was declared; manual review is recommended."

    return {
        "status": status,
        "declared_license": declared_license,
        "origin": license_origin,
        "note": note,
    }


def _security_flags(
    *,
    recommendation: Dict[str, Any],
    serialization_scan: Dict[str, Any],
    vulnerability_scan: Dict[str, Any],
    backdoor_heuristics: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    unknown_model_probe: Dict[str, Any],
) -> Dict[str, Any]:
    contradiction_flags = [
        item for item in contradictions if str(item.get("severity") or "").upper() in _HIGH_SEVERITIES
    ]
    backdoor_findings = backdoor_heuristics.get("findings") or []
    elevated_backdoor = [
        item for item in backdoor_findings if str(item.get("severity") or "").upper() in _HIGH_SEVERITIES
    ]
    recommendation_reasons = recommendation.get("reasons") or []
    blocking_reasons = [
        item
        for item in recommendation_reasons
        if str(item.get("verdict") or "").upper() in {"DO_NOT_APPROVE", "PILOT_ONLY"}
    ]
    probe_findings = unknown_model_probe.get("findings") or []
    high_probe_findings = [
        item for item in probe_findings if str(item.get("severity") or "").upper() in _HIGH_SEVERITIES
    ]
    return {
        "dangerous_serialization": str(serialization_scan.get("status") or "").upper()
        == "UNSAFE_PATTERNS_FOUND",
        "high_or_critical_vulnerability_count": _sum_counts(
            vulnerability_scan.get("by_severity"), _HIGH_SEVERITIES
        ),
        "high_confidence_contradictions": contradiction_flags,
        "backdoor_signals": elevated_backdoor,
        "unknown_model_probe_findings": probe_findings,
        "high_risk_probe_findings": high_probe_findings,
        "blocking_reasons": blocking_reasons[:8],
    }


def _evidence_gaps(
    *,
    recommendation: Dict[str, Any],
    weight_inspection: Dict[str, Any],
    serialization_scan: Dict[str, Any],
    provenance_assessment: Dict[str, Any],
    hf_card: Dict[str, Any],
) -> List[str]:
    gaps = list(recommendation.get("evidence_gaps") or [])
    if not serialization_scan:
        gaps.append("Artifact serialization scan has not been recorded.")
    if not weight_inspection:
        gaps.append("Artifact header inspection has not been recorded.")
    if not hf_card:
        gaps.append("No model card or config-derived publisher metadata was available.")
    if provenance_assessment.get("trust_caps"):
        gaps.append("Independent identity/provenance verification is still missing.")
    return _dedupe(gaps)


def _next_steps(
    *,
    identity: Dict[str, str],
    model_card_consistency: Dict[str, Any],
    security_flags: Dict[str, Any],
    evidence_gaps: List[str],
    artifact_inspection: Dict[str, Any],
) -> List[str]:
    steps: List[str] = []

    if security_flags.get("dangerous_serialization"):
        steps.append("Block adoption until the unsafe serialization pattern is removed or a safer artifact format is provided.")
    if security_flags.get("high_or_critical_vulnerability_count"):
        steps.append("Review and remediate high or critical dependency vulnerabilities before deployment.")
    if security_flags.get("high_confidence_contradictions"):
        steps.append("Resolve contradictions between declared metadata and artifact-observed facts before trusting the checkpoint identity.")
    if identity.get("status") != "INDEPENDENTLY_VERIFIED":
        steps.append("Obtain independently verified provenance evidence, such as a verified attestation or signature.")
    if model_card_consistency.get("status") in {"NO_MODEL_CARD", "DECLARED_ONLY"}:
        steps.append("Capture stronger artifact-native evidence to reduce reliance on publisher declarations.")
    if not artifact_inspection.get("weight_inspection_status"):
        steps.append("Retain an inspectable artifact file so AIAF can derive architecture and parameter facts directly from the weights.")
    if evidence_gaps and len(steps) < 5:
        steps.append("Close the remaining evidence gaps before treating this model as production-ready.")
    return _dedupe(steps)


def _overall_posture(
    *,
    identity: Dict[str, str],
    artifact_inspection: Dict[str, Any],
    model_card_consistency: Dict[str, Any],
    security_flags: Dict[str, Any],
    provenance_score: Optional[float],
) -> str:
    if (
        security_flags.get("dangerous_serialization")
        or (security_flags.get("high_or_critical_vulnerability_count") or 0) > 0
        or security_flags.get("high_confidence_contradictions")
        or security_flags.get("backdoor_signals")
        or security_flags.get("high_risk_probe_findings")
    ):
        return "DO_NOT_TRUST"

    inspected = str(artifact_inspection.get("weight_inspection_status") or "").upper() == "INSPECTED"
    serial_clean = str(artifact_inspection.get("serialization_status") or "").upper() in {"CLEAN", ""}
    confirmed = model_card_consistency.get("status") == "ARTIFACT_CONFIRMED"

    if (
        identity.get("status") == "INDEPENDENTLY_VERIFIED"
        and inspected
        and serial_clean
        and confirmed
        and (provenance_score or 0) >= 70
    ):
        return "SUBSTANTIAL_ASSURANCE"

    if inspected or artifact_inspection.get("serialization_status"):
        return "ARTIFACT_OBSERVED"

    return "DECLARATION_HEAVY"


def _summary(
    posture: str,
    *,
    identity: Dict[str, str],
    security_flags: Dict[str, Any],
    artifact_inspection: Dict[str, Any],
) -> str:
    if posture == "DO_NOT_TRUST":
        return "AIAF found blocking security or identity issues. This model should not be trusted for adoption until those issues are resolved."
    if posture == "SUBSTANTIAL_ASSURANCE":
        return "AIAF could inspect the artifact, confirm key declared facts against observed evidence, and tie identity to verified provenance."
    if posture == "ARTIFACT_OBSERVED":
        return (
            "AIAF inspected the artifact directly, but trust still stops short of independent identity verification."
            if identity.get("status") != "INDEPENDENTLY_VERIFIED"
            else "AIAF inspected the artifact directly and established a stronger-than-declarative view, though some gaps remain."
        )
    if artifact_inspection.get("artifact_present"):
        return "AIAF has some artifact evidence, but the current trust picture is still dominated by declarations and missing verification."
    return "AIAF currently relies mostly on operator or publisher declarations for this model."


def _fact_origin(name: str, ledger_entries: Iterable[Dict[str, Any]]) -> Optional[str]:
    strongest: Optional[EvidenceOrigin] = None
    for entry in ledger_entries:
        if entry.get("name") != name:
            continue
        origin = coerce_origin(entry.get("origin"))
        if strongest is None or origin.value == EvidenceOrigin.INDEPENDENTLY_VERIFIED.value:
            strongest = origin
        elif _origin_rank(origin) > _origin_rank(strongest):
            strongest = origin
    return strongest.value if strongest else None


def _origin_rank(origin: EvidenceOrigin) -> int:
    order = {
        EvidenceOrigin.USER_ENTERED: 0,
        EvidenceOrigin.PROVIDER_DECLARED: 1,
        EvidenceOrigin.ARTIFACT_DERIVED: 2,
        EvidenceOrigin.LOCALLY_OBSERVED: 3,
        EvidenceOrigin.INDEPENDENTLY_VERIFIED: 4,
    }
    return order.get(origin, 0)


def _sum_counts(raw: Any, severities: Iterable[str]) -> int:
    if not isinstance(raw, dict):
        return 0
    wanted = {str(item).upper() for item in severities}
    total = 0
    for key, value in raw.items():
        if str(key).upper() in wanted:
            try:
                total += int(value)
            except (TypeError, ValueError):
                continue
    return total


def _safe_number(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for item in items:
        key = repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out

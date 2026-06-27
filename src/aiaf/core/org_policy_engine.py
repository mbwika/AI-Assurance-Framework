"""Organization policy engine for external model adoption.

Phase 4 adds an organization-defined approval layer on top of the evidence and
risk posture already computed by AIAF. The policy question is different from
"is the model risky?": given the intended use case, data sensitivity, and
deployment exposure, *what evidence bar must be met before this organization
should approve it, and what scope restrictions must apply?*

This module evaluates three operator-facing context dimensions:

``use_case``
    What the model will be used for. High-stakes uses (healthcare, finance,
    hiring, legal, law enforcement, security operations, identity decisions)
    require stronger evidence and tighter operating scope.
``data_classification``
    The most sensitive data the model will touch. Regulated or highly sensitive
    data raises the evidence bar.
``deployment_exposure``
    How exposed the model is operationally (internal vs authenticated vs
    external/public). Public exposure requires runtime evidence such as live
    behavioral probes.

Outputs are machine-readable so the adoption engine and UI can explain:
- what policy context was applied,
- which evidence items were required,
- which of those requirements were met or missing,
- what approval scope the organization should attach to the verdict.
"""

from __future__ import annotations

from typing import Any

from ..registry.evidence_origin import (
    EvidenceOrigin,
    coerce_origin,
    is_verified_grade,
    ledger_from_list,
)

ORG_POLICY_VERSION = "1.0"

_USE_CASE_LOW = {
    "",
    "general",
    "experimentation",
    "research",
    "summarization",
    "translation",
    "knowledge_assistant",
    "productivity",
    "customer_support",
    "search",
}

_USE_CASE_HIGH = {
    "healthcare",
    "clinical",
    "medical",
    "finance",
    "financial_services",
    "banking",
    "payments",
    "hiring",
    "recruitment",
    "employment",
    "law_enforcement",
    "policing",
    "legal",
    "identity",
    "identity_verification",
    "security",
    "security_operations",
    "cybersecurity",
    "education",
    "critical_infrastructure",
}

_DATA_TIERS = {
    "public": 0,
    "open": 0,
    "none": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 2,
    "proprietary": 2,
    "pii": 3,
    "personal": 3,
    "personal_data": 3,
    "phi": 4,
    "pci": 4,
    "biometric": 4,
    "secret": 4,
    "regulated": 4,
}

_EXPOSURE_TIERS = {
    "internal": 0,
    "private": 0,
    "authenticated": 1,
    "partner": 1,
    "restricted": 1,
    "external": 2,
    "public": 2,
    "internet": 2,
    "anonymous": 3,
}

_APPROVAL_SCOPE = {
    "baseline": {
        "allowed_exposure": "internal_or_authenticated",
        "allowed_data": "internal_or_lower",
        "requires_change_review": False,
        "requires_continuous_monitoring": False,
        "notes": [
            "Approval applies only to the declared use case and registered model artifact."
        ],
    },
    "heightened": {
        "allowed_exposure": "authenticated_or_restricted",
        "allowed_data": "restricted_or_lower",
        "requires_change_review": True,
        "requires_continuous_monitoring": True,
        "notes": [
            "Maintain named ownership and monitor the deployment for drift and abuse signals.",
            "Do not broaden the use case, data scope, or exposure path without re-triage.",
        ],
    },
    "pilot_only": {
        "allowed_exposure": "internal_pilot",
        "allowed_data": "synthetic_or_minimized_sensitive_data",
        "requires_change_review": True,
        "requires_continuous_monitoring": True,
        "notes": [
            "Limit adoption to a monitored pilot with rollback, kill switch, and explicit operator oversight.",
            "Do not expose the model to anonymous/public users under this approval scope.",
        ],
    },
}


def evaluate_org_policy(
    model_record: dict[str, Any],
    *,
    policy_context: dict[str, Any] | None = None,
    provenance_assessment: dict[str, Any] | None = None,
    governance_summary: dict[str, Any] | None = None,
    vulnerability_scan: dict[str, Any] | None = None,
    serialization_scan: dict[str, Any] | None = None,
    behavioral_probes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply organization policy to a model adoption decision."""
    model_record = model_record if isinstance(model_record, dict) else {}
    provenance_assessment = provenance_assessment or {}
    governance_summary = governance_summary or {}
    vulnerability_scan = vulnerability_scan or {}
    metadata = model_record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    ledger = ledger_from_list(metadata.get("evidence_ledger"))

    context = _resolve_policy_context(model_record, policy_context)
    posture = _policy_posture(context)
    requirements = _build_requirements(
        context,
        ledger,
        provenance_assessment,
        governance_summary,
        vulnerability_scan,
        serialization_scan,
        behavioral_probes,
    )
    missing = [req for req in requirements if req.get("required") and not req.get("met")]

    caps: list[dict[str, Any]] = []
    conditions: list[str] = []
    evidence_gaps: list[str] = []

    for req in missing:
        evidence_gaps.append(req["gap"])

    if posture["level"] in {"high", "critical"} and missing:
        summary = ", ".join(req["label"] for req in missing[:4])
        caps.append(
            {
                "verdict": "INSUFFICIENT_EVIDENCE",
                "category": "org_policy",
                "reason": (
                    "Organization policy for this use case requires more evidence before approval: "
                    f"{summary}."
                ),
                "refs": [req["id"] for req in missing],
                "origin": None,
            }
        )

    if posture["level"] == "critical":
        caps.append(
            {
                "verdict": "APPROVE_WITH_CONDITIONS",
                "category": "approval_scope",
                "reason": (
                    "This model is being evaluated for a high-sensitivity and externally exposed "
                    "context; any approval must remain tightly scoped."
                ),
                "refs": [context["use_case"], context["data_classification"], context["deployment_exposure"]],
                "origin": None,
            }
        )
        conditions.extend(_APPROVAL_SCOPE["pilot_only"]["notes"])
    elif posture["level"] == "high":
        caps.append(
            {
                "verdict": "APPROVE_WITH_CONDITIONS",
                "category": "approval_scope",
                "reason": (
                    "Organization policy treats this context as heightened; approval must stay "
                    "within a reviewed operating scope."
                ),
                "refs": [context["use_case"], context["data_classification"], context["deployment_exposure"]],
                "origin": None,
            }
        )
        conditions.extend(_APPROVAL_SCOPE["heightened"]["notes"])
    elif posture["level"] == "medium":
        conditions.append(
            "Keep approval bound to the declared use case and reassess before increasing exposure or data sensitivity."
        )

    scope_key = "baseline"
    if posture["level"] == "critical":
        scope_key = "pilot_only"
    elif posture["level"] in {"high", "medium"}:
        scope_key = "heightened"

    return {
        "policy_version": ORG_POLICY_VERSION,
        "context": context,
        "posture": posture,
        "required_evidence": requirements,
        "missing_required_evidence": [req["id"] for req in missing],
        "caps": caps,
        "conditions": conditions,
        "evidence_gaps": evidence_gaps,
        "approval_scope": {
            **_APPROVAL_SCOPE[scope_key],
            "use_case": context["use_case"],
            "data_classification": context["data_classification"],
            "deployment_exposure": context["deployment_exposure"],
        },
    }


def _resolve_policy_context(
    model_record: dict[str, Any],
    policy_context: dict[str, Any] | None,
) -> dict[str, str]:
    metadata = model_record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    profile = metadata.get("model_risk_profile")
    profile = profile if isinstance(profile, dict) else {}
    supplied = policy_context if isinstance(policy_context, dict) else {}

    use_case = _norm(
        supplied.get("use_case")
        or supplied.get("intended_use")
        or metadata.get("use_case")
        or metadata.get("intended_use")
        or profile.get("domain")
        or metadata.get("domain")
        or model_record.get("domain")
        or "general"
    )
    data_classification = _norm(
        supplied.get("data_classification")
        or supplied.get("data_sensitivity")
        or profile.get("data_classification")
        or metadata.get("data_classification")
        or model_record.get("data_classification")
        or "internal"
    )
    deployment_exposure = _norm(
        supplied.get("deployment_exposure")
        or supplied.get("exposure")
        or profile.get("deployment_exposure")
        or metadata.get("deployment_exposure")
        or model_record.get("deployment_exposure")
        or "internal"
    )
    user_access = _norm(
        supplied.get("user_access")
        or profile.get("user_access")
        or metadata.get("user_access")
        or model_record.get("user_access")
        or ""
    )
    if user_access == "anonymous" and _EXPOSURE_TIERS.get(deployment_exposure, 0) < 3:
        deployment_exposure = "anonymous"

    return {
        "use_case": use_case,
        "data_classification": data_classification,
        "deployment_exposure": deployment_exposure,
        "user_access": user_access or "unspecified",
    }


def _policy_posture(context: dict[str, str]) -> dict[str, Any]:
    use_case_tier = _use_case_tier(context["use_case"])
    data_tier = _DATA_TIERS.get(context["data_classification"], 1)
    exposure_tier = _EXPOSURE_TIERS.get(context["deployment_exposure"], 0)
    score = use_case_tier + data_tier + exposure_tier

    if data_tier >= 4 and exposure_tier >= 2:
        level = "critical"
    elif score >= 6 or (use_case_tier >= 3 and exposure_tier >= 2):
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    return {
        "level": level,
        "score": score,
        "use_case_tier": use_case_tier,
        "data_tier": data_tier,
        "exposure_tier": exposure_tier,
    }


def _build_requirements(
    context: dict[str, str],
    ledger,
    provenance: dict[str, Any],
    governance: dict[str, Any],
    vuln: dict[str, Any],
    serialization_scan: dict[str, Any] | None,
    behavioral_probes: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    posture = _policy_posture(context)
    requirements: list[dict[str, Any]] = []

    def add(
        req_id: str,
        label: str,
        required: bool,
        met: bool,
        gap: str,
    ) -> None:
        requirements.append(
            {
                "id": req_id,
                "label": label,
                "required": required,
                "met": met,
                "gap": gap,
            }
        )

    verified_identity = _has_verified_identity(ledger)
    signed_attestation = _has_verified_attestation(ledger)
    governance_clear = not (governance.get("gaps") or [])
    vuln_complete = bool(vuln) and vuln.get("assessment_complete") is not False
    serialization_complete = (
        serialization_scan is not None
        and str(serialization_scan.get("status") or "").upper()
        not in {"NO_FILE", "UNSUPPORTED_FORMAT", "SCAN_ERROR"}
    )
    probes_complete = (
        behavioral_probes is not None
        and str(behavioral_probes.get("status") or "").upper() == "COMPLETED"
    )
    provenance_complete = (
        bool(provenance)
        and provenance.get("assessment_complete") is not False
        and isinstance(provenance.get("confidence"), (int, float))
        and float(provenance.get("confidence")) >= 0.45
    )

    high_context = posture["level"] in {"high", "critical"}
    public_context = posture["exposure_tier"] >= 2
    sensitive_context = posture["data_tier"] >= 3

    add(
        "provenance_complete",
        "Complete provenance assessment",
        True,
        provenance_complete,
        "Complete, confidence-bounded provenance assessment for the declared deployment context.",
    )
    add(
        "vulnerability_coverage",
        "Dependency vulnerability coverage",
        True,
        vuln_complete,
        "Complete dependency vulnerability coverage for the model's resolved components.",
    )
    add(
        "verified_identity",
        "Independently verified model identity",
        high_context or sensitive_context,
        verified_identity,
        "Independently verified model identity (publisher/source) for this high-trust deployment context.",
    )
    add(
        "signed_provenance",
        "Verified signed provenance attestation",
        high_context,
        signed_attestation,
        "Verified signed provenance attestation binding model identity and artifact digest.",
    )
    add(
        "serialization_scan",
        "Artifact serialization safety scan",
        public_context or high_context,
        serialization_complete,
        "Artifact-level serialization safety scan before approving this exposure profile.",
    )
    add(
        "behavioral_probes",
        "Live behavioral safety evaluation",
        public_context,
        probes_complete,
        "Live behavioral safety evaluation against the endpoint for a publicly reachable deployment.",
    )
    add(
        "governance_gaps_closed",
        "Closed governance evidence gaps",
        sensitive_context or high_context,
        governance_clear,
        "Close governance evidence gaps before approving this use case and data scope.",
    )

    return requirements


def _use_case_tier(value: str) -> int:
    if value in _USE_CASE_LOW:
        return 0
    if value in _USE_CASE_HIGH:
        return 3
    return 1


def _has_verified_attestation(ledger) -> bool:
    return any(
        coerce_origin(fact.get("origin")) == EvidenceOrigin.INDEPENDENTLY_VERIFIED
        and fact.get("name") in {"provenance_attestation", "sigstore_verification"}
        for fact in ledger.to_list()
    )


def _has_verified_identity(ledger) -> bool:
    if _has_verified_attestation(ledger):
        return True
    weakest = ledger.weakest_origin(("publisher", "source", "source_url", "repository"))
    return weakest is not None and is_verified_grade(weakest)


def _norm(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text

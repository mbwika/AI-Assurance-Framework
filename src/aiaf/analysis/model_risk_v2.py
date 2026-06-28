"""Uncertainty-aware model impact, exposure, and safeguard risk heuristics."""

import math
import re
from collections import OrderedDict
from collections.abc import Iterable
from typing import Any

MODEL_RISK_SCORING_VERSION = "2.0"
PROVIDER_RISK_INTELLIGENCE_VERSION = "1.0"
_MAX_CAPABILITIES = 100
_MAX_CONNECTED_SYSTEMS = 1_000
_MAX_CONTEXT_ENTRIES = 100
_MAX_CONTROL_ITEMS = 100
_MAX_TEXT_CHARS = 256

HIGH_IMPACT_DOMAINS = {
    "biometrics": 8.5,
    "critical_infrastructure": 9.5,
    "credit": 8.0,
    "education": 7.0,
    "employment": 8.0,
    "healthcare": 9.0,
    "insurance": 8.0,
    "law_enforcement": 9.5,
    "legal": 8.5,
    "public_benefits": 8.5,
    "essential_services": 9.0,
}

CAPABILITY_RISK = {
    "autonomous_actions": 8.5,
    "biometric_identification": 8.5,
    "code_execution": 9.5,
    "external_communications": 6.5,
    "financial_transactions": 9.5,
    "identity_decisions": 8.5,
    "medical_decisions": 9.5,
    "physical_control": 10.0,
    "privileged_data_access": 8.0,
    "tool_use": 6.0,
}

_IMPACT_LEVELS = {
    "minimal": 1.0,
    "low": 1.0,
    "moderate": 4.0,
    "medium": 4.0,
    "high": 7.5,
    "critical": 10.0,
    "severe": 10.0,
}
_EXPOSURE_LEVELS = {
    "offline": 0.5,
    "isolated": 1.0,
    "restricted": 2.0,
    "internal": 3.0,
    "partner": 5.0,
    "external": 8.0,
    "internet": 9.0,
    "public": 10.0,
}
_ACCESS_LEVELS = {
    "service_account": 2.0,
    "restricted": 2.0,
    "privileged": 2.5,
    "authenticated": 4.0,
    "employees": 4.0,
    "customers": 6.0,
    "public": 9.0,
    "anonymous": 10.0,
}
_DATA_LEVELS = {
    "public": 0.5,
    "internal": 2.5,
    "proprietary": 5.0,
    "confidential": 6.5,
    "pii": 7.5,
    "financial": 8.0,
    "restricted": 8.5,
    "credentials": 9.0,
    "authentication_data": 9.0,
    "phi": 9.0,
    "secret": 10.0,
}
_DECISION_AUTHORITY = {
    "none": 0.0,
    "informational": 1.0,
    "assistive": 2.0,
    "advisory": 3.0,
    "recommendation": 4.0,
    "ranking": 5.0,
    "approval": 7.0,
    "automated_decision": 9.0,
    "final_decision": 10.0,
}
_REVERSIBILITY = {
    "fully_reversible": 1.0,
    "reversible": 2.0,
    "partially_reversible": 6.0,
    "difficult": 8.0,
    "irreversible": 10.0,
}
_SAFETY_CRITICALITY = {
    "none": 0.0,
    "low": 2.0,
    "material": 6.0,
    "high": 8.0,
    "safety_critical": 10.0,
}
_DEPLOYMENT_SCALE = {
    "prototype": 1.0,
    "pilot": 2.0,
    "limited": 3.0,
    "department": 4.0,
    "organization": 5.5,
    "regional": 7.0,
    "national": 9.0,
    "global": 10.0,
}
_DISABLED_VALUES = {
    "",
    "0",
    "false",
    "none",
    "no",
    "disabled",
    "off",
    "not_configured",
    "not_applicable",
}
_TOOL_CAPABILITIES = {
    "shell": {"tool_use", "code_execution"},
    "code_interpreter": {"tool_use", "code_execution"},
    "filesystem": {"tool_use", "privileged_data_access"},
    "database": {"tool_use", "privileged_data_access"},
    "email": {"tool_use", "external_communications"},
    "browser": {"tool_use", "external_communications"},
    "http": {"tool_use", "external_communications"},
    "payment": {"tool_use", "financial_transactions"},
    "cloud_admin": {"tool_use", "autonomous_actions"},
}
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_LOW_RISK_LICENSES = frozenset(
    {
        "apache-2.0",
        "mit",
        "bsd-2-clause",
        "bsd-3-clause",
        "mpl-2.0",
        "cc-by-4.0",
    }
)
_MEDIUM_RISK_LICENSES = frozenset(
    {
        "openrail",
        "openrail++",
        "cc-by-sa-4.0",
        "cc-by-nc-4.0",
        "gpl-3.0",
        "lgpl-3.0",
    }
)
_HIGH_RISK_LICENSES = frozenset(
    {
        "unknown",
        "proprietary",
        "custom",
        "llama2",
        "llama3",
        "gemma",
    }
)
_KNOWN_PROVIDER_HOST_RISK = {
    "huggingface.co": 2.5,
    "github.com": 3.5,
    "hf.co": 2.5,
    "modelscope.cn": 3.5,
    "openai.com": 3.0,
    "azure.com": 3.0,
    "amazonaws.com": 3.0,
}


def estimate_model_risk_v2(
    artifact: dict[str, Any], assessment_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Estimate conservative residual model risk on a bounded 0-10 scale."""
    factors: list[dict[str, Any]] = []
    recommendations: list[str] = []
    assessment_complete = True

    if not isinstance(artifact, dict):
        artifact = {}
        assessment_complete = False
        _append_factor(
            factors,
            "malformed_model_artifact",
            "evidence_quality",
            0.0,
            "HIGH",
            "Model risk evidence must be an object.",
            "Provide a structured model-risk artifact.",
        )

    profile_value = artifact.get("model_risk_profile")
    if profile_value is None:
        profile_value = artifact.get("impact_assessment")
    if profile_value is None:
        profile = {}
        _append_factor(
            factors,
            "missing_model_risk_profile",
            "evidence_quality",
            0.0,
            "HIGH",
            "No structured model-risk profile was supplied.",
            "Document impact, exposure, data, capabilities, affected people, and safeguards.",
        )
    elif not isinstance(profile_value, dict):
        profile = {}
        assessment_complete = False
        _append_factor(
            factors,
            "malformed_model_risk_profile",
            "evidence_quality",
            0.0,
            "HIGH",
            "Model-risk profile must be an object.",
            "Provide a structured model-risk profile.",
        )
    else:
        profile = profile_value

    context, context_complete = _assessment_context(assessment_context, factors)
    assessment_complete = assessment_complete and context_complete
    domain_scores = {**HIGH_IMPACT_DOMAINS, **context["domain_risk_scores"]}
    capability_scores = {**CAPABILITY_RISK, **context["capability_risk_scores"]}

    identity_present = bool(
        _bounded_text(artifact.get("model_name") or artifact.get("model_id") or artifact.get("id"))
    )
    if not identity_present:
        _append_factor(
            factors,
            "missing_model_identity",
            "evidence_quality",
            0.0,
            "MEDIUM",
            "Model identity is missing.",
            "Bind the assessment to a stable model name and version.",
        )

    raw = {
        "impact_level": _value(profile, artifact, "impact_level"),
        "domain": _value(profile, artifact, "domain"),
        "deployment_exposure": _value(profile, artifact, "deployment_exposure"),
        "user_access": _value(profile, artifact, "user_access"),
        "data_classification": _value(profile, artifact, "data_classification"),
        "decision_authority": _value(profile, artifact, "decision_authority"),
        "reversibility": _value(profile, artifact, "reversibility"),
        "safety_criticality": _value(profile, artifact, "safety_criticality"),
        "deployment_scale": _value(profile, artifact, "deployment_scale"),
        "affected_users": _value(profile, artifact, "affected_users"),
        "connected_systems": _value(profile, artifact, "connected_systems"),
        "capabilities": _value(profile, artifact, "capabilities"),
        "vulnerable_populations": _value(profile, artifact, "vulnerable_populations"),
        "handles_sensitive_data": _value(profile, artifact, "handles_sensitive_data"),
    }

    normalized, normalization_complete = _normalize_profile(
        raw, domain_scores, capability_scores, factors
    )
    provider_intelligence = assess_provider_risk_intelligence(artifact, assessment_context)
    assessment_complete = assessment_complete and normalization_complete
    inferred_capabilities, inference_complete = _infer_capabilities(artifact)
    if not inference_complete:
        assessment_complete = False
        _append_factor(
            factors,
            "tool_capability_inference_limit_exceeded",
            "evidence_quality",
            0.0,
            "HIGH",
            "Tool inventory is malformed or exceeds the capability-inference bound.",
            "Provide a bounded tool inventory and assess segmented agents separately.",
        )
    undeclared = sorted(inferred_capabilities - normalized["capabilities"])
    if undeclared:
        normalized["capabilities"].update(undeclared)
        _append_factor(
            factors,
            "undeclared_high_risk_capability",
            "capability",
            0.0,
            "HIGH",
            "Operational tool evidence implies capabilities absent from the declared profile.",
            "Reconcile declared capabilities with enabled tools and runtime behavior.",
            evidence=undeclared,
        )

    impact_signals = []
    _signal(impact_signals, "impact_level", normalized["impact_score"], 1.0)
    _signal(impact_signals, "domain", normalized["domain_score"], 0.9)
    _signal(impact_signals, "decision_authority", normalized["decision_score"], 0.9)
    _signal(impact_signals, "reversibility", normalized["reversibility_score"], 0.7)
    _signal(impact_signals, "safety_criticality", normalized["criticality_score"], 1.0)
    if normalized["vulnerable_populations"]:
        _signal(impact_signals, "vulnerable_populations", 8.5, 0.8)
    impact = _dimension("impact", impact_signals, assumed_score=4.0)

    exposure_signals = []
    _signal(exposure_signals, "deployment_exposure", normalized["exposure_score"], 1.0)
    _signal(exposure_signals, "user_access", normalized["access_score"], 0.8)
    _signal(exposure_signals, "deployment_scale", normalized["scale_score"], 0.7)
    _signal(exposure_signals, "connected_systems", normalized["connected_score"], 0.6)
    exposure = _dimension("exposure", exposure_signals, assumed_score=3.0)

    capability_signals = [
        {
            "name": capability,
            "score": capability_scores.get(capability, 3.0),
            "weight": 1.0,
        }
        for capability in sorted(normalized["capabilities"])
    ]
    capability = _dimension("capability", capability_signals, assumed_score=1.0)
    if len(capability_signals) > 1:
        capability["score"] = round(
            min(10.0, capability["score"] + 0.35 * (len(capability_signals) - 1)),
            3,
        )

    data_signals = []
    _signal(data_signals, "data_classification", normalized["data_score"], 1.0)
    if normalized["handles_sensitive_data"]:
        _signal(data_signals, "handles_sensitive_data", 8.0, 0.9)
    data = _dimension("data", data_signals, assumed_score=2.5)

    dimensions = OrderedDict(
        (
            ("impact", impact),
            ("exposure", exposure),
            ("capability", capability),
            ("data", data),
        )
    )
    coherence_complete = _profile_coherence(normalized, factors)
    assessment_complete = assessment_complete and coherence_complete
    dimension_weights = {"impact": 0.35, "exposure": 0.25, "capability": 0.25, "data": 0.15}
    inherent_base = math.sqrt(
        sum(
            dimension_weights[name] * dimensions[name]["score"] ** 2
            for name in dimension_weights
        )
    )

    interactions = _interaction_risks(normalized, dimensions, factors)
    interaction_bonus = min(3.0, sum(item["bonus"] for item in interactions))
    inherent_risk = round(min(10.0, inherent_base + interaction_bonus), 3)

    controls = _assess_controls(profile, artifact, normalized, dimensions, factors)
    assessment_complete = assessment_complete and controls["assessment_complete"]
    reduction_cap = context["control_reduction_cap"]
    control_reduction = reduction_cap * controls["effectiveness"]
    residual_point = round(inherent_risk * (1.0 - control_reduction), 3)

    evidence_quality = _evidence_quality(raw, identity_present, controls, factors)
    uncertainty_margin = round((1.0 - evidence_quality["confidence"]) * 3.0, 3)
    lower_bound = round(
        max(0.0, inherent_risk * (1.0 - min(0.6, control_reduction + 0.1))),
        3,
    )
    upper_bound = round(min(10.0, residual_point + uncertainty_margin), 3)

    score_gates = _score_gates(normalized, dimensions, controls, interactions)
    for gate in score_gates:
        upper_bound = max(upper_bound, gate["minimum_score"])
    upper_bound = round(min(10.0, upper_bound), 3)
    risk_score = upper_bound
    severity = _severity(risk_score)
    for gate in score_gates:
        if _SEVERITY_ORDER[gate["minimum_severity"]] > _SEVERITY_ORDER[severity]:
            severity = gate["minimum_severity"]

    for factor in factors:
        recommendation = factor.get("recommendation")
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    essential_fields = (
        "impact_level",
        "deployment_exposure",
        "data_classification",
        "capabilities",
    )
    if any(raw[field] is None for field in essential_fields):
        assessment_complete = False

    if provider_intelligence["overall_risk_score"] >= 7.0:
        _append_factor(
            factors,
            "provider_supply_chain_risk",
            "supply_chain",
            0.0,
            provider_intelligence["severity"],
            "Provider, maintainer, license, or adoption evidence indicates elevated third-party risk.",
            "Review provider provenance, publisher identity, disclosure quality, and adoption anomalies before deployment.",
            evidence={
                "provider_risk_score": provider_intelligence["overall_risk_score"],
                "provider_indicators": provider_intelligence["indicators"][:10],
            },
        )
    for recommendation in provider_intelligence["recommendations"]:
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    return {
        "assessment_version": MODEL_RISK_SCORING_VERSION,
        "scoring_version": MODEL_RISK_SCORING_VERSION,
        "methodology": "uncertainty_aware_inherent_control_residual_model_risk",
        "score_scale": {"minimum": 0.0, "maximum": 10.0},
        "risk_score": risk_score,
        "score": risk_score,
        "inherent_risk_score": inherent_risk,
        "residual_risk_score": residual_point,
        "lower_confidence_bound": lower_bound,
        "upper_confidence_bound": upper_bound,
        "uncertainty_margin": uncertainty_margin,
        "severity": severity,
        "confidence": evidence_quality["confidence"],
        "assessment_complete": assessment_complete,
        "indicators": _unique(factor["indicator"] for factor in factors),
        "factors": factors,
        "dimensions": dimensions,
        "interactions": interactions,
        "control_assessment": controls,
        "evidence_quality": evidence_quality,
        "score_gates": score_gates,
        "evidence": {
            "impact_level": normalized["impact_level"],
            "domain": normalized["domain"] or None,
            "deployment_exposure": normalized["deployment_exposure"],
            "data_classification": normalized["data_classification"],
            "user_access": normalized["user_access"],
            "decision_authority": normalized["decision_authority"],
            "reversibility": normalized["reversibility"],
            "deployment_scale": normalized["deployment_scale"],
            "affected_users": normalized["affected_users"],
            "capabilities": sorted(normalized["capabilities"]),
            "inferred_capabilities": sorted(inferred_capabilities),
            "vulnerable_populations": normalized["vulnerable_populations"],
        },
        "provider_risk_intelligence": provider_intelligence,
        "recommendations": recommendations,
    }


def assess_provider_risk_intelligence(
    artifact: dict[str, Any], assessment_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Assess provider, maintainer, license, and adoption evidence on a 0-10 risk scale."""
    from ..registry.hf_model_card import summarize_disclosure_posture
    from .adoption_velocity import summarize_velocity_risk

    assessment_context = assessment_context if isinstance(assessment_context, dict) else {}
    artifact = artifact if isinstance(artifact, dict) else {}
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    card_data = metadata.get("hf_model_card") if isinstance(metadata.get("hf_model_card"), dict) else {}
    provider_factors: list[dict[str, Any]] = []
    recommendations: list[str] = []

    source = _normalize(metadata.get("provider") or artifact.get("source"))
    source_url = _bounded_text(artifact.get("source_url") or metadata.get("source_url"))
    host, namespace = _source_host_and_namespace(source_url)
    provider_name = source or _normalize(metadata.get("runtime_provider")) or (host.split(".")[0] if host else None)

    provider_score = 8.0
    provider_detail = "Provider origin is missing or cannot be corroborated from source evidence."
    if host and provider_name and provider_name in host.replace(".", "_"):
        provider_score = _KNOWN_PROVIDER_HOST_RISK.get(host, 3.5)
        provider_detail = "Provider identity is corroborated by the artifact source host."
    elif host:
        provider_score = _KNOWN_PROVIDER_HOST_RISK.get(host, 5.5)
        provider_detail = "Artifact source host provides some provider identity evidence."
    elif provider_name:
        provider_score = 5.0
        provider_detail = "Provider identity is declared but not corroborated by a source URL."
    if host and provider_name and provider_name not in host.replace(".", "_") and source:
        provider_score = max(provider_score, 8.5)
        _append_factor(
            provider_factors,
            "provider_identity_conflict",
            "provider",
            0.0,
            "HIGH",
            "Declared provider conflicts with the artifact source host.",
            "Align the declared provider with the effective registry or hosting source.",
            evidence={"provider": provider_name, "host": host},
        )
        recommendations.append("Reconcile provider identity with the artifact source URL and registry host.")

    publisher_claims = _publisher_claims(artifact, metadata, card_data, namespace)
    publisher_score = 7.5
    publisher_detail = "Publisher identity is missing."
    if len(publisher_claims) >= 2:
        publisher_score = 8.5
        publisher_detail = "Publisher identity conflicts across registry, model card, or source namespace evidence."
        _append_factor(
            provider_factors,
            "publisher_identity_conflict",
            "publisher",
            0.0,
            "HIGH",
            publisher_detail,
            "Align publisher identity across registry, model card, and source namespace evidence.",
            evidence=sorted(publisher_claims),
        )
        recommendations.append("Resolve conflicting publisher or namespace claims before relying on the artifact.")
    elif publisher_claims:
        publisher_score = 2.0 if namespace else 4.0
        publisher_detail = (
            "Publisher identity is corroborated by repository namespace evidence."
            if namespace
            else "Publisher identity is declared but not corroborated by namespace evidence."
        )

    maintainer_score = 7.0
    maintainer_detail = "Maintainer attribution is sparse."
    if card_data.get("publisher") and (card_data.get("model_card_signals") or {}).get("sections_present"):
        maintainer_score = 2.5
        maintainer_detail = "Maintainer attribution is supported by a structured model card."
    elif artifact.get("publisher") or metadata.get("publisher"):
        maintainer_score = 4.5
        maintainer_detail = "Maintainer attribution is declared but has limited supporting metadata."
    else:
        _append_factor(
            provider_factors,
            "maintainer_attribution_missing",
            "maintainer",
            0.0,
            "MEDIUM",
            "Maintainer attribution is missing from provider metadata.",
            "Record accountable publisher or maintainer identity for the artifact.",
        )
        recommendations.append("Capture accountable maintainer identity and publication ownership.")

    license_score, license_detail = _license_posture(artifact, metadata, card_data, provider_factors, recommendations)
    disclosure = summarize_disclosure_posture(card_data)
    disclosure_score = float(disclosure["risk_score"])
    if disclosure_score >= 6.5:
        _append_factor(
            provider_factors,
            "model_card_disclosure_gap",
            "disclosure",
            0.0,
            "MEDIUM" if disclosure_score < 8.0 else "HIGH",
            "Model-card disclosures are incomplete for provider due diligence.",
            "Publish intended use, training-data, evaluation, limitation, safety, and privacy disclosures.",
            evidence={"missing_disclosures": disclosure["missing_disclosures"]},
        )
        recommendations.append("Improve model-card disclosures for safety, privacy, evaluation, and intended use.")

    adoption_summary = summarize_velocity_risk(
        metadata.get("adoption_velocity_assessment")
        or metadata.get("adoption_velocity")
        or metadata.get("adoption_velocity_profile")
        or artifact.get("adoption_velocity_assessment")
        or artifact.get("adoption_velocity")
    )
    adoption_score = float(adoption_summary["risk_score"])
    if adoption_summary["risk_level"] in {"HIGH", "CRITICAL"}:
        _append_factor(
            provider_factors,
            "adoption_velocity_anomaly",
            "adoption",
            0.0,
            adoption_summary["risk_level"],
            "Adoption velocity evidence suggests coordinated promotion, spike abuse, or anomalous uptake.",
            "Require heightened provider review and validate legitimacy before deployment.",
            evidence={"signals": adoption_summary["signals"]},
        )
        recommendations.append("Investigate abnormal adoption velocity before trusting the artifact supply chain.")
    elif not adoption_summary["evidence_present"]:
        recommendations.append("Collect adoption-velocity evidence to detect sudden provider or artifact popularity anomalies.")

    provenance_score, provenance_detail = _provenance_posture(artifact, metadata, provider_factors, recommendations)

    dimensions = OrderedDict(
        (
            ("provider_identity", _provider_dimension(provider_score, provider_detail, {"provider": provider_name, "host": host})),
            ("publisher_consistency", _provider_dimension(publisher_score, publisher_detail, {"claims": sorted(publisher_claims)})),
            ("maintainer_attribution", _provider_dimension(maintainer_score, maintainer_detail, {"publisher": card_data.get("publisher") or artifact.get("publisher")})),
            ("license_posture", _provider_dimension(license_score, license_detail, {"license": _bounded_text(card_data.get("license") or artifact.get("license") or metadata.get("license"))})),
            ("disclosure_posture", _provider_dimension(disclosure_score, "Model-card disclosure completeness affects provider due diligence confidence.", {"coverage": disclosure["coverage"], "missing_disclosures": disclosure["missing_disclosures"]})),
            ("adoption_posture", _provider_dimension(adoption_score, "Adoption-velocity evidence helps detect coordinated or bot-driven trust manipulation.", {"signals": adoption_summary["signals"], "risk_level": adoption_summary["risk_level"]})),
            ("provenance_posture", _provider_dimension(provenance_score, provenance_detail, {"attestation_count": _attestation_count(artifact, metadata)})),
        )
    )
    scores = [dimension["score"] for dimension in dimensions.values()]
    average_score = sum(scores) / len(scores)
    overall_risk_score = round(min(10.0, average_score * 0.6 + max(scores) * 0.4), 3)
    confidence = round(
        min(
            1.0,
            max(
                0.0,
                0.35
                + 0.25 * disclosure["confidence"]
                + 0.2 * adoption_summary["confidence"]
                + 0.2 * (1.0 if provider_name or host else 0.0),
            ),
        ),
        3,
    )
    assessment_complete = bool(provider_name or host or publisher_claims or card_data or source_url)
    severity = _severity(overall_risk_score)

    return {
        "assessment_version": PROVIDER_RISK_INTELLIGENCE_VERSION,
        "overall_risk_score": overall_risk_score,
        "severity": severity,
        "confidence": confidence,
        "assessment_complete": assessment_complete,
        "provider": provider_name,
        "publisher": next(iter(sorted(publisher_claims)), None),
        "dimensions": dimensions,
        "indicators": _unique(factor["indicator"] for factor in provider_factors),
        "factors": provider_factors,
        "recommendations": recommendations,
        "evidence": {
            "source": source,
            "source_url_host": host,
            "source_namespace": namespace,
            "publisher_claims": sorted(publisher_claims),
            "disclosure_posture": disclosure,
            "adoption_posture": adoption_summary,
            "license": _bounded_text(card_data.get("license") or artifact.get("license") or metadata.get("license")),
        },
    }


def _assessment_context(value, factors):
    result = {
        "domain_risk_scores": {},
        "capability_risk_scores": {},
        "control_reduction_cap": 0.4,
    }
    if value is None:
        return result, True
    if not isinstance(value, dict):
        _append_factor(
            factors,
            "malformed_model_risk_context",
            "evidence_quality",
            0.0,
            "HIGH",
            "Assessment context must be an object.",
            "Provide bounded organization-specific model-risk context.",
        )
        return result, False
    complete = True
    for field in ("domain_risk_scores", "capability_risk_scores"):
        overrides = value.get(field)
        if overrides is None:
            continue
        if not isinstance(overrides, dict) or len(overrides) > _MAX_CONTEXT_ENTRIES:
            complete = False
            _append_factor(
                factors,
                "malformed_model_risk_context",
                "evidence_quality",
                0.0,
                "HIGH",
                f"{field} must be a bounded score map.",
                "Use at most 100 normalized taxonomy entries with scores from 0 to 10.",
            )
            continue
        for key, raw_score in overrides.items():
            score = _bounded_score(raw_score)
            name = _normalize(key)
            if not name or score is None:
                complete = False
                _append_factor(
                    factors,
                    "malformed_model_risk_context",
                    "evidence_quality",
                    0.0,
                    "HIGH",
                    f"{field} contains an invalid taxonomy score.",
                    "Use named taxonomy entries with scores from 0 to 10.",
                )
                continue
            result[field][name] = score
    if "control_reduction_cap" in value:
        cap = _bounded_score(value.get("control_reduction_cap"))
        if cap is None or cap > 0.6:
            complete = False
            _append_factor(
                factors,
                "malformed_model_risk_context",
                "evidence_quality",
                0.0,
                "HIGH",
                "Control reduction cap must be between 0 and 0.6.",
                "Use a conservative control reduction cap no greater than 0.6.",
            )
        else:
            result["control_reduction_cap"] = cap
    return result, complete


def _normalize_profile(raw, domain_scores, capability_scores, factors):
    complete = True

    def category(field, mapping, default):
        nonlocal complete
        value = raw.get(field)
        if value is None:
            return default, None
        normalized = _normalize(value)
        if normalized not in mapping:
            complete = False
            _append_factor(
                factors,
                f"unknown_{field}",
                "evidence_quality",
                0.0,
                "MEDIUM",
                f"{field} uses an unsupported category.",
                f"Classify {field.replace('_', ' ')} using the documented taxonomy.",
                evidence=_bounded_text(value),
            )
            return normalized, None
        return normalized, mapping[normalized]

    impact_level, impact_score = category("impact_level", _IMPACT_LEVELS, "moderate")
    exposure, exposure_score = category("deployment_exposure", _EXPOSURE_LEVELS, "internal")
    user_access, access_score = category("user_access", _ACCESS_LEVELS, "authenticated")
    data_classification, data_score = category("data_classification", _DATA_LEVELS, "internal")
    decision_authority, decision_score = category("decision_authority", _DECISION_AUTHORITY, "advisory")
    reversibility, reversibility_score = category("reversibility", _REVERSIBILITY, "partially_reversible")
    criticality, criticality_score = category("safety_criticality", _SAFETY_CRITICALITY, "none")

    domain = _normalize(raw.get("domain"))
    domain_score = domain_scores.get(domain)
    if domain and domain_score is None:
        domain_score = 3.0

    capabilities, capabilities_complete = _bounded_normalized_set(
        raw.get("capabilities"), _MAX_CAPABILITIES
    )
    if not capabilities_complete:
        complete = False
        _append_factor(
            factors,
            "malformed_or_excessive_capability_inventory",
            "evidence_quality",
            0.0,
            "HIGH",
            "Capability inventory is malformed or exceeds the analysis bound.",
            "Provide no more than 100 named model capabilities.",
        )
    unknown_capabilities = sorted(capabilities - set(capability_scores))
    if unknown_capabilities:
        _append_factor(
            factors,
            "unclassified_model_capability",
            "evidence_quality",
            0.0,
            "MEDIUM",
            "One or more capabilities have no explicit risk classification.",
            "Classify organization-specific capabilities in the assessment context.",
            evidence=unknown_capabilities,
        )

    affected_users = _nonnegative_number(raw.get("affected_users"))
    if raw.get("affected_users") is not None and affected_users is None:
        complete = False
        _append_factor(
            factors,
            "malformed_affected_user_count",
            "evidence_quality",
            0.0,
            "MEDIUM",
            "Affected-user count must be a non-negative finite number.",
            "Provide a bounded estimate of affected people or decisions.",
        )
    deployment_scale = _normalize(raw.get("deployment_scale"))
    scale_score = None
    if affected_users is not None:
        scale_score = _population_scale_score(affected_users)
    elif deployment_scale:
        scale_score = _DEPLOYMENT_SCALE.get(deployment_scale)
        if scale_score is None:
            complete = False
            _append_factor(
                factors,
                "unknown_deployment_scale",
                "evidence_quality",
                0.0,
                "MEDIUM",
                "Deployment scale uses an unsupported category.",
                "Classify deployment scale or provide affected_users.",
            )

    connected_count, connected_complete = _collection_count(
        raw.get("connected_systems"), _MAX_CONNECTED_SYSTEMS
    )
    if not connected_complete:
        complete = False
        _append_factor(
            factors,
            "malformed_or_excessive_connected_systems",
            "evidence_quality",
            0.0,
            "MEDIUM",
            "Connected-system evidence is malformed or exceeds the analysis bound.",
            "Provide a bounded connected-system inventory.",
        )
    connected_score = None if connected_count is None else min(10.0, 2.0 + math.log2(connected_count + 1) * 1.8)

    vulnerable = _effective_flag_or_collection(raw.get("vulnerable_populations"))
    sensitive = _effective_flag_or_collection(raw.get("handles_sensitive_data"))
    return {
        "impact_level": impact_level,
        "impact_score": impact_score,
        "domain": domain,
        "domain_score": domain_score,
        "deployment_exposure": exposure,
        "exposure_score": exposure_score,
        "user_access": user_access,
        "access_score": access_score,
        "data_classification": data_classification,
        "data_score": data_score,
        "decision_authority": decision_authority,
        "decision_score": decision_score,
        "reversibility": reversibility,
        "reversibility_score": reversibility_score,
        "safety_criticality": criticality,
        "criticality_score": criticality_score,
        "deployment_scale": deployment_scale,
        "scale_score": scale_score,
        "affected_users": affected_users,
        "connected_score": connected_score,
        "capabilities": capabilities,
        "vulnerable_populations": vulnerable,
        "handles_sensitive_data": sensitive,
    }, complete


def _interaction_risks(normalized, dimensions, factors):
    capabilities = normalized["capabilities"]
    exposure = max(
        dimensions["exposure"]["score"],
        normalized["exposure_score"] or 0.0,
        normalized["access_score"] or 0.0,
    )
    data = max(
        dimensions["data"]["score"],
        normalized["data_score"] or 0.0,
        8.0 if normalized["handles_sensitive_data"] else 0.0,
    )
    impact = max(
        dimensions["impact"]["score"],
        normalized["impact_score"] or 0.0,
        normalized["domain_score"] or 0.0,
        normalized["decision_score"] or 0.0,
        normalized["criticality_score"] or 0.0,
    )
    scale = normalized["scale_score"] or 0.0
    interactions = []

    def add(indicator, bonus, severity, detail, recommendation):
        item = {
            "indicator": indicator,
            "bonus": bonus,
            "severity": severity,
            "detail": detail,
        }
        interactions.append(item)
        _append_factor(
            factors,
            indicator,
            "interaction",
            bonus,
            severity,
            detail,
            recommendation,
        )

    if "code_execution" in capabilities and exposure >= 8.0:
        add(
            "public_code_execution_coupling",
            1.5,
            "CRITICAL",
            "Externally exposed model behavior can influence code execution.",
            "Isolate code execution and require authenticated, policy-constrained invocation.",
        )
    if {"autonomous_actions", "financial_transactions"}.issubset(capabilities):
        add(
            "autonomous_financial_action_coupling",
            2.0,
            "CRITICAL",
            "Autonomous behavior can initiate financial transactions.",
            "Require transaction limits, dual authorization, and deterministic rollback.",
        )
    if (
        capabilities & {"identity_decisions", "medical_decisions", "biometric_identification"}
        and impact >= 7.0
    ):
        add(
            "high_impact_automated_decision_coupling",
            1.5,
            "CRITICAL",
            "High-impact model capabilities can affect rights, access, health, or identity.",
            "Require accountable human authority, appeal, and independent performance evaluation.",
        )
    if data >= 7.0 and exposure >= 8.0:
        add(
            "externally_exposed_sensitive_data_coupling",
            1.5,
            "CRITICAL",
            "Sensitive data processing is coupled with external exposure.",
            "Constrain data access, minimize sensitive fields, and validate leakage controls.",
        )
    if {
        "autonomous_actions",
        "tool_use",
        "external_communications",
    }.issubset(capabilities):
        add(
            "autonomous_external_tool_chain",
            1.75,
            "CRITICAL",
            "Autonomy, tool use, and external communication create a complete action chain.",
            "Enforce runtime authorization, scoped credentials, call budgets, and approval cuts.",
        )
    if scale >= 8.0 and normalized["reversibility_score"] == 10.0:
        add(
            "high_scale_irreversible_outcomes",
            1.25,
            "HIGH",
            "High-scale decisions are declared irreversible.",
            "Introduce staged rollout, appeal, rollback, and pre-deployment simulation.",
        )
    return interactions


def _profile_coherence(normalized, factors):
    complete = True
    consequence_signals = (
        normalized["domain_score"] or 0.0,
        normalized["decision_score"] or 0.0,
        normalized["criticality_score"] or 0.0,
    )
    if (
        normalized["impact_score"] is not None
        and normalized["impact_score"] <= 4.0
        and max(consequence_signals) >= 7.5
    ):
        complete = False
        _append_factor(
            factors,
            "declared_impact_underclassification",
            "evidence_quality",
            0.0,
            "HIGH",
            "Declared impact conflicts with domain, authority, or safety-criticality evidence.",
            "Reclassify impact using the highest credible consequence evidence.",
        )
    if (
        normalized["data_score"] is not None
        and normalized["data_score"] <= 2.5
        and normalized["handles_sensitive_data"]
    ):
        complete = False
        _append_factor(
            factors,
            "data_classification_inconsistency",
            "evidence_quality",
            0.0,
            "HIGH",
            "Sensitive-data handling conflicts with the declared data classification.",
            "Reconcile data classification with actual fields and access paths.",
        )
    if (
        normalized["exposure_score"] is not None
        and normalized["exposure_score"] <= 3.0
        and (normalized["access_score"] or 0.0) >= 9.0
    ):
        complete = False
        _append_factor(
            factors,
            "deployment_access_inconsistency",
            "evidence_quality",
            0.0,
            "HIGH",
            "Internal or restricted exposure conflicts with public or anonymous access.",
            "Classify deployment exposure from the effective access path.",
        )
    return complete


def _assess_controls(profile, artifact, normalized, dimensions, factors):
    capabilities = normalized["capabilities"]
    high_impact = dimensions["impact"]["score"] >= 6.0
    external = dimensions["exposure"]["score"] >= 6.0
    sensitive = dimensions["data"]["score"] >= 6.0
    high_capability = dimensions["capability"]["score"] >= 6.0
    specs = [
        ("safety_evaluations", 1.2, True),
        ("continuous_monitoring", 1.0, external or high_impact or high_capability),
        ("incident_response", 0.8, external or high_impact),
        ("audit_logging", 0.8, high_impact or high_capability),
        ("access_controls", 1.2, external or sensitive or high_capability),
        ("output_validation", 1.0, high_impact or high_capability),
        (
            "human_oversight",
            1.2,
            high_impact or (normalized["decision_score"] or 0.0) >= 5.0,
        ),
        ("fail_safe", 1.0, high_impact or bool(capabilities & {"code_execution", "physical_control", "autonomous_actions"})),
        ("capability_constraints", 1.0, high_capability),
        ("rate_limits", 0.6, external),
        ("data_governance", 1.0, sensitive),
    ]
    controls = []
    total_weight = 0.0
    weighted_strength = 0.0
    quality_values = []
    assessment_complete = True
    for name, weight, applicable in specs:
        if not applicable:
            continue
        value = _value(profile, artifact, name)
        if name == "safety_evaluations" and value is None:
            value = artifact.get("model_evaluation") or artifact.get("adversarial_tests")
        if isinstance(value, (list, tuple)) and len(value) > _MAX_CONTROL_ITEMS:
            assessment_complete = False
            _append_factor(
                factors,
                "control_evidence_limit_exceeded",
                "evidence_quality",
                0.0,
                "HIGH",
                f"{name.replace('_', ' ').title()} evidence exceeds the analysis bound.",
                "Summarize and segment control evidence into bounded assessment sets.",
                evidence={"control": name, "provided": len(value), "analyzed": _MAX_CONTROL_ITEMS},
            )
        strength, quality, failed = _control_strength(value)
        controls.append(
            {
                "control": name,
                "weight": weight,
                "strength": round(strength, 3),
                "evidence_quality": round(quality, 3),
                "status": "FAILED" if failed else "EFFECTIVE" if strength >= 0.7 else "PARTIAL" if strength > 0 else "MISSING",
            }
        )
        total_weight += weight
        weighted_strength += weight * strength
        quality_values.append(quality)
        if failed:
            _append_factor(
                factors,
                f"failed_{name}",
                "control_gaps",
                0.0,
                "HIGH",
                f"{name.replace('_', ' ').title()} evidence includes a failed result.",
                f"Remediate failed {name.replace('_', ' ')} evidence before deployment.",
            )
        elif strength <= 0.0:
            _append_factor(
                factors,
                f"missing_{name}",
                "control_gaps",
                0.0,
                "HIGH" if high_impact or external or high_capability else "MEDIUM",
                f"Applicable {name.replace('_', ' ')} evidence is absent or disabled.",
                f"Implement and verify {name.replace('_', ' ')} for this deployment context.",
            )
        elif strength < 0.5:
            _append_factor(
                factors,
                f"weak_{name}_evidence",
                "control_gaps",
                0.0,
                "MEDIUM",
                f"{name.replace('_', ' ').title()} is asserted without strong verification evidence.",
                f"Attach tested and independently verified {name.replace('_', ' ')} evidence.",
            )
    effectiveness = weighted_strength / total_weight if total_weight else 0.0
    evidence_quality = sum(quality_values) / len(quality_values) if quality_values else 0.0
    return {
        "effectiveness": round(effectiveness, 3),
        "evidence_quality": round(evidence_quality, 3),
        "applicable_control_count": len(controls),
        "effective_control_count": sum(control["strength"] >= 0.7 for control in controls),
        "failed_control_count": sum(control["status"] == "FAILED" for control in controls),
        "assessment_complete": assessment_complete,
        "controls": controls,
    }


def _control_strength(value):
    if value is None or value is False:
        return 0.0, 0.0, False
    if value is True:
        return 0.4, 0.25, False
    if isinstance(value, str):
        if _normalize(value) in _DISABLED_VALUES:
            return 0.0, 0.0, False
        return 0.45, 0.35, False
    if isinstance(value, dict):
        if value.get("enabled") is False or value.get("implemented") is False:
            return 0.0, 0.4, False
        failed = (
            value.get("passed") is False
            or value.get("verified") is False
            or _normalize(value.get("status")) in {"failed", "fail", "rejected"}
        )
        if failed:
            return 0.0, 0.7, True
        strength = 0.2
        quality = 0.2
        if value.get("enabled") is True or value.get("implemented") is True:
            strength += 0.2
        if any(value.get(field) for field in ("method", "policy", "strategy", "procedure", "owner")):
            strength += 0.2
            quality += 0.15
        if value.get("tested") is True or value.get("passed") is True:
            strength += 0.2
            quality += 0.25
        if value.get("verified") is True or value.get("independently_reviewed") is True:
            strength += 0.2
            quality += 0.4
        return min(1.0, strength), min(1.0, quality), False
    if isinstance(value, (list, tuple)):
        if not value:
            return 0.0, 0.0, False
        values = list(value)[:_MAX_CONTROL_ITEMS]
        results = [_control_strength(item) for item in values]
        failed = any(result[2] for result in results)
        if failed:
            return 0.0, sum(result[1] for result in results) / len(results), True
        return (
            sum(result[0] for result in results) / len(results),
            sum(result[1] for result in results) / len(results),
            False,
        )
    return 0.0, 0.0, False


def _evidence_quality(raw, identity_present, controls, factors):
    fields = (
        "impact_level",
        "domain",
        "deployment_exposure",
        "user_access",
        "data_classification",
        "decision_authority",
        "reversibility",
        "deployment_scale",
        "capabilities",
    )
    present = {field: raw.get(field) is not None for field in fields}
    profile_coverage = sum(present.values()) / len(present)
    identity_score = 1.0 if identity_present else 0.0
    control_quality = controls["evidence_quality"]
    malformed = sum(
        factor["indicator"].startswith(("malformed_", "unknown_"))
        or factor["indicator"].startswith("unclassified_")
        or factor["indicator"].endswith("_inconsistency")
        or factor["indicator"].endswith("_underclassification")
        for factor in factors
    )
    confidence = 0.55 * profile_coverage + 0.15 * identity_score + 0.3 * control_quality
    confidence *= max(0.5, 1.0 - 0.08 * min(malformed, 6))
    confidence = round(min(1.0, max(0.0, confidence)), 3)
    return {
        "confidence": confidence,
        "profile_coverage": round(profile_coverage, 3),
        "control_evidence_quality": control_quality,
        "identity_bound": identity_present,
        "fields_present": present,
        "missing_fields": sorted(field for field, is_present in present.items() if not is_present),
        "malformed_or_unclassified_fields": malformed,
    }


def _score_gates(normalized, dimensions, controls, interactions):
    interaction_names = {item["indicator"] for item in interactions}
    control_map = {item["control"]: item for item in controls["controls"]}
    gates = []

    def strength(name):
        return control_map.get(name, {}).get("strength", 0.0)

    def add(gate, minimum_score, severity, reason):
        gates.append(
            {
                "gate": gate,
                "minimum_score": minimum_score,
                "minimum_severity": severity,
                "reason": reason,
            }
        )

    if "public_code_execution_coupling" in interaction_names:
        add(
            "public_code_execution",
            7.5,
            "CRITICAL",
            "Publicly reachable code execution requires critical-risk treatment.",
        )
    if "autonomous_financial_action_coupling" in interaction_names:
        add(
            "autonomous_financial_transactions",
            8.5,
            "CRITICAL",
            "Autonomous financial authority has a critical residual-risk floor.",
        )
    if (
        "high_impact_automated_decision_coupling" in interaction_names
        and strength("human_oversight") < 0.7
    ):
        add(
            "high_impact_decision_without_verified_oversight",
            8.0,
            "CRITICAL",
            "High-impact decisions lack strongly evidenced human oversight.",
        )
    if (
        "externally_exposed_sensitive_data_coupling" in interaction_names
        and strength("access_controls") < 0.7
    ):
        add(
            "sensitive_external_system_without_verified_access_control",
            8.0,
            "CRITICAL",
            "Externally exposed sensitive data lacks strongly evidenced access control.",
        )
    if normalized["criticality_score"] == 10.0 and strength("fail_safe") < 0.7:
        add(
            "safety_critical_system_without_verified_fail_safe",
            8.5,
            "CRITICAL",
            "Safety-critical deployment lacks strongly evidenced fail-safe behavior.",
        )
    return gates


def _infer_capabilities(artifact):
    tools = artifact.get("tools")
    if isinstance(tools, str):
        tools = [tools]
    if tools is None:
        tools = []
        complete = True
    elif not isinstance(tools, (list, tuple, set)):
        tools = []
        complete = False
    else:
        tools = list(tools)
        complete = len(tools) <= _MAX_CAPABILITIES
    capabilities = set()
    for tool in list(tools)[:_MAX_CAPABILITIES]:
        capabilities.update(_TOOL_CAPABILITIES.get(_normalize(tool), {"tool_use"}))
    if artifact.get("autonomy_level") in {"high", "full", "autonomous"}:
        capabilities.add("autonomous_actions")
    if artifact.get("runtime_tool_authorization") is True and tools:
        capabilities.add("tool_use")
    return capabilities, complete


def _dimension(name, signals, assumed_score):
    if signals:
        score = max(signal["score"] for signal in signals)
        assumed = False
    else:
        score = assumed_score
        signals = [
            {
                "name": "assumed_baseline",
                "score": assumed_score,
                "weight": 1.0,
            }
        ]
        assumed = True
    return {
        "score": round(min(10.0, score), 3),
        "assumed": assumed,
        "signals": signals,
    }


def _signal(signals, name, score, weight):
    if score is not None:
        signals.append({"name": name, "score": round(score, 3), "weight": weight})


def _append_factor(
    factors,
    indicator,
    dimension,
    contribution,
    severity,
    detail,
    recommendation,
    evidence=None,
):
    candidate = {
        "indicator": indicator,
        "dimension": dimension,
        "weight": contribution,
        "contribution": contribution,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }
    if evidence is not None:
        candidate["evidence"] = evidence
    if candidate not in factors:
        factors.append(candidate)


def _bounded_normalized_set(value, limit):
    if value is None:
        return set(), True
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        return set(), False
    complete = len(values) <= limit
    return {_normalize(item) for item in values[:limit] if _normalize(item)}, complete


def _collection_count(value, limit):
    if value is None:
        return None, True
    if isinstance(value, bool):
        return None, False
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)) or value < 0:
            return None, False
        count = int(value)
        return min(count, limit), count <= limit
    if isinstance(value, str):
        return 1 if value.strip() else 0, True
    if isinstance(value, (list, tuple, set)):
        return min(len(value), limit), len(value) <= limit
    return None, False


def _effective_flag_or_collection(value):
    if isinstance(value, str):
        return _normalize(value) not in _DISABLED_VALUES
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return value is True


def _publisher_claims(artifact, metadata, card_data, namespace):
    claims = set()
    for value in (
        artifact.get("publisher"),
        metadata.get("publisher"),
        card_data.get("publisher") if isinstance(card_data, dict) else None,
        namespace,
    ):
        normalized = _normalize(value)
        if normalized:
            claims.add(normalized)
    return claims


def _license_posture(artifact, metadata, card_data, factors, recommendations):
    declared = _normalize(artifact.get("license") or metadata.get("license"))
    card_license = _normalize(card_data.get("license") if isinstance(card_data, dict) else None)
    license_name = card_license or declared
    if declared and card_license and declared != card_license:
        _append_factor(
            factors,
            "license_identity_conflict",
            "license",
            0.0,
            "HIGH",
            "Registry license claim conflicts with provider-declared model-card license evidence.",
            "Align license declarations with the upstream provider artifact metadata.",
            evidence={"registry": declared, "provider": card_license},
        )
        recommendations.append("Resolve conflicting license declarations before adoption or redistribution.")
        return 8.0, "License evidence conflicts across registry and provider metadata."
    if not license_name:
        recommendations.append("Record a concrete license so downstream adopters can assess usage and redistribution risk.")
        return 8.5, "License information is missing."
    if license_name in _LOW_RISK_LICENSES:
        return 2.0, "License is common and clearly classifiable."
    if license_name in _MEDIUM_RISK_LICENSES:
        recommendations.append("Review license restrictions and policy compatibility before deployment.")
        return 5.5, "License imposes conditions or reciprocity that may constrain downstream use."
    if license_name in _HIGH_RISK_LICENSES:
        recommendations.append("Perform explicit legal and supply-chain review for custom or restrictive licensing.")
        return 8.0, "License is custom, restrictive, or poorly standardized."
    recommendations.append("Normalize the license to a well-understood SPDX-style identifier where possible.")
    return 6.5, "License is present but not recognized as a standard low-risk identifier."


def _provenance_posture(artifact, metadata, factors, recommendations):
    provenance = metadata.get("provenance_assessment") if isinstance(metadata.get("provenance_assessment"), dict) else {}
    score = _nonnegative_number(provenance.get("provenance_score") or artifact.get("provenance_score"))
    complete = provenance.get("assessment_complete") is True
    confidence = _nonnegative_number(provenance.get("confidence"))
    attestation_count = _attestation_count(artifact, metadata)
    if score is not None and score >= 80 and complete:
        return 2.0, "Provider provenance evidence is complete and strong."
    if score is not None and score >= 50:
        return 4.5, "Provider provenance evidence is present but not fully complete."
    if attestation_count > 0:
        return 5.5 if confidence is None or confidence < 0.8 else 4.5, "Attestation evidence exists but provider provenance posture remains only partially verified."
    _append_factor(
        factors,
        "provider_provenance_gap",
        "provenance",
        0.0,
        "HIGH",
        "Provider provenance evidence is missing or incomplete.",
        "Require signed provenance, attestation verification, or equivalent provider integrity evidence.",
    )
    recommendations.append("Collect signed provenance or attestation evidence for the provider artifact.")
    return 8.5, "Provider provenance evidence is missing."


def _attestation_count(artifact, metadata):
    for value in (
        artifact.get("attestations"),
        artifact.get("provenance_attestations"),
        metadata.get("attestations"),
        metadata.get("provenance_attestations"),
    ):
        if isinstance(value, (list, tuple)):
            return len(value)
    return 0


def _source_host_and_namespace(source_url):
    if not source_url or "://" not in source_url:
        return None, None
    remainder = source_url.split("://", 1)[1]
    host, _, path = remainder.partition("/")
    namespace = None
    segments = [segment for segment in path.split("/") if segment]
    if segments:
        namespace = _normalize(segments[0])
    return host.lower() if host else None, namespace


def _provider_dimension(score, detail, evidence):
    return {
        "score": round(min(10.0, max(0.0, float(score))), 3),
        "severity": _severity(score),
        "detail": detail,
        "evidence": evidence,
    }


def _population_scale_score(value):
    if value <= 0:
        return 0.0
    return round(min(10.0, 2.0 + 1.5 * max(0.0, math.log10(value / 100.0))), 3)


def _nonnegative_number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(result) or result < 0:
        return None
    return result


def _bounded_score(value):
    if isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(result) or not 0.0 <= result <= 10.0:
        return None
    return result


def _value(profile, artifact, key):
    value = profile.get(key)
    return artifact.get(key) if value is None else value


def _normalize(value):
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _bounded_text(value):
    return str(value or "").strip()[:_MAX_TEXT_CHARS]


def _severity(score):
    if score >= 7.5:
        return "CRITICAL"
    if score >= 5.0:
        return "HIGH"
    if score >= 2.5:
        return "MEDIUM"
    return "LOW"


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))

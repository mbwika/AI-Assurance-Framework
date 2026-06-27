"""Evidence-quality-aware composite trustworthiness scoring."""

import math
import re
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlparse

TRUSTWORTHINESS_SCORING_VERSION = "2.0"
_MAX_FINDINGS = 1_000

WEIGHTS = {
    "security_posture": 0.25,
    "supply_chain_integrity": 0.20,
    "governance_evidence": 0.15,
    "operational_monitoring": 0.15,
    "agentic_safeguards": 0.15,
    "model_reliability": 0.10,
}

_FINDING_DIMENSIONS = {
    "supply_chain": "supply_chain_integrity",
    "dependency_risk": "supply_chain_integrity",
    "dependency_vulnerability": "supply_chain_integrity",
    "adversarial_testing": "operational_monitoring",
    "agent_risk": "agentic_safeguards",
    "tool_invocation_risk": "agentic_safeguards",
    "workflow_security": "agentic_safeguards",
    "workflow_graph": "agentic_safeguards",
    "hallucination_risk": "model_reliability",
    "bias_fairness": "model_reliability",
    "bias_risk": "model_reliability",
}
_RESOLVED_STATUSES = {"closed", "resolved", "remediated", "fixed"}
_SEVERITY_PENALTIES = {"LOW": 2.0, "MEDIUM": 6.0, "HIGH": 14.0, "CRITICAL": 28.0}
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_AGENTIC_FIELDS = (
    "tools",
    "permissions",
    "autonomy_level",
    "workflow_steps",
    "agentic",
    "agent_policy",
    "runtime_tool_authorization",
)
_QUANTITATIVE_RELIABILITY_FIELDS = frozenset(
    {
        "sample_size",
        "total_claims",
        "correct_claims",
        "factual_accuracy",
        "citation_precision",
        "citation_coverage",
        "source_trust",
        "expected_calibration_error",
        "demographic_parity_difference",
        "disparate_impact_ratio",
        "equal_opportunity_difference",
        "false_positive_rate_gap",
        "counterfactual_flip_rate",
        "groups_evaluated",
        "test_cases",
        "passed_cases",
        "failed_cases",
    }
)


def score_trustworthiness(
    artifact: dict[str, Any],
    risk_score: float = 0.0,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Score trustworthiness across applicable evidence-backed dimensions."""
    artifact = artifact if isinstance(artifact, dict) else {}
    bounded_risk, risk_warnings, risk_valid = _bounded_risk_score(risk_score)
    normalized_findings, finding_warnings, finding_state = _normalize_findings(findings)
    warnings = risk_warnings + finding_warnings
    active_findings = [item for item in normalized_findings if item["active"]]
    findings_by_dimension = _findings_by_dimension(active_findings)

    dimensions = {
        "security_posture": _security_posture_dimension(
            bounded_risk,
            findings_by_dimension["security_posture"],
            risk_valid=risk_valid,
            finding_state=finding_state,
        ),
        "supply_chain_integrity": _supply_chain_dimension(
            artifact, findings_by_dimension["supply_chain_integrity"]
        ),
        "governance_evidence": _governance_dimension(artifact),
        "operational_monitoring": _operational_dimension(
            artifact, findings_by_dimension["operational_monitoring"]
        ),
        "agentic_safeguards": _agentic_dimension(
            artifact, findings_by_dimension["agentic_safeguards"]
        ),
        "model_reliability": _model_reliability_dimension(
            artifact, findings_by_dimension["model_reliability"]
        ),
    }

    applicable = [name for name, value in dimensions.items() if value["applicable"]]
    applicable_weight = sum(WEIGHTS[name] for name in applicable)
    effective_weights = {
        name: (WEIGHTS[name] / applicable_weight if name in applicable else 0.0)
        for name in WEIGHTS
    }
    raw_score = sum(
        dimensions[name]["score"] * effective_weights[name] for name in applicable
    )
    confidence = sum(
        dimensions[name]["confidence"] * effective_weights[name] for name in applicable
    )

    gates = _score_gates(
        active_findings=active_findings,
        risk_score=bounded_risk,
        confidence=confidence,
        finding_state=finding_state,
    )
    applied_cap = min((gate["maximum_score"] for gate in gates), default=100.0)
    score = _clamp(min(raw_score, applied_cap))
    evidence_gaps = _ordered_unique(
        gap for dimension in dimensions.values() for gap in dimension.get("gaps", [])
    )
    recommendations = _ordered_unique(_recommendation(gap) for gap in evidence_gaps)

    return {
        "trustworthiness_score": round(score, 2),
        "raw_trustworthiness_score": round(_clamp(raw_score), 2),
        "level": _level(score),
        "confidence": round(_clamp_unit(confidence), 4),
        "scoring_version": TRUSTWORTHINESS_SCORING_VERSION,
        "score_scale": {"minimum": 0.0, "maximum": 100.0},
        "dimensions": dimensions,
        "applicable_dimensions": applicable,
        "weights": {name: round(weight, 6) for name, weight in effective_weights.items()},
        "score_breakdown": [
            {
                "dimension": name,
                "score": dimensions[name]["score"],
                "effective_weight": round(effective_weights[name], 6),
                "contribution": round(
                    dimensions[name]["score"] * effective_weights[name], 4
                ),
            }
            for name in WEIGHTS
            if name in applicable
        ],
        "score_gates": gates,
        "evidence_gaps": evidence_gaps,
        "recommendations": recommendations,
        "warnings": _ordered_unique(warnings),
        "finding_summary": {
            "provided": finding_state["provided"],
            "analyzed": finding_state["analyzed"],
            "active": len(active_findings),
            "resolved": len(normalized_findings) - len(active_findings),
            "invalid": finding_state["invalid"],
            "truncated": finding_state["truncated"],
        },
    }


def _security_posture_dimension(risk_score, findings, risk_valid, finding_state):
    finding_penalty, finding_evidence, finding_gaps = _finding_impact(findings)
    risk_penalty = min(risk_score * 8.0, 80.0)
    score = _clamp(100.0 - max(risk_penalty, finding_penalty))
    confidence = 1.0
    warnings = []
    if not risk_valid:
        confidence -= 0.35
        warnings.append("aggregate risk score was malformed or outside the supported range")
    if finding_state["invalid"]:
        confidence -= min(finding_state["invalid"] * 0.05, 0.35)
    if finding_state["truncated"]:
        confidence -= 0.15
    return _dimension_result(
        score=score,
        confidence=confidence,
        evidence={
            "finding_count": len(findings),
            "severe_findings": finding_evidence["severe_findings"],
            "severity_counts": finding_evidence["severity_counts"],
            "risk_score": round(risk_score, 3),
            "risk_penalty": round(risk_penalty, 2),
            "finding_penalty": round(finding_penalty, 2),
        },
        gaps=finding_gaps,
        warnings=warnings,
    )


def _supply_chain_dimension(artifact, findings):
    checks = [
        ("source_url", 12.0, _source_quality(artifact.get("source_url"))),
        ("publisher", 10.0, _text_quality(artifact.get("publisher"))),
        ("sha256", 15.0, _sha256_quality(artifact.get("sha256"))),
        ("license", 8.0, _license_quality(artifact.get("license"))),
        ("dependencies", 15.0, _dependency_quality(artifact.get("dependencies"))),
        (
            "training_artifacts",
            15.0,
            _training_artifact_quality(artifact.get("training_artifacts")),
        ),
        (
            "deployment_pipeline",
            15.0,
            _deployment_pipeline_quality(artifact.get("deployment_pipeline")),
        ),
        (
            "provenance_attestations",
            10.0,
            _attestation_quality(artifact.get("provenance_attestations")),
        ),
    ]
    return _quality_dimension(checks, findings)


def _governance_dimension(artifact):
    checks = [
        ("owner", 25.0, _text_quality(artifact.get("owner"))),
        ("risk_owner", 25.0, _text_quality(artifact.get("risk_owner"))),
        (
            "compliance_scope",
            25.0,
            _collection_quality(artifact.get("compliance_scope")),
        ),
        (
            "documentation_url",
            25.0,
            _source_quality(artifact.get("documentation_url")),
        ),
    ]
    return _quality_dimension(checks, [])


def _operational_dimension(artifact, findings):
    checks = [
        (
            "monitoring_enabled",
            35.0,
            1.0 if artifact.get("monitoring_enabled") is True else 0.0,
        ),
        (
            "assessment_frequency",
            25.0,
            _frequency_quality(artifact.get("assessment_frequency")),
        ),
        (
            "adversarial_tests",
            40.0,
            _adversarial_evidence_quality(artifact.get("adversarial_tests")),
        ),
    ]
    return _quality_dimension(checks, findings)


def _agentic_dimension(artifact, findings):
    applicable = (
        bool(findings)
        or artifact.get("agentic") is True
        or any(
            _has_declared_value(artifact.get(field))
            for field in _AGENTIC_FIELDS
            if field != "agentic"
        )
    )
    if not applicable:
        return _not_applicable_dimension()
    policy = artifact.get("agent_policy")
    policy = policy if isinstance(policy, dict) else {}
    constraints = artifact.get("operational_constraints")
    if constraints is None:
        constraints = artifact.get("constraints")
    checks = [
        ("tools", 10.0, _collection_quality(artifact.get("tools"))),
        ("permissions", 10.0, _collection_quality(artifact.get("permissions"))),
        (
            "autonomy_level",
            10.0,
            _autonomy_declaration_quality(artifact.get("autonomy_level")),
        ),
        (
            "human_review_required",
            15.0,
            _human_review_quality(artifact, policy),
        ),
        (
            "workflow_steps",
            15.0,
            _workflow_evidence_quality(artifact.get("workflow_steps")),
        ),
        ("agent_policy", 20.0, _agent_policy_quality(policy)),
        (
            "operational_constraints",
            10.0,
            _collection_quality(constraints),
        ),
        (
            "runtime_tool_authorization",
            10.0,
            1.0 if artifact.get("runtime_tool_authorization") is True else 0.0,
        ),
    ]
    return _quality_dimension(checks, findings, applicable=True)


def _model_reliability_dimension(artifact, findings):
    profile = artifact.get("model_risk_profile")
    profile = profile if isinstance(profile, dict) else {}
    safety_evaluations = artifact.get("safety_evaluations")
    if safety_evaluations is None:
        safety_evaluations = profile.get("safety_evaluations")
    factuality = (
        artifact.get("factuality_evaluation")
        or artifact.get("factuality_evidence")
        or artifact.get("retrieval_evidence")
    )
    fairness = artifact.get("bias_evaluation") or artifact.get("fairness_evaluation")
    human_oversight = artifact.get("human_oversight")
    if human_oversight is None:
        human_oversight = profile.get("human_oversight")
    output_validation = artifact.get("output_validation")
    if output_validation is None:
        output_validation = profile.get("output_validation")
    calibration = artifact.get("calibration_evidence") or artifact.get(
        "uncertainty_evaluation"
    )
    values = (
        safety_evaluations,
        factuality,
        fairness,
        human_oversight,
        output_validation,
        calibration,
    )
    applicable = bool(findings) or any(_has_declared_value(value) for value in values)
    if not applicable:
        return _not_applicable_dimension()
    checks = [
        ("safety_evaluations", 25.0, _evaluation_quality(safety_evaluations)),
        ("factuality_evaluation", 20.0, _structured_evidence_quality(factuality)),
        ("bias_evaluation", 20.0, _structured_evidence_quality(fairness)),
        ("human_oversight", 15.0, 1.0 if human_oversight is True else 0.0),
        ("output_validation", 10.0, _text_or_structure_quality(output_validation)),
        ("calibration_evidence", 10.0, _structured_evidence_quality(calibration)),
    ]
    return _quality_dimension(checks, findings, applicable=True)


def _quality_dimension(checks, findings, applicable=True):
    if not applicable:
        return _not_applicable_dimension()
    score = 0.0
    coverage = 0.0
    evidence = []
    evidence_quality = {}
    gaps = []
    for field, weight, raw_quality in checks:
        quality = _clamp_unit(raw_quality)
        score += weight * quality
        evidence_quality[field] = round(quality, 4)
        if quality > 0.0:
            evidence.append(field)
            coverage += weight
        if quality == 0.0:
            gaps.append(f"missing evidence: {field}")
        elif quality < 0.75:
            gaps.append(f"weak evidence: {field}")

    finding_penalty, finding_evidence, finding_gaps = _finding_impact(findings)
    score = _clamp(score - finding_penalty)
    gaps.extend(finding_gaps)
    confidence = coverage / 100.0
    result = _dimension_result(
        score=score,
        confidence=confidence,
        evidence=evidence,
        gaps=gaps,
        warnings=[],
        evidence_quality=evidence_quality,
    )
    result["finding_evidence"] = finding_evidence
    return result


def _not_applicable_dimension():
    return {
        "score": 100.0,
        "status": "NOT_APPLICABLE",
        "applicable": False,
        "confidence": 1.0,
        "evidence": [],
        "evidence_quality": {},
        "gaps": [],
        "warnings": [],
        "finding_evidence": {
            "finding_count": 0,
            "severity_counts": {severity: 0 for severity in _SEVERITY_ORDER},
            "severe_findings": [],
        },
    }


def _dimension_result(
    score,
    confidence,
    evidence,
    gaps,
    warnings,
    evidence_quality=None,
):
    score = round(_clamp(score), 2)
    severe_gap = any(str(gap).startswith("severe finding: ") for gap in gaps)
    return {
        "score": score,
        "status": "PASS" if score >= 75.0 and not severe_gap else "NEEDS_REVIEW",
        "applicable": True,
        "confidence": round(_clamp_unit(confidence), 4),
        "evidence": evidence,
        "evidence_quality": evidence_quality or {},
        "gaps": _ordered_unique(gaps),
        "warnings": _ordered_unique(warnings),
    }


def _normalize_findings(findings):
    warnings = []
    invalid = 0
    if findings is None:
        raw_findings: Sequence[Any] = []
    elif isinstance(findings, (list, tuple)):
        raw_findings = findings
    else:
        raw_findings = []
        invalid = 1
        warnings.append("findings must be a list or tuple")

    provided = len(raw_findings)
    truncated = provided > _MAX_FINDINGS
    if truncated:
        warnings.append(f"findings exceeded the {_MAX_FINDINGS}-record analysis bound")
    normalized = []
    for index, finding in enumerate(raw_findings[:_MAX_FINDINGS]):
        if not isinstance(finding, dict):
            invalid += 1
            warnings.append(f"finding {index + 1} is not an object")
            continue
        finding_type = _normalized_value(finding.get("type")) or "unknown_finding"
        raw_severity = str(finding.get("severity") or "").strip().upper()
        if raw_severity not in _SEVERITY_ORDER:
            raw_severity = "HIGH"
            invalid += 1
            warnings.append(f"finding {index + 1} has an invalid severity")
        status = _normalized_value(finding.get("status"))
        normalized.append(
            {
                "type": finding_type[:128],
                "severity": raw_severity,
                "status": status,
                "active": status not in _RESOLVED_STATUSES,
            }
        )
    return normalized, warnings, {
        "provided": provided,
        "analyzed": len(normalized),
        "invalid": invalid,
        "truncated": truncated,
    }


def _findings_by_dimension(findings):
    result = {name: [] for name in WEIGHTS}
    for finding in findings:
        dimension = _FINDING_DIMENSIONS.get(finding["type"], "security_posture")
        result[dimension].append(finding)
    return result


def _finding_impact(findings):
    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    severe_findings = []
    penalty = 0.0
    gaps = []
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] += 1
        penalty += _SEVERITY_PENALTIES[severity]
        if severity in {"HIGH", "CRITICAL"}:
            severe_findings.append(finding["type"])
            gaps.append(f"severe finding: {finding['type']}")
    return min(penalty, 85.0), {
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "severe_findings": _ordered_unique(severe_findings),
    }, _ordered_unique(gaps)


def _score_gates(active_findings, risk_score, confidence, finding_state):
    gates = []
    critical = [item["type"] for item in active_findings if item["severity"] == "CRITICAL"]
    high = [item["type"] for item in active_findings if item["severity"] == "HIGH"]
    critical_supply = [
        item["type"]
        for item in active_findings
        if item["severity"] == "CRITICAL"
        and _FINDING_DIMENSIONS.get(item["type"]) == "supply_chain_integrity"
    ]
    if critical:
        gates.append(
            {
                "gate": "active_critical_finding",
                "maximum_score": 49.0,
                "evidence": _ordered_unique(critical),
            }
        )
    if critical_supply:
        gates.append(
            {
                "gate": "critical_supply_chain_integrity",
                "maximum_score": 39.0,
                "evidence": _ordered_unique(critical_supply),
            }
        )
    if len(high) >= 2:
        gates.append(
            {
                "gate": "multiple_active_high_findings",
                "maximum_score": 64.0,
                "evidence": _ordered_unique(high),
            }
        )
    if risk_score >= 8.0:
        gates.append(
            {
                "gate": "critical_aggregate_risk",
                "maximum_score": 39.0,
                "evidence": {"risk_score": round(risk_score, 3)},
            }
        )
    if confidence < 0.35:
        gates.append(
            {
                "gate": "insufficient_assurance_confidence",
                "maximum_score": 49.0,
                "evidence": {"confidence": round(confidence, 4)},
            }
        )
    if finding_state["invalid"] or finding_state["truncated"]:
        gates.append(
            {
                "gate": "incomplete_finding_evidence",
                "maximum_score": 64.0,
                "evidence": {
                    "invalid": finding_state["invalid"],
                    "truncated": finding_state["truncated"],
                },
            }
        )
    return gates


def _bounded_risk_score(value):
    if isinstance(value, bool):
        return 10.0, ["aggregate risk score must be numeric"], False
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return 10.0, ["aggregate risk score must be numeric"], False
    if not math.isfinite(parsed):
        return 10.0, ["aggregate risk score must be finite"], False
    if parsed < 0.0 or parsed > 10.0:
        return 10.0, [
            "out-of-range aggregate risk score was treated as maximum risk"
        ], False
    return parsed, [], True


def _source_quality(value):
    if not isinstance(value, str) or not value.strip():
        return 0.0
    parsed = urlparse(value.strip())
    if parsed.scheme == "https" and parsed.netloc:
        return 1.0
    if parsed.scheme in {"s3", "gs", "oci"} and parsed.netloc:
        return 0.9
    if parsed.scheme == "http" and parsed.netloc:
        return 0.4
    return 0.5


def _text_quality(value):
    return 1.0 if isinstance(value, str) and len(value.strip()) >= 2 else 0.0


def _text_or_structure_quality(value):
    if isinstance(value, str):
        return 1.0 if value.strip() else 0.0
    if isinstance(value, (dict, list, tuple, set)):
        return 1.0 if value else 0.0
    return 0.0


def _sha256_quality(value):
    if not isinstance(value, str) or not value.strip():
        return 0.0
    return (
        1.0
        if re.fullmatch(r"(?:sha256:)?[A-Fa-f0-9]{64}", value.strip())
        else 0.25
    )


def _license_quality(value):
    if not isinstance(value, str) or not value.strip():
        return 0.0
    normalized = _normalized_value(value)
    return 0.25 if normalized in {"unknown", "none", "unlicensed", "proprietary_unknown"} else 1.0


def _collection_quality(value):
    if isinstance(value, str):
        return 1.0 if value.strip() else 0.0
    if isinstance(value, (list, tuple, set, dict)):
        return 1.0 if value else 0.0
    return 0.0


def _dependency_quality(value):
    if not isinstance(value, (list, tuple, set)) or not value:
        return 0.0
    records = list(value)[:1_000]
    pinned = sum(1 for dependency in records if _dependency_is_pinned(dependency))
    return 0.5 + 0.5 * (pinned / len(records))


def _dependency_is_pinned(value):
    if isinstance(value, dict):
        version = str(value.get("version") or value.get("specifier") or "").strip()
        digest = str(value.get("sha256") or value.get("hash") or "").strip()
        exact_version = bool(re.fullmatch(r"==[^*<>=!~\s]+", version)) or bool(
            re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", version)
        )
        return exact_version or bool(
            re.fullmatch(r"(?:sha256:)?[A-Fa-f0-9]{64}", digest)
        )
    text = str(value or "").strip()
    return (
        bool(re.search(r"==[^*<>=!~\s]+(?:\s|$)", text))
        or bool(re.fullmatch(r"(?:@?[^@\s]+)@v?\d+(?:\.\d+){1,3}", text))
        or bool(re.search(r"(?:sha256:)?[A-Fa-f0-9]{64}", text))
    )


def _training_artifact_quality(value):
    if not isinstance(value, (list, tuple)) or not value:
        return 0.0
    qualities = []
    for record in list(value)[:1_000]:
        if not isinstance(record, dict):
            qualities.append(0.2 if _has_declared_value(record) else 0.0)
            continue
        quality = 0.2 if _has_declared_value(record.get("name")) else 0.0
        source = record.get("source_url") or record.get("source")
        if _has_declared_value(source):
            quality += 0.3
        digest = record.get("sha256") or record.get("checksum")
        quality += 0.5 * _sha256_quality(digest)
        qualities.append(min(quality, 1.0))
    return sum(qualities) / len(qualities)


def _deployment_pipeline_quality(value):
    if not isinstance(value, dict) or not value:
        return 0.0
    quality = 0.0
    if _has_declared_value(value.get("environment")):
        quality += 0.25
    artifact_ref = str(value.get("artifact_ref") or value.get("image") or "")
    if re.search(r"@sha256:[A-Fa-f0-9]{64}(?:$|[^A-Fa-f0-9])", artifact_ref):
        quality += 0.40
    elif artifact_ref:
        quality += 0.20
    if _has_declared_value(
        value.get("approval_gate") or value.get("approved_by") or value.get("promotion_approval")
    ):
        quality += 0.35
    return min(quality, 1.0)


def _attestation_quality(value):
    if not isinstance(value, (list, tuple)) or not value:
        return 0.0
    qualities = []
    for record in list(value)[:1_000]:
        if not isinstance(record, dict):
            qualities.append(0.0)
            continue
        quality = 0.0
        algorithm = _normalized_value(
            record.get("algorithm") or record.get("predicate_type")
        )
        if algorithm:
            quality += 0.15
        signature = record.get("signature")
        if isinstance(signature, str) and re.fullmatch(r"[A-Fa-f0-9]{64}", signature):
            quality += 0.25
        elif _has_declared_value(signature):
            quality += 0.10
        statement = record.get("statement")
        subject = record.get("subject") or record.get("digest") or record.get(
            "artifact_digest"
        )
        if isinstance(statement, dict):
            subject = statement.get("subject") or subject
            if record.get("schema_version") == "2.0" and set(record) == {
                "schema_version",
                "algorithm",
                "key_id",
                "statement",
                "signature",
            }:
                quality += 0.10
        if _has_declared_value(subject):
            quality += 0.20
        # Verification is trusted only when supplied through a verifier-owned
        # assessment context. Inline status fields are self-assertions here.
        qualities.append(min(quality, 0.70))
    return sum(qualities) / len(qualities)


def _frequency_quality(value):
    normalized = _normalized_value(value)
    if normalized in {"continuous", "hourly", "daily", "weekly", "monthly"}:
        return 1.0
    return 0.5 if normalized else 0.0


def _adversarial_evidence_quality(value):
    if not isinstance(value, (list, tuple)) or not value:
        return 0.0
    records = list(value)[:1_000]
    valid = [record for record in records if isinstance(record, dict)]
    if not valid:
        return 0.2
    failed = sum(1 for record in valid if record.get("passed") is False)
    incomplete = sum(
        1
        for record in valid
        if _normalized_value(record.get("status"))
        in {"skipped", "not_run", "pending", "blocked"}
    )
    quality = len(valid) / len(records)
    quality *= max(0.0, 1.0 - failed / len(valid))
    quality *= max(0.25, 1.0 - 0.75 * incomplete / len(valid))
    return quality


def _autonomy_declaration_quality(value):
    return 1.0 if _normalized_value(value) in {"none", "low", "medium", "high", "full"} else 0.0


def _human_review_quality(artifact, policy):
    if artifact.get("human_review_required") is True:
        return 1.0
    review_tools = policy.get("require_human_review_for_tools")
    review_actions = policy.get("require_approval_for_actions")
    return 1.0 if _collection_quality(review_tools) or _collection_quality(review_actions) else 0.0


def _workflow_evidence_quality(value):
    if not isinstance(value, (list, tuple)) or not value:
        return 0.0
    records = list(value)[:1_000]
    structured = sum(isinstance(record, dict) and bool(record) for record in records)
    return 0.5 + 0.5 * structured / len(records)


def _agent_policy_quality(policy):
    if not isinstance(policy, dict) or not policy:
        return 0.0
    controls = (
        "allowed_tools",
        "denied_tools",
        "allowed_permissions",
        "denied_permissions",
        "require_human_review_for_tools",
        "require_approval_for_actions",
        "max_external_calls",
    )
    present = sum(_has_declared_value(policy.get(control)) for control in controls)
    return min(0.4 + present * 0.12, 1.0)


def _evaluation_quality(value):
    if not isinstance(value, (list, tuple)) or not value:
        return 0.0
    records = list(value)[:1_000]
    valid = [record for record in records if isinstance(record, dict)]
    if not valid:
        return 0.2
    failed = sum(1 for record in valid if record.get("passed") is False)
    declared = sum(record.get("passed") is not None for record in valid)
    return (declared / len(records)) * max(0.2, 1.0 - failed / len(valid))


def _structured_evidence_quality(value):
    if not isinstance(value, dict) or not value:
        return 0.0
    quality = 0.20
    quantitative = sum(
        _finite_nonnegative_number(value.get(field))
        for field in _QUANTITATIVE_RELIABILITY_FIELDS
        if field in value
    )
    quality += min(0.35, quantitative * 0.07)
    if value.get("validated") is True or value.get("reviewed") is True:
        quality += 0.10
    if _has_declared_value(value.get("evaluation_id") or value.get("test_suite_id")):
        quality += 0.05
    if _sha256_quality(value.get("dataset_sha256")) == 1.0:
        quality += 0.10
    if _has_declared_value(value.get("evaluated_at")):
        quality += 0.05
    return min(quality, 0.85)


def _finite_nonnegative_number(value):
    if isinstance(value, bool):
        return False
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return math.isfinite(parsed) and parsed >= 0.0


def _has_declared_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _recommendation(gap):
    if gap.startswith("missing evidence: "):
        field = gap.split(": ", 1)[1]
        return f"Collect and attach {field} evidence."
    if gap.startswith("weak evidence: "):
        field = gap.split(": ", 1)[1]
        return f"Strengthen and independently validate {field} evidence."
    if gap.startswith("severe finding: "):
        finding = gap.split(": ", 1)[1]
        return f"Review and mitigate {finding} before relying on the artifact."
    return "Review trustworthiness evidence gap."


def _normalized_value(value):
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _ordered_unique(values: Iterable[Any]):
    return list(dict.fromkeys(values))


def _clamp(value):
    return _clamp_range(float(value), 0.0, 100.0)


def _clamp_unit(value):
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if not math.isfinite(parsed):
        return 0.0
    return _clamp_range(parsed, 0.0, 1.0)


def _clamp_range(value, minimum, maximum):
    return max(minimum, min(maximum, value))


def _level(score):
    if score >= 80.0:
        return "HIGH"
    if score >= 50.0:
        return "MODERATE"
    return "LOW"

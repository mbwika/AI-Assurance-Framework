"""RiskEngine orchestration for AI assurance analyzers."""
from datetime import datetime, timezone
from typing import Any

from ..analysis import (
    TOOL_RISK_SCORING_VERSION,
    BiasSeverity,
    HallucinationRiskLevel,
    ToolRiskTier,
    assess_adversarial_exposure,
    assess_agent_risk_v2,
    assess_bias_fairness,
    assess_hallucination_risk,
    assess_tool_invocation_risk,
    detect_data_leakage,
    detect_jailbreak,
    detect_prompt_injection,
    estimate_model_risk_v2,
    score_trustworthiness,
    validate_supply_chain,
)
from ..mapping.standards import map_finding_to_controls
from .risk_register_engine import RiskRegisterEngine

RISK_AGGREGATION_VERSION = "1.0"
SEVERITY_WEIGHTS = {"LOW": 1.0, "MEDIUM": 1.5, "HIGH": 2.5, "CRITICAL": 4.0}
SEVERITY_FLOORS = {"LOW": 1.0, "MEDIUM": 3.0, "HIGH": 6.0, "CRITICAL": 8.0}

# Uncertainty-aware v2 scorers always surface evidence-quality factors, so a
# nonzero score no longer implies a reportable finding. Model and agent risk are
# emitted only at MEDIUM severity or higher; below that they remain trend metrics.
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_FINDING_SEVERITY_FLOOR = _SEVERITY_RANK["MEDIUM"]

# Per-invocation tool risk is surfaced as a finding only once it reaches the
# MEDIUM tier; below that it is still captured as a trend metric. Tier ranks
# also let the engine pick the highest-risk invocation deterministically.
_TOOL_TIER_RANK = {
    ToolRiskTier.SAFE: 0,
    ToolRiskTier.LOW: 1,
    ToolRiskTier.MEDIUM: 2,
    ToolRiskTier.HIGH: 3,
    ToolRiskTier.CRITICAL: 4,
}
_TOOL_TIER_TO_SEVERITY = {
    ToolRiskTier.SAFE: "LOW",
    ToolRiskTier.LOW: "LOW",
    ToolRiskTier.MEDIUM: "MEDIUM",
    ToolRiskTier.HIGH: "HIGH",
    ToolRiskTier.CRITICAL: "CRITICAL",
}
_TOOL_FINDING_TIER_FLOOR = _TOOL_TIER_RANK[ToolRiskTier.MEDIUM]
_TOOL_INVOCATION_CONTEXT_KEYS = (
    "capability",
    "action",
    "operation",
    "input_source",
    "data_classification",
    "target_environment",
    "output_destination",
)
_HALLUCINATION_LEVEL_RANK = {
    HallucinationRiskLevel.LOW: 0,
    HallucinationRiskLevel.MEDIUM: 1,
    HallucinationRiskLevel.HIGH: 2,
    HallucinationRiskLevel.CRITICAL: 3,
}
_HALLUCINATION_FINDING_LEVEL_FLOOR = _HALLUCINATION_LEVEL_RANK[HallucinationRiskLevel.MEDIUM]

_BIAS_SEVERITY_RANK = {
    BiasSeverity.NONE: 0,
    BiasSeverity.LOW: 1,
    BiasSeverity.MEDIUM: 2,
    BiasSeverity.HIGH: 3,
    BiasSeverity.CRITICAL: 4,
}
# Bias/fairness is surfaced as a finding at MEDIUM severity or higher; below
# that it is still captured as a trend metric for continuous monitoring.
_BIAS_FINDING_SEVERITY_FLOOR = _BIAS_SEVERITY_RANK[BiasSeverity.MEDIUM]

_TOOL_INVOCATION_CONTEXT_FLAGS = (
    "contains_secrets",
    "destination_trusted",
    "output_consumed_by_agent",
    "approval_verified",
)


class RiskEngine:
    def __init__(self, datastore: object | None = None):
        self.datastore = datastore

    def analyze(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Run a set of analyses on the provided artifact and return findings.

        The engine runs small analysis pipelines and persists findings using
        the configured datastore (if any).
        """
        content = artifact.get("content", "")

        pi = detect_prompt_injection(content, source_context=_source_context(artifact))
        jb = detect_jailbreak(content, analysis_context=_jailbreak_context(artifact))
        mr = estimate_model_risk_v2(artifact)
        ar = assess_agent_risk_v2(artifact)
        sc = validate_supply_chain(
            artifact, assessment_context=_attestation_verification_context(artifact)
        )
        dl = detect_data_leakage(content, analysis_context=_egress_context(artifact))
        at = assess_adversarial_exposure(artifact)
        ti = _assess_tool_invocations(artifact)
        hr = _assess_hallucination(artifact)
        bf = _assess_bias_fairness(artifact)

        findings = []
        if pi.get("suspicious"):
            findings.append(_finding("prompt_injection", pi))
        if jb.get("suspicious"):
            findings.append(_finding("jailbreak", jb))
        if _SEVERITY_RANK.get(mr.get("severity"), 0) >= _FINDING_SEVERITY_FLOOR:
            findings.append(_finding("model_risk", mr))
        if ar.get("applicable") and _SEVERITY_RANK.get(ar.get("severity"), 0) >= _FINDING_SEVERITY_FLOOR:
            findings.append(_finding("agent_risk", ar))
        if not sc.get("valid", True):
            findings.append(_finding("supply_chain", sc))
        if dl.get("suspicious"):
            findings.append(_finding("data_leakage", dl))
        if at.get("risk_score", 0) > 0:
            findings.append(_finding("adversarial_testing", at))
        if ti is not None and ti["max_tier_rank"] >= _TOOL_FINDING_TIER_FLOOR:
            findings.append(_finding("tool_invocation_risk", ti))
        if hr["overall_risk_rank"] >= _HALLUCINATION_FINDING_LEVEL_FLOOR:
            findings.append(_finding("hallucination_risk", hr))
        if bf["overall_severity_rank"] >= _BIAS_FINDING_SEVERITY_FLOOR:
            findings.append(_finding("bias_fairness", bf))

        aggregation = aggregate_risk_score(findings)
        score = aggregation["score"]

        for finding in findings:
            finding["mapping"] = map_finding_to_controls(finding)

        trust = score_trustworthiness(artifact, risk_score=score, findings=findings)

        record = {
            "artifact_id": artifact.get("id"),
            "timestamp": _utc_now(),
            "findings": findings,
            "score": score,
            "risk_aggregation": aggregation,
            "trustworthiness": trust,
            "risk_register": {"observed_risks": [], "observation_count": 0},
            "persistence": {
                "status": "NOT_CONFIGURED" if self.datastore is None else "COMPLETE",
                "operations": [],
                "errors": [],
            },
        }

        if self.datastore is not None:
            try:
                self.datastore.save_finding(record)
                record["persistence"]["operations"].append("finding")
            except Exception as exc:
                _persistence_error(record, "finding", exc)
            try:
                observed_risks = RiskRegisterEngine(self.datastore).observe_findings(
                    artifact.get("id"),
                    findings,
                    observed_at=record["timestamp"],
                    remediation_sla=artifact.get("remediation_sla"),
                )
                record["risk_register"] = {
                    "observed_risks": observed_risks,
                    "observation_count": len(observed_risks),
                }
                record["persistence"]["operations"].append("risk_register")
            except Exception as exc:
                _persistence_error(record, "risk_register", exc)
            try:
                self.datastore.save_metric(
                    "model_risk_score",
                    mr.get("risk_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "assessment_version": mr.get("assessment_version"),
                        "scoring_version": mr.get("scoring_version"),
                        "severity": mr.get("severity"),
                        "inherent_risk_score": mr.get("inherent_risk_score"),
                        "residual_risk_score": mr.get("residual_risk_score"),
                        "lower_confidence_bound": mr.get("lower_confidence_bound"),
                        "upper_confidence_bound": mr.get("upper_confidence_bound"),
                        "confidence": mr.get("confidence"),
                        "evidence_quality": (mr.get("evidence_quality") or {}).get("confidence"),
                        "assessment_complete": mr.get("assessment_complete"),
                        "score_gates": [gate.get("gate") for gate in mr.get("score_gates", [])],
                        "indicators": mr.get("indicators", []),
                        "dimension_scores": {
                            name: dimension.get("score")
                            for name, dimension in mr.get("dimensions", {}).items()
                        },
                    },
                )
                record["persistence"]["operations"].append("model_risk_metric")
            except Exception as exc:
                _persistence_error(record, "model_risk_metric", exc)
            try:
                self.datastore.save_metric(
                    "risk_score",
                    score,
                    {
                        "artifact_id": artifact.get("id"),
                        "finding_count": len(findings),
                        "max_severity": _max_severity(findings),
                        "aggregation_version": RISK_AGGREGATION_VERSION,
                    },
                )
                record["persistence"]["operations"].append("risk_metric")
            except Exception as exc:
                _persistence_error(record, "risk_metric", exc)
            try:
                self.datastore.save_metric(
                    "trustworthiness_score",
                    trust.get("trustworthiness_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "level": trust.get("level"),
                        "raw_trustworthiness_score": trust.get(
                            "raw_trustworthiness_score"
                        ),
                        "confidence": trust.get("confidence"),
                        "scoring_version": trust.get("scoring_version"),
                        "applicable_dimensions": trust.get("applicable_dimensions", []),
                        "score_gates": [
                            gate.get("gate")
                            for gate in trust.get("score_gates", [])
                        ],
                        "dimension_scores": {
                            name: dimension.get("score")
                            for name, dimension in trust.get("dimensions", {}).items()
                        },
                    },
                )
                record["persistence"]["operations"].append("trustworthiness_metric")
            except Exception as exc:
                _persistence_error(record, "trustworthiness_metric", exc)
            if ti is not None:
                try:
                    self.datastore.save_metric(
                        "tool_invocation_risk_score",
                        ti.get("risk_score", 0.0),
                        {
                            "artifact_id": artifact.get("id"),
                            "invocation_count": ti.get("invocation_count"),
                            "highest_risk_tool": ti.get("highest_risk_tool"),
                            "highest_risk_tier": ti.get("highest_risk_tier"),
                            "scoring_version": ti.get("scoring_version"),
                        },
                    )
                    record["persistence"]["operations"].append("tool_invocation_metric")
                except Exception as exc:
                    _persistence_error(record, "tool_invocation_metric", exc)
            try:
                self.datastore.save_metric(
                    "hallucination_risk_score",
                    hr.get("risk_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "overall_risk": hr.get("overall_risk"),
                        "evidence_quality": hr.get("evidence_quality"),
                        "factuality_lower_bound": hr.get("factuality_lower_bound"),
                        "scoring_version": hr.get("scoring_version"),
                    },
                )
                record["persistence"]["operations"].append("hallucination_metric")
            except Exception as exc:
                _persistence_error(record, "hallucination_metric", exc)
            try:
                self.datastore.save_metric(
                    "bias_fairness_score",
                    bf.get("risk_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "overall_severity": bf.get("overall_severity"),
                        "evidence_quality": bf.get("evidence_quality"),
                        "scoring_version": bf.get("scoring_version"),
                    },
                )
                record["persistence"]["operations"].append("bias_fairness_metric")
            except Exception as exc:
                _persistence_error(record, "bias_fairness_metric", exc)
            try:
                self.datastore.save_metric(
                    "data_leakage_score",
                    dl.get("risk_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "severity": dl.get("severity"),
                        "confidence": dl.get("confidence"),
                        "data_classes": dl.get("data_classes", []),
                        "context_multiplier": dl.get("context_multiplier"),
                        "scoring_version": dl.get("scoring_version"),
                    },
                )
                record["persistence"]["operations"].append("data_leakage_metric")
            except Exception as exc:
                _persistence_error(record, "data_leakage_metric", exc)
            try:
                robustness = at.get("robustness", {})
                evidence_quality = at.get("evidence_quality", {})
                self.datastore.save_metric(
                    "adversarial_evidence_quality_score",
                    evidence_quality.get("score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "conservative_robustness_score": robustness.get(
                            "conservative_robustness_score"
                        ),
                        "upper_confidence_bound": robustness.get(
                            "upper_confidence_bound"
                        ),
                        "coverage_ratio": at.get("coverage", {}).get("coverage_ratio"),
                        "scoring_version": at.get("scoring_version"),
                    },
                )
                record["persistence"]["operations"].append("adversarial_metric")
            except Exception as exc:
                _persistence_error(record, "adversarial_metric", exc)
            try:
                self.datastore.save_metric(
                    "supply_chain_risk_score",
                    sc.get("risk_score", 0.0),
                    {
                        "artifact_id": artifact.get("id"),
                        "scoring_version": sc.get("scoring_version"),
                        "severity": sc.get("severity"),
                        "raw_risk_score": sc.get("raw_risk_score"),
                        "valid": sc.get("valid"),
                        "assessment_complete": sc.get("assessment_complete"),
                        "confidence": (sc.get("evidence_quality") or {}).get("confidence"),
                        "evidence_coverage": (sc.get("evidence_quality") or {}).get("coverage"),
                    },
                )
                record["persistence"]["operations"].append("supply_chain_metric")
            except Exception as exc:
                _persistence_error(record, "supply_chain_metric", exc)
            if ar.get("applicable"):
                try:
                    workflow_graph = ar.get("workflow_graph", {})
                    delegation = ar.get("delegation_analysis", {})
                    self.datastore.save_metric(
                        "agent_risk_score",
                        ar.get("risk_score", 0.0),
                        {
                            "artifact_id": artifact.get("id"),
                            "scoring_version": ar.get("scoring_version"),
                            "severity": ar.get("severity"),
                            "inherent_risk_score": ar.get("inherent_risk_score"),
                            "residual_risk_score": ar.get("residual_risk_score"),
                            "confidence": ar.get("confidence"),
                            "assessment_complete": ar.get("assessment_complete"),
                            "score_gates": [gate.get("gate") for gate in ar.get("score_gates", [])],
                            "policy_profile": ar.get("policy_profile"),
                            "delegation": {
                                "agent_count": delegation.get("agent_count"),
                                "edge_count": delegation.get("edge_count"),
                                "cycle_count": len(delegation.get("cycles", [])),
                            },
                            "workflow_graph": {
                                "scoring_version": workflow_graph.get("scoring_version"),
                                "assessment_complete": workflow_graph.get("assessment_complete"),
                                "node_count": workflow_graph.get("node_count"),
                                "edge_count": workflow_graph.get("edge_count"),
                                "risk_count": workflow_graph.get("risk_summary", {}).get("risk_count"),
                            },
                        },
                    )
                    record["persistence"]["operations"].append("agent_risk_metric")
                except Exception as exc:
                    _persistence_error(record, "agent_risk_metric", exc)

        return record


def aggregate_risk_score(findings) -> dict[str, Any]:
    """Aggregate heterogeneous findings into a severity-aware 0-10 score."""
    if not findings:
        return {
            "version": RISK_AGGREGATION_VERSION,
            "methodology": "severity_weighted_mean_with_floor_and_density",
            "score": 0.0,
            "severity": "LOW",
            "finding_count": 0,
            "contributions": [],
            "score_scale": {"minimum": 0.0, "maximum": 10.0},
        }

    contributions = []
    weighted_total = 0.0
    total_weight = 0.0
    max_floor = 0.0
    for finding in findings:
        severity = str(finding.get("severity") or "LOW").upper()
        raw_score = max(0.0, min(10.0, float(finding.get("risk_score") or 0.0)))
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        weighted_total += raw_score * weight
        total_weight += weight
        max_floor = max(max_floor, SEVERITY_FLOORS.get(severity, 1.0))
        contributions.append(
            {
                "type": finding.get("type", "unknown"),
                "severity": severity,
                "raw_score": raw_score,
                "weight": weight,
            }
        )

    weighted_mean = weighted_total / total_weight if total_weight else 0.0
    density_uplift = min(max(len(findings) - 1, 0) * 0.25, 1.0)
    score = round(min(10.0, max(weighted_mean, max_floor) + density_uplift), 3)
    severity = (
        "CRITICAL"
        if score >= 8
        else "HIGH"
        if score >= 6
        else "MEDIUM"
        if score >= 3
        else "LOW"
    )
    return {
        "version": RISK_AGGREGATION_VERSION,
        "methodology": "severity_weighted_mean_with_floor_and_density",
        "score": score,
        "severity": severity,
        "finding_count": len(findings),
        "weighted_mean": round(weighted_mean, 3),
        "severity_floor": max_floor,
        "density_uplift": round(density_uplift, 3),
        "contributions": contributions,
        "score_scale": {"minimum": 0.0, "maximum": 10.0},
    }


def _assess_tool_invocations(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """Run per-invocation tool risk scoring and aggregate it into a finding detail.

    Invocations are sourced from an explicit ``tool_invocations`` list and from
    ``workflow_steps``/``workflow`` entries that declare a tool. The bare
    ``tools`` list is intentionally not used here: those names carry no
    per-invocation context and are already evaluated by ``assess_agent_risk_v2``.
    Returns ``None`` when the artifact declares no tool invocations.
    """
    invocations = _collect_tool_invocations(artifact)
    if not invocations:
        return None

    results = [assess_tool_invocation_risk(**kwargs) for kwargs in invocations]
    highest = max(results, key=lambda result: result.score)

    indicators: list = []
    for result in results:
        for contribution in result.score_breakdown:
            if contribution.indicator not in indicators:
                indicators.append(contribution.indicator)

    return {
        "risk_score": highest.score,
        "score": highest.score,
        "severity": _TOOL_TIER_TO_SEVERITY.get(highest.risk_tier, "LOW"),
        "suspicious": highest.score > 0,
        "scoring_version": TOOL_RISK_SCORING_VERSION,
        "invocation_count": len(results),
        "highest_risk_tool": highest.tool_name,
        "highest_risk_tier": highest.risk_tier.value,
        "max_tier_rank": _TOOL_TIER_RANK.get(highest.risk_tier, 0),
        "indicators": indicators,
        "tool_results": [_serialize_tool_result(result) for result in results],
        "owasp_refs": sorted({ref for result in results for ref in result.owasp_refs}),
        "mitre_atlas_refs": sorted(
            {ref for result in results for ref in result.mitre_atlas_refs}
        ),
    }


def _collect_tool_invocations(artifact: dict[str, Any]) -> list:
    """Normalize explicit and workflow-derived tool invocations into kwargs."""
    invocations: list = []

    explicit = artifact.get("tool_invocations")
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, dict) and (item.get("tool_name") or item.get("tool")):
                invocations.append(_invocation_kwargs(item, artifact))

    workflow = artifact.get("workflow_steps") or artifact.get("workflow") or []
    if isinstance(workflow, dict):
        workflow = workflow.get("steps", [])
    for step in workflow or []:
        if isinstance(step, dict) and (step.get("tool") or step.get("name")):
            invocations.append(_invocation_kwargs(step, artifact))

    return invocations


def _invocation_kwargs(item: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    """Map an explicit invocation or a workflow step to analyzer keyword args."""
    context = item.get("input_context")
    if not isinstance(context, dict):
        context = {}
        for key in _TOOL_INVOCATION_CONTEXT_KEYS:
            if item.get(key) is not None:
                context[key] = item.get(key)
        for key in _TOOL_INVOCATION_CONTEXT_FLAGS:
            if key in item:
                context[key] = item.get(key)

    requires_approval = (
        _flag(item.get("requires_human_approval"))
        or _flag(item.get("requires_approval"))
        or _flag(item.get("approval_required"))
        or _flag(artifact.get("human_review_required"))
    )

    return {
        "tool_name": item.get("tool_name") or item.get("tool") or "",
        "declared_permissions": item.get("declared_permissions") or item.get("permissions"),
        "input_context": context or None,
        "requires_human_approval": requires_approval,
        "is_idempotent": _flag(item.get("is_idempotent"), True),
        "has_input_validation": _flag(
            item.get("has_input_validation", item.get("input_validation"))
        ),
        "has_output_sanitization": _flag(
            item.get("has_output_sanitization", item.get("output_sanitization"))
        ),
    }


def _serialize_tool_result(result: Any) -> dict[str, Any]:
    """Convert a ToolInvocationRiskResult into a JSON-serializable dict."""
    return {
        "tool_name": result.tool_name,
        "risk_tier": result.risk_tier.value,
        "score": result.score,
        "capability_class": result.capability_class,
        "matched_capabilities": list(result.matched_capabilities),
        "risk_factors": list(result.risk_factors),
        "recommendations": list(result.recommendations),
        "owasp_refs": list(result.owasp_refs),
        "mitre_atlas_refs": list(result.mitre_atlas_refs),
        "scoring_version": result.scoring_version,
        "score_breakdown": [
            {
                "indicator": contribution.indicator,
                "weight": contribution.weight,
                "detail": contribution.detail,
            }
            for contribution in result.score_breakdown
        ],
    }


def _assess_hallucination(artifact: dict[str, Any]) -> dict[str, Any]:
    """Run hallucination risk assessment from artifact-declared context.

    All 13 boolean flags and three evidence dicts are sourced directly from the
    artifact. The analyzer always runs (domain defaults to "") so a trend metric
    is always available; the calling site gates finding emission at MEDIUM+.
    """
    result = assess_hallucination_risk(
        model_id=str(artifact.get("model_id") or artifact.get("id") or ""),
        domain=str(artifact.get("domain") or ""),
        has_output_grounding=_flag(artifact.get("has_output_grounding")),
        has_retrieval_augmentation=_flag(artifact.get("has_retrieval_augmentation")),
        has_factuality_evaluation=_flag(artifact.get("has_factuality_evaluation")),
        has_confidence_calibration=_flag(artifact.get("has_confidence_calibration")),
        has_human_review_for_high_stakes=_flag(
            artifact.get("has_human_review_for_high_stakes")
        ),
        output_used_for_automated_decisions=_flag(
            artifact.get("output_used_for_automated_decisions")
        ),
        has_self_consistency_checking=_flag(
            artifact.get("has_self_consistency_checking")
        ),
        knowledge_cutoff_declared=_flag(artifact.get("knowledge_cutoff_declared")),
        factuality_evidence=artifact.get("factuality_evidence"),
        retrieval_evidence=artifact.get("retrieval_evidence"),
        decision_context=artifact.get("decision_context"),
    )
    serialized = _serialize_hallucination_result(result)
    serialized["overall_risk_rank"] = _HALLUCINATION_LEVEL_RANK.get(result.overall_risk, 0)
    return serialized


def _serialize_hallucination_result(result: Any) -> dict[str, Any]:
    """Convert a HallucinationRiskResult into a JSON-serializable dict."""
    return {
        "risk_score": result.risk_score,
        "score": result.risk_score,
        "severity": result.overall_risk.value,
        "overall_risk": result.overall_risk.value,
        "scoring_version": result.scoring_version,
        "evidence_quality": result.evidence_quality,
        "factuality_lower_bound": result.factuality_lower_bound,
        "risk_factors": [
            {
                "factor": f.factor,
                "risk_level": f.risk_level.value,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "weight": f.weight,
                "evidence": f.evidence,
            }
            for f in result.risk_factors
        ],
        "recommendations": list(result.recommendations),
        "owasp_refs": list(result.owasp_refs),
        "nist_ai_rmf_refs": list(result.nist_ai_rmf_refs),
        "evaluation_warnings": list(result.evaluation_warnings),
    }


def _assess_bias_fairness(artifact: dict[str, Any]) -> dict[str, Any]:
    """Run bias and fairness assessment from artifact-declared context.

    Like the hallucination assessment, this always runs (domain defaults to "")
    so a trend metric is always persisted; the calling site gates finding
    emission at MEDIUM severity or higher. Group-outcome evidence, declared
    controls, and decision context are sourced directly from the artifact.
    """
    result = assess_bias_fairness(
        model_id=str(artifact.get("model_id") or artifact.get("id") or ""),
        domain=str(artifact.get("domain") or ""),
        declared_sensitive_attributes=(
            artifact.get("sensitive_attributes")
            or artifact.get("declared_sensitive_attributes")
        ),
        has_bias_evaluation=_flag(artifact.get("has_bias_evaluation")),
        has_fairness_metrics=_flag(artifact.get("has_fairness_metrics")),
        has_demographic_parity_check=_flag(
            artifact.get("has_demographic_parity_check")
        ),
        has_disparate_impact_analysis=_flag(
            artifact.get("has_disparate_impact_analysis")
        ),
        has_counterfactual_testing=_flag(
            artifact.get("has_counterfactual_testing")
        ),
        human_oversight_level=str(artifact.get("human_oversight_level") or "none"),
        group_metrics=artifact.get("group_metrics"),
        evaluation_context=(
            artifact.get("bias_evaluation_context")
            or artifact.get("fairness_evaluation_context")
        ),
        decision_context=artifact.get("decision_context"),
    )
    serialized = _serialize_bias_result(result)
    serialized["overall_severity_rank"] = _BIAS_SEVERITY_RANK.get(
        result.overall_severity, 0
    )
    return serialized


def _serialize_bias_result(result: Any) -> dict[str, Any]:
    """Convert a BiasFairnessResult into a JSON-serializable dict."""
    return {
        "risk_score": result.risk_score,
        "score": result.risk_score,
        "severity": result.overall_severity.value,
        "overall_severity": result.overall_severity.value,
        "scoring_version": result.scoring_version,
        "evidence_quality": result.evidence_quality,
        "indicators": [item.indicator for item in result.indicators],
        "risk_factors": [
            {
                "indicator": item.indicator,
                "severity": item.severity.value,
                "description": item.description,
                "mitigation": item.mitigation,
                "weight": item.weight,
                "evidence": item.evidence,
            }
            for item in result.indicators
        ],
        "recommendations": list(result.recommendations),
        "mitre_atlas_refs": list(result.mitre_atlas_refs),
        "nist_ai_rmf_refs": list(result.nist_ai_rmf_refs),
        "eu_ai_act_refs": list(result.eu_ai_act_refs),
        "fairness_metrics_summary": result.fairness_metrics_summary,
        "evaluation_warnings": list(result.evaluation_warnings),
    }


def _attestation_verification_context(
    artifact: dict[str, Any],
) -> dict[str, Any] | None:
    """Build the detached verified-attestation context for supply-chain analysis.

    Schema-2 provenance attestations carry no inline verification (the signed
    envelope is strict), so the registry persists verification evidence
    separately. This rebuilds the trusted-ID/digest context that
    ``validate_supply_chain`` binds to each attestation by id and statement
    digest. ``as_of`` is the current assessment time (not the historical
    verification time) so attestation expiry and stale-evidence detection are
    evaluated now rather than at issuance. Returns ``None`` when the artifact
    declares no verified attestations.
    """
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    records = (
        artifact.get("provenance_attestation_verifications")
        or metadata.get("provenance_attestation_verifications")
    )
    if not isinstance(records, list) or not records:
        return None
    ids: list = []
    digests: dict[str, Any] = {}
    for record in records:
        if not isinstance(record, dict) or not record.get("verified"):
            continue
        attestation_id = record.get("attestation_id")
        if not attestation_id:
            continue
        ids.append(attestation_id)
        digest = record.get("attestation_sha256")
        if digest:
            digests[attestation_id] = digest
    if not ids:
        return None
    return {
        "verified_attestation_ids": ids,
        "verified_attestation_digests": digests,
        "as_of": _utc_now(),
    }


_TRUTHY_FLAG_STRINGS = frozenset({"1", "true", "yes", "y", "on", "enabled"})
_FALSY_FLAG_STRINGS = frozenset({"0", "false", "no", "n", "off", "disabled", ""})


def _flag(value: Any, default: bool = False) -> bool:
    """Coerce an artifact flag to bool without treating the string "false" as True.

    JSON and form artifacts can carry boolean flags as strings; ``bool("false")``
    is truthy, which would silently grant evaluation credit the artifact never
    claimed. Recognized truthy/falsy strings are mapped explicitly; unrecognized
    values fall back to ``default`` (conservatively ``False`` for evidence flags).
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUTHY_FLAG_STRINGS:
            return True
        if normalized in _FALSY_FLAG_STRINGS:
            return False
        return default
    return bool(value)


def _source_context(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """Return optional provenance context for prompt-injection analysis."""
    context = artifact.get("source_context")
    return context if isinstance(context, dict) else None


def _jailbreak_context(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """Return optional provenance/security-testing context for jailbreak analysis."""
    context = artifact.get("analysis_context") or artifact.get("source_context")
    return context if isinstance(context, dict) else None


def _egress_context(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """Return optional egress/destination/transport context for leakage analysis."""
    context = (
        artifact.get("egress_context")
        or artifact.get("data_leakage_context")
        or artifact.get("analysis_context")
    )
    return context if isinstance(context, dict) else None


def _finding(finding_type: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": finding_type,
        "risk_score": float(detail.get("risk_score", detail.get("score", 0.0)) or 0.0),
        "severity": detail.get("severity", "LOW"),
        "indicators": detail.get("indicators", []),
        "detail": detail,
    }


def _max_severity(findings) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    selected = "LOW"
    for finding in findings:
        severity = finding.get("severity", "LOW")
        if order.get(severity, 0) > order[selected]:
            selected = severity
    return selected


def _persistence_error(
    record: dict[str, Any], operation: str, error: Exception
) -> None:
    record["persistence"]["status"] = "DEGRADED"
    record["persistence"]["errors"].append(
        {
            "operation": operation,
            "error_type": type(error).__name__,
            "message": str(error),
        }
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

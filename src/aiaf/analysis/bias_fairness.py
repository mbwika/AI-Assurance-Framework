"""Evidence-aware bias and fairness risk assessment.

The analyzer evaluates deployment consequence, protected-attribute use,
statistical group outcomes, classification error disparities, counterfactual
instability, intersectional coverage, and oversight quality. Exact counts are
used to preserve uncertainty; the module performs no I/O or orchestration.
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


BIAS_FAIRNESS_SCORING_VERSION = "2.0"


class BiasSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class BiasIndicator:
    indicator: str
    severity: BiasSeverity
    description: str
    mitigation: Optional[str] = None
    weight: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiasFairnessResult:
    model_id: str
    overall_severity: BiasSeverity
    risk_score: float
    indicators: List[BiasIndicator] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    mitre_atlas_refs: List[str] = field(default_factory=list)
    nist_ai_rmf_refs: List[str] = field(default_factory=list)
    eu_ai_act_refs: List[str] = field(default_factory=list)
    scoring_version: str = BIAS_FAIRNESS_SCORING_VERSION
    fairness_metrics_summary: Dict[str, Any] = field(default_factory=dict)
    evidence_quality: str = "NONE"
    evaluation_warnings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class _GroupEvidence:
    name: str
    attributes: Tuple[str, ...]
    sample_size: int
    favorable_outcomes: Optional[int]
    true_positives: Optional[int]
    actual_positives: Optional[int]
    false_positives: Optional[int]
    actual_negatives: Optional[int]


_HIGH_STAKES_DOMAIN_PHRASES = (
    ("hiring",),
    ("employment",),
    ("lending",),
    ("credit", "scoring"),
    ("credit", "decision"),
    ("criminal", "justice"),
    ("healthcare",),
    ("education",),
    ("social", "benefits"),
    ("insurance",),
    ("housing",),
    ("bail", "risk"),
    ("parole",),
    ("child", "welfare"),
)
_SELECTION_DOMAIN_PHRASES = (
    ("hiring",),
    ("employment",),
    ("lending",),
    ("credit",),
    ("housing",),
    ("insurance",),
    ("education", "admission"),
)
_SENSITIVE_ATTRIBUTES = frozenset(
    {
        "race",
        "ethnicity",
        "gender",
        "sex",
        "age",
        "religion",
        "nationality",
        "disability",
        "pregnancy",
        "sexual_orientation",
        "marital_status",
        "political_opinion",
        "veteran_status",
        "genetic_information",
    }
)
_DIRECT_ATTRIBUTE_USES = frozenset(
    {"decision_input", "direct_input", "feature", "ranking_feature", "eligibility"}
)
_AUDIT_ATTRIBUTE_USES = frozenset({"audit_only", "evaluation_only", "monitoring_only"})
_PARITY_GOALS = frozenset(
    {"demographic_parity", "selection_parity", "adverse_impact", "disparate_impact"}
)
_EQUAL_OPPORTUNITY_GOALS = frozenset({"equal_opportunity", "equalized_odds"})
_LOW_OVERSIGHT = frozenset({"none", "minimal", "ad_hoc", "unknown", ""})
# Bias or disparate outcomes do not, by themselves, establish an adversarial
# ATLAS technique. Craft Adversarial Data (AML.T0043) belongs on a separate
# finding only when evidence supports intentional data manipulation.
_MITRE_ATLAS_REFS: Tuple[str, ...] = ()
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN = re.compile(r"[a-z0-9]+")
_DEFAULT_MIN_GROUP_SAMPLE_SIZE = 100


def assess_bias_fairness(
    model_id: str,
    domain: str,
    declared_sensitive_attributes: Optional[List[str]] = None,
    has_bias_evaluation: bool = False,
    has_fairness_metrics: bool = False,
    has_demographic_parity_check: bool = False,
    has_disparate_impact_analysis: bool = False,
    has_counterfactual_testing: bool = False,
    human_oversight_level: str = "none",
    group_metrics: Optional[List[Dict[str, Any]]] = None,
    evaluation_context: Optional[Dict[str, Any]] = None,
    decision_context: Optional[Dict[str, Any]] = None,
) -> BiasFairnessResult:
    """Assess bias risk from declarations and exact group-outcome evidence.

    Each group metric requires group and sample_size. Optional exact counts are
    favorable_outcomes (or selected/positive_outcomes), true_positives with
    actual_positives, and false_positives with actual_negatives. The
    evaluation context can declare fairness_goal, favorable_outcome_direction,
    adverse_impact_ratio_threshold, rate_gap_threshold,
    min_group_sample_size, sensitive_attribute_use, proxy_attributes, and
    intersectional_evaluation.
    """
    attributes = _normalized_list(declared_sensitive_attributes)
    has_bias_evaluation = has_bias_evaluation is True
    has_fairness_metrics = has_fairness_metrics is True
    has_demographic_parity_check = has_demographic_parity_check is True
    has_disparate_impact_analysis = has_disparate_impact_analysis is True
    has_counterfactual_testing = has_counterfactual_testing is True
    protected_attributes = sorted(set(attributes) & _SENSITIVE_ATTRIBUTES)
    evaluation = evaluation_context if isinstance(evaluation_context, dict) else {}
    decision = decision_context if isinstance(decision_context, dict) else {}
    invalid_group_container = group_metrics is not None and not isinstance(
        group_metrics, list
    )
    raw_groups = group_metrics if isinstance(group_metrics, list) else []
    indicators: List[BiasIndicator] = []
    recommendations: List[str] = []
    warnings: List[str] = []

    def add(
        indicator: str,
        severity: BiasSeverity,
        weight: float,
        description: str,
        mitigation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        if any(item.indicator == indicator for item in indicators):
            return
        indicators.append(
            BiasIndicator(
                indicator=indicator,
                severity=severity,
                description=description,
                mitigation=mitigation or None,
                weight=weight,
                evidence=evidence or {},
            )
        )
        if mitigation and mitigation not in recommendations:
            recommendations.append(mitigation)

    high_stakes = _matches_domain(domain, _HIGH_STAKES_DOMAIN_PHRASES)
    selection_domain = _matches_domain(domain, _SELECTION_DOMAIN_PHRASES)
    fairness_goal = _normalized_value(evaluation.get("fairness_goal"))

    if high_stakes:
        add(
            "high_stakes_domain",
            BiasSeverity.HIGH,
            2.5,
            f"Model is deployed in high-stakes domain '{domain}'",
            "Define harm-specific fairness requirements and deployment stop thresholds",
        )

    attribute_use = _normalized_value(evaluation.get("sensitive_attribute_use"))
    if protected_attributes and attribute_use in _DIRECT_ATTRIBUTE_USES:
        add(
            "protected_attributes_used_for_decisions",
            BiasSeverity.HIGH,
            1.5,
            f"Protected attributes are direct decision inputs: {protected_attributes}",
            "Remove protected attributes from decision features unless a documented lawful exception applies",
            {"attributes": protected_attributes, "use": attribute_use},
        )
    elif protected_attributes and attribute_use not in _AUDIT_ATTRIBUTE_USES:
        add(
            "protected_attribute_use_unclear",
            BiasSeverity.MEDIUM,
            0.75,
            f"Protected attributes are in scope but their use is not constrained: {protected_attributes}",
            "Declare whether protected attributes are audit-only or decision inputs",
            {"attributes": protected_attributes, "use": attribute_use or "undeclared"},
        )

    proxy_attributes = _normalized_list(evaluation.get("proxy_attributes"))
    if proxy_attributes:
        add(
            "potential_proxy_attributes",
            BiasSeverity.HIGH,
            1.0,
            f"Potential protected-attribute proxies are used: {proxy_attributes}",
            "Measure proxy correlation and remove features that create unjustified disparate treatment",
            {"proxy_attributes": proxy_attributes},
        )

    outcome_direction = _normalized_value(
        evaluation.get("favorable_outcome_direction") or "positive"
    )
    if outcome_direction not in {"positive", "beneficial", "negative", "adverse"}:
        warnings.append(
            "favorable_outcome_direction must be positive/beneficial or negative/adverse."
        )
        add(
            "invalid_outcome_direction",
            BiasSeverity.MEDIUM,
            0.5,
            "Favorable outcome direction is malformed, so positive outcomes are assumed",
            "Declare whether the counted outcome is beneficial or adverse",
        )
        outcome_direction = "positive"
    groups, invalid_groups = _parse_group_metrics(
        raw_groups, outcome_direction, warnings
    )
    if invalid_group_container:
        warnings.append("group_metrics must be a list of group evidence objects.")
        invalid_groups += 1
    if invalid_groups:
        add(
            "invalid_group_metric_evidence",
            BiasSeverity.HIGH,
            1.0,
            f"{invalid_groups} group metric record(s) are malformed or internally inconsistent",
            "Reject malformed evidence and retain exact group numerators and denominators",
            {"invalid_group_records": invalid_groups},
        )

    quantitative_evidence = _has_quantitative_comparison(groups)
    evaluation_declared = has_bias_evaluation or bool(raw_groups)
    if not evaluation_declared:
        add(
            "no_bias_evaluation",
            BiasSeverity.HIGH,
            2.0,
            "No bias evaluation evidence is declared",
            "Run representative group, intersectional, and counterfactual evaluations",
        )
    elif not quantitative_evidence:
        add(
            "unquantified_bias_evaluation",
            BiasSeverity.HIGH,
            1.5,
            "Bias evaluation lacks at least two valid group-outcome records",
            "Retain exact outcome and error counts for each evaluated group",
        )

    if not has_fairness_metrics and not quantitative_evidence:
        add(
            "no_fairness_metrics",
            BiasSeverity.MEDIUM,
            1.0,
            "No quantitative fairness metric evidence is available",
            "Select fairness metrics tied to the deployment harm model",
        )
    elif has_fairness_metrics and not quantitative_evidence:
        add(
            "unquantified_fairness_metrics",
            BiasSeverity.MEDIUM,
            0.75,
            "Fairness metrics are declared without comparable group numerators and denominators",
            "Retain exact group outcome or confusion-matrix counts for every declared metric",
        )

    selection_required = selection_domain or fairness_goal in _PARITY_GOALS
    if selection_required and not has_demographic_parity_check and not quantitative_evidence:
        add(
            "no_selection_parity_check",
            BiasSeverity.MEDIUM,
            0.5,
            "Selection parity has not been evaluated for a consequential allocation domain",
            "Measure favorable outcome rates by protected and intersectional group",
        )
    if selection_required and not has_disparate_impact_analysis and not quantitative_evidence:
        add(
            "no_disparate_impact_analysis",
            BiasSeverity.MEDIUM,
            0.5,
            "No adverse-impact ratio analysis is available",
            "Evaluate adverse-impact ratios with uncertainty and applicable legal review",
        )
    counterfactual_evidence_present = any(
        field in evaluation
        for field in ("counterfactual_changed_outcomes", "counterfactual_total")
    )
    if high_stakes and not has_counterfactual_testing and not counterfactual_evidence_present:
        add(
            "no_counterfactual_testing",
            BiasSeverity.MEDIUM,
            0.5,
            "No counterfactual sensitivity testing is declared",
            "Test whether protected-attribute changes alter outcomes while legitimate features remain fixed",
        )

    configured_minimum = _positive_integer(evaluation.get("min_group_sample_size"))
    if "min_group_sample_size" in evaluation and configured_minimum is None:
        warnings.append("min_group_sample_size must be a positive integer.")
        add(
            "invalid_group_sample_policy",
            BiasSeverity.MEDIUM,
            0.5,
            "Minimum group sample policy is malformed; the default is used",
            "Declare a positive integer minimum group sample size",
        )
    minimum_group_size = _DEFAULT_MIN_GROUP_SAMPLE_SIZE
    if configured_minimum is not None:
        if configured_minimum < _DEFAULT_MIN_GROUP_SAMPLE_SIZE:
            add(
                "unsafe_group_sample_policy",
                BiasSeverity.MEDIUM,
                0.5,
                f"Configured minimum group sample size {configured_minimum} weakens the {_DEFAULT_MIN_GROUP_SAMPLE_SIZE}-record assurance floor",
                "Use a minimum at least as strong as the built-in statistical assurance floor",
                {
                    "configured_minimum": configured_minimum,
                    "enforced_minimum": _DEFAULT_MIN_GROUP_SAMPLE_SIZE,
                },
            )
        else:
            minimum_group_size = configured_minimum
    underpowered = sorted(
        group.name for group in groups if group.sample_size < minimum_group_size
    )
    underpowered_denominators = _underpowered_metric_denominators(
        groups, minimum_group_size
    )
    underpowered_evidence = sorted(set(underpowered + underpowered_denominators))
    if underpowered_evidence:
        add(
            "underpowered_group_evaluation",
            BiasSeverity.HIGH,
            1.0,
            f"Group metric denominators below the {minimum_group_size}-record minimum: {underpowered_evidence}",
            "Increase subgroup samples or use a justified uncertainty-aware evaluation design",
            {
                "groups_or_metrics": underpowered_evidence,
                "minimum_group_sample_size": minimum_group_size,
            },
        )

    if raw_groups and len(groups) < 2:
        add(
            "insufficient_group_comparison",
            BiasSeverity.HIGH,
            1.0,
            "Fewer than two valid groups are available for disparity comparison",
            "Evaluate all materially affected protected groups against a justified reference",
        )

    if len(protected_attributes) >= 2 and not _has_intersectional_evidence(groups):
        add(
            "missing_intersectional_evaluation",
            BiasSeverity.HIGH,
            0.75,
            "Multiple protected attributes are in scope without intersectional group evidence",
            "Evaluate intersections rather than relying only on single-attribute averages",
            {"attributes": protected_attributes},
        )

    summary: Dict[str, Any] = {
        "group_count": len(groups),
        "invalid_group_records": invalid_groups,
        "minimum_group_sample_size": minimum_group_size,
        "groups": [_group_summary(group) for group in groups],
    }
    summary["selection_parity"] = _evaluate_selection_disparity(
        groups, evaluation, add, warnings
    )
    summary["equal_opportunity"] = _evaluate_rate_gap(
        groups,
        "true_positives",
        "actual_positives",
        "true_positive_rate",
        "equal_opportunity_gap",
        evaluation,
        add,
        warnings,
    )
    summary["false_positive_parity"] = _evaluate_rate_gap(
        groups,
        "false_positives",
        "actual_negatives",
        "false_positive_rate",
        "false_positive_rate_gap",
        evaluation,
        add,
        warnings,
    )

    if fairness_goal in _EQUAL_OPPORTUNITY_GOALS:
        required = ["equal_opportunity"]
        if fairness_goal == "equalized_odds":
            required.append("false_positive_parity")
        missing = [name for name in required if not summary[name]["available"]]
        if missing:
            add(
                "missing_goal_aligned_error_metrics",
                BiasSeverity.HIGH,
                0.75,
                f"Fairness goal '{fairness_goal}' lacks required metrics: {missing}",
                "Collect confusion-matrix counts by group for the declared fairness goal",
                {"fairness_goal": fairness_goal, "missing_metrics": missing},
            )

    summary["counterfactual"] = _evaluate_counterfactual(
        has_counterfactual_testing,
        evaluation,
        minimum_group_size,
        add,
        warnings,
    )

    oversight = _normalized_value(human_oversight_level)
    if oversight not in {
        "none",
        "minimal",
        "ad_hoc",
        "standard",
        "extensive",
        "independent",
        "unknown",
        "",
    }:
        warnings.append(f"Unknown human_oversight_level: {human_oversight_level}")
        oversight = "unknown"
    automated = _hazard_bool(decision, "automated_decisions")
    current_score = sum(item.weight for item in indicators)
    if oversight in _LOW_OVERSIGHT and (high_stakes or automated or current_score >= 3.0):
        add(
            "insufficient_human_oversight",
            BiasSeverity.HIGH,
            1.0,
            "Consequential or elevated fairness risk has insufficient human oversight",
            "Use independent reviewers with authority to override and remediate model decisions",
        )
    if "review_independent" in decision and not _control_bool(
        decision, "review_independent"
    ):
        add(
            "non_independent_fairness_review",
            BiasSeverity.MEDIUM,
            0.75,
            "Human review is not independent of the model recommendation",
            "Require source-first review and measure reviewer disagreement and override behavior",
        )

    evidence_quality = _evidence_quality(
        groups, invalid_groups, underpowered_evidence, quantitative_evidence
    )
    score = min(round(sum(item.weight for item in indicators), 2), 10.0)
    return BiasFairnessResult(
        model_id=model_id,
        overall_severity=_severity(score),
        risk_score=score,
        indicators=indicators,
        recommendations=recommendations,
        mitre_atlas_refs=list(_MITRE_ATLAS_REFS),
        nist_ai_rmf_refs=["GOVERN 1.1", "MAP 5.1", "MEASURE 2.5", "MEASURE 2.6"],
        eu_ai_act_refs=["Article 9", "Article 10"],
        fairness_metrics_summary=summary,
        evidence_quality=evidence_quality,
        evaluation_warnings=warnings,
    )


def _parse_group_metrics(raw_groups, outcome_direction, warnings):
    groups = []
    invalid = 0
    seen = set()
    for index, raw in enumerate(raw_groups):
        if not isinstance(raw, dict):
            warnings.append(f"Group metric at index {index} must be an object.")
            invalid += 1
            continue
        name = str(raw.get("group") or raw.get("name") or "").strip()
        sample_size = _positive_integer(raw.get("sample_size"))
        if not name or sample_size is None or name.casefold() in seen:
            warnings.append(
                f"Group metric at index {index} needs a unique group and positive sample_size."
            )
            invalid += 1
            continue

        raw_outcomes = _first_present(
            raw, ("favorable_outcomes", "positive_outcomes", "selected")
        )
        raw_favorable = _bounded_count(raw_outcomes, sample_size)
        if raw_outcomes is not None and raw_favorable is None:
            warnings.append(f"Group '{name}' has invalid favorable outcome counts.")
            invalid += 1
            continue
        favorable = raw_favorable
        if favorable is not None and outcome_direction in {"negative", "adverse"}:
            favorable = sample_size - favorable

        true_positives, actual_positives, valid_tpr = _count_pair(
            raw, "true_positives", "actual_positives"
        )
        false_positives, actual_negatives, valid_fpr = _count_pair(
            raw, "false_positives", "actual_negatives"
        )
        if (
            not valid_tpr
            or not valid_fpr
            or (actual_positives is not None and actual_positives > sample_size)
            or (actual_negatives is not None and actual_negatives > sample_size)
            or (
                actual_positives is not None
                and actual_negatives is not None
                and actual_positives + actual_negatives != sample_size
            )
            or (
                raw_favorable is not None
                and true_positives is not None
                and false_positives is not None
                and raw_favorable != true_positives + false_positives
            )
        ):
            warnings.append(f"Group '{name}' has inconsistent confusion-matrix counts.")
            invalid += 1
            continue

        attributes = _group_attributes(raw.get("attributes"))
        groups.append(
            _GroupEvidence(
                name=name,
                attributes=attributes,
                sample_size=sample_size,
                favorable_outcomes=favorable,
                true_positives=true_positives,
                actual_positives=actual_positives,
                false_positives=false_positives,
                actual_negatives=actual_negatives,
            )
        )
        seen.add(name.casefold())
    return groups, invalid


def _evaluate_selection_disparity(groups, evaluation, add, warnings):
    eligible = [group for group in groups if group.favorable_outcomes is not None]
    if len(eligible) < 2:
        return {"available": False}
    threshold = _ratio_threshold(
        evaluation.get("adverse_impact_ratio_threshold"), 0.80, warnings
    )
    rates = {
        group.name: group.favorable_outcomes / group.sample_size for group in eligible
    }
    best = max(eligible, key=lambda group: rates[group.name])
    worst = min(eligible, key=lambda group: rates[group.name])
    best_rate = rates[best.name]
    worst_rate = rates[worst.name]
    if best_rate == 0:
        add(
            "degenerate_outcome_distribution",
            BiasSeverity.MEDIUM,
            0.75,
            "No evaluated group receives a favorable outcome",
            "Review outcome definitions and whether the system is fit for deployment",
        )
        return {
            "available": True,
            "adverse_impact_ratio": None,
            "best_group": best.name,
            "worst_group": worst.name,
        }

    ratio = worst_rate / best_rate
    worst_interval = _wilson_interval(worst.favorable_outcomes, worst.sample_size)
    best_interval = _wilson_interval(best.favorable_outcomes, best.sample_size)
    conservative_ratio = (
        worst_interval[1] / best_interval[0] if best_interval[0] > 0 else None
    )
    robust = conservative_ratio is not None and conservative_ratio < threshold
    evidence = {
        "best_group": best.name,
        "best_rate": round(best_rate, 4),
        "worst_group": worst.name,
        "worst_rate": round(worst_rate, 4),
        "adverse_impact_ratio": round(ratio, 4),
        "threshold": threshold,
        "confidence_bounded_ratio": (
            round(conservative_ratio, 4) if conservative_ratio is not None else None
        ),
        "statistically_robust": robust,
    }
    if ratio < threshold:
        add(
            "statistically_robust_adverse_impact"
            if robust
            else "potential_adverse_impact",
            BiasSeverity.HIGH if robust else BiasSeverity.MEDIUM,
            5.0 if robust else 1.25,
            (
                f"Favorable-outcome ratio is {ratio:.3f} for '{worst.name}' "
                f"relative to '{best.name}'"
            ),
            "Investigate causal drivers, validate job-related necessity, and halt harmful deployment",
            evidence,
        )
    elif ratio < min(1.0, threshold + 0.10):
        add(
            "near_threshold_adverse_impact",
            BiasSeverity.MEDIUM,
            0.5,
            f"Favorable-outcome ratio of {ratio:.3f} is near the {threshold:.2f} threshold",
            "Increase sample coverage and monitor the ratio with confidence intervals",
            evidence,
        )
    return {"available": True, **evidence}


def _evaluate_rate_gap(
    groups,
    numerator_field,
    denominator_field,
    metric_name,
    indicator_name,
    evaluation,
    add,
    warnings,
):
    eligible = [
        group
        for group in groups
        if getattr(group, numerator_field) is not None
        and getattr(group, denominator_field) is not None
    ]
    if len(eligible) < 2:
        return {"available": False}
    threshold = _gap_threshold(evaluation.get("rate_gap_threshold"), 0.10, warnings)
    rates = {
        group.name: getattr(group, numerator_field) / getattr(group, denominator_field)
        for group in eligible
    }
    highest = max(eligible, key=lambda group: rates[group.name])
    lowest = min(eligible, key=lambda group: rates[group.name])
    gap = rates[highest.name] - rates[lowest.name]
    high_interval = _wilson_interval(
        getattr(highest, numerator_field), getattr(highest, denominator_field)
    )
    low_interval = _wilson_interval(
        getattr(lowest, numerator_field), getattr(lowest, denominator_field)
    )
    robust_gap = max(0.0, high_interval[0] - low_interval[1])
    robust = robust_gap > threshold
    evidence = {
        "highest_group": highest.name,
        "highest_rate": round(rates[highest.name], 4),
        "lowest_group": lowest.name,
        "lowest_rate": round(rates[lowest.name], 4),
        "rate_gap": round(gap, 4),
        "confidence_bounded_gap": round(robust_gap, 4),
        "threshold": threshold,
        "statistically_robust": robust,
    }
    if gap > threshold:
        add(
            f"statistically_robust_{indicator_name}" if robust else indicator_name,
            BiasSeverity.HIGH if robust else BiasSeverity.MEDIUM,
            2.5 if robust else 1.0,
            f"{metric_name} differs by {gap:.1%} between '{highest.name}' and '{lowest.name}'",
            "Diagnose group-specific error mechanisms and enforce goal-aligned error constraints",
            evidence,
        )
    return {"available": True, **evidence}


def _evaluate_counterfactual(
    has_testing, evaluation, minimum_sample_size, add, warnings
):
    changed_value = evaluation.get("counterfactual_changed_outcomes")
    total_value = evaluation.get("counterfactual_total")
    if changed_value is None and total_value is None:
        if has_testing:
            add(
                "unquantified_counterfactual_testing",
                BiasSeverity.LOW,
                0.25,
                "Counterfactual testing is declared without exact changed/total counts",
                "Retain exact counterfactual outcome-flip counts",
            )
        return {"available": False}
    changed = _nonnegative_integer(changed_value)
    total = _positive_integer(total_value)
    if changed is None or total is None or changed > total:
        warnings.append("Counterfactual counts must satisfy 0 <= changed <= total.")
        add(
            "invalid_counterfactual_evidence",
            BiasSeverity.MEDIUM,
            0.5,
            "Counterfactual evidence is malformed",
            "Reject malformed evidence and retain exact changed and total counts",
        )
        return {"available": False}
    rate = changed / total
    lower, upper = _wilson_interval(changed, total)
    threshold = _gap_threshold(
        evaluation.get("counterfactual_flip_threshold"), 0.05, warnings
    )
    underpowered = total < minimum_sample_size
    if underpowered:
        add(
            "underpowered_counterfactual_evaluation",
            BiasSeverity.HIGH,
            1.0,
            f"Counterfactual evaluation has {total} samples, below the {minimum_sample_size}-record minimum",
            "Increase counterfactual sample coverage before treating instability estimates as robust",
            {"total": total, "minimum_sample_size": minimum_sample_size},
        )
    robust = not underpowered and lower > threshold
    evidence = {
        "changed_outcomes": changed,
        "total": total,
        "flip_rate": round(rate, 4),
        "confidence_interval_95": [round(lower, 4), round(upper, 4)],
        "threshold": threshold,
        "statistically_robust": robust,
        "underpowered": underpowered,
    }
    if rate > threshold:
        add(
            "counterfactual_outcome_instability",
            BiasSeverity.HIGH if robust else BiasSeverity.MEDIUM,
            3.0 if robust else 1.5,
            f"Protected-attribute counterfactuals change {rate:.1%} of outcomes",
            "Remove unjustified protected or proxy influence and retest causal pathways",
            evidence,
        )
    return {"available": True, **evidence}


def _group_summary(group):
    summary = {
        "group": group.name,
        "attributes": list(group.attributes),
        "sample_size": group.sample_size,
    }
    if group.favorable_outcomes is not None:
        rate = group.favorable_outcomes / group.sample_size
        summary["favorable_outcomes"] = group.favorable_outcomes
        summary["favorable_outcome_rate"] = round(rate, 4)
    if group.true_positives is not None:
        summary["true_positive_rate"] = round(
            group.true_positives / group.actual_positives, 4
        )
    if group.false_positives is not None:
        summary["false_positive_rate"] = round(
            group.false_positives / group.actual_negatives, 4
        )
    return summary


def _has_intersectional_evidence(groups):
    for group in groups:
        attribute_names = {
            _normalized_value(attribute.split("=", 1)[0])
            for attribute in group.attributes
        }
        if len(attribute_names & _SENSITIVE_ATTRIBUTES) >= 2:
            return True
    return False


def _has_quantitative_comparison(groups):
    comparable_fields = (
        "favorable_outcomes",
        "true_positives",
        "false_positives",
    )
    return any(
        sum(getattr(group, field) is not None for group in groups) >= 2
        for field in comparable_fields
    )


def _underpowered_metric_denominators(groups, minimum):
    underpowered = []
    for group in groups:
        if group.actual_positives is not None and group.actual_positives < minimum:
            underpowered.append(f"{group.name}:actual_positives")
        if group.actual_negatives is not None and group.actual_negatives < minimum:
            underpowered.append(f"{group.name}:actual_negatives")
    return underpowered


def _evidence_quality(groups, invalid, underpowered, quantitative):
    if invalid:
        return "INVALID"
    if not groups:
        return "NONE"
    if not quantitative or underpowered:
        return "WEAK"
    return "STRONG"


def _count_pair(raw, numerator_name, denominator_name):
    numerator_value = raw.get(numerator_name)
    denominator_value = raw.get(denominator_name)
    if numerator_value is None and denominator_value is None:
        return None, None, True
    numerator = _nonnegative_integer(numerator_value)
    denominator = _positive_integer(denominator_value)
    if numerator is None or denominator is None or numerator > denominator:
        return None, None, False
    return numerator, denominator, True


def _bounded_count(value, total):
    if value is None:
        return None
    parsed = _nonnegative_integer(value)
    return parsed if parsed is not None and parsed <= total else None


def _first_present(mapping, fields):
    for field in fields:
        if field in mapping:
            return mapping[field]
    return None


def _group_attributes(value):
    if isinstance(value, dict):
        return tuple(
            sorted(
                f"{_normalized_value(key)}={_normalized_value(item)}"
                for key, item in value.items()
            )
        )
    return tuple(_normalized_list(value))


def _normalized_list(value):
    if value in (None, ""):
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({_normalized_value(item) for item in value if _normalized_value(item)})


def _ratio_threshold(value, default, warnings):
    if value is None:
        return default
    parsed = _unit_interval(value)
    if parsed is None or parsed <= 0:
        warnings.append("adverse_impact_ratio_threshold must be in (0, 1].")
        return default
    return parsed


def _gap_threshold(value, default, warnings):
    if value is None:
        return default
    parsed = _unit_interval(value)
    if parsed is None or parsed <= 0:
        warnings.append("Fairness gap thresholds must be in (0, 1].")
        return default
    return parsed


def _wilson_interval(successes, observations, z=1.959964):
    proportion = successes / observations
    z_squared = z * z
    denominator = 1.0 + z_squared / observations
    center = (proportion + z_squared / (2.0 * observations)) / denominator
    margin = (
        z
        * math.sqrt(
            (proportion * (1.0 - proportion) + z_squared / (4.0 * observations))
            / observations
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _matches_domain(domain, phrases):
    tokens = _tokenize(domain)
    return any(_contains_phrase(tokens, phrase) for phrase in phrases)


def _tokenize(value):
    expanded = _CAMEL_BOUNDARY.sub(" ", str(value or ""))
    return tuple(_TOKEN.findall(expanded.lower()))


def _contains_phrase(tokens, phrase):
    width = len(phrase)
    return any(
        tokens[index : index + width] == phrase
        for index in range(len(tokens) - width + 1)
    )


def _normalized_value(value):
    return "_".join(_tokenize(value))


def _control_bool(context, key):
    return context.get(key) is True


def _hazard_bool(context, key):
    value = context.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "enabled"}


def _unit_interval(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and 0.0 <= parsed <= 1.0 else None


def _positive_integer(value):
    parsed = _nonnegative_integer(value)
    return parsed if parsed is not None and parsed > 0 else None


def _nonnegative_integer(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0 or not parsed.is_integer():
        return None
    return int(parsed)


def _severity(score):
    if score >= 7.5:
        return BiasSeverity.CRITICAL
    if score >= 5.0:
        return BiasSeverity.HIGH
    if score >= 3.0:
        return BiasSeverity.MEDIUM
    if score >= 1.0:
        return BiasSeverity.LOW
    return BiasSeverity.NONE

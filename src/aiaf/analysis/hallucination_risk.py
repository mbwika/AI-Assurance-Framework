"""Evidence-aware hallucination and factual-reliability risk assessment.

The analyzer separates deployment consequence, missing controls, measured
factuality, retrieval integrity, and decision automation. Quantitative pass
rates are evaluated with a Wilson lower confidence bound so small evaluation
sets cannot create false assurance. The module is pure and performs no I/O.
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


HALLUCINATION_RISK_SCORING_VERSION = "2.0"


class HallucinationRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class HallucinationRiskFactor:
    factor: str
    risk_level: HallucinationRiskLevel
    detail: str
    recommendation: Optional[str] = None
    weight: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HallucinationRiskResult:
    model_id: str
    overall_risk: HallucinationRiskLevel
    risk_score: float
    risk_factors: List[HallucinationRiskFactor] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    owasp_refs: List[str] = field(default_factory=list)
    nist_ai_rmf_refs: List[str] = field(default_factory=list)
    scoring_version: str = HALLUCINATION_RISK_SCORING_VERSION
    factuality_lower_bound: Optional[float] = None
    evidence_quality: str = "NONE"
    evaluation_warnings: List[str] = field(default_factory=list)


_HIGH_STAKES_DOMAIN_PHRASES = (
    ("medical",),
    ("clinical",),
    ("healthcare",),
    ("diagnosis",),
    ("drug", "dosage"),
    ("surgical", "guidance"),
    ("legal",),
    ("legal", "interpretation"),
    ("financial", "advice"),
    ("credit", "decision"),
    ("safety", "critical"),
    ("emergency", "response"),
    ("news", "generation"),
    ("academic", "research"),
)
_HIGH_HARM_LEVELS = frozenset({"high", "critical", "severe", "catastrophic"})
_GENERATE_ON_FAILURE = frozenset(
    {"generate", "model_only", "best_effort", "continue", "answer_anyway"}
)
_FACTUALITY_OBSERVATION_FIELDS = frozenset(
    {"correct_claims", "total_claims", "factual_accuracy", "sample_size"}
)
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN = re.compile(r"[a-z0-9]+")


def assess_hallucination_risk(
    model_id: str,
    domain: str,
    has_output_grounding: bool = False,
    has_retrieval_augmentation: bool = False,
    has_factuality_evaluation: bool = False,
    has_confidence_calibration: bool = False,
    has_human_review_for_high_stakes: bool = False,
    output_used_for_automated_decisions: bool = False,
    has_self_consistency_checking: bool = False,
    knowledge_cutoff_declared: bool = False,
    factuality_evidence: Optional[Dict[str, Any]] = None,
    retrieval_evidence: Optional[Dict[str, Any]] = None,
    decision_context: Optional[Dict[str, Any]] = None,
) -> HallucinationRiskResult:
    """Assess factual-reliability risk without treating declared controls as proof.

    factuality_evidence accepts exact correct_claims/total_claims counts or
    factual_accuracy plus sample_size. Optional metrics include
    out_of_distribution_accuracy, expected_calibration_error, and
    evaluation_age_days.

    retrieval_evidence may include source_trust, citation precision and
    coverage, index_age_days, max_index_age_days, untrusted_content_allowed,
    prompt_injection_filter, and retrieval_failure_fallback.
    """
    factuality = factuality_evidence if isinstance(factuality_evidence, dict) else {}
    retrieval = retrieval_evidence if isinstance(retrieval_evidence, dict) else {}
    decision = decision_context if isinstance(decision_context, dict) else {}
    has_output_grounding = has_output_grounding is True
    has_retrieval_augmentation = has_retrieval_augmentation is True
    has_factuality_evaluation = has_factuality_evaluation is True
    has_confidence_calibration = has_confidence_calibration is True
    has_human_review_for_high_stakes = has_human_review_for_high_stakes is True
    output_used_for_automated_decisions = output_used_for_automated_decisions is True
    has_self_consistency_checking = has_self_consistency_checking is True
    knowledge_cutoff_declared = knowledge_cutoff_declared is True
    factors: List[HallucinationRiskFactor] = []
    recommendations: List[str] = []
    warnings: List[str] = []

    def add(
        factor: str,
        level: HallucinationRiskLevel,
        weight: float,
        detail: str,
        recommendation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        if any(item.factor == factor for item in factors):
            return
        factors.append(
            HallucinationRiskFactor(
                factor=factor,
                risk_level=level,
                detail=detail,
                recommendation=recommendation or None,
                weight=weight,
                evidence=evidence or {},
            )
        )
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    high_stakes = _is_high_stakes_domain(domain) or _normalized_value(
        decision.get("harm_severity")
    ) in _HIGH_HARM_LEVELS
    automated_decisions = output_used_for_automated_decisions or _hazard_bool(
        decision, "automated_decisions"
    )
    retrieval_active = has_retrieval_augmentation or bool(retrieval)
    evaluation_declared = has_factuality_evaluation or bool(
        _FACTUALITY_OBSERVATION_FIELDS & set(factuality)
    )

    if high_stakes:
        add(
            "high_stakes_domain",
            HallucinationRiskLevel.HIGH,
            2.5,
            f"Unsupported claims in domain '{domain}' can cause material harm",
            "Require claim-level evidence and independent review before consequential use",
        )
    if automated_decisions:
        add(
            "automated_decision_dependency",
            HallucinationRiskLevel.HIGH,
            1.25,
            "Model output directly influences an automated decision",
            "Constrain automated actions to verified structured outputs and reversible operations",
        )

    if not has_output_grounding:
        add(
            "no_output_grounding",
            HallucinationRiskLevel.HIGH,
            1.75,
            "No claim-level grounding or source-verification control is declared",
            "Bind factual claims to retrievable sources and verify that each source supports the claim",
        )
    elif not _has_citation_measurement(factuality, retrieval):
        add(
            "grounding_effectiveness_unverified",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Grounding is declared without measured citation support or coverage",
            "Measure citation entailment, source quality, and unsupported-claim rate",
        )

    if not evaluation_declared:
        add(
            "no_factuality_evaluation",
            HallucinationRiskLevel.HIGH,
            1.5,
            "No factuality evaluation evidence is declared",
            "Evaluate claim correctness on representative in-domain and adversarial samples",
        )

    factuality_lower_bound, evidence_quality = _evaluate_factuality_evidence(
        factuality, evaluation_declared, add, warnings
    )
    _evaluate_distribution_shift(factuality, add, warnings)
    _evaluate_evidence_age(factuality, add, warnings)

    if not has_confidence_calibration:
        add(
            "uncalibrated_confidence",
            HallucinationRiskLevel.MEDIUM,
            0.75,
            "Confidence or abstention behavior is not calibrated against factual accuracy",
            "Calibrate an externally measured confidence signal and define abstention thresholds",
        )
    elif "expected_calibration_error" not in factuality:
        add(
            "calibration_effectiveness_unverified",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Confidence calibration is declared without measured calibration error",
            "Retain calibration error and raw confidence/outcome evidence from representative samples",
        )
    else:
        _evaluate_calibration(factuality, add, warnings)

    if retrieval_active:
        _evaluate_retrieval_integrity(retrieval, high_stakes, add, warnings)
    elif high_stakes and not has_output_grounding:
        add(
            "no_retrieval_support",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "High-stakes generation has no retrieval or equivalent verified knowledge source",
            "Use an authoritative, versioned knowledge source with retrieval-failure abstention",
        )

    _evaluate_citation_support(factuality, retrieval, add, warnings)

    if automated_decisions and not has_human_review_for_high_stakes:
        add(
            "automated_decisions_without_review",
            HallucinationRiskLevel.CRITICAL,
            2.25,
            "Unverified model output can trigger automated decisions without human review",
            "Require invocation-bound independent review for high-impact or low-confidence outputs",
        )
    elif high_stakes and not has_human_review_for_high_stakes:
        add(
            "high_stakes_output_without_review",
            HallucinationRiskLevel.HIGH,
            1.0,
            "High-stakes factual output has no declared independent human review",
            "Require source-first independent review before the output informs consequential action",
        )
    elif has_human_review_for_high_stakes and (high_stakes or automated_decisions):
        _evaluate_review_quality(decision, high_stakes, automated_decisions, add, warnings)

    if automated_decisions and _normalized_value(decision.get("reversibility")) in {
        "none",
        "irreversible",
        "low",
    }:
        add(
            "irreversible_automated_action",
            HallucinationRiskLevel.HIGH,
            1.0,
            "Model-dependent automated action is difficult or impossible to reverse",
            "Require a reversible staging step and explicit approval before commitment",
        )
    if automated_decisions and not _control_bool(decision, "abstention_enabled"):
        add(
            "no_automated_abstention",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Automated decision flow has no declared low-confidence abstention path",
            "Fail closed when evidence is missing, retrieval fails, or confidence is below threshold",
        )

    if not has_self_consistency_checking:
        add(
            "no_consistency_checking",
            HallucinationRiskLevel.LOW,
            0.25,
            "No contradiction or consistency check is declared",
            "Use consistency checks as a diagnostic, not as proof of factual correctness",
        )
    if not knowledge_cutoff_declared:
        add(
            "undeclared_knowledge_cutoff",
            HallucinationRiskLevel.LOW,
            0.25,
            "Knowledge cutoff is not declared, obscuring recency limitations",
            "Declare the knowledge cutoff and require retrieval for time-sensitive claims",
        )

    score = min(round(sum(item.weight for item in factors), 2), 10.0)
    return HallucinationRiskResult(
        model_id=model_id,
        overall_risk=_risk_level(score),
        risk_score=score,
        risk_factors=factors,
        recommendations=recommendations,
        owasp_refs=["LLM09 Misinformation"],
        nist_ai_rmf_refs=["MANAGE 2.2", "MEASURE 2.1", "MAP 5.2"],
        factuality_lower_bound=factuality_lower_bound,
        evidence_quality=evidence_quality,
        evaluation_warnings=warnings,
    )


def _evaluate_factuality_evidence(factuality, evaluation_declared, add, warnings):
    if not evaluation_declared:
        return None, "NONE"
    if not factuality:
        add(
            "unquantified_factuality_evaluation",
            HallucinationRiskLevel.HIGH,
            1.5,
            "Factuality evaluation is declared without sample counts or measured accuracy",
            "Retain exact passed-claim and total-claim counts for statistical interpretation",
        )
        return None, "DECLARED"

    observations = _factuality_observations(factuality)
    if observations is None:
        warnings.append(
            "Factuality evidence must provide valid counts or a unit-interval accuracy and sample size."
        )
        add(
            "invalid_factuality_evidence",
            HallucinationRiskLevel.HIGH,
            1.5,
            "Factuality evidence is malformed or outside its valid range",
            "Reject malformed metrics and retain raw evaluation counts",
        )
        return None, "INVALID"

    correct, total = observations
    lower_bound = round(_wilson_lower_bound(correct, total), 4)
    evidence = {
        "correct_claims": correct,
        "total_claims": total,
        "wilson_lower_95": lower_bound,
    }
    if lower_bound < 0.60:
        add(
            "poor_factuality_lower_bound",
            HallucinationRiskLevel.CRITICAL,
            2.5,
            f"95% factuality lower bound is only {lower_bound:.1%}",
            "Block consequential use until representative factuality performance improves",
            evidence,
        )
        quality = "WEAK"
    elif lower_bound < 0.75:
        add(
            "low_factuality_lower_bound",
            HallucinationRiskLevel.HIGH,
            1.75,
            f"95% factuality lower bound is {lower_bound:.1%}",
            "Improve factuality and expand evaluation coverage before deployment",
            evidence,
        )
        quality = "WEAK"
    elif lower_bound < 0.90:
        add(
            "moderate_factuality_lower_bound",
            HallucinationRiskLevel.MEDIUM,
            1.0,
            f"95% factuality lower bound is {lower_bound:.1%}",
            "Use abstention and human verification for claims outside validated performance",
            evidence,
        )
        quality = "MODERATE"
    elif lower_bound < 0.95:
        add(
            "factuality_uncertainty",
            HallucinationRiskLevel.LOW,
            0.5,
            f"95% factuality lower bound is {lower_bound:.1%}",
            "Continue expanding representative evaluation samples",
            evidence,
        )
        quality = "MODERATE"
    else:
        quality = "STRONG"
    return lower_bound, quality


def _evaluate_distribution_shift(factuality, add, warnings):
    in_domain = _unit_interval(factuality.get("factual_accuracy"))
    out_of_distribution = _unit_interval(factuality.get("out_of_distribution_accuracy"))
    if "out_of_distribution_accuracy" in factuality and out_of_distribution is None:
        warnings.append("out_of_distribution_accuracy must be between 0 and 1.")
        add(
            "invalid_distribution_shift_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Out-of-distribution performance evidence is malformed",
            "Reject invalid metrics and retain exact shifted-evaluation counts",
        )
        return
    if in_domain is None or out_of_distribution is None:
        return
    gap = in_domain - out_of_distribution
    if out_of_distribution < 0.75 or gap > 0.15:
        add(
            "distribution_shift_degradation",
            HallucinationRiskLevel.HIGH,
            1.25,
            (
                f"Out-of-distribution accuracy is {out_of_distribution:.1%} "
                f"with a {gap:.1%} in-domain gap"
            ),
            "Add shifted, adversarial, and temporal test sets and route novel inputs to abstention",
            {
                "in_domain_accuracy": in_domain,
                "out_of_distribution_accuracy": out_of_distribution,
            },
        )


def _evaluate_evidence_age(factuality, add, warnings):
    age = _nonnegative_number(factuality.get("evaluation_age_days"))
    if "evaluation_age_days" in factuality and age is None:
        warnings.append("evaluation_age_days must be a non-negative number.")
        add(
            "invalid_evidence_age",
            HallucinationRiskLevel.LOW,
            0.25,
            "Factuality evidence age is malformed",
            "Record a verifiable evaluation timestamp",
        )
        return
    if age is None or age <= 90:
        return
    weight = 1.0 if age > 180 else 0.5
    add(
        "stale_factuality_evidence",
        HallucinationRiskLevel.HIGH if age > 180 else HallucinationRiskLevel.MEDIUM,
        weight,
        f"Factuality evidence is {age:g} days old",
        "Re-evaluate after model, prompt, retrieval corpus, or deployment-distribution changes",
        {"evaluation_age_days": age},
    )


def _evaluate_calibration(factuality, add, warnings):
    calibration_error = _unit_interval(factuality.get("expected_calibration_error"))
    if "expected_calibration_error" in factuality and calibration_error is None:
        warnings.append("expected_calibration_error must be between 0 and 1.")
        add(
            "invalid_calibration_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Confidence-calibration evidence is malformed",
            "Reject invalid calibration metrics and retain raw confidence/outcome pairs",
        )
        return
    if calibration_error is None or calibration_error <= 0.10:
        return
    add(
        "poor_confidence_calibration",
        (
            HallucinationRiskLevel.HIGH
            if calibration_error > 0.20
            else HallucinationRiskLevel.MEDIUM
        ),
        1.0 if calibration_error > 0.20 else 0.5,
        f"Expected calibration error is {calibration_error:.1%}",
        "Recalibrate against held-out in-domain and shifted factuality outcomes",
        {"expected_calibration_error": calibration_error},
    )


def _evaluate_retrieval_integrity(retrieval, high_stakes, add, warnings):
    if not retrieval:
        add(
            "retrieval_integrity_unverified",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Retrieval augmentation is declared without source-quality or integrity evidence",
            "Measure retrieval quality, corpus provenance, freshness, and injection resistance",
        )
        return

    source_trust = _unit_interval(retrieval.get("source_trust"))
    if "source_trust" not in retrieval:
        add(
            "retrieval_source_trust_unverified",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Retrieval evidence does not establish source provenance or trust",
            "Score and retain provenance evidence for every retrieval source",
        )
    elif source_trust is None:
        warnings.append("source_trust must be between 0 and 1.")
        add(
            "invalid_retrieval_trust_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Retrieval source-trust evidence is malformed",
            "Require a unit-interval source-trust score backed by provenance policy",
        )
    elif source_trust is not None and source_trust < 0.80:
        add(
            "low_retrieval_source_trust",
            (
                HallucinationRiskLevel.HIGH
                if source_trust < 0.50
                else HallucinationRiskLevel.MEDIUM
            ),
            1.25 if source_trust < 0.50 else 0.5,
            f"Retrieval source-trust score is {source_trust:.1%}",
            "Restrict retrieval to authoritative, provenance-verified sources",
            {"source_trust": source_trust},
        )

    if _hazard_bool(retrieval, "untrusted_content_allowed") and not _control_bool(
        retrieval, "prompt_injection_filter"
    ):
        add(
            "untrusted_retrieval_without_injection_filter",
            HallucinationRiskLevel.HIGH,
            1.5,
            "Untrusted retrieved content can influence generation without injection filtering",
            "Separate retrieved data from instructions and enforce source and content policies",
        )

    fallback = _normalized_value(retrieval.get("retrieval_failure_fallback"))
    if fallback in _GENERATE_ON_FAILURE:
        add(
            "unsafe_retrieval_failure_fallback",
            HallucinationRiskLevel.HIGH,
            1.0,
            f"Retrieval failure falls back to '{fallback}' instead of abstaining",
            "Fail closed or disclose inability to answer when authoritative retrieval fails",
        )

    age = _nonnegative_number(retrieval.get("index_age_days"))
    configured_max = _nonnegative_number(retrieval.get("max_index_age_days"))
    if "max_index_age_days" in retrieval and configured_max is None:
        warnings.append("max_index_age_days must be a non-negative number.")
        add(
            "invalid_retrieval_freshness_policy",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Retrieval freshness limit is malformed",
            "Define a valid non-negative index freshness limit",
        )
    if "index_age_days" in retrieval and age is None:
        warnings.append("index_age_days must be a non-negative number.")
        add(
            "invalid_retrieval_age_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Retrieval index age evidence is malformed",
            "Record a verifiable retrieval-index build timestamp",
        )
    elif age is not None:
        maximum = configured_max if configured_max is not None else (30.0 if high_stakes else 180.0)
        if age > maximum:
            add(
                "stale_retrieval_index",
                (
                    HallucinationRiskLevel.HIGH
                    if high_stakes
                    else HallucinationRiskLevel.MEDIUM
                ),
                1.0 if high_stakes else 0.5,
                f"Retrieval index age of {age:g} days exceeds the {maximum:g}-day limit",
                "Refresh and revalidate the retrieval index before factual use",
                {"index_age_days": age, "max_index_age_days": maximum},
            )


def _evaluate_citation_support(factuality, retrieval, add, warnings):
    precision_value = retrieval.get(
        "citation_precision", factuality.get("citation_precision")
    )
    coverage_value = retrieval.get(
        "citation_coverage", factuality.get("citation_coverage")
    )
    if precision_value is None and coverage_value is None:
        return
    precision = _unit_interval(precision_value)
    coverage = _unit_interval(coverage_value)
    if precision is None or coverage is None:
        warnings.append(
            "citation_precision and citation_coverage must both be between 0 and 1."
        )
        add(
            "invalid_citation_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.75,
            "Citation support evidence is incomplete or malformed",
            "Require valid citation precision and claim-coverage measurements",
        )
        return
    support = min(precision, coverage)
    if support >= 0.80:
        return
    add(
        "weak_citation_support",
        HallucinationRiskLevel.HIGH if support < 0.50 else HallucinationRiskLevel.MEDIUM,
        1.5 if support < 0.50 else 0.75,
        f"Citation support is bounded by {support:.1%} precision/coverage",
        "Verify that citations entail each claim and measure unsupported-claim coverage",
        {"citation_precision": precision, "citation_coverage": coverage},
    )


def _evaluate_review_quality(decision, high_stakes, automated_decisions, add, warnings):
    missing_evidence = {
        field for field in ("review_independent", "review_coverage") if field not in decision
    }
    if missing_evidence:
        consequential = high_stakes and automated_decisions
        add(
            "review_effectiveness_unverified",
            HallucinationRiskLevel.HIGH if consequential else HallucinationRiskLevel.MEDIUM,
            1.0 if consequential else 0.5,
            "Human review is declared without independent-review and coverage evidence",
            "Retain invocation-bound reviewer independence and exact review-coverage evidence",
            {"missing_evidence": sorted(missing_evidence)},
        )
    if "review_independent" in decision and not _control_bool(
        decision, "review_independent"
    ):
        add(
            "non_independent_human_review",
            HallucinationRiskLevel.MEDIUM,
            0.75,
            "Declared reviewer is not independent of the model-generated recommendation",
            "Require reviewers to inspect source evidence before seeing the model recommendation",
        )
    coverage = _unit_interval(decision.get("review_coverage"))
    if "review_coverage" in decision and coverage is None:
        warnings.append("review_coverage must be between 0 and 1.")
        add(
            "invalid_review_coverage_evidence",
            HallucinationRiskLevel.MEDIUM,
            0.5,
            "Human-review coverage evidence is malformed",
            "Retain reviewed-output and total-output counts for review coverage",
        )
    elif (
        coverage is not None
        and high_stakes
        and automated_decisions
        and coverage < 1.0
    ):
        add(
            "incomplete_high_stakes_review_coverage",
            HallucinationRiskLevel.HIGH,
            1.0,
            f"Only {coverage:.1%} of high-stakes automated outputs receive review",
            "Require review of every consequential output or remove direct automation",
            {"review_coverage": coverage},
        )


def _factuality_observations(evidence: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    correct = _nonnegative_integer(evidence.get("correct_claims"))
    total = _positive_integer(evidence.get("total_claims"))
    count_fields_present = "correct_claims" in evidence or "total_claims" in evidence
    rate_fields_present = "factual_accuracy" in evidence or "sample_size" in evidence
    if count_fields_present:
        if correct is None or total is None or correct > total:
            return None
        if rate_fields_present:
            accuracy = _unit_interval(evidence.get("factual_accuracy"))
            sample_size = _positive_integer(evidence.get("sample_size"))
            if accuracy is None or sample_size is None or sample_size != total:
                return None
            rounding_tolerance = 1.0 / total
            if abs(correct / total - accuracy) > rounding_tolerance + 1e-12:
                return None
        return correct, total
    accuracy = _unit_interval(evidence.get("factual_accuracy"))
    sample_size = _positive_integer(evidence.get("sample_size"))
    if accuracy is None or sample_size is None:
        return None
    return math.floor(accuracy * sample_size + 1e-12), sample_size


def _wilson_lower_bound(successes: int, observations: int, z: float = 1.959964) -> float:
    proportion = successes / observations
    z_squared = z * z
    denominator = 1.0 + z_squared / observations
    center = proportion + z_squared / (2.0 * observations)
    margin = z * math.sqrt(
        (proportion * (1.0 - proportion) + z_squared / (4.0 * observations))
        / observations
    )
    return max(0.0, (center - margin) / denominator)


def _has_citation_measurement(
    factuality: Dict[str, Any], retrieval: Dict[str, Any]
) -> bool:
    return all(
        any(field in evidence for evidence in (factuality, retrieval))
        for field in ("citation_precision", "citation_coverage")
    )


def _is_high_stakes_domain(domain: str) -> bool:
    tokens = _tokenize(domain)
    return any(
        _contains_phrase(tokens, phrase) for phrase in _HIGH_STAKES_DOMAIN_PHRASES
    )


def _tokenize(value: Any) -> Tuple[str, ...]:
    expanded = _CAMEL_BOUNDARY.sub(" ", str(value or ""))
    return tuple(_TOKEN.findall(expanded.lower()))


def _contains_phrase(tokens: Tuple[str, ...], phrase: Tuple[str, ...]) -> bool:
    width = len(phrase)
    return any(
        tokens[index : index + width] == phrase
        for index in range(len(tokens) - width + 1)
    )


def _normalized_value(value: Any) -> str:
    return "_".join(_tokenize(value))


def _control_bool(context: Dict[str, Any], key: str) -> bool:
    return context.get(key) is True


def _hazard_bool(context: Dict[str, Any], key: str) -> bool:
    value = context.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "enabled"}


def _unit_interval(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and 0.0 <= parsed <= 1.0 else None


def _nonnegative_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0.0 else None


def _positive_integer(value: Any) -> Optional[int]:
    parsed = _nonnegative_integer(value)
    return parsed if parsed is not None and parsed > 0 else None


def _nonnegative_integer(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0 or not parsed.is_integer():
        return None
    return int(parsed)


def _risk_level(score: float) -> HallucinationRiskLevel:
    if score >= 7.5:
        return HallucinationRiskLevel.CRITICAL
    if score >= 5.0:
        return HallucinationRiskLevel.HIGH
    if score >= 2.5:
        return HallucinationRiskLevel.MEDIUM
    return HallucinationRiskLevel.LOW

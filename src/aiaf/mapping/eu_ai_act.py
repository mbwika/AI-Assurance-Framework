"""EU AI Act (Regulation (EU) 2024/1689) risk classification and obligation mappings.

Provides:
- Risk category classification (Unacceptable / High-Risk / Limited-Risk / Minimal-Risk)
- Control-level obligation mapping from AIAF controls to Act articles
- Use-case classification helpers for high-risk and prohibited applications

References: Regulation (EU) 2024/1689 of the European Parliament and of the Council.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class EUAIActRiskCategory(str, Enum):
    UNACCEPTABLE = "UNACCEPTABLE"
    HIGH_RISK = "HIGH_RISK"
    LIMITED_RISK = "LIMITED_RISK"
    MINIMAL_RISK = "MINIMAL_RISK"


@dataclass
class EUAIActArticleRef:
    article: str
    title: str
    relevant_clauses: List[str] = field(default_factory=list)


@dataclass
class EUAIActControlMapping:
    aiaf_control_id: str
    risk_category: EUAIActRiskCategory
    article_refs: List[EUAIActArticleRef] = field(default_factory=list)
    obligation: str = ""
    notes: str = ""


EU_AI_ACT_CONTROL_MAPPINGS: List[EUAIActControlMapping] = [
    EUAIActControlMapping(
        aiaf_control_id="AIAF-GOV-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 9", "Risk management system", ["9.1", "9.2", "9.3", "9.4"])],
        obligation=(
            "High-risk AI systems must implement a continuous risk management system covering "
            "identification and analysis of known and reasonably foreseeable risks."
        ),
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-GOV-02",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 13", "Transparency and provision of information to deployers", ["13.1", "13.2", "13.3"])],
        obligation="High-risk AI systems must be sufficiently transparent to enable deployers to interpret outputs and use them appropriately.",
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-REG-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 12", "Record-keeping", ["12.1", "12.2"])],
        obligation="High-risk AI systems must enable automatic logging of events throughout their operational lifetime.",
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-SUPPLY-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 11", "Technical documentation", ["11.1", "Annex IV"])],
        obligation=(
            "Technical documentation including training data governance, provenance, and supply-chain "
            "information must be drawn up before placing a high-risk AI system on the market."
        ),
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-MONITOR-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 72", "Post-market monitoring by providers", ["72.1", "72.2", "72.3"])],
        obligation="Providers must proactively collect and review post-market monitoring data on the performance of high-risk AI systems.",
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-HUMAN-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 14", "Human oversight", ["14.1", "14.2", "14.3", "14.4", "14.5"])],
        obligation="High-risk AI systems must allow effective human oversight by natural persons during deployment.",
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-BIAS-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 10", "Data and data governance", ["10.2", "10.3", "10.4", "10.5"])],
        obligation=(
            "Training, validation, and testing datasets must be subject to data governance; "
            "bias must be examined and, where possible, addressed."
        ),
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-ACC-01",
        risk_category=EUAIActRiskCategory.HIGH_RISK,
        article_refs=[EUAIActArticleRef("Article 15", "Accuracy, robustness and cybersecurity", ["15.1", "15.3"])],
        obligation="High-risk AI systems must achieve appropriate levels of accuracy, robustness, and cybersecurity throughout their lifecycle.",
    ),
    EUAIActControlMapping(
        aiaf_control_id="AIAF-CONF-01",
        risk_category=EUAIActRiskCategory.LIMITED_RISK,
        article_refs=[EUAIActArticleRef("Article 50", "Transparency obligations for certain AI systems", ["50.1", "50.2"])],
        obligation="AI systems interacting with natural persons (e.g., chatbots) must disclose their AI nature.",
    ),
]

PROHIBITED_USE_CASES = frozenset({
    "subliminal_manipulation",
    "exploitation_of_vulnerabilities",
    "social_scoring_by_public_authorities",
    "real_time_remote_biometric_identification_law_enforcement",
    "emotion_recognition_workplace_educational",
    "biometric_categorisation_sensitive_attributes",
})

HIGH_RISK_USE_CASES = frozenset({
    "biometric_identification",
    "critical_infrastructure_management",
    "education_assessment",
    "employment_recruitment",
    "essential_private_public_services",
    "law_enforcement",
    "migration_asylum_border",
    "justice_democratic_processes",
    "safety_components",
})


def classify_eu_ai_act_risk(use_case: str, domain: str = "") -> EUAIActRiskCategory:
    """Return the EU AI Act risk category for a given use case."""
    normalized = (use_case + " " + domain).lower().replace(" ", "_").replace("-", "_")
    for uc in PROHIBITED_USE_CASES:
        if uc in normalized:
            return EUAIActRiskCategory.UNACCEPTABLE
    for uc in HIGH_RISK_USE_CASES:
        if uc in normalized:
            return EUAIActRiskCategory.HIGH_RISK
    return EUAIActRiskCategory.LIMITED_RISK


def get_obligations_for_control(aiaf_control_id: str) -> List[EUAIActControlMapping]:
    """Return all EU AI Act obligation mappings for a given AIAF control ID."""
    return [m for m in EU_AI_ACT_CONTROL_MAPPINGS if m.aiaf_control_id == aiaf_control_id]


def get_high_risk_obligations() -> List[EUAIActControlMapping]:
    return [m for m in EU_AI_ACT_CONTROL_MAPPINGS if m.risk_category == EUAIActRiskCategory.HIGH_RISK]

"""Risk analysis API schemas."""
from typing import Any

from pydantic import BaseModel, Field


class RiskAnalysisRequest(BaseModel):
    artifact_id: str | None = None
    model_risk_profile: dict[str, Any] | None = None
    prompt_samples: list[str] | None = None
    agent_config: dict[str, Any] | None = None
    supply_chain_context: dict[str, Any] | None = None
    include_bias_assessment: bool = False
    include_hallucination_assessment: bool = False


class RiskFinding(BaseModel):
    id: str
    type: str
    severity: str
    score: float
    description: str
    recommendations: list[str] = Field(default_factory=list)
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)


class UncertaintyAwareRiskDetail(BaseModel):
    """Shared shape of the v2 model- and agent-risk scorers.

    Findings are emitted only at MEDIUM severity or higher (agent risk also
    requires ``applicable``); below that the assessment is retained as a trend
    metric. ``risk_score`` is the conservative upper confidence bound.
    """

    assessment_version: str = "2.0"
    scoring_version: str = "2.0"
    severity: str
    risk_score: float
    inherent_risk_score: float | None = None
    residual_risk_score: float | None = None
    lower_confidence_bound: float | None = None
    upper_confidence_bound: float | None = None
    confidence: float | None = None
    assessment_complete: bool | None = None
    applicable: bool | None = None
    score_gates: list[dict[str, Any]] = Field(default_factory=list)


class RiskAnalysisResponse(BaseModel):
    artifact_id: str | None = None
    aggregate_score: float
    posture: str
    findings: list[RiskFinding] = Field(default_factory=list)
    analysis_version: str = "2"
    timestamp: str | None = None

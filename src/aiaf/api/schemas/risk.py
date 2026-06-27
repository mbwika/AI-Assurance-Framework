"""Risk analysis API schemas."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskAnalysisRequest(BaseModel):
    artifact_id: Optional[str] = None
    model_risk_profile: Optional[Dict[str, Any]] = None
    prompt_samples: Optional[List[str]] = None
    agent_config: Optional[Dict[str, Any]] = None
    supply_chain_context: Optional[Dict[str, Any]] = None
    include_bias_assessment: bool = False
    include_hallucination_assessment: bool = False


class RiskFinding(BaseModel):
    id: str
    type: str
    severity: str
    score: float
    description: str
    recommendations: List[str] = Field(default_factory=list)
    framework_refs: Dict[str, List[str]] = Field(default_factory=dict)


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
    inherent_risk_score: Optional[float] = None
    residual_risk_score: Optional[float] = None
    lower_confidence_bound: Optional[float] = None
    upper_confidence_bound: Optional[float] = None
    confidence: Optional[float] = None
    assessment_complete: Optional[bool] = None
    applicable: Optional[bool] = None
    score_gates: List[Dict[str, Any]] = Field(default_factory=list)


class RiskAnalysisResponse(BaseModel):
    artifact_id: Optional[str] = None
    aggregate_score: float
    posture: str
    findings: List[RiskFinding] = Field(default_factory=list)
    analysis_version: str = "2"
    timestamp: Optional[str] = None

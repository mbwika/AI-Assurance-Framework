"""Advanced Assurance API — Phase E.

REST endpoints for:
  POST /v1/advanced/poisoning/assess         — Poisoning / backdoor assessment
  POST /v1/advanced/extraction/assess        — Model extraction risk assessment
  POST /v1/advanced/training-data/assess     — Training-data assurance assessment
  POST /v1/advanced/contamination/check      — Benchmark contamination check
  POST /v1/advanced/adversary/simulate       — Adversary capability simulation
  POST /v1/advanced/confidence/score         — Formal risk confidence scoring
  GET  /v1/advanced/{model_id}/summary       — Per-model Phase-E summary
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .models import get_api_key, get_store
from ..analysis.poisoning_tests import PoisoningTestError, assess_poisoning_risk
from ..analysis.extraction_tests import ExtractionTestError, assess_extraction_risk
from ..analysis.training_data_assurance import assess_training_data_assurance
from ..analysis.benchmark_contamination import ContaminationError, check_contamination
from ..analysis.adversary_simulation import (
    SimulationError, simulate_adversary, THREAT_PROFILES,
)
from ..core.risk_confidence import RiskConfidenceError, compute_risk_confidence

router = APIRouter(prefix="/v1/advanced", tags=["advanced-assurance"])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_record(model_id: str, store: Any) -> Dict[str, Any]:
    """Retrieve model record from store; return stub if not found."""
    try:
        record = store.get_model(model_id)
    except Exception:
        record = None
    return record or {"model_id": model_id, "metadata": {}}


# ── Pydantic request models ────────────────────────────────────────────────────

class BehavioralResponse(BaseModel):
    input: str = ""
    output: str = ""
    control_output: Optional[str] = None


class PoisoningAssessRequest(BaseModel):
    model_id: str
    behavioral_responses: Optional[List[BehavioralResponse]] = None


class ExtractionAssessRequest(BaseModel):
    model_id: str
    sample_outputs: Optional[List[str]] = None
    candidate_records: Optional[List[str]] = None


class BenchmarkScoreEntry(BaseModel):
    benchmark_name: str
    score: float
    population_mean: Optional[float] = None
    population_std: Optional[float] = None
    benchmark_release_date: Optional[str] = None
    verified_score: Optional[float] = None


class ContaminationCheckRequest(BaseModel):
    model_id: str
    benchmark_scores: List[BenchmarkScoreEntry]


class DeploymentContext(BaseModel):
    internet_facing: bool = False
    has_guardrails: bool = False
    has_output_filtering: bool = False
    has_rate_limiting: bool = False
    handles_pii: bool = False
    model_trust_level: str = "INTERNAL"


class AdversarySimulateRequest(BaseModel):
    model_id: str
    threat_profile: str
    deployment_context: Optional[DeploymentContext] = None


class EvidenceItem(BaseModel):
    name: str
    value: float = Field(..., ge=0.0, le=10.0)
    weight: float = Field(..., gt=0.0)
    origin: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class ConfidenceScoreRequest(BaseModel):
    evidence_items: List[EvidenceItem]


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/poisoning/assess")
def assess_poisoning(
    req: PoisoningAssessRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Assess poisoning and backdoor risk for a registered model."""
    record = _get_record(req.model_id, store)
    responses = (
        [r.model_dump() for r in req.behavioral_responses]
        if req.behavioral_responses
        else None
    )
    try:
        return assess_poisoning_risk(record, store, behavioral_responses=responses)
    except PoisoningTestError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/extraction/assess")
def assess_extraction(
    req: ExtractionAssessRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Assess model extraction and membership-inference vulnerability."""
    record = _get_record(req.model_id, store)
    try:
        return assess_extraction_risk(
            record,
            store,
            sample_outputs=req.sample_outputs,
            candidate_records=req.candidate_records,
        )
    except ExtractionTestError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/training-data/assess")
def assess_training_data(
    req: ExtractionAssessRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Assess training-data lineage and governance assurance."""
    record = _get_record(req.model_id, store)
    return assess_training_data_assurance(record, store)


@router.post("/contamination/check")
def check_benchmark_contamination(
    req: ContaminationCheckRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Check benchmark scores for training-data contamination indicators."""
    record = _get_record(req.model_id, store)
    scores = [s.model_dump() for s in req.benchmark_scores]
    try:
        return check_contamination(record, scores, store)
    except ContaminationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/adversary/simulate")
def adversary_simulate(
    req: AdversarySimulateRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Simulate a threat actor's capability against a deployed model."""
    if req.threat_profile.upper() not in THREAT_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown threat_profile '{req.threat_profile}'. "
                   f"Valid: {sorted(THREAT_PROFILES)}",
        )
    record = _get_record(req.model_id, store)
    ctx = req.deployment_context.model_dump() if req.deployment_context else {}
    try:
        return simulate_adversary(record, req.threat_profile, store, deployment_context=ctx)
    except SimulationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/confidence/score")
def confidence_score(
    req: ConfidenceScoreRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Compute a formally justified, origin-weighted risk confidence score."""
    items = [i.model_dump() for i in req.evidence_items]
    try:
        return compute_risk_confidence(items, store=store)
    except RiskConfidenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{model_id}/summary")
def advanced_summary(
    model_id: str,
    threat_profile: str = "MOTIVATED_ATTACKER",
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
) -> Dict[str, Any]:
    """Return a combined Phase-E advanced assurance summary for a model.

    Runs poisoning assessment, extraction risk, training-data assurance, and adversary simulation
    (no benchmark contamination — that requires caller-supplied scores).
    """
    record = _get_record(model_id, store)

    if threat_profile.upper() not in THREAT_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown threat_profile '{threat_profile}'.",
        )

    poisoning = assess_poisoning_risk(record, store)
    extraction = assess_extraction_risk(record, store)
    training_data = assess_training_data_assurance(record, store)
    adversary = simulate_adversary(record, threat_profile.upper(), store)

    return {
        "model_id": model_id,
        "threat_profile_simulated": threat_profile.upper(),
        "poisoning": poisoning,
        "extraction": extraction,
        "training_data_assurance": training_data,
        "adversary_simulation": adversary,
    }

"""Frontier / Dangerous-Capability Evaluation API.

REST endpoints:
  POST /v1/frontier/assess           — assess dangerous capabilities from findings
  POST /v1/frontier/assess/gpai      — map assessment to GPAI CoP commitments
  GET  /v1/frontier/taxonomy         — capability taxonomy + GPAI commitment index
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .models import get_api_key
from ..analysis.frontier_eval import (
    FRONTIER_EVAL_VERSION,
    CAPABILITY_CATEGORIES,
    EVIDENCE_STRENGTHS,
    FrontierEvalError,
    assess_frontier_capabilities,
    map_to_gpai_commitments,
    get_capability_taxonomy,
)

router = APIRouter(prefix="/v1/frontier", tags=["frontier-eval"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CapabilityFindingItem(BaseModel):
    capability: str = Field(..., description="One of the CAPABILITY_CATEGORIES constants")
    evidence_strength: str = Field(..., description="One of the EVIDENCE_* constants")
    evidence_origin: str = "LOCALLY_OBSERVED"
    safeguard_present: bool = False
    method: Optional[str] = None
    description: Optional[str] = None
    mitigation: Optional[str] = None


class FrontierAssessRequest(BaseModel):
    model_id: str
    capability_findings: List[CapabilityFindingItem] = Field(default_factory=list)
    training_flops: Optional[float] = Field(None, ge=0)
    parameter_count: Optional[float] = Field(None, ge=0)
    context: Optional[str] = None


class GPAIMappingRequest(BaseModel):
    capability_assessment: Dict[str, Any]


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/assess")
def assess_capabilities(
    req: FrontierAssessRequest,
    _: str = Depends(get_api_key),
):
    findings = [f.model_dump() for f in req.capability_findings]
    try:
        return assess_frontier_capabilities(
            req.model_id, findings,
            training_flops=req.training_flops,
            parameter_count=req.parameter_count,
            context=req.context,
        )
    except FrontierEvalError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/assess/gpai")
def map_gpai(
    req: FrontierAssessRequest,
    _: str = Depends(get_api_key),
):
    findings = [f.model_dump() for f in req.capability_findings]
    try:
        assessment = assess_frontier_capabilities(
            req.model_id, findings,
            training_flops=req.training_flops,
            parameter_count=req.parameter_count,
            context=req.context,
        )
        return map_to_gpai_commitments(assessment)
    except FrontierEvalError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/taxonomy")
def capability_taxonomy(_: str = Depends(get_api_key)):
    return get_capability_taxonomy()

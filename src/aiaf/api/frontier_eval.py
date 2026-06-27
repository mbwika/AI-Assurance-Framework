"""Frontier / Dangerous-Capability Evaluation API.

REST endpoints:
  POST /v1/frontier/assess           — assess dangerous capabilities from findings
  POST /v1/frontier/assess/gpai      — map assessment to GPAI CoP commitments
  GET  /v1/frontier/taxonomy         — capability taxonomy + GPAI commitment index
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis.frontier_eval import (
    FrontierEvalError,
    assess_frontier_capabilities,
    get_capability_taxonomy,
    map_to_gpai_commitments,
)
from .models import get_api_key

router = APIRouter(prefix="/v1/frontier", tags=["frontier-eval"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CapabilityFindingItem(BaseModel):
    capability: str = Field(..., description="One of the CAPABILITY_CATEGORIES constants")
    evidence_strength: str = Field(..., description="One of the EVIDENCE_* constants")
    evidence_origin: str = "LOCALLY_OBSERVED"
    safeguard_present: bool = False
    method: str | None = None
    description: str | None = None
    mitigation: str | None = None


class FrontierAssessRequest(BaseModel):
    model_id: str
    capability_findings: list[CapabilityFindingItem] = Field(default_factory=list)
    training_flops: float | None = Field(None, ge=0)
    parameter_count: float | None = Field(None, ge=0)
    context: str | None = None


class GPAIMappingRequest(BaseModel):
    capability_assessment: dict[str, Any]


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

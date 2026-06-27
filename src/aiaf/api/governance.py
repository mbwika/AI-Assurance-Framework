"""Governance engine API routes."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core import GovernanceEngine, GovernanceEvidenceEngine
from ..mapping.control_catalog import get_control_catalog
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/governance", tags=["governance"])


class EvidenceSubmission(BaseModel):
    artifact_id: str = Field(min_length=1, max_length=255)
    control_id: str = Field(min_length=1, max_length=64)
    evidence_fields: list[str] = Field(min_length=1, max_length=50)
    evidence_type: str
    reference: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(min_length=64, max_length=64)
    submitted_by: str = Field(min_length=1, max_length=255)
    expires_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceReview(BaseModel):
    decision: str
    reviewer: str = Field(min_length=1, max_length=255)
    rationale: str = Field(min_length=1, max_length=4000)


@router.get("/controls")
def governance_controls(api_key: str = Depends(get_api_key)):
    return {"controls": get_control_catalog()}


@router.post("/evaluate")
def evaluate_governance(artifact: dict[str, Any], api_key: str = Depends(get_api_key)):
    store = get_store()
    engine = GovernanceEngine(datastore=store)
    return engine.evaluate(artifact)


@router.post("/evidence")
def submit_control_evidence(
    request: EvidenceSubmission, api_key: str = Depends(get_api_key)
):
    try:
        return GovernanceEvidenceEngine(get_store()).submit(
            artifact_id=request.artifact_id,
            control_id=request.control_id,
            evidence_fields=request.evidence_fields,
            evidence_type=request.evidence_type,
            reference=request.reference,
            sha256=request.sha256,
            submitted_by=request.submitted_by,
            expires_at=request.expires_at,
            metadata=request.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/evidence")
def list_control_evidence(
    limit: int = 1000,
    artifact_id: str | None = None,
    control_id: str | None = None,
    status: str | None = None,
    api_key: str = Depends(get_api_key),
):
    engine = GovernanceEvidenceEngine(get_store())
    try:
        evidence = engine.list(
            limit=limit,
            artifact_id=artifact_id,
            control_id=control_id,
            status=status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"evidence": evidence, "count": len(evidence), "summary": engine.summary()}


@router.get("/evidence/{evidence_id}")
def get_control_evidence(
    evidence_id: str, api_key: str = Depends(get_api_key)
):
    evidence = GovernanceEvidenceEngine(get_store()).get(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Control evidence not found")
    return evidence


@router.post("/evidence/{evidence_id}/review")
def review_control_evidence(
    evidence_id: str,
    request: EvidenceReview,
    api_key: str = Depends(get_api_key),
):
    try:
        evidence = GovernanceEvidenceEngine(get_store()).review(
            evidence_id,
            decision=request.decision,
            reviewer=request.reviewer,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not evidence:
        raise HTTPException(status_code=404, detail="Control evidence not found")
    return evidence

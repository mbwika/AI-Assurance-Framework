"""Operational risk register APIs."""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core import RiskRegisterEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/risks", tags=["risk register"])


class RiskUpdate(BaseModel):
    status: str | None = None
    owner: str | None = Field(default=None, max_length=255)
    due_at: str | None = None
    resolution: str | None = Field(default=None, max_length=4000)


@router.get("")
def list_risks(
    limit: int = 100,
    status: str | None = None,
    artifact_id: str | None = None,
    severity: str | None = None,
    api_key: str = Depends(get_api_key),
):
    engine = RiskRegisterEngine(get_store())
    try:
        risks = engine.list(
            limit=limit,
            status=status,
            artifact_id=artifact_id,
            severity=severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"risks": risks, "count": len(risks), "summary": engine.summary()}


@router.get("/{risk_id}")
def get_risk(risk_id: str, api_key: str = Depends(get_api_key)):
    risk = RiskRegisterEngine(get_store()).get(risk_id)
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk


@router.patch("/{risk_id}")
def update_risk(
    risk_id: str,
    request: RiskUpdate,
    api_key: str = Depends(get_api_key),
):
    changes = (
        request.model_dump(exclude_unset=True)
        if hasattr(request, "model_dump")
        else request.dict(exclude_unset=True)
    )
    try:
        risk = RiskRegisterEngine(get_store()).update(risk_id, changes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk

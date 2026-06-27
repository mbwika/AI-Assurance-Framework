"""AI Resource Abuse / Cost-Risk Monitoring API.

REST endpoints:
  POST /v1/resources/budgets                       — create resource budget
  GET  /v1/resources/budgets/{id}                  — get budget
  POST /v1/resources/budgets/{id}/usage            — record resource usage event
  GET  /v1/resources/budgets/{id}/session          — get current session state
  GET  /v1/resources/budgets/{id}/violations       — list violations for session
  GET  /v1/resources/sessions/at-risk              — list all at-risk sessions
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis.resource_monitor import (
    RESOURCE_TYPES,
    ResourceMonitorError,
    check_budget_violations,
    create_budget,
    get_budget,
    get_session_state,
    list_at_risk_sessions,
    record_usage,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/resources", tags=["resource-monitoring"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CreateBudgetRequest(BaseModel):
    budget_id: str
    model_id: str
    budget: dict[str, float] | None = None


class RecordUsageRequest(BaseModel):
    resource_type: str = Field(..., description=f"One of: {', '.join(sorted(RESOURCE_TYPES))}")
    value: float
    metadata: dict[str, Any] | None = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/budgets", status_code=201)
def create_resource_budget(
    req: CreateBudgetRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return create_budget(req.budget_id, req.model_id, store, budget=req.budget)


@router.get("/budgets/{budget_id}")
def get_resource_budget(
    budget_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    budget = get_budget(budget_id, store)
    if not budget:
        raise HTTPException(status_code=404, detail=f"Budget {budget_id!r} not found.")
    return budget


@router.post("/budgets/{budget_id}/usage")
def record_resource_usage(
    budget_id: str,
    req: RecordUsageRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return record_usage(budget_id, req.resource_type, req.value, store,
                            metadata=req.metadata)
    except ResourceMonitorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/budgets/{budget_id}/session")
def get_resource_session(
    budget_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    state = get_session_state(budget_id, store)
    if not state:
        raise HTTPException(status_code=404, detail=f"Session for budget {budget_id!r} not found.")
    return state


@router.get("/budgets/{budget_id}/violations")
def get_budget_violations(
    budget_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return check_budget_violations(budget_id, store)
    except ResourceMonitorError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/sessions/at-risk")
def list_at_risk_resource_sessions(
    risk_type: str | None = None,
    limit: int = 50,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_at_risk_sessions(store, risk_type=risk_type, limit=limit)

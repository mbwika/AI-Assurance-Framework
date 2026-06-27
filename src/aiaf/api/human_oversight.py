"""Human Oversight Monitor API — ASI09 Human-Agent Trust Exploitation.

REST endpoints:
  POST /v1/oversight/sessions                          — create session
  POST /v1/oversight/sessions/{id}/output              — record agent output turn
  POST /v1/oversight/sessions/{id}/tool-call           — record tool call
  GET  /v1/oversight/sessions/{id}/assess              — assess session risk
  POST /v1/oversight/sessions/{id}/close               — close session
  GET  /v1/oversight/at-risk                           — list elevated/high/critical sessions
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .models import get_api_key, get_store
from ..analysis.human_oversight_monitor import (
    HUMAN_OVERSIGHT_VERSION,
    HumanOversightError,
    RISK_ELEVATED,
    RISK_HIGH,
    RISK_CRITICAL,
    SIGNAL_TYPES,
    SESSION_ACTIVE,
    SESSION_CLOSED,
    create_oversight_session,
    get_oversight_session,
    record_agent_output,
    record_tool_call,
    assess_session,
    close_session,
    list_at_risk_sessions,
)

router = APIRouter(prefix="/v1/oversight", tags=["human-oversight"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CreateSessionRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    agent_id: str = Field(..., min_length=1, max_length=256)
    principal_id: Optional[str] = None
    known_principals: Optional[List[str]] = None
    context: Optional[str] = None


class RecordOutputRequest(BaseModel):
    text: str = Field(..., min_length=1)
    turn_id: Optional[str] = None
    occurred_at: Optional[str] = None


class RecordToolCallRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256)
    tool_params: Dict[str, Any] = Field(default_factory=dict)
    turn_id: Optional[str] = None
    described_intent: Optional[str] = None
    occurred_at: Optional[str] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/sessions", status_code=201)
def create_session(
    req: CreateSessionRequest,
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    try:
        return create_oversight_session(
            req.session_id,
            req.agent_id,
            store,
            principal_id=req.principal_id,
            known_principals=req.known_principals,
            context=req.context,
        )
    except HumanOversightError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/sessions/{session_id}/output")
def record_output(
    session_id: str,
    req: RecordOutputRequest,
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    try:
        return record_agent_output(
            session_id,
            req.text,
            store,
            turn_id=req.turn_id,
            occurred_at=req.occurred_at,
        )
    except HumanOversightError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/sessions/{session_id}/tool-call")
def record_tool(
    session_id: str,
    req: RecordToolCallRequest,
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    try:
        return record_tool_call(
            session_id,
            req.tool_name,
            req.tool_params,
            store,
            turn_id=req.turn_id,
            described_intent=req.described_intent,
            occurred_at=req.occurred_at,
        )
    except HumanOversightError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/sessions/{session_id}/assess")
def assess(
    session_id: str,
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    try:
        return assess_session(session_id, store)
    except HumanOversightError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/sessions/{session_id}/close")
def close(
    session_id: str,
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    try:
        return close_session(session_id, store)
    except HumanOversightError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/at-risk")
def at_risk(
    min_risk: str = Query(RISK_ELEVATED, description="Minimum risk level to include"),
    limit: int = Query(50, ge=1, le=500),
    _: str = Depends(get_api_key),
    store=Depends(get_store),
):
    if min_risk not in {RISK_ELEVATED, RISK_HIGH, RISK_CRITICAL}:
        raise HTTPException(
            status_code=422,
            detail=f"min_risk must be one of {RISK_ELEVATED!r}, {RISK_HIGH!r}, {RISK_CRITICAL!r}",
        )
    sessions = list_at_risk_sessions(store, min_risk=min_risk, limit=limit)
    return {
        "sessions": sessions,
        "count": len(sessions),
        "min_risk": min_risk,
        "human_oversight_version": HUMAN_OVERSIGHT_VERSION,
    }

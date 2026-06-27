"""Agentic AI assurance API routes."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis import get_agent_policy_profiles
from ..core import AgenticAssuranceEngine, AgentRuntimeEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/agentic", tags=["agentic assurance"])


class AgentSessionCreate(BaseModel):
    artifact: Dict[str, Any]


class ToolAuthorizationRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=255)
    tool: str = Field(min_length=1, max_length=255)
    action: Optional[str] = Field(default=None, max_length=255)
    permissions: List[str] = Field(default_factory=list, max_length=100)
    workflow_step_id: Optional[str] = Field(default=None, max_length=255)
    input_source: Optional[str] = Field(default=None, max_length=255)
    input_validation: Optional[str] = Field(default=None, max_length=1000)
    target: Optional[str] = Field(default=None, max_length=2048)
    approval_id: Optional[str] = Field(default=None, max_length=255)
    approved_by: Optional[str] = Field(default=None, max_length=255)


class AgentSessionStatusUpdate(BaseModel):
    status: str


@router.get("/policy-profiles")
def policy_profiles(api_key: str = Depends(get_api_key)):
    profiles = get_agent_policy_profiles()
    return {"profiles": profiles, "count": len(profiles)}


@router.post("/validate")
def validate_agentic_artifact(
    artifact: Dict[str, Any], api_key: str = Depends(get_api_key)
):
    return AgenticAssuranceEngine(datastore=get_store()).evaluate(artifact)


@router.post("/sessions")
def create_agent_session(
    request: AgentSessionCreate, api_key: str = Depends(get_api_key)
):
    try:
        return AgentRuntimeEngine(get_store()).create_session(request.artifact)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/sessions")
def list_agent_sessions(
    limit: int = 100,
    artifact_id: Optional[str] = None,
    status: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    try:
        sessions = AgentRuntimeEngine(get_store()).list_sessions(
            limit=limit, artifact_id=artifact_id, status=status
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"sessions": sessions, "count": len(sessions)}


@router.post("/sessions/{session_id}/authorize")
def authorize_tool_invocation(
    session_id: str,
    request: ToolAuthorizationRequest,
    api_key: str = Depends(get_api_key),
):
    try:
        return AgentRuntimeEngine(get_store()).authorize(
            session_id,
            request_id=request.request_id,
            tool=request.tool,
            action=request.action,
            permissions=request.permissions,
            workflow_step_id=request.workflow_step_id,
            input_source=request.input_source,
            input_validation=request.input_validation,
            target=request.target,
            approval_id=request.approval_id,
            approved_by=request.approved_by,
        )
    except ValueError as exc:
        status_code = 404 if str(exc) == "Agent session not found" else 422
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/invocations")
def list_tool_invocations(
    limit: int = 100,
    session_id: Optional[str] = None,
    decision: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    try:
        invocations = AgentRuntimeEngine(get_store()).list_invocations(
            limit=limit, session_id=session_id, decision=decision
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"invocations": invocations, "count": len(invocations)}


@router.patch("/sessions/{session_id}")
def update_agent_session_status(
    session_id: str,
    request: AgentSessionStatusUpdate,
    api_key: str = Depends(get_api_key),
):
    try:
        session = AgentRuntimeEngine(get_store()).update_session_status(
            session_id, request.status
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not session:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return session

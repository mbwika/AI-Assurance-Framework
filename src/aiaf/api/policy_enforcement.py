"""Runtime Policy Enforcement Point (PEP) API.

REST endpoints:
  POST   /v1/pep/policies            — create enforcement policy
  GET    /v1/pep/policies            — list policies
  GET    /v1/pep/policies/{id}       — get policy
  DELETE /v1/pep/policies/{id}       — delete policy
  POST   /v1/pep/enforce             — evaluate a request
  GET    /v1/pep/policies/{id}/log   — get enforcement log for policy
  GET    /v1/pep/modes               — list enforcement modes
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.policy_enforcement import (
    ENFORCEMENT_MODES,
    VERDICTS,
    PolicyEnforcementError,
    create_pep_policy,
    delete_pep_policy,
    enforce_request,
    get_enforcement_log,
    get_pep_policy,
    list_pep_policies,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/pep", tags=["policy-enforcement"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CreatePolicyRequest(BaseModel):
    policy_id: str
    principal_id: str
    mode: str = "ENFORCE"
    allowed_actions: list[str] | None = None
    denied_actions: list[str] | None = None
    allowed_resources: list[str] | None = None
    denied_resources: list[str] | None = None
    conditions: list[str] | None = None
    max_requests_per_min: float = Field(0, ge=0)
    description: str | None = None


class EnforceRequest(BaseModel):
    principal_id: str
    action: str
    resource: str
    context: dict[str, Any] | None = None
    policy_id: str | None = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/policies", status_code=201)
def create_policy_route(
    req: CreatePolicyRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return create_pep_policy(
            req.policy_id, req.principal_id, store,
            mode=req.mode,
            allowed_actions=req.allowed_actions,
            denied_actions=req.denied_actions,
            allowed_resources=req.allowed_resources,
            denied_resources=req.denied_resources,
            conditions=req.conditions,
            max_requests_per_min=req.max_requests_per_min,
            description=req.description,
        )
    except PolicyEnforcementError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/policies")
def list_policies_route(
    principal_id: str | None = None,
    mode: str | None = None,
    limit: int = 200,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_pep_policies(store, principal_id=principal_id, mode=mode, limit=limit)


@router.get("/policies/{policy_id}")
def get_policy_route(
    policy_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    policy = get_pep_policy(policy_id, store)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found.")
    return policy


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy_route(
    policy_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    if not delete_pep_policy(policy_id, store):
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found.")


@router.post("/enforce")
def enforce_route(
    req: EnforceRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return enforce_request(
            req.principal_id, req.action, req.resource, store,
            context=req.context,
            policy_id=req.policy_id,
        )
    except PolicyEnforcementError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/policies/{policy_id}/log")
def get_log_route(
    policy_id: str,
    verdict: str | None = None,
    limit: int = 100,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return get_enforcement_log(policy_id, store, verdict=verdict, limit=limit)


@router.get("/modes")
def get_modes(_: str = Depends(get_api_key)):
    return {
        "enforcement_modes": sorted(ENFORCEMENT_MODES),
        "verdicts": sorted(VERDICTS),
    }

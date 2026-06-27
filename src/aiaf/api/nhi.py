"""Non-Human Identity (NHI) Lifecycle Governance API.

REST endpoints:
  POST  /v1/nhi                      — register NHI
  GET   /v1/nhi                      — list NHIs
  GET   /v1/nhi/{id}                 — get NHI
  PATCH /v1/nhi/{id}                 — update NHI fields
  POST  /v1/nhi/{id}/state           — transition lifecycle state
  GET   /v1/nhi/hygiene/report       — organisation-wide hygiene report
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .models import get_api_key, get_store
from ..registry.nhi_registry import (
    NHI_TYPES, NHI_STATES,
    DEFAULT_STALE_DAYS, DEFAULT_CREDENTIAL_AGE_DAYS,
    NHIError,
    register_nhi, get_nhi, list_nhis,
    update_nhi_state, update_nhi,
    assess_nhi_hygiene,
)

router = APIRouter(prefix="/v1/nhi", tags=["nhi"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterNHIRequest(BaseModel):
    nhi_id: str
    nhi_type: str
    display_name: Optional[str] = None
    owner_id: Optional[str] = None
    environment: Optional[str] = None
    granted_scopes: Optional[List[str]] = None
    minimum_required_scopes: Optional[List[str]] = None
    credential_issued_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    is_active_in_environment: bool = False
    attributes: Optional[Dict[str, Any]] = None


class UpdateNHIRequest(BaseModel):
    granted_scopes: Optional[List[str]] = None
    minimum_required_scopes: Optional[List[str]] = None
    credential_issued_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    owner_id: Optional[str] = None
    is_active_in_environment: Optional[bool] = None
    attributes: Optional[Dict[str, Any]] = None


class TransitionStateRequest(BaseModel):
    new_state: str
    reason: Optional[str] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
def register_nhi_route(
    req: RegisterNHIRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return register_nhi(
            req.nhi_id, req.nhi_type, store,
            display_name=req.display_name,
            owner_id=req.owner_id,
            environment=req.environment,
            granted_scopes=req.granted_scopes,
            minimum_required_scopes=req.minimum_required_scopes,
            credential_issued_at=req.credential_issued_at,
            last_seen_at=req.last_seen_at,
            is_active_in_environment=req.is_active_in_environment,
            attributes=req.attributes,
        )
    except NHIError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("")
def list_nhis_route(
    nhi_type: Optional[str] = None,
    state: Optional[str] = None,
    owner_id: Optional[str] = None,
    limit: int = 200,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_nhis(store, nhi_type=nhi_type, state=state, owner_id=owner_id, limit=limit)


@router.get("/hygiene/report")
def hygiene_report_route(
    stale_days: int = DEFAULT_STALE_DAYS,
    credential_age_days: int = DEFAULT_CREDENTIAL_AGE_DAYS,
    include_revoked: bool = False,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return assess_nhi_hygiene(
        store,
        stale_days=stale_days,
        credential_age_days=credential_age_days,
        include_revoked=include_revoked,
    )


@router.get("/{nhi_id}")
def get_nhi_route(
    nhi_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    nhi = get_nhi(nhi_id, store)
    if not nhi:
        raise HTTPException(status_code=404, detail=f"NHI {nhi_id!r} not found.")
    return nhi


@router.patch("/{nhi_id}")
def update_nhi_route(
    nhi_id: str,
    req: UpdateNHIRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return update_nhi(
            nhi_id, store,
            granted_scopes=req.granted_scopes,
            minimum_required_scopes=req.minimum_required_scopes,
            credential_issued_at=req.credential_issued_at,
            last_seen_at=req.last_seen_at,
            owner_id=req.owner_id,
            is_active_in_environment=req.is_active_in_environment,
            attributes=req.attributes,
        )
    except NHIError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{nhi_id}/state")
def transition_state_route(
    nhi_id: str,
    req: TransitionStateRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return update_nhi_state(nhi_id, req.new_state, store, reason=req.reason)
    except NHIError as exc:
        # 409 for terminal-state conflicts, 404 for missing, 422 for invalid
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=404, detail=str(exc))
        if "terminal" in str(exc).lower() or "invalid transition" in str(exc).lower():
            raise HTTPException(status_code=409, detail=str(exc))
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/meta/types")
def get_nhi_types(_: str = Depends(get_api_key)):
    return {"nhi_types": sorted(NHI_TYPES), "nhi_states": sorted(NHI_STATES)}

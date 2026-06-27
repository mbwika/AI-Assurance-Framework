"""Identity and Delegation Registry API.

REST endpoints:
  POST /v1/identity/principals                      — register principal
  GET  /v1/identity/principals                      — list principals
  GET  /v1/identity/principals/{id}                 — get principal
  PATCH /v1/identity/principals/{id}                — update principal
  POST /v1/identity/delegations                     — grant delegation
  GET  /v1/identity/delegations/{id}                — get delegation
  POST /v1/identity/delegations/{id}/revoke         — revoke delegation
  GET  /v1/identity/delegations                     — list delegations
  POST /v1/identity/verify                          — verify authority
  GET  /v1/identity/principals/{id}/authority-chain — authority chain
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..registry.identity_registry import (
    TRUST_INTERNAL,
    IdentityError,
    get_authority_chain,
    get_delegation,
    get_principal,
    grant_delegation,
    list_delegations,
    list_principals,
    register_principal,
    revoke_delegation,
    update_principal,
    verify_authority,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/identity", tags=["identity"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterPrincipalRequest(BaseModel):
    principal_id: str
    principal_type: str
    name: str
    trust_level: str = TRUST_INTERNAL
    capabilities: list[str] | None = None
    attributes: dict[str, Any] | None = None


class UpdatePrincipalRequest(BaseModel):
    trust_level: str | None = None
    capabilities: list[str] | None = None
    attributes: dict[str, Any] | None = None


class GrantDelegationRequest(BaseModel):
    delegation_id: str
    delegator_id: str
    delegate_id: str
    scope: list[str]
    granted_by: str | None = None
    expires_at: str | None = None


class RevokeDelegationRequest(BaseModel):
    reason: str | None = None


class VerifyAuthorityRequest(BaseModel):
    principal_id: str
    action: str
    resource: str


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/principals", status_code=201)
def register_principal_route(
    req: RegisterPrincipalRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return register_principal(
            req.principal_id, req.principal_type, req.name, store,
            trust_level=req.trust_level,
            capabilities=req.capabilities,
            attributes=req.attributes,
        )
    except IdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/principals")
def list_principals_route(
    principal_type: str | None = None,
    trust_level: str | None = None,
    limit: int = 100,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_principals(store, principal_type=principal_type,
                           trust_level=trust_level, limit=limit)


@router.get("/principals/{principal_id}")
def get_principal_route(
    principal_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    p = get_principal(principal_id, store)
    if not p:
        raise HTTPException(status_code=404, detail=f"Principal {principal_id!r} not found.")
    return p


@router.patch("/principals/{principal_id}")
def update_principal_route(
    principal_id: str,
    req: UpdatePrincipalRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return update_principal(
            principal_id, store,
            trust_level=req.trust_level,
            capabilities=req.capabilities,
            attributes=req.attributes,
        )
    except IdentityError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422,
                            detail=str(exc))


@router.post("/delegations", status_code=201)
def grant_delegation_route(
    req: GrantDelegationRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return grant_delegation(
            req.delegation_id, req.delegator_id, req.delegate_id, req.scope, store,
            granted_by=req.granted_by,
            expires_at=req.expires_at,
        )
    except IdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/delegations/{delegation_id}")
def get_delegation_route(
    delegation_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    d = get_delegation(delegation_id, store)
    if not d:
        raise HTTPException(status_code=404, detail=f"Delegation {delegation_id!r} not found.")
    return d


@router.post("/delegations/{delegation_id}/revoke")
def revoke_delegation_route(
    delegation_id: str,
    req: RevokeDelegationRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return revoke_delegation(delegation_id, store, reason=req.reason)
    except IdentityError as exc:
        raise HTTPException(
            status_code=404 if "not found" in str(exc) else 409,
            detail=str(exc),
        )


@router.get("/delegations")
def list_delegations_route(
    delegator_id: str | None = None,
    delegate_id: str | None = None,
    active_only: bool = True,
    limit: int = 100,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_delegations(
        store,
        delegator_id=delegator_id,
        delegate_id=delegate_id,
        active_only=active_only,
        limit=limit,
    )


@router.post("/verify")
def verify_authority_route(
    req: VerifyAuthorityRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return verify_authority(req.principal_id, req.action, req.resource, store)


@router.get("/principals/{principal_id}/authority-chain")
def get_authority_chain_route(
    principal_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return get_authority_chain(principal_id, store)

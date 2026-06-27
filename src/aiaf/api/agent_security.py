"""Agent Security & Tool Manifest API.

Routes
------
Agent registry
  POST   /v1/agents                              Register an agent
  GET    /v1/agents                              List agents
  GET    /v1/agents/{agent_id}                   Get agent record
  DELETE /v1/agents/{agent_id}                   Deregister agent
  GET    /v1/agents/{agent_id}/permissions       Permission graph analysis
  POST   /v1/agents/{agent_id}/policies          Create/replace authorization policies
  GET    /v1/agents/{agent_id}/policies          Get authorization policies
  DELETE /v1/agents/{agent_id}/policies          Delete authorization policies
  POST   /v1/agents/{agent_id}/authorize         Runtime tool-call authorization

Tool manifests
  POST   /v1/tools/manifests                     Create + register a signed manifest
  GET    /v1/tools/manifests                     List manifests
  GET    /v1/tools/manifests/{tool}/{version}    Get a manifest
  POST   /v1/tools/manifests/{tool}/{version}/verify  Re-verify a manifest
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..analysis.permission_graph import (
    analyse_permissions,
)
from ..core.tool_authorization import (
    VERDICT_DENY,
    AuthorizationError,
    authorize,
    create_policy,
    delete_policy,
    get_policy,
)
from ..registry.agent_registry import (
    CAPABILITY_FLAGS,
    REGISTRY_VERSION,
    STATUS_ACTIVE,
    STATUS_QUARANTINED,
    STATUS_SUSPENDED,
    TRUST_LABELS,
    AgentRegistryError,
    deregister_agent,
    get_agent,
    list_agents,
    register_agent,
    set_agent_status,
    set_tool_block,
)
from ..registry.tool_manifest import (
    MANIFEST_VERSION,
    ManifestError,
    create_manifest,
    get_manifest,
    list_manifests,
    register_manifest,
    verify_manifest,
)
from .models import get_api_key, get_store

agents_router = APIRouter(prefix="/v1/agents", tags=["agent-security"])
tools_router = APIRouter(prefix="/v1/tools", tags=["tool-manifests"])


# ── Request / response models ─────────────────────────────────────────────────

class RegisterAgentRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    name: str = Field(..., description="Human-readable agent name")
    declared_tools: list[str] = Field(
        default_factory=list, description="Tools the agent is authorised to invoke"
    )
    trust_level: str = Field(
        ..., description=f"Trust classification; one of {sorted(TRUST_LABELS)}"
    )
    capability_flags: list[str] = Field(
        default_factory=list,
        description=f"Capability declarations; valid flags: {sorted(CAPABILITY_FLAGS)}",
    )
    purpose: str | None = Field(None, description="Intended function of the agent")
    operational_constraints: dict[str, Any] | None = Field(
        None, description="Operational limits (max_tool_calls_per_session, etc.)"
    )
    manifest_id: str | None = Field(None, description="ID of a linked signed tool manifest")
    metadata: dict[str, Any] | None = None


class ToolPolicyItem(BaseModel):
    tool_name: str
    policy_id: str | None = None
    allow_if: dict[str, Any] | None = Field(None, description="Conditions dict")


class CreatePolicyRequest(BaseModel):
    tool_policies: list[ToolPolicyItem] = Field(..., description="Per-tool policy rules")
    default_policy: str = Field(
        VERDICT_DENY,
        description="Verdict when no rule matches: ALLOW or DENY",
    )
    metadata: dict[str, Any] | None = None


class AuthorizeRequest(BaseModel):
    tool_name: str = Field(..., description="Tool the agent wants to invoke")
    session_context: dict[str, Any] = Field(
        default_factory=dict,
        description="Runtime context (data_sensitivity, user_consent_given, call_count, …)",
    )


class SetStatusRequest(BaseModel):
    reason: str | None = Field(None, description="Why the agent is being re-stated")


class CreateManifestRequest(BaseModel):
    tool_name: str = Field(..., description="Unique tool identifier")
    version: str = Field(..., description="Semantic version string")
    description: str = Field(..., description="What this tool does")
    input_schema: dict[str, Any] = Field(
        default_factory=dict, description="JSON Schema for tool inputs"
    )
    declared_capabilities: list[str] = Field(
        default_factory=list, description="Capability flags this tool grants"
    )
    signing_key_hex: str = Field(
        ..., description="HMAC signing key as a hex string (min 64 hex chars = 32 bytes)"
    )
    allowed_agents: list[str] | None = Field(
        None, description="Agent IDs authorised to use this tool (None = unrestricted)"
    )
    issuer: str | None = Field(None, description="Issuer identifier")
    expires_at: str | None = Field(None, description="ISO-8601 expiry timestamp")


class VerifyManifestRequest(BaseModel):
    signing_key_hex: str = Field(
        ..., description="HMAC signing key as hex string"
    )
    current_schema: dict[str, Any] | None = Field(
        None, description="Current input schema for drift detection"
    )


# ── Agent routes ──────────────────────────────────────────────────────────────

@agents_router.post("", status_code=status.HTTP_201_CREATED)
def register(
    req: RegisterAgentRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Register or update an agent in the AIAF agent registry."""
    try:
        result = register_agent(
            agent_id=req.agent_id,
            name=req.name,
            declared_tools=req.declared_tools,
            trust_level=req.trust_level,
            capability_flags=req.capability_flags,
            store=store,
            purpose=req.purpose,
            operational_constraints=req.operational_constraints,
            manifest_id=req.manifest_id,
            metadata=req.metadata,
        )
    except AgentRegistryError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"registry_version": REGISTRY_VERSION, **result}


@agents_router.get("")
def list_all_agents(
    limit: int = 50,
    trust_level: str | None = None,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """List registered agents."""
    agents = list_agents(store, limit=limit, trust_level=trust_level)
    return {
        "registry_version": REGISTRY_VERSION,
        "count": len(agents),
        "agents": agents,
    }


@agents_router.get("/{agent_id}")
def get_one_agent(
    agent_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Get a single agent's registry record."""
    agent = get_agent(agent_id, store)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return {"registry_version": REGISTRY_VERSION, **agent}


@agents_router.delete("/{agent_id}", status_code=status.HTTP_200_OK)
def deregister(
    agent_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Deregister (soft-delete) an agent."""
    found = deregister_agent(agent_id, store)
    if not found:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return {"agent_id": agent_id, "status": "deregistered"}


@agents_router.post("/{agent_id}/suspend")
def suspend_agent(
    agent_id: str,
    req: SetStatusRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Suspend an agent so all runtime tool calls are denied."""
    try:
        return set_agent_status(agent_id, STATUS_SUSPENDED, store, reason=req.reason)
    except AgentRegistryError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422, detail=str(exc))


@agents_router.post("/{agent_id}/quarantine")
def quarantine_agent(
    agent_id: str,
    req: SetStatusRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Quarantine an agent pending investigation or containment."""
    try:
        return set_agent_status(agent_id, STATUS_QUARANTINED, store, reason=req.reason)
    except AgentRegistryError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422, detail=str(exc))


@agents_router.post("/{agent_id}/resume")
def resume_agent(
    agent_id: str,
    req: SetStatusRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Return a contained agent to active status."""
    try:
        return set_agent_status(agent_id, STATUS_ACTIVE, store, reason=req.reason)
    except AgentRegistryError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422, detail=str(exc))


@agents_router.post("/{agent_id}/tools/{tool_name}/block")
def block_agent_tool(
    agent_id: str,
    tool_name: str,
    req: SetStatusRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Emergency-block one declared tool for an agent."""
    try:
        return set_tool_block(agent_id, tool_name, True, store, reason=req.reason)
    except AgentRegistryError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422, detail=str(exc))


@agents_router.post("/{agent_id}/tools/{tool_name}/unblock")
def unblock_agent_tool(
    agent_id: str,
    tool_name: str,
    req: SetStatusRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Lift a previously applied tool block."""
    try:
        return set_tool_block(agent_id, tool_name, False, store, reason=req.reason)
    except AgentRegistryError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 422, detail=str(exc))


# ── Permission graph ──────────────────────────────────────────────────────────

@agents_router.get("/{agent_id}/permissions")
def permission_analysis(
    agent_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Run permission graph analysis for a registered agent."""
    agent = get_agent(agent_id, store)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    result = analyse_permissions(agent)
    return result


# ── Authorization policies ────────────────────────────────────────────────────

@agents_router.post("/{agent_id}/policies", status_code=status.HTTP_201_CREATED)
def set_policies(
    agent_id: str,
    req: CreatePolicyRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Create or replace authorization policies for an agent."""
    if get_agent(agent_id, store) is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    try:
        tool_policies = [tp.model_dump() for tp in req.tool_policies]
        result = create_policy(
            agent_id=agent_id,
            tool_policies=tool_policies,
            store=store,
            default_policy=req.default_policy,
            metadata=req.metadata,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


@agents_router.get("/{agent_id}/policies")
def get_policies(
    agent_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Get the authorization policies for an agent."""
    policy = get_policy(agent_id, store)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"No policies found for agent '{agent_id}'.")
    return policy


@agents_router.delete("/{agent_id}/policies")
def remove_policies(
    agent_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Delete all authorization policies for an agent."""
    deleted = delete_policy(agent_id, store)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No policies found for agent '{agent_id}'.")
    return {"agent_id": agent_id, "policies_deleted": True}


# ── Runtime authorization ─────────────────────────────────────────────────────

@agents_router.post("/{agent_id}/authorize")
def authorize_tool_call(
    agent_id: str,
    req: AuthorizeRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Evaluate whether an agent may call a tool given the current session context."""
    result = authorize(
        agent_id=agent_id,
        tool_name=req.tool_name,
        session_context=req.session_context,
        store=store,
    )
    return result


# ── Tool manifest routes ──────────────────────────────────────────────────────

@tools_router.post("/manifests", status_code=status.HTTP_201_CREATED)
def create_and_register_manifest(
    req: CreateManifestRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Create a signed tool manifest and register it in the AIAF store."""
    try:
        key_bytes = bytes.fromhex(req.signing_key_hex)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"signing_key_hex is not valid hex: {exc}")

    try:
        manifest = create_manifest(
            tool_name=req.tool_name,
            version=req.version,
            description=req.description,
            input_schema=req.input_schema,
            declared_capabilities=req.declared_capabilities,
            signing_key=key_bytes,
            allowed_agents=req.allowed_agents,
            issuer=req.issuer,
            expires_at=req.expires_at,
        )
    except ManifestError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    summary = register_manifest(manifest, store)
    return {"manifest_version": MANIFEST_VERSION, **summary}


@tools_router.get("/manifests")
def list_all_manifests(
    tool_name: str | None = None,
    limit: int = 50,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """List registered tool manifests."""
    manifests = list_manifests(store, tool_name=tool_name, limit=limit)
    return {
        "manifest_version": MANIFEST_VERSION,
        "count": len(manifests),
        "manifests": manifests,
    }


@tools_router.get("/manifests/{tool_name}/{version}")
def get_one_manifest(
    tool_name: str,
    version: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Get a stored tool manifest."""
    m = get_manifest(tool_name, version, store)
    if m is None:
        raise HTTPException(
            status_code=404,
            detail=f"No manifest for tool '{tool_name}' version '{version}'.",
        )
    return m


@tools_router.post("/manifests/{tool_name}/{version}/verify")
def verify_stored_manifest(
    tool_name: str,
    version: str,
    req: VerifyManifestRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Re-verify the integrity of a stored tool manifest."""
    record = store.get_model(f"tool_manifest:{tool_name}:{version}")
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"No manifest for tool '{tool_name}' version '{version}'.",
        )
    try:
        key_bytes = bytes.fromhex(req.signing_key_hex)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"signing_key_hex is not valid hex: {exc}")

    meta = record.get("metadata") or {}
    manifest = {
        "manifest_id": meta.get("manifest_id"),
        "manifest_version": meta.get("manifest_version"),
        "algorithm": meta.get("algorithm"),
        "statement": meta.get("statement"),
        "signature": meta.get("signature"),
    }
    result = verify_manifest(manifest, key_bytes, current_schema=req.current_schema)
    return result

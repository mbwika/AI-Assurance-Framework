"""Agent Registry.

Maintains a registry of deployed agents: their identity, declared tool
inventory, trust level, capability flags, and operational constraints.

Design notes
------------
* Every agent that operates within an AIAF-governed environment should be
  registered here before it is granted access to tools.
* Capability flags are the primary evidence signal for the permission graph
  analyser — they describe *what an agent can do*, independent of what it
  claims it will do.
* Storage uses the AIAF model store under ``"agent:{agent_id}"``.
* Sensitive operational parameters (signing keys, credentials) are never
  stored — only their hashes or identifiers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REGISTRY_VERSION = "1.0"

_AGENT_PREFIX = "agent:"
MAX_TOOLS_PER_AGENT = 200

STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_QUARANTINED = "quarantined"
STATUS_DEREGISTERED = "deregistered"

AGENT_STATUSES = frozenset({
    STATUS_ACTIVE,
    STATUS_SUSPENDED,
    STATUS_QUARANTINED,
    STATUS_DEREGISTERED,
})

# ── Trust levels ──────────────────────────────────────────────────────────────

TRUST_VERIFIED = "VERIFIED"       # cryptographically attested; signed manifest
TRUST_INTERNAL = "INTERNAL"       # internal, reviewed, policy-controlled
TRUST_EXTERNAL = "EXTERNAL"       # third-party or open-source agent
TRUST_USER = "USER"               # user-defined / user-supplied agent
TRUST_UNTRUSTED = "UNTRUSTED"     # explicitly high-risk or unreviewed

TRUST_LABELS = frozenset({
    TRUST_VERIFIED, TRUST_INTERNAL, TRUST_EXTERNAL, TRUST_USER, TRUST_UNTRUSTED,
})

TRUST_RANK: Dict[str, int] = {
    TRUST_VERIFIED: 5,
    TRUST_INTERNAL: 4,
    TRUST_EXTERNAL: 3,
    TRUST_USER: 2,
    TRUST_UNTRUSTED: 1,
}

# ── Capability flags ──────────────────────────────────────────────────────────
# Declare what an agent *can* do through its tool inventory.

CAPABILITY_NETWORK_EGRESS = "network_egress"        # can send data externally
CAPABILITY_FILE_READ = "file_read"                  # can read local files
CAPABILITY_FILE_WRITE = "file_write"                # can write/delete local files
CAPABILITY_CODE_EXECUTION = "code_execution"        # can run arbitrary code
CAPABILITY_DATA_READ = "data_read"                  # can read structured data / DBs
CAPABILITY_DATA_WRITE = "data_write"                # can write to structured data / DBs
CAPABILITY_TOOL_INVOCATION = "tool_invocation"      # can invoke other tools programmatically
CAPABILITY_SUBAGENT_SPAWN = "subagent_spawn"        # can spawn or delegate to other agents
CAPABILITY_APPROVAL_BYPASS = "approval_bypass"      # can skip human-approval gates
CAPABILITY_MEMORY_READ = "memory_read"              # can read persistent agent memory
CAPABILITY_MEMORY_WRITE = "memory_write"            # can write persistent agent memory

CAPABILITY_FLAGS = frozenset({
    CAPABILITY_NETWORK_EGRESS, CAPABILITY_FILE_READ, CAPABILITY_FILE_WRITE,
    CAPABILITY_CODE_EXECUTION, CAPABILITY_DATA_READ, CAPABILITY_DATA_WRITE,
    CAPABILITY_TOOL_INVOCATION, CAPABILITY_SUBAGENT_SPAWN, CAPABILITY_APPROVAL_BYPASS,
    CAPABILITY_MEMORY_READ, CAPABILITY_MEMORY_WRITE,
})

# Risk rank: higher = riskier.  Used by permission graph for severity derivation.
CAPABILITY_RISK_RANK: Dict[str, int] = {
    CAPABILITY_DATA_READ: 1,
    CAPABILITY_FILE_READ: 1,
    CAPABILITY_MEMORY_READ: 1,
    CAPABILITY_NETWORK_EGRESS: 3,
    CAPABILITY_DATA_WRITE: 3,
    CAPABILITY_FILE_WRITE: 3,
    CAPABILITY_MEMORY_WRITE: 3,
    CAPABILITY_TOOL_INVOCATION: 4,
    CAPABILITY_CODE_EXECUTION: 5,
    CAPABILITY_SUBAGENT_SPAWN: 5,
    CAPABILITY_APPROVAL_BYPASS: 6,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _agent_key(agent_id: str) -> str:
    return f"{_AGENT_PREFIX}{agent_id}"


class AgentRegistryError(ValueError):
    pass


def _validate_trust_label(label: str) -> str:
    label = str(label).upper().strip()
    if label not in TRUST_LABELS:
        raise AgentRegistryError(
            f"Invalid trust label {label!r}; valid: {sorted(TRUST_LABELS)}"
        )
    return label


def _validate_capabilities(caps: List[str]) -> List[str]:
    caps = [str(c).lower().strip() for c in (caps or [])]
    unknown = [c for c in caps if c not in CAPABILITY_FLAGS]
    if unknown:
        raise AgentRegistryError(
            f"Unknown capability flags: {unknown}; valid: {sorted(CAPABILITY_FLAGS)}"
        )
    return sorted(set(caps))


# ── Registry operations ───────────────────────────────────────────────────────

def register_agent(
    agent_id: str,
    name: str,
    declared_tools: List[str],
    trust_level: str,
    capability_flags: List[str],
    store: Any,
    *,
    purpose: Optional[str] = None,
    operational_constraints: Optional[Dict[str, Any]] = None,
    manifest_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Register an agent in the AIAF agent registry.

    Parameters
    ----------
    agent_id:
        Unique identifier for this agent deployment.
    name:
        Human-readable agent name.
    declared_tools:
        List of tool names the agent is authorised to invoke.
    trust_level:
        Trust classification for this agent.
    capability_flags:
        Explicit capability declarations — what the agent *can* do through
        its tool set.  Validated against ``CAPABILITY_FLAGS``.
    store:
        AIAF model store.
    purpose:
        Short description of the agent's intended function (used by the
        permission graph analyser to detect purpose-scope mismatches).
    operational_constraints:
        Dict of operational limits: ``max_tool_calls_per_session``,
        ``allowed_data_sensitivity``, ``requires_approval_for_egress``, etc.
    manifest_id:
        ID of a signed tool manifest linked to this agent.
    """
    if not str(agent_id).strip():
        raise AgentRegistryError("agent_id must be non-empty")
    agent_id = str(agent_id).strip()
    trust_level = _validate_trust_label(trust_level)
    capability_flags = _validate_capabilities(capability_flags)

    if not isinstance(declared_tools, list):
        raise AgentRegistryError("declared_tools must be a list")
    declared_tools = [str(t).strip() for t in declared_tools if str(t).strip()]
    if len(declared_tools) > MAX_TOOLS_PER_AGENT:
        raise AgentRegistryError(
            f"Agent may declare at most {MAX_TOOLS_PER_AGENT} tools."
        )

    key = _agent_key(agent_id)
    existing = store.get_model(key) or {}
    existing_meta = existing.get("metadata") or {}
    now = _utc_now()

    record: Dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            **existing_meta,
            "agent_id": agent_id,
            "name": str(name).strip(),
            "declared_tools": declared_tools,
            "trust_level": trust_level,
            "capability_flags": capability_flags,
            "purpose": str(purpose).strip() if purpose else None,
            "operational_constraints": operational_constraints or {},
            "manifest_id": manifest_id,
            "registry_version": REGISTRY_VERSION,
            "registered_at": existing_meta.get("registered_at") or now,
            "updated_at": now,
            "extra": metadata or {},
            "status": STATUS_ACTIVE,
            "status_reason": existing_meta.get("status_reason"),
            "status_changed_at": existing_meta.get("status_changed_at") or now,
            "blocked_tools": existing_meta.get("blocked_tools") or {},
        },
    }
    store.save_model(record)
    return _agent_summary(record)


def get_agent(agent_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return the registry record for ``agent_id``, or ``None``."""
    record = store.get_model(_agent_key(agent_id))
    if not record:
        return None
    return _agent_summary(record)


def list_agents(
    store: Any,
    limit: int = 50,
    trust_level: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List registered agents, newest first."""
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_AGENT_PREFIX):
            continue
        summary = _agent_summary(m)
        if trust_level and summary.get("trust_level") != str(trust_level).upper():
            continue
        result.append(summary)
    result.sort(key=lambda a: a.get("registered_at") or "", reverse=True)
    return result[:limit]


def deregister_agent(agent_id: str, store: Any) -> bool:
    """Mark an agent as deregistered (soft delete).

    Returns ``True`` if the agent existed, ``False`` otherwise.
    """
    key = _agent_key(agent_id)
    record = store.get_model(key)
    if not record:
        return False
    meta = record.get("metadata") or {}
    meta["status"] = STATUS_DEREGISTERED
    meta["deregistered_at"] = _utc_now()
    record["metadata"] = meta
    store.save_model(record)
    return True


def link_manifest(agent_id: str, manifest_id: str, store: Any) -> Dict[str, Any]:
    """Link a signed tool manifest to a registered agent.

    Raises ``AgentRegistryError`` if the agent is not found.
    """
    key = _agent_key(agent_id)
    record = store.get_model(key)
    if not record:
        raise AgentRegistryError(f"Agent '{agent_id}' not found.")
    meta = record.get("metadata") or {}
    meta["manifest_id"] = str(manifest_id).strip()
    meta["updated_at"] = _utc_now()
    record["metadata"] = meta
    store.save_model(record)
    return _agent_summary(record)


def set_agent_status(
    agent_id: str,
    status: str,
    store: Any,
    *,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Set the runtime containment status for an agent."""
    normalized = str(status).lower().strip()
    if normalized not in AGENT_STATUSES:
        raise AgentRegistryError(
            f"Invalid status {status!r}; valid: {sorted(AGENT_STATUSES)}"
        )
    key = _agent_key(agent_id)
    record = store.get_model(key)
    if not record:
        raise AgentRegistryError(f"Agent '{agent_id}' not found.")
    meta = record.get("metadata") or {}
    meta["status"] = normalized
    meta["status_reason"] = str(reason).strip() if reason else None
    meta["status_changed_at"] = _utc_now()
    meta["updated_at"] = meta["status_changed_at"]
    record["metadata"] = meta
    store.save_model(record)
    return _agent_summary(record)


def set_tool_block(
    agent_id: str,
    tool_name: str,
    blocked: bool,
    store: Any,
    *,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Block or unblock one declared tool for an agent."""
    key = _agent_key(agent_id)
    record = store.get_model(key)
    if not record:
        raise AgentRegistryError(f"Agent '{agent_id}' not found.")
    meta = record.get("metadata") or {}
    declared_tools = set(meta.get("declared_tools") or [])
    tool_name = str(tool_name).strip()
    if tool_name not in declared_tools:
        raise AgentRegistryError(
            f"Tool '{tool_name}' is not declared for agent '{agent_id}'."
        )

    blocked_tools = dict(meta.get("blocked_tools") or {})
    if blocked:
        blocked_tools[tool_name] = {
            "reason": str(reason).strip() if reason else None,
            "blocked_at": _utc_now(),
        }
    else:
        blocked_tools.pop(tool_name, None)
    meta["blocked_tools"] = blocked_tools
    meta["updated_at"] = _utc_now()
    record["metadata"] = meta
    store.save_model(record)
    return _agent_summary(record)


def _agent_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    meta = record.get("metadata") or {}
    caps = meta.get("capability_flags") or []
    max_rank = max((CAPABILITY_RISK_RANK.get(c, 0) for c in caps), default=0)
    return {
        "agent_id": meta.get("agent_id"),
        "name": meta.get("name"),
        "trust_level": meta.get("trust_level"),
        "declared_tools": meta.get("declared_tools") or [],
        "capability_flags": caps,
        "max_capability_risk_rank": max_rank,
        "purpose": meta.get("purpose"),
        "operational_constraints": meta.get("operational_constraints") or {},
        "manifest_id": meta.get("manifest_id"),
        "status": meta.get("status", STATUS_ACTIVE),
        "status_reason": meta.get("status_reason"),
        "status_changed_at": meta.get("status_changed_at"),
        "blocked_tools": meta.get("blocked_tools") or {},
        "registered_at": meta.get("registered_at"),
        "updated_at": meta.get("updated_at"),
        "registry_version": meta.get("registry_version", REGISTRY_VERSION),
    }

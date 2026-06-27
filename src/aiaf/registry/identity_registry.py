"""Model/Agent Identity and Delegation Registry.

Treats models, agents, tools, datasets, humans, and services as first-class
principals with explicit trust levels, capabilities, and verifiable identities.

Supports:
  - Principal registration with typed trust levels
  - Delegation grants: principal A delegates a scoped permission set to B
  - Delegation revocation with reason
  - Authority verification: can principal X perform action Y on resource Z?
  - Authority chain walk: full delegation path from a principal to its grants

Scope format
------------
A delegation ``scope`` is a list of strings, each of the form
``"action:resource"``, ``"action:*"``, ``"*:resource"``, or ``"*"``
(all actions on all resources).

Evidence origin
---------------
LOCALLY_OBSERVED — all principal and delegation data is stored and
managed by AIAF locally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

IDENTITY_VERSION = "1.0"

# ── Principal types ────────────────────────────────────────────────────────────
PRINCIPAL_MODEL = "MODEL"
PRINCIPAL_AGENT = "AGENT"
PRINCIPAL_TOOL = "TOOL"
PRINCIPAL_DATASET = "DATASET"
PRINCIPAL_HUMAN = "HUMAN"
PRINCIPAL_SERVICE = "SERVICE"

PRINCIPAL_TYPES: frozenset = frozenset({
    PRINCIPAL_MODEL, PRINCIPAL_AGENT, PRINCIPAL_TOOL,
    PRINCIPAL_DATASET, PRINCIPAL_HUMAN, PRINCIPAL_SERVICE,
})

# ── Trust levels ───────────────────────────────────────────────────────────────
TRUST_UNTRUSTED = "UNTRUSTED"
TRUST_EXTERNAL = "EXTERNAL"
TRUST_INTERNAL = "INTERNAL"
TRUST_PRIVILEGED = "PRIVILEGED"

TRUST_LEVELS: frozenset = frozenset(
    {TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED}
)

_TRUST_RANK: Dict[str, int] = {
    TRUST_PRIVILEGED: 3, TRUST_INTERNAL: 2, TRUST_EXTERNAL: 1, TRUST_UNTRUSTED: 0,
}

# ── Delegation status ──────────────────────────────────────────────────────────
DELEGATION_ACTIVE = "ACTIVE"
DELEGATION_REVOKED = "REVOKED"
DELEGATION_EXPIRED = "EXPIRED"

_TERMINAL_DELEGATION_STATUSES: frozenset = frozenset({DELEGATION_REVOKED, DELEGATION_EXPIRED})

# ── Storage prefixes ───────────────────────────────────────────────────────────
_PRINCIPAL_PREFIX = "identity:principal:"
_DELEGATION_PREFIX = "identity:delegation:"


class IdentityError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _principal_key(principal_id: str) -> str:
    return f"{_PRINCIPAL_PREFIX}{principal_id}"


def _delegation_key(delegation_id: str) -> str:
    return f"{_DELEGATION_PREFIX}{delegation_id}"


def _meta(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _is_expired(delegation: Dict[str, Any]) -> bool:
    exp = delegation.get("expires_at")
    if not exp:
        return False
    try:
        expiry = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= expiry
    except ValueError:
        return False


def _scope_matches(scope_item: str, action: str, resource: str) -> bool:
    """Return True if scope_item grants action on resource."""
    if scope_item == "*":
        return True
    if ":" not in scope_item:
        return scope_item == action
    a_pat, r_pat = scope_item.split(":", 1)
    return (a_pat in ("*", action)) and (r_pat in ("*", resource))


def _delegation_is_active(delegation: Dict[str, Any]) -> bool:
    if delegation.get("status") != DELEGATION_ACTIVE:
        return False
    if _is_expired(delegation):
        return False
    return True


# ── Principal CRUD ─────────────────────────────────────────────────────────────

def register_principal(
    principal_id: str,
    principal_type: str,
    name: str,
    store: Any,
    *,
    trust_level: str = TRUST_INTERNAL,
    capabilities: Optional[List[str]] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Register a new principal or update an existing one."""
    principal_id = str(principal_id).strip()
    if not principal_id:
        raise IdentityError("principal_id must not be empty")
    principal_type = str(principal_type).upper().strip()
    if principal_type not in PRINCIPAL_TYPES:
        raise IdentityError(
            f"Unknown principal_type {principal_type!r}. Valid: {sorted(PRINCIPAL_TYPES)}"
        )
    trust_level = str(trust_level).upper().strip()
    if trust_level not in TRUST_LEVELS:
        raise IdentityError(f"Unknown trust_level {trust_level!r}. Valid: {sorted(TRUST_LEVELS)}")

    existing = _meta(store.get_model(_principal_key(principal_id)))
    now = _utc_now()
    record_meta: Dict[str, Any] = {
        "principal_id": principal_id,
        "principal_type": principal_type,
        "name": name,
        "trust_level": trust_level,
        "capabilities": list(capabilities or []),
        "attributes": dict(attributes or {}),
        "registered_at": existing.get("registered_at") or now,
        "updated_at": now,
        "identity_version": IDENTITY_VERSION,
    }
    store.save_model({
        "model_id": _principal_key(principal_id),
        "id": _principal_key(principal_id),
        "metadata": record_meta,
    })
    return record_meta


def get_principal(principal_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return a principal record, or None if not found."""
    rec = store.get_model(_principal_key(str(principal_id).strip()))
    return _meta(rec) if rec else None


def list_principals(
    store: Any,
    *,
    principal_type: Optional[str] = None,
    trust_level: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List principals with optional type and trust level filters."""
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_PRINCIPAL_PREFIX):
            continue
        p = _meta(rec)
        if principal_type and p.get("principal_type") != str(principal_type).upper():
            continue
        if trust_level and p.get("trust_level") != str(trust_level).upper():
            continue
        results.append(p)
        if len(results) >= limit:
            break
    return results


def update_principal(
    principal_id: str,
    store: Any,
    *,
    trust_level: Optional[str] = None,
    capabilities: Optional[List[str]] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Partially update an existing principal."""
    existing = get_principal(principal_id, store)
    if not existing:
        raise IdentityError(f"Principal {principal_id!r} not found.")
    if trust_level is not None:
        tl = str(trust_level).upper()
        if tl not in TRUST_LEVELS:
            raise IdentityError(f"Unknown trust_level {tl!r}")
        existing["trust_level"] = tl
    if capabilities is not None:
        existing["capabilities"] = list(capabilities)
    if attributes is not None:
        existing["attributes"] = {**existing.get("attributes", {}), **attributes}
    existing["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _principal_key(principal_id),
        "id": _principal_key(principal_id),
        "metadata": existing,
    })
    return existing


# ── Delegation CRUD ────────────────────────────────────────────────────────────

def grant_delegation(
    delegation_id: str,
    delegator_id: str,
    delegate_id: str,
    scope: List[str],
    store: Any,
    *,
    granted_by: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Grant delegate_id permission to act within scope on behalf of delegator_id."""
    delegation_id = str(delegation_id).strip()
    if not delegation_id:
        raise IdentityError("delegation_id must not be empty")
    if not scope:
        raise IdentityError("scope must not be empty")
    if not isinstance(scope, list):
        raise IdentityError("scope must be a list of permission strings")

    now = _utc_now()
    record_meta: Dict[str, Any] = {
        "delegation_id": delegation_id,
        "delegator_id": delegator_id,
        "delegate_id": delegate_id,
        "scope": list(scope),
        "status": DELEGATION_ACTIVE,
        "granted_by": granted_by,
        "expires_at": expires_at,
        "granted_at": now,
        "updated_at": now,
    }
    store.save_model({
        "model_id": _delegation_key(delegation_id),
        "id": _delegation_key(delegation_id),
        "metadata": record_meta,
    })
    return record_meta


def get_delegation(delegation_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return a delegation record, or None if not found."""
    rec = store.get_model(_delegation_key(str(delegation_id).strip()))
    if not rec:
        return None
    d = _meta(rec)
    # Auto-mark expired delegations on read
    if d.get("status") == DELEGATION_ACTIVE and _is_expired(d):
        d["status"] = DELEGATION_EXPIRED
        d["updated_at"] = _utc_now()
        store.save_model({"model_id": _delegation_key(delegation_id), "id": _delegation_key(delegation_id), "metadata": d})
    return d


def revoke_delegation(
    delegation_id: str,
    store: Any,
    *,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Revoke an active delegation immediately."""
    d = get_delegation(delegation_id, store)
    if not d:
        raise IdentityError(f"Delegation {delegation_id!r} not found.")
    if d["status"] in _TERMINAL_DELEGATION_STATUSES:
        raise IdentityError(
            f"Delegation {delegation_id!r} is already in terminal status {d['status']!r}."
        )
    d["status"] = DELEGATION_REVOKED
    d["revoked_at"] = _utc_now()
    d["revocation_reason"] = reason
    d["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _delegation_key(delegation_id),
        "id": _delegation_key(delegation_id),
        "metadata": d,
    })
    return d


def list_delegations(
    store: Any,
    *,
    delegator_id: Optional[str] = None,
    delegate_id: Optional[str] = None,
    active_only: bool = True,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List delegations with optional filters."""
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_DELEGATION_PREFIX):
            continue
        d = _meta(rec)
        if delegator_id and d.get("delegator_id") != delegator_id:
            continue
        if delegate_id and d.get("delegate_id") != delegate_id:
            continue
        if active_only and not _delegation_is_active(d):
            continue
        results.append(d)
        if len(results) >= limit:
            break
    return results


# ── Authority verification ─────────────────────────────────────────────────────

def verify_authority(
    principal_id: str,
    action: str,
    resource: str,
    store: Any,
) -> Dict[str, Any]:
    """Verify whether principal_id is authorised to perform action on resource.

    Checks direct capabilities on the principal record and then walks the
    delegation chain to find a granted scope that covers the request.
    """
    principal = get_principal(principal_id, store)
    if not principal:
        return {
            "authorized": False,
            "reason": f"Principal {principal_id!r} not registered.",
            "delegation_chain": [],
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
        }

    # Check own capabilities first
    own_caps = principal.get("capabilities") or []
    for cap in own_caps:
        if _scope_matches(cap, action, resource):
            return {
                "authorized": True,
                "reason": f"Principal has direct capability: {cap!r}.",
                "delegation_chain": [],
                "principal_id": principal_id,
                "action": action,
                "resource": resource,
            }

    # Walk delegations
    chain = get_authority_chain(principal_id, store)
    for link in chain:
        for scope_item in link.get("scope", []):
            if _scope_matches(scope_item, action, resource):
                return {
                    "authorized": True,
                    "reason": (
                        f"Authorised via delegation {link['delegation_id']!r} "
                        f"(scope {scope_item!r}) from {link['delegator_id']!r}."
                    ),
                    "delegation_chain": chain,
                    "principal_id": principal_id,
                    "action": action,
                    "resource": resource,
                }

    return {
        "authorized": False,
        "reason": (
            f"No capability or active delegation grants {action!r} on {resource!r}."
        ),
        "delegation_chain": chain,
        "principal_id": principal_id,
        "action": action,
        "resource": resource,
    }


def get_authority_chain(
    principal_id: str,
    store: Any,
    *,
    _visited: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Return all active delegations where this principal is the delegate.

    Recursively follows delegation chains (cycle-safe via ``_visited``).
    """
    if _visited is None:
        _visited = set()
    if principal_id in _visited:
        return []
    _visited.add(principal_id)

    direct = list_delegations(store, delegate_id=principal_id, active_only=True)
    chain = list(direct)
    for d in direct:
        parent_id = d.get("delegator_id")
        if parent_id and parent_id not in _visited:
            chain.extend(get_authority_chain(parent_id, store, _visited=_visited))
    return chain

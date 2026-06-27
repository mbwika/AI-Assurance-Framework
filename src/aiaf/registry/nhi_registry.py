"""Non-Human Identity (NHI) Discovery & Lifecycle Governance Registry.

Addresses the 2026 crisis of machine identity at scale (100:1–500:1 machine-to-human
ratio, second-leading breach cause).  Tracks AI/automation machine identities with
full lifecycle management, credential hygiene scoring, and stale/over-privileged
identity detection.

NHI types
---------
MODEL_SERVING     — model serving endpoint (REST/gRPC)
AGENT_WORKER      — autonomous agent worker process
TOOL_EXECUTOR     — tool/function executor (code sandbox, shell, API wrapper)
PIPELINE_RUNNER   — ML pipeline / batch job runner
DATA_CONNECTOR    — data source/sink connector (database, object store, streaming)
GATEWAY           — API gateway, proxy, or MCP server

Lifecycle states (in order)
---------------------------
PENDING           — registered but not yet provisioned
ACTIVE            — fully provisioned and operational
DORMANT           — provisioned but not recently active (staleness risk)
DEPROVISIONING    — in the process of being shut down
REVOKED           — credentials revoked; identity no longer valid

Hygiene signals
---------------
stale_days_threshold   — days since last_seen_at before flagged as stale (default: 30)
credential_age_days    — days since credential_issued_at before flagged (default: 90)
over_privileged        — more scopes than declared minimum_required_scopes

Evidence origin
---------------
LOCALLY_OBSERVED — all NHI data is registered and assessed by AIAF locally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

NHI_VERSION = "1.0"

# ── NHI types ──────────────────────────────────────────────────────────────────
NHI_MODEL_SERVING = "MODEL_SERVING"
NHI_AGENT_WORKER = "AGENT_WORKER"
NHI_TOOL_EXECUTOR = "TOOL_EXECUTOR"
NHI_PIPELINE_RUNNER = "PIPELINE_RUNNER"
NHI_DATA_CONNECTOR = "DATA_CONNECTOR"
NHI_GATEWAY = "GATEWAY"

NHI_TYPES: frozenset = frozenset({
    NHI_MODEL_SERVING, NHI_AGENT_WORKER, NHI_TOOL_EXECUTOR,
    NHI_PIPELINE_RUNNER, NHI_DATA_CONNECTOR, NHI_GATEWAY,
})

# ── Lifecycle states ───────────────────────────────────────────────────────────
NHI_PENDING = "PENDING"
NHI_ACTIVE = "ACTIVE"
NHI_DORMANT = "DORMANT"
NHI_DEPROVISIONING = "DEPROVISIONING"
NHI_REVOKED = "REVOKED"

NHI_STATES: frozenset = frozenset(
    {NHI_PENDING, NHI_ACTIVE, NHI_DORMANT, NHI_DEPROVISIONING, NHI_REVOKED}
)

# Terminal states — cannot transition away
_TERMINAL_STATES: frozenset = frozenset({NHI_REVOKED})

# Valid state transitions
_VALID_TRANSITIONS: Dict[str, frozenset] = {
    NHI_PENDING: frozenset({NHI_ACTIVE, NHI_REVOKED}),
    NHI_ACTIVE: frozenset({NHI_DORMANT, NHI_DEPROVISIONING, NHI_REVOKED}),
    NHI_DORMANT: frozenset({NHI_ACTIVE, NHI_DEPROVISIONING, NHI_REVOKED}),
    NHI_DEPROVISIONING: frozenset({NHI_REVOKED}),
    NHI_REVOKED: frozenset(),
}

# ── Hygiene defaults ───────────────────────────────────────────────────────────
DEFAULT_STALE_DAYS = 30
DEFAULT_CREDENTIAL_AGE_DAYS = 90

# ── Hygiene verdict ────────────────────────────────────────────────────────────
HYGIENE_CLEAN = "CLEAN"
HYGIENE_REVIEW_NEEDED = "REVIEW_NEEDED"
HYGIENE_AT_RISK = "AT_RISK"
HYGIENE_CRITICAL = "CRITICAL"

# ── Storage prefix ─────────────────────────────────────────────────────────────
_NHI_PREFIX = "nhi:"


class NHIError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _nhi_key(nhi_id: str) -> str:
    return f"{_NHI_PREFIX}{nhi_id}"


def _load_meta(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _days_since(ts: Optional[str]) -> Optional[float]:
    """Return days elapsed since an ISO-8601 UTC timestamp, or None."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return delta.total_seconds() / 86400.0
    except Exception:
        return None


def _scope_count(scopes: Any) -> int:
    if isinstance(scopes, list):
        return len(scopes)
    if isinstance(scopes, (set, frozenset)):
        return len(scopes)
    return 0


# ── Hygiene scoring ────────────────────────────────────────────────────────────

def _score_hygiene(
    nhi: Dict[str, Any],
    *,
    stale_days: int = DEFAULT_STALE_DAYS,
    credential_age_days: int = DEFAULT_CREDENTIAL_AGE_DAYS,
) -> Dict[str, Any]:
    """Compute hygiene signals and verdict for a single NHI record."""
    issues: List[str] = []
    severity_rank = 0  # 0=clean, 1=review, 2=at-risk, 3=critical

    state = nhi.get("state", NHI_PENDING)

    # Stale detection
    days_since_seen = _days_since(nhi.get("last_seen_at"))
    is_stale = (
        state in (NHI_ACTIVE, NHI_DORMANT)
        and days_since_seen is not None
        and days_since_seen > stale_days
    )
    if is_stale:
        issues.append(
            f"Identity not seen for {days_since_seen:.0f} days (threshold: {stale_days})."
        )
        severity_rank = max(severity_rank, 2)

    # Credential age
    cred_age = _days_since(nhi.get("credential_issued_at"))
    cred_expired = cred_age is not None and cred_age > credential_age_days
    if cred_expired:
        issues.append(
            f"Credential is {cred_age:.0f} days old (rotation threshold: {credential_age_days})."
        )
        severity_rank = max(severity_rank, 2)

    # Over-privileged
    granted = _scope_count(nhi.get("granted_scopes"))
    minimum = _scope_count(nhi.get("minimum_required_scopes"))
    over_privileged = (minimum > 0) and (granted > minimum)
    if over_privileged:
        issues.append(
            f"Has {granted} granted scopes but only {minimum} are declared as minimum required."
        )
        severity_rank = max(severity_rank, 1)

    # Orphaned — no owner
    orphaned = not nhi.get("owner_id")
    if orphaned:
        issues.append("NHI has no declared owner_id — orphaned identity.")
        severity_rank = max(severity_rank, 2)

    # Revoked but still flagged active (state mismatch)
    state_mismatch = state == NHI_REVOKED and nhi.get("is_active_in_environment", False)
    if state_mismatch:
        issues.append("Identity is REVOKED in registry but flagged as active in environment.")
        severity_rank = max(severity_rank, 3)

    verdict_map = {0: HYGIENE_CLEAN, 1: HYGIENE_REVIEW_NEEDED, 2: HYGIENE_AT_RISK, 3: HYGIENE_CRITICAL}

    return {
        "is_stale": is_stale,
        "days_since_last_seen": round(days_since_seen, 1) if days_since_seen is not None else None,
        "credential_age_days": round(cred_age, 1) if cred_age is not None else None,
        "credential_rotation_needed": cred_expired,
        "over_privileged": over_privileged,
        "orphaned": orphaned,
        "hygiene_verdict": verdict_map[severity_rank],
        "hygiene_issues": issues,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def register_nhi(
    nhi_id: str,
    nhi_type: str,
    store: Any,
    *,
    display_name: Optional[str] = None,
    owner_id: Optional[str] = None,
    environment: Optional[str] = None,
    granted_scopes: Optional[List[str]] = None,
    minimum_required_scopes: Optional[List[str]] = None,
    credential_issued_at: Optional[str] = None,
    last_seen_at: Optional[str] = None,
    is_active_in_environment: bool = False,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Register a non-human identity.

    Parameters
    ----------
    nhi_id:                     Unique identifier (e.g. service-account name, client-id).
    nhi_type:                   One of NHI_* type constants.
    owner_id:                   Human or team that owns this NHI.
    environment:                Deployment environment (prod, staging, dev).
    granted_scopes:             All permissions/scopes currently granted.
    minimum_required_scopes:    Minimum scopes needed for operation (for over-privilege check).
    credential_issued_at:       ISO-8601 timestamp when credentials were last rotated.
    last_seen_at:               ISO-8601 timestamp of last observed activity.
    is_active_in_environment:   Whether the identity is observed as active externally.
    """
    if not nhi_id or not nhi_id.strip():
        raise NHIError("nhi_id must be non-empty.")

    nhi_type = str(nhi_type).upper().strip()
    if nhi_type not in NHI_TYPES:
        raise NHIError(f"Unknown nhi_type {nhi_type!r}. Valid: {sorted(NHI_TYPES)}")

    now = _utc_now()
    record: Dict[str, Any] = {
        "model_id": _nhi_key(nhi_id),
        "id": _nhi_key(nhi_id),
        "metadata": {
            "nhi_id": nhi_id,
            "nhi_type": nhi_type,
            "display_name": display_name or nhi_id,
            "owner_id": owner_id,
            "environment": environment,
            "state": NHI_PENDING,
            "granted_scopes": granted_scopes or [],
            "minimum_required_scopes": minimum_required_scopes or [],
            "credential_issued_at": credential_issued_at,
            "last_seen_at": last_seen_at,
            "is_active_in_environment": is_active_in_environment,
            "attributes": attributes or {},
            "state_history": [
                {"state": NHI_PENDING, "at": now, "reason": "initial registration"}
            ],
            "evidence_origin": "LOCALLY_OBSERVED",
            "registered_at": now,
            "updated_at": now,
        },
    }
    store.save_model(record)
    return _load_meta(store.get_model(_nhi_key(nhi_id)))


def get_nhi(nhi_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return NHI record, or None if not found."""
    rec = store.get_model(_nhi_key(nhi_id))
    return _load_meta(rec) if rec else None


def list_nhis(
    store: Any,
    *,
    nhi_type: Optional[str] = None,
    state: Optional[str] = None,
    owner_id: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """List registered NHIs with optional filters."""
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_NHI_PREFIX):
            continue
        meta = _load_meta(rec)
        if nhi_type and meta.get("nhi_type") != str(nhi_type).upper().strip():
            continue
        if state and meta.get("state") != str(state).upper().strip():
            continue
        if owner_id and meta.get("owner_id") != owner_id:
            continue
        results.append(meta)
        if len(results) >= limit:
            break
    return results


def update_nhi_state(
    nhi_id: str,
    new_state: str,
    store: Any,
    *,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Transition an NHI to a new lifecycle state.

    Enforces valid state machine transitions.
    """
    new_state = str(new_state).upper().strip()
    if new_state not in NHI_STATES:
        raise NHIError(f"Unknown state {new_state!r}. Valid: {sorted(NHI_STATES)}")

    nhi = get_nhi(nhi_id, store)
    if not nhi:
        raise NHIError(f"NHI {nhi_id!r} not found.")

    current = nhi.get("state", NHI_PENDING)
    if current in _TERMINAL_STATES:
        raise NHIError(
            f"NHI {nhi_id!r} is in terminal state {current!r} and cannot be transitioned."
        )
    if new_state not in _VALID_TRANSITIONS.get(current, frozenset()):
        raise NHIError(
            f"Invalid transition {current!r} → {new_state!r} for NHI {nhi_id!r}. "
            f"Valid: {sorted(_VALID_TRANSITIONS.get(current, frozenset()))}"
        )

    now = _utc_now()
    updated = dict(nhi)
    updated["state"] = new_state
    updated["updated_at"] = now
    history = list(updated.get("state_history") or [])
    history.append({"state": new_state, "at": now, "reason": reason or ""})
    updated["state_history"] = history

    store.save_model({
        "model_id": _nhi_key(nhi_id),
        "id": _nhi_key(nhi_id),
        "metadata": updated,
    })
    return _load_meta(store.get_model(_nhi_key(nhi_id)))


def update_nhi(
    nhi_id: str,
    store: Any,
    *,
    granted_scopes: Optional[List[str]] = None,
    minimum_required_scopes: Optional[List[str]] = None,
    credential_issued_at: Optional[str] = None,
    last_seen_at: Optional[str] = None,
    owner_id: Optional[str] = None,
    is_active_in_environment: Optional[bool] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Update mutable fields on an NHI record (credential rotation, scope changes, etc.)."""
    nhi = get_nhi(nhi_id, store)
    if not nhi:
        raise NHIError(f"NHI {nhi_id!r} not found.")

    updated = dict(nhi)
    if granted_scopes is not None:
        updated["granted_scopes"] = granted_scopes
    if minimum_required_scopes is not None:
        updated["minimum_required_scopes"] = minimum_required_scopes
    if credential_issued_at is not None:
        updated["credential_issued_at"] = credential_issued_at
    if last_seen_at is not None:
        updated["last_seen_at"] = last_seen_at
    if owner_id is not None:
        updated["owner_id"] = owner_id
    if is_active_in_environment is not None:
        updated["is_active_in_environment"] = is_active_in_environment
    if attributes is not None:
        existing_attrs = dict(updated.get("attributes") or {})
        existing_attrs.update(attributes)
        updated["attributes"] = existing_attrs

    updated["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _nhi_key(nhi_id),
        "id": _nhi_key(nhi_id),
        "metadata": updated,
    })
    return _load_meta(store.get_model(_nhi_key(nhi_id)))


def assess_nhi_hygiene(
    store: Any,
    *,
    stale_days: int = DEFAULT_STALE_DAYS,
    credential_age_days: int = DEFAULT_CREDENTIAL_AGE_DAYS,
    include_revoked: bool = False,
) -> Dict[str, Any]:
    """Return an organisation-wide NHI hygiene report.

    Returns
    -------
    Dict with keys:
        total_nhis, by_state, by_type,
        stale_count, over_privileged_count, orphaned_count, rotation_needed_count,
        critical_count, at_risk_count, review_needed_count, clean_count,
        critical_nhis, at_risk_nhis,
        evidence_origin, assessed_at
    """
    all_nhis = list_nhis(store, limit=10_000)
    if not include_revoked:
        all_nhis = [n for n in all_nhis if n.get("state") != NHI_REVOKED]

    by_state: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    stale_count = 0
    over_privileged_count = 0
    orphaned_count = 0
    rotation_needed_count = 0
    verdict_counts: Dict[str, int] = {
        HYGIENE_CLEAN: 0,
        HYGIENE_REVIEW_NEEDED: 0,
        HYGIENE_AT_RISK: 0,
        HYGIENE_CRITICAL: 0,
    }
    critical_nhis: List[Dict[str, Any]] = []
    at_risk_nhis: List[Dict[str, Any]] = []

    for nhi in all_nhis:
        st = nhi.get("state", NHI_PENDING)
        nt = nhi.get("nhi_type", "UNKNOWN")
        by_state[st] = by_state.get(st, 0) + 1
        by_type[nt] = by_type.get(nt, 0) + 1

        hygiene = _score_hygiene(nhi, stale_days=stale_days, credential_age_days=credential_age_days)
        verdict = hygiene["hygiene_verdict"]
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        if hygiene["is_stale"]:
            stale_count += 1
        if hygiene["over_privileged"]:
            over_privileged_count += 1
        if hygiene["orphaned"]:
            orphaned_count += 1
        if hygiene["credential_rotation_needed"]:
            rotation_needed_count += 1

        entry = {**nhi, "hygiene": hygiene}
        if verdict == HYGIENE_CRITICAL:
            critical_nhis.append(entry)
        elif verdict == HYGIENE_AT_RISK:
            at_risk_nhis.append(entry)

    return {
        "total_nhis": len(all_nhis),
        "by_state": by_state,
        "by_type": by_type,
        "stale_count": stale_count,
        "over_privileged_count": over_privileged_count,
        "orphaned_count": orphaned_count,
        "rotation_needed_count": rotation_needed_count,
        "critical_count": verdict_counts[HYGIENE_CRITICAL],
        "at_risk_count": verdict_counts[HYGIENE_AT_RISK],
        "review_needed_count": verdict_counts[HYGIENE_REVIEW_NEEDED],
        "clean_count": verdict_counts[HYGIENE_CLEAN],
        "critical_nhis": critical_nhis,
        "at_risk_nhis": at_risk_nhis,
        "stale_days_threshold": stale_days,
        "credential_age_days_threshold": credential_age_days,
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }

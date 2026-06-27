"""Remediation Tracker.

Tracks remediation actions linked to security incidents detected by AIAF.
Each remediation has a type (PATCH, CONFIG_CHANGE, etc.), a lifecycle
state (PENDING → IN_PROGRESS → RESOLVED / ACCEPTED_RISK / WONT_FIX),
and optional due-date and assignee fields.

Storage
-------
Remediations are stored under ``"remediation:{remediation_id}"``.

Evidence origin
---------------
LOCALLY_OBSERVED — AIAF observes and tracks the remediation state; it
makes no independent claim about whether the underlying issue is fixed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REMEDIATION_VERSION = "1.0"

_REMEDIATION_PREFIX = "remediation:"

# ── Action types ───────────────────────────────────────────────────────────────
ACTION_TYPE_PATCH = "PATCH"
ACTION_TYPE_CONFIG_CHANGE = "CONFIG_CHANGE"
ACTION_TYPE_MODEL_SWAP = "MODEL_SWAP"
ACTION_TYPE_GUARDRAIL_ADD = "GUARDRAIL_ADD"
ACTION_TYPE_POLICY_UPDATE = "POLICY_UPDATE"
ACTION_TYPE_MANUAL_REVIEW = "MANUAL_REVIEW"

ACTION_TYPES: frozenset = frozenset({
    ACTION_TYPE_PATCH, ACTION_TYPE_CONFIG_CHANGE, ACTION_TYPE_MODEL_SWAP,
    ACTION_TYPE_GUARDRAIL_ADD, ACTION_TYPE_POLICY_UPDATE, ACTION_TYPE_MANUAL_REVIEW,
})

# ── Status ─────────────────────────────────────────────────────────────────────
REMEDIATION_PENDING = "PENDING"
REMEDIATION_IN_PROGRESS = "IN_PROGRESS"
REMEDIATION_RESOLVED = "RESOLVED"
REMEDIATION_ACCEPTED_RISK = "ACCEPTED_RISK"
REMEDIATION_WONT_FIX = "WONT_FIX"

REMEDIATION_STATUSES: frozenset = frozenset({
    REMEDIATION_PENDING, REMEDIATION_IN_PROGRESS, REMEDIATION_RESOLVED,
    REMEDIATION_ACCEPTED_RISK, REMEDIATION_WONT_FIX,
})

_TERMINAL_STATUSES: frozenset = frozenset(
    {REMEDIATION_RESOLVED, REMEDIATION_ACCEPTED_RISK, REMEDIATION_WONT_FIX}
)


class RemediationError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _remediation_key(remediation_id: str) -> str:
    return f"{_REMEDIATION_PREFIX}{remediation_id}"


def _summary(record: Dict[str, Any]) -> Dict[str, Any]:
    m = record.get("metadata") or {}
    return {
        "remediation_id": m.get("remediation_id"),
        "incident_id": m.get("incident_id"),
        "model_id": m.get("model_id"),
        "action_type": m.get("action_type"),
        "description": m.get("description"),
        "status": m.get("status"),
        "assigned_to": m.get("assigned_to"),
        "due_date": m.get("due_date"),
        "resolution_note": m.get("resolution_note"),
        "status_history": m.get("status_history") or [],
        "created_at": m.get("created_at"),
        "updated_at": m.get("updated_at"),
        "resolved_at": m.get("resolved_at"),
        "remediation_version": m.get("remediation_version", REMEDIATION_VERSION),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def create_remediation(
    remediation_id: str,
    incident_id: str,
    action_type: str,
    description: str,
    store: Any,
    *,
    model_id: Optional[str] = None,
    assigned_to: Optional[str] = None,
    due_date: Optional[str] = None,
) -> Dict[str, Any]:
    remediation_id = str(remediation_id).strip()
    if not remediation_id:
        raise RemediationError("remediation_id must be non-empty")
    incident_id = str(incident_id).strip()
    if not incident_id:
        raise RemediationError("incident_id must be non-empty")
    action_type = str(action_type).upper().strip()
    if action_type not in ACTION_TYPES:
        raise RemediationError(
            f"Unknown action_type: {action_type!r}. Valid: {sorted(ACTION_TYPES)}"
        )
    description = str(description).strip()
    if not description:
        raise RemediationError("description must be non-empty")

    key = _remediation_key(remediation_id)
    now = _to_iso(_utc_now())
    existing = store.get_model(key)
    created_at = (existing or {}).get("metadata", {}).get("created_at") or now

    record: Dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            "remediation_id": remediation_id,
            "incident_id": incident_id,
            "model_id": str(model_id).strip() if model_id else None,
            "action_type": action_type,
            "description": description,
            "status": REMEDIATION_PENDING,
            "assigned_to": str(assigned_to).strip() if assigned_to else None,
            "due_date": due_date,
            "resolution_note": None,
            "status_history": [{"status": REMEDIATION_PENDING, "at": now}],
            "created_at": created_at,
            "updated_at": now,
            "resolved_at": None,
            "remediation_version": REMEDIATION_VERSION,
        },
    }
    store.save_model(record)
    return _summary(record)


def get_remediation(remediation_id: str, store: Any) -> Optional[Dict[str, Any]]:
    record = store.get_model(_remediation_key(remediation_id))
    return _summary(record) if record else None


def update_remediation_status(
    remediation_id: str,
    new_status: str,
    store: Any,
    *,
    resolution_note: Optional[str] = None,
) -> Dict[str, Any]:
    key = _remediation_key(remediation_id)
    record = store.get_model(key)
    if not record:
        raise RemediationError(f"Remediation not found: {remediation_id!r}")

    new_status = str(new_status).upper().strip()
    if new_status not in REMEDIATION_STATUSES:
        raise RemediationError(
            f"Invalid status: {new_status!r}. Valid: {sorted(REMEDIATION_STATUSES)}"
        )

    current = record["metadata"]["status"]
    if current in _TERMINAL_STATUSES:
        raise RemediationError(
            f"Remediation {remediation_id!r} is already in terminal state {current!r}"
        )

    now = _to_iso(_utc_now())
    record["metadata"]["status"] = new_status
    record["metadata"]["updated_at"] = now
    if resolution_note:
        record["metadata"]["resolution_note"] = str(resolution_note).strip()
    if new_status in _TERMINAL_STATUSES:
        record["metadata"]["resolved_at"] = now

    history = list(record["metadata"].get("status_history") or [])
    history.append({"status": new_status, "at": now, "note": resolution_note or ""})
    record["metadata"]["status_history"] = history

    store.save_model(record)
    return _summary(record)


def list_remediations(
    store: Any,
    *,
    incident_id: Optional[str] = None,
    model_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_REMEDIATION_PREFIX):
            continue
        s = _summary(m)
        if incident_id and s.get("incident_id") != str(incident_id).strip():
            continue
        if model_id and s.get("model_id") != str(model_id).strip():
            continue
        if status and s.get("status") != str(status).upper():
            continue
        result.append(s)
    result.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return result[:limit]


def link_to_incident(
    remediation_id: str,
    incident_id: str,
    store: Any,
) -> Dict[str, Any]:
    """Re-link a remediation to a different incident."""
    key = _remediation_key(remediation_id)
    record = store.get_model(key)
    if not record:
        raise RemediationError(f"Remediation not found: {remediation_id!r}")
    incident_id = str(incident_id).strip()
    if not incident_id:
        raise RemediationError("incident_id must be non-empty")
    record["metadata"]["incident_id"] = incident_id
    record["metadata"]["updated_at"] = _to_iso(_utc_now())
    store.save_model(record)
    return _summary(record)

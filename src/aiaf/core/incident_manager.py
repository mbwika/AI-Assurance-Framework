"""Incident Manager.

Lifecycle management for security incidents detected by AIAF's
continuous security operations layer.  Incidents flow through a
well-defined state machine; notes and state transitions are appended
to an immutable audit trail inside the record.

Storage
-------
Incidents are stored under ``"incident:{incident_id}"``.

Evidence origin
---------------
LOCALLY_OBSERVED — the framework records and tracks incidents; the
calling code is responsible for supplying the origin of the underlying
finding that triggered the incident.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

INCIDENT_VERSION = "1.0"

_INCIDENT_PREFIX = "incident:"
_MAX_NOTES = 200

# ── Severity ───────────────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_VALUES: frozenset = frozenset(
    {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}
)

_SEVERITY_RANK: Dict[str, int] = {
    SEVERITY_CRITICAL: 4, SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2, SEVERITY_LOW: 1, SEVERITY_INFO: 0,
}

# ── State machine ──────────────────────────────────────────────────────────────
STATE_OPEN = "OPEN"
STATE_INVESTIGATING = "INVESTIGATING"
STATE_CONTAINED = "CONTAINED"
STATE_RESOLVED = "RESOLVED"
STATE_ACCEPTED = "ACCEPTED"

STATE_VALUES: frozenset = frozenset(
    {STATE_OPEN, STATE_INVESTIGATING, STATE_CONTAINED, STATE_RESOLVED, STATE_ACCEPTED}
)

_TERMINAL_STATES: frozenset = frozenset({STATE_RESOLVED, STATE_ACCEPTED})

_ALLOWED_TRANSITIONS: Dict[str, frozenset] = {
    STATE_OPEN: frozenset({STATE_INVESTIGATING, STATE_CONTAINED, STATE_RESOLVED, STATE_ACCEPTED}),
    STATE_INVESTIGATING: frozenset({STATE_CONTAINED, STATE_RESOLVED, STATE_ACCEPTED}),
    STATE_CONTAINED: frozenset({STATE_RESOLVED, STATE_ACCEPTED}),
    STATE_RESOLVED: frozenset(),
    STATE_ACCEPTED: frozenset(),
}


class IncidentError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _incident_key(incident_id: str) -> str:
    return f"{_INCIDENT_PREFIX}{incident_id}"


def _summary(record: Dict[str, Any]) -> Dict[str, Any]:
    m = record.get("metadata") or {}
    return {
        "incident_id": m.get("incident_id"),
        "title": m.get("title"),
        "severity": m.get("severity"),
        "state": m.get("state"),
        "source": m.get("source"),
        "model_id": m.get("model_id"),
        "description": m.get("description"),
        "findings": m.get("findings") or [],
        "tags": m.get("tags") or [],
        "notes": m.get("notes") or [],
        "state_history": m.get("state_history") or [],
        "evidence_origin": m.get("evidence_origin", "LOCALLY_OBSERVED"),
        "created_at": m.get("created_at"),
        "updated_at": m.get("updated_at"),
        "resolved_at": m.get("resolved_at"),
        "incident_version": m.get("incident_version", INCIDENT_VERSION),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def create_incident(
    incident_id: str,
    title: str,
    severity: str,
    source: str,
    model_id: str,
    store: Any,
    *,
    description: Optional[str] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    evidence_origin: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    incident_id = str(incident_id).strip()
    if not incident_id:
        raise IncidentError("incident_id must be non-empty")
    title = str(title).strip()
    if not title:
        raise IncidentError("title must be non-empty")
    severity = str(severity).upper().strip()
    if severity not in SEVERITY_VALUES:
        raise IncidentError(f"Invalid severity: {severity!r}. Valid: {sorted(SEVERITY_VALUES)}")

    key = _incident_key(incident_id)
    now = _to_iso(_utc_now())
    existing = store.get_model(key)
    created_at = (existing or {}).get("metadata", {}).get("created_at") or now

    record: Dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "state": STATE_OPEN,
            "source": str(source).strip(),
            "model_id": str(model_id).strip(),
            "description": str(description).strip() if description else None,
            "findings": list(findings) if findings else [],
            "tags": list(tags) if tags else [],
            "notes": [],
            "state_history": [{"state": STATE_OPEN, "at": now, "note": "Incident created"}],
            "evidence_origin": evidence_origin or "LOCALLY_OBSERVED",
            "created_at": created_at,
            "updated_at": now,
            "resolved_at": None,
            "incident_version": INCIDENT_VERSION,
        },
    }
    store.save_model(record)
    return _summary(record)


def get_incident(incident_id: str, store: Any) -> Optional[Dict[str, Any]]:
    record = store.get_model(_incident_key(incident_id))
    return _summary(record) if record else None


def list_incidents(
    store: Any,
    *,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    model_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_INCIDENT_PREFIX):
            continue
        s = _summary(m)
        if severity and s.get("severity") != str(severity).upper():
            continue
        if state and s.get("state") != str(state).upper():
            continue
        if model_id and s.get("model_id") != str(model_id).strip():
            continue
        result.append(s)
    result.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return result[:limit]


def update_incident_state(
    incident_id: str,
    new_state: str,
    store: Any,
    *,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    key = _incident_key(incident_id)
    record = store.get_model(key)
    if not record:
        raise IncidentError(f"Incident not found: {incident_id!r}")

    new_state = str(new_state).upper().strip()
    if new_state not in STATE_VALUES:
        raise IncidentError(f"Invalid state: {new_state!r}. Valid: {sorted(STATE_VALUES)}")

    current = record["metadata"]["state"]
    allowed = _ALLOWED_TRANSITIONS.get(current, frozenset())
    if new_state not in allowed:
        raise IncidentError(
            f"Transition {current!r} → {new_state!r} not allowed. "
            f"Allowed: {sorted(allowed) or ['none (terminal state)']}"
        )

    now = _to_iso(_utc_now())
    record["metadata"]["state"] = new_state
    record["metadata"]["updated_at"] = now
    if new_state in _TERMINAL_STATES:
        record["metadata"]["resolved_at"] = now

    history = list(record["metadata"].get("state_history") or [])
    history.append({"state": new_state, "at": now, "note": note or ""})
    record["metadata"]["state_history"] = history

    store.save_model(record)
    return _summary(record)


def add_incident_note(
    incident_id: str,
    note: str,
    store: Any,
    *,
    author: Optional[str] = None,
) -> Dict[str, Any]:
    key = _incident_key(incident_id)
    record = store.get_model(key)
    if not record:
        raise IncidentError(f"Incident not found: {incident_id!r}")
    note = str(note).strip()
    if not note:
        raise IncidentError("note must be non-empty")

    now = _to_iso(_utc_now())
    notes = list(record["metadata"].get("notes") or [])
    notes.append({"text": note, "author": author, "at": now})
    if len(notes) > _MAX_NOTES:
        notes = notes[-_MAX_NOTES:]
    record["metadata"]["notes"] = notes
    record["metadata"]["updated_at"] = now
    store.save_model(record)
    return _summary(record)


def snapshot_incident(incident_id: str, store: Any) -> Dict[str, Any]:
    """Return a point-in-time snapshot dict of the incident (immutable copy)."""
    record = store.get_model(_incident_key(incident_id))
    if not record:
        raise IncidentError(f"Incident not found: {incident_id!r}")
    s = _summary(record)
    s["snapshot_at"] = _to_iso(_utc_now())
    s["is_snapshot"] = True
    return s

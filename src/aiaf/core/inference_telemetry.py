"""Runtime Inference Telemetry Sink.

Ingests live prompt/response/tool-call pairs from an AIAF proxy sidecar or
from third-party guardrail providers and folds them into the AIAF evidence
model as LOCALLY_OBSERVED findings.

Design principles
-----------------
* Content privacy: raw prompt/response text is never stored.  Only
  ``content_hash`` (SHA-256) is persisted so operators can correlate events
  without reproducing personal data.
* Immutability: events are append-only; re-ingesting an event_id is a no-op.
* Bounded storage: sessions retain the last MAX_SESSION_EVENTS events; older
  events are summarised and dropped.
* Evidence taxonomy: every event is LOCALLY_OBSERVED.  The summary feeds
  the FactLedger in the same way as other AIAF live-evidence modules.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

TELEMETRY_VERSION = "1.0"
_SESSION_PREFIX = "session:"
MAX_SESSION_EVENTS = 1000

VALID_EVENT_TYPES = frozenset({
    "tool_call",
    "llm_completion",
    "user_message",
    "agent_action",
    "error",
    "session_start",
    "session_end",
    "guardrail_block",
    "custom",
})

VALID_STATUSES = frozenset({"ok", "error", "timeout", "blocked"})


# ── Helpers ──────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _session_key(session_id: str) -> str:
    return f"{_SESSION_PREFIX}{session_id}"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _coerce_positive_float(v: Any) -> float | None:
    try:
        f = float(v)
        return f if f >= 0 else None
    except (TypeError, ValueError):
        return None


def _coerce_non_negative_int(v: Any) -> int | None:
    try:
        i = int(v)
        return i if i >= 0 else None
    except (TypeError, ValueError):
        return None


# ── Validation ────────────────────────────────────────────────────────────────

class TelemetryValidationError(ValueError):
    pass


def _validate_session_id(session_id: str) -> str:
    if not session_id or not session_id.strip():
        raise TelemetryValidationError("session_id must be a non-empty string")
    return session_id.strip()


def _normalise_event(
    raw: dict[str, Any],
    session_id: str,
    sequence: int,
    server_ts: str,
) -> dict[str, Any]:
    """Validate and normalise a single raw event dict."""
    event_type = str(raw.get("event_type") or "").strip().lower()
    if event_type not in VALID_EVENT_TYPES:
        raise TelemetryValidationError(
            f"Unknown event_type {event_type!r}; "
            f"valid types: {sorted(VALID_EVENT_TYPES)}"
        )

    status = str(raw.get("status") or "ok").strip().lower()
    if status not in VALID_STATUSES:
        status = "ok"

    event: dict[str, Any] = {
        "session_id": session_id,
        "event_id": str(raw.get("event_id") or _sha256(f"{session_id}:{sequence}:{server_ts}")),
        "event_type": event_type,
        "sequence": sequence,
        "timestamp": str(raw.get("timestamp") or server_ts),
        "status": status,
        "latency_ms": _coerce_positive_float(raw.get("latency_ms")),
        "token_count": _coerce_non_negative_int(raw.get("token_count")),
        "tool_name": str(raw["tool_name"]).strip() if raw.get("tool_name") else None,
        "model_id": str(raw["model_id"]).strip() if raw.get("model_id") else None,
        "content_hash": str(raw["content_hash"]).strip() if raw.get("content_hash") else None,
        "metadata": raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {},
        "evidence_origin": "LOCALLY_OBSERVED",
    }
    return event


# ── Core functions ────────────────────────────────────────────────────────────

def ingest_events(
    session_id: str,
    raw_events: list[dict[str, Any]],
    store: Any,
) -> dict[str, Any]:
    """Validate and persist a batch of trace events for ``session_id``.

    Returns a summary of the ingest operation.  Idempotent on duplicate
    ``event_id`` values within a session (existing events are skipped).

    Parameters
    ----------
    session_id:
        Logical agent/inference session identifier.
    raw_events:
        List of raw event dicts from the caller.
    store:
        AIAF model store (must support ``get_model`` / ``save_model``).
    """
    session_id = _validate_session_id(session_id)
    if not raw_events:
        return {
            "session_id": session_id,
            "accepted": 0,
            "rejected": 0,
            "errors": [],
            "telemetry_version": TELEMETRY_VERSION,
        }

    key = _session_key(session_id)
    record = store.get_model(key) or {
        "model_id": key,
        "id": key,
        "metadata": {},
    }
    meta = record.setdefault("metadata", {})
    existing_events: list[dict[str, Any]] = meta.get("events") or []
    existing_ids = {e["event_id"] for e in existing_events}
    next_seq = max((e.get("sequence", 0) for e in existing_events), default=-1) + 1

    server_ts = _utc_now()
    accepted: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for i, raw in enumerate(raw_events):
        try:
            event = _normalise_event(raw, session_id, next_seq, server_ts)
        except TelemetryValidationError as exc:
            errors.append({"index": i, "error": str(exc)})
            continue

        if event["event_id"] in existing_ids:
            continue  # idempotent: skip duplicate

        existing_ids.add(event["event_id"])
        accepted.append(event)
        next_seq += 1

    all_events = existing_events + accepted
    # Rolling window: keep only the tail
    if len(all_events) > MAX_SESSION_EVENTS:
        all_events = all_events[-MAX_SESSION_EVENTS:]

    meta["events"] = all_events
    meta["session_id"] = session_id
    meta["telemetry_version"] = TELEMETRY_VERSION
    meta["last_ingested_at"] = server_ts
    meta["registered_at"] = meta.get("registered_at") or server_ts
    meta["summary"] = _compute_summary(session_id, all_events)

    record["metadata"] = meta
    store.save_model(record)

    return {
        "session_id": session_id,
        "accepted": len(accepted),
        "rejected": len(errors),
        "errors": errors,
        "event_count": len(all_events),
        "summary": meta["summary"],
        "telemetry_version": TELEMETRY_VERSION,
    }


def get_session(session_id: str, store: Any) -> dict[str, Any] | None:
    """Return the full session record (events list + summary), or ``None``."""
    session_id = _validate_session_id(session_id)
    record = store.get_model(_session_key(session_id))
    if not record:
        return None
    meta = record.get("metadata") or {}
    return {
        "session_id": session_id,
        "summary": meta.get("summary") or {},
        "events": meta.get("events") or [],
        "telemetry_version": meta.get("telemetry_version", TELEMETRY_VERSION),
        "registered_at": meta.get("registered_at"),
        "last_ingested_at": meta.get("last_ingested_at"),
    }


def get_session_events(
    session_id: str,
    store: Any,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], int]:
    """Return a paginated slice of events and the total count."""
    session_id = _validate_session_id(session_id)
    record = store.get_model(_session_key(session_id))
    if not record:
        return [], 0
    events = (record.get("metadata") or {}).get("events") or []
    total = len(events)
    page = events[offset: offset + limit]
    return page, total


def list_sessions(store: Any, limit: int = 50) -> list[dict[str, Any]]:
    """Return summary metadata for up to ``limit`` recent sessions."""
    all_models = store.list_models() if hasattr(store, "list_models") else []
    sessions = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_SESSION_PREFIX):
            continue
        meta = m.get("metadata") or {}
        summary = meta.get("summary") or {}
        sessions.append({
            "session_id": meta.get("session_id") or mid.removeprefix(_SESSION_PREFIX),
            "event_count": summary.get("event_count", 0),
            "error_rate": summary.get("error_rate"),
            "duration_ms": summary.get("duration_ms"),
            "status": summary.get("session_status"),
            "last_ingested_at": meta.get("last_ingested_at"),
        })
    # Most recently updated first
    sessions.sort(key=lambda s: s.get("last_ingested_at") or "", reverse=True)
    return sessions[:limit]


def delete_session(session_id: str, store: Any) -> bool:
    """Delete all stored events for a session.  Returns True if deleted."""
    session_id = _validate_session_id(session_id)
    key = _session_key(session_id)
    record = store.get_model(key)
    if not record:
        return False
    # Overwrite with empty metadata (preserve the record shell for audit trail)
    meta = record.get("metadata") or {}
    meta["events"] = []
    meta["summary"] = {}
    meta["deleted_at"] = _utc_now()
    record["metadata"] = meta
    store.save_model(record)
    return True


# ── Summary computation ───────────────────────────────────────────────────────

def _compute_summary(session_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute session-level aggregate metrics from an events list."""
    if not events:
        return {
            "session_id": session_id,
            "event_count": 0,
            "evidence_origin": "LOCALLY_OBSERVED",
            "telemetry_version": TELEMETRY_VERSION,
        }

    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    tool_names: set = set()
    models_seen: set = set()
    total_latency = 0.0
    total_tokens = 0
    latency_count = 0
    error_count = 0
    block_count = 0

    timestamps = []
    for ev in events:
        et = ev.get("event_type", "custom")
        by_type[et] = by_type.get(et, 0) + 1

        st = ev.get("status", "ok")
        by_status[st] = by_status.get(st, 0) + 1

        if ev.get("tool_name"):
            tool_names.add(ev["tool_name"])
        if ev.get("model_id"):
            models_seen.add(ev["model_id"])

        lat = ev.get("latency_ms")
        if lat is not None:
            total_latency += lat
            latency_count += 1

        tok = ev.get("token_count")
        if tok is not None:
            total_tokens += tok

        if st == "error":
            error_count += 1
        if st == "blocked":
            block_count += 1

        ts = ev.get("timestamp")
        if ts:
            timestamps.append(ts)

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    # Duration: best-effort ISO-string compare (lexicographic works for UTC ISO strings)
    duration_ms: float | None = None
    if first_ts and last_ts and first_ts != last_ts:
        try:
            t0 = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            duration_ms = (t1 - t0).total_seconds() * 1000
        except Exception:
            pass

    n = len(events)
    error_rate = round(error_count / n, 4) if n else 0.0

    # Session-level status heuristic
    if block_count > 0:
        session_status = "BLOCKED"
    elif error_rate > 0.2:
        session_status = "DEGRADED"
    elif error_count > 0:
        session_status = "PARTIAL_ERRORS"
    else:
        session_status = "OK"

    return {
        "session_id": session_id,
        "event_count": n,
        "first_event_at": first_ts,
        "last_event_at": last_ts,
        "duration_ms": duration_ms,
        "by_event_type": by_type,
        "by_status": by_status,
        "total_latency_ms": round(total_latency, 2) if latency_count else None,
        "mean_latency_ms": round(total_latency / latency_count, 2) if latency_count else None,
        "total_tokens": total_tokens or None,
        "tool_names_seen": sorted(tool_names),
        "models_seen": sorted(models_seen),
        "error_count": error_count,
        "error_rate": error_rate,
        "block_count": block_count,
        "session_status": session_status,
        "evidence_origin": "LOCALLY_OBSERVED",
        "telemetry_version": TELEMETRY_VERSION,
    }

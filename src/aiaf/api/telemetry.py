"""Runtime Inference Telemetry API.

Receives live prompt/response/tool-call events from agent sidecars or
guardrail providers and stores them as LOCALLY_OBSERVED evidence tied to
a logical session.  Downstream consumers (behavioral baseline, action ledger,
reporting) read from the same session store.

Evidence model
--------------
Every ingested event is tagged LOCALLY_OBSERVED.  Raw content is never stored
— only ``content_hash`` (SHA-256 the caller computes before sending).
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.inference_telemetry import (
    TELEMETRY_VERSION,
    TelemetryValidationError,
    delete_session,
    get_session,
    get_session_events,
    ingest_events,
    list_sessions,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/telemetry", tags=["telemetry"])


class TraceEventRequest(BaseModel):
    event_type: str
    timestamp: str | None = None
    event_id: str | None = None
    latency_ms: float | None = None
    token_count: int | None = None
    tool_name: str | None = None
    model_id: str | None = None
    content_hash: str | None = None
    status: str = "ok"
    metadata: dict[str, Any] = {}


class IngestRequest(BaseModel):
    session_id: str
    events: list[TraceEventRequest]


@router.post("/traces", summary="Ingest trace events for a session")
def ingest_traces(req: IngestRequest, api_key: str = Depends(get_api_key)):
    """Ingest a batch of trace events for the given session.

    Events are idempotent on ``event_id``; re-ingesting an already-seen
    event_id is silently skipped.  The response includes the number of
    accepted vs. rejected events and an updated session summary.
    """
    store = get_store()
    try:
        result = ingest_events(
            req.session_id,
            [e.model_dump() for e in req.events],
            store,
        )
    except TelemetryValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@router.get("/sessions", summary="List telemetry sessions")
def list_telemetry_sessions(
    limit: int = Query(default=50, ge=1, le=500),
    api_key: str = Depends(get_api_key),
):
    """Return summary metadata for recent telemetry sessions, newest first."""
    store = get_store()
    sessions = list_sessions(store, limit=limit)
    return {
        "sessions": sessions,
        "count": len(sessions),
        "telemetry_version": TELEMETRY_VERSION,
    }


@router.get("/sessions/{session_id}", summary="Get session summary and events")
def get_telemetry_session(session_id: str, api_key: str = Depends(get_api_key)):
    """Return the full session record: summary metrics plus the event list."""
    store = get_store()
    record = get_session(session_id, store)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found.",
        )
    return record


@router.get(
    "/sessions/{session_id}/events",
    summary="Paginated event list for a session",
)
def get_telemetry_session_events(
    session_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    api_key: str = Depends(get_api_key),
):
    """Return a paginated slice of raw events for the given session."""
    store = get_store()
    events, total = get_session_events(session_id, store, offset=offset, limit=limit)
    if total == 0 and offset == 0:
        # Distinguish "no events yet" from "session not found"
        existing = get_session(session_id, store)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail=f"Session '{session_id}' not found.",
            )
    return {
        "session_id": session_id,
        "offset": offset,
        "limit": limit,
        "total": total,
        "events": events,
    }


@router.delete(
    "/sessions/{session_id}",
    summary="Delete stored events for a session",
)
def delete_telemetry_session(session_id: str, api_key: str = Depends(get_api_key)):
    """Delete all stored events for a session.

    The session record shell is preserved with a ``deleted_at`` timestamp for
    audit-trail continuity; only the event payload is cleared.
    """
    store = get_store()
    deleted = delete_session(session_id, store)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found.",
        )
    return {"session_id": session_id, "deleted": True}

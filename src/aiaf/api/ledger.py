"""Agent Action Ledger API.

Hash-chained append-only log of tool invocations.  Each entry is chained to
its predecessor via SHA-256; the ``verify`` endpoint replays the chain to
detect any tampering or out-of-order insertion.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.agent_action_ledger import (
    LEDGER_VERSION,
    LedgerValidationError,
    append_entry,
    get_ledger,
    get_ledger_entries,
    list_ledgers,
    verify_chain,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/ledger", tags=["ledger"])


class AppendEntryRequest(BaseModel):
    tool_name: str
    input_hash: str
    decision: str = "ALLOW"
    timestamp: str | None = None
    metadata: dict[str, Any] = {}


@router.post(
    "/sessions/{session_id}/entries",
    summary="Append a tool-invocation entry to the action ledger",
)
def ledger_append(
    session_id: str,
    req: AppendEntryRequest,
    api_key: str = Depends(get_api_key),
):
    """Append a hash-chained entry to the action ledger for ``session_id``.

    * ``tool_name`` — name of the tool that was or will be invoked.
    * ``input_hash`` — SHA-256 of the sanitised tool arguments (raw args are
      never stored; the caller computes the hash before calling this endpoint).
    * ``decision`` — ``ALLOW`` (tool invocation proceeded), ``DENY``
      (invocation was blocked), or ``FLAG`` (invocation was permitted but
      flagged for review).
    """
    store = get_store()
    try:
        entry = append_entry(
            session_id,
            req.tool_name,
            req.input_hash,
            req.decision,
            store,
            metadata=req.metadata,
            timestamp=req.timestamp,
        )
    except LedgerValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return entry


@router.get(
    "/sessions",
    summary="List agent action ledger sessions",
)
def ledger_list_sessions(
    limit: int = Query(default=50, ge=1, le=500),
    api_key: str = Depends(get_api_key),
):
    """Return summary metadata for recent ledger sessions, newest first."""
    store = get_store()
    sessions = list_ledgers(store, limit=limit)
    return {
        "sessions": sessions,
        "count": len(sessions),
        "ledger_version": LEDGER_VERSION,
    }


@router.get(
    "/sessions/{session_id}",
    summary="Get the action ledger for a session",
)
def ledger_get_session(session_id: str, api_key: str = Depends(get_api_key)):
    """Return the full ledger (all entries) for the given session."""
    store = get_store()
    ledger = get_ledger(session_id, store)
    if ledger is None:
        raise HTTPException(
            status_code=404,
            detail=f"Ledger for session '{session_id}' not found.",
        )
    return ledger


@router.get(
    "/sessions/{session_id}/entries",
    summary="Paginated entry list for a ledger session",
)
def ledger_get_entries(
    session_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    api_key: str = Depends(get_api_key),
):
    """Return a paginated slice of ledger entries for the given session."""
    store = get_store()
    entries, total = get_ledger_entries(session_id, store, offset=offset, limit=limit)
    if total == 0 and offset == 0:
        existing = get_ledger(session_id, store)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail=f"Ledger for session '{session_id}' not found.",
            )
    return {
        "session_id": session_id,
        "offset": offset,
        "limit": limit,
        "total": total,
        "entries": entries,
    }


@router.get(
    "/sessions/{session_id}/verify",
    summary="Verify the hash chain integrity of a ledger session",
)
def ledger_verify(session_id: str, api_key: str = Depends(get_api_key)):
    """Replay the hash chain for ``session_id`` and report integrity status.

    A ``chain_valid: true`` result means no entry has been modified, deleted,
    or inserted since it was appended.  ``tampered_at_sequence`` identifies
    the first broken link when tampering is detected.
    """
    store = get_store()
    return verify_chain(session_id, store)

"""MCP server tool supply-chain scanning API.

Endpoints for registering MCP servers, scanning their tool descriptors for
injection/rug-pull/SSRF risks, and retrieving scan history.

Evidence model
--------------
Tool descriptors are PROVIDER_DECLARED (the server says what tools do).
Scan findings are LOCALLY_OBSERVED (AIAF derived them from the bytes).
Rug-pull diffs are LOCALLY_OBSERVED meta-evidence (AIAF observed the change).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..registry.mcp_scanner import scan_server_tools
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/mcp", tags=["mcp"])

_MCP_SERVER_PREFIX = "mcp_server:"


class MCPScanRequest(BaseModel):
    server_id: str
    tools: List[Dict[str, Any]]
    persist: bool = True


class MCPRescanRequest(BaseModel):
    tools: List[Dict[str, Any]]
    persist: bool = True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _store_key(server_id: str) -> str:
    return f"{_MCP_SERVER_PREFIX}{server_id}"


def _get_server_record(store, server_id: str) -> Optional[Dict[str, Any]]:
    return store.get_model(_store_key(server_id))


def _save_server_record(store, server_id: str, record: Dict[str, Any]) -> None:
    record.setdefault("model_id", _store_key(server_id))
    record.setdefault("id", _store_key(server_id))
    store.save_model(record)


def _append_scan_history(record: Dict[str, Any], scan_result: Dict[str, Any]) -> None:
    meta = record.setdefault("metadata", {})
    history = meta.setdefault("scan_history", [])
    history.append({
        "status": scan_result.get("status"),
        "rug_pull_detected": scan_result.get("rug_pull_detected"),
        "tool_count": scan_result.get("tool_count"),
        "match_count": scan_result.get("match_count"),
        "by_severity": scan_result.get("by_severity"),
        "scanned_at": scan_result.get("scanned_at"),
    })
    # Keep the last 50 scan summaries only
    meta["scan_history"] = history[-50:]


@router.post("/servers", summary="Register MCP server and scan its tools")
def register_and_scan(req: MCPScanRequest, api_key: str = Depends(get_api_key)):
    """Register an MCP server, scan its tool descriptors, and optionally persist
    the result as the baseline snapshot for future rug-pull detection.

    Pass ``persist=true`` (default) to store the snapshot so that subsequent
    calls to ``POST /v1/mcp/servers/{server_id}/scan`` can detect rug-pulls.
    """
    store = get_store()
    existing = _get_server_record(store, req.server_id)

    # No previous snapshot on first registration — this establishes the baseline
    scan_result = scan_server_tools(req.tools, req.server_id, previous_snapshot=None)

    if req.persist:
        record: Dict[str, Any] = existing or {
            "model_id": _store_key(req.server_id),
            "id": _store_key(req.server_id),
            "metadata": {},
        }
        meta = record.setdefault("metadata", {})
        meta["server_id"] = req.server_id
        meta["latest_scan"] = scan_result
        meta["snapshot"] = scan_result.get("snapshot") or {}
        meta["tool_hashes"] = scan_result.get("tool_hashes") or {}
        meta["registered_at"] = meta.get("registered_at") or _utc_now()
        _append_scan_history(record, scan_result)
        _save_server_record(store, req.server_id, record)
        _save_audit(store, req.server_id, scan_result, "mcp_server_registered")

    return scan_result


@router.get("/servers", summary="List registered MCP servers")
def list_servers(api_key: str = Depends(get_api_key)):
    """Return a summary list of all registered MCP servers."""
    store = get_store()
    all_models = store.list_models() if hasattr(store, "list_models") else []
    servers = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_MCP_SERVER_PREFIX):
            continue
        meta = m.get("metadata") or {}
        latest = meta.get("latest_scan") or {}
        servers.append({
            "server_id": meta.get("server_id") or mid.removeprefix(_MCP_SERVER_PREFIX),
            "status": latest.get("status"),
            "rug_pull_detected": latest.get("rug_pull_detected"),
            "tool_count": latest.get("tool_count"),
            "match_count": latest.get("match_count"),
            "last_scanned_at": latest.get("scanned_at"),
            "registered_at": meta.get("registered_at"),
        })
    return {"servers": servers, "count": len(servers)}


@router.get("/servers/{server_id}", summary="Get latest MCP server scan result")
def get_server(server_id: str, api_key: str = Depends(get_api_key)):
    """Return the most recent scan result for the given MCP server."""
    store = get_store()
    record = _get_server_record(store, server_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"MCP server '{server_id}' not found. Register it first via POST /v1/mcp/servers.")
    meta = record.get("metadata") or {}
    latest = meta.get("latest_scan")
    if not latest:
        raise HTTPException(status_code=404, detail="No scan result found for this server.")
    return latest


@router.post("/servers/{server_id}/scan", summary="Re-scan MCP server tools (rug-pull detection)")
def rescan_server(
    server_id: str,
    req: MCPRescanRequest,
    api_key: str = Depends(get_api_key),
):
    """Re-scan an already-registered MCP server's tool descriptors.

    Compares the current tools against the stored baseline snapshot to detect
    rug-pull attacks (tool descriptions or schemas changed since last scan).
    The result is stored and the new snapshot replaces the baseline.
    """
    store = get_store()
    record = _get_server_record(store, server_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"MCP server '{server_id}' not found. Register it first via POST /v1/mcp/servers.",
        )
    meta = record.get("metadata") or {}
    previous_snapshot = meta.get("latest_scan")  # full prior result for rug-pull diff

    scan_result = scan_server_tools(req.tools, server_id, previous_snapshot=previous_snapshot)

    if req.persist:
        meta["latest_scan"] = scan_result
        meta["snapshot"] = scan_result.get("snapshot") or {}
        meta["tool_hashes"] = scan_result.get("tool_hashes") or {}
        record["metadata"] = meta
        _append_scan_history(record, scan_result)
        _save_server_record(store, server_id, record)
        _save_audit(store, server_id, scan_result, "mcp_server_rescanned")

    return scan_result


@router.get("/servers/{server_id}/history", summary="Get MCP server scan history")
def scan_history(server_id: str, api_key: str = Depends(get_api_key)):
    """Return the last 50 scan summaries for the given MCP server."""
    store = get_store()
    record = _get_server_record(store, server_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"MCP server '{server_id}' not found.",
        )
    meta = record.get("metadata") or {}
    history = meta.get("scan_history") or []
    return {
        "server_id": server_id,
        "scan_count": len(history),
        "history": history,
    }


def _save_audit(store, server_id: str, scan_result: Dict[str, Any], event_type: str) -> None:
    try:
        store.save_audit_log({
            "event_type": event_type,
            "artifact_id": _store_key(server_id),
            "details": {
                "server_id": server_id,
                "status": scan_result.get("status"),
                "rug_pull_detected": scan_result.get("rug_pull_detected"),
                "tool_count": scan_result.get("tool_count"),
                "match_count": scan_result.get("match_count"),
            },
        })
    except Exception:
        pass

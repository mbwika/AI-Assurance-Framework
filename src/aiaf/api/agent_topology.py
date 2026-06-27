"""Multi-Agent Topology & Cascade Analyzer API.

REST endpoints:
  POST /v1/topology                            — register topology
  GET  /v1/topology/{id}                       — get topology metadata
  POST /v1/topology/{id}/nodes                 — add node
  POST /v1/topology/{id}/edges                 — add edge
  GET  /v1/topology/{id}/analyze               — run full analysis
  GET  /v1/topology/layers                     — list trust levels
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .models import get_api_key, get_store
from ..analysis.agent_topology import (
    TRUST_LEVELS, NODE_TYPES, CHANNEL_TYPES,
    TOPOLOGY_RISK_LOW, TOPOLOGY_RISK_MEDIUM, TOPOLOGY_RISK_HIGH, TOPOLOGY_RISK_CRITICAL,
    AgentTopologyError,
    register_topology, get_topology,
    add_agent_node, add_communication_edge,
    analyze_topology,
)

router = APIRouter(prefix="/v1/topology", tags=["agent-topology"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterTopologyRequest(BaseModel):
    topology_id: str
    name: Optional[str] = None
    description: Optional[str] = None


class AddNodeRequest(BaseModel):
    node_id: str
    node_type: str
    trust_level: str
    has_guardrail: bool = False
    capabilities: Optional[List[str]] = None
    internet_facing: bool = False
    attributes: Optional[Dict[str, Any]] = None


class AddEdgeRequest(BaseModel):
    from_node_id: str
    to_node_id: str
    channel: str = "DIRECT_CALL"
    bidirectional: bool = False
    has_guardrail: bool = False
    attributes: Optional[Dict[str, Any]] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
def register_topology_route(
    req: RegisterTopologyRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return register_topology(
            req.topology_id, store,
            name=req.name, description=req.description,
        )
    except AgentTopologyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{topology_id}")
def get_topology_route(
    topology_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    meta = get_topology(topology_id, store)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Topology {topology_id!r} not found.")
    return meta


@router.post("/{topology_id}/nodes", status_code=201)
def add_node_route(
    topology_id: str,
    req: AddNodeRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return add_agent_node(
            topology_id, req.node_id, req.node_type, req.trust_level, store,
            has_guardrail=req.has_guardrail,
            capabilities=req.capabilities,
            internet_facing=req.internet_facing,
            attributes=req.attributes,
        )
    except AgentTopologyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/{topology_id}/edges", status_code=201)
def add_edge_route(
    topology_id: str,
    req: AddEdgeRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return add_communication_edge(
            topology_id, req.from_node_id, req.to_node_id, store,
            channel=req.channel,
            bidirectional=req.bidirectional,
            has_guardrail=req.has_guardrail,
            attributes=req.attributes,
        )
    except AgentTopologyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{topology_id}/analyze")
def analyze_topology_route(
    topology_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return analyze_topology(topology_id, store)
    except AgentTopologyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/meta/schema")
def get_topology_schema(_: str = Depends(get_api_key)):
    return {
        "trust_levels": sorted(TRUST_LEVELS),
        "node_types": sorted(NODE_TYPES),
        "channel_types": sorted(CHANNEL_TYPES),
        "risk_levels": [
            TOPOLOGY_RISK_LOW, TOPOLOGY_RISK_MEDIUM,
            TOPOLOGY_RISK_HIGH, TOPOLOGY_RISK_CRITICAL,
        ],
    }

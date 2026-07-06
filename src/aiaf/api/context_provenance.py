"""Runtime context provenance graph API.

Routes
------
POST /v1/context-provenance/graphs                    Register an empty provenance graph
GET  /v1/context-provenance/graphs/{graph_id}          Get graph metadata
POST /v1/context-provenance/graphs/{graph_id}/nodes    Add a node
GET  /v1/context-provenance/graphs/{graph_id}/nodes    List nodes
POST /v1/context-provenance/graphs/{graph_id}/edges    Add a directed influence edge
GET  /v1/context-provenance/graphs/{graph_id}/edges    List edges
GET  /v1/context-provenance/influence                  Blast-radius lookup by source_ref
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis.context_provenance import (
    NODE_TYPES,
    REL_INFLUENCES,
    RELATIONSHIP_TYPES,
    ContextProvenanceError,
    add_influence_edge,
    add_provenance_node,
    find_influenced_by,
    get_provenance_graph,
    list_provenance_edges,
    list_provenance_nodes,
    register_provenance_graph,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/context-provenance", tags=["context-provenance"])


class RegisterGraphRequest(BaseModel):
    graph_id: str = Field(..., description="Logical identifier for this provenance graph (e.g. a session or response id)")
    session_id: str | None = Field(None, description="Agent/telemetry session this graph belongs to")
    model_id: str | None = Field(None, description="Model this graph traces context for")
    name: str | None = Field(None, description="Human-readable label; defaults to graph_id")
    metadata: dict[str, Any] | None = Field(None, description="Arbitrary extra fields")


class AddNodeRequest(BaseModel):
    node_id: str = Field(..., description="Unique node id within this graph")
    node_type: str = Field(..., description=f"One of {sorted(NODE_TYPES)}")
    source_ref: str | None = Field(None, description="External reference this node resolves from (e.g. a RAG doc_id)")
    content_hash: str | None = Field(None, description="Content hash of the underlying artifact, if any")
    metadata: dict[str, Any] | None = None


class AddEdgeRequest(BaseModel):
    from_node_id: str = Field(..., description="Upstream node id")
    to_node_id: str = Field(..., description="Downstream node id influenced by from_node_id")
    relationship: str = Field(REL_INFLUENCES, description=f"One of {sorted(RELATIONSHIP_TYPES)}")
    metadata: dict[str, Any] | None = None


@router.post("/graphs", status_code=201)
def create_graph(
    req: RegisterGraphRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Register an empty runtime context-provenance graph."""
    try:
        return register_provenance_graph(
            req.graph_id,
            store,
            session_id=req.session_id,
            model_id=req.model_id,
            name=req.name,
            metadata=req.metadata,
        )
    except ContextProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/graphs/{graph_id}")
def get_graph(
    graph_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Return provenance graph metadata (including nodes/edges/index)."""
    meta = get_provenance_graph(graph_id, store)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Provenance graph {graph_id!r} not found.")
    return meta


@router.post("/graphs/{graph_id}/nodes", status_code=201)
def create_node(
    graph_id: str,
    req: AddNodeRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Add one node (prompt, RAG document, tool output, policy/guardrail

    decision, model response, ...) to a registered provenance graph.
    """
    try:
        return add_provenance_node(
            graph_id,
            req.node_id,
            req.node_type,
            store,
            source_ref=req.source_ref,
            content_hash=req.content_hash,
            metadata=req.metadata,
        )
    except ContextProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/graphs/{graph_id}/nodes")
def get_nodes(
    graph_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return {"graph_id": graph_id, "nodes": list_provenance_nodes(graph_id, store)}


@router.post("/graphs/{graph_id}/edges", status_code=201)
def create_edge(
    graph_id: str,
    req: AddEdgeRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Add one directed influence edge between two existing nodes.

    Rejected if it would introduce a cycle (the graph is a DAG) or if either
    endpoint doesn't exist yet.
    """
    try:
        return add_influence_edge(
            graph_id,
            req.from_node_id,
            req.to_node_id,
            store,
            relationship=req.relationship,
            metadata=req.metadata,
        )
    except ContextProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/graphs/{graph_id}/edges")
def get_edges(
    graph_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return {"graph_id": graph_id, "edges": list_provenance_edges(graph_id, store)}


@router.get("/influence")
def influence(
    source_ref: str,
    graph_id: str | None = None,
    max_depth: int = 32,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Blast-radius lookup: every node downstream of ``source_ref`` across

    one graph (if ``graph_id`` given) or all registered graphs.
    """
    try:
        return find_influenced_by(source_ref, store, graph_id=graph_id, max_depth=max_depth)
    except ContextProvenanceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

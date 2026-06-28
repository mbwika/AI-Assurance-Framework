"""Runtime context provenance graph with reverse-index influence lookups.

Stores a bounded DAG of runtime influences under the generic ``provenance:``
namespace. One graph can represent a single response, session, or evaluation
run. Nodes may represent prompts, retrieved documents, tool outputs, policy
decisions, guardrail decisions, or final model responses.

The key primitive is ``find_influenced_by(source_ref)``:
1. Resolve one or more seed nodes by ``source_ref`` using a reverse index.
2. Traverse the DAG downstream to enumerate impacted nodes.

This keeps the implementation schema-free while providing the blast-radius
primitive needed by later roadmap capabilities.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime, timezone
from typing import Any

PROVENANCE_GRAPH_VERSION = "1.0"

NODE_USER_INPUT = "USER_INPUT"
NODE_SYSTEM_PROMPT = "SYSTEM_PROMPT"
NODE_PROMPT_TEMPLATE = "PROMPT_TEMPLATE"
NODE_RAG_DOCUMENT = "RAG_DOCUMENT"
NODE_TOOL_OUTPUT = "TOOL_OUTPUT"
NODE_MCP_RESOURCE = "MCP_RESOURCE"
NODE_POLICY_DECISION = "POLICY_DECISION"
NODE_GUARDRAIL_DECISION = "GUARDRAIL_DECISION"
NODE_EVALUATION_RESULT = "EVALUATION_RESULT"
NODE_MODEL_RESPONSE = "MODEL_RESPONSE"
NODE_PROVIDER_CONTEXT = "PROVIDER_CONTEXT"

NODE_TYPES: frozenset[str] = frozenset(
    {
        NODE_USER_INPUT,
        NODE_SYSTEM_PROMPT,
        NODE_PROMPT_TEMPLATE,
        NODE_RAG_DOCUMENT,
        NODE_TOOL_OUTPUT,
        NODE_MCP_RESOURCE,
        NODE_POLICY_DECISION,
        NODE_GUARDRAIL_DECISION,
        NODE_EVALUATION_RESULT,
        NODE_MODEL_RESPONSE,
        NODE_PROVIDER_CONTEXT,
    }
)

REL_INFLUENCES = "influences"
REL_FILTERED_BY = "filtered_by"
REL_EVALUATED_BY = "evaluated_by"

RELATIONSHIP_TYPES: frozenset[str] = frozenset(
    {REL_INFLUENCES, REL_FILTERED_BY, REL_EVALUATED_BY}
)

_PROVENANCE_PREFIX = "provenance:"
_MAX_NODES = 2_000
_MAX_EDGES = 10_000
_MAX_PATH_RESULTS = 5_000


class ContextProvenanceError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _graph_key(graph_id: str) -> str:
    return f"{_PROVENANCE_PREFIX}{graph_id}"


def _load_meta(record: dict[str, Any] | None) -> dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_graph_id(graph_id: str) -> str:
    graph = str(graph_id or "").strip()
    if not graph:
        raise ContextProvenanceError("graph_id must be non-empty.")
    return graph


def _validate_node_id(node_id: str) -> str:
    node = str(node_id or "").strip()
    if not node:
        raise ContextProvenanceError("node_id must be non-empty.")
    return node


def _validate_node_type(node_type: str) -> str:
    candidate = str(node_type or "").strip().upper()
    if candidate not in NODE_TYPES:
        raise ContextProvenanceError(f"Unknown node_type {node_type!r}. Valid: {sorted(NODE_TYPES)}")
    return candidate


def _validate_relationship(relationship: str) -> str:
    candidate = str(relationship or "").strip().lower()
    if candidate not in RELATIONSHIP_TYPES:
        raise ContextProvenanceError(
            f"Unknown relationship {relationship!r}. Valid: {sorted(RELATIONSHIP_TYPES)}"
        )
    return candidate


def _graph_record(graph_id: str, record: dict[str, Any] | None = None) -> dict[str, Any]:
    base = record or {"model_id": _graph_key(graph_id), "id": _graph_key(graph_id), "metadata": {}}
    metadata = base.setdefault("metadata", {})
    metadata.setdefault("graph_id", graph_id)
    metadata.setdefault("graph_version", PROVENANCE_GRAPH_VERSION)
    metadata.setdefault("nodes", {})
    metadata.setdefault("edges", [])
    metadata.setdefault("adjacency", {})
    metadata.setdefault("reverse_adjacency", {})
    metadata.setdefault("source_ref_index", {})
    metadata.setdefault("node_count", 0)
    metadata.setdefault("edge_count", 0)
    metadata.setdefault("evidence_origin", "LOCALLY_OBSERVED")
    metadata.setdefault("registered_at", _utc_now())
    metadata.setdefault("updated_at", metadata["registered_at"])
    metadata["graph_sha256"] = _graph_digest(metadata)
    return base


def _graph_digest(metadata: dict[str, Any]) -> str:
    payload = {
        "graph_id": metadata.get("graph_id"),
        "graph_version": metadata.get("graph_version"),
        "nodes": {
            node_id: metadata.get("nodes", {}).get(node_id)
            for node_id in sorted(metadata.get("nodes", {}))
        },
        "edges": sorted(
            metadata.get("edges", []),
            key=lambda item: (
                item.get("from_node_id", ""),
                item.get("to_node_id", ""),
                item.get("relationship", ""),
            ),
        ),
        "source_ref_index": {
            source_ref: sorted(node_ids)
            for source_ref, node_ids in sorted((metadata.get("source_ref_index") or {}).items())
        },
    }
    return _sha256(payload)


def _reachable(start: str, adjacency: dict[str, list[str]]) -> set[str]:
    visited: set[str] = set()
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for neighbour in adjacency.get(current, []):
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append(neighbour)
    return visited


def _all_graph_records(store: Any) -> list[dict[str, Any]]:
    return [
        record
        for record in (store.list_models() if hasattr(store, "list_models") else [])
        if str(record.get("model_id") or record.get("id") or "").startswith(_PROVENANCE_PREFIX)
    ]


def register_provenance_graph(
    graph_id: str,
    store: Any,
    *,
    session_id: str | None = None,
    model_id: str | None = None,
    name: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register an empty provenance graph."""
    graph_id = _validate_graph_id(graph_id)
    record = _graph_record(graph_id)
    meta = record["metadata"]
    meta["name"] = name or graph_id
    meta["session_id"] = session_id
    meta["model_id"] = model_id
    meta["custom_metadata"] = dict(metadata or {})
    meta["graph_sha256"] = _graph_digest(meta)
    store.save_model(record)
    return _load_meta(store.get_model(_graph_key(graph_id)))


def get_provenance_graph(graph_id: str, store: Any) -> dict[str, Any] | None:
    """Return provenance graph metadata, or None if missing."""
    graph_id = _validate_graph_id(graph_id)
    record = store.get_model(_graph_key(graph_id))
    return _load_meta(record) if record else None


def add_provenance_node(
    graph_id: str,
    node_id: str,
    node_type: str,
    store: Any,
    *,
    source_ref: str | None = None,
    content_hash: str | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Add one node to the provenance graph."""
    graph_id = _validate_graph_id(graph_id)
    node_id = _validate_node_id(node_id)
    node_type = _validate_node_type(node_type)
    record = store.get_model(_graph_key(graph_id))
    if not record:
        raise ContextProvenanceError(f"Provenance graph {graph_id!r} is not registered.")
    base = _graph_record(graph_id, record)
    meta = base["metadata"]
    nodes = meta["nodes"]
    if node_id in nodes:
        raise ContextProvenanceError(f"Node {node_id!r} already exists in graph {graph_id!r}.")
    if len(nodes) >= _MAX_NODES:
        raise ContextProvenanceError("Provenance node bound exceeded.")

    ts = timestamp or _utc_now()
    source = str(source_ref).strip() if source_ref is not None and str(source_ref).strip() else None
    node = {
        "node_id": node_id,
        "node_type": node_type,
        "source_ref": source,
        "content_hash": str(content_hash).strip() if content_hash is not None else None,
        "metadata": dict(metadata or {}),
        "recorded_at": ts,
    }
    node["node_sha256"] = _sha256(node)
    nodes[node_id] = node
    meta["adjacency"].setdefault(node_id, [])
    meta["reverse_adjacency"].setdefault(node_id, [])
    if source is not None:
        meta["source_ref_index"].setdefault(source, [])
        if node_id not in meta["source_ref_index"][source]:
            meta["source_ref_index"][source].append(node_id)
            meta["source_ref_index"][source].sort()
    meta["node_count"] = len(nodes)
    meta["updated_at"] = ts
    meta["graph_sha256"] = _graph_digest(meta)
    store.save_model(base)
    return node


def add_influence_edge(
    graph_id: str,
    from_node_id: str,
    to_node_id: str,
    store: Any,
    *,
    relationship: str = REL_INFLUENCES,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Add one directed influence edge while preserving DAG acyclicity."""
    graph_id = _validate_graph_id(graph_id)
    from_node = _validate_node_id(from_node_id)
    to_node = _validate_node_id(to_node_id)
    relationship = _validate_relationship(relationship)
    if from_node == to_node:
        raise ContextProvenanceError("Influence edges must not self-reference.")

    record = store.get_model(_graph_key(graph_id))
    if not record:
        raise ContextProvenanceError(f"Provenance graph {graph_id!r} is not registered.")
    base = _graph_record(graph_id, record)
    meta = base["metadata"]
    if from_node not in meta["nodes"] or to_node not in meta["nodes"]:
        raise ContextProvenanceError("Both endpoints must exist before adding an edge.")
    if len(meta["edges"]) >= _MAX_EDGES:
        raise ContextProvenanceError("Provenance edge bound exceeded.")
    if from_node in _reachable(to_node, meta["adjacency"]):
        raise ContextProvenanceError("Influence edge would introduce a cycle.")
    for edge in meta["edges"]:
        if (
            edge.get("from_node_id") == from_node
            and edge.get("to_node_id") == to_node
            and edge.get("relationship") == relationship
        ):
            raise ContextProvenanceError("Influence edge already exists.")

    ts = timestamp or _utc_now()
    edge = {
        "from_node_id": from_node,
        "to_node_id": to_node,
        "relationship": relationship,
        "metadata": dict(metadata or {}),
        "recorded_at": ts,
    }
    edge["edge_sha256"] = _sha256(edge)
    meta["edges"].append(edge)
    meta["adjacency"].setdefault(from_node, [])
    if to_node not in meta["adjacency"][from_node]:
        meta["adjacency"][from_node].append(to_node)
        meta["adjacency"][from_node].sort()
    meta["reverse_adjacency"].setdefault(to_node, [])
    if from_node not in meta["reverse_adjacency"][to_node]:
        meta["reverse_adjacency"][to_node].append(from_node)
        meta["reverse_adjacency"][to_node].sort()
    meta["edge_count"] = len(meta["edges"])
    meta["updated_at"] = ts
    meta["graph_sha256"] = _graph_digest(meta)
    store.save_model(base)
    return edge


def list_provenance_nodes(graph_id: str, store: Any) -> list[dict[str, Any]]:
    """Return all nodes in one graph ordered by node_id."""
    meta = get_provenance_graph(graph_id, store)
    if not meta:
        return []
    return [meta["nodes"][node_id] for node_id in sorted(meta.get("nodes", {}))]


def list_provenance_edges(graph_id: str, store: Any) -> list[dict[str, Any]]:
    """Return all edges in one graph in stable order."""
    meta = get_provenance_graph(graph_id, store)
    if not meta:
        return []
    return sorted(
        meta.get("edges", []),
        key=lambda item: (
            item.get("from_node_id", ""),
            item.get("to_node_id", ""),
            item.get("relationship", ""),
        ),
    )


def find_influenced_by(
    source_ref: str,
    store: Any,
    *,
    graph_id: str | None = None,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Resolve all downstream nodes influenced by ``source_ref``."""
    source = str(source_ref or "").strip()
    if not source:
        raise ContextProvenanceError("source_ref must be non-empty.")
    if max_depth <= 0:
        raise ContextProvenanceError("max_depth must be positive.")

    if graph_id is not None:
        meta = get_provenance_graph(graph_id, store)
        graphs = [meta] if meta else []
    else:
        graphs = [_load_meta(record) for record in _all_graph_records(store)]

    aggregate_results = []
    influenced_ids: set[tuple[str, str]] = set()
    seed_ids: set[tuple[str, str]] = set()
    for meta in graphs:
        if not meta:
            continue
        graph = str(meta.get("graph_id") or "")
        seeds = list((meta.get("source_ref_index") or {}).get(source) or [])
        if not seeds:
            continue
        queue = deque((seed, 0) for seed in seeds)
        visited: set[str] = set(seeds)
        impacted: list[dict[str, Any]] = []
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbour in (meta.get("adjacency") or {}).get(current, []):
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))
                node = (meta.get("nodes") or {}).get(neighbour)
                if node is not None and len(impacted) < _MAX_PATH_RESULTS:
                    impacted.append({"graph_id": graph, **node, "influence_depth": depth + 1})
                    influenced_ids.add((graph, neighbour))
        aggregate_results.append(
            {
                "graph_id": graph,
                "seed_node_ids": sorted(seeds),
                "influenced_nodes": sorted(
                    impacted,
                    key=lambda item: (item.get("influence_depth", 0), item.get("node_id", "")),
                ),
            }
        )
        for seed in seeds:
            seed_ids.add((graph, seed))

    aggregate_results.sort(key=lambda item: item["graph_id"])
    return {
        "source_ref": source,
        "graph_id": graph_id,
        "graph_count": len(aggregate_results),
        "seed_node_count": len(seed_ids),
        "influenced_node_count": len(influenced_ids),
        "graph_results": aggregate_results,
        "evidence_origin": "LOCALLY_OBSERVED",
        "queried_at": _utc_now(),
    }

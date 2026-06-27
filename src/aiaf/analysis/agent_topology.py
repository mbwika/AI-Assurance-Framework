"""Multi-Agent Topology & Cascade / Blast-Radius Analyzer.

Models an agent deployment as a directed communication graph and performs:
  - Trust-boundary detection: edges that cross trust levels
  - Cascade path enumeration: all paths a compromise could propagate
  - Blast-radius estimation: fraction of the system reachable from a given node
  - Single-point-of-cascade-failure (SPOCF) detection
  - Circuit-breaker coverage gap detection

Topology concepts
-----------------
Node   — a registered agent, model, tool, or service endpoint with a trust level
Edge   — a directed communication link (caller → callee) with an optional channel type

Trust levels (ascending)
------------------------
UNTRUSTED < EXTERNAL < INTERNAL < PRIVILEGED

A trust-boundary crossing occurs when an edge goes from a lower trust level to a
higher one (privilege escalation path) or from EXTERNAL into INTERNAL/PRIVILEGED
without a declared guardrail.

Risk levels
-----------
TOPOLOGY_RISK_LOW      — no trust-boundary crossings, no SPOCF nodes
TOPOLOGY_RISK_MEDIUM   — minor crossings or partial guardrail coverage
TOPOLOGY_RISK_HIGH     — privilege-escalation paths or high blast radius
TOPOLOGY_RISK_CRITICAL — unguarded path to PRIVILEGED or blast radius > 60%

Evidence origin
---------------
LOCALLY_OBSERVED — topology data is registered and analysed locally by AIAF.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

AGENT_TOPOLOGY_VERSION = "1.0"

# ── Node trust levels ──────────────────────────────────────────────────────────
TRUST_UNTRUSTED = "UNTRUSTED"
TRUST_EXTERNAL = "EXTERNAL"
TRUST_INTERNAL = "INTERNAL"
TRUST_PRIVILEGED = "PRIVILEGED"

TRUST_LEVELS: frozenset = frozenset(
    {TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED}
)

_TRUST_RANK: Dict[str, int] = {
    TRUST_UNTRUSTED: 0,
    TRUST_EXTERNAL: 1,
    TRUST_INTERNAL: 2,
    TRUST_PRIVILEGED: 3,
}

# ── Node types ─────────────────────────────────────────────────────────────────
NODE_AGENT = "AGENT"
NODE_MODEL = "MODEL"
NODE_TOOL = "TOOL"
NODE_SERVICE = "SERVICE"
NODE_HUMAN = "HUMAN"

NODE_TYPES: frozenset = frozenset(
    {NODE_AGENT, NODE_MODEL, NODE_TOOL, NODE_SERVICE, NODE_HUMAN}
)

# ── Channel types ──────────────────────────────────────────────────────────────
CHANNEL_DIRECT_CALL = "DIRECT_CALL"
CHANNEL_SHARED_MEMORY = "SHARED_MEMORY"
CHANNEL_MESSAGE_QUEUE = "MESSAGE_QUEUE"
CHANNEL_API = "API"
CHANNEL_TOOL_CALL = "TOOL_CALL"

CHANNEL_TYPES: frozenset = frozenset(
    {CHANNEL_DIRECT_CALL, CHANNEL_SHARED_MEMORY, CHANNEL_MESSAGE_QUEUE,
     CHANNEL_API, CHANNEL_TOOL_CALL}
)

# ── Topology risk levels ───────────────────────────────────────────────────────
TOPOLOGY_RISK_LOW = "LOW"
TOPOLOGY_RISK_MEDIUM = "MEDIUM"
TOPOLOGY_RISK_HIGH = "HIGH"
TOPOLOGY_RISK_CRITICAL = "CRITICAL"

# ── Storage prefixes ───────────────────────────────────────────────────────────
_TOPOLOGY_PREFIX = "agent_topology:"
_NODE_PREFIX = "topology_node:"
_EDGE_PREFIX = "topology_edge:"


class AgentTopologyError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _topology_key(topology_id: str) -> str:
    return f"{_TOPOLOGY_PREFIX}{topology_id}"


def _node_key(topology_id: str, node_id: str) -> str:
    return f"{_NODE_PREFIX}{topology_id}:{node_id}"


def _edge_key(topology_id: str, from_id: str, to_id: str) -> str:
    return f"{_EDGE_PREFIX}{topology_id}:{from_id}->{to_id}"


def _load_meta(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _get_all_nodes(topology_id: str, store: Any) -> List[Dict[str, Any]]:
    prefix = _node_key(topology_id, "")
    return [
        _load_meta(rec)
        for rec in (store.list_models() if hasattr(store, "list_models") else [])
        if str(rec.get("model_id") or rec.get("id") or "").startswith(prefix)
    ]


def _get_all_edges(topology_id: str, store: Any) -> List[Dict[str, Any]]:
    prefix = f"{_EDGE_PREFIX}{topology_id}:"
    return [
        _load_meta(rec)
        for rec in (store.list_models() if hasattr(store, "list_models") else [])
        if str(rec.get("model_id") or rec.get("id") or "").startswith(prefix)
    ]


def _bfs_reachable(start: str, adj: Dict[str, List[str]]) -> Set[str]:
    """BFS from start node; returns all reachable nodes (excluding start)."""
    visited: Set[str] = set()
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbour in adj.get(node, []):
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append(neighbour)
    return visited


def _all_paths(start: str, adj: Dict[str, List[str]], max_depth: int = 10) -> List[List[str]]:
    """Enumerate all simple paths from start up to max_depth length."""
    paths: List[List[str]] = []
    stack: List[Tuple[str, List[str]]] = [(start, [start])]
    while stack:
        node, path = stack.pop()
        if len(path) > max_depth:
            paths.append(path)
            continue
        neighbours = adj.get(node, [])
        if not neighbours:
            paths.append(path)
            continue
        for n in neighbours:
            if n not in path:  # avoid cycles
                stack.append((n, path + [n]))
            else:
                paths.append(path + [n + "(cycle)"])
    return paths


# ── Public API ─────────────────────────────────────────────────────────────────

def register_topology(
    topology_id: str,
    store: Any,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a new agent topology graph.

    Parameters
    ----------
    topology_id:  Unique identifier for this topology.
    store:        AIAF persistence store.
    """
    if not topology_id or not topology_id.strip():
        raise AgentTopologyError("topology_id must be non-empty.")

    record: Dict[str, Any] = {
        "model_id": _topology_key(topology_id),
        "id": _topology_key(topology_id),
        "metadata": {
            "topology_id": topology_id,
            "name": name or topology_id,
            "description": description or "",
            "node_count": 0,
            "edge_count": 0,
            "evidence_origin": "LOCALLY_OBSERVED",
            "registered_at": _utc_now(),
            "updated_at": _utc_now(),
        },
    }
    store.save_model(record)
    return _load_meta(store.get_model(_topology_key(topology_id)))


def get_topology(topology_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return topology metadata, or None if not registered."""
    rec = store.get_model(_topology_key(topology_id))
    return _load_meta(rec) if rec else None


def add_agent_node(
    topology_id: str,
    node_id: str,
    node_type: str,
    trust_level: str,
    store: Any,
    *,
    has_guardrail: bool = False,
    capabilities: Optional[List[str]] = None,
    internet_facing: bool = False,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Add a node (agent, model, tool, or service) to the topology.

    Parameters
    ----------
    node_id:       Unique identifier for this node within the topology.
    node_type:     One of NODE_* constants.
    trust_level:   One of TRUST_* constants.
    has_guardrail: Whether this node has an output guardrail/policy-enforcement layer.
    capabilities:  What this node can do (e.g. ["read_db", "write_files"]).
    internet_facing: Whether this node is directly reachable from the internet.
    """
    if not topology_id or not topology_id.strip():
        raise AgentTopologyError("topology_id must be non-empty.")
    if not node_id or not node_id.strip():
        raise AgentTopologyError("node_id must be non-empty.")

    node_type = str(node_type).upper().strip()
    if node_type not in NODE_TYPES:
        raise AgentTopologyError(
            f"Unknown node_type {node_type!r}. Valid: {sorted(NODE_TYPES)}"
        )

    trust_level = str(trust_level).upper().strip()
    if trust_level not in TRUST_LEVELS:
        raise AgentTopologyError(
            f"Unknown trust_level {trust_level!r}. Valid: {sorted(TRUST_LEVELS)}"
        )

    topology_meta = get_topology(topology_id, store)
    if not topology_meta:
        raise AgentTopologyError(
            f"Topology {topology_id!r} not found. Call register_topology first."
        )

    record: Dict[str, Any] = {
        "model_id": _node_key(topology_id, node_id),
        "id": _node_key(topology_id, node_id),
        "metadata": {
            "topology_id": topology_id,
            "node_id": node_id,
            "node_type": node_type,
            "trust_level": trust_level,
            "trust_rank": _TRUST_RANK[trust_level],
            "has_guardrail": has_guardrail,
            "capabilities": capabilities or [],
            "internet_facing": internet_facing,
            "attributes": attributes or {},
            "evidence_origin": "LOCALLY_OBSERVED",
            "added_at": _utc_now(),
        },
    }
    store.save_model(record)

    # Update topology counters
    updated = dict(topology_meta)
    updated["node_count"] = updated.get("node_count", 0) + 1
    updated["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _topology_key(topology_id),
        "id": _topology_key(topology_id),
        "metadata": updated,
    })

    return _load_meta(store.get_model(_node_key(topology_id, node_id)))


def add_communication_edge(
    topology_id: str,
    from_node_id: str,
    to_node_id: str,
    store: Any,
    *,
    channel: str = CHANNEL_DIRECT_CALL,
    bidirectional: bool = False,
    has_guardrail: bool = False,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Add a directed communication edge between two nodes.

    Parameters
    ----------
    from_node_id:   Caller / initiator node.
    to_node_id:     Callee / receiver node.
    channel:        One of CHANNEL_* constants.
    bidirectional:  If True, also adds the reverse edge with same properties.
    has_guardrail:  Whether this channel is protected by an inline guard.
    """
    if not topology_id or not topology_id.strip():
        raise AgentTopologyError("topology_id must be non-empty.")

    channel = str(channel).upper().strip()
    if channel not in CHANNEL_TYPES:
        raise AgentTopologyError(
            f"Unknown channel {channel!r}. Valid: {sorted(CHANNEL_TYPES)}"
        )

    topology_meta = get_topology(topology_id, store)
    if not topology_meta:
        raise AgentTopologyError(f"Topology {topology_id!r} not found.")

    from_rec = store.get_model(_node_key(topology_id, from_node_id))
    to_rec = store.get_model(_node_key(topology_id, to_node_id))
    if not from_rec:
        raise AgentTopologyError(f"Node {from_node_id!r} not found in topology {topology_id!r}.")
    if not to_rec:
        raise AgentTopologyError(f"Node {to_node_id!r} not found in topology {topology_id!r}.")

    from_meta = _load_meta(from_rec)
    to_meta = _load_meta(to_rec)

    from_rank = _TRUST_RANK.get(from_meta.get("trust_level", TRUST_UNTRUSTED), 0)
    to_rank = _TRUST_RANK.get(to_meta.get("trust_level", TRUST_UNTRUSTED), 0)
    crosses_trust_boundary = to_rank > from_rank
    privilege_escalation = crosses_trust_boundary and to_meta.get("trust_level") == TRUST_PRIVILEGED

    def _save_edge(fid: str, tid: str, fm: Dict, tm: Dict) -> None:
        f_rank = _TRUST_RANK.get(fm.get("trust_level", TRUST_UNTRUSTED), 0)
        t_rank = _TRUST_RANK.get(tm.get("trust_level", TRUST_UNTRUSTED), 0)
        crosses = t_rank > f_rank
        priv_esc = crosses and tm.get("trust_level") == TRUST_PRIVILEGED
        edge_record: Dict[str, Any] = {
            "model_id": _edge_key(topology_id, fid, tid),
            "id": _edge_key(topology_id, fid, tid),
            "metadata": {
                "topology_id": topology_id,
                "from_node_id": fid,
                "to_node_id": tid,
                "channel": channel,
                "has_guardrail": has_guardrail,
                "crosses_trust_boundary": crosses,
                "privilege_escalation": priv_esc,
                "from_trust": fm.get("trust_level"),
                "to_trust": tm.get("trust_level"),
                "attributes": attributes or {},
                "evidence_origin": "LOCALLY_OBSERVED",
                "added_at": _utc_now(),
            },
        }
        store.save_model(edge_record)

    _save_edge(from_node_id, to_node_id, from_meta, to_meta)
    if bidirectional:
        _save_edge(to_node_id, from_node_id, to_meta, from_meta)

    # Update topology counters
    updated = dict(topology_meta)
    updated["edge_count"] = updated.get("edge_count", 0) + (2 if bidirectional else 1)
    updated["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _topology_key(topology_id),
        "id": _topology_key(topology_id),
        "metadata": updated,
    })

    return _load_meta(store.get_model(_edge_key(topology_id, from_node_id, to_node_id)))


def analyze_topology(topology_id: str, store: Any) -> Dict[str, Any]:
    """Run full topology analysis — trust boundaries, blast radius, SPOCFs.

    Returns
    -------
    Dict with keys:
        topology_id, agent_topology_version, overall_risk,
        node_count, edge_count,
        trust_boundary_crossings,
        privilege_escalation_paths,
        spocf_nodes,
        max_blast_radius_pct,
        blast_radius_by_node,
        guardrail_coverage_pct,
        internet_facing_unguarded,
        findings, recommended_mitigations,
        evidence_origin, analyzed_at
    """
    topology_meta = get_topology(topology_id, store)
    if not topology_meta:
        raise AgentTopologyError(f"Topology {topology_id!r} not found.")

    nodes = _get_all_nodes(topology_id, store)
    edges = _get_all_edges(topology_id, store)

    if not nodes:
        return {
            "topology_id": topology_id,
            "agent_topology_version": AGENT_TOPOLOGY_VERSION,
            "overall_risk": TOPOLOGY_RISK_LOW,
            "node_count": 0,
            "edge_count": 0,
            "trust_boundary_crossings": [],
            "privilege_escalation_paths": [],
            "spocf_nodes": [],
            "max_blast_radius_pct": 0.0,
            "blast_radius_by_node": {},
            "guardrail_coverage_pct": 100.0,
            "internet_facing_unguarded": [],
            "findings": [],
            "recommended_mitigations": [],
            "evidence_origin": "LOCALLY_OBSERVED",
            "analyzed_at": _utc_now(),
        }

    node_map: Dict[str, Dict[str, Any]] = {n["node_id"]: n for n in nodes}
    n_total = len(nodes)

    # Build adjacency list
    adj: Dict[str, List[str]] = {n["node_id"]: [] for n in nodes}
    for edge in edges:
        fid = edge.get("from_node_id", "")
        tid = edge.get("to_node_id", "")
        if fid in adj:
            adj[fid].append(tid)

    # ── Trust boundary crossings ───────────────────────────────────────────────
    trust_crossings = []
    for edge in edges:
        if edge.get("crosses_trust_boundary"):
            trust_crossings.append({
                "from_node": edge["from_node_id"],
                "to_node": edge["to_node_id"],
                "from_trust": edge.get("from_trust"),
                "to_trust": edge.get("to_trust"),
                "channel": edge.get("channel"),
                "has_guardrail": edge.get("has_guardrail", False),
                "privilege_escalation": edge.get("privilege_escalation", False),
            })

    priv_esc_paths = [c for c in trust_crossings if c["privilege_escalation"]]

    # ── Blast radius per node ──────────────────────────────────────────────────
    blast_radius_by_node: Dict[str, float] = {}
    for node in nodes:
        nid = node["node_id"]
        reachable = _bfs_reachable(nid, adj)
        blast_pct = round(len(reachable) / n_total * 100, 1) if n_total > 1 else 0.0
        blast_radius_by_node[nid] = blast_pct

    max_blast = max(blast_radius_by_node.values(), default=0.0)

    # ── SPOCF — node whose removal reduces max reachability significantly ─────
    # Simplified heuristic: nodes reachable from ALL internet-facing nodes
    internet_nodes = [n["node_id"] for n in nodes if n.get("internet_facing")]
    spocf_candidates: Set[str] = set()
    if len(internet_nodes) >= 1:
        # A node is SPOCF if it's on every path from internet-facing nodes to PRIVILEGED nodes
        privileged_nodes = {n["node_id"] for n in nodes if n.get("trust_level") == TRUST_PRIVILEGED}
        if privileged_nodes:
            # Nodes reachable from each internet node
            reachable_sets = [_bfs_reachable(inode, adj) for inode in internet_nodes]
            if reachable_sets:
                # Intersection = nodes on all paths from internet
                common = reachable_sets[0].intersection(*reachable_sets[1:])
                # Those that can themselves reach a privileged node
                for candidate in common:
                    if _bfs_reachable(candidate, adj) & privileged_nodes:
                        spocf_candidates.add(candidate)

    spocf_nodes = sorted(spocf_candidates)

    # ── Guardrail coverage ─────────────────────────────────────────────────────
    crossing_count = len(trust_crossings)
    guarded_count = sum(1 for c in trust_crossings if c["has_guardrail"])
    guardrail_coverage_pct = (
        round(guarded_count / crossing_count * 100, 1) if crossing_count else 100.0
    )

    # ── Internet-facing nodes without guardrail on outbound edges ─────────────
    internet_unguarded = []
    for inode in internet_nodes:
        node_meta = node_map.get(inode, {})
        if not node_meta.get("has_guardrail", False):
            internet_unguarded.append(inode)

    # ── Build findings ─────────────────────────────────────────────────────────
    findings: List[Dict[str, Any]] = []

    for crossing in [c for c in trust_crossings if not c["has_guardrail"]]:
        sev = "CRITICAL" if crossing["privilege_escalation"] else "HIGH"
        findings.append({
            "severity": sev,
            "category": "TRUST_BOUNDARY_CROSSING",
            "detail": (
                f"Unguarded {crossing['channel']} edge from {crossing['from_trust']} node "
                f"{crossing['from_node']!r} to {crossing['to_trust']} node {crossing['to_node']!r}."
            ),
        })

    for node in nodes:
        br = blast_radius_by_node.get(node["node_id"], 0.0)
        if br >= 80.0:
            findings.append({
                "severity": "CRITICAL",
                "category": "HIGH_BLAST_RADIUS",
                "detail": (
                    f"Node {node['node_id']!r} ({node.get('trust_level')}) can reach "
                    f"{br:.0f}% of the topology if compromised."
                ),
            })
        elif br >= 60.0:
            findings.append({
                "severity": "HIGH",
                "category": "HIGH_BLAST_RADIUS",
                "detail": (
                    f"Node {node['node_id']!r} can reach {br:.0f}% of the topology if compromised."
                ),
            })

    for spocf in spocf_nodes:
        findings.append({
            "severity": "HIGH",
            "category": "SINGLE_POINT_OF_CASCADE_FAILURE",
            "detail": (
                f"Node {spocf!r} is on every internet-to-privileged path — "
                "compromise cascades to all privileged nodes."
            ),
        })

    for inode in internet_unguarded:
        findings.append({
            "severity": "HIGH",
            "category": "INTERNET_FACING_UNGUARDED",
            "detail": f"Internet-facing node {inode!r} has no guardrail.",
        })

    # ── Overall risk ───────────────────────────────────────────────────────────
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        overall_risk = TOPOLOGY_RISK_CRITICAL
    elif "HIGH" in severities:
        overall_risk = TOPOLOGY_RISK_HIGH
    elif findings:
        overall_risk = TOPOLOGY_RISK_MEDIUM
    else:
        overall_risk = TOPOLOGY_RISK_LOW

    # ── Mitigations ────────────────────────────────────────────────────────────
    mitigations: List[str] = []
    if priv_esc_paths:
        mitigations.append(
            "Add inline policy enforcement (guardrail) on all edges leading to PRIVILEGED nodes."
        )
    if spocf_nodes:
        mitigations.append(
            "Deploy circuit-breakers on SPOCF nodes to contain cascade failures."
        )
    if internet_unguarded:
        mitigations.append(
            "Wrap all internet-facing nodes in an input/output guardrail layer before processing."
        )
    if max_blast >= 60.0:
        mitigations.append(
            "Segment the topology into isolated trust zones to reduce blast radius."
        )

    return {
        "topology_id": topology_id,
        "agent_topology_version": AGENT_TOPOLOGY_VERSION,
        "overall_risk": overall_risk,
        "node_count": n_total,
        "edge_count": len(edges),
        "trust_boundary_crossings": trust_crossings,
        "privilege_escalation_paths": priv_esc_paths,
        "spocf_nodes": spocf_nodes,
        "max_blast_radius_pct": max_blast,
        "blast_radius_by_node": blast_radius_by_node,
        "guardrail_coverage_pct": guardrail_coverage_pct,
        "internet_facing_unguarded": internet_unguarded,
        "findings": findings,
        "recommended_mitigations": mitigations,
        "evidence_origin": "LOCALLY_OBSERVED",
        "analyzed_at": _utc_now(),
    }

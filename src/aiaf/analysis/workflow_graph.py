"""Bounded graph-level security analysis for agentic workflows."""

from collections import deque
from dataclasses import dataclass
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


WORKFLOW_GRAPH_SCORING_VERSION = "2.0"
_MAX_NODES = 1_000
_MAX_EDGES = 5_000
_MAX_RISKS = 500
_MAX_IDENTIFIER_CHARS = 128

SENSITIVE_TOOLS = {
    "shell",
    "browser",
    "filesystem",
    "email",
    "database",
    "http",
    "payment",
    "cloud_admin",
}
ELEVATED_PERMISSIONS = {
    "*",
    "write",
    "delete",
    "admin",
    "root",
    "sudo",
    "network",
    "deploy",
    "execute",
    "send_email",
    "transfer_funds",
}
HIGH_IMPACT_ACTIONS = {
    "write",
    "delete",
    "deploy",
    "execute",
    "send_email",
    "transfer_funds",
    "external_call",
}

_UNTRUSTED_SOURCES = {
    "external",
    "untrusted",
    "user",
    "retrieval",
    "web",
    "uploaded_content",
}
_MODEL_OUTPUT_SOURCES = {"model", "model_output", "llm", "generated_content"}
_SENSITIVE_CLASSIFICATIONS = {
    "confidential",
    "restricted",
    "secret",
    "pii",
    "phi",
    "financial",
    "credentials",
    "authentication_data",
}
_EXTERNAL_SINK_TOOLS = {"browser", "email", "http", "payment"}
_EXTERNAL_SINK_ACTIONS = {"external_call", "send_email", "transfer_funds"}
_CODE_EXECUTION_TOOLS = {"shell", "filesystem", "cloud_admin"}
_CODE_EXECUTION_ACTIONS = {"execute", "write", "deploy", "delete"}
_APPROVAL_ACTIONS = {
    "approve",
    "approval",
    "authorize",
    "human_review",
    "review",
}
_DISABLED_CONTROL_VALUES = {
    "",
    "0",
    "false",
    "none",
    "no",
    "disabled",
    "off",
    "not_configured",
    "not_implemented",
    "n_a",
    "pending",
    "placeholder",
    "planned",
    "proposed",
    "tbd",
    "todo",
    "unknown",
}
_NON_OPERATIONAL_CONTROL_TOKENS = frozenset(
    {"draft", "future", "pending", "placeholder", "planned", "proposed", "tbd", "todo"}
)


@dataclass(frozen=True)
class _Edge:
    source: str
    target: str
    kind: str = "next"
    conditional: bool = False


def analyze_workflow_graph(
    artifact: Dict[str, Any], policy: object = None
) -> Dict[str, Any]:
    """Analyze graph structure, termination, approval cuts, taint, and privilege."""
    artifact = artifact if isinstance(artifact, dict) else {}
    risks: List[Dict[str, Any]] = []
    assessment_complete = True
    if policy is None:
        policy_dict: Dict[str, Any] = {}
    elif not isinstance(policy, dict):
        policy_dict = {}
        assessment_complete = False
        risks.append(
            _risk(
                "malformed_workflow_policy",
                "HIGH",
                {"reason": "policy must be an object"},
                "Workflow policy could not be interpreted safely.",
            )
        )
    else:
        policy_dict = policy

    raw_steps, malformed_steps = _raw_workflow_steps(artifact)
    provided_node_count = len(raw_steps)
    if malformed_steps:
        assessment_complete = False
        risks.append(
            _risk(
                "malformed_workflow_steps",
                "HIGH",
                {"reason": malformed_steps},
                "Workflow steps must be represented as a list of objects.",
            )
        )
    if provided_node_count > _MAX_NODES:
        assessment_complete = False
        risks.append(
            _risk(
                "workflow_node_limit_exceeded",
                "HIGH",
                {"provided": provided_node_count, "analyzed": _MAX_NODES},
                "Workflow exceeds the bounded node-analysis limit.",
            )
        )

    nodes: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    invalid_step_count = 0
    for index, raw_step in enumerate(raw_steps[:_MAX_NODES]):
        if not isinstance(raw_step, dict):
            invalid_step_count += 1
            assessment_complete = False
            risks.append(
                _risk(
                    "malformed_workflow_step",
                    "HIGH",
                    {"index": index},
                    "Workflow step must be an object.",
                )
            )
            continue
        node_id = _node_identifier(raw_step, index)
        if node_id in nodes:
            assessment_complete = False
            risks.append(
                _risk(
                    "duplicate_workflow_step_id",
                    "HIGH",
                    node_id,
                    "Workflow step identifiers must be unique.",
                )
            )
            continue
        nodes[node_id] = raw_step
        order.append(node_id)

    if not nodes:
        return _result(
            nodes=nodes,
            edges=[],
            entrypoint=None,
            terminal_nodes=[],
            reachable=set(),
            cycles=[],
            risks=risks,
            assessment_complete=assessment_complete,
            metrics={
                "provided_node_count": provided_node_count,
                "invalid_step_count": invalid_step_count,
                "provided_edge_count": 0,
            },
            nodes_without_terminal_path=[],
        )

    raw_edges, explicit_edges, provided_edge_count, edge_input_incomplete = _workflow_edges(
        artifact, nodes, order, risks
    )
    if edge_input_incomplete:
        assessment_complete = False

    edges: List[_Edge] = []
    edge_keys = set()
    adjacency = {node_id: [] for node_id in nodes}
    predecessors = {node_id: [] for node_id in nodes}
    for edge in raw_edges[:_MAX_EDGES]:
        if edge.source not in nodes or edge.target not in nodes:
            assessment_complete = False
            risks.append(
                _risk(
                    "unknown_workflow_transition",
                    "HIGH",
                    f"{edge.source}->{edge.target}",
                    "Workflow transition references an unknown step.",
                )
            )
            continue
        key = (edge.source, edge.target, edge.kind)
        if key in edge_keys:
            continue
        edge_keys.add(key)
        edges.append(edge)
        if edge.target not in adjacency[edge.source]:
            adjacency[edge.source].append(edge.target)
            predecessors[edge.target].append(edge.source)

    workflow = artifact.get("workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    requested_entrypoint = (
        artifact.get("workflow_entrypoint") or workflow.get("entrypoint") or order[0]
    )
    entrypoint = _clean_identifier(requested_entrypoint)
    if entrypoint not in nodes:
        assessment_complete = False
        risks.append(
            _risk(
                "unknown_workflow_entrypoint",
                "HIGH",
                entrypoint,
                "Workflow entrypoint does not exist.",
            )
        )
        entrypoint = order[0]

    declared_tools = _normalized_set(artifact.get("tools"))
    if policy_dict.get("require_declared_tools") or declared_tools:
        for node_id, step in nodes.items():
            tool = _normalized_value(step.get("tool"))
            if tool and tool not in declared_tools:
                risks.append(
                    _risk(
                        "undeclared_workflow_tool",
                        "HIGH",
                        node_id,
                        f"Workflow uses undeclared tool {tool}.",
                    )
                )

    reachable = _reachable(entrypoint, adjacency)
    unreachable = sorted(set(nodes) - reachable)
    for node_id in unreachable:
        risks.append(
            _risk(
                "unreachable_workflow_step",
                "MEDIUM",
                node_id,
                "Workflow step cannot be reached from the entrypoint.",
            )
        )

    declared_terminals = {
        node_id for node_id, step in nodes.items() if _declares_terminal(step)
    }
    for node_id in sorted(declared_terminals):
        if adjacency[node_id]:
            risks.append(
                _risk(
                    "terminal_step_has_outgoing_transition",
                    "HIGH",
                    {"node": node_id, "targets": sorted(adjacency[node_id])},
                    "A declared terminal step still has outgoing transitions.",
                )
            )
    terminal_nodes = sorted(node_id for node_id in nodes if not adjacency[node_id])
    reachable_terminals = sorted(set(terminal_nodes) & reachable)
    if (policy_dict.get("require_termination_path") or explicit_edges) and not reachable_terminals:
        risks.append(
            _risk(
                "missing_termination_path",
                "HIGH",
                entrypoint,
                "No terminal workflow step is reachable from the entrypoint.",
            )
        )

    terminal_reachable = _reverse_reachable(terminal_nodes, predecessors)
    nodes_without_terminal_path = sorted(reachable - terminal_reachable)
    if nodes_without_terminal_path:
        risks.append(
            _risk(
                "nonterminating_workflow_region",
                "HIGH",
                {"nodes": nodes_without_terminal_path[:100]},
                "Reachable workflow nodes have no path to a terminal step.",
            )
        )

    components = _strongly_connected_components(adjacency)
    cycles = [
        component
        for component in components
        if len(component) > 1 or component[0] in adjacency[component[0]]
    ]
    global_cycle_bound, invalid_bound = _global_cycle_bound(artifact, policy_dict)
    if invalid_bound:
        assessment_complete = False
        risks.append(
            _risk(
                "invalid_workflow_iteration_bound",
                "HIGH",
                {"reason": invalid_bound},
                "Workflow iteration bounds must be positive bounded integers.",
            )
        )
    cycle_bounds: Dict[Tuple[str, ...], Optional[int]] = {}
    for cycle in cycles:
        bound = _component_cycle_bound(
            cycle,
            global_cycle_bound,
            nodes,
            entrypoint,
            adjacency,
            reachable,
        )
        cycle_bounds[tuple(cycle)] = bound
        if bound is None:
            risks.append(
                _risk(
                    "unbounded_workflow_cycle",
                    "CRITICAL",
                    cycle,
                    "Workflow cycle has no effective iteration bound.",
                )
            )
        if not set(cycle) & terminal_reachable:
            risks.append(
                _risk(
                    "cycle_without_exit_path",
                    "HIGH",
                    cycle,
                    "Workflow cycle has no path to a terminal step.",
                )
            )
        if bound is None and any(_is_high_impact_step(nodes[node]) for node in cycle):
            risks.append(
                _risk(
                    "repeatable_high_impact_action",
                    "CRITICAL",
                    {"cycle": cycle},
                    "An unbounded cycle can repeat a high-impact action.",
                )
            )

    approval_risks, approval_guards = _approval_control_risks(
        nodes, adjacency, entrypoint, reachable, artifact
    )
    risks.extend(approval_risks)
    risks.extend(_taint_risks(nodes, adjacency, entrypoint, reachable))
    risks.extend(
        _privilege_transition_risks(
            nodes,
            edges,
            artifact,
            entrypoint,
            adjacency,
            reachable,
            approval_guards,
        )
    )

    max_steps_raw = policy_dict.get("max_workflow_steps")
    max_steps = _positive_int(max_steps_raw)
    if max_steps_raw is not None and max_steps is None:
        assessment_complete = False
        risks.append(
            _risk(
                "invalid_workflow_step_bound",
                "HIGH",
                {"value_type": type(max_steps_raw).__name__},
                "Workflow step limits must be positive bounded integers.",
            )
        )
    elif max_steps is not None and len(nodes) > max_steps:
        risks.append(
            _risk(
                "workflow_step_limit_exceeded",
                "MEDIUM",
                len(nodes),
                f"Workflow has {len(nodes)} steps; policy allows {max_steps}.",
            )
        )

    component_count = _weak_component_count(nodes, adjacency)
    metrics = {
        "provided_node_count": provided_node_count,
        "invalid_step_count": invalid_step_count,
        "provided_edge_count": provided_edge_count,
        "reachable_node_count": len(reachable),
        "unreachable_node_count": len(unreachable),
        "terminal_node_count": len(terminal_nodes),
        "nodes_with_terminal_path": len(reachable & terminal_reachable),
        "strongly_connected_component_count": len(components),
        "cyclic_component_count": len(cycles),
        "branching_node_count": sum(len(targets) > 1 for targets in adjacency.values()),
        "maximum_out_degree": max((len(targets) for targets in adjacency.values()), default=0),
        "cyclomatic_complexity": max(len(edges) - len(nodes) + component_count, 0),
        "approval_guard_count": len(approval_guards),
        "cycle_bounds": [
            {"nodes": list(component), "maximum_iterations": bound}
            for component, bound in cycle_bounds.items()
        ],
    }
    return _result(
        nodes=nodes,
        edges=edges,
        entrypoint=entrypoint,
        terminal_nodes=terminal_nodes,
        reachable=reachable,
        cycles=cycles,
        risks=risks,
        assessment_complete=assessment_complete,
        metrics=metrics,
        nodes_without_terminal_path=nodes_without_terminal_path,
    )


def _raw_workflow_steps(artifact):
    if "workflow_steps" in artifact:
        raw = artifact.get("workflow_steps")
    else:
        raw = artifact.get("workflow") or []
    if isinstance(raw, dict):
        raw = raw.get("steps", [])
    if raw is None:
        return [], None
    if not isinstance(raw, (list, tuple)):
        return [], "workflow steps must be a list or tuple"
    return list(raw), None


def _node_identifier(step, index):
    raw = step.get("id") or step.get("name") or f"step-{index + 1}"
    cleaned = _clean_identifier(raw)
    return cleaned or f"step-{index + 1}"


def _workflow_edges(artifact, nodes, order, risks):
    workflow = artifact.get("workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    explicit = "workflow_edges" in artifact or "edges" in workflow
    declared = artifact.get("workflow_edges") if "workflow_edges" in artifact else workflow.get("edges")
    provided = 0
    incomplete = False
    edges: List[_Edge] = []
    if explicit:
        if declared is None:
            declared = []
        if not isinstance(declared, (list, tuple)):
            risks.append(
                _risk(
                    "malformed_workflow_edges",
                    "HIGH",
                    {"reason": "workflow edges must be a list or tuple"},
                    "Workflow transitions could not be interpreted safely.",
                )
            )
            return [], True, 0, True
        provided = len(declared)
        if provided > _MAX_EDGES:
            incomplete = True
            risks.append(
                _risk(
                    "workflow_edge_limit_exceeded",
                    "HIGH",
                    {"provided": provided, "analyzed": _MAX_EDGES},
                    "Workflow exceeds the bounded edge-analysis limit.",
                )
            )
        for index, raw_edge in enumerate(list(declared)[:_MAX_EDGES]):
            edge = _parse_edge(raw_edge)
            if edge is None:
                incomplete = True
                risks.append(
                    _risk(
                        "malformed_workflow_edge",
                        "HIGH",
                        {"index": index},
                        "Workflow transition must declare source and target steps.",
                    )
                )
                continue
            edges.append(edge)
        return edges, True, provided, incomplete

    has_step_transitions = False
    for node_id, step in nodes.items():
        for field, kind in (
            ("next", "next"),
            ("on_success", "success"),
            ("on_failure", "failure"),
        ):
            value = step.get(field)
            if value is None or value == "":
                continue
            has_step_transitions = True
            values = value if isinstance(value, (list, tuple)) else [value]
            for target in values:
                edges.append(_Edge(node_id, _clean_identifier(target), kind, kind != "next"))
        transitions = step.get("transitions")
        if transitions is None:
            continue
        if not isinstance(transitions, (list, tuple)):
            incomplete = True
            risks.append(
                _risk(
                    "malformed_workflow_transition",
                    "HIGH",
                    node_id,
                    "Step transitions must be a list of transition objects.",
                )
            )
            continue
        for transition in transitions:
            if not isinstance(transition, dict) or not transition.get("to"):
                incomplete = True
                risks.append(
                    _risk(
                        "malformed_workflow_transition",
                        "HIGH",
                        node_id,
                        "Step transition is missing a target.",
                    )
                )
                continue
            has_step_transitions = True
            kind = _normalized_value(
                transition.get("kind") or transition.get("type") or transition.get("on")
            ) or "conditional"
            edges.append(
                _Edge(
                    node_id,
                    _clean_identifier(transition.get("to")),
                    kind,
                    bool(transition.get("condition")) or kind != "next",
                )
            )
    provided = len(edges)
    if provided > _MAX_EDGES:
        incomplete = True
        risks.append(
            _risk(
                "workflow_edge_limit_exceeded",
                "HIGH",
                {"provided": provided, "analyzed": _MAX_EDGES},
                "Workflow exceeds the bounded edge-analysis limit.",
            )
        )
        edges = edges[:_MAX_EDGES]
    if not has_step_transitions:
        edges = [_Edge(source, target) for source, target in zip(order, order[1:])]
        provided = len(edges)
    return edges, has_step_transitions, provided, incomplete


def _parse_edge(raw_edge):
    if isinstance(raw_edge, dict):
        source = raw_edge.get("from") or raw_edge.get("source")
        target = raw_edge.get("to") or raw_edge.get("target")
        if source is None or target is None:
            return None
        kind = _normalized_value(
            raw_edge.get("kind") or raw_edge.get("type") or raw_edge.get("on")
        ) or "next"
        return _Edge(
            _clean_identifier(source),
            _clean_identifier(target),
            kind,
            bool(raw_edge.get("condition")) or kind != "next",
        )
    if isinstance(raw_edge, (list, tuple)) and len(raw_edge) == 2:
        return _Edge(_clean_identifier(raw_edge[0]), _clean_identifier(raw_edge[1]))
    return None


def _reachable(entrypoint, adjacency, blocked=None):
    if entrypoint is None:
        return set()
    blocked = set(blocked or ())
    if entrypoint in blocked:
        return set()
    visited = set()
    pending = [entrypoint]
    while pending:
        node = pending.pop()
        if node in visited or node in blocked:
            continue
        visited.add(node)
        pending.extend(
            target
            for target in reversed(adjacency.get(node, []))
            if target not in blocked
        )
    return visited


def _reverse_reachable(starts, predecessors):
    visited = set()
    pending = list(starts)
    while pending:
        node = pending.pop()
        if node in visited:
            continue
        visited.add(node)
        pending.extend(predecessors.get(node, []))
    return visited


def _find_path(entrypoint, target, adjacency, blocked=None):
    blocked = set(blocked or ())
    if entrypoint in blocked or target in blocked:
        return None
    pending = deque([entrypoint])
    parents = {entrypoint: None}
    while pending:
        node = pending.popleft()
        if node == target:
            path = []
            current = node
            while current is not None:
                path.append(current)
                current = parents[current]
            return list(reversed(path))
        for child in sorted(adjacency.get(node, [])):
            if child in blocked or child in parents:
                continue
            parents[child] = node
            pending.append(child)
    return None


def _strongly_connected_components(adjacency):
    visited = set()
    finish_order = []
    for start in sorted(adjacency):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for target in sorted(adjacency[node], reverse=True):
                if target not in visited:
                    stack.append((target, False))

    reverse = {node: [] for node in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].append(source)
    assigned = set()
    components = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component = []
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.append(node)
            for source in sorted(reverse[node], reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    pending.append(source)
        components.append(sorted(component))
    return sorted(components)


def _global_cycle_bound(artifact, policy):
    constraints = artifact.get("operational_constraints")
    if constraints is None:
        constraints = artifact.get("constraints")
    constraints = constraints if isinstance(constraints, dict) else {}
    values = [
        policy.get("max_workflow_iterations"),
        constraints.get("max_iterations"),
    ]
    declared = [value for value in values if value is not None]
    if not declared:
        return None, None
    parsed = [_positive_int(value) for value in declared]
    if any(value is None for value in parsed):
        return None, "declared global iteration bound is invalid"
    return min(parsed), None


def _component_cycle_bound(
    component,
    global_bound,
    nodes,
    entrypoint,
    adjacency,
    reachable,
):
    if global_bound is not None:
        return global_bound
    node_bounds = {node: _positive_int(nodes[node].get("max_iterations")) for node in component}
    if all(bound is not None for bound in node_bounds.values()):
        return max(node_bounds.values())
    controllers = [node for node, bound in node_bounds.items() if bound is not None]
    for controller in controllers:
        if controller not in reachable:
            continue
        dominates_component = all(
            member == controller
            or member not in _reachable(entrypoint, adjacency, blocked={controller})
            for member in component
        )
        if dominates_component and _acyclic_without_controller(
            component, controller, adjacency
        ):
            return node_bounds[controller]
    return None


def _acyclic_without_controller(component, controller, adjacency):
    remaining = set(component) - {controller}
    indegree = {node: 0 for node in remaining}
    for source in remaining:
        for target in adjacency[source]:
            if target in remaining:
                indegree[target] += 1
    pending = deque(sorted(node for node, degree in indegree.items() if degree == 0))
    removed = 0
    while pending:
        node = pending.popleft()
        removed += 1
        for target in sorted(adjacency[node]):
            if target not in indegree:
                continue
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    return removed == len(remaining)


def _approval_control_risks(nodes, adjacency, entrypoint, reachable, artifact):
    guards = {node_id for node_id, step in nodes.items() if _is_approval_guard(step)}
    risks = []
    sensitive_nodes = [
        node_id
        for node_id in sorted(reachable)
        if _is_sensitive_step(nodes[node_id])
    ]
    if artifact.get("human_review_required") is True and sensitive_nodes:
        risks.append(
            _risk(
                "global_review_without_graph_enforcement",
                "HIGH",
                {"sensitive_nodes": sensitive_nodes[:100]},
                "A global review declaration does not prove that every sensitive path crosses an approval guard.",
            )
        )
    for node_id in sensitive_nodes:
        step = nodes[node_id]
        if _requires_direct_approval(step) or node_id in guards:
            _append_self_approval_risk(risks, node_id, step)
            continue
        effective_guards, self_approval_guards = _effective_approval_guards(
            node_id, step, guards, nodes, adjacency, reachable
        )
        for guard in sorted(self_approval_guards):
            risks.append(
                _risk(
                    "self_approved_sensitive_action",
                    "HIGH",
                    {
                        "node": node_id,
                        "approval_guard": guard,
                        "actor": _execution_principal(step),
                    },
                    "The same workflow principal operates an approval guard and its downstream sensitive action.",
                )
            )
        bypass_path = _find_path(
            entrypoint, node_id, adjacency, blocked=effective_guards
        )
        if bypass_path is not None:
            risks.append(
                _risk(
                    "sensitive_action_without_approval_guard",
                    "HIGH",
                    {"node": node_id, "unguarded_path": bypass_path},
                    "A sensitive workflow action is reachable without an approval guard.",
                )
            )
    return risks, guards


def _append_self_approval_risk(risks, node_id, step):
    actor = _normalized_value(step.get("actor") or step.get("executor"))
    approver = _normalized_value(
        step.get("approved_by") or step.get("approval_actor") or step.get("reviewer")
    )
    if actor and approver and actor == approver:
        risks.append(
            _risk(
                "self_approved_sensitive_action",
                "HIGH",
                {"node": node_id, "actor": actor},
                "The same workflow principal executes and approves a sensitive action.",
            )
        )


def _taint_risks(nodes, adjacency, entrypoint, reachable):
    sources = []
    for node_id, step in nodes.items():
        if node_id not in reachable:
            continue
        input_source = _normalized_value(step.get("input_source"))
        trust = _normalized_value(step.get("input_trust") or step.get("trust_level"))
        classification = _normalized_value(
            step.get("data_classification") or step.get("output_data_classification")
        )
        if input_source in _MODEL_OUTPUT_SOURCES:
            sources.append((node_id, "model_output"))
        elif input_source in _UNTRUSTED_SOURCES or trust in {"external", "untrusted"}:
            sources.append((node_id, "untrusted"))
        if (
            classification in _SENSITIVE_CLASSIFICATIONS
            or step.get("contains_sensitive_data") is True
            or input_source in {"secret_store", "credential_store"}
        ):
            sources.append((node_id, "sensitive"))

    risks = []
    observed = set()
    pending = deque((node, taint, [node]) for node, taint in sources)
    while pending:
        node_id, taint, path = pending.popleft()
        state = (node_id, taint)
        if state in observed:
            continue
        observed.add(state)
        step = nodes[node_id]
        if _taint_is_sanitized(step, taint):
            continue

        tool = _normalized_value(step.get("tool"))
        action = _normalized_value(step.get("action"))
        if taint in {"untrusted", "model_output"} and (
            tool in SENSITIVE_TOOLS or action in HIGH_IMPACT_ACTIONS
        ):
            risks.append(
                _risk(
                    "tainted_dataflow_to_sensitive_tool",
                    "HIGH",
                    {"node": node_id, "taint": taint, "path": path},
                    "Unvalidated data can reach a sensitive tool or high-impact action.",
                )
            )
        if taint == "model_output" and (
            tool in _CODE_EXECUTION_TOOLS or action in _CODE_EXECUTION_ACTIONS
        ):
            risks.append(
                _risk(
                    "model_output_to_code_execution",
                    "CRITICAL",
                    {"node": node_id, "path": path},
                    "Model-generated content can directly influence code or system execution.",
                )
            )
        if taint == "sensitive" and (
            tool in _EXTERNAL_SINK_TOOLS or action in _EXTERNAL_SINK_ACTIONS
        ):
            risks.append(
                _risk(
                    "sensitive_dataflow_to_external_sink",
                    "CRITICAL",
                    {"node": node_id, "path": path},
                    "Sensitive data can reach an external communication or payment sink.",
                )
            )
        if taint in {"untrusted", "model_output"} and (
            step.get("controls_transition") is True
            or step.get("dynamic_routing") is True
            or _normalized_value(step.get("action")) in {"route", "dispatch"}
        ):
            risks.append(
                _risk(
                    "untrusted_data_controls_workflow",
                    "HIGH",
                    {"node": node_id, "taint": taint, "path": path},
                    "Unvalidated data can influence workflow control flow.",
                )
            )
        for target in adjacency[node_id]:
            if target in reachable and (target, taint) not in observed:
                pending.append((target, taint, path + [target]))
    return _deduplicate_risks(risks)


def _privilege_transition_risks(
    nodes,
    edges,
    artifact,
    entrypoint,
    adjacency,
    reachable,
    approval_guards,
):
    risks = []
    for edge in edges:
        if edge.source not in reachable or edge.target not in reachable:
            continue
        source = nodes[edge.source]
        target = nodes[edge.target]
        source_permissions = _normalized_set(source.get("permissions"))
        target_permissions = _normalized_set(target.get("permissions"))
        escalation = (target_permissions - source_permissions) & ELEVATED_PERMISSIONS
        if not escalation:
            continue
        guarded = _requires_direct_approval(target)
        if not guarded:
            effective_guards, _ = _effective_approval_guards(
                edge.target,
                target,
                approval_guards,
                nodes,
                adjacency,
                reachable,
            )
            guarded = _find_path(
                entrypoint, edge.target, adjacency, blocked=effective_guards
            ) is None
        if not guarded:
            risks.append(
                _risk(
                    "unapproved_privilege_escalation",
                    "CRITICAL",
                    {
                        "node": edge.target,
                        "permissions": sorted(escalation),
                        "transition": f"{edge.source}->{edge.target}",
                    },
                    "Workflow transition adds elevated permissions without an approval cut.",
                )
            )
    return risks


def _taint_is_sanitized(step, taint):
    if taint == "sensitive":
        controls = (
            step.get("redacts_sensitive_data"),
            step.get("data_loss_prevention"),
            step.get("output_filter"),
        )
    else:
        controls = (step.get("input_validation"), step.get("sanitizes_input"))
    return any(_effective_control(control) for control in controls)


def _effective_control(value):
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, str):
        normalized = _normalized_value(value)
        tokens = set(normalized.split("_"))
        return (
            normalized not in _DISABLED_CONTROL_VALUES
            and not tokens & _NON_OPERATIONAL_CONTROL_TOKENS
        )
    if isinstance(value, dict):
        if value.get("enabled") is False:
            return False
        return any(
            _effective_control(value.get(field))
            for field in ("strategy", "method", "rules", "validator", "policy")
        )
    if isinstance(value, (list, tuple, set)):
        return any(_effective_control(item) for item in value)
    return False


def _is_approval_guard(step):
    return (
        step.get("approval_gate") is True
        or step.get("human_review") is True
        or _normalized_value(step.get("action")) in _APPROVAL_ACTIONS
        or _normalized_value(step.get("type")) in _APPROVAL_ACTIONS
        or _normalized_value(step.get("tool")) == "human_review"
    )


def _effective_approval_guards(
    node_id, step, guards, nodes, adjacency, reachable
):
    relevant_guards = {
        guard
        for guard in guards
        if guard in reachable
        and guard != node_id
        and _find_path(guard, node_id, adjacency) is not None
    }
    executor = _execution_principal(step)
    if not executor:
        return relevant_guards, set()
    self_approval = {
        guard
        for guard in relevant_guards
        if _approval_principal(nodes[guard]) == executor
    }
    return relevant_guards - self_approval, self_approval


def _execution_principal(step):
    return _normalized_value(step.get("actor") or step.get("executor"))


def _approval_principal(step):
    return _normalized_value(
        step.get("approver")
        or step.get("reviewer")
        or step.get("approved_by")
        or step.get("actor")
        or step.get("executor")
    )


def _requires_direct_approval(step):
    return step.get("requires_approval") is True or step.get("approval_required") is True


def _is_sensitive_step(step):
    return _normalized_value(step.get("tool")) in SENSITIVE_TOOLS or _is_high_impact_step(step)


def _is_high_impact_step(step):
    return _normalized_value(step.get("action")) in HIGH_IMPACT_ACTIONS


def _declares_terminal(step):
    return step.get("terminal") is True or _normalized_value(step.get("action")) in {
        "finish",
        "return",
        "stop",
    }


def _weak_component_count(nodes, adjacency):
    undirected = {node: set() for node in nodes}
    for source, targets in adjacency.items():
        for target in targets:
            undirected[source].add(target)
            undirected[target].add(source)
    visited = set()
    count = 0
    for start in sorted(nodes):
        if start in visited:
            continue
        count += 1
        pending = [start]
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            visited.add(node)
            pending.extend(undirected[node] - visited)
    return count


def _result(
    nodes,
    edges,
    entrypoint,
    terminal_nodes,
    reachable,
    cycles,
    risks,
    assessment_complete,
    metrics,
    nodes_without_terminal_path,
):
    deduplicated = _deduplicate_risks(risks)
    if len(deduplicated) > _MAX_RISKS:
        assessment_complete = False
        deduplicated = deduplicated[: _MAX_RISKS - 1]
        deduplicated.append(
            _risk(
                "workflow_risk_limit_reached",
                "HIGH",
                {"limit": _MAX_RISKS},
                "Workflow produced more risks than the bounded result limit.",
            )
        )
    severity_counts = {severity: 0 for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    for risk in deduplicated:
        severity_counts[risk["severity"]] = severity_counts.get(risk["severity"], 0) + 1
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "entrypoint": entrypoint,
        "terminal_nodes": sorted(terminal_nodes),
        "reachable_nodes": sorted(reachable),
        "cycles": sorted(cycles),
        "risks": deduplicated,
        "scoring_version": WORKFLOW_GRAPH_SCORING_VERSION,
        "assessment_complete": assessment_complete,
        "nodes_without_terminal_path": sorted(nodes_without_terminal_path),
        "graph_metrics": metrics,
        "risk_summary": {
            "risk_count": len(deduplicated),
            "severity_counts": severity_counts,
        },
        "edges": [
            {
                "from": edge.source,
                "to": edge.target,
                "kind": edge.kind,
                "conditional": edge.conditional,
            }
            for edge in edges
        ],
    }


def _deduplicate_risks(risks):
    result = []
    seen = set()
    for risk in risks:
        key = (risk.get("indicator"), repr(risk.get("evidence")))
        if key in seen:
            continue
        seen.add(key)
        result.append(risk)
    return result


def _risk(indicator, severity, evidence, detail):
    return {
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "detail": detail,
    }


def _normalized_set(value):
    if value in (None, ""):
        return set()
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, (list, tuple, set)):
        return set()
    return {_normalized_value(item) for item in values if _normalized_value(item)}


def _positive_int(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    return parsed if 0 < parsed <= 1_000_000_000 else None


def _clean_identifier(value):
    return str(value or "").strip()[:_MAX_IDENTIFIER_CHARS]


def _normalized_value(value):
    return "_".join(re.findall(r"[a-z0-9*]+", str(value or "").lower()))

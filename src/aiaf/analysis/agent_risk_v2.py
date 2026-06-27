"""Authority- and blast-radius-aware static risk analysis for AI agents."""

import json
import math
import re
from collections.abc import Iterable
from typing import Any

from .agent_policy_profiles import AUTONOMY_ORDER, resolve_agent_policy
from .workflow_graph import analyze_workflow_graph

AGENT_RISK_SCORING_VERSION = "2.0"
_MAX_TOOLS = 100
_MAX_PERMISSIONS = 200
_MAX_AGENTS = 200
_MAX_DELEGATIONS = 1_000
_MAX_CONTROL_ITEMS = 100
_MAX_TEXT_CHARS = 256
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

AUTONOMY_RISK = {
    "none": 0.0,
    "low": 2.0,
    "supervised": 3.0,
    "medium": 5.0,
    "high": 7.0,
    "autonomous": 9.0,
    "full": 10.0,
}
TOOL_RISK = {
    "browser": 6.0,
    "cloud_admin": 10.0,
    "code_interpreter": 9.0,
    "database": 8.0,
    "email": 7.0,
    "filesystem": 7.5,
    "http": 6.0,
    "payment": 10.0,
    "shell": 9.5,
}
PERMISSION_RISK = {
    "*": 10.0,
    "admin": 10.0,
    "root": 10.0,
    "sudo": 10.0,
    "transfer_funds": 10.0,
    "deploy": 9.0,
    "delete": 8.5,
    "execute": 8.0,
    "write": 6.0,
    "send_email": 6.0,
    "network": 5.5,
    "read": 2.0,
}
_CREDENTIAL_SCOPE = {
    "none": 0.0,
    "ephemeral": 2.0,
    "read_only": 3.0,
    "scoped": 4.0,
    "resource": 4.0,
    "project": 6.0,
    "broad": 8.0,
    "organization": 8.5,
    "cross_account": 9.0,
    "admin": 10.0,
    "unrestricted": 10.0,
}
_TARGET_SCOPE = {
    "single_resource": 2.0,
    "resource": 2.0,
    "project": 4.0,
    "environment": 5.0,
    "organization": 7.5,
    "cross_account": 9.0,
    "multi_tenant": 9.0,
    "unrestricted": 10.0,
}
_DATA_SCOPE = {
    "public": 1.0,
    "internal": 3.0,
    "confidential": 7.0,
    "pii": 8.0,
    "financial": 8.5,
    "restricted": 9.0,
    "phi": 9.0,
    "credentials": 10.0,
    "secret": 10.0,
}
_EXTERNAL_TOOLS = {"browser", "email", "http", "payment"}
_PRIVILEGED_TOOLS = {"shell", "cloud_admin", "code_interpreter"}
_FINANCIAL_TOOLS = {"payment"}
_PRIVILEGED_PERMISSIONS = {"*", "admin", "root", "sudo", "deploy", "execute"}
_FINANCIAL_PERMISSIONS = {"transfer_funds"}
_EXTERNAL_PERMISSIONS = {"network", "send_email", "transfer_funds"}
_DISABLED_VALUES = {
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
_NON_OPERATIONAL_TOKENS = frozenset(
    {"draft", "future", "pending", "placeholder", "planned", "proposed", "tbd", "todo"}
)


def assess_agent_risk_v2(
    artifact: dict[str, Any], policy: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Assess static agent authority, reach, workflow, delegation, and controls."""
    factors: list[dict[str, Any]] = []
    assessment_complete = True
    malformed_root = not isinstance(artifact, dict)
    if malformed_root:
        artifact = {}
        _factor(
            factors,
            "malformed_agent_artifact",
            "evidence_quality",
            "HIGH",
            "Agent evidence must be an object.",
            "Provide a structured agent artifact.",
        )
        assessment_complete = False

    applicable = malformed_root or _is_agentic(artifact)
    if not applicable:
        return _not_applicable_result()

    tools, tools_complete = _bounded_set(artifact.get("tools"), _MAX_TOOLS)
    permissions, permissions_complete = _bounded_set(
        artifact.get("permissions"), _MAX_PERMISSIONS
    )
    if not tools_complete:
        assessment_complete = False
        _factor(
            factors,
            "malformed_or_excessive_tool_inventory",
            "evidence_quality",
            "HIGH",
            "Tool inventory is malformed or exceeds 100 entries.",
            "Segment agents and provide a bounded declared-tool inventory.",
        )
    if not permissions_complete:
        assessment_complete = False
        _factor(
            factors,
            "malformed_or_excessive_permission_inventory",
            "evidence_quality",
            "HIGH",
            "Permission inventory is malformed or exceeds 200 entries.",
            "Segment agents and provide a bounded permission inventory.",
        )

    autonomy = _normalize(artifact.get("autonomy_level") or "low")
    if autonomy not in AUTONOMY_RISK:
        assessment_complete = False
        _factor(
            factors,
            "unknown_autonomy_level",
            "evidence_quality",
            "HIGH",
            "Autonomy level is not recognized.",
            "Classify autonomy using none, low, supervised, medium, high, autonomous, or full.",
            evidence=_bounded_text(artifact.get("autonomy_level")),
        )
        autonomy_score = 7.0
    else:
        autonomy_score = AUTONOMY_RISK[autonomy]

    effective_policy, policy_complete, policy_errors = _effective_policy(
        artifact, policy
    )
    assessment_complete = assessment_complete and policy_complete
    factors.extend(policy_errors)
    policy_violations = _policy_violations(
        tools, permissions, autonomy, artifact, effective_policy
    )
    for violation in policy_violations:
        _factor(
            factors,
            violation["indicator"],
            "policy",
            violation["severity"],
            violation["detail"],
            "Reconcile agent authority with the approved policy before activation.",
            evidence=violation.get("evidence"),
        )

    workflow_graph = analyze_workflow_graph(artifact, effective_policy)
    workflow_risks = list(workflow_graph.get("risks", []))
    if not workflow_graph.get("assessment_complete", True):
        assessment_complete = False
    for risk in workflow_risks[:500]:
        _factor(
            factors,
            risk.get("indicator", "workflow_security_risk"),
            "workflow",
            _severity(risk.get("severity")),
            risk.get("detail", "Workflow security risk detected."),
            "Correct the unsafe workflow path before runtime activation.",
            evidence=risk.get("evidence"),
        )

    delegation = _analyze_delegation(artifact)
    if not delegation["assessment_complete"]:
        assessment_complete = False
    for risk in delegation["risks"]:
        _factor(
            factors,
            risk["indicator"],
            "delegation",
            risk["severity"],
            risk["detail"],
            "Constrain delegation authority, depth, and target privileges.",
            evidence=risk.get("evidence"),
        )

    credential_scope, credential_score, credential_complete = _category_score(
        artifact.get("credential_scope"), _CREDENTIAL_SCOPE, "none"
    )
    target_scope, target_score, target_complete = _category_score(
        artifact.get("target_scope"), _TARGET_SCOPE, "single_resource"
    )
    data_scope, data_score, data_complete = _category_score(
        artifact.get("data_scope") or artifact.get("data_classification"),
        _DATA_SCOPE,
        "internal",
    )
    for complete, indicator, detail in (
        (credential_complete, "unknown_credential_scope", "Credential scope is not recognized."),
        (target_complete, "unknown_target_scope", "Target scope is not recognized."),
        (data_complete, "unknown_agent_data_scope", "Agent data scope is not recognized."),
    ):
        if not complete:
            assessment_complete = False
            _factor(
                factors,
                indicator,
                "evidence_quality",
                "MEDIUM",
                detail,
                "Classify the scope using the documented authority taxonomy.",
            )

    tool_scores = [TOOL_RISK.get(tool, 3.0) for tool in tools]
    permission_scores = [PERMISSION_RISK.get(permission, 4.0) for permission in permissions]
    authority_score = _monotonic_set_score(
        [*tool_scores, *permission_scores, credential_score, target_score]
    )
    authority_signals = {
        "tools": sorted(
            ({"name": tool, "score": TOOL_RISK.get(tool, 3.0)} for tool in tools),
            key=lambda item: (-item["score"], item["name"]),
        ),
        "permissions": sorted(
            (
                {"name": permission, "score": PERMISSION_RISK.get(permission, 4.0)}
                for permission in permissions
            ),
            key=lambda item: (-item["score"], item["name"]),
        ),
        "credential_scope": {"value": credential_scope, "score": credential_score},
        "target_scope": {"value": target_scope, "score": target_score},
    }

    external_reach = 0.0
    if tools & _EXTERNAL_TOOLS or permissions & _EXTERNAL_PERMISSIONS:
        external_reach = 7.0
    if artifact.get("internet_access") is True:
        external_reach = max(external_reach, 9.0)
    if target_scope in {"cross_account", "multi_tenant", "unrestricted"}:
        external_reach = max(external_reach, target_score)
    persistence_score = _persistence_score(artifact)
    action_scale, scale_complete = _action_scale(artifact, effective_policy)
    if not scale_complete:
        assessment_complete = False
        _factor(
            factors,
            "malformed_agent_action_budget",
            "evidence_quality",
            "HIGH",
            "Agent action or concurrency budget is malformed.",
            "Provide positive bounded action, external-call, and concurrency limits.",
        )
    reach_score = _monotonic_set_score(
        [external_reach, data_score, persistence_score, action_scale]
    )

    workflow_score = max(
        (_risk_severity_score(risk.get("severity")) for risk in workflow_risks),
        default=0.0,
    )
    delegation_score = max(
        (_risk_severity_score(risk.get("severity")) for risk in delegation["risks"]),
        default=0.0,
    )

    dimensions = {
        "autonomy": {"score": autonomy_score, "value": autonomy},
        "authority": {"score": authority_score, "signals": authority_signals},
        "reach_and_persistence": {
            "score": reach_score,
            "signals": {
                "external_reach": external_reach,
                "data_scope": {"value": data_scope, "score": data_score},
                "persistence": persistence_score,
                "action_scale": action_scale,
            },
        },
        "workflow": {
            "score": workflow_score,
            "risk_count": len(workflow_risks),
        },
        "delegation": {
            "score": delegation_score,
            "risk_count": len(delegation["risks"]),
        },
    }
    weights = {
        "autonomy": 0.18,
        "authority": 0.29,
        "reach_and_persistence": 0.18,
        "workflow": 0.22,
        "delegation": 0.13,
    }
    inherent_base = math.sqrt(
        sum(weights[name] * dimensions[name]["score"] ** 2 for name in weights)
    )

    interactions = _agent_interactions(
        artifact,
        autonomy_score,
        tools,
        permissions,
        credential_score,
        data_score,
        external_reach,
        persistence_score,
        workflow_risks,
        delegation,
        factors,
    )
    inherent_risk = round(
        min(10.0, inherent_base + min(3.0, sum(item["bonus"] for item in interactions))),
        3,
    )

    controls = _assess_agent_controls(
        artifact,
        effective_policy,
        autonomy_score,
        authority_score,
        reach_score,
        bool(delegation["edge_count"]),
        factors,
    )
    assessment_complete = assessment_complete and controls["assessment_complete"]
    residual = round(inherent_risk * (1.0 - 0.4 * controls["effectiveness"]), 3)
    evidence_quality = _evidence_quality(
        artifact,
        effective_policy,
        workflow_graph,
        controls,
        factors,
    )
    if evidence_quality["confidence"] < 0.6:
        _factor(
            factors,
            "limited_agent_risk_evidence",
            "evidence_quality",
            "MEDIUM",
            "Agent risk evidence has limited coverage or verification quality.",
            "Document authority scopes, workflow, policy, constraints, and verified controls.",
        )
    uncertainty_margin = round((1.0 - evidence_quality["confidence"]) * 3.0, 3)
    lower_bound = round(
        max(0.0, inherent_risk * (1.0 - min(0.6, 0.4 * controls["effectiveness"] + 0.1))),
        3,
    )
    upper_bound = round(min(10.0, residual + uncertainty_margin), 3)
    score_gates = _agent_score_gates(
        interactions,
        workflow_risks,
        delegation["risks"],
        policy_violations,
        controls,
    )
    for gate in score_gates:
        upper_bound = max(upper_bound, gate["minimum_score"])
    upper_bound = round(min(10.0, upper_bound), 3)
    severity = _score_severity(upper_bound)
    for gate in score_gates:
        if _SEVERITY_ORDER[gate["minimum_severity"]] > _SEVERITY_ORDER[severity]:
            severity = gate["minimum_severity"]

    indicators = _unique(factor["indicator"] for factor in factors)
    recommendations = _unique(
        factor["recommendation"]
        for factor in factors
        if factor.get("recommendation")
    )
    return {
        "applicable": True,
        "assessment_version": AGENT_RISK_SCORING_VERSION,
        "scoring_version": AGENT_RISK_SCORING_VERSION,
        "methodology": "authority_blast_radius_workflow_delegation_residual_risk",
        "score_scale": {"minimum": 0.0, "maximum": 10.0},
        "risk_score": upper_bound,
        "score": upper_bound,
        "inherent_risk_score": inherent_risk,
        "residual_risk_score": residual,
        "lower_confidence_bound": lower_bound,
        "upper_confidence_bound": upper_bound,
        "uncertainty_margin": uncertainty_margin,
        "severity": severity,
        "suspicious": upper_bound >= 2.5,
        "confidence": evidence_quality["confidence"],
        "assessment_complete": assessment_complete,
        "indicators": indicators,
        "factors": factors,
        "dimensions": dimensions,
        "interactions": interactions,
        "control_assessment": controls,
        "evidence_quality": evidence_quality,
        "score_gates": score_gates,
        "workflow_risks": workflow_risks,
        "workflow_graph": workflow_graph,
        "delegation_analysis": delegation,
        "policy_profile": artifact.get("agent_policy_profile"),
        "effective_policy": effective_policy,
        "policy_violations": policy_violations,
        "evidence": {
            "autonomy_level": autonomy,
            "tools": sorted(tools),
            "permissions": sorted(permissions),
            "credential_scope": credential_scope,
            "target_scope": target_scope,
            "data_scope": data_scope,
        },
        "recommendations": recommendations,
    }


def _not_applicable_result():
    return {
        "applicable": False,
        "assessment_version": AGENT_RISK_SCORING_VERSION,
        "scoring_version": AGENT_RISK_SCORING_VERSION,
        "methodology": "authority_blast_radius_workflow_delegation_residual_risk",
        "score_scale": {"minimum": 0.0, "maximum": 10.0},
        "risk_score": 0.0,
        "score": 0.0,
        "inherent_risk_score": 0.0,
        "residual_risk_score": 0.0,
        "lower_confidence_bound": 0.0,
        "upper_confidence_bound": 0.0,
        "uncertainty_margin": 0.0,
        "severity": "LOW",
        "suspicious": False,
        "confidence": 1.0,
        "assessment_complete": True,
        "indicators": [],
        "factors": [],
        "dimensions": {},
        "interactions": [],
        "control_assessment": {},
        "evidence_quality": {"confidence": 1.0, "applicable": False},
        "score_gates": [],
        "workflow_risks": [],
        "workflow_graph": {},
        "delegation_analysis": {},
        "policy_profile": None,
        "effective_policy": {},
        "policy_violations": [],
        "evidence": {},
        "recommendations": [],
    }


def _effective_policy(artifact, supplied_policy):
    errors = []
    complete = True
    if supplied_policy is not None:
        if not isinstance(supplied_policy, dict):
            _factor(
                errors,
                "malformed_agent_policy",
                "policy",
                "HIGH",
                "Supplied agent policy must be an object.",
                "Provide a structured deny-by-default agent policy.",
            )
            return {}, False, errors
        sanitized, sanitized_complete = _sanitize_policy(supplied_policy)
        if not sanitized_complete:
            _factor(
                errors,
                "malformed_agent_policy",
                "policy",
                "HIGH",
                "Supplied agent policy contains malformed bounded controls.",
                "Use typed allowlists, booleans, and bounded numeric limits.",
            )
        return sanitized, sanitized_complete, errors

    overrides = artifact.get("agent_policy")
    if overrides is None:
        overrides = artifact.get("policy")
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, dict):
        _factor(
            errors,
            "malformed_agent_policy",
            "policy",
            "HIGH",
            "Agent policy overrides must be an object.",
            "Provide structured agent policy constraints.",
        )
        overrides = {}
        complete = False
    profile_name = artifact.get("agent_policy_profile")
    try:
        resolved = resolve_agent_policy(profile_name, overrides)
    except (KeyError, TypeError, ValueError):
        _factor(
            errors,
            "unknown_or_malformed_agent_policy_profile",
            "policy",
            "HIGH",
            "Agent policy profile could not be resolved.",
            "Select a defined profile and valid conservative overrides.",
            evidence=_bounded_text(profile_name),
        )
        return overrides, False, errors
    resolved, sanitized_complete = _sanitize_policy(resolved)
    complete = complete and sanitized_complete
    if not sanitized_complete:
        _factor(
            errors,
            "malformed_agent_policy",
            "policy",
            "HIGH",
            "Resolved agent policy contains malformed bounded controls.",
            "Use typed allowlists, booleans, and bounded numeric limits.",
        )
    if not resolved:
        _factor(
            errors,
            "missing_agent_policy",
            "policy",
            "HIGH",
            "Agent has no explicit policy constraints.",
            "Apply a deny-by-default policy profile before activation.",
        )
    return resolved, complete, errors


def _sanitize_policy(policy):
    result = {}
    complete = True
    for field, limit in (
        ("allowed_tools", _MAX_TOOLS),
        ("denied_tools", _MAX_TOOLS),
        ("allowed_permissions", _MAX_PERMISSIONS),
        ("denied_permissions", _MAX_PERMISSIONS),
        ("require_human_review_for_tools", _MAX_TOOLS),
        ("require_approval_for_actions", _MAX_PERMISSIONS),
    ):
        if field not in policy:
            continue
        values, values_complete = _bounded_set(policy.get(field), limit)
        result[field] = sorted(values)
        complete = complete and values_complete
    for field in (
        "require_input_validation_for_external_tools",
        "require_declared_tools",
        "require_termination_path",
        "require_workflow_step_binding",
    ):
        if field not in policy:
            continue
        if isinstance(policy.get(field), bool):
            result[field] = policy[field]
        else:
            complete = False
    for field in ("max_workflow_steps", "max_workflow_iterations"):
        if field not in policy:
            continue
        parsed = _positive_int(policy.get(field))
        if parsed is None:
            complete = False
        else:
            result[field] = parsed
    if "max_external_calls" in policy:
        parsed = _nonnegative_int(policy.get("max_external_calls"))
        if parsed is None:
            complete = False
        else:
            result["max_external_calls"] = parsed
    if "max_autonomy_level" in policy:
        autonomy = _normalize(policy.get("max_autonomy_level"))
        if autonomy not in AUTONOMY_RISK:
            complete = False
        else:
            result["max_autonomy_level"] = autonomy
    return result, complete


def _policy_violations(tools, permissions, autonomy, artifact, policy):
    if not policy:
        return []
    violations = []
    allowed_tools, _ = _bounded_set(policy.get("allowed_tools"), _MAX_TOOLS)
    denied_tools, _ = _bounded_set(policy.get("denied_tools"), _MAX_TOOLS)
    allowed_permissions, _ = _bounded_set(
        policy.get("allowed_permissions"), _MAX_PERMISSIONS
    )
    denied_permissions, _ = _bounded_set(
        policy.get("denied_permissions"), _MAX_PERMISSIONS
    )
    for tool in sorted(tools & denied_tools):
        violations.append(_violation("denied_tool", "CRITICAL", f"Tool {tool} is explicitly denied.", tool=tool))
    for tool in sorted(tools - allowed_tools if allowed_tools else []):
        violations.append(_violation("disallowed_tool", "HIGH", f"Tool {tool} is outside the allowlist.", tool=tool))
    for permission in sorted(permissions & denied_permissions):
        violations.append(_violation("denied_permission", "CRITICAL", f"Permission {permission} is explicitly denied.", permission=permission))
    for permission in sorted(permissions - allowed_permissions if allowed_permissions else []):
        violations.append(_violation("disallowed_permission", "HIGH", f"Permission {permission} is outside the allowlist.", permission=permission))
    max_autonomy = _normalize(policy.get("max_autonomy_level"))
    if max_autonomy and AUTONOMY_ORDER.get(autonomy, 99) > AUTONOMY_ORDER.get(max_autonomy, -1):
        violations.append(
            _violation(
                "autonomy_exceeds_policy",
                "HIGH",
                f"Autonomy {autonomy} exceeds policy maximum {max_autonomy}.",
                autonomy=autonomy,
                maximum=max_autonomy,
            )
        )
    constraints = _operational_constraints(artifact)
    elevated = AUTONOMY_RISK.get(autonomy, 7.0) >= 7.0 or bool(
        tools & set(TOOL_RISK)
    )
    if elevated and not isinstance(constraints, dict):
        violations.append(
            _violation(
                "missing_operational_constraints",
                "HIGH",
                "Elevated authority lacks structured operational constraints.",
            )
        )
    elif elevated and not _has_effective_operational_limit(constraints):
        violations.append(
            _violation(
                "missing_effective_operational_limits",
                "HIGH",
                "Operational constraints do not declare an effective action, call, concurrency, time, token, cost, or delegation bound.",
            )
        )
    return violations


def _analyze_delegation(artifact):
    risks = []
    complete = True
    root_id = _bounded_text(artifact.get("id") or artifact.get("agent_id") or "root")
    agents_raw = artifact.get("agents")
    if agents_raw is None:
        agents_raw = []
    if not isinstance(agents_raw, (list, tuple)):
        agents_raw = []
        complete = False
        risks.append(_delegation_risk("malformed_agent_inventory", "HIGH", {}, "Agent inventory must be a list."))
    if len(agents_raw) > _MAX_AGENTS:
        complete = False
        risks.append(
            _delegation_risk(
                "agent_inventory_limit_exceeded",
                "HIGH",
                {"provided": len(agents_raw), "analyzed": _MAX_AGENTS},
                "Agent inventory exceeds the bounded analysis limit.",
            )
        )
    agents = {
        root_id: {
            "id": root_id,
            "tools": artifact.get("tools"),
            "permissions": artifact.get("permissions"),
            "credential_scope": artifact.get("credential_scope"),
            "target_scope": artifact.get("target_scope"),
        }
    }
    for index, raw in enumerate(list(agents_raw)[:_MAX_AGENTS]):
        if not isinstance(raw, dict):
            complete = False
            risks.append(_delegation_risk("malformed_agent_record", "HIGH", {"index": index}, "Agent record must be an object."))
            continue
        agent_id = _bounded_text(raw.get("id") or raw.get("name"))
        if not agent_id or agent_id in agents:
            complete = False
            risks.append(_delegation_risk("duplicate_or_missing_agent_id", "HIGH", {"index": index, "id": agent_id}, "Agent identifiers must be non-empty and unique."))
            continue
        agents[agent_id] = raw

    delegations_raw = artifact.get("delegations")
    if delegations_raw is None:
        delegations_raw = []
    if not isinstance(delegations_raw, (list, tuple)):
        delegations_raw = []
        complete = False
        risks.append(_delegation_risk("malformed_delegation_inventory", "HIGH", {}, "Delegations must be a list."))
    if len(delegations_raw) > _MAX_DELEGATIONS:
        complete = False
        risks.append(
            _delegation_risk(
                "delegation_limit_exceeded",
                "HIGH",
                {"provided": len(delegations_raw), "analyzed": _MAX_DELEGATIONS},
                "Delegations exceed the bounded analysis limit.",
            )
        )

    adjacency = {agent_id: [] for agent_id in agents}
    edges = []
    edge_keys = set()
    for index, raw in enumerate(list(delegations_raw)[:_MAX_DELEGATIONS]):
        if not isinstance(raw, dict):
            complete = False
            risks.append(_delegation_risk("malformed_delegation", "HIGH", {"index": index}, "Delegation must be an object."))
            continue
        source = _bounded_text(raw.get("from") or raw.get("source") or raw.get("delegator"))
        target = _bounded_text(raw.get("to") or raw.get("target") or raw.get("delegate"))
        if source not in agents or target not in agents:
            complete = False
            risks.append(_delegation_risk("unknown_delegation_agent", "HIGH", {"index": index, "from": source, "to": target}, "Delegation references an unknown agent."))
            continue
        constraints = raw.get("constraints")
        constraint_effect = _delegation_constraint_effect(agents[target], constraints)
        if not constraint_effect["constraints_valid"]:
            complete = False
            risks.append(
                _delegation_risk(
                    "malformed_delegation_constraints",
                    "HIGH",
                    {"index": index, "from": source, "to": target},
                    "Delegation constraints contain malformed bounded authority fields.",
                )
            )
        edge = {
            "from": source,
            "to": target,
            **constraint_effect,
        }
        if (source, target) not in edge_keys:
            edge_keys.add((source, target))
            edges.append(edge)
            adjacency[source].append(target)
        if source == target:
            risks.append(_delegation_risk("self_delegation", "HIGH", {"agent": source}, "Agent delegates authority to itself."))

    reachable = _reachable(root_id, adjacency)
    for agent_id in sorted(set(agents) - reachable):
        risks.append(_delegation_risk("unreachable_delegated_agent", "MEDIUM", {"agent": agent_id}, "Declared delegated agent is unreachable from the root agent."))
    components = _strong_components(adjacency)
    cycles = [component for component in components if len(component) > 1 or component[0] in adjacency[component[0]]]
    if cycles:
        risks.append(_delegation_risk("delegation_cycle", "HIGH", {"cycles": cycles}, "Delegation graph contains a cycle."))
        constraints = _operational_constraints(artifact)
        constraints = constraints if isinstance(constraints, dict) else {}
        bound = _positive_int(constraints.get("max_delegation_depth")) if isinstance(constraints, dict) else None
        if bound is None:
            risks.append(_delegation_risk("unbounded_recursive_delegation", "CRITICAL", {"cycles": cycles}, "Recursive delegation has no effective depth bound."))

    authority = {}
    for agent_id, record in agents.items():
        score, record_complete = _agent_record_authority_details(record)
        authority[agent_id] = score
        if not record_complete:
            complete = False
            risks.append(
                _delegation_risk(
                    "malformed_delegated_authority",
                    "HIGH",
                    {"agent": agent_id},
                    "Agent authority inventory or scope is malformed or exceeds analysis bounds.",
                )
            )
    root_authority = authority[root_id]
    for edge in edges:
        source_score = authority[edge["from"]]
        target_score = authority[edge["to"]]
        effective_target = edge["effective_target_authority"]
        if target_score > source_score + 0.5:
            if effective_target <= source_score + 0.5:
                indicator = "privilege_amplifying_delegation"
                severity = "HIGH"
            elif edge["authority_restricted"]:
                indicator = "insufficiently_scoped_privilege_amplifying_delegation"
                severity = "CRITICAL"
            else:
                indicator = "unscoped_privilege_amplifying_delegation"
                severity = "CRITICAL"
            risks.append(
                _delegation_risk(
                    indicator,
                    severity,
                    {
                        "from": edge["from"],
                        "to": edge["to"],
                        "source_authority": source_score,
                        "target_authority": target_score,
                        "effective_target_authority": effective_target,
                    },
                    "Delegation reaches an agent with greater effective authority.",
                )
            )

    effective_reachable_authority = {root_id: root_authority}
    for _ in range(len(agents)):
        changed = False
        for edge in edges:
            if edge["from"] not in effective_reachable_authority:
                continue
            target = edge["to"]
            candidate = edge["effective_target_authority"]
            if candidate > effective_reachable_authority.get(target, -1.0):
                effective_reachable_authority[target] = candidate
                changed = True
        if not changed:
            break
    amplified = sorted(
        agent_id
        for agent_id, score in effective_reachable_authority.items()
        if agent_id != root_id and score > root_authority + 0.5
    )
    if amplified:
        risks.append(
            _delegation_risk(
                "transitive_authority_amplification",
                "CRITICAL",
                {"root": root_id, "agents": amplified},
                "Root agent can transitively invoke agents with greater authority.",
            )
        )
    return {
        "assessment_complete": complete,
        "root_agent": root_id,
        "agent_count": len(agents),
        "edge_count": len(edges),
        "reachable_agents": sorted(reachable),
        "cycles": cycles,
        "authority_scores": {key: authority[key] for key in sorted(authority)},
        "effective_reachable_authority": {
            key: effective_reachable_authority[key]
            for key in sorted(effective_reachable_authority)
        },
        "risks": _deduplicate_risks(risks),
        "edges": edges,
    }


def _agent_record_authority(record):
    return _agent_record_authority_details(record)[0]


def _agent_record_authority_details(record):
    tools, tools_complete = _bounded_set(record.get("tools"), _MAX_TOOLS)
    permissions, permissions_complete = _bounded_set(
        record.get("permissions"), _MAX_PERMISSIONS
    )
    scores = [TOOL_RISK.get(tool, 3.0) for tool in tools]
    scores.extend(PERMISSION_RISK.get(permission, 4.0) for permission in permissions)
    _, credential_score, credential_complete = _category_score(
        record.get("credential_scope"), _CREDENTIAL_SCOPE, "none"
    )
    _, target_score, target_complete = _category_score(
        record.get("target_scope"), _TARGET_SCOPE, "single_resource"
    )
    scores.extend((credential_score, target_score))
    return _monotonic_set_score(scores), all(
        (tools_complete, permissions_complete, credential_complete, target_complete)
    )


def _agent_interactions(
    artifact,
    autonomy,
    tools,
    permissions,
    credential_score,
    data_score,
    external_reach,
    persistence,
    workflow_risks,
    delegation,
    factors,
):
    interactions = []

    def add(indicator, bonus, severity, detail, recommendation):
        interactions.append({"indicator": indicator, "bonus": bonus, "severity": severity, "detail": detail})
        _factor(factors, indicator, "interaction", severity, detail, recommendation, contribution=bonus)

    privileged = bool(tools & _PRIVILEGED_TOOLS or permissions & _PRIVILEGED_PERMISSIONS)
    financial = bool(tools & _FINANCIAL_TOOLS or permissions & _FINANCIAL_PERMISSIONS)
    if autonomy >= 7.0 and privileged:
        add("autonomous_privileged_execution", 1.75, "CRITICAL", "High-autonomy agent holds privileged execution authority.", "Require sandboxing, scoped credentials, and per-action authorization.")
    if autonomy >= 7.0 and financial:
        add("autonomous_financial_authority", 2.0, "CRITICAL", "High-autonomy agent can initiate financial actions.", "Require dual authorization, transaction limits, and rollback.")
    if artifact.get("self_modification") is True and autonomy >= 7.0 and privileged:
        add("self_modifying_privileged_agent", 2.0, "CRITICAL", "Agent can modify behavior while retaining privileged execution.", "Disable self-modification in privileged environments and require signed updates.")
    if data_score >= 8.0 and external_reach >= 7.0 and persistence >= 5.0:
        add("persistent_sensitive_data_exfiltration_path", 1.75, "CRITICAL", "Persistent agent state combines sensitive data and external reach.", "Isolate memory, enforce egress controls, and expire sensitive context.")
    if credential_score >= 8.0 and any(
        risk.get("indicator") in {"tainted_dataflow_to_sensitive_tool", "model_output_to_code_execution"}
        for risk in workflow_risks
    ):
        add("untrusted_control_of_broad_credentials", 2.0, "CRITICAL", "Untrusted workflow data can influence broadly credentialed actions.", "Use short-lived scoped credentials and deterministic parameter validation.")
    if delegation.get("cycles") and autonomy >= 7.0:
        add("autonomous_recursive_delegation", 1.75, "CRITICAL", "High-autonomy operation combines with recursive delegation.", "Enforce delegation depth, budgets, and root-level cancellation.")
    return interactions


def _assess_agent_controls(artifact, policy, autonomy, authority, reach, has_delegation, factors):
    high_risk = max(autonomy, authority, reach) >= 6.0
    specs = [
        ("runtime_tool_authorization", 1.4, authority >= 5.0),
        ("human_review", 1.1, autonomy >= 5.0 or authority >= 7.0),
        ("sandboxing", 1.1, authority >= 7.0),
        ("credential_scoping", 1.0, authority >= 6.0),
        ("continuous_monitoring", 0.9, high_risk),
        ("audit_logging", 0.8, high_risk),
        ("kill_switch", 1.0, autonomy >= 7.0 or reach >= 7.0),
        ("rate_limits", 0.7, reach >= 5.0),
        ("delegation_policy", 1.0, has_delegation),
    ]
    controls = []
    total_weight = 0.0
    weighted_strength = 0.0
    qualities = []
    complete = True
    for name, weight, applicable in specs:
        if not applicable:
            continue
        value = artifact.get(name)
        if name == "runtime_tool_authorization" and value is None:
            value = None
        if name == "rate_limits" and value is None:
            constraints = _operational_constraints(artifact)
            value = (
                constraints.get("max_external_calls")
                if isinstance(constraints, dict)
                else None
            )
        if isinstance(value, (list, tuple)) and len(value) > _MAX_CONTROL_ITEMS:
            complete = False
            _factor(factors, "agent_control_evidence_limit_exceeded", "evidence_quality", "HIGH", f"{name} evidence exceeds the analysis bound.", "Summarize bounded control evidence.", evidence={"control": name, "provided": len(value)})
        strength, quality, failed = _control_strength(value)
        controls.append({"control": name, "weight": weight, "strength": round(strength, 3), "evidence_quality": round(quality, 3), "status": "FAILED" if failed else "EFFECTIVE" if strength >= 0.7 else "PARTIAL" if strength > 0 else "MISSING"})
        total_weight += weight
        weighted_strength += weight * strength
        qualities.append(quality)
        if failed:
            _factor(factors, f"failed_{name}", "controls", "HIGH", f"{name} evidence records a failed control.", f"Remediate and retest {name}.")
        elif strength <= 0:
            _factor(factors, f"missing_{name}", "controls", "HIGH" if high_risk else "MEDIUM", f"Applicable {name} evidence is absent or disabled.", f"Implement and verify {name}.")
    return {
        "effectiveness": round(weighted_strength / total_weight if total_weight else 0.0, 3),
        "evidence_quality": round(sum(qualities) / len(qualities) if qualities else 0.0, 3),
        "assessment_complete": complete,
        "applicable_control_count": len(controls),
        "effective_control_count": sum(control["strength"] >= 0.7 for control in controls),
        "failed_control_count": sum(control["status"] == "FAILED" for control in controls),
        "controls": controls,
    }


def _control_strength(value):
    if value is None or value is False:
        return 0.0, 0.0, False
    if value is True:
        return 0.4, 0.25, False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0.55, 0.4, False) if value > 0 else (0.0, 0.0, False)
    if isinstance(value, str):
        return (0.45, 0.35, False) if _operational_evidence_text(value) else (0.0, 0.0, False)
    if isinstance(value, dict):
        if value.get("enabled") is False or value.get("implemented") is False:
            return 0.0, 0.4, False
        failed = value.get("passed") is False or value.get("verified") is False or _normalize(value.get("status")) in {"failed", "rejected"}
        if failed:
            return 0.0, 0.7, True
        strength, quality = 0.0, 0.1
        if value.get("enabled") is True or value.get("implemented") is True:
            strength += 0.2
        if any(
            _operational_evidence_text(value.get(field))
            for field in ("method", "policy", "strategy")
        ):
            strength += 0.3
            quality += 0.2
        if _operational_evidence_text(value.get("owner")):
            quality += 0.1
        if value.get("tested") is True or value.get("passed") is True:
            strength += 0.2
            quality += 0.25
        if value.get("verified") is True or value.get("independently_reviewed") is True:
            strength += 0.3
            quality += 0.4
        return min(1.0, strength), min(1.0, quality), False
    if isinstance(value, (list, tuple)):
        values = list(value)[:_MAX_CONTROL_ITEMS]
        if not values:
            return 0.0, 0.0, False
        results = [_control_strength(item) for item in values]
        if any(result[2] for result in results):
            return 0.0, sum(result[1] for result in results) / len(results), True
        return sum(result[0] for result in results) / len(results), sum(result[1] for result in results) / len(results), False
    return 0.0, 0.0, False


def _evidence_quality(artifact, policy, workflow, controls, factors):
    fields = {
        "identity": bool(artifact.get("id") or artifact.get("agent_id") or artifact.get("name")),
        "autonomy_level": artifact.get("autonomy_level") is not None,
        "tools": artifact.get("tools") is not None,
        "permissions": artifact.get("permissions") is not None,
        "operational_constraints": isinstance(
            _operational_constraints(artifact), dict
        ),
        "policy": bool(policy),
        "workflow": bool(artifact.get("workflow_steps") or artifact.get("workflow")),
        "credential_scope": artifact.get("credential_scope") is not None,
        "target_scope": artifact.get("target_scope") is not None,
    }
    coverage = sum(fields.values()) / len(fields)
    malformed = sum(
        factor["indicator"].startswith(("malformed_", "unknown_"))
        or factor["indicator"].endswith("_limit_exceeded")
        for factor in factors
    )
    confidence = 0.6 * coverage + 0.3 * controls["evidence_quality"] + 0.1 * float(workflow.get("assessment_complete", False))
    confidence *= max(0.5, 1.0 - 0.08 * min(malformed, 6))
    confidence = round(min(1.0, max(0.0, confidence)), 3)
    return {
        "confidence": confidence,
        "coverage_ratio": round(coverage, 3),
        "control_evidence_quality": controls["evidence_quality"],
        "fields_present": fields,
        "missing_fields": sorted(field for field, present in fields.items() if not present),
        "malformed_or_truncated_fields": malformed,
    }


def _agent_score_gates(
    interactions, workflow_risks, delegation_risks, policy_violations, controls
):
    names = {item["indicator"] for item in interactions}
    workflow_names = {risk.get("indicator") for risk in workflow_risks}
    delegation_names = {risk.get("indicator") for risk in delegation_risks}
    policy_names = {item["indicator"] for item in policy_violations}
    control_map = {item["control"]: item["strength"] for item in controls["controls"]}
    gates = []

    def add(name, score, severity, reason):
        gates.append({"gate": name, "minimum_score": score, "minimum_severity": severity, "reason": reason})

    if "autonomous_privileged_execution" in names:
        add("autonomous_privileged_execution", 8.5, "CRITICAL", "Autonomous privileged execution has a critical risk floor.")
    if "autonomous_financial_authority" in names:
        add("autonomous_financial_authority", 9.0, "CRITICAL", "Autonomous financial authority has a critical risk floor.")
    if "self_modifying_privileged_agent" in names:
        add("self_modifying_privileged_agent", 9.0, "CRITICAL", "Self-modifying privileged behavior has a critical risk floor.")
    if (
        "unbounded_workflow_cycle" in workflow_names
        or "unbounded_recursive_delegation" in delegation_names
    ):
        add("unbounded_agent_execution", 8.5, "CRITICAL", "Unbounded execution or delegation has a critical risk floor.")
    if any(risk.get("severity") == "CRITICAL" for risk in workflow_risks):
        add("critical_workflow_path", 8.0, "CRITICAL", "Critical workflow evidence sets a residual risk floor.")
    if policy_names & {"denied_tool", "denied_permission"}:
        add("explicit_policy_denial", 8.0, "CRITICAL", "Explicitly denied authority is present in the agent configuration.")
    if "persistent_sensitive_data_exfiltration_path" in names and control_map.get("runtime_tool_authorization", 0.0) < 0.7:
        add("sensitive_persistent_agent_without_runtime_authorization", 8.0, "CRITICAL", "Sensitive persistent external reach lacks verified runtime authorization.")
    return gates


def _persistence_score(artifact):
    scores = []
    memory = _normalize(artifact.get("memory_persistence") or artifact.get("memory_scope"))
    scores.append({"none": 0.0, "session": 3.0, "persistent": 7.0, "long_term": 8.0, "shared": 9.0}.get(memory, 0.0))
    if artifact.get("background_execution") is True or artifact.get("scheduled_execution") is True:
        scores.append(7.0)
    if artifact.get("self_modification") is True:
        scores.append(9.0)
    if artifact.get("can_spawn_agents") is True:
        scores.append(8.0)
    return max(scores, default=0.0)


def _action_scale(artifact, policy):
    constraints = _operational_constraints(artifact)
    constraints = {} if constraints is None else constraints
    if constraints and not isinstance(constraints, dict):
        return 8.0, False
    values = []
    complete = True
    for field in ("max_actions", "max_external_calls", "max_parallel_actions"):
        raw = constraints.get(field) if isinstance(constraints, dict) else None
        if raw is None and field == "max_external_calls":
            raw = policy.get(field) if policy else None
        if raw is None:
            continue
        parsed = _positive_int(raw)
        if parsed is None:
            complete = False
            continue
        values.append(parsed)
    if not values:
        return 6.0, complete
    largest = max(values)
    return round(min(10.0, 1.0 + math.log10(largest + 1) * 2.5), 3), complete


def _has_effective_operational_limit(constraints):
    if not isinstance(constraints, dict):
        return False
    return any(
        _positive_int(constraints.get(field)) is not None
        for field in (
            "max_actions",
            "max_external_calls",
            "max_parallel_actions",
            "max_delegation_depth",
            "max_runtime_seconds",
            "max_tokens",
            "max_cost_cents",
        )
    )


def _operational_constraints(artifact):
    if "operational_constraints" in artifact:
        return artifact.get("operational_constraints")
    return artifact.get("constraints")


def _delegation_constraint_effect(target_record, value):
    raw_authority = _agent_record_authority(target_record)
    result = {
        "constraints_declared": False,
        "constraints_valid": value is None or isinstance(value, dict),
        "authority_restricted": False,
        "effective_target_authority": raw_authority,
    }
    if value is None:
        return result
    if not isinstance(value, dict):
        return result

    parsed = {}
    valid = True
    for field, limit in (
        ("allowed_tools", _MAX_TOOLS),
        ("allowed_permissions", _MAX_PERMISSIONS),
        ("allowed_actions", _MAX_PERMISSIONS),
        ("allowed_targets", _MAX_CONTROL_ITEMS),
    ):
        if field in value:
            parsed[field], complete = _bounded_set(value.get(field), limit)
            valid = valid and complete
            result["constraints_declared"] = result["constraints_declared"] or complete

    constrained_target_score = None
    if "target_scope" in value:
        normalized_scope = _normalize(value.get("target_scope"))
        if normalized_scope in _TARGET_SCOPE:
            constrained_target_score = _TARGET_SCOPE[normalized_scope]
            result["constraints_declared"] = True
        else:
            valid = False

    if "requires_approval" in value:
        approval = value.get("requires_approval")
        if isinstance(approval, bool):
            result["constraints_declared"] = result["constraints_declared"] or approval
        else:
            valid = False
    for field in ("max_calls", "max_actions", "max_delegation_depth"):
        if field in value:
            if _positive_int(value.get(field)) is None:
                valid = False
            else:
                result["constraints_declared"] = True

    result["constraints_valid"] = valid
    if not valid:
        result["constraints_declared"] = False
        return result

    target_tools, _ = _bounded_set(target_record.get("tools"), _MAX_TOOLS)
    target_permissions, _ = _bounded_set(
        target_record.get("permissions"), _MAX_PERMISSIONS
    )
    capability_scores = []
    if "allowed_actions" in parsed:
        capability_scores.extend(
            max(
                TOOL_RISK.get(action, 0.0),
                PERMISSION_RISK.get(action, 0.0),
                4.0 if action not in TOOL_RISK and action not in PERMISSION_RISK else 0.0,
            )
            for action in parsed["allowed_actions"]
        )
    else:
        effective_tools = target_tools
        effective_permissions = target_permissions
        if "allowed_tools" in parsed:
            effective_tools &= parsed["allowed_tools"]
        if "allowed_permissions" in parsed:
            effective_permissions &= parsed["allowed_permissions"]
        capability_scores.extend(TOOL_RISK.get(tool, 3.0) for tool in effective_tools)
        capability_scores.extend(
            PERMISSION_RISK.get(permission, 4.0)
            for permission in effective_permissions
        )

    _, credential_score, _ = _category_score(
        target_record.get("credential_scope"), _CREDENTIAL_SCOPE, "none"
    )
    _, target_score, _ = _category_score(
        target_record.get("target_scope"), _TARGET_SCOPE, "single_resource"
    )
    if constrained_target_score is not None:
        target_score = min(target_score, constrained_target_score)
    if "allowed_targets" in parsed:
        target_count = len(parsed["allowed_targets"])
        target_bound = 0.0 if target_count == 0 else 2.0 if target_count == 1 else 4.0
        target_score = min(target_score, target_bound)

    effective = min(
        raw_authority,
        _monotonic_set_score([*capability_scores, credential_score, target_score]),
    )
    result["effective_target_authority"] = effective
    result["authority_restricted"] = effective < raw_authority - 0.001
    return result


def _category_score(value, mapping, default):
    if value is None:
        return default, mapping[default], True
    normalized = _normalize(value)
    if normalized not in mapping:
        return normalized, 7.0, False
    return normalized, mapping[normalized], True


def _bounded_set(value, limit):
    if value is None:
        return set(), True
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, set):
        values = sorted(value, key=str)
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        return set(), False
    complete = len(values) <= limit
    normalized = set()
    for item in values[:limit]:
        if not isinstance(item, str) or not item.strip() or len(item) > _MAX_TEXT_CHARS:
            complete = False
            continue
        normalized.add(_normalize(item))
    return normalized, complete


def _operational_evidence_text(value):
    if not isinstance(value, str):
        return False
    normalized = _normalize(value)
    tokens = set(normalized.split("_"))
    return bool(normalized) and normalized not in _DISABLED_VALUES and not (
        tokens & _NON_OPERATIONAL_TOKENS
    )


def _monotonic_set_score(scores):
    positive = sorted((float(score) for score in scores if score is not None and score > 0), reverse=True)
    if not positive:
        return 0.0
    return round(min(10.0, positive[0] + 0.2 * (len(positive) - 1)), 3)


def _reachable(start, adjacency):
    visited = set()
    pending = [start]
    while pending:
        node = pending.pop()
        if node in visited:
            continue
        visited.add(node)
        pending.extend(reversed(adjacency.get(node, [])))
    return visited


def _strong_components(adjacency):
    visited, finish = set(), []
    for start in sorted(adjacency):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish.append(node)
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
    assigned, components = set(), []
    for start in reversed(finish):
        if start in assigned:
            continue
        component, pending = [], [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.append(node)
            for source in reverse[node]:
                if source not in assigned:
                    assigned.add(source)
                    pending.append(source)
        components.append(sorted(component))
    return sorted(components)


def _factor(factors, indicator, dimension, severity, detail, recommendation, evidence=None, contribution=0.0):
    candidate = {"indicator": indicator, "dimension": dimension, "severity": severity, "weight": contribution, "contribution": contribution, "detail": detail, "recommendation": recommendation}
    if evidence is not None:
        candidate["evidence"] = evidence
    if candidate not in factors:
        factors.append(candidate)


def _violation(indicator, severity, detail, **evidence):
    return {"indicator": indicator, "severity": severity, "detail": detail, "evidence": evidence or None}


def _delegation_risk(indicator, severity, evidence, detail):
    return {"indicator": indicator, "severity": severity, "evidence": evidence, "detail": detail}


def _deduplicate_risks(risks):
    result, seen = [], set()
    for risk in risks:
        key = (risk["indicator"], json.dumps(risk.get("evidence"), sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            result.append(risk)
    return result


def _risk_severity_score(value):
    return {"LOW": 2.0, "MEDIUM": 4.0, "HIGH": 7.5, "CRITICAL": 10.0}.get(_severity(value), 7.5)


def _severity(value):
    normalized = str(value or "HIGH").upper()
    return normalized if normalized in _SEVERITY_ORDER else "HIGH"


def _score_severity(score):
    if score >= 7.5:
        return "CRITICAL"
    if score >= 5.0:
        return "HIGH"
    if score >= 2.5:
        return "MEDIUM"
    return "LOW"


def _positive_int(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0 < parsed <= 1_000_000_000 else None


def _nonnegative_int(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0 <= parsed <= 1_000_000_000 else None


def _is_agentic(artifact):
    return any(
        artifact.get(field)
        for field in (
            "agentic",
            "autonomy_level",
            "tools",
            "permissions",
            "workflow_steps",
            "workflow",
            "agent_policy",
            "agent_policy_profile",
            "agents",
            "delegations",
        )
    )


def _normalize(value):
    return "_".join(re.findall(r"[a-z0-9*]+", str(value or "").lower()))


def _bounded_text(value):
    return str(value or "").strip()[:_MAX_TEXT_CHARS]


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))

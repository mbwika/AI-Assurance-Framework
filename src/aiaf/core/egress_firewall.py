"""Unified egress and capability firewall with ledger-backed decisions.

This module centralizes runtime decisions for network, tool, and data egress.
Each decision combines:

* agent capability and operational-constraint checks
* policy enforcement point (PEP) evaluation
* tool authorization checks for tool-channel requests
* tamper-evident logging to the agent action ledger
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any

from ..registry.agent_registry import (
    CAPABILITY_DATA_READ,
    CAPABILITY_DATA_WRITE,
    CAPABILITY_NETWORK_EGRESS,
    STATUS_ACTIVE,
    get_agent,
)
from .agent_action_ledger import append_entry
from .policy_enforcement import (
    VERDICT_ALLOW,
    VERDICT_CONDITIONAL,
    VERDICT_DENY,
    enforce_request,
)
from .tool_authorization import authorize as authorize_tool

FIREWALL_VERSION = "1.0"

CHANNEL_NETWORK = "network"
CHANNEL_TOOL = "tool"
CHANNEL_DATA = "data"

CHANNELS: frozenset[str] = frozenset({CHANNEL_NETWORK, CHANNEL_TOOL, CHANNEL_DATA})

LEDGER_DECISION_ALLOW = "ALLOW"
LEDGER_DECISION_DENY = "DENY"
LEDGER_DECISION_FLAG = "FLAG"

_SENSITIVITY_RANK: dict[str, int] = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "RESTRICTED": 4,
}


class FirewallDecisionError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_channel(channel: str) -> str:
    normalized = str(channel or "").strip().lower()
    if normalized not in CHANNELS:
        raise FirewallDecisionError(
            f"channel must be one of {sorted(CHANNELS)}, got {channel!r}"
        )
    return normalized


def _normalize_action(channel: str, action: str | None) -> str:
    if action:
        normalized = str(action).strip().lower()
        if normalized:
            return normalized
    return {
        CHANNEL_NETWORK: "connect",
        CHANNEL_TOOL: "invoke",
        CHANNEL_DATA: "export",
    }[channel]


def _decision_resource(channel: str, target: str) -> str:
    return f"{channel}:{target}"


def _default_required_capabilities(channel: str, action: str) -> list[str]:
    if channel == CHANNEL_NETWORK:
        return [CAPABILITY_NETWORK_EGRESS]
    if channel == CHANNEL_DATA:
        if action in {"read", "query", "fetch"}:
            return [CAPABILITY_DATA_READ]
        return [CAPABILITY_DATA_WRITE]
    return []


def _hash_request(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _matches_any(patterns: list[str], value: str) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _max_sensitivity(left: str, right: str) -> bool:
    return _SENSITIVITY_RANK.get(left.upper(), 0) <= _SENSITIVITY_RANK.get(right.upper(), 0)


def _constraint_decision(
    agent: dict[str, Any],
    channel: str,
    target: str,
    context: dict[str, Any],
    required_capabilities: list[str],
) -> dict[str, Any]:
    reasons: list[str] = []
    conditions_required: list[str] = []
    missing_capabilities = sorted(
        set(required_capabilities) - set(agent.get("capability_flags") or [])
    )
    verdict = VERDICT_ALLOW

    if missing_capabilities:
        verdict = VERDICT_DENY
        reasons.append(
            "Missing required capabilities: " + ", ".join(missing_capabilities)
        )

    constraints = agent.get("operational_constraints") or {}

    allowed_sensitivity = constraints.get("allowed_data_sensitivity")
    context_sensitivity = str(context.get("data_sensitivity") or "").upper()
    if (
        verdict != VERDICT_DENY
        and allowed_sensitivity
        and context_sensitivity
        and not _max_sensitivity(context_sensitivity, str(allowed_sensitivity))
    ):
        verdict = VERDICT_CONDITIONAL
        reasons.append(
            "Context sensitivity exceeds allowed_data_sensitivity constraint."
        )
        conditions_required.append(
            f"data_sensitivity<={str(allowed_sensitivity).upper()}"
        )

    if (
        verdict != VERDICT_DENY
        and channel in {CHANNEL_NETWORK, CHANNEL_DATA}
        and constraints.get("requires_approval_for_egress")
        and not (
            context.get("approval_granted")
            or context.get("human_approved")
            or context.get("user_consent_given")
        )
    ):
        verdict = VERDICT_CONDITIONAL
        reasons.append("Egress requires approval under agent operational constraints.")
        conditions_required.append("approval_granted")

    if verdict != VERDICT_DENY and channel == CHANNEL_TOOL:
        max_calls = constraints.get("max_tool_calls_per_session")
        if max_calls is not None and int(context.get("call_count") or 0) >= int(max_calls):
            verdict = VERDICT_CONDITIONAL
            reasons.append("Session has reached max_tool_calls_per_session.")
            conditions_required.append(f"call_count<{int(max_calls)}")

    blocked_targets = [
        str(pattern)
        for pattern in (constraints.get("blocked_egress_destinations") or [])
        if str(pattern).strip()
    ]
    if verdict != VERDICT_DENY and channel in {CHANNEL_NETWORK, CHANNEL_DATA} and blocked_targets:
        if _matches_any(blocked_targets, target):
            verdict = VERDICT_DENY
            reasons.append("Target matches blocked_egress_destinations constraint.")

    allowed_targets = [
        str(pattern)
        for pattern in (constraints.get("allowed_egress_destinations") or [])
        if str(pattern).strip()
    ]
    if verdict != VERDICT_DENY and channel in {CHANNEL_NETWORK, CHANNEL_DATA} and allowed_targets:
        if not _matches_any(allowed_targets, target):
            verdict = VERDICT_DENY
            reasons.append("Target is outside allowed_egress_destinations constraint.")

    if not reasons:
        reasons.append("Agent capabilities and operational constraints permit request.")

    return {
        "verdict": verdict,
        "reasons": reasons,
        "conditions_required": conditions_required,
        "required_capabilities": required_capabilities,
        "missing_capabilities": missing_capabilities,
    }


def _ledger_decision(verdict: str) -> str:
    if verdict == VERDICT_DENY:
        return LEDGER_DECISION_DENY
    if verdict == VERDICT_CONDITIONAL:
        return LEDGER_DECISION_FLAG
    return LEDGER_DECISION_ALLOW


def _combine_verdicts(*verdicts: str) -> str:
    filtered = [v for v in verdicts if v]
    if VERDICT_DENY in filtered:
        return VERDICT_DENY
    if VERDICT_CONDITIONAL in filtered:
        return VERDICT_CONDITIONAL
    return VERDICT_ALLOW


def decide_egress(
    agent_id: str,
    session_id: str,
    channel: str,
    target: str,
    store: Any,
    *,
    action: str | None = None,
    context: dict[str, Any] | None = None,
    policy_id: str | None = None,
    required_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate and log a network/tool/data egress decision."""
    if not str(agent_id).strip():
        raise FirewallDecisionError("agent_id must be non-empty")
    if not str(session_id).strip():
        raise FirewallDecisionError("session_id must be non-empty")
    if not str(target).strip():
        raise FirewallDecisionError("target must be non-empty")

    channel = _normalize_channel(channel)
    action = _normalize_action(channel, action)
    context = dict(context or {})
    target = str(target).strip()
    decided_at = _utc_now()

    agent = get_agent(agent_id, store)
    effective_required_capabilities = sorted(
        set(required_capabilities or _default_required_capabilities(channel, action))
    )

    if agent is None:
        verdict = VERDICT_DENY
        reasons = [f"Agent '{agent_id}' is not registered."]
        conditions_required: list[str] = []
        capability_result = {
            "verdict": verdict,
            "reasons": reasons,
            "conditions_required": conditions_required,
            "required_capabilities": effective_required_capabilities,
            "missing_capabilities": effective_required_capabilities,
        }
        pep_result = {
            "verdict": VERDICT_ALLOW,
            "policy_ids_evaluated": [],
            "reasons": ["No PEP evaluation performed because agent is missing."],
            "conditions_required": [],
            "mode": "PASSTHROUGH",
        }
        tool_result = None
    elif agent.get("status") != STATUS_ACTIVE:
        verdict = VERDICT_DENY
        reasons = [
            f"Agent '{agent_id}' is {agent.get('status')}, not active."
            + (
                f" Reason: {agent.get('status_reason')}."
                if agent.get("status_reason")
                else ""
            )
        ]
        conditions_required = []
        capability_result = {
            "verdict": verdict,
            "reasons": reasons,
            "conditions_required": conditions_required,
            "required_capabilities": effective_required_capabilities,
            "missing_capabilities": [],
        }
        pep_result = {
            "verdict": VERDICT_ALLOW,
            "policy_ids_evaluated": [],
            "reasons": ["No PEP evaluation performed because agent is inactive."],
            "conditions_required": [],
            "mode": "PASSTHROUGH",
        }
        tool_result = None
    else:
        capability_result = _constraint_decision(
            agent,
            channel,
            target,
            context,
            effective_required_capabilities,
        )
        pep_result = enforce_request(
            principal_id=agent_id,
            action=action,
            resource=_decision_resource(channel, target),
            store=store,
            context=context,
            policy_id=policy_id,
        )
        tool_result = None
        if channel == CHANNEL_TOOL:
            tool_result = authorize_tool(
                agent_id=agent_id,
                tool_name=target,
                session_context=context,
                store=store,
            )
        verdict = _combine_verdicts(
            capability_result["verdict"],
            pep_result.get("verdict", VERDICT_ALLOW),
            (tool_result or {}).get("verdict", ""),
        )
        reasons = []
        reasons.extend(capability_result["reasons"])
        reasons.extend(pep_result.get("reasons") or [])
        if tool_result:
            reasons.extend(tool_result.get("reasons") or [])
        conditions_required = []
        conditions_required.extend(capability_result["conditions_required"])
        conditions_required.extend(pep_result.get("conditions_required") or [])
        if tool_result:
            conditions_required.extend(tool_result.get("unmet_conditions") or [])

    ledger_entry = append_entry(
        session_id=session_id,
        tool_name=target if channel == CHANNEL_TOOL else f"egress:{channel}",
        input_hash=_hash_request(
            {
                "agent_id": agent_id,
                "channel": channel,
                "action": action,
                "target": target,
                "context": context,
            }
        ),
        decision=_ledger_decision(verdict),
        store=store,
        timestamp=decided_at,
        metadata={
            "agent_id": agent_id,
            "channel": channel,
            "action": action,
            "target": target,
            "verdict": verdict,
            "policy_ids_evaluated": pep_result.get("policy_ids_evaluated") or [],
            "tool_authorization_verdict": (tool_result or {}).get("verdict"),
            "required_capabilities": capability_result.get("required_capabilities") or [],
            "missing_capabilities": capability_result.get("missing_capabilities") or [],
        },
    )

    return {
        "firewall_version": FIREWALL_VERSION,
        "agent_id": agent_id,
        "session_id": session_id,
        "channel": channel,
        "action": action,
        "target": target,
        "verdict": verdict,
        "ledger_decision": ledger_entry["decision"],
        "reasons": reasons,
        "conditions_required": sorted(set(conditions_required)),
        "capability_decision": capability_result,
        "policy_decision": pep_result,
        "tool_authorization": tool_result,
        "ledger_entry_id": ledger_entry["entry_id"],
        "ledger_sequence": ledger_entry["sequence"],
        "decided_at": decided_at,
        "evidence_origin": "LOCALLY_OBSERVED",
    }


def authorize_network_egress(
    agent_id: str,
    session_id: str,
    destination: str,
    store: Any,
    *,
    action: str = "connect",
    context: dict[str, Any] | None = None,
    policy_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate a network egress attempt."""
    return decide_egress(
        agent_id=agent_id,
        session_id=session_id,
        channel=CHANNEL_NETWORK,
        target=destination,
        store=store,
        action=action,
        context=context,
        policy_id=policy_id,
    )


def authorize_tool_egress(
    agent_id: str,
    session_id: str,
    tool_name: str,
    store: Any,
    *,
    context: dict[str, Any] | None = None,
    policy_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate a tool invocation under the unified firewall."""
    return decide_egress(
        agent_id=agent_id,
        session_id=session_id,
        channel=CHANNEL_TOOL,
        target=tool_name,
        store=store,
        action="invoke",
        context=context,
        policy_id=policy_id,
    )


def authorize_data_egress(
    agent_id: str,
    session_id: str,
    target: str,
    store: Any,
    *,
    action: str = "export",
    context: dict[str, Any] | None = None,
    policy_id: str | None = None,
    required_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate a data egress or data-plane operation."""
    return decide_egress(
        agent_id=agent_id,
        session_id=session_id,
        channel=CHANNEL_DATA,
        target=target,
        store=store,
        action=action,
        context=context,
        policy_id=policy_id,
        required_capabilities=required_capabilities,
    )

"""Tool Authorization Engine.

Runtime ALLOW / DENY / CONDITIONAL policy engine for per-tool-call access
control.  Every tool invocation by a registered agent can be evaluated
against a stored policy set before it is executed.

This complements:
* ``agent_action_ledger`` — records what the agent *did* (tamper-evident log)
* ``guardrail_engine`` — classifies *content* (what the prompt says)
* ``tool_authorization`` — enforces *policy* (is this call permitted?)

Policy model
------------
Policies are stored per-agent under ``"auth_policy:{agent_id}"`` and contain
a list of per-tool rules.  Each rule specifies one or more ``allow_if``
conditions; ALL conditions must be met for the verdict to be ``ALLOW``.
Unmet conditions produce ``CONDITIONAL`` (allowed pending remediation).
A tool not covered by any rule falls back to the agent's ``default_policy``
(``"DENY"`` unless overridden).

Verdict constants
-----------------
``ALLOW``       — all conditions met; call may proceed.
``DENY``        — explicitly denied; call must not proceed.
``CONDITIONAL`` — conditions not met; call blocked pending resolution.

Session context keys
--------------------
``data_sensitivity``       — "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED"
``user_consent_given``     — bool
``call_count``             — int (tool calls so far this session)
``trust_level``            — "VERIFIED" | "INTERNAL" | "EXTERNAL" | "USER" | "UNTRUSTED"
``session_context_tags``   — list[str] — arbitrary tags (e.g. "customer_support")
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

AUTH_VERSION = "1.0"

_POLICY_PREFIX = "auth_policy:"

VERDICT_ALLOW = "ALLOW"
VERDICT_DENY = "DENY"
VERDICT_CONDITIONAL = "CONDITIONAL"

# Data sensitivity order (higher index = more sensitive)
_DATA_SENSITIVITY_RANK: Dict[str, int] = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "RESTRICTED": 4,
}

# Trust level rank
_TRUST_RANK: Dict[str, int] = {
    "VERIFIED": 5,
    "INTERNAL": 4,
    "EXTERNAL": 3,
    "USER": 2,
    "UNTRUSTED": 1,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _policy_key(agent_id: str) -> str:
    return f"{_POLICY_PREFIX}{agent_id}"


class AuthorizationError(ValueError):
    pass


# ── Policy management ─────────────────────────────────────────────────────────

def create_policy(
    agent_id: str,
    tool_policies: List[Dict[str, Any]],
    store: Any,
    *,
    default_policy: str = VERDICT_DENY,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create or replace authorization policies for an agent.

    Parameters
    ----------
    agent_id:
        Agent whose tool calls are governed by these policies.
    tool_policies:
        List of per-tool policy dicts.  Each must have ``tool_name`` and
        optionally ``allow_if`` (conditions dict) and ``policy_id``.

        Supported ``allow_if`` conditions:

        * ``data_sensitivity_max`` (str) — reject calls where session
          ``data_sensitivity`` exceeds this level.
        * ``user_consent_required`` (bool) — reject if
          ``user_consent_given`` is falsy.
        * ``max_calls_per_session`` (int) — reject if ``call_count``
          meets or exceeds this value.
        * ``trust_level_min`` (str) — reject if session ``trust_level``
          is below this rank.
        * ``allowed_context_tags`` (list[str]) — reject if
          ``session_context_tags`` has no overlap with this list.
    default_policy:
        Verdict to apply when no rule matches a tool call (``"ALLOW"``
        or ``"DENY"``; default ``"DENY"``).
    """
    if not str(agent_id).strip():
        raise AuthorizationError("agent_id must be non-empty")
    if default_policy not in (VERDICT_ALLOW, VERDICT_DENY):
        raise AuthorizationError(
            f"default_policy must be ALLOW or DENY, got {default_policy!r}"
        )

    policies_validated = []
    for i, tp in enumerate(tool_policies):
        tool_name = str(tp.get("tool_name") or "").strip()
        if not tool_name:
            raise AuthorizationError(f"tool_policies[{i}].tool_name must be non-empty")
        policies_validated.append({
            "tool_name": tool_name,
            "policy_id": str(tp.get("policy_id") or f"pol-{i:04d}"),
            "allow_if": dict(tp.get("allow_if") or {}),
        })

    now = _utc_now()
    key = _policy_key(agent_id)
    existing = store.get_model(key) or {}
    existing_meta = existing.get("metadata") or {}

    record: Dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            **existing_meta,
            "agent_id": agent_id,
            "tool_policies": policies_validated,
            "default_policy": default_policy,
            "auth_version": AUTH_VERSION,
            "created_at": existing_meta.get("created_at") or now,
            "updated_at": now,
            "extra": metadata or {},
        },
    }
    store.save_model(record)
    return _policy_summary(record)


def get_policy(agent_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return the stored policy set for ``agent_id``, or ``None``."""
    record = store.get_model(_policy_key(agent_id))
    if not record:
        return None
    return _policy_summary(record)


def delete_policy(agent_id: str, store: Any) -> bool:
    """Delete the authorization policy for ``agent_id``.

    Returns ``True`` if a policy existed, ``False`` otherwise.
    """
    key = _policy_key(agent_id)
    record = store.get_model(key)
    if not record:
        return False
    meta = record.get("metadata") or {}
    meta["tool_policies"] = []
    meta["default_policy"] = VERDICT_DENY
    meta["deleted_at"] = _utc_now()
    record["metadata"] = meta
    store.save_model(record)
    return True


def _policy_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    meta = record.get("metadata") or {}
    policies = meta.get("tool_policies") or []
    return {
        "agent_id": meta.get("agent_id"),
        "tool_policy_count": len(policies),
        "tool_policies": policies,
        "default_policy": meta.get("default_policy", VERDICT_DENY),
        "auth_version": meta.get("auth_version", AUTH_VERSION),
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
    }


# ── Authorization ─────────────────────────────────────────────────────────────

def authorize(
    agent_id: str,
    tool_name: str,
    session_context: Dict[str, Any],
    store: Any,
) -> Dict[str, Any]:
    """Evaluate whether ``agent_id`` may call ``tool_name`` given ``session_context``.

    Parameters
    ----------
    agent_id:
        The agent requesting the tool call.
    tool_name:
        The tool being invoked.
    session_context:
        Runtime context dict with keys documented at module level.
    store:
        AIAF model store (for loading agent + policy records).

    Returns
    -------
    Dict with keys: ``auth_version``, ``verdict``, ``agent_id``, ``tool_name``,
    ``reasons`` (list of human-readable strings), ``unmet_conditions`` (for
    CONDITIONAL), ``policy_id``, ``authorized_at``.
    """
    reasons: List[str] = []
    unmet: List[str] = []
    authorized_at = _utc_now()

    # 1. Check agent is registered and active
    from ..registry.agent_registry import get_agent
    agent = get_agent(agent_id, store)
    if agent is None:
        return _verdict(
            VERDICT_DENY, agent_id, tool_name, authorized_at,
            reasons=[f"Agent '{agent_id}' is not registered."],
        )
    if agent.get("status") != "active":
        return _verdict(
            VERDICT_DENY, agent_id, tool_name, authorized_at,
            reasons=[
                f"Agent '{agent_id}' is {agent.get('status')}, not active."
                + (
                    f" Reason: {agent.get('status_reason')}."
                    if agent.get("status_reason")
                    else ""
                )
            ],
        )

    # 2. Check tool is in declared_tools
    declared = set(agent.get("declared_tools") or [])
    if tool_name not in declared:
        return _verdict(
            VERDICT_DENY, agent_id, tool_name, authorized_at,
            reasons=[
                f"Tool '{tool_name}' is not in agent '{agent_id}' declared_tools list."
            ],
        )

    blocked_tools = agent.get("blocked_tools") or {}
    if tool_name in blocked_tools:
        block_reason = (blocked_tools.get(tool_name) or {}).get("reason")
        return _verdict(
            VERDICT_DENY, agent_id, tool_name, authorized_at,
            reasons=[
                f"Tool '{tool_name}' is currently blocked for agent '{agent_id}'."
                + (f" Reason: {block_reason}." if block_reason else "")
            ],
        )

    # 3. Load and apply authorization policies
    policy_record = get_policy(agent_id, store)
    if policy_record is None:
        return _verdict(
            VERDICT_DENY, agent_id, tool_name, authorized_at,
            reasons=[
                f"No authorization policy found for agent '{agent_id}'. "
                "Default policy: DENY."
            ],
        )

    default_policy = policy_record.get("default_policy", VERDICT_DENY)
    matching_rule: Optional[Dict[str, Any]] = None
    for rule in policy_record.get("tool_policies") or []:
        if rule.get("tool_name") == tool_name:
            matching_rule = rule
            break

    if matching_rule is None:
        verdict_val = default_policy
        return _verdict(
            verdict_val, agent_id, tool_name, authorized_at,
            reasons=[
                f"No specific policy for tool '{tool_name}'; "
                f"applying default_policy={default_policy}."
            ],
        )

    # 4. Evaluate allow_if conditions
    allow_if = matching_rule.get("allow_if") or {}
    policy_id = matching_rule.get("policy_id", "")

    # 4a. data_sensitivity_max
    ds_max = allow_if.get("data_sensitivity_max")
    if ds_max is not None:
        ctx_ds = str(session_context.get("data_sensitivity") or "PUBLIC").upper()
        rank_max = _DATA_SENSITIVITY_RANK.get(str(ds_max).upper(), 0)
        rank_ctx = _DATA_SENSITIVITY_RANK.get(ctx_ds, 0)
        if rank_ctx > rank_max:
            unmet.append(
                f"data_sensitivity={ctx_ds} exceeds policy maximum {str(ds_max).upper()}"
            )

    # 4b. user_consent_required
    ucr = allow_if.get("user_consent_required")
    if ucr:
        if not session_context.get("user_consent_given"):
            unmet.append("user_consent_given is required but not present in session context")

    # 4c. max_calls_per_session
    max_calls = allow_if.get("max_calls_per_session")
    if max_calls is not None:
        call_count = int(session_context.get("call_count") or 0)
        if call_count >= int(max_calls):
            unmet.append(
                f"call_count={call_count} meets or exceeds max_calls_per_session={max_calls}"
            )

    # 4d. trust_level_min
    tl_min = allow_if.get("trust_level_min")
    if tl_min is not None:
        ctx_tl = str(session_context.get("trust_level") or "").upper()
        rank_min = _TRUST_RANK.get(str(tl_min).upper(), 0)
        rank_ctx = _TRUST_RANK.get(ctx_tl, 0)
        if rank_ctx < rank_min:
            unmet.append(
                f"session trust_level={ctx_tl} is below required minimum {str(tl_min).upper()}"
            )

    # 4e. allowed_context_tags
    act = allow_if.get("allowed_context_tags")
    if act is not None:
        allowed_set = set(act)
        ctx_tags = set(session_context.get("session_context_tags") or [])
        if not ctx_tags & allowed_set:
            unmet.append(
                f"session_context_tags {sorted(ctx_tags)} has no overlap with "
                f"allowed_context_tags {sorted(allowed_set)}"
            )

    if not unmet:
        reasons.append(f"All conditions for tool '{tool_name}' met (policy {policy_id}).")
        return _verdict(
            VERDICT_ALLOW, agent_id, tool_name, authorized_at,
            reasons=reasons, policy_id=policy_id,
        )
    else:
        return _verdict(
            VERDICT_CONDITIONAL, agent_id, tool_name, authorized_at,
            reasons=[f"Conditions unmet for tool '{tool_name}' (policy {policy_id})."],
            unmet_conditions=unmet,
            policy_id=policy_id,
        )


def _verdict(
    verdict_val: str,
    agent_id: str,
    tool_name: str,
    authorized_at: str,
    *,
    reasons: Optional[List[str]] = None,
    unmet_conditions: Optional[List[str]] = None,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "auth_version": AUTH_VERSION,
        "verdict": verdict_val,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "reasons": reasons or [],
        "unmet_conditions": unmet_conditions or [],
        "policy_id": policy_id,
        "evidence_origin": "LOCALLY_OBSERVED",
        "authorized_at": authorized_at,
    }

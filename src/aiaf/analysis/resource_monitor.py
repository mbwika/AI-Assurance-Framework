"""AI Resource Abuse and Cost-Risk Monitor.

Tracks per-session resource consumption (tokens, tool calls, agent loop
iterations, retries, planning depth) and raises structured violations when
configured budgets are exceeded.

Risk types
----------
DENIAL_OF_WALLET    — projected session cost exceeds cost budget
RUNAWAY_AGENT_LOOP  — loop iteration counter exceeds threshold
RECURSIVE_PLANNING  — planning depth exceeds threshold
EXCESSIVE_RETRIES   — retry counter exceeds threshold
ABNORMAL_SPEND      — per-request token spike above single-request limit

Budget defaults (operators override per session via ``create_budget``):
    max_tokens_per_request  8 000
    max_tokens_per_session  100 000
    max_tool_calls          200
    max_loop_iterations     50
    max_retries             10
    max_planning_depth      15
    cost_per_1k_tokens      0.002 USD
    max_session_cost_usd    1.00 USD

Evidence origin
---------------
LOCALLY_OBSERVED — all values are reported by the calling application;
AIAF performs the accounting and violation detection locally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

RESOURCE_MONITOR_VERSION = "1.0"

# ── Resource types ─────────────────────────────────────────────────────────────
RESOURCE_TOKENS = "TOKENS"
RESOURCE_TOOL_CALLS = "TOOL_CALLS"
RESOURCE_LOOP_ITERATIONS = "LOOP_ITERATIONS"
RESOURCE_RETRIES = "RETRIES"
RESOURCE_PLANNING_DEPTH = "PLANNING_DEPTH"

RESOURCE_TYPES: frozenset = frozenset({
    RESOURCE_TOKENS, RESOURCE_TOOL_CALLS, RESOURCE_LOOP_ITERATIONS,
    RESOURCE_RETRIES, RESOURCE_PLANNING_DEPTH,
})

# ── Risk types ─────────────────────────────────────────────────────────────────
RISK_DENIAL_OF_WALLET = "DENIAL_OF_WALLET"
RISK_RUNAWAY_LOOP = "RUNAWAY_AGENT_LOOP"
RISK_RECURSIVE_PLANNING = "RECURSIVE_PLANNING"
RISK_EXCESSIVE_RETRIES = "EXCESSIVE_RETRIES"
RISK_ABNORMAL_SPEND = "ABNORMAL_SPEND"

RISK_TYPES: frozenset = frozenset({
    RISK_DENIAL_OF_WALLET, RISK_RUNAWAY_LOOP,
    RISK_RECURSIVE_PLANNING, RISK_EXCESSIVE_RETRIES, RISK_ABNORMAL_SPEND,
})

# ── Session risk levels ────────────────────────────────────────────────────────
SESSION_SAFE = "SAFE"
SESSION_ELEVATED = "ELEVATED"
SESSION_CRITICAL = "CRITICAL"

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_BUDGET: dict[str, float] = {
    "max_tokens_per_request": 8_000.0,
    "max_tokens_per_session": 100_000.0,
    "max_tool_calls_per_session": 200.0,
    "max_loop_iterations": 50.0,
    "max_retries": 10.0,
    "max_planning_depth": 15.0,
    "cost_per_1k_tokens": 0.002,
    "max_session_cost_usd": 1.00,
}

_BUDGET_PREFIX = "resource_budget:"
_SESSION_PREFIX = "resource_session:"


class ResourceMonitorError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _budget_key(budget_id: str) -> str:
    return f"{_BUDGET_PREFIX}{budget_id}"


def _session_key(budget_id: str) -> str:
    return f"{_SESSION_PREFIX}{budget_id}"


def _load_metadata(record: dict[str, Any] | None) -> dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _compute_cost(total_tokens: float, cost_per_1k: float) -> float:
    return round(total_tokens / 1000.0 * cost_per_1k, 6)


def _detect_violations(
    state: dict[str, Any],
    budget: dict[str, Any],
    last_token_delta: float | None = None,
) -> list[dict[str, Any]]:
    """Return list of new violation dicts for the current state."""
    violations = []
    now = _utc_now()

    tokens = state.get("total_tokens", 0.0)
    cost = state.get("estimated_cost_usd", 0.0)
    loops = state.get("loop_iterations", 0.0)
    retries = state.get("retries", 0.0)
    depth = state.get("planning_depth", 0.0)

    if tokens > budget.get("max_tokens_per_session", DEFAULT_BUDGET["max_tokens_per_session"]):
        violations.append({
            "risk_type": RISK_DENIAL_OF_WALLET,
            "value": tokens,
            "threshold": budget["max_tokens_per_session"],
            "detail": f"Session token count {tokens:,.0f} exceeds budget {budget['max_tokens_per_session']:,.0f}.",
            "detected_at": now,
        })

    if cost > budget.get("max_session_cost_usd", DEFAULT_BUDGET["max_session_cost_usd"]):
        violations.append({
            "risk_type": RISK_DENIAL_OF_WALLET,
            "value": cost,
            "threshold": budget["max_session_cost_usd"],
            "detail": f"Estimated cost ${cost:.4f} exceeds budget ${budget['max_session_cost_usd']:.4f}.",
            "detected_at": now,
        })

    if loops > budget.get("max_loop_iterations", DEFAULT_BUDGET["max_loop_iterations"]):
        violations.append({
            "risk_type": RISK_RUNAWAY_LOOP,
            "value": loops,
            "threshold": budget["max_loop_iterations"],
            "detail": f"Agent loop iterations {loops:,.0f} exceed limit {budget['max_loop_iterations']:,.0f}.",
            "detected_at": now,
        })

    if retries > budget.get("max_retries", DEFAULT_BUDGET["max_retries"]):
        violations.append({
            "risk_type": RISK_EXCESSIVE_RETRIES,
            "value": retries,
            "threshold": budget["max_retries"],
            "detail": f"Retry count {retries:,.0f} exceeds limit {budget['max_retries']:,.0f}.",
            "detected_at": now,
        })

    if depth > budget.get("max_planning_depth", DEFAULT_BUDGET["max_planning_depth"]):
        violations.append({
            "risk_type": RISK_RECURSIVE_PLANNING,
            "value": depth,
            "threshold": budget["max_planning_depth"],
            "detail": f"Planning depth {depth:,.0f} exceeds limit {budget['max_planning_depth']:,.0f}.",
            "detected_at": now,
        })

    if last_token_delta is not None:
        max_req = budget.get("max_tokens_per_request", DEFAULT_BUDGET["max_tokens_per_request"])
        if last_token_delta > max_req:
            violations.append({
                "risk_type": RISK_ABNORMAL_SPEND,
                "value": last_token_delta,
                "threshold": max_req,
                "detail": f"Single-request token count {last_token_delta:,.0f} exceeds per-request limit {max_req:,.0f}.",
                "detected_at": now,
            })

    return violations


def _risk_level(violations: list[dict[str, Any]]) -> str:
    critical_types = {RISK_DENIAL_OF_WALLET, RISK_RUNAWAY_LOOP, RISK_RECURSIVE_PLANNING}
    for v in violations:
        if v.get("risk_type") in critical_types:
            return SESSION_CRITICAL
    return SESSION_ELEVATED if violations else SESSION_SAFE


# ── Public API ─────────────────────────────────────────────────────────────────

def create_budget(
    budget_id: str,
    model_id: str,
    store: Any,
    *,
    budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Define a resource budget for a model/agent session."""
    merged_budget = {**DEFAULT_BUDGET, **(budget or {})}
    record: dict[str, Any] = {
        "model_id": _budget_key(budget_id),
        "id": _budget_key(budget_id),
        "metadata": {
            "budget_id": budget_id,
            "model_id": model_id,
            "budget": merged_budget,
            "created_at": _utc_now(),
        },
    }
    store.save_model(record)

    # Initialise empty session state
    _init_session(budget_id, model_id, store)
    return _load_metadata(store.get_model(_budget_key(budget_id)))


def get_budget(budget_id: str, store: Any) -> dict[str, Any] | None:
    """Return budget definition, or None if not found."""
    rec = store.get_model(_budget_key(budget_id))
    return _load_metadata(rec) if rec else None


def _init_session(budget_id: str, model_id: str, store: Any) -> None:
    """Create or reset a fresh session state record."""
    record: dict[str, Any] = {
        "model_id": _session_key(budget_id),
        "id": _session_key(budget_id),
        "metadata": {
            "budget_id": budget_id,
            "model_id": model_id,
            "total_tokens": 0.0,
            "total_tool_calls": 0.0,
            "loop_iterations": 0.0,
            "retries": 0.0,
            "planning_depth": 0.0,
            "estimated_cost_usd": 0.0,
            "violations": [],
            "risk_level": SESSION_SAFE,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        },
    }
    store.save_model(record)


def record_usage(
    budget_id: str,
    resource_type: str,
    value: float,
    store: Any,
    *,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a resource usage event and return the updated session state.

    For TOKENS, ``value`` is the token count for this request.
    For all others, ``value`` is the absolute current value (replaces previous
    for PLANNING_DEPTH) or an increment (for TOOL_CALLS, LOOP_ITERATIONS,
    RETRIES).
    """
    resource_type = str(resource_type).upper().strip()
    if resource_type not in RESOURCE_TYPES:
        raise ResourceMonitorError(
            f"Unknown resource_type {resource_type!r}. Valid: {sorted(RESOURCE_TYPES)}"
        )

    budget_rec = get_budget(budget_id, store)
    if not budget_rec:
        raise ResourceMonitorError(f"Budget {budget_id!r} not found. Call create_budget first.")
    budget = budget_rec["budget"]

    session_rec = store.get_model(_session_key(budget_id))
    state = _load_metadata(session_rec)
    if not state:
        state = {"total_tokens": 0.0, "total_tool_calls": 0.0, "loop_iterations": 0.0,
                 "retries": 0.0, "planning_depth": 0.0, "estimated_cost_usd": 0.0,
                 "violations": [], "risk_level": SESSION_SAFE}

    last_token_delta = None
    if resource_type == RESOURCE_TOKENS:
        state["total_tokens"] = float(state.get("total_tokens", 0)) + value
        state["estimated_cost_usd"] = _compute_cost(
            state["total_tokens"], budget.get("cost_per_1k_tokens", DEFAULT_BUDGET["cost_per_1k_tokens"])
        )
        last_token_delta = value
    elif resource_type == RESOURCE_TOOL_CALLS:
        state["total_tool_calls"] = float(state.get("total_tool_calls", 0)) + value
    elif resource_type == RESOURCE_LOOP_ITERATIONS:
        state["loop_iterations"] = float(state.get("loop_iterations", 0)) + value
    elif resource_type == RESOURCE_RETRIES:
        state["retries"] = float(state.get("retries", 0)) + value
    elif resource_type == RESOURCE_PLANNING_DEPTH:
        # Planning depth is an absolute (current depth), not a cumulative sum
        state["planning_depth"] = max(float(state.get("planning_depth", 0)), float(value))

    new_violations = _detect_violations(state, budget, last_token_delta)
    existing = [v["risk_type"] for v in (state.get("violations") or [])]
    for v in new_violations:
        if v["risk_type"] not in existing:
            state.setdefault("violations", []).append(v)
            existing.append(v["risk_type"])

    state["risk_level"] = _risk_level(state.get("violations", []))
    state["updated_at"] = _utc_now()

    updated_record: dict[str, Any] = {
        "model_id": _session_key(budget_id),
        "id": _session_key(budget_id),
        "metadata": state,
    }
    store.save_model(updated_record)
    return state


def get_session_state(budget_id: str, store: Any) -> dict[str, Any] | None:
    """Return current session state, or None if budget not found."""
    rec = store.get_model(_session_key(budget_id))
    return _load_metadata(rec) if rec else None


def check_budget_violations(budget_id: str, store: Any) -> dict[str, Any]:
    """Return all violations for a session with summary."""
    state = get_session_state(budget_id, store)
    if not state:
        raise ResourceMonitorError(f"Budget {budget_id!r} not found.")
    violations = state.get("violations") or []
    risk_types = list({v["risk_type"] for v in violations})
    return {
        "budget_id": budget_id,
        "risk_level": state.get("risk_level", SESSION_SAFE),
        "violation_count": len(violations),
        "risk_types_triggered": risk_types,
        "violations": violations,
        "checked_at": _utc_now(),
    }


def list_at_risk_sessions(
    store: Any,
    *,
    risk_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List sessions with at least one violation."""
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_SESSION_PREFIX):
            continue
        state = _load_metadata(rec)
        violations = state.get("violations") or []
        if not violations:
            continue
        if risk_type and not any(v.get("risk_type") == risk_type for v in violations):
            continue
        results.append(state)
        if len(results) >= limit:
            break
    return results

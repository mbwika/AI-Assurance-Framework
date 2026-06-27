"""Tests for src/aiaf/analysis/resource_monitor.py"""

import pytest

from aiaf.analysis.resource_monitor import (
    DEFAULT_BUDGET,
    RESOURCE_LOOP_ITERATIONS,
    RESOURCE_MONITOR_VERSION,
    RESOURCE_PLANNING_DEPTH,
    RESOURCE_RETRIES,
    RESOURCE_TOKENS,
    RESOURCE_TOOL_CALLS,
    RESOURCE_TYPES,
    RISK_ABNORMAL_SPEND,
    RISK_DENIAL_OF_WALLET,
    RISK_EXCESSIVE_RETRIES,
    RISK_RECURSIVE_PLANNING,
    RISK_RUNAWAY_LOOP,
    SESSION_CRITICAL,
    SESSION_SAFE,
    ResourceMonitorError,
    check_budget_violations,
    create_budget,
    get_budget,
    get_session_state,
    list_at_risk_sessions,
    record_usage,
)


class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_version_string(self):
        assert RESOURCE_MONITOR_VERSION == "1.0"

    def test_resource_types_complete(self):
        assert RESOURCE_TOKENS in RESOURCE_TYPES
        assert RESOURCE_PLANNING_DEPTH in RESOURCE_TYPES

    def test_default_budget_keys(self):
        required = {
            "max_tokens_per_request", "max_tokens_per_session",
            "max_tool_calls_per_session", "max_loop_iterations",
            "max_retries", "max_planning_depth",
            "cost_per_1k_tokens", "max_session_cost_usd",
        }
        assert required.issubset(DEFAULT_BUDGET.keys())


# ── create_budget / get_budget ─────────────────────────────────────────────────

class TestCreateBudget:
    def test_create_budget_returns_metadata(self):
        store = _Store()
        result = create_budget("b1", "model-a", store)
        assert result["budget_id"] == "b1"
        assert result["model_id"] == "model-a"
        assert "budget" in result

    def test_create_budget_merges_defaults(self):
        store = _Store()
        result = create_budget("b1", "model-a", store, budget={"max_loop_iterations": 10.0})
        assert result["budget"]["max_loop_iterations"] == 10.0
        assert result["budget"]["max_retries"] == DEFAULT_BUDGET["max_retries"]

    def test_get_budget_after_create(self):
        store = _Store()
        create_budget("b2", "model-b", store)
        b = get_budget("b2", store)
        assert b is not None
        assert b["budget_id"] == "b2"

    def test_get_budget_missing_returns_none(self):
        store = _Store()
        assert get_budget("nonexistent", store) is None

    def test_create_initialises_session_state(self):
        store = _Store()
        create_budget("b3", "m", store)
        state = get_session_state("b3", store)
        assert state is not None
        assert state["total_tokens"] == 0.0
        assert state["risk_level"] == SESSION_SAFE


# ── record_usage ───────────────────────────────────────────────────────────────

class TestRecordUsage:
    def test_record_tokens_accumulates(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_TOKENS, 1000.0, store)
        record_usage("b", RESOURCE_TOKENS, 500.0, store)
        state = get_session_state("b", store)
        assert state["total_tokens"] == 1500.0

    def test_record_tokens_computes_cost(self):
        store = _Store()
        create_budget("b", "m", store, budget={"cost_per_1k_tokens": 0.01})
        record_usage("b", RESOURCE_TOKENS, 1000.0, store)
        state = get_session_state("b", store)
        assert abs(state["estimated_cost_usd"] - 0.01) < 1e-6

    def test_record_tool_calls_accumulates(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_TOOL_CALLS, 5.0, store)
        record_usage("b", RESOURCE_TOOL_CALLS, 3.0, store)
        state = get_session_state("b", store)
        assert state["total_tool_calls"] == 8.0

    def test_record_loop_iterations_accumulates(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_LOOP_ITERATIONS, 20.0, store)
        record_usage("b", RESOURCE_LOOP_ITERATIONS, 30.0, store)
        state = get_session_state("b", store)
        assert state["loop_iterations"] == 50.0

    def test_planning_depth_uses_max_not_sum(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_PLANNING_DEPTH, 5.0, store)
        record_usage("b", RESOURCE_PLANNING_DEPTH, 3.0, store)  # lower — should not decrease
        state = get_session_state("b", store)
        assert state["planning_depth"] == 5.0

    def test_planning_depth_increases_when_higher(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_PLANNING_DEPTH, 2.0, store)
        record_usage("b", RESOURCE_PLANNING_DEPTH, 8.0, store)
        state = get_session_state("b", store)
        assert state["planning_depth"] == 8.0

    def test_record_retries_accumulates(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_RETRIES, 7.0, store)
        state = get_session_state("b", store)
        assert state["retries"] == 7.0

    def test_unknown_resource_type_raises(self):
        store = _Store()
        create_budget("b", "m", store)
        with pytest.raises(ResourceMonitorError, match="Unknown resource_type"):
            record_usage("b", "UNKNOWN_TYPE", 1.0, store)

    def test_missing_budget_raises(self):
        store = _Store()
        with pytest.raises(ResourceMonitorError, match="not found"):
            record_usage("nonexistent", RESOURCE_TOKENS, 1.0, store)


# ── Violation detection ────────────────────────────────────────────────────────

class TestViolationDetection:
    def _make_tight_budget(self, store):
        create_budget("b", "m", store, budget={
            "max_tokens_per_session": 100.0,
            "max_token_per_request": 50.0,
            "max_loop_iterations": 5.0,
            "max_retries": 2.0,
            "max_planning_depth": 3.0,
            "max_session_cost_usd": 0.001,
            "cost_per_1k_tokens": 0.002,
        })

    def test_token_session_violation(self):
        store = _Store()
        self._make_tight_budget(store)
        record_usage("b", RESOURCE_TOKENS, 200.0, store)
        result = check_budget_violations("b", store)
        assert RISK_DENIAL_OF_WALLET in result["risk_types_triggered"]

    def test_loop_violation(self):
        store = _Store()
        self._make_tight_budget(store)
        record_usage("b", RESOURCE_LOOP_ITERATIONS, 10.0, store)
        result = check_budget_violations("b", store)
        assert RISK_RUNAWAY_LOOP in result["risk_types_triggered"]

    def test_retry_violation(self):
        store = _Store()
        self._make_tight_budget(store)
        record_usage("b", RESOURCE_RETRIES, 5.0, store)
        result = check_budget_violations("b", store)
        assert RISK_EXCESSIVE_RETRIES in result["risk_types_triggered"]

    def test_planning_depth_violation(self):
        store = _Store()
        self._make_tight_budget(store)
        record_usage("b", RESOURCE_PLANNING_DEPTH, 10.0, store)
        result = check_budget_violations("b", store)
        assert RISK_RECURSIVE_PLANNING in result["risk_types_triggered"]

    def test_per_request_token_spike(self):
        store = _Store()
        create_budget("b", "m", store, budget={"max_tokens_per_request": 100.0})
        record_usage("b", RESOURCE_TOKENS, 500.0, store)
        state = get_session_state("b", store)
        risk_types = {v["risk_type"] for v in state["violations"]}
        assert RISK_ABNORMAL_SPEND in risk_types

    def test_no_violation_when_under_budget(self):
        store = _Store()
        create_budget("b", "m", store)
        record_usage("b", RESOURCE_TOKENS, 100.0, store)
        result = check_budget_violations("b", store)
        assert result["violation_count"] == 0
        assert result["risk_level"] == SESSION_SAFE

    def test_risk_level_critical_on_token_excess(self):
        store = _Store()
        create_budget("b", "m", store, budget={"max_tokens_per_session": 1.0})
        record_usage("b", RESOURCE_TOKENS, 10.0, store)
        state = get_session_state("b", store)
        assert state["risk_level"] == SESSION_CRITICAL

    def test_violations_not_duplicated(self):
        store = _Store()
        create_budget("b", "m", store, budget={"max_tokens_per_session": 1.0})
        record_usage("b", RESOURCE_TOKENS, 10.0, store)
        record_usage("b", RESOURCE_TOKENS, 10.0, store)
        result = check_budget_violations("b", store)
        dow_violations = [v for v in result["violations"] if v["risk_type"] == RISK_DENIAL_OF_WALLET]
        assert len(dow_violations) == 1  # deduped by risk_type

    def test_check_violations_missing_budget_raises(self):
        store = _Store()
        with pytest.raises(ResourceMonitorError):
            check_budget_violations("no-such", store)


# ── list_at_risk_sessions ──────────────────────────────────────────────────────

class TestListAtRiskSessions:
    def test_returns_only_sessions_with_violations(self):
        store = _Store()
        create_budget("safe", "m", store)
        create_budget("risky", "m", store, budget={"max_tokens_per_session": 1.0})
        record_usage("safe", RESOURCE_TOKENS, 50.0, store)
        record_usage("risky", RESOURCE_TOKENS, 100.0, store)
        at_risk = list_at_risk_sessions(store)
        budget_ids = {s["budget_id"] for s in at_risk}
        assert "risky" in budget_ids
        assert "safe" not in budget_ids

    def test_filter_by_risk_type(self):
        store = _Store()
        create_budget("b", "m", store, budget={"max_loop_iterations": 1.0})
        record_usage("b", RESOURCE_LOOP_ITERATIONS, 10.0, store)
        results = list_at_risk_sessions(store, risk_type=RISK_RUNAWAY_LOOP)
        assert len(results) >= 1

    def test_empty_when_no_violations(self):
        store = _Store()
        create_budget("b", "m", store)
        assert list_at_risk_sessions(store) == []

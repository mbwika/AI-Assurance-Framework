"""Tests for aiaf.core.tool_authorization."""

import pytest

from aiaf.core.tool_authorization import (
    AUTH_VERSION,
    VERDICT_ALLOW,
    VERDICT_CONDITIONAL,
    VERDICT_DENY,
    AuthorizationError,
    authorize,
    create_policy,
    delete_policy,
    get_policy,
)
from aiaf.registry.agent_registry import register_agent

# ── Fake store ────────────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._data = {}
    def get_model(self, key):
        return self._data.get(key)
    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record
    def list_models(self):
        return list(self._data.values())


def _setup_store_with_agent(agent_id="agent-1", tools=None):
    store = _Store()
    register_agent(
        agent_id, "Test Bot", tools or ["send_email", "search"], "INTERNAL",
        ["network_egress", "data_read"], store,
    )
    return store


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_auth_version(self):
        assert AUTH_VERSION == "1.0"

    def test_verdict_constants(self):
        assert VERDICT_ALLOW == "ALLOW"
        assert VERDICT_DENY == "DENY"
        assert VERDICT_CONDITIONAL == "CONDITIONAL"


# ── create_policy ─────────────────────────────────────────────────────────────

class TestCreatePolicy:
    def test_basic_policy_creation(self):
        store = _setup_store_with_agent()
        result = create_policy(
            "agent-1",
            [{"tool_name": "send_email", "allow_if": {"data_sensitivity_max": "INTERNAL"}}],
            store,
        )
        assert result["agent_id"] == "agent-1"
        assert result["tool_policy_count"] == 1

    def test_empty_agent_id_raises(self):
        store = _Store()
        with pytest.raises(AuthorizationError):
            create_policy("", [], store)

    def test_invalid_default_policy_raises(self):
        store = _Store()
        with pytest.raises(AuthorizationError):
            create_policy("a1", [], store, default_policy="MAYBE")

    def test_tool_name_required(self):
        store = _Store()
        with pytest.raises(AuthorizationError):
            create_policy("a1", [{"tool_name": ""}], store)

    def test_default_policy_stored(self):
        store = _setup_store_with_agent("a2")
        create_policy("a2", [], store, default_policy=VERDICT_ALLOW)
        policy = get_policy("a2", store)
        assert policy["default_policy"] == VERDICT_ALLOW

    def test_multiple_tool_policies(self):
        store = _setup_store_with_agent()
        result = create_policy(
            "agent-1",
            [
                {"tool_name": "send_email"},
                {"tool_name": "search"},
            ],
            store,
        )
        assert result["tool_policy_count"] == 2

    def test_re_create_preserves_created_at(self):
        store = _setup_store_with_agent()
        r1 = create_policy("agent-1", [], store)
        r2 = create_policy("agent-1", [], store)
        assert r1["created_at"] == r2["created_at"]

    def test_auth_version_in_result(self):
        store = _setup_store_with_agent()
        result = create_policy("agent-1", [], store)
        assert result["auth_version"] == AUTH_VERSION


# ── get_policy ────────────────────────────────────────────────────────────────

class TestGetPolicy:
    def test_get_existing_policy(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [{"tool_name": "send_email"}], store)
        policy = get_policy("agent-1", store)
        assert policy is not None
        assert policy["agent_id"] == "agent-1"

    def test_get_nonexistent_returns_none(self):
        store = _Store()
        assert get_policy("nobody", store) is None


# ── delete_policy ─────────────────────────────────────────────────────────────

class TestDeletePolicy:
    def test_delete_existing_policy(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [{"tool_name": "send_email"}], store)
        assert delete_policy("agent-1", store) is True
        policy = get_policy("agent-1", store)
        assert policy["tool_policy_count"] == 0

    def test_delete_nonexistent_returns_false(self):
        store = _Store()
        assert delete_policy("nobody", store) is False


# ── authorize — verdict logic ─────────────────────────────────────────────────

class TestAuthorize:
    def _base_context(self):
        return {
            "data_sensitivity": "INTERNAL",
            "user_consent_given": True,
            "call_count": 0,
            "trust_level": "INTERNAL",
            "session_context_tags": ["customer_support"],
        }

    def test_allow_with_all_conditions_met(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"data_sensitivity_max": "INTERNAL"},
            }
        ], store)
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_ALLOW

    def test_deny_unregistered_agent(self):
        store = _Store()
        result = authorize("nobody", "send_email", {}, store)
        assert result["verdict"] == VERDICT_DENY
        assert any("not registered" in r for r in result["reasons"])

    def test_deny_deregistered_agent(self):
        from aiaf.registry.agent_registry import deregister_agent
        store = _setup_store_with_agent()
        deregister_agent("agent-1", store)
        result = authorize("agent-1", "send_email", {}, store)
        assert result["verdict"] == VERDICT_DENY

    def test_deny_suspended_agent(self):
        from aiaf.registry.agent_registry import set_agent_status
        store = _setup_store_with_agent()
        set_agent_status("agent-1", "suspended", store, reason="investigating egress")
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_DENY
        assert any("investigating egress" in reason for reason in result["reasons"])

    def test_deny_blocked_tool(self):
        from aiaf.registry.agent_registry import set_tool_block
        store = _setup_store_with_agent()
        create_policy("agent-1", [{"tool_name": "send_email"}], store)
        set_tool_block("agent-1", "send_email", True, store, reason="temporary containment")
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_DENY
        assert any("temporary containment" in reason for reason in result["reasons"])

    def test_deny_tool_not_in_declared_tools(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [], store)
        result = authorize("agent-1", "delete_database", self._base_context(), store)
        assert result["verdict"] == VERDICT_DENY
        assert any("declared_tools" in r for r in result["reasons"])

    def test_deny_no_policy_exists(self):
        store = _setup_store_with_agent()
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_DENY
        assert any("No authorization policy" in r for r in result["reasons"])

    def test_deny_by_default_policy(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [], store, default_policy=VERDICT_DENY)
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_DENY

    def test_allow_by_default_allow_policy(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [], store, default_policy=VERDICT_ALLOW)
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_ALLOW

    def test_conditional_data_sensitivity_exceeded(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"data_sensitivity_max": "INTERNAL"},
            }
        ], store)
        ctx = {**self._base_context(), "data_sensitivity": "CONFIDENTIAL"}
        result = authorize("agent-1", "send_email", ctx, store)
        assert result["verdict"] == VERDICT_CONDITIONAL
        assert any("data_sensitivity" in c for c in result["unmet_conditions"])

    def test_conditional_consent_required_but_absent(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"user_consent_required": True},
            }
        ], store)
        ctx = {**self._base_context(), "user_consent_given": False}
        result = authorize("agent-1", "send_email", ctx, store)
        assert result["verdict"] == VERDICT_CONDITIONAL
        assert any("user_consent_given" in c for c in result["unmet_conditions"])

    def test_conditional_max_calls_exceeded(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"max_calls_per_session": 5},
            }
        ], store)
        ctx = {**self._base_context(), "call_count": 5}
        result = authorize("agent-1", "send_email", ctx, store)
        assert result["verdict"] == VERDICT_CONDITIONAL

    def test_conditional_trust_level_too_low(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"trust_level_min": "VERIFIED"},
            }
        ], store)
        ctx = {**self._base_context(), "trust_level": "EXTERNAL"}
        result = authorize("agent-1", "send_email", ctx, store)
        assert result["verdict"] == VERDICT_CONDITIONAL

    def test_conditional_context_tags_no_overlap(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"allowed_context_tags": ["admin", "internal_ops"]},
            }
        ], store)
        ctx = {**self._base_context(), "session_context_tags": ["customer_support"]}
        result = authorize("agent-1", "send_email", ctx, store)
        assert result["verdict"] == VERDICT_CONDITIONAL

    def test_allow_context_tags_overlap(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [
            {
                "tool_name": "send_email",
                "allow_if": {"allowed_context_tags": ["customer_support", "admin"]},
            }
        ], store)
        result = authorize("agent-1", "send_email", self._base_context(), store)
        assert result["verdict"] == VERDICT_ALLOW

    def test_result_has_required_fields(self):
        store = _setup_store_with_agent()
        create_policy("agent-1", [], store)
        result = authorize("agent-1", "send_email", self._base_context(), store)
        for field in ("auth_version", "verdict", "agent_id", "tool_name",
                      "reasons", "unmet_conditions", "evidence_origin", "authorized_at"):
            assert field in result

    def test_evidence_origin_locally_observed(self):
        store = _setup_store_with_agent()
        result = authorize("agent-1", "send_email", {}, store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_auth_version_in_result(self):
        store = _setup_store_with_agent()
        result = authorize("agent-1", "send_email", {}, store)
        assert result["auth_version"] == AUTH_VERSION

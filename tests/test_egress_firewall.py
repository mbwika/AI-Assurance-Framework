"""Tests for aiaf.core.egress_firewall."""

import pytest

from aiaf.core.agent_action_ledger import get_ledger, verify_chain
from aiaf.core.egress_firewall import (
    CHANNEL_DATA,
    CHANNEL_NETWORK,
    CHANNEL_TOOL,
    FIREWALL_VERSION,
    FirewallDecisionError,
    authorize_data_egress,
    authorize_network_egress,
    authorize_tool_egress,
    decide_egress,
)
from aiaf.core.policy_enforcement import VERDICT_DENY, create_pep_policy
from aiaf.core.tool_authorization import (
    VERDICT_ALLOW,
    VERDICT_CONDITIONAL,
    create_policy,
)
from aiaf.registry.agent_registry import register_agent, set_agent_status


class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record

    def list_models(self):
        return list(self._data.values())


def _register_agent(store, *, capabilities=None, constraints=None, tools=None):
    register_agent(
        "agent-1",
        "Firewall Agent",
        tools or ["send_email", "search"],
        "INTERNAL",
        capabilities or ["network_egress", "data_write"],
        store,
        operational_constraints=constraints or {},
    )


def _tool_context(**overrides):
    base = {
        "data_sensitivity": "INTERNAL",
        "user_consent_given": True,
        "call_count": 0,
        "trust_level": "INTERNAL",
        "session_context_tags": ["ops"],
    }
    base.update(overrides)
    return base


def test_constants_are_exposed():
    assert FIREWALL_VERSION == "1.0"
    assert {CHANNEL_NETWORK, CHANNEL_TOOL, CHANNEL_DATA} == {"network", "tool", "data"}


def test_network_egress_allowed_and_logged():
    store = _Store()
    _register_agent(store, capabilities=["network_egress"])

    result = authorize_network_egress(
        "agent-1",
        "sess-1",
        "api.openai.com",
        store,
        context={"approval_granted": True},
    )

    assert result["verdict"] == VERDICT_ALLOW
    assert result["ledger_decision"] == "ALLOW"
    ledger = get_ledger("sess-1", store)
    assert ledger["entry_count"] == 1
    assert ledger["entries"][0]["tool_name"] == "egress:network"
    assert verify_chain("sess-1", store)["chain_valid"] is True


def test_network_egress_denied_when_capability_missing():
    store = _Store()
    _register_agent(store, capabilities=["data_write"])

    result = authorize_network_egress("agent-1", "sess-1", "example.com", store)

    assert result["verdict"] == VERDICT_DENY
    assert "network_egress" in result["capability_decision"]["missing_capabilities"]
    assert result["ledger_decision"] == "DENY"


def test_network_egress_becomes_conditional_without_required_approval():
    store = _Store()
    _register_agent(
        store,
        capabilities=["network_egress"],
        constraints={"requires_approval_for_egress": True},
    )

    result = authorize_network_egress("agent-1", "sess-1", "example.com", store)

    assert result["verdict"] == VERDICT_CONDITIONAL
    assert "approval_granted" in result["conditions_required"]
    assert result["ledger_decision"] == "FLAG"


def test_network_egress_denied_by_destination_constraint():
    store = _Store()
    _register_agent(
        store,
        capabilities=["network_egress"],
        constraints={"blocked_egress_destinations": ["*.evil.example"]},
    )

    result = authorize_network_egress(
        "agent-1",
        "sess-1",
        "api.evil.example",
        store,
    )

    assert result["verdict"] == VERDICT_DENY
    assert any("blocked_egress_destinations" in reason for reason in result["reasons"])


def test_network_egress_pep_deny_is_respected():
    store = _Store()
    _register_agent(store, capabilities=["network_egress"])
    create_pep_policy(
        "pep-1",
        "agent-1",
        store,
        denied_resources=["network:blocked.example"],
    )

    result = authorize_network_egress(
        "agent-1",
        "sess-1",
        "blocked.example",
        store,
    )

    assert result["verdict"] == VERDICT_DENY
    assert result["policy_decision"]["verdict"] == VERDICT_DENY
    assert result["policy_decision"]["policy_ids_evaluated"] == ["pep-1"]


def test_tool_egress_uses_tool_authorization():
    store = _Store()
    _register_agent(store, capabilities=["network_egress"], tools=["send_email"])
    create_policy(
        "agent-1",
        [{"tool_name": "send_email", "allow_if": {"data_sensitivity_max": "INTERNAL"}}],
        store,
    )

    result = authorize_tool_egress(
        "agent-1",
        "sess-1",
        "send_email",
        store,
        context=_tool_context(),
    )

    assert result["verdict"] == VERDICT_ALLOW
    assert result["tool_authorization"]["verdict"] == VERDICT_ALLOW
    ledger = get_ledger("sess-1", store)
    assert ledger["entries"][0]["tool_name"] == "send_email"


def test_tool_egress_conditional_maps_to_flagged_ledger_entry():
    store = _Store()
    _register_agent(store, capabilities=["network_egress"], tools=["send_email"])
    create_policy(
        "agent-1",
        [{"tool_name": "send_email", "allow_if": {"user_consent_required": True}}],
        store,
    )

    result = authorize_tool_egress(
        "agent-1",
        "sess-1",
        "send_email",
        store,
        context=_tool_context(user_consent_given=False),
    )

    assert result["verdict"] == VERDICT_CONDITIONAL
    assert result["ledger_decision"] == "FLAG"
    assert result["tool_authorization"]["verdict"] == VERDICT_CONDITIONAL


def test_data_channel_uses_read_capability_for_read_actions():
    store = _Store()
    _register_agent(store, capabilities=["data_read"])

    result = authorize_data_egress(
        "agent-1",
        "sess-1",
        "warehouse:customers",
        store,
        action="read",
    )

    assert result["verdict"] == VERDICT_ALLOW
    assert result["capability_decision"]["required_capabilities"] == ["data_read"]


def test_inactive_agent_is_denied_and_still_logged():
    store = _Store()
    _register_agent(store, capabilities=["network_egress"])
    set_agent_status("agent-1", "suspended", store, reason="containment")

    result = authorize_network_egress("agent-1", "sess-1", "example.com", store)

    assert result["verdict"] == VERDICT_DENY
    assert any("containment" in reason for reason in result["reasons"])
    assert get_ledger("sess-1", store)["entry_count"] == 1


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"agent_id": "", "session_id": "s1", "channel": "network", "target": "x"}, "agent_id"),
        ({"agent_id": "a1", "session_id": "", "channel": "network", "target": "x"}, "session_id"),
        ({"agent_id": "a1", "session_id": "s1", "channel": "bogus", "target": "x"}, "channel"),
        ({"agent_id": "a1", "session_id": "s1", "channel": "network", "target": ""}, "target"),
    ],
)
def test_invalid_requests_raise(kwargs, message):
    store = _Store()
    with pytest.raises(FirewallDecisionError, match=message):
        decide_egress(store=store, **kwargs)

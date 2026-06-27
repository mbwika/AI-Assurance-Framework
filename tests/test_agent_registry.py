"""Tests for aiaf.registry.agent_registry."""

import pytest

from aiaf.registry.agent_registry import (
    CAPABILITY_APPROVAL_BYPASS,
    CAPABILITY_CODE_EXECUTION,
    CAPABILITY_FLAGS,
    CAPABILITY_NETWORK_EGRESS,
    CAPABILITY_RISK_RANK,
    MAX_TOOLS_PER_AGENT,
    REGISTRY_VERSION,
    TRUST_EXTERNAL,
    TRUST_INTERNAL,
    TRUST_LABELS,
    TRUST_RANK,
    TRUST_UNTRUSTED,
    TRUST_USER,
    TRUST_VERIFIED,
    AgentRegistryError,
    _validate_capabilities,
    _validate_trust_label,
    deregister_agent,
    get_agent,
    link_manifest,
    list_agents,
    register_agent,
)

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


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_registry_version(self):
        assert REGISTRY_VERSION == "1.0"

    def test_trust_labels_frozenset(self):
        for t in (TRUST_VERIFIED, TRUST_INTERNAL, TRUST_EXTERNAL, TRUST_USER, TRUST_UNTRUSTED):
            assert t in TRUST_LABELS

    def test_trust_rank_order(self):
        assert TRUST_RANK[TRUST_VERIFIED] > TRUST_RANK[TRUST_INTERNAL]
        assert TRUST_RANK[TRUST_INTERNAL] > TRUST_RANK[TRUST_EXTERNAL]
        assert TRUST_RANK[TRUST_EXTERNAL] > TRUST_RANK[TRUST_USER]
        assert TRUST_RANK[TRUST_USER] > TRUST_RANK[TRUST_UNTRUSTED]

    def test_capability_flags_frozenset(self):
        assert CAPABILITY_NETWORK_EGRESS in CAPABILITY_FLAGS
        assert CAPABILITY_CODE_EXECUTION in CAPABILITY_FLAGS
        assert CAPABILITY_APPROVAL_BYPASS in CAPABILITY_FLAGS

    def test_capability_risk_rank_approval_bypass_highest(self):
        assert CAPABILITY_RISK_RANK[CAPABILITY_APPROVAL_BYPASS] > CAPABILITY_RISK_RANK[CAPABILITY_CODE_EXECUTION]

    def test_max_tools_per_agent(self):
        assert MAX_TOOLS_PER_AGENT >= 100


# ── Validators ────────────────────────────────────────────────────────────────

class TestValidators:
    def test_valid_trust_label_case_insensitive(self):
        assert _validate_trust_label("internal") == "INTERNAL"
        assert _validate_trust_label("VERIFIED") == "VERIFIED"

    def test_invalid_trust_label_raises(self):
        with pytest.raises(AgentRegistryError):
            _validate_trust_label("ADMIN")

    def test_valid_capabilities_normalised(self):
        result = _validate_capabilities(["NETWORK_EGRESS", "code_execution"])
        assert "network_egress" in result
        assert "code_execution" in result

    def test_invalid_capability_raises(self):
        with pytest.raises(AgentRegistryError):
            _validate_capabilities(["fly_away"])

    def test_capabilities_deduplicated_and_sorted(self):
        result = _validate_capabilities(["code_execution", "code_execution", "network_egress"])
        assert result == sorted(set(result))


# ── register_agent ────────────────────────────────────────────────────────────

class TestRegisterAgent:
    def test_basic_registration(self):
        store = _Store()
        result = register_agent(
            "a1", "Test Bot", ["search", "email"], "INTERNAL",
            ["network_egress", "data_read"], store,
        )
        assert result["agent_id"] == "a1"
        assert result["name"] == "Test Bot"
        assert result["trust_level"] == "INTERNAL"
        assert "network_egress" in result["capability_flags"]

    def test_empty_agent_id_raises(self):
        store = _Store()
        with pytest.raises(AgentRegistryError):
            register_agent("", "Bot", [], "INTERNAL", [], store)

    def test_invalid_trust_level_raises(self):
        store = _Store()
        with pytest.raises(AgentRegistryError):
            register_agent("a2", "Bot", [], "SUPERUSER", [], store)

    def test_invalid_capability_raises(self):
        store = _Store()
        with pytest.raises(AgentRegistryError):
            register_agent("a3", "Bot", [], "INTERNAL", ["fly"], store)

    def test_declared_tools_list_required(self):
        store = _Store()
        with pytest.raises(AgentRegistryError):
            register_agent("a4", "Bot", "not-a-list", "INTERNAL", [], store)

    def test_registry_version_returned(self):
        store = _Store()
        result = register_agent("a5", "Bot", [], "INTERNAL", [], store)
        assert result["registry_version"] == REGISTRY_VERSION

    def test_re_registration_preserves_registered_at(self):
        store = _Store()
        r1 = register_agent("a6", "Bot", [], "INTERNAL", [], store)
        r2 = register_agent("a6", "Bot v2", [], "VERIFIED", [], store)
        assert r1["registered_at"] == r2["registered_at"]
        assert r2["trust_level"] == "VERIFIED"

    def test_status_active_on_registration(self):
        store = _Store()
        result = register_agent("a7", "Bot", [], "INTERNAL", [], store)
        assert result["status"] == "active"

    def test_purpose_stored(self):
        store = _Store()
        result = register_agent("a8", "Bot", [], "INTERNAL", [], store,
                                purpose="Customer support")
        assert result["purpose"] == "Customer support"

    def test_operational_constraints_stored(self):
        store = _Store()
        constraints = {"max_tool_calls_per_session": 20}
        result = register_agent("a9", "Bot", [], "INTERNAL", [], store,
                                operational_constraints=constraints)
        assert result["operational_constraints"]["max_tool_calls_per_session"] == 20

    def test_manifest_id_stored(self):
        store = _Store()
        result = register_agent("a10", "Bot", [], "INTERNAL", [], store,
                                manifest_id="mfst-abc123")
        assert result["manifest_id"] == "mfst-abc123"

    def test_max_capability_risk_rank_computed(self):
        store = _Store()
        result = register_agent("a11", "Bot", [], "INTERNAL",
                                [CAPABILITY_APPROVAL_BYPASS], store)
        assert result["max_capability_risk_rank"] == CAPABILITY_RISK_RANK[CAPABILITY_APPROVAL_BYPASS]

    def test_empty_caps_max_rank_zero(self):
        store = _Store()
        result = register_agent("a12", "Bot", [], "INTERNAL", [], store)
        assert result["max_capability_risk_rank"] == 0


# ── get_agent ─────────────────────────────────────────────────────────────────

class TestGetAgent:
    def test_get_registered_agent(self):
        store = _Store()
        register_agent("g1", "Bot", [], "INTERNAL", [], store)
        result = get_agent("g1", store)
        assert result is not None
        assert result["agent_id"] == "g1"

    def test_get_nonexistent_returns_none(self):
        store = _Store()
        assert get_agent("nonexistent", store) is None


# ── list_agents ───────────────────────────────────────────────────────────────

class TestListAgents:
    def test_list_empty(self):
        store = _Store()
        assert list_agents(store) == []

    def test_list_returns_registered(self):
        store = _Store()
        register_agent("l1", "A", [], "INTERNAL", [], store)
        register_agent("l2", "B", [], "EXTERNAL", [], store)
        results = list_agents(store)
        ids = {r["agent_id"] for r in results}
        assert "l1" in ids and "l2" in ids

    def test_list_filter_by_trust_level(self):
        store = _Store()
        register_agent("f1", "A", [], "INTERNAL", [], store)
        register_agent("f2", "B", [], "EXTERNAL", [], store)
        results = list_agents(store, trust_level="INTERNAL")
        assert all(r["trust_level"] == "INTERNAL" for r in results)

    def test_list_respects_limit(self):
        store = _Store()
        for i in range(5):
            register_agent(f"lim{i}", f"Bot{i}", [], "INTERNAL", [], store)
        results = list_agents(store, limit=3)
        assert len(results) <= 3

    def test_list_excludes_non_agent_records(self):
        store = _Store()
        store.save_model({"model_id": "some_model", "metadata": {}})
        results = list_agents(store)
        assert all(r.get("agent_id") is not None for r in results)


# ── deregister_agent ──────────────────────────────────────────────────────────

class TestDeregisterAgent:
    def test_deregister_sets_status(self):
        store = _Store()
        register_agent("d1", "Bot", [], "INTERNAL", [], store)
        assert deregister_agent("d1", store) is True
        agent = get_agent("d1", store)
        assert agent["status"] == "deregistered"

    def test_deregister_nonexistent_returns_false(self):
        store = _Store()
        assert deregister_agent("nobody", store) is False

    def test_deregister_sets_deregistered_at(self):
        store = _Store()
        register_agent("d2", "Bot", [], "INTERNAL", [], store)
        deregister_agent("d2", store)
        raw = store.get_model("agent:d2")
        assert "deregistered_at" in raw["metadata"]


# ── link_manifest ─────────────────────────────────────────────────────────────

class TestLinkManifest:
    def test_link_updates_manifest_id(self):
        store = _Store()
        register_agent("m1", "Bot", [], "INTERNAL", [], store)
        result = link_manifest("m1", "mfst-xyz", store)
        assert result["manifest_id"] == "mfst-xyz"

    def test_link_nonexistent_raises(self):
        store = _Store()
        with pytest.raises(AgentRegistryError):
            link_manifest("nobody", "mfst-xyz", store)

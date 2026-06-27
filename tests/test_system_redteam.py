"""Tests for src/aiaf/core/system_redteam.py"""

import pytest

from aiaf.core.system_redteam import (
    ALL_LAYERS,
    LAYER_APP,
    LAYER_APPROVAL,
    LAYER_IDENTITY,
    LAYER_MODEL,
    LAYER_RETRIEVAL,
    LAYER_TELEMETRY,
    LAYER_TOOLS,
    SCENARIO_DENIAL_OF_WALLET,
    SCENARIO_IDENTITY_ESCALATION,
    SCENARIO_PROMPT_INJECTION_CASCADE,
    SCENARIO_RAG_POISONING_EXFIL,
    SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE,
    SCENARIOS,
    SYSTEM_REDTEAM_VERSION,
    SYSTEM_RISK_CRITICAL,
    SYSTEM_RISK_HIGH,
    SYSTEM_RISK_LOW,
    SYSTEM_RISK_MEDIUM,
    SystemRedTeamError,
    run_system_redteam,
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
    def test_version(self):
        assert SYSTEM_REDTEAM_VERSION == "1.0"

    def test_all_layers_complete(self):
        expected = {LAYER_MODEL, LAYER_APP, LAYER_RETRIEVAL, LAYER_TOOLS,
                    LAYER_IDENTITY, LAYER_TELEMETRY, LAYER_APPROVAL}
        assert expected == ALL_LAYERS

    def test_scenarios_complete(self):
        expected = {
            SCENARIO_PROMPT_INJECTION_CASCADE, SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE,
            SCENARIO_RAG_POISONING_EXFIL, SCENARIO_IDENTITY_ESCALATION,
            SCENARIO_DENIAL_OF_WALLET,
        }
        assert expected == SCENARIOS


# ── run_system_redteam — basics ────────────────────────────────────────────────

class TestRunSystemRedteamBasics:
    def test_returns_dict_with_required_keys(self):
        store = _Store()
        result = run_system_redteam("sys-1", store)
        required = {
            "system_id", "system_redteam_version", "overall_risk",
            "layers_tested", "layer_findings", "cross_layer_scenarios",
            "applicable_scenario_count", "total_findings",
            "critical_findings", "recommended_priority_fixes",
            "evidence_origin", "assessed_at",
        }
        assert required.issubset(result.keys())

    def test_system_id_echoed(self):
        store = _Store()
        result = run_system_redteam("my-system", store)
        assert result["system_id"] == "my-system"

    def test_version_echoed(self):
        store = _Store()
        result = run_system_redteam("s", store)
        assert result["system_redteam_version"] == SYSTEM_REDTEAM_VERSION

    def test_evidence_origin_locally_observed(self):
        store = _Store()
        result = run_system_redteam("s", store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_all_layers_tested_by_default(self):
        store = _Store()
        result = run_system_redteam("s", store)
        assert set(result["layers_tested"]) == ALL_LAYERS

    def test_five_cross_layer_scenarios(self):
        store = _Store()
        result = run_system_redteam("s", store)
        assert len(result["cross_layer_scenarios"]) == 5

    def test_overall_risk_is_valid(self):
        store = _Store()
        result = run_system_redteam("s", store)
        assert result["overall_risk"] in {SYSTEM_RISK_LOW, SYSTEM_RISK_MEDIUM,
                                          SYSTEM_RISK_HIGH, SYSTEM_RISK_CRITICAL}


# ── Layer subset ───────────────────────────────────────────────────────────────

class TestLayerSubset:
    def test_restrict_to_single_layer(self):
        store = _Store()
        result = run_system_redteam("s", store, layers=[LAYER_MODEL])
        assert result["layers_tested"] == [LAYER_MODEL]
        assert set(result["layer_findings"].keys()) == {LAYER_MODEL}

    def test_unknown_layer_raises(self):
        store = _Store()
        with pytest.raises(SystemRedTeamError, match="Unknown layers"):
            run_system_redteam("s", store, layers=["BADLAYER"])

    def test_restrict_to_two_layers(self):
        store = _Store()
        result = run_system_redteam("s", store, layers=[LAYER_MODEL, LAYER_APP])
        assert set(result["layers_tested"]) == {LAYER_MODEL, LAYER_APP}


# ── System configuration effects ──────────────────────────────────────────────

class TestSystemConfigEffects:
    def test_external_models_triggers_model_finding(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"external_models": True})
        model_findings = result["layer_findings"].get(LAYER_MODEL, [])
        sev_list = [f["severity"] for f in model_findings]
        assert "HIGH" in sev_list

    def test_internet_facing_without_guardrails_critical(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "internet_facing": True,
            "has_guardrails": False,
        })
        app_findings = result["layer_findings"].get(LAYER_APP, [])
        sev_list = [f["severity"] for f in app_findings]
        assert "CRITICAL" in sev_list

    def test_internet_facing_with_guardrails_no_critical_in_app(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "internet_facing": True,
            "has_guardrails": True,
        })
        app_findings = result["layer_findings"].get(LAYER_APP, [])
        sev_list = [f["severity"] for f in app_findings]
        assert "CRITICAL" not in sev_list

    def test_no_rag_returns_no_retrieval_findings(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_rag": False})
        retrieval_findings = result["layer_findings"].get(LAYER_RETRIEVAL, [])
        assert retrieval_findings == []

    def test_rag_present_triggers_retrieval_findings(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_rag": True})
        retrieval_findings = result["layer_findings"].get(LAYER_RETRIEVAL, [])
        assert len(retrieval_findings) > 0

    def test_agents_without_identity_management_finding(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_agents": True,
            "has_identity_management": False,
        })
        id_findings = result["layer_findings"].get(LAYER_IDENTITY, [])
        assert len(id_findings) > 0

    def test_no_audit_logging_triggers_telemetry_finding(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_audit_logging": False})
        tel_findings = result["layer_findings"].get(LAYER_TELEMETRY, [])
        assert any("audit" in f["finding"].lower() for f in tel_findings)

    def test_no_resource_limits_triggers_telemetry_finding(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_resource_limits": False})
        tel_findings = result["layer_findings"].get(LAYER_TELEMETRY, [])
        assert any("resource" in f["finding"].lower() or "budget" in f["finding"].lower()
                   for f in tel_findings)

    def test_agents_without_approval_triggers_approval_finding(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_agents": True,
            "has_human_approval": False,
        })
        appr_findings = result["layer_findings"].get(LAYER_APPROVAL, [])
        assert len(appr_findings) > 0


# ── Cross-layer scenarios ──────────────────────────────────────────────────────

class TestCrossLayerScenarios:
    def _get_scenario(self, result, name):
        for s in result["cross_layer_scenarios"]:
            if s["scenario"] == name:
                return s
        return None

    def test_prompt_injection_cascade_applicable_with_rag_and_tools(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_rag": True,
            "has_tools": True,
        })
        s = self._get_scenario(result, SCENARIO_PROMPT_INJECTION_CASCADE)
        assert s is not None
        assert s["applicable"] is True

    def test_prompt_injection_cascade_not_applicable_without_rag(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_rag": False,
            "has_tools": True,
        })
        s = self._get_scenario(result, SCENARIO_PROMPT_INJECTION_CASCADE)
        assert s["applicable"] is False

    def test_supply_chain_abuse_applicable_with_external_agents_tools(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "external_models": True,
            "has_agents": True,
            "has_tools": True,
        })
        s = self._get_scenario(result, SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE)
        assert s["applicable"] is True

    def test_denial_of_wallet_applicable_with_agents_no_limits(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_agents": True,
            "has_resource_limits": False,
        })
        s = self._get_scenario(result, SCENARIO_DENIAL_OF_WALLET)
        assert s["applicable"] is True

    def test_denial_of_wallet_not_applicable_with_resource_limits(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_agents": True,
            "has_resource_limits": True,
        })
        s = self._get_scenario(result, SCENARIO_DENIAL_OF_WALLET)
        assert s["applicable"] is False

    def test_identity_escalation_applicable_without_identity_mgmt(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_agents": True,
            "has_identity_management": False,
        })
        s = self._get_scenario(result, SCENARIO_IDENTITY_ESCALATION)
        assert s["applicable"] is True

    def test_applicable_scenarios_counted(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "has_rag": True, "has_tools": True,
            "external_models": True, "has_agents": True,
            "has_resource_limits": False, "has_identity_management": False,
        })
        assert result["applicable_scenario_count"] >= 3

    def test_attack_path_non_empty_for_applicable_scenario(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_rag": True, "has_tools": True})
        s = self._get_scenario(result, SCENARIO_PROMPT_INJECTION_CASCADE)
        assert len(s["attack_path"]) > 0

    def test_attack_path_empty_for_non_applicable_scenario(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_rag": False})
        s = self._get_scenario(result, SCENARIO_PROMPT_INJECTION_CASCADE)
        assert s["attack_path"] == []

    def test_mitigations_non_empty_for_applicable_scenario(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={"has_rag": True, "has_tools": True})
        s = self._get_scenario(result, SCENARIO_PROMPT_INJECTION_CASCADE)
        assert len(s["mitigations"]) > 0


# ── Overall risk escalation ────────────────────────────────────────────────────

class TestOverallRisk:
    def test_minimal_config_still_has_findings(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={})
        # A plain deployment with no controls will have findings
        assert result["total_findings"] > 0

    def test_internet_facing_without_guardrails_is_critical(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "internet_facing": True,
            "has_guardrails": False,
        })
        assert result["overall_risk"] == SYSTEM_RISK_CRITICAL

    def test_critical_findings_counted(self):
        store = _Store()
        result = run_system_redteam("s", store, system_config={
            "internet_facing": True,
            "has_guardrails": False,
        })
        assert result["critical_findings"] >= 1

    def test_priority_fixes_are_strings(self):
        store = _Store()
        result = run_system_redteam("s", store)
        for fix in result["recommended_priority_fixes"]:
            assert isinstance(fix, str) and len(fix) > 0


# ── model_ids / agent_ids enrichment ──────────────────────────────────────────

class TestModelAgentEnrichment:
    def test_model_ids_sets_model_count(self):
        store = _Store()
        result = run_system_redteam("s", store, model_ids=["m1", "m2", "m3", "m4", "m5"])
        # model_count >= 5 → extra finding about large model count
        model_findings = result["layer_findings"].get(LAYER_MODEL, [])
        finding_texts = " ".join(f["finding"] for f in model_findings)
        assert "5" in finding_texts

    def test_agent_ids_enables_has_agents(self):
        store = _Store()
        result = run_system_redteam("s", store, agent_ids=["a1"],
                                    system_config={"has_resource_limits": False})
        s = None
        for scenario in result["cross_layer_scenarios"]:
            if scenario["scenario"] == SCENARIO_DENIAL_OF_WALLET:
                s = scenario
        assert s["applicable"] is True

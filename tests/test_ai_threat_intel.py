"""Tests for src/aiaf/registry/ai_threat_intel.py"""

import pytest

from aiaf.registry.ai_threat_intel import (
    _BUILTIN_INDEX,
    _BUILTIN_THREATS,
    ASSET_AGENT,
    ASSET_DATASET,
    ASSET_MODEL,
    ASSET_RAG_STORE,
    ASSET_TOOL,
    CATEGORY_AVAILABILITY,
    CATEGORY_DATA_ATTACKS,
    CATEGORY_EXFILTRATION,
    CATEGORY_MODEL_INTEGRITY,
    CATEGORY_PROMPT_ATTACKS,
    CATEGORY_SUPPLY_CHAIN,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_CUSTOM,
    SOURCE_MITRE_ATLAS,
    SOURCE_OWASP_AGENTIC,
    SOURCE_OWASP_LLM,
    ThreatIntelError,
    build_threat_landscape,
    correlate_agent,
    correlate_model,
    correlate_tool,
    get_threat,
    ingest_threat,
    list_threats,
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


# ── Built-in knowledge base ────────────────────────────────────────────────────

class TestBuiltins:
    def test_builtin_count(self):
        assert len(_BUILTIN_THREATS) == 20

    def test_owasp_llm_techniques_present(self):
        ids = {t["technique_id"] for t in _BUILTIN_THREATS}
        for i in range(1, 11):
            assert f"LLM{i:02d}" in ids

    def test_mitre_atlas_techniques_present(self):
        ids = {t["technique_id"] for t in _BUILTIN_THREATS}
        for tid in ["AML.T0018", "AML.T0020", "AML.T0024", "AML.T0031",
                    "AML.T0040", "AML.T0043", "AML.T0046"]:
            assert tid in ids

    def test_owasp_agentic_techniques_present(self):
        ids = {t["technique_id"] for t in _BUILTIN_THREATS}
        assert "AGENTIC-01" in ids
        assert "AGENTIC-02" in ids
        assert "AGENTIC-03" in ids

    def test_all_have_required_fields(self):
        required = {"technique_id", "name", "category", "description",
                    "affected_asset_types", "severity", "source"}
        for t in _BUILTIN_THREATS:
            missing = required - t.keys()
            assert not missing, f"{t['technique_id']} missing: {missing}"

    def test_builtin_index_keys_match_techniques(self):
        for tid, t in _BUILTIN_INDEX.items():
            assert t["technique_id"] == tid

    def test_llm01_severity_critical(self):
        assert _BUILTIN_INDEX["LLM01"]["severity"] == SEVERITY_CRITICAL

    def test_aml_t0018_category_model_integrity(self):
        assert _BUILTIN_INDEX["AML.T0018"]["category"] == CATEGORY_MODEL_INTEGRITY


# ── ingest_threat ──────────────────────────────────────────────────────────────

class TestIngestThreat:
    def test_basic_ingest(self):
        store = _Store()
        result = ingest_threat(
            "CUSTOM-01", "Test Threat", CATEGORY_PROMPT_ATTACKS,
            "A test threat.", [ASSET_MODEL], SEVERITY_HIGH, store,
        )
        assert result["technique_id"] == "CUSTOM-01"
        assert result["severity"] == SEVERITY_HIGH
        assert result["source"] == SOURCE_CUSTOM
        assert "ingested_at" in result

    def test_ingest_normalises_technique_id_uppercase(self):
        store = _Store()
        result = ingest_threat(
            "custom-x1", "Test", CATEGORY_SUPPLY_CHAIN, "Desc.",
            [ASSET_TOOL], SEVERITY_LOW, store,
        )
        assert result["technique_id"] == "CUSTOM-X1"

    def test_ingest_persists_to_store(self):
        store = _Store()
        ingest_threat("CX-01", "T", CATEGORY_AVAILABILITY, "D", [ASSET_AGENT], SEVERITY_MEDIUM, store)
        retrieved = get_threat("CX-01", store)
        assert retrieved is not None
        assert retrieved["technique_id"] == "CX-01"

    def test_ingest_invalid_category_raises(self):
        store = _Store()
        with pytest.raises(ThreatIntelError, match="Unknown category"):
            ingest_threat("X", "N", "BAD_CAT", "D", [ASSET_MODEL], SEVERITY_LOW, store)

    def test_ingest_invalid_severity_raises(self):
        store = _Store()
        with pytest.raises(ThreatIntelError, match="Unknown severity"):
            ingest_threat("X", "N", CATEGORY_AVAILABILITY, "D", [ASSET_MODEL], "EXTREME", store)

    def test_ingest_invalid_asset_type_raises(self):
        store = _Store()
        with pytest.raises(ThreatIntelError, match="Unknown asset types"):
            ingest_threat("X", "N", CATEGORY_SUPPLY_CHAIN, "D", ["ROBOT"], SEVERITY_LOW, store)

    def test_ingest_empty_technique_id_raises(self):
        store = _Store()
        with pytest.raises(ThreatIntelError):
            ingest_threat("", "N", CATEGORY_SUPPLY_CHAIN, "D", [ASSET_MODEL], SEVERITY_LOW, store)

    def test_ingest_overwrites_builtin(self):
        store = _Store()
        ingest_threat(
            "LLM01", "Custom Override", CATEGORY_PROMPT_ATTACKS, "New desc.",
            [ASSET_MODEL], SEVERITY_MEDIUM, store,
        )
        threat = get_threat("LLM01", store)
        assert threat["name"] == "Custom Override"
        assert threat["severity"] == SEVERITY_MEDIUM

    def test_ingest_with_optional_fields(self):
        store = _Store()
        result = ingest_threat(
            "CX-02", "T", CATEGORY_DATA_ATTACKS, "D", [ASSET_DATASET], SEVERITY_HIGH, store,
            owasp_llm_id="LLM04",
            mitre_atlas_id="AML.T0020",
            capability_triggers=["fine-tuned"],
            recommended_controls=["provenance_check"],
            source=SOURCE_MITRE_ATLAS,
        )
        assert result["owasp_llm_id"] == "LLM04"
        assert result["mitre_atlas_id"] == "AML.T0020"
        assert "fine-tuned" in result["capability_triggers"]
        assert result["source"] == SOURCE_MITRE_ATLAS


# ── get_threat ─────────────────────────────────────────────────────────────────

class TestGetThreat:
    def test_get_builtin(self):
        store = _Store()
        t = get_threat("LLM01", store)
        assert t is not None
        assert t["technique_id"] == "LLM01"

    def test_get_missing_returns_none(self):
        store = _Store()
        assert get_threat("NOTEXIST", store) is None

    def test_custom_overrides_builtin_on_get(self):
        store = _Store()
        ingest_threat("LLM02", "Override", CATEGORY_EXFILTRATION, "D", [ASSET_MODEL], SEVERITY_LOW, store)
        t = get_threat("LLM02", store)
        assert t["severity"] == SEVERITY_LOW  # overridden

    def test_get_normalises_to_uppercase(self):
        store = _Store()
        t = get_threat("llm01", store)
        assert t is not None


# ── list_threats ───────────────────────────────────────────────────────────────

class TestListThreats:
    def test_returns_all_builtins_by_default(self):
        store = _Store()
        threats = list_threats(store)
        assert len(threats) == 20

    def test_filter_by_category(self):
        store = _Store()
        threats = list_threats(store, category=CATEGORY_PROMPT_ATTACKS)
        assert all(t["category"] == CATEGORY_PROMPT_ATTACKS for t in threats)
        assert len(threats) > 0

    def test_filter_by_severity_critical(self):
        store = _Store()
        threats = list_threats(store, severity=SEVERITY_CRITICAL)
        assert all(t["severity"] == SEVERITY_CRITICAL for t in threats)

    def test_filter_by_asset_type(self):
        store = _Store()
        threats = list_threats(store, asset_type=ASSET_RAG_STORE)
        assert all(ASSET_RAG_STORE in t["affected_asset_types"] for t in threats)
        assert len(threats) > 0

    def test_filter_by_source(self):
        store = _Store()
        threats = list_threats(store, source=SOURCE_MITRE_ATLAS)
        assert all(t["source"] == SOURCE_MITRE_ATLAS for t in threats)
        assert len(threats) == 7  # 7 MITRE ATLAS built-ins

    def test_custom_added_to_list(self):
        store = _Store()
        ingest_threat("CX-LIST", "T", CATEGORY_AVAILABILITY, "D", [ASSET_MODEL], SEVERITY_MEDIUM, store)
        threats = list_threats(store)
        tids = {t["technique_id"] for t in threats}
        assert "CX-LIST" in tids

    def test_sorted_by_severity_desc(self):
        store = _Store()
        threats = list_threats(store)
        ranks = [{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(t["severity"], 0) for t in threats]
        assert ranks == sorted(ranks, reverse=True)


# ── correlate_model ────────────────────────────────────────────────────────────

class TestCorrelateModel:
    def test_basic_model_correlation(self):
        store = _Store()
        rec = {"model_id": "m1", "metadata": {"task_types": ["chat", "instruction-following"]}}
        result = correlate_model(rec, store)
        assert "applicable_threats" in result
        assert result["threat_count"] > 0
        assert result["model_id"] == "m1"

    def test_top_n_limits_results(self):
        store = _Store()
        rec = {"model_id": "m1", "metadata": {}}
        result = correlate_model(rec, store, top_n=3)
        assert len(result["applicable_threats"]) <= 3

    def test_evidence_origin_locally_observed(self):
        store = _Store()
        rec = {"model_id": "m1", "metadata": {}}
        result = correlate_model(rec, store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_highest_severity_field(self):
        store = _Store()
        rec = {"model_id": "m1", "metadata": {}}
        result = correlate_model(rec, store)
        assert result["highest_severity"] in {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}

    def test_rag_model_gets_rag_threats(self):
        store = _Store()
        rec = {"model_id": "rag-m", "metadata": {"task_types": ["retrieval", "rag", "embedding"]}}
        result = correlate_model(rec, store)
        tids = {t["technique_id"] for t in result["applicable_threats"]}
        assert "LLM08" in tids


# ── correlate_agent ────────────────────────────────────────────────────────────

class TestCorrelateAgent:
    def test_basic_agent_correlation(self):
        store = _Store()
        rec = {"model_id": "a1", "metadata": {"autonomous": True}}
        result = correlate_agent(rec, store)
        assert result["agent_id"] == "a1"
        assert result["threat_count"] > 0

    def test_agentic_threats_present(self):
        store = _Store()
        rec = {"model_id": "a1", "metadata": {}}
        result = correlate_agent(rec, store)
        tids = {t["technique_id"] for t in result["applicable_threats"]}
        assert "LLM06" in tids or "LLM01" in tids or "AGENTIC-01" in tids


# ── correlate_tool ─────────────────────────────────────────────────────────────

class TestCorrelateTool:
    def test_basic_tool_correlation(self):
        store = _Store()
        rec = {"model_id": "t1", "metadata": {}}
        result = correlate_tool(rec, store)
        assert result["tool_id"] == "t1"
        assert result["threat_count"] > 0

    def test_mcp_tool_gets_mcp_threats(self):
        store = _Store()
        rec = {"model_id": "t1", "metadata": {"server_type": "mcp"}}
        result = correlate_tool(rec, store)
        assert result["threat_count"] >= 1


# ── build_threat_landscape ─────────────────────────────────────────────────────

class TestBuildThreatLandscape:
    def test_total_count_equals_builtins(self):
        store = _Store()
        landscape = build_threat_landscape(store)
        assert landscape["total_techniques"] == 20
        assert landscape["builtin_count"] == 20

    def test_critical_techniques_listed(self):
        store = _Store()
        landscape = build_threat_landscape(store)
        assert len(landscape["critical_techniques"]) > 0
        assert "LLM01" in landscape["critical_techniques"]

    def test_by_severity_all_keys_present(self):
        store = _Store()
        landscape = build_threat_landscape(store)
        assert set(landscape["by_severity"].keys()) == {
            SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
        }

    def test_by_source_has_all_three_sources(self):
        store = _Store()
        landscape = build_threat_landscape(store)
        assert SOURCE_OWASP_LLM in landscape["by_source"]
        assert SOURCE_MITRE_ATLAS in landscape["by_source"]
        assert SOURCE_OWASP_AGENTIC in landscape["by_source"]

    def test_custom_count_increases_after_ingest(self):
        store = _Store()
        ingest_threat("CX-L1", "T", CATEGORY_AVAILABILITY, "D", [ASSET_MODEL], SEVERITY_LOW, store)
        landscape = build_threat_landscape(store)
        assert landscape["custom_count"] >= 1

    def test_evidence_origin(self):
        store = _Store()
        landscape = build_threat_landscape(store)
        assert landscape["evidence_origin"] == "LOCALLY_OBSERVED"

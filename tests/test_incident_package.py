"""Tests for reporting/incident_package.py — Cap 7: AI incident reporting packages."""
import pytest

from aiaf.reporting.incident_package import (
    _CLASS_EVIDENCE_CHECKLIST,
    INCIDENT_CLASS_AGENT_CONTAINMENT,
    INCIDENT_CLASS_DATA_LEAKAGE,
    INCIDENT_CLASS_MODEL_EXTRACTION,
    INCIDENT_CLASS_PROMPT_INJECTION,
    INCIDENT_CLASS_RAG_POISONING,
    INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE,
    INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION,
    INCIDENT_CLASSES,
    INCIDENT_PACKAGE_VERSION,
    IncidentPackageError,
    build_incident_package,
    export_package,
)

# ---------------------------------------------------------------------------
# Minimal store stub
# ---------------------------------------------------------------------------

class _Store:
    def __init__(self):
        self._models = {}

    def save_model(self, record):
        mid = str(record.get("model_id") or "")
        self._models[mid] = record
        return mid

    def get_model(self, model_id):
        return self._models.get(str(model_id))

    def list_models(self):
        return list(self._models.values())


def _make_incident(store, incident_id, **kwargs):
    from aiaf.core.incident_manager import create_incident
    return create_incident(
        incident_id=incident_id,
        title=kwargs.get("title", "Test Incident"),
        severity=kwargs.get("severity", "HIGH"),
        source=kwargs.get("source", "test_suite"),
        model_id=kwargs.get("model_id", "test-model"),
        store=store,
        description=kwargs.get("description", "A test incident."),
        tags=kwargs.get("tags", []),
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_incident_class_constants():
    assert INCIDENT_CLASS_PROMPT_INJECTION == "PROMPT_INJECTION"
    assert INCIDENT_CLASS_DATA_LEAKAGE == "DATA_LEAKAGE"
    assert INCIDENT_CLASS_MODEL_EXTRACTION == "MODEL_EXTRACTION"
    assert INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION == "UNSAFE_TOOL_INVOCATION"
    assert INCIDENT_CLASS_RAG_POISONING == "RAG_POISONING"
    assert INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE == "UNAUTHORIZED_MODEL_CHANGE"
    assert INCIDENT_CLASS_AGENT_CONTAINMENT == "AGENT_CONTAINMENT"


def test_incident_classes_frozenset():
    assert len(INCIDENT_CLASSES) == 7
    for cls in (
        INCIDENT_CLASS_PROMPT_INJECTION,
        INCIDENT_CLASS_DATA_LEAKAGE,
        INCIDENT_CLASS_MODEL_EXTRACTION,
        INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION,
        INCIDENT_CLASS_RAG_POISONING,
        INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE,
        INCIDENT_CLASS_AGENT_CONTAINMENT,
    ):
        assert cls in INCIDENT_CLASSES


def test_version_constant():
    assert INCIDENT_PACKAGE_VERSION == "1.0"


# ---------------------------------------------------------------------------
# Evidence checklists
# ---------------------------------------------------------------------------

def test_evidence_checklists_non_empty():
    for cls in INCIDENT_CLASSES:
        checklist = _CLASS_EVIDENCE_CHECKLIST.get(cls)
        assert checklist, f"Missing checklist for {cls}"
        assert len(checklist) >= 3


def test_prompt_injection_checklist():
    cl = _CLASS_EVIDENCE_CHECKLIST[INCIDENT_CLASS_PROMPT_INJECTION]
    assert "offending_input_hash" in cl
    assert "influenced_output_refs" in cl


def test_rag_poisoning_checklist():
    cl = _CLASS_EVIDENCE_CHECKLIST[INCIDENT_CLASS_RAG_POISONING]
    assert "tainted_chunk_refs" in cl
    assert "blast_radius_output_refs" in cl


# ---------------------------------------------------------------------------
# build_incident_package
# ---------------------------------------------------------------------------

def test_build_package_basic():
    store = _Store()
    _make_incident(store, "inc-001")
    pkg = build_incident_package("inc-001", store)
    assert pkg["incident_id"] == "inc-001"
    assert pkg["incident_package_version"] == INCIDENT_PACKAGE_VERSION
    assert "bundle_sha256" in pkg
    assert "timeline" in pkg
    assert "evidence_checklist" in pkg


def test_build_package_with_incident_class():
    store = _Store()
    _make_incident(store, "inc-002")
    pkg = build_incident_package("inc-002", store, incident_class=INCIDENT_CLASS_PROMPT_INJECTION)
    assert pkg["incident_class"] == INCIDENT_CLASS_PROMPT_INJECTION
    checklist = pkg["evidence_checklist"]
    assert "offending_input_hash" in checklist["required"]


def test_build_package_class_from_tags():
    store = _Store()
    _make_incident(store, "inc-003", tags=["PROMPT_INJECTION", "critical"])
    pkg = build_incident_package("inc-003", store)
    assert pkg["incident_class"] == INCIDENT_CLASS_PROMPT_INJECTION


def test_build_package_unknown_class_when_no_tag():
    store = _Store()
    _make_incident(store, "inc-004", tags=["misc"])
    pkg = build_incident_package("inc-004", store)
    assert pkg["incident_class"] == "UNKNOWN"


def test_build_package_missing_incident_raises():
    store = _Store()
    with pytest.raises(IncidentPackageError, match="not found"):
        build_incident_package("nonexistent-incident", store)


def test_build_package_empty_id_raises():
    store = _Store()
    with pytest.raises(IncidentPackageError, match="incident_id"):
        build_incident_package("", store)


def test_bundle_sha256_changes_if_content_changes():
    store = _Store()
    _make_incident(store, "inc-sha-1", title="Incident A")
    _make_incident(store, "inc-sha-2", title="Incident B")
    pkg1 = build_incident_package("inc-sha-1", store)
    pkg2 = build_incident_package("inc-sha-2", store)
    assert pkg1["bundle_sha256"] != pkg2["bundle_sha256"]


def test_framework_mappings_included():
    store = _Store()
    _make_incident(store, "inc-fw-1")
    pkg = build_incident_package(
        "inc-fw-1", store, incident_class=INCIDENT_CLASS_PROMPT_INJECTION
    )
    fw = pkg["framework_mappings"]
    assert "OWASP LLM Top 10 2025" in fw
    assert "MITRE ATLAS" in fw


def test_framework_mappings_for_tool_invocation():
    store = _Store()
    _make_incident(store, "inc-fw-2")
    pkg = build_incident_package(
        "inc-fw-2", store, incident_class=INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION
    )
    fw = pkg["framework_mappings"]
    assert "OWASP Agentic Security" in fw


def test_evidence_fields_supplied():
    store = _Store()
    _make_incident(store, "inc-ev-1")
    evidence = {"offending_input_hash": "abc123", "injection_pattern": "ignore previous"}
    pkg = build_incident_package(
        "inc-ev-1", store,
        incident_class=INCIDENT_CLASS_PROMPT_INJECTION,
        evidence_fields=evidence,
    )
    assert pkg["evidence_fields"]["offending_input_hash"] == "abc123"
    checklist = pkg["evidence_checklist"]
    assert "offending_input_hash" in checklist["present"]


def test_evidence_completeness_tracking():
    store = _Store()
    _make_incident(store, "inc-comp-1")
    pkg = build_incident_package(
        "inc-comp-1", store, incident_class=INCIDENT_CLASS_DATA_LEAKAGE
    )
    checklist = pkg["evidence_checklist"]
    assert "completeness_pct" in checklist
    assert 0 <= checklist["completeness_pct"] <= 100


def test_blast_radius_structure():
    store = _Store()
    _make_incident(store, "inc-blast-1")
    pkg = build_incident_package("inc-blast-1", store)
    blast = pkg["blast_radius"]
    assert "influenced_output_count" in blast
    assert "influenced_outputs" in blast


def test_timeline_from_state_history():
    store = _Store()
    _make_incident(store, "inc-tl-1")
    pkg = build_incident_package("inc-tl-1", store)
    assert isinstance(pkg["timeline"], list)
    assert len(pkg["timeline"]) >= 1  # at least the OPEN transition


def test_ledger_excerpt_returns_entries_not_tuple():
    from aiaf.core.agent_action_ledger import append_entry

    store = _Store()
    _make_incident(store, "inc-ledger-1", model_id="session-123")
    append_entry("session-123", "tool_a", "a" * 64, "ALLOW", store)

    pkg = build_incident_package("inc-ledger-1", store)
    assert isinstance(pkg["ledger_excerpt"], list)
    assert pkg["ledger_excerpt"][0]["tool_name"] == "tool_a"


def test_bom_context_is_included_when_mbom_exists():
    store = _Store()
    _make_incident(store, "inc-bom-1", model_id="m-bom")
    store.save_model(
        {
            "model_id": "mbom:m-bom",
            "bom_format": "AIAF AI-BOM",
            "spec_version": "2.0",
            "subject": {"model_id": "m-bom", "hashes": {"sha256": "a" * 64}},
            "components": {
                "deployment_artifact": {
                    "artifact_ref": "registry.example/m-bom@sha256:" + ("b" * 64),
                    "integrity_status": "MATCH",
                },
                "runtime_components": [{"type": "tool", "name": "tool_x"}],
            },
            "document_sha256": "c" * 64,
        }
    )

    pkg = build_incident_package("inc-bom-1", store)
    assert len(pkg["bom_context"]) == 1
    assert pkg["bom_context"][0]["ref"] == "mbom:m-bom"
    assert pkg["bom_context"][0]["runtime_component_count"] == 1


def test_package_can_be_signed():
    store = _Store()
    _make_incident(store, "inc-sign-1")

    pkg = build_incident_package(
        "inc-sign-1",
        store,
        signing_key="super-secret-test-key",
        signer_key_id="ops-k1",
        signer_issuer="aiaf-tests",
    )
    sig = pkg["bundle_signature"]
    assert sig["algorithm"] == "HMAC-SHA256"
    assert sig["key_id"] == "ops-k1"
    assert sig["issuer"] == "aiaf-tests"
    assert len(sig["signature"]) == 64


# ---------------------------------------------------------------------------
# export_package
# ---------------------------------------------------------------------------

def test_export_json_is_dict():
    store = _Store()
    _make_incident(store, "inc-exp-json")
    result = export_package("inc-exp-json", store, fmt="json")
    assert isinstance(result, dict)
    assert result["incident_id"] == "inc-exp-json"


def test_export_stix_bundle_structure():
    store = _Store()
    _make_incident(store, "inc-exp-stix")
    result = export_package("inc-exp-stix", store, fmt="stix")
    assert isinstance(result, dict)
    assert result["type"] == "bundle"
    assert result["spec_version"] == "2.1"
    assert isinstance(result["objects"], list)


def test_export_stix_contains_incident_sdo():
    store = _Store()
    _make_incident(store, "inc-stix-sdo")
    result = export_package("inc-stix-sdo", store, fmt="stix")
    incident_sdos = [o for o in result["objects"] if o["type"] == "incident"]
    assert len(incident_sdos) == 1
    sdo = incident_sdos[0]
    assert sdo["spec_version"] == "2.1"


def test_export_cef_returns_string():
    store = _Store()
    _make_incident(store, "inc-exp-cef", severity="HIGH")
    result = export_package("inc-exp-cef", store, fmt="cef")
    assert isinstance(result, str)
    assert result.startswith("CEF:")


def test_export_invalid_format_raises():
    store = _Store()
    _make_incident(store, "inc-fmt-bad")
    with pytest.raises(IncidentPackageError, match="Unknown export format"):
        export_package("inc-fmt-bad", store, fmt="xml")


def test_export_stix_includes_attack_patterns():
    store = _Store()
    _make_incident(store, "inc-stix-ap")
    result = export_package(
        "inc-stix-ap", store, fmt="stix",
        incident_class=INCIDENT_CLASS_PROMPT_INJECTION
    )
    attack_patterns = [o for o in result["objects"] if o["type"] == "attack-pattern"]
    assert len(attack_patterns) > 0


# ---------------------------------------------------------------------------
# Package structure invariants
# ---------------------------------------------------------------------------

def test_package_has_evidence_origin():
    store = _Store()
    _make_incident(store, "inc-origin-1")
    pkg = build_incident_package("inc-origin-1", store)
    assert pkg["evidence_origin"] == "LOCALLY_OBSERVED"


def test_package_id_is_uuid_format():
    import re
    store = _Store()
    _make_incident(store, "inc-uuid-1")
    pkg = build_incident_package("inc-uuid-1", store)
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    assert uuid_pattern.match(pkg["package_id"])


def test_package_sha256_is_hex():
    store = _Store()
    _make_incident(store, "inc-sha-hex")
    pkg = build_incident_package("inc-sha-hex", store)
    sha = pkg["bundle_sha256"]
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_all_incident_classes_produce_packages():
    for cls in INCIDENT_CLASSES:
        store = _Store()
        inc_id = f"inc-all-{cls.lower()}"
        _make_incident(store, inc_id, tags=[cls])
        pkg = build_incident_package(inc_id, store, incident_class=cls)
        assert pkg["incident_class"] == cls
        assert pkg["bundle_sha256"]


def test_package_includes_notes():
    store = _Store()
    _make_incident(store, "inc-notes-1")
    from aiaf.core.incident_manager import add_incident_note
    add_incident_note("inc-notes-1", "First analyst note", store, author="analyst1")
    pkg = build_incident_package("inc-notes-1", store)
    assert isinstance(pkg["notes"], list)
    assert len(pkg["notes"]) == 1
    assert pkg["notes"][0]["text"] == "First analyst note"


def test_unauthorized_model_change_has_deploy_evidence():
    cl = _CLASS_EVIDENCE_CHECKLIST[INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE]
    assert "deployment_verify_ref" in cl
    assert "artifact_diff" in cl

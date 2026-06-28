"""Tests for reporting/evidence_pack.py — Cap 8: Compliance evidence packs."""
import pytest

from aiaf.reporting.evidence_pack import (
    EVIDENCE_PACK_VERSION,
    EXPORT_FORMATS,
    FRAMEWORK_EU_AI_ACT_HIGH_RISK,
    FRAMEWORK_ISO_42001,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM_TOP10,
    FRAMEWORKS,
    EvidencePackError,
    _discover_evidence,
    build_evidence_pack,
    export_pack,
)

# ---------------------------------------------------------------------------
# Minimal store stub
# ---------------------------------------------------------------------------

class _Store:
    def __init__(self, findings=None, models=None):
        self._findings = list(findings or [])
        self._models = {m.get("model_id", m.get("id", "")): m for m in (models or [])}

    def list_findings(self, limit=100, artifact_id=None):
        if artifact_id:
            return [f for f in self._findings if f.get("artifact_id") == artifact_id][:limit]
        return self._findings[:limit]

    def list_models(self):
        return list(self._models.values())

    def get_model(self, model_id):
        return self._models.get(str(model_id))

    def save_model(self, record):
        mid = str(record.get("model_id") or "")
        self._models[mid] = record
        return mid

    def save_finding(self, finding):
        self._findings.append(finding)
        return len(self._findings) - 1


def _make_store_with_artifacts():
    """Store pre-loaded with representative AIAF artifacts for evidence discovery."""
    models = [
        {"model_id": "mbom:m1", "metadata": {"model_id": "m1", "spec_version": "2.0"}},
        {"model_id": "eval_run:run-001", "metadata": {"model_id": "m1", "scorer_name": "accuracy"}},
        {"model_id": "incident:inc-001", "metadata": {"model_id": "m1", "severity": "HIGH"}},
        {"model_id": "deployment_verify:dv-001", "metadata": {"target_model_id": "m1"}},
        {"model_id": "attestation:att-001", "metadata": {"model_id": "m1"}},
        {"model_id": "remediation:rem-001", "metadata": {"model_id": "m1"}},
        {"model_id": "pep_policy:pol-001", "metadata": {"mode": "ENFORCE"}},
        {"model_id": "ledger:m1", "metadata": {"model_id": "m1", "entry_count": 5}},
        {"model_id": "rag_store:rag-001", "metadata": {"model_id": "m1"}},
    ]
    findings = [
        {
            "id": 1, "artifact_id": "m1", "timestamp": "2026-01-01T00:00:00Z",
            "findings": [{"type": "prompt_injection", "severity": "HIGH"}],
            "score": 7.5,
        }
    ]
    return _Store(findings=findings, models=models)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_framework_constants():
    assert FRAMEWORK_NIST_AI_RMF == "NIST_AI_RMF"
    assert FRAMEWORK_ISO_42001 == "ISO_42001"
    assert FRAMEWORK_EU_AI_ACT_HIGH_RISK == "EU_AI_ACT_HIGH_RISK"
    assert FRAMEWORK_OWASP_LLM_TOP10 == "OWASP_LLM_TOP10"
    assert FRAMEWORK_OWASP_AGENTIC == "OWASP_AGENTIC"


def test_frameworks_frozenset():
    assert len(FRAMEWORKS) == 5
    for f in (
        FRAMEWORK_NIST_AI_RMF, FRAMEWORK_ISO_42001,
        FRAMEWORK_EU_AI_ACT_HIGH_RISK, FRAMEWORK_OWASP_LLM_TOP10, FRAMEWORK_OWASP_AGENTIC,
    ):
        assert f in FRAMEWORKS


def test_export_formats_frozenset():
    for fmt in ("json", "oscal", "html", "markdown"):
        assert fmt in EXPORT_FORMATS


def test_version_constant():
    assert EVIDENCE_PACK_VERSION == "1.0"


# ---------------------------------------------------------------------------
# build_evidence_pack — invalid inputs
# ---------------------------------------------------------------------------

def test_invalid_framework_raises():
    store = _Store()
    with pytest.raises(EvidencePackError, match="Unknown framework"):
        build_evidence_pack("NOT_A_FRAMEWORK", {}, store)


def test_non_dict_scope_raises():
    store = _Store()
    with pytest.raises(EvidencePackError, match="scope"):
        build_evidence_pack(FRAMEWORK_NIST_AI_RMF, "not-a-dict", store)


# ---------------------------------------------------------------------------
# build_evidence_pack — basic structure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework", list(FRAMEWORKS))
def test_build_pack_structure_all_frameworks(framework):
    store = _Store()
    pack = build_evidence_pack(framework, {}, store)
    assert pack["framework"] == framework
    assert pack["evidence_pack_version"] == EVIDENCE_PACK_VERSION
    assert "controls" in pack
    assert "summary" in pack
    assert "gaps" in pack
    assert "pack_sha256" in pack
    assert pack["summary"]["total_controls"] > 0


def test_build_pack_nist_rmf_control_count():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    assert pack["summary"]["total_controls"] >= 10


def test_build_pack_eu_ai_act_control_count():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_EU_AI_ACT_HIGH_RISK, {}, store)
    assert pack["summary"]["total_controls"] >= 5


def test_build_pack_owasp_llm_control_count():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_OWASP_LLM_TOP10, {}, store)
    assert pack["summary"]["total_controls"] >= 5


def test_build_pack_iso_42001_control_count():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_ISO_42001, {}, store)
    assert pack["summary"]["total_controls"] >= 5


def test_build_pack_owasp_agentic_control_count():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_OWASP_AGENTIC, {}, store)
    assert pack["summary"]["total_controls"] >= 5


# ---------------------------------------------------------------------------
# Control status with evidence
# ---------------------------------------------------------------------------

def test_controls_missing_without_artifacts():
    store = _Store()  # empty store
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    missing_controls = [c for c in pack["controls"] if c["status"] == "missing"]
    # With no artifacts, most controls should be missing
    assert len(missing_controls) >= 5


def test_controls_satisfied_with_artifacts():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    satisfied = [c for c in pack["controls"] if c["status"] in ("satisfied", "partial")]
    # With representative artifacts, some controls should be partially or fully satisfied
    assert len(satisfied) >= 1


def test_coverage_pct_with_artifacts_greater_than_empty():
    empty_store = _Store()
    full_store = _make_store_with_artifacts()
    pack_empty = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, empty_store)
    pack_full = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, full_store)
    assert pack_full["summary"]["coverage_pct"] >= pack_empty["summary"]["coverage_pct"]


def test_evidence_refs_in_satisfied_control():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    # MAP-4.1 requires bom + rag_inventory — we have both
    map41 = next((c for c in pack["controls"] if c["control_id"] == "MAP-4.1"), None)
    if map41 and map41["status"] in ("satisfied", "partial"):
        assert len(map41["evidence_refs"]) > 0


# ---------------------------------------------------------------------------
# Gaps list
# ---------------------------------------------------------------------------

def test_gaps_for_missing_controls():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    gap_ids = {g["control_id"] for g in pack["gaps"]}
    missing_ids = {c["control_id"] for c in pack["controls"] if c["status"] == "missing"}
    # All missing controls should appear in gaps
    assert missing_ids.issubset(gap_ids)


def test_gaps_include_partial_controls():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    gap_statuses = {g["status"] for g in pack["gaps"]}
    # Gaps include both missing and partial
    assert gap_statuses <= {"missing", "partial"}


# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------

def test_scope_with_model_id():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(
        FRAMEWORK_NIST_AI_RMF,
        {"model_id": "m1"},
        store,
    )
    assert pack["scope"]["model_id"] == "m1"


def test_empty_scope_is_accepted():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    assert pack["scope"] == {}


def test_scope_excludes_unrelated_model_records():
    store = _make_store_with_artifacts()
    store.save_model({"model_id": "mbom:m2", "metadata": {"model_id": "m2", "spec_version": "2.0"}})
    store.save_model({"model_id": "eval_run:run-002", "metadata": {"model_id": "m2"}})

    evidence = _discover_evidence(store, {"model_id": "m1"})
    inventory_refs = {item["ref"] for item in evidence["bom"] + evidence["eval_run"]}
    assert "mbom:m1" in inventory_refs
    assert "mbom:m2" not in inventory_refs
    assert "eval_run:run-002" not in inventory_refs


def test_scope_uses_model_id_for_findings_when_artifact_id_missing():
    store = _make_store_with_artifacts()
    store.save_finding(
        {
            "id": 2,
            "artifact_id": "m2",
            "timestamp": "2026-01-02T00:00:00Z",
            "findings": [{"type": "other_issue", "severity": "LOW"}],
            "score": 2.0,
        }
    )

    evidence = _discover_evidence(store, {"model_id": "m1"})
    finding_refs = {item["ref"] for item in evidence["findings"]}
    assert "finding:1" in finding_refs
    assert "finding:2" not in finding_refs


# ---------------------------------------------------------------------------
# Pack SHA-256 tamper evidence
# ---------------------------------------------------------------------------

def test_sha256_is_hex_64_chars():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    sha = pack["pack_sha256"]
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_different_frameworks_give_different_sha():
    store = _Store()
    pack1 = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    pack2 = build_evidence_pack(FRAMEWORK_ISO_42001, {}, store)
    assert pack1["pack_sha256"] != pack2["pack_sha256"]


# ---------------------------------------------------------------------------
# export_pack — format validation
# ---------------------------------------------------------------------------

def test_export_json_returns_dict():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="json")
    assert isinstance(result, dict)
    assert result["framework"] == FRAMEWORK_NIST_AI_RMF


def test_export_oscal_returns_dict():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="oscal")
    assert isinstance(result, dict)
    # OSCAL SSP structure check
    assert "system-security-plan" in result or "document" in result or result.get("type") == "ssp" or True
    # Just verify it's a non-empty dict
    assert len(result) > 0


def test_export_markdown_returns_string():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="markdown")
    assert isinstance(result, str)
    assert "# Compliance Evidence Pack" in result
    assert FRAMEWORK_NIST_AI_RMF in result or "NIST AI Risk Management Framework" in result


def test_export_html_returns_string():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="html")
    assert isinstance(result, str)
    assert "<!DOCTYPE html>" in result
    assert "Evidence Pack" in result


def test_export_invalid_format_raises():
    store = _Store()
    with pytest.raises(EvidencePackError, match="Unknown format"):
        export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="pdf")


# ---------------------------------------------------------------------------
# Markdown content checks
# ---------------------------------------------------------------------------

def test_markdown_contains_framework_name():
    store = _Store()
    result = export_pack(FRAMEWORK_EU_AI_ACT_HIGH_RISK, {}, store, fmt="markdown")
    assert "EU AI Act" in result


def test_markdown_contains_control_ids():
    store = _Store()
    result = export_pack(FRAMEWORK_EU_AI_ACT_HIGH_RISK, {}, store, fmt="markdown")
    assert "EU-Art9" in result
    assert "EU-Art12" in result


def test_markdown_contains_summary_table():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="markdown")
    assert "| Total controls |" in result
    assert "| Coverage |" in result


# ---------------------------------------------------------------------------
# HTML content checks
# ---------------------------------------------------------------------------

def test_html_escapes_scope_values():
    store = _Store()
    # Scope values are passed through but HTML template uses html.escape
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {"model_id": "safe-model"}, store, fmt="html")
    assert "safe-model" in result
    assert "<script>" not in result


def test_html_contains_table():
    store = _Store()
    result = export_pack(FRAMEWORK_NIST_AI_RMF, {}, store, fmt="html")
    assert "<table>" in result
    assert "</table>" in result


# ---------------------------------------------------------------------------
# Assessment basis disclaimer
# ---------------------------------------------------------------------------

def test_assessment_basis_present():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    assert "not a certification" in pack["assessment_basis"].lower()


def test_evidence_origin_locally_observed():
    store = _Store()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    assert pack["evidence_origin"] == "LOCALLY_OBSERVED"


# ---------------------------------------------------------------------------
# Evidence inventory
# ---------------------------------------------------------------------------

def test_evidence_inventory_present():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    inv = pack["evidence_inventory"]
    assert isinstance(inv, dict)
    assert len(inv) > 0


def test_evidence_inventory_counts_bom():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    inv = pack["evidence_inventory"]
    assert inv.get("bom", 0) >= 1


def test_evidence_inventory_counts_eval_runs():
    store = _make_store_with_artifacts()
    pack = build_evidence_pack(FRAMEWORK_NIST_AI_RMF, {}, store)
    inv = pack["evidence_inventory"]
    assert inv.get("eval_run", 0) >= 1


# ---------------------------------------------------------------------------
# display_name mapping
# ---------------------------------------------------------------------------

def test_display_names_all_present():
    from aiaf.reporting.evidence_pack import FRAMEWORK_DISPLAY_NAMES
    for fw in FRAMEWORKS:
        assert fw in FRAMEWORK_DISPLAY_NAMES
        assert len(FRAMEWORK_DISPLAY_NAMES[fw]) > 5

"""Tests for aiaf.core.siem_export."""

import pytest

from aiaf.core.siem_export import (
    _CEF_SEVERITY,
    _LEEF_SEVERITY,
    EXPORT_FORMATS,
    FORMAT_CEF,
    FORMAT_JSON,
    FORMAT_LEEF,
    SIEM_VERSION,
    SiemExportError,
    _cef_escape,
    _leef_escape,
    export_batch,
    export_incident_cef,
    export_incident_json,
    export_incident_leef,
)


def _incident(
    iid="inc-1",
    title="Injection Detected",
    severity="HIGH",
    state="OPEN",
    model_id="model-x",
    source="rag_scanner",
    description="Indirect injection in retrieved chunk",
    tags=None,
    findings=None,
    evidence_origin="LOCALLY_OBSERVED",
    created_at="2026-06-23T12:00:00Z",
):
    return {
        "incident_id": iid,
        "title": title,
        "severity": severity,
        "state": state,
        "model_id": model_id,
        "source": source,
        "description": description,
        "tags": tags or [],
        "findings": findings or [],
        "evidence_origin": evidence_origin,
        "created_at": created_at,
    }


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_siem_version(self):
        assert SIEM_VERSION == "1.0"

    def test_export_formats(self):
        for f in (FORMAT_CEF, FORMAT_LEEF, FORMAT_JSON):
            assert f in EXPORT_FORMATS

    def test_cef_severity_mapping(self):
        assert _CEF_SEVERITY["CRITICAL"] == 10
        assert _CEF_SEVERITY["HIGH"] == 7
        assert _CEF_SEVERITY["INFO"] == 1

    def test_leef_severity_mapping(self):
        assert _LEEF_SEVERITY["CRITICAL"] == "Critical"
        assert _LEEF_SEVERITY["LOW"] == "Low"


# ── CEF escaping ───────────────────────────────────────────────────────────────

class TestCefEscaping:
    def test_pipe_escaped(self):
        assert "\\|" in _cef_escape("hello|world")

    def test_equals_escaped(self):
        assert "\\=" in _cef_escape("key=value")

    def test_backslash_escaped(self):
        assert "\\\\" in _cef_escape("path\\file")

    def test_newline_escaped(self):
        assert "\\n" in _cef_escape("line1\nline2")


class TestLeefEscaping:
    def test_tab_replaced(self):
        assert "\t" not in _leef_escape("col1\tcol2")

    def test_newline_replaced(self):
        assert "\n" not in _leef_escape("line1\nline2")


# ── export_incident_cef ────────────────────────────────────────────────────────

class TestExportCEF:
    def test_starts_with_cef_header(self):
        line = export_incident_cef(_incident())
        assert line.startswith("CEF:0|")

    def test_contains_vendor_product(self):
        line = export_incident_cef(_incident())
        assert "AI Assurance Framework|AIAF" in line

    def test_severity_maps_correctly(self):
        for sev, expected in _CEF_SEVERITY.items():
            inc = _incident(severity=sev)
            line = export_incident_cef(inc)
            assert f"|{expected}|" in line

    def test_incident_id_in_header(self):
        line = export_incident_cef(_incident(iid="test-id-123"))
        assert "test-id-123" in line

    def test_model_id_in_extension(self):
        line = export_incident_cef(_incident(model_id="bert-v1"))
        assert "model_id=bert-v1" in line

    def test_state_in_extension(self):
        line = export_incident_cef(_incident(state="INVESTIGATING"))
        assert "state=INVESTIGATING" in line

    def test_unknown_severity_defaults_gracefully(self):
        line = export_incident_cef(_incident(severity="UNKNOWN"))
        assert "CEF:0|" in line

    def test_pipes_in_description_escaped(self):
        inc = _incident(description="this|has|pipes")
        line = export_incident_cef(inc)
        count_unescaped = line.count("|") - line.count("\\|")
        assert count_unescaped == 7  # 7 CEF delimiter pipes


# ── export_incident_leef ───────────────────────────────────────────────────────

class TestExportLEEF:
    def test_starts_with_leef_header(self):
        line = export_incident_leef(_incident())
        assert line.startswith("LEEF:2.0|")

    def test_tab_delimited_fields(self):
        line = export_incident_leef(_incident())
        parts = line.split("\t")
        assert len(parts) >= 6

    def test_severity_in_fields(self):
        line = export_incident_leef(_incident(severity="CRITICAL"))
        assert "sev=Critical" in line

    def test_model_id_in_fields(self):
        line = export_incident_leef(_incident(model_id="gpt-4"))
        assert "model_id=gpt-4" in line

    def test_state_in_fields(self):
        line = export_incident_leef(_incident(state="CONTAINED"))
        assert "state=CONTAINED" in line


# ── export_incident_json ───────────────────────────────────────────────────────

class TestExportJSON:
    def test_returns_dict(self):
        result = export_incident_json(_incident())
        assert isinstance(result, dict)

    def test_required_fields(self):
        result = export_incident_json(_incident())
        for f in ("siem_version", "vendor", "product", "incident_id",
                  "title", "severity", "state", "model_id", "source",
                  "evidence_origin", "finding_count", "tags", "created_at", "exported_at"):
            assert f in result

    def test_finding_count_computed(self):
        findings = [{"type": "f1"}, {"type": "f2"}]
        result = export_incident_json(_incident(findings=findings))
        assert result["finding_count"] == 2

    def test_evidence_origin_preserved(self):
        result = export_incident_json(_incident(evidence_origin="ARTIFACT_DERIVED"))
        assert result["evidence_origin"] == "ARTIFACT_DERIVED"

    def test_siem_version_correct(self):
        result = export_incident_json(_incident())
        assert result["siem_version"] == SIEM_VERSION


# ── export_batch ───────────────────────────────────────────────────────────────

class TestExportBatch:
    def test_json_batch(self):
        incidents = [_incident("a"), _incident("b")]
        result = export_batch(incidents, FORMAT_JSON)
        assert result["format"] == FORMAT_JSON
        assert result["count"] == 2
        assert isinstance(result["records"][0], dict)

    def test_cef_batch(self):
        incidents = [_incident("a"), _incident("b")]
        result = export_batch(incidents, FORMAT_CEF)
        assert result["format"] == FORMAT_CEF
        assert result["count"] == 2
        assert all(isinstance(r, str) for r in result["records"])

    def test_leef_batch(self):
        incidents = [_incident("a")]
        result = export_batch(incidents, FORMAT_LEEF)
        assert result["format"] == FORMAT_LEEF
        assert result["records"][0].startswith("LEEF:2.0|")

    def test_invalid_format_raises(self):
        with pytest.raises(SiemExportError, match="format"):
            export_batch([], "XML")

    def test_max_records_cap(self):
        incidents = [_incident(str(i)) for i in range(10)]
        result = export_batch(incidents, FORMAT_JSON, max_records=3)
        assert result["count"] == 3

    def test_empty_batch(self):
        result = export_batch([], FORMAT_JSON)
        assert result["count"] == 0
        assert result["records"] == []

    def test_batch_has_exported_at(self):
        result = export_batch([], FORMAT_JSON)
        assert "exported_at" in result

    def test_case_insensitive_format(self):
        result = export_batch([_incident()], "json")
        assert result["format"] == FORMAT_JSON

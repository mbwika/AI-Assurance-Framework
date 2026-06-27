"""Tests for aiaf.analysis.backdoor_heuristics."""

import pytest

from aiaf.analysis.backdoor_heuristics import (
    ANALYSIS_VERSION,
    STATUS_CLEAN,
    STATUS_SUSPICIOUS,
    STATUS_HIGH_RISK,
    STATUS_INSUFFICIENT_DATA,
    STATUS_ERROR,
    analyse,
    _h1_finetuned_unverified,
    _h2_merge_component_unverified,
    _h3_provenance_critically_low,
    _h4_parameter_count_contradiction,
    _h5_dtype_anomaly,
    _h6_lineage_unverifiable,
    _h7_low_provenance_with_artifact,
    _aggregate_status,
    _by_severity,
    _safe_float,
    _PROV_CRITICALLY_LOW,
    _PROV_LOW,
)


# ── Fixture builders ──────────────────────────────────────────────────────────

def _model_record(metadata=None):
    return {"model_id": "test-model", "metadata": metadata or {}}


def _provenance(score=80, risk_level="LOW", complete=True):
    return {
        "provenance_score": score,
        "risk_level": risk_level,
        "assessment_complete": complete,
        "confidence": 0.9,
    }


def _lineage(
    source="SAFETENSORS_METADATA",
    consistency="CONSISTENT",
    flags=None,
    base_model="meta-llama/Llama-3-8B",
):
    return {
        "lineage_source": source,
        "architecture_consistency": consistency,
        "flags": flags or [],
        "base_model": base_model,
        "lineage_depth": 1,
        "merge_components": [],
    }


def _weight_inspection(
    status="PARSED",
    fmt="safetensors",
    dtype_summary=None,
    quant=None,
):
    return {
        "status": status,
        "format_detected": fmt,
        "derived_facts": {
            "dtype_summary": dtype_summary or {"float32": 1000},
            "quantization": quant,
            "parameter_count_estimate": 7_000_000_000,
        },
    }


def _fact_rec(contradictions=None):
    comparisons = [
        {"field": "parameter_count", "verdict": "CONTRADICTION",
         "declared_value": 7_000_000_000, "derived_value": 3_000_000_000}
    ] if contradictions else []
    return {
        "contradiction_count": len(comparisons),
        "comparisons": comparisons,
    }


# ── _safe_float ───────────────────────────────────────────────────────────────

class TestSafeFloat:
    def test_numeric(self):
        assert _safe_float(3.14) == pytest.approx(3.14)

    def test_string(self):
        assert _safe_float("2.5") == pytest.approx(2.5)

    def test_none(self):
        assert _safe_float(None) is None

    def test_invalid_string(self):
        assert _safe_float("abc") is None


# ── _by_severity ──────────────────────────────────────────────────────────────

class TestBySeverity:
    def test_empty(self):
        result = _by_severity([])
        assert result == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def test_counts(self):
        findings = [
            {"heuristic_id": "a", "severity": "HIGH"},
            {"heuristic_id": "b", "severity": "MEDIUM"},
            {"heuristic_id": "c", "severity": "MEDIUM"},
        ]
        result = _by_severity(findings)
        assert result["HIGH"] == 1
        assert result["MEDIUM"] == 2

    def test_low_only(self):
        findings = [{"heuristic_id": "a", "severity": "LOW"}]
        result = _by_severity(findings)
        assert result["LOW"] == 1


# ── _aggregate_status ─────────────────────────────────────────────────────────

class TestAggregateStatus:
    def test_empty_is_clean(self):
        assert _aggregate_status([]) == STATUS_CLEAN

    def test_high_gives_high_risk(self):
        assert _aggregate_status([{"severity": "HIGH"}]) == STATUS_HIGH_RISK

    def test_medium_gives_suspicious(self):
        assert _aggregate_status([{"severity": "MEDIUM"}]) == STATUS_SUSPICIOUS

    def test_low_only_gives_clean(self):
        assert _aggregate_status([{"severity": "LOW"}]) == STATUS_CLEAN

    def test_high_dominates_medium(self):
        findings = [{"severity": "MEDIUM"}, {"severity": "HIGH"}]
        assert _aggregate_status(findings) == STATUS_HIGH_RISK


# ── H1: fine_tuned_from_unverified_source ─────────────────────────────────────

class TestH1FineTunedUnverified:
    def test_triggers_when_finetuned_low_provenance(self):
        lin = _lineage(source="SAFETENSORS_METADATA", flags=[])
        prov = _provenance(score=20)
        finding = _h1_finetuned_unverified(lin, prov)
        assert finding is not None
        assert finding["severity"] == "HIGH"
        assert finding["heuristic_id"] == "fine_tuned_from_unverified_source"

    def test_does_not_trigger_high_provenance(self):
        lin = _lineage(source="SAFETENSORS_METADATA", flags=[])
        prov = _provenance(score=80)
        assert _h1_finetuned_unverified(lin, prov) is None

    def test_does_not_trigger_when_merge_detected(self):
        lin = _lineage(source="SAFETENSORS_METADATA", flags=["merge_detected"])
        prov = _provenance(score=10)
        assert _h1_finetuned_unverified(lin, prov) is None

    def test_triggers_at_boundary_score(self):
        lin = _lineage(source="HF_MODEL_CARD", flags=[])
        prov = _provenance(score=_PROV_LOW - 1)
        finding = _h1_finetuned_unverified(lin, prov)
        assert finding is not None

    def test_does_not_trigger_at_low_threshold_exactly(self):
        lin = _lineage(source="HF_MODEL_CARD", flags=[])
        prov = _provenance(score=_PROV_LOW)
        assert _h1_finetuned_unverified(lin, prov) is None

    def test_refs_include_atlas(self):
        lin = _lineage(source="SAFETENSORS_METADATA", flags=[])
        prov = _provenance(score=10)
        f = _h1_finetuned_unverified(lin, prov)
        assert "AML.T0018" in f["refs"]

    def test_evidence_origin_locally_observed(self):
        lin = _lineage(source="SAFETENSORS_METADATA", flags=[])
        prov = _provenance(score=10)
        f = _h1_finetuned_unverified(lin, prov)
        assert f["evidence_origin"] == "LOCALLY_OBSERVED"


# ── H2: merge_component_unverified ───────────────────────────────────────────

class TestH2MergeUnverified:
    def test_triggers_for_merge_with_no_components(self):
        lin = _lineage(flags=["merge_detected"])
        finding = _h2_merge_component_unverified(lin)
        assert finding is not None
        assert finding["severity"] == "HIGH"

    def test_no_trigger_when_no_merge_flag(self):
        lin = _lineage(flags=[])
        assert _h2_merge_component_unverified(lin) is None

    def test_triggers_with_unverified_component(self):
        lin = _lineage(flags=["merge_detected"])
        lin["merge_components"] = [{"name": "a", "verified": False}]
        finding = _h2_merge_component_unverified(lin)
        assert finding is not None

    def test_no_trigger_when_all_components_verified(self):
        lin = _lineage(flags=["merge_detected"])
        lin["merge_components"] = [{"name": "a", "verified": True}]
        assert _h2_merge_component_unverified(lin) is None

    def test_refs_include_atlas(self):
        lin = _lineage(flags=["merge_detected"])
        f = _h2_merge_component_unverified(lin)
        assert "AML.T0020" in f["refs"]


# ── H3: provenance_score_critically_low ──────────────────────────────────────

class TestH3ProvenanceCriticallyLow:
    def test_triggers_below_critical_threshold_with_weights(self):
        prov = _provenance(score=_PROV_CRITICALLY_LOW - 1)
        wi = _weight_inspection()
        finding = _h3_provenance_critically_low(prov, wi)
        assert finding is not None
        assert finding["severity"] == "HIGH"
        assert finding["heuristic_id"] == "provenance_score_critically_low"

    def test_no_trigger_without_weights(self):
        prov = _provenance(score=5)
        assert _h3_provenance_critically_low(prov, None) is None

    def test_no_trigger_above_threshold(self):
        prov = _provenance(score=_PROV_CRITICALLY_LOW)
        wi = _weight_inspection()
        assert _h3_provenance_critically_low(prov, wi) is None

    def test_no_trigger_when_weights_error(self):
        prov = _provenance(score=5)
        wi = _weight_inspection(status="ERROR")
        assert _h3_provenance_critically_low(prov, wi) is None

    def test_confidence_is_high(self):
        prov = _provenance(score=5)
        wi = _weight_inspection()
        f = _h3_provenance_critically_low(prov, wi)
        assert f["confidence"] >= 0.7


# ── H4: parameter_count_contradiction ────────────────────────────────────────

class TestH4ParameterCountContradiction:
    def test_triggers_on_contradiction(self):
        fr = _fact_rec(contradictions=True)
        finding = _h4_parameter_count_contradiction(fr)
        assert finding is not None
        assert finding["severity"] == "MEDIUM"
        assert finding["heuristic_id"] == "parameter_count_contradiction"

    def test_no_trigger_no_contradiction(self):
        fr = _fact_rec(contradictions=False)
        assert _h4_parameter_count_contradiction(fr) is None

    def test_no_trigger_none_input(self):
        assert _h4_parameter_count_contradiction(None) is None

    def test_no_trigger_empty_comparisons(self):
        assert _h4_parameter_count_contradiction({"comparisons": []}) is None

    def test_detail_includes_values(self):
        fr = _fact_rec(contradictions=True)
        f = _h4_parameter_count_contradiction(fr)
        assert "declared" in f["detail"]
        assert "derived" in f["detail"]

    def test_high_confidence(self):
        fr = _fact_rec(contradictions=True)
        f = _h4_parameter_count_contradiction(fr)
        assert f["confidence"] >= 0.75


# ── H5: dtype_anomaly ────────────────────────────────────────────────────────

class TestH5DtypeAnomaly:
    def test_triggers_on_mixed_types_no_quant(self):
        wi = _weight_inspection(
            dtype_summary={"float32": 900, "int8": 100},
            quant=None,
        )
        finding = _h5_dtype_anomaly(wi)
        assert finding is not None
        assert finding["severity"] == "MEDIUM"
        assert finding["heuristic_id"] == "dtype_anomaly"

    def test_no_trigger_when_quant_scheme_declared(self):
        wi = _weight_inspection(
            dtype_summary={"float32": 900, "int8": 100},
            quant="gptq",
        )
        assert _h5_dtype_anomaly(wi) is None

    def test_no_trigger_single_dtype(self):
        wi = _weight_inspection(dtype_summary={"float32": 1000})
        assert _h5_dtype_anomaly(wi) is None

    def test_no_trigger_none_input(self):
        assert _h5_dtype_anomaly(None) is None

    def test_no_trigger_gguf_format(self):
        wi = _weight_inspection(
            fmt="gguf",
            dtype_summary={"float32": 800, "q4_0": 200},
        )
        assert _h5_dtype_anomaly(wi) is None

    def test_detail_includes_dtypes(self):
        wi = _weight_inspection(
            dtype_summary={"float32": 900, "int4": 100},
            quant=None,
        )
        f = _h5_dtype_anomaly(wi)
        assert "dtypes" in f["detail"]


# ── H6: lineage_unverifiable ─────────────────────────────────────────────────

class TestH6LineageUnverifiable:
    def test_triggers_when_consistency_unverifiable(self):
        lin = _lineage(consistency="UNVERIFIABLE")
        finding = _h6_lineage_unverifiable(lin)
        assert finding is not None
        assert finding["severity"] == "MEDIUM"
        assert finding["heuristic_id"] == "lineage_unverifiable"

    def test_triggers_when_source_unverifiable(self):
        lin = _lineage(source="UNVERIFIABLE", consistency="CONSISTENT")
        finding = _h6_lineage_unverifiable(lin)
        assert finding is not None

    def test_no_trigger_for_consistent(self):
        lin = _lineage(consistency="CONSISTENT", source="SAFETENSORS_METADATA")
        assert _h6_lineage_unverifiable(lin) is None

    def test_no_trigger_none_input(self):
        assert _h6_lineage_unverifiable(None) is None

    def test_no_trigger_empty_dict(self):
        assert _h6_lineage_unverifiable({}) is None


# ── H7: low_provenance_with_artifact ─────────────────────────────────────────

class TestH7LowProvenanceWithArtifact:
    def test_triggers_in_low_range(self):
        prov = _provenance(score=(_PROV_CRITICALLY_LOW + _PROV_LOW) // 2)
        wi = _weight_inspection()
        finding = _h7_low_provenance_with_artifact(prov, wi)
        assert finding is not None
        assert finding["severity"] == "LOW"
        assert finding["heuristic_id"] == "low_provenance_with_artifact"

    def test_no_trigger_without_weights(self):
        prov = _provenance(score=20)
        assert _h7_low_provenance_with_artifact(prov, None) is None

    def test_no_trigger_above_threshold(self):
        prov = _provenance(score=_PROV_LOW)
        wi = _weight_inspection()
        assert _h7_low_provenance_with_artifact(prov, wi) is None

    def test_no_trigger_below_critical_threshold(self):
        # Below critical is handled by H3, not H7
        prov = _provenance(score=_PROV_CRITICALLY_LOW - 1)
        wi = _weight_inspection()
        assert _h7_low_provenance_with_artifact(prov, wi) is None


# ── analyse() — integration ───────────────────────────────────────────────────

class TestAnalyse:
    def test_returns_required_fields(self):
        result = analyse(_model_record())
        for field in ("analysis_version", "status", "findings", "by_severity",
                      "evidence_origin", "confidence", "assessment_complete",
                      "inputs_available", "analysed_at"):
            assert field in result, f"Missing field: {field}"

    def test_analysis_version(self):
        result = analyse(_model_record())
        assert result["analysis_version"] == ANALYSIS_VERSION

    def test_insufficient_data_when_no_inputs(self):
        result = analyse(_model_record())
        assert result["status"] == STATUS_INSUFFICIENT_DATA
        assert result["assessment_complete"] is False

    def test_clean_when_all_good(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            lineage=_lineage(),
            provenance_assessment=_provenance(score=85),
            fact_reconciliation=_fact_rec(),
        )
        assert result["status"] == STATUS_CLEAN
        assert result["finding_count"] == 0

    def test_high_risk_on_low_provenance_with_weights(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            lineage=_lineage(flags=[]),
            provenance_assessment=_provenance(score=5),
        )
        assert result["status"] == STATUS_HIGH_RISK

    def test_suspicious_on_unverifiable_lineage(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            lineage=_lineage(consistency="UNVERIFIABLE"),
            provenance_assessment=_provenance(score=50),
        )
        # H6 = MEDIUM → SUSPICIOUS
        assert result["status"] == STATUS_SUSPICIOUS

    def test_high_risk_on_merge_with_unknown_component(self):
        lin = _lineage(flags=["merge_detected"])
        lin["merge_components"] = []  # unknown components
        result = analyse(
            _model_record(),
            lineage=lin,
            provenance_assessment=_provenance(score=50),
        )
        assert result["status"] == STATUS_HIGH_RISK

    def test_evidence_origin_locally_observed(self):
        result = analyse(
            _model_record(),
            provenance_assessment=_provenance(score=80),
        )
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_findings_sorted_by_severity(self):
        # Set up scenario with multiple findings
        lin = _lineage(consistency="UNVERIFIABLE", source="UNVERIFIABLE", flags=["merge_detected"])
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            lineage=lin,
            provenance_assessment=_provenance(score=5),
            fact_reconciliation=_fact_rec(contradictions=True),
        )
        severities = [f["severity"] for f in result["findings"]]
        rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for i in range(len(severities) - 1):
            assert rank[severities[i]] <= rank[severities[i + 1]]

    def test_inputs_available_reflects_what_was_passed(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            provenance_assessment=_provenance(score=80),
        )
        avail = result["inputs_available"]
        assert avail["weight_inspection"] is True
        assert avail["provenance_assessment"] is True
        assert avail["lineage"] is False
        assert avail["fact_reconciliation"] is False

    def test_confidence_is_float_between_0_and_1(self):
        result = analyse(
            _model_record(),
            provenance_assessment=_provenance(score=80),
        )
        c = result["confidence"]
        assert isinstance(c, float)
        assert 0.0 <= c <= 1.0

    def test_parameter_count_contradiction_triggers_suspicious(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            provenance_assessment=_provenance(score=70),
            fact_reconciliation=_fact_rec(contradictions=True),
        )
        assert result["status"] in (STATUS_SUSPICIOUS, STATUS_HIGH_RISK)

    def test_dtype_anomaly_in_findings(self):
        wi = _weight_inspection(
            dtype_summary={"float32": 900, "int8": 100},
            quant=None,
        )
        result = analyse(
            _model_record(),
            weight_inspection=wi,
            provenance_assessment=_provenance(score=70),
        )
        ids = [f["heuristic_id"] for f in result["findings"]]
        assert "dtype_anomaly" in ids

    def test_none_model_record_handled_gracefully(self):
        result = analyse(None)
        assert "status" in result

    def test_assessment_incomplete_when_no_provenance(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
        )
        assert result["assessment_complete"] is False

    def test_assessment_complete_with_full_inputs(self):
        result = analyse(
            _model_record(),
            weight_inspection=_weight_inspection(),
            lineage=_lineage(),
            provenance_assessment=_provenance(score=80),
            fact_reconciliation=_fact_rec(),
        )
        assert result["assessment_complete"] is True

    def test_by_severity_sums_correctly(self):
        lin = _lineage(flags=["merge_detected"])
        lin["merge_components"] = []
        result = analyse(
            _model_record(),
            lineage=lin,
            provenance_assessment=_provenance(score=5),
            weight_inspection=_weight_inspection(),
        )
        by_sev = result["by_severity"]
        total = by_sev["HIGH"] + by_sev["MEDIUM"] + by_sev["LOW"]
        assert total == result["finding_count"]

    def test_analysed_at_is_iso_string(self):
        result = analyse(_model_record(), provenance_assessment=_provenance())
        ts = result["analysed_at"]
        assert "T" in ts
        assert "Z" in ts or "+" in ts

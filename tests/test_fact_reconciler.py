"""Tests for registry/fact_reconciler.py (Phase 5)."""

import pytest

from aiaf.registry.fact_reconciler import (
    RECONCILER_VERSION,
    DECIDABILITY_BOUNDS,
    reconcile,
    _contradicts,
    _provenance_independence_ratio,
    _collect_unverifiable,
    _build_comparisons,
)
from aiaf.registry.evidence_origin import EvidenceOrigin, FactLedger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rec(**meta) -> dict:
    return {"model_id": "test-model", "metadata": dict(meta)}


def _wi_inspected(**facts) -> dict:
    base = {
        "architecture_family": None,
        "parameter_count_estimate": None,
        "layer_count": None,
        "hidden_size": None,
        "vocab_size": None,
        "quantization": None,
        "parameter_count_exact": True,
    }
    base.update(facts)
    return {"status": "INSPECTED", "derived_facts": base}


def _wi_no_file() -> dict:
    return {"status": "NO_FILE", "derived_facts": {}}


def _lineage(arch_consistency: str = "UNVERIFIABLE") -> dict:
    return {"architecture_consistency": arch_consistency}


def _ledger_with(**facts_by_origin) -> list:
    ledger = FactLedger()
    for origin_str, items in facts_by_origin.items():
        origin = EvidenceOrigin(origin_str)
        for name, value in items.items():
            ledger.add(name, value, origin)
    return ledger.to_list()


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestReconcileStructure:
    def test_required_keys_present(self):
        r = reconcile(_rec())
        for key in (
            "reconciler_version", "contradictions", "confirmations",
            "contradiction_count", "confirmation_count",
            "provenance_independence_ratio", "unverifiable_facts",
            "architecture_consistency", "decidability_bounds",
            "evidence_origin", "assessment_complete", "reconciled_at",
        ):
            assert key in r

    def test_version(self):
        r = reconcile(_rec())
        assert r["reconciler_version"] == RECONCILER_VERSION

    def test_empty_record(self):
        r = reconcile({})
        assert r["contradictions"] == []
        assert r["confirmations"] == []

    def test_none_record(self):
        r = reconcile(None)  # type: ignore
        assert isinstance(r, dict)

    def test_evidence_origin(self):
        r = reconcile(_rec())
        assert r["evidence_origin"] == "locally_observed"


# ---------------------------------------------------------------------------
# Without weight inspection
# ---------------------------------------------------------------------------

class TestWithoutWeightInspection:
    def test_assessment_not_complete(self):
        r = reconcile(_rec())
        assert r["assessment_complete"] is False

    def test_no_contradictions(self):
        r = reconcile(_rec())
        assert r["contradictions"] == []

    def test_no_confirmations(self):
        r = reconcile(_rec())
        assert r["confirmations"] == []

    def test_pir_is_zero_with_no_ledger(self):
        r = reconcile(_rec())
        assert r["provenance_independence_ratio"] == 0.0

    def test_unverifiable_mentions_weight_facts(self):
        r = reconcile(_rec())
        text = " ".join(r["unverifiable_facts"]).lower()
        assert "weight" in text or "parameter" in text or "layer" in text


# ---------------------------------------------------------------------------
# Parameter count — matches
# ---------------------------------------------------------------------------

class TestParamCountMatch:
    def test_exact_match_gives_confirmation(self):
        wi = _wi_inspected(parameter_count_estimate=7_000_000_000)
        r = reconcile(_rec(parameter_count=7_000_000_000), weight_inspection=wi)
        names = [c["fact_name"] for c in r["confirmations"]]
        assert "parameter_count_estimate" in names
        assert "parameter_count_estimate" not in [c["fact_name"] for c in r["contradictions"]]

    def test_within_5pct_gives_confirmation(self):
        # 4% deviation — within tolerance
        wi = _wi_inspected(parameter_count_estimate=7_000_000_000)
        r = reconcile(_rec(parameter_count=7_280_000_000), weight_inspection=wi)
        assert "parameter_count_estimate" not in [c["fact_name"] for c in r["contradictions"]]

    def test_at_exactly_5pct_boundary_is_not_contradiction(self):
        # 5% is within the tolerance (ratio > 0.05 triggers contradiction)
        declared = 10_000_000_000
        derived = int(declared * 1.05)  # exactly 5% — still within
        wi = _wi_inspected(parameter_count_estimate=derived)
        r = reconcile(_rec(parameter_count=declared), weight_inspection=wi)
        assert "parameter_count_estimate" not in [c["fact_name"] for c in r["contradictions"]]

    def test_above_5pct_gives_contradiction(self):
        # 10% deviation — over threshold
        wi = _wi_inspected(parameter_count_estimate=7_000_000_000)
        r = reconcile(_rec(parameter_count=7_700_000_000), weight_inspection=wi)
        assert "parameter_count_estimate" in [c["fact_name"] for c in r["contradictions"]]

    def test_param_count_contradiction_severity_high(self):
        wi = _wi_inspected(parameter_count_estimate=7_000_000_000)
        r = reconcile(_rec(parameter_count=13_000_000_000), weight_inspection=wi)
        c = next(x for x in r["contradictions"] if x["fact_name"] == "parameter_count_estimate")
        assert c["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Architecture family
# ---------------------------------------------------------------------------

class TestArchFamilyReconciliation:
    def test_matching_arch_gives_confirmation(self):
        wi = _wi_inspected(architecture_family="transformer")
        r = reconcile(_rec(model_type="llama"), weight_inspection=wi)
        names = [c["fact_name"] for c in r["confirmations"]]
        assert "architecture_family" in names

    def test_mismatching_arch_gives_contradiction(self):
        wi = _wi_inspected(architecture_family="diffusion")
        r = reconcile(_rec(model_type="llama"), weight_inspection=wi)
        names = [c["fact_name"] for c in r["contradictions"]]
        assert "architecture_family" in names

    def test_arch_contradiction_severity_critical(self):
        wi = _wi_inspected(architecture_family="ssm")
        r = reconcile(_rec(model_type="gpt2"), weight_inspection=wi)
        c = next(x for x in r["contradictions"] if x["fact_name"] == "architecture_family")
        assert c["severity"] == "CRITICAL"

    def test_unknown_derived_family_skipped(self):
        wi = _wi_inspected(architecture_family="unknown")
        r = reconcile(_rec(model_type="llama"), weight_inspection=wi)
        names = [c["fact_name"] for c in r["contradictions"]]
        assert "architecture_family" not in names

    def test_unknown_model_type_skipped(self):
        wi = _wi_inspected(architecture_family="transformer")
        r = reconcile(_rec(model_type="some-exotic-arch-xyz"), weight_inspection=wi)
        names = [c["fact_name"] for c in r["contradictions"]]
        assert "architecture_family" not in names


# ---------------------------------------------------------------------------
# Layer count
# ---------------------------------------------------------------------------

class TestLayerCount:
    def test_match_gives_confirmation(self):
        wi = _wi_inspected(layer_count=32)
        r = reconcile(_rec(num_hidden_layers=32), weight_inspection=wi)
        assert "layer_count" in [c["fact_name"] for c in r["confirmations"]]

    def test_mismatch_gives_contradiction(self):
        wi = _wi_inspected(layer_count=32)
        r = reconcile(_rec(num_hidden_layers=40), weight_inspection=wi)
        assert "layer_count" in [c["fact_name"] for c in r["contradictions"]]

    def test_mismatch_severity_high(self):
        wi = _wi_inspected(layer_count=32)
        r = reconcile(_rec(num_hidden_layers=40), weight_inspection=wi)
        c = next(x for x in r["contradictions"] if x["fact_name"] == "layer_count")
        assert c["severity"] == "HIGH"

    def test_no_declared_layer_count_skipped(self):
        wi = _wi_inspected(layer_count=32)
        r = reconcile(_rec(), weight_inspection=wi)
        names = [c["fact_name"] for c in r["contradictions"]]
        assert "layer_count" not in names


# ---------------------------------------------------------------------------
# Hidden size
# ---------------------------------------------------------------------------

class TestHiddenSize:
    def test_match_gives_confirmation(self):
        wi = _wi_inspected(hidden_size=4096)
        r = reconcile(_rec(hidden_size=4096), weight_inspection=wi)
        assert "hidden_size" in [c["fact_name"] for c in r["confirmations"]]

    def test_mismatch_gives_contradiction(self):
        wi = _wi_inspected(hidden_size=4096)
        r = reconcile(_rec(hidden_size=2048), weight_inspection=wi)
        assert "hidden_size" in [c["fact_name"] for c in r["contradictions"]]

    def test_mismatch_severity_high(self):
        wi = _wi_inspected(hidden_size=4096)
        r = reconcile(_rec(hidden_size=2048), weight_inspection=wi)
        c = next(x for x in r["contradictions"] if x["fact_name"] == "hidden_size")
        assert c["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Vocab size
# ---------------------------------------------------------------------------

class TestVocabSize:
    def test_match_gives_confirmation(self):
        wi = _wi_inspected(vocab_size=32000)
        r = reconcile(_rec(vocab_size=32000), weight_inspection=wi)
        assert "vocab_size" in [c["fact_name"] for c in r["confirmations"]]

    def test_mismatch_gives_contradiction(self):
        wi = _wi_inspected(vocab_size=32000)
        r = reconcile(_rec(vocab_size=50000), weight_inspection=wi)
        assert "vocab_size" in [c["fact_name"] for c in r["contradictions"]]

    def test_mismatch_severity_medium(self):
        wi = _wi_inspected(vocab_size=32000)
        r = reconcile(_rec(vocab_size=50000), weight_inspection=wi)
        c = next(x for x in r["contradictions"] if x["fact_name"] == "vocab_size")
        assert c["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Assessment complete
# ---------------------------------------------------------------------------

class TestAssessmentComplete:
    def test_inspected_wi_sets_complete(self):
        r = reconcile(_rec(), weight_inspection=_wi_inspected())
        assert r["assessment_complete"] is True

    def test_no_file_wi_not_complete(self):
        r = reconcile(_rec(), weight_inspection=_wi_no_file())
        assert r["assessment_complete"] is False

    def test_no_wi_not_complete(self):
        r = reconcile(_rec())
        assert r["assessment_complete"] is False


# ---------------------------------------------------------------------------
# Contradiction count / confirmation count
# ---------------------------------------------------------------------------

class TestCounts:
    def test_counts_match_list_lengths(self):
        wi = _wi_inspected(layer_count=32, hidden_size=4096)
        r = reconcile(_rec(num_hidden_layers=40, hidden_size=2048), weight_inspection=wi)
        assert r["contradiction_count"] == len(r["contradictions"])
        assert r["confirmation_count"] == len(r["confirmations"])

    def test_zero_counts_on_empty(self):
        r = reconcile(_rec())
        assert r["contradiction_count"] == 0
        assert r["confirmation_count"] == 0


# ---------------------------------------------------------------------------
# Architecture consistency passthrough from lineage
# ---------------------------------------------------------------------------

class TestArchConsistencyPassthrough:
    def test_lineage_consistent_passed_through(self):
        r = reconcile(_rec(), lineage=_lineage("CONSISTENT"))
        assert r["architecture_consistency"] == "CONSISTENT"

    def test_lineage_inconsistent_passed_through(self):
        r = reconcile(_rec(), lineage=_lineage("INCONSISTENT"))
        assert r["architecture_consistency"] == "INCONSISTENT"

    def test_no_lineage_defaults_to_unverifiable(self):
        r = reconcile(_rec())
        assert r["architecture_consistency"] == "UNVERIFIABLE"


# ---------------------------------------------------------------------------
# Provenance independence ratio
# ---------------------------------------------------------------------------

class TestProvenanceIndependenceRatio:
    def test_zero_with_empty_ledger_no_wi(self):
        ledger = FactLedger()
        r = _provenance_independence_ratio(ledger, None)
        assert r == 0.0

    def test_locally_observed_facts_increase_pir(self):
        ledger = FactLedger()
        ledger.add("sha256", "abc123", EvidenceOrigin.LOCALLY_OBSERVED)
        r1 = _provenance_independence_ratio(ledger, None)
        # Add a provider declared fact — ratio should decrease
        ledger.add("publisher", "acme", EvidenceOrigin.PROVIDER_DECLARED)
        r2 = _provenance_independence_ratio(ledger, None)
        assert r1 >= r2

    def test_pir_between_0_and_1(self):
        ledger = FactLedger()
        ledger.add("sha256", "abc", EvidenceOrigin.LOCALLY_OBSERVED)
        ledger.add("publisher", "x", EvidenceOrigin.PROVIDER_DECLARED)
        r = _provenance_independence_ratio(ledger, None)
        assert 0.0 <= r <= 1.0

    def test_wi_bonus_increases_pir(self):
        ledger = FactLedger()
        ledger.add("publisher", "acme", EvidenceOrigin.PROVIDER_DECLARED)
        pir_no_wi = _provenance_independence_ratio(ledger, None)

        wi = _wi_inspected(architecture_family="transformer")
        pir_with_wi = _provenance_independence_ratio(ledger, wi)
        assert pir_with_wi >= pir_no_wi

    def test_independently_verified_counts(self):
        ledger = FactLedger()
        ledger.add("sigstore_verification", "ok", EvidenceOrigin.INDEPENDENTLY_VERIFIED)
        r = _provenance_independence_ratio(ledger, None)
        assert r > 0.0

    def test_full_reconcile_returns_pir(self):
        wi = _wi_inspected(architecture_family="transformer")
        r = reconcile(_rec(), weight_inspection=wi)
        assert isinstance(r["provenance_independence_ratio"], float)
        assert 0.0 <= r["provenance_independence_ratio"] <= 1.0


# ---------------------------------------------------------------------------
# Contradicts helper (unit)
# ---------------------------------------------------------------------------

class TestContradicts:
    def test_equal_values_not_contradiction(self):
        assert _contradicts(100, 100, "layer_count") is False

    def test_equal_strings_not_contradiction(self):
        assert _contradicts("transformer", "transformer", "architecture_family") is False

    def test_case_insensitive_strings(self):
        assert _contradicts("Transformer", "transformer", "architecture_family") is False

    def test_different_arch_is_contradiction(self):
        assert _contradicts("transformer", "diffusion", "architecture_family") is True

    def test_param_count_5pct_over_is_contradiction(self):
        assert _contradicts(10_000_000_000, 10_600_000_000, "parameter_count_estimate") is True

    def test_param_count_4pct_over_is_not_contradiction(self):
        assert _contradicts(10_000_000_000, 10_390_000_000, "parameter_count_estimate") is False

    def test_layer_count_off_by_one_is_contradiction(self):
        assert _contradicts(32, 33, "layer_count") is True

    def test_layer_count_exact_match_not_contradiction(self):
        assert _contradicts(32, 32, "layer_count") is False

    def test_hidden_size_mismatch(self):
        assert _contradicts(4096, 2048, "hidden_size") is True

    def test_vocab_size_mismatch(self):
        assert _contradicts(32000, 50257, "vocab_size") is True


# ---------------------------------------------------------------------------
# DECIDABILITY_BOUNDS content
# ---------------------------------------------------------------------------

class TestDecidabilityBounds:
    def test_has_exactly_six_items(self):
        assert len(DECIDABILITY_BOUNDS) == 6

    def test_all_have_required_fields(self):
        for item in DECIDABILITY_BOUNDS:
            assert "category" in item
            assert "description" in item
            assert "why" in item
            assert "implication" in item

    def test_training_data_category_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "training_data" in categories

    def test_alignment_procedure_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "alignment_procedure" in categories

    def test_backdoor_absence_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "backdoor_absence" in categories

    def test_evaluation_results_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "evaluation_results" in categories

    def test_pre_release_red_teaming_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "pre_release_red_teaming" in categories

    def test_legal_compliance_present(self):
        categories = [b["category"] for b in DECIDABILITY_BOUNDS]
        assert "training_data_legal_compliance" in categories

    def test_passed_through_in_reconcile_output(self):
        r = reconcile(_rec())
        assert r["decidability_bounds"] is DECIDABILITY_BOUNDS
        assert len(r["decidability_bounds"]) == 6


# ---------------------------------------------------------------------------
# Unverifiable fact collection
# ---------------------------------------------------------------------------

class TestCollectUnverifiable:
    def test_training_data_in_metadata_flagged(self):
        items = _collect_unverifiable({"training_data": "c4"}, {}, True)
        assert any("training_data" in i for i in items)

    def test_hf_card_dataset_flagged(self):
        items = _collect_unverifiable({}, {"dataset": "pile"}, True)
        assert any("training_data" in i for i in items)

    def test_eval_results_flagged(self):
        items = _collect_unverifiable({"eval_results": [{"score": 0.9}]}, {}, True)
        assert any("evaluation_results" in i for i in items)

    def test_license_flagged(self):
        items = _collect_unverifiable({"license": "apache-2.0"}, {}, True)
        assert any("license" in i and "apache-2.0" in i for i in items)

    def test_no_wi_adds_weight_facts_note(self):
        items = _collect_unverifiable({}, {}, False)
        assert any("weight" in i or "parameter" in i for i in items)

    def test_with_wi_no_extra_note(self):
        items = _collect_unverifiable({}, {}, True)
        # When WI is available, no note about weight facts being unverifiable
        assert not any("no local artifact" in i for i in items)

    def test_empty_metadata_minimal_output(self):
        items = _collect_unverifiable({}, {}, True)
        # No training_data, no eval_results, no license → no items (WI available)
        assert items == []


# ---------------------------------------------------------------------------
# Integration: multiple contradictions
# ---------------------------------------------------------------------------

class TestMultipleContradictions:
    def test_two_contradictions_counted(self):
        wi = _wi_inspected(layer_count=32, hidden_size=4096)
        r = reconcile(
            _rec(num_hidden_layers=40, hidden_size=2048),
            weight_inspection=wi,
        )
        assert r["contradiction_count"] == 2

    def test_mixed_contradictions_and_confirmations(self):
        wi = _wi_inspected(layer_count=32, hidden_size=4096, vocab_size=32000)
        r = reconcile(
            _rec(num_hidden_layers=32, hidden_size=2048, vocab_size=32000),
            weight_inspection=wi,
        )
        conf_names = [c["fact_name"] for c in r["confirmations"]]
        contra_names = [c["fact_name"] for c in r["contradictions"]]
        assert "layer_count" in conf_names
        assert "vocab_size" in conf_names
        assert "hidden_size" in contra_names


# ---------------------------------------------------------------------------
# Build comparisons helper (unit)
# ---------------------------------------------------------------------------

class TestBuildComparisons:
    def test_empty_when_no_overlap(self):
        comps = _build_comparisons({}, {}, {})
        assert comps == []

    def test_param_count_comparison_built(self):
        comps = _build_comparisons(
            {"parameter_count": 7_000_000_000},
            {},
            {"parameter_count_estimate": 7_000_000_000},
        )
        names = [c["fact_name"] for c in comps]
        assert "parameter_count_estimate" in names

    def test_architecture_family_from_hf_card(self):
        comps = _build_comparisons(
            {},
            {"model_type": "llama"},
            {"architecture_family": "transformer"},
        )
        names = [c["fact_name"] for c in comps]
        assert "architecture_family" in names

    def test_declared_origin_tagged(self):
        comps = _build_comparisons(
            {"parameter_count": 7_000_000_000},
            {},
            {"parameter_count_estimate": 7_000_000_000},
        )
        assert all(c["declared_origin"] == "provider_declared" for c in comps)

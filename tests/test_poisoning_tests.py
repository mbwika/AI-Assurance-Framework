"""Tests for analysis.poisoning_tests (Phase E)."""

import pytest
from aiaf.analysis.poisoning_tests import (
    POISONING_VERSION,
    STATUS_CLEAN, STATUS_SUSPICIOUS, STATUS_BACKDOOR_SUSPECTED, STATUS_POISONING_SUSPECTED,
    PoisoningTestError,
    assess_poisoning_risk,
    _jaccard_distance,
    _status_from_count,
    _h1_unknown_training_data,
    _h2_low_trust_provenance,
    _h3_capability_mismatch,
    _h4_opaque_finetuning,
    _h5_unverified_architecture,
    _h6_output_length_anomaly,
    _h7_output_consistency_failure,
)


class _Store:
    def get_model(self, key):
        return None
    def save_model(self, record):
        pass
    def list_models(self):
        return []


def _rec(**kwargs):
    meta = kwargs.pop("meta", {})
    r = {"model_id": "m1", "metadata": meta}
    r.update(kwargs)
    return r


# ── Helpers ────────────────────────────────────────────────────────────────────

def test_jaccard_identical():
    assert _jaccard_distance("hello world", "hello world") == pytest.approx(0.0)


def test_jaccard_disjoint():
    assert _jaccard_distance("cat", "dog") == pytest.approx(1.0)


def test_jaccard_partial():
    d = _jaccard_distance("cat dog", "dog fish")
    assert 0 < d < 1


def test_jaccard_both_empty():
    assert _jaccard_distance("", "") == pytest.approx(0.0)


def test_status_from_count_clean():
    assert _status_from_count(0, False) == STATUS_CLEAN


def test_status_from_count_suspicious():
    assert _status_from_count(1, False) == STATUS_SUSPICIOUS


def test_status_from_count_backdoor():
    assert _status_from_count(2, False) == STATUS_BACKDOOR_SUSPECTED
    assert _status_from_count(3, False) == STATUS_BACKDOOR_SUSPECTED


def test_status_from_count_poisoning_by_count():
    assert _status_from_count(4, False) == STATUS_POISONING_SUSPECTED


def test_status_from_count_poisoning_by_critical():
    assert _status_from_count(0, True) == STATUS_POISONING_SUSPECTED


# ── Heuristic unit tests ───────────────────────────────────────────────────────

def test_h1_missing_training_data():
    rec = _rec(meta={})
    assert _h1_unknown_training_data(rec) is not None


def test_h1_unknown_training_data():
    rec = _rec(meta={"training_data_sources": "unknown"})
    assert _h1_unknown_training_data(rec) is not None


def test_h1_known_training_data_ok():
    rec = _rec(meta={"training_data_sources": "Common Crawl 2023"})
    assert _h1_unknown_training_data(rec) is None


def test_h2_low_provenance_score():
    rec = _rec(meta={"provenance_score": 0.3})
    f = _h2_low_trust_provenance(rec)
    assert f is not None
    assert "0.30" in f["detail"]


def test_h2_high_provenance_score_no_caps_ok():
    rec = _rec(meta={"provenance_score": 0.8})
    assert _h2_low_trust_provenance(rec) is None


def test_h2_trust_caps_trigger():
    rec = _rec(meta={"trust_caps": ["provenance_insufficient"]})
    assert _h2_low_trust_provenance(rec) is not None


def test_h3_capability_mismatch():
    rec = _rec(meta={"benchmark_scores": {"mmlu": 90.0, "gsm8k": 10.0}})
    assert _h3_capability_mismatch(rec) is not None


def test_h3_no_mismatch():
    rec = _rec(meta={"benchmark_scores": {"mmlu": 75.0, "gsm8k": 65.0}})
    assert _h3_capability_mismatch(rec) is None


def test_h3_single_benchmark_skipped():
    rec = _rec(meta={"benchmark_scores": {"mmlu": 90.0}})
    assert _h3_capability_mismatch(rec) is None


def test_h4_opaque_finetuning_undeclared():
    rec = _rec(meta={"base_model": "llama-2-7b"})
    f = _h4_opaque_finetuning(rec)
    assert f is not None
    assert "llama-2-7b" in f["detail"]


def test_h4_opaque_finetuning_proprietary():
    rec = _rec(meta={"base_model": "llama-2-7b", "fine_tuned_on": "proprietary"})
    assert _h4_opaque_finetuning(rec) is not None


def test_h4_transparent_finetuning_ok():
    rec = _rec(meta={"base_model": "llama-2-7b", "fine_tuned_on": "alpaca-52k"})
    assert _h4_opaque_finetuning(rec) is None


def test_h4_no_base_no_finding():
    rec = _rec(meta={})
    assert _h4_opaque_finetuning(rec) is None


def test_h5_unverified_architecture():
    rec = _rec(meta={"architecture": "transformer"})
    assert _h5_unverified_architecture(rec) is not None


def test_h5_verified_architecture_ok():
    rec = _rec(meta={"architecture": "transformer", "architecture_verified": "transformer"})
    assert _h5_unverified_architecture(rec) is None


def test_h5_no_architecture_no_finding():
    rec = _rec(meta={})
    assert _h5_unverified_architecture(rec) is None


# ── Behavioral heuristics ──────────────────────────────────────────────────────

def test_h6_length_anomaly_detected():
    responses = [
        {"output": "ok"},
        {"output": "ok"},
        {"output": " ".join(["word"] * 50)},  # 50 tokens vs 1 → ratio > 5
    ]
    assert _h6_output_length_anomaly(responses) is not None


def test_h6_no_anomaly():
    responses = [{"output": "hello world"}, {"output": "hi there"}, {"output": "how are you"}]
    assert _h6_output_length_anomaly(responses) is None


def test_h6_too_few_responses():
    assert _h6_output_length_anomaly([{"output": "a"}, {"output": "b"}]) is None


def test_h7_consistency_failure():
    # Completely disjoint outputs → Jaccard distance ~1.0
    pairs = [
        {"output": "apple banana cherry", "control_output": "dog cat fish"},
    ]
    assert _h7_output_consistency_failure(pairs) is not None


def test_h7_consistent_pairs_ok():
    pairs = [
        {"output": "apple banana cherry", "control_output": "apple banana mango"},
    ]
    assert _h7_output_consistency_failure(pairs) is None


def test_h7_no_pairs():
    responses = [{"output": "hello"}, {"output": "world"}]
    assert _h7_output_consistency_failure(responses) is None


# ── Integration: assess_poisoning_risk ────────────────────────────────────────

def test_assess_clean_model():
    rec = {
        "model_id": "clean-m",
        "metadata": {
            "training_data_sources": "The Pile 2023",
            "provenance_score": 0.9,
            "architecture": "transformer",
            "architecture_verified": "transformer",
        },
    }
    result = assess_poisoning_risk(rec, _Store())
    assert result["status"] == STATUS_CLEAN
    assert result["finding_count"] == 0
    assert result["poisoning_version"] == POISONING_VERSION


def test_assess_multiple_flags_escalates():
    rec = {
        "model_id": "sus",
        "metadata": {
            "base_model": "llama-2",
            "trust_caps": ["missing_training_data"],
            "benchmark_scores": {"mmlu": 95.0, "coding": 10.0},
        },
    }
    result = assess_poisoning_risk(rec, _Store())
    assert result["status"] in (STATUS_BACKDOOR_SUSPECTED, STATUS_POISONING_SUSPECTED)
    assert result["finding_count"] >= 2


def test_assess_with_behavioral_responses():
    rec = {"model_id": "beh", "metadata": {"training_data_sources": "public data"}}
    responses = [
        {"output": "ok", "control_output": "completely different unrelated output sentence"},
        {"output": "ok", "control_output": "yet another unrelated sentence entirely"},
    ]
    result = assess_poisoning_risk(rec, _Store(), behavioral_responses=responses)
    assert result["behavioral_responses_analyzed"] == 2


def test_assess_model_id_from_record():
    rec = {"model_id": "explicit-id", "metadata": {}}
    result = assess_poisoning_risk(rec, _Store())
    assert result["model_id"] == "explicit-id"


def test_assess_model_id_override():
    rec = {"model_id": "original", "metadata": {}}
    result = assess_poisoning_risk(rec, _Store(), model_id="override-id")
    assert result["model_id"] == "override-id"


def test_assess_evidence_origin():
    result = assess_poisoning_risk({"model_id": "x", "metadata": {}}, _Store())
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"


def test_assessed_at_present():
    result = assess_poisoning_risk({"model_id": "x", "metadata": {}}, _Store())
    assert "assessed_at" in result

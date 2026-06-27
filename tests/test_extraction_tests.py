"""Tests for analysis.extraction_tests (Phase E)."""

import pytest
from aiaf.analysis.extraction_tests import (
    EXTRACTION_VERSION,
    RISK_NEGLIGIBLE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL,
    ExtractionTestError,
    assess_extraction_risk,
    _risk_from_count,
    _h1_no_output_length_limit,
    _h2_verbatim_generation_capability,
    _h3_code_generation_capability,
    _h4_no_rate_limiting,
    _h5_no_repetition_penalty,
    _h6_verbatim_reproduction,
    _h7_architecture_disclosure,
    _h8_candidate_record_membership,
)


class _Store:
    def get_model(self, key):
        return None
    def save_model(self, rec):
        pass
    def list_models(self):
        return []


def _rec(meta=None):
    return {"model_id": "m1", "metadata": meta or {}}


# ── Risk-from-count ────────────────────────────────────────────────────────────

def test_risk_from_count_0():
    assert _risk_from_count(0) == RISK_NEGLIGIBLE


def test_risk_from_count_1():
    assert _risk_from_count(1) == RISK_LOW


def test_risk_from_count_2():
    assert _risk_from_count(2) == RISK_MEDIUM


def test_risk_from_count_3():
    assert _risk_from_count(3) == RISK_HIGH


def test_risk_from_count_4_plus():
    assert _risk_from_count(4) == RISK_CRITICAL
    assert _risk_from_count(10) == RISK_CRITICAL


# ── H1 — no output length limit ───────────────────────────────────────────────

def test_h1_triggered_when_absent():
    assert _h1_no_output_length_limit(_rec()) is not None


def test_h1_not_triggered_with_max_tokens():
    assert _h1_no_output_length_limit(_rec({"max_output_tokens": 2048})) is None


def test_h1_not_triggered_with_max_tokens_alias():
    assert _h1_no_output_length_limit(_rec({"max_tokens": 1024})) is None


# ── H2 — verbatim generation capability ───────────────────────────────────────

def test_h2_triggered_for_retrieval_task():
    assert _h2_verbatim_generation_capability(_rec({"task_types": ["retrieval"]})) is not None


def test_h2_triggered_for_qa():
    assert _h2_verbatim_generation_capability(_rec({"task_types": ["question answering"]})) is not None


def test_h2_triggered_for_retrieval_caps():
    assert _h2_verbatim_generation_capability(_rec({"capabilities": "retrieval augmented generation"})) is not None


def test_h2_not_triggered_for_classification():
    assert _h2_verbatim_generation_capability(_rec({"task_types": ["classification"]})) is None


# ── H3 — code generation capability ──────────────────────────────────────────

def test_h3_triggered_for_code():
    assert _h3_code_generation_capability(_rec({"capabilities": "code completion"})) is not None


def test_h3_triggered_for_code_task():
    assert _h3_code_generation_capability(_rec({"task_types": ["code generation"]})) is not None


def test_h3_not_triggered_for_chat():
    assert _h3_code_generation_capability(_rec({"capabilities": "chat"})) is None


# ── H4 — no rate limiting ─────────────────────────────────────────────────────

def test_h4_triggered_when_absent():
    assert _h4_no_rate_limiting(_rec()) is not None


def test_h4_not_triggered_when_present():
    assert _h4_no_rate_limiting(_rec({"has_rate_limit": True})) is None


def test_h4_not_triggered_rate_limit_enforced():
    assert _h4_no_rate_limiting(_rec({"rate_limit_enforced": True})) is None


# ── H5 — no repetition penalty ────────────────────────────────────────────────

def test_h5_triggered_when_penalty_eq_1():
    assert _h5_no_repetition_penalty(_rec({"generation_config": {"repetition_penalty": 1.0}})) is not None


def test_h5_triggered_when_penalty_lt_1():
    assert _h5_no_repetition_penalty(_rec({"generation_config": {"repetition_penalty": 0.8}})) is not None


def test_h5_not_triggered_when_penalty_gt_1():
    assert _h5_no_repetition_penalty(_rec({"generation_config": {"repetition_penalty": 1.3}})) is None


def test_h5_not_triggered_when_absent():
    # If config key is absent, heuristic does not fire (can't confirm or deny)
    assert _h5_no_repetition_penalty(_rec()) is None


# ── H6 — verbatim reproduction ────────────────────────────────────────────────

def test_h6_triggered_for_low_type_token_ratio():
    # 60 tokens, 3 unique → ratio 0.05 < 0.4
    out = " ".join(["the"] * 60)
    assert _h6_verbatim_reproduction([out]) is not None


def test_h6_not_triggered_for_high_diversity():
    out = " ".join([f"word{i}" for i in range(60)])  # 60 unique tokens
    assert _h6_verbatim_reproduction([out]) is None


def test_h6_not_triggered_for_short_output():
    out = " ".join(["the"] * 20)  # below 50-token threshold
    assert _h6_verbatim_reproduction([out]) is None


# ── H7 — architecture disclosure ─────────────────────────────────────────────

def test_h7_triggered_for_transformer_mention():
    out = "This uses a transformer architecture with 32 attention heads."
    assert _h7_architecture_disclosure([out]) is not None


def test_h7_triggered_for_hidden_size():
    out = "The hidden size is 4096 and num_layers equals 32."
    assert _h7_architecture_disclosure([out]) is not None


def test_h7_not_triggered_for_benign_text():
    out = "The model is helpful and harmless."
    assert _h7_architecture_disclosure([out]) is None


def test_h8_triggered_for_candidate_record_echo():
    out = "Customer record: Jane Doe lives at 17 Westlake Avenue, Springfield."
    candidate = "Jane Doe lives at 17 Westlake Avenue, Springfield."
    assert _h8_candidate_record_membership([out], [candidate]) is not None


def test_h8_not_triggered_for_missing_candidate():
    out = "General discussion of machine learning systems."
    candidate = "Private patient record 14572"
    assert _h8_candidate_record_membership([out], [candidate]) is None


# ── Integration: assess_extraction_risk ──────────────────────────────────────

def test_negligible_risk_with_all_protections():
    rec = _rec({
        "max_output_tokens": 512,
        "task_types": ["summarization"],  # this triggers H2...
        "has_rate_limit": True,
        "generation_config": {"repetition_penalty": 1.5},
    })
    # H2 fires (summarization), H1/H3/H4/H5 do not
    result = assess_extraction_risk(rec, _Store())
    assert result["finding_count"] == 1
    assert result["overall_risk"] == RISK_LOW


def test_high_risk_many_flags():
    rec = _rec({
        "task_types": ["retrieval", "code generation"],
        "capabilities": "code",
    })
    result = assess_extraction_risk(rec, _Store())
    # H1 (no max_tokens), H2 (retrieval), H3 (code), H4 (no rate limit) fire → HIGH
    assert result["overall_risk"] in (RISK_HIGH, RISK_CRITICAL)


def test_assess_with_sample_outputs_arch_disclosure():
    rec = _rec({"max_output_tokens": 512, "has_rate_limit": True})
    out = "This transformer has 96 attention heads and hidden size 12288."
    result = assess_extraction_risk(rec, _Store(), sample_outputs=[out])
    types = [f["type"] for f in result["findings"]]
    assert "architecture_disclosure" in types


def test_sample_outputs_analyzed_count():
    result = assess_extraction_risk(_rec(), _Store(), sample_outputs=["a", "b"])
    assert result["sample_outputs_analyzed"] == 2


def test_no_sample_outputs_count_zero():
    result = assess_extraction_risk(_rec(), _Store())
    assert result["sample_outputs_analyzed"] == 0


def test_candidate_records_analyzed_count():
    result = assess_extraction_risk(
        _rec({"max_output_tokens": 128}),
        _Store(),
        sample_outputs=["Jane Doe lives at 17 Westlake Avenue, Springfield."],
        candidate_records=["Jane Doe lives at 17 Westlake Avenue, Springfield."],
    )
    assert result["candidate_records_analyzed"] == 1
    assert any(f["type"] == "candidate_record_membership_signal" for f in result["findings"])


def test_version_and_origin():
    result = assess_extraction_risk(_rec(), _Store())
    assert result["extraction_version"] == EXTRACTION_VERSION
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"

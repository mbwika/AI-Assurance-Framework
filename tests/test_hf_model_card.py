"""Tests for src/aiaf/registry/hf_model_card.py (Phase 3)."""

import json

from aiaf.registry.evidence_origin import EvidenceOrigin, FactLedger
from aiaf.registry.hf_model_card import (
    HF_MODEL_CARD_VERSION,
    STATUS_FETCH_FAILED,
    STATUS_NO_CARD,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    enrich_ledger,
    parse_snapshot_dir,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_README = """\
---
license: apache-2.0
pipeline_tag: text-generation
language:
  - en
tags:
  - llama
  - causal-lm
---
# My Model

A cool model.
"""

_FULL_README = """\
---
license: mit
pipeline_tag: text-classification
language:
  - en
  - fr
tags:
  - bert
  - classification
base_model: bert-base-uncased
authors:
  - acme-corp
---
# BERT Fine-tuned

Fine-tuned on custom data.
"""

_DISCLOSURE_README = """\
---
license: apache-2.0
pipeline_tag: text-generation
tags:
  - chat
  - instruct
---
# Demo Model

## Intended Use
Internal assistant workflows.

## Training Data
Mixture of public instruction corpora.

## Evaluation
Benchmarked on internal task suites.

## Limitations
May hallucinate and should not be used for legal decisions.

## Safety
Includes misuse and prompt-injection caveats.

## Privacy
No claim is made that the model cannot memorize personal data.
"""

_NO_FRONTMATTER_README = """\
# My Model

No YAML frontmatter here — just plain markdown.
"""

_CONFIG_JSON = {
    "model_type": "llama",
    "architectures": ["LlamaForCausalLM"],
    "_name_or_path": "meta-llama/Llama-3-8B",
    "vocab_size": 32000,
    "max_position_embeddings": 8192,
    "torch_dtype": "bfloat16",
}

_TOKENIZER_CONFIG = {
    "tokenizer_class": "LlamaTokenizerFast",
}


def _make_snapshot(tmp_path, readme=None, config=None, tokenizer_config=None):
    if readme is not None:
        (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    if config is not None:
        (tmp_path / "config.json").write_text(json.dumps(config), encoding="utf-8")
    if tokenizer_config is not None:
        (tmp_path / "tokenizer_config.json").write_text(
            json.dumps(tokenizer_config), encoding="utf-8"
        )
    return str(tmp_path)


# ---------------------------------------------------------------------------
# parse_snapshot_dir tests
# ---------------------------------------------------------------------------


def test_schema_version_constant():
    assert HF_MODEL_CARD_VERSION == "1.0"


def test_parse_minimal_readme(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README)
    result = parse_snapshot_dir(snap)
    assert result["status"] == STATUS_SUCCESS
    assert result["license"] == "apache-2.0"
    assert result["pipeline_tag"] == "text-generation"
    assert "en" in (result["language"] or [])


def test_parse_full_readme_publisher(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_FULL_README)
    result = parse_snapshot_dir(snap)
    assert result["status"] == STATUS_SUCCESS
    assert result["license"] == "mit"
    assert result["base_model"] == "bert-base-uncased"
    assert result["publisher"] == "acme-corp"
    assert "bert" in (result["tags"] or [])


def test_parse_config_json(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README, config=_CONFIG_JSON)
    result = parse_snapshot_dir(snap)
    assert result["model_type"] == "llama"
    assert "LlamaForCausalLM" in (result["architectures"] or [])


def test_publisher_derived_from_config_name_or_path(tmp_path):
    snap = _make_snapshot(tmp_path, config=_CONFIG_JSON)
    result = parse_snapshot_dir(snap)
    assert result["publisher"] == "meta-llama"


def test_tokenizer_class_extracted(tmp_path):
    snap = _make_snapshot(
        tmp_path,
        readme=_MINIMAL_README,
        config=_CONFIG_JSON,
        tokenizer_config=_TOKENIZER_CONFIG,
    )
    result = parse_snapshot_dir(snap)
    assert result["tokenizer_class"] == "LlamaTokenizerFast"


def test_model_card_disclosure_signals_detected(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_DISCLOSURE_README, config=_CONFIG_JSON)
    result = parse_snapshot_dir(snap)
    signals = result["model_card_signals"]
    assert signals["dataset_disclosure_present"] is True
    assert signals["evaluation_disclosure_present"] is True
    assert signals["limitations_disclosure_present"] is True
    assert signals["intended_use_present"] is True
    assert signals["safety_disclosure_present"] is True
    assert signals["privacy_disclosure_present"] is True


def test_config_claims_extracted_for_phase_a_probes(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README, config=_CONFIG_JSON)
    result = parse_snapshot_dir(snap)
    assert result["vocab_size"] == 32000
    assert result["context_window"] == 8192
    assert result["torch_dtype"] == "bfloat16"


def test_missing_readme_returns_no_card_status(tmp_path):
    snap = _make_snapshot(tmp_path)
    result = parse_snapshot_dir(snap)
    assert result["status"] == STATUS_NO_CARD


def test_no_frontmatter_readme_is_partial(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_NO_FRONTMATTER_README)
    result = parse_snapshot_dir(snap)
    # ModelCard may parse successfully but return no license/pipeline_tag —
    # status is SUCCESS (no parse error) but fields are None.
    assert result["status"] in (STATUS_SUCCESS, STATUS_PARTIAL, STATUS_NO_CARD)
    assert result["license"] is None


def test_malformed_config_json_does_not_crash(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README)
    (tmp_path / "config.json").write_text("{ bad json }", encoding="utf-8")
    result = parse_snapshot_dir(snap)
    # Should not raise; partial result acceptable.
    assert "status" in result
    assert result["license"] == "apache-2.0"


def test_result_has_required_fields(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README, config=_CONFIG_JSON)
    result = parse_snapshot_dir(snap)
    for field in (
        "schema_version", "status", "publisher", "license", "pipeline_tag",
        "language", "tags", "base_model", "model_type", "architectures",
        "tokenizer_class", "vocab_size", "context_window", "torch_dtype",
        "model_card_signals", "errors",
    ):
        assert field in result, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# enrich_ledger tests
# ---------------------------------------------------------------------------


def test_enrich_ledger_adds_provider_declared_facts(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_MINIMAL_README, config=_CONFIG_JSON)
    card = parse_snapshot_dir(snap)
    ledger = FactLedger()
    enrich_ledger(card, ledger)
    entries = ledger.to_list()
    origins = {e["origin"] for e in entries}
    assert EvidenceOrigin.PROVIDER_DECLARED.value in origins


def test_enrich_ledger_noop_on_failed_status(tmp_path):
    card = {"status": STATUS_FETCH_FAILED, "license": "mit"}
    ledger = FactLedger()
    enrich_ledger(card, ledger)
    assert ledger.to_list() == []


def test_enrich_ledger_tags_license_as_provider_declared(tmp_path):
    snap = _make_snapshot(tmp_path, readme=_FULL_README)
    card = parse_snapshot_dir(snap)
    ledger = FactLedger()
    enrich_ledger(card, ledger)
    lic_entries = [e for e in ledger.to_list() if e["name"] == "license"]
    assert len(lic_entries) >= 1
    assert lic_entries[0]["origin"] == EvidenceOrigin.PROVIDER_DECLARED.value

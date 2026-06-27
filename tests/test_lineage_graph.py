"""Tests for registry/lineage_graph.py (Phase 5)."""


from aiaf.registry.lineage_graph import (
    LINEAGE_VERSION,
    MODEL_TYPE_TO_FAMILY,
    _check_arch_consistency,
    _detect_merge_flags,
    derive_lineage,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _rec(model_id: str = "test-model", **meta) -> dict:
    return {"model_id": model_id, "metadata": dict(meta)}


def _wi_inspected(arch_family: str = "transformer") -> dict:
    return {
        "status": "INSPECTED",
        "derived_facts": {"architecture_family": arch_family},
    }


def _wi_header_only() -> dict:
    return {
        "status": "HEADER_ONLY",
        "derived_facts": {"architecture_family": None},
    }


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestDeriveLineageStructure:
    def test_required_keys_present(self):
        r = derive_lineage(_rec())
        for key in (
            "lineage_version", "base_model", "all_base_models", "lineage_chain",
            "lineage_depth", "lineage_source", "lineage_completeness",
            "architecture_consistency", "flags", "cannot_verify",
            "evidence_origin", "derived_at",
        ):
            assert key in r

    def test_version(self):
        r = derive_lineage(_rec())
        assert r["lineage_version"] == LINEAGE_VERSION

    def test_empty_record(self):
        r = derive_lineage({})
        assert r["lineage_depth"] == 1

    def test_none_record(self):
        r = derive_lineage(None)  # type: ignore
        assert r["lineage_depth"] == 1


# ---------------------------------------------------------------------------
# No base model
# ---------------------------------------------------------------------------

class TestNoBaseModel:
    def test_depth_is_1(self):
        r = derive_lineage(_rec("my-model"))
        assert r["lineage_depth"] == 1

    def test_chain_is_model_id(self):
        r = derive_lineage(_rec("my-model"))
        assert r["lineage_chain"] == ["my-model"]

    def test_completeness_unknown(self):
        r = derive_lineage(_rec("my-model"))
        assert r["lineage_completeness"] == "UNKNOWN"

    def test_base_model_is_none(self):
        r = derive_lineage(_rec("my-model"))
        assert r["base_model"] is None

    def test_no_flags(self):
        r = derive_lineage(_rec("my-model"))
        assert r["flags"] == []

    def test_arch_consistency_unverifiable_without_wi(self):
        r = derive_lineage(_rec("my-model"))
        assert r["architecture_consistency"] == "UNVERIFIABLE"


# ---------------------------------------------------------------------------
# Base model from config fields
# ---------------------------------------------------------------------------

class TestBaseModelFromConfig:
    def test_base_model_field(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["base_model"] == "llama-7b"

    def test_depth_is_2(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["lineage_depth"] == 2

    def test_chain_order(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["lineage_chain"] == ["llama-7b", "fine-tuned"]

    def test_completeness_partial(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["lineage_completeness"] == "PARTIAL"

    def test_source_config_json(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["lineage_source"] == "config_json"

    def test_evidence_origin_provider_declared(self):
        r = derive_lineage(_rec("fine-tuned", base_model="llama-7b"))
        assert r["evidence_origin"] == "provider_declared"

    def test_name_or_path_fallback(self):
        r = derive_lineage(_rec("fine-tuned", _name_or_path="meta-llama/Llama-2-7b-hf"))
        assert r["base_model"] == "meta-llama/Llama-2-7b-hf"

    def test_parent_model_fallback(self):
        r = derive_lineage(_rec("child", parent_model="original"))
        assert r["base_model"] == "original"

    def test_same_as_model_id_ignored(self):
        r = derive_lineage(_rec("same-model", base_model="same-model"))
        assert r["base_model"] is None


# ---------------------------------------------------------------------------
# Base model from HF model card
# ---------------------------------------------------------------------------

class TestBaseModelFromHFCard:
    def _rec_with_card(self, model_id: str, card: dict) -> dict:
        return {"model_id": model_id, "metadata": {"hf_model_card": card}}

    def test_single_base_model(self):
        r = derive_lineage(self._rec_with_card("ft", {"base_model": "mistralai/Mistral-7B-v0.1"}))
        assert r["base_model"] == "mistralai/Mistral-7B-v0.1"

    def test_source_hf_model_card(self):
        r = derive_lineage(self._rec_with_card("ft", {"base_model": "mistralai/Mistral-7B-v0.1"}))
        assert r["lineage_source"] == "hf_model_card"

    def test_multiple_base_models_all_captured(self):
        r = derive_lineage(self._rec_with_card("merged", {
            "base_model": ["model-a", "model-b", "model-c"],
        }))
        assert set(r["all_base_models"]) == {"model-a", "model-b", "model-c"}

    def test_multiple_base_models_sets_first_as_primary(self):
        r = derive_lineage(self._rec_with_card("merged", {
            "base_model": ["model-a", "model-b"],
        }))
        assert r["base_model"] == "model-a"


# ---------------------------------------------------------------------------
# User-entered base model (weakest)
# ---------------------------------------------------------------------------

class TestUserEnteredBaseModel:
    def test_user_base_model_accepted(self):
        r = derive_lineage(_rec("ft", user_base_model="some-base"))
        assert r["base_model"] == "some-base"

    def test_source_is_user_entered(self):
        r = derive_lineage(_rec("ft", user_base_model="some-base"))
        assert r["lineage_source"] == "user_entered"

    def test_evidence_origin_user_entered(self):
        r = derive_lineage(_rec("ft", user_base_model="some-base"))
        assert r["evidence_origin"] == "user_entered"

    def test_config_json_preferred_over_user_entered(self):
        r = derive_lineage(_rec("ft", base_model="config-base", user_base_model="user-base"))
        assert r["base_model"] == "config-base"
        assert r["lineage_source"] == "config_json"


# ---------------------------------------------------------------------------
# Merge detection
# ---------------------------------------------------------------------------

class TestMergeDetection:
    def test_merge_in_model_id(self):
        r = derive_lineage(_rec("llama-7b-merge-v1"))
        assert any("merge indicator" in f.lower() for f in r["flags"])

    def test_slerp_in_model_id(self):
        r = derive_lineage(_rec("model-slerp-blend"))
        assert any("slerp" in f.lower() for f in r["flags"])

    def test_ties_in_model_id(self):
        # "ties-merged-model" contains both "ties" and "merge" — either indicator may be flagged first
        r = derive_lineage(_rec("ties-merged-model"))
        assert len(r["flags"]) > 0  # at least one merge-indicator flag is set

    def test_merge_tag_in_hf_card(self):
        r = derive_lineage({"model_id": "my-model", "metadata": {
            "hf_model_card": {"tags": ["merge", "llm"]},
        }})
        assert any("tag" in f.lower() for f in r["flags"])

    def test_multiple_base_models_flag(self):
        r = derive_lineage({"model_id": "merged", "metadata": {
            "hf_model_card": {"base_model": ["a", "b", "c"]},
        }})
        assert any("multiple" in f.lower() for f in r["flags"])

    def test_merge_config_in_metadata(self):
        r = derive_lineage(_rec("my-model", merge_config={"type": "ties"}))
        assert any("merge_config" in f.lower() or "mergekit" in f.lower() for f in r["flags"])

    def test_merge_flag_adds_cannot_verify_item(self):
        r = derive_lineage(_rec("slerp-model"))
        text = " ".join(r["cannot_verify"]).lower()
        assert "merge" in text or "composition" in text

    def test_clean_model_no_flags(self):
        r = derive_lineage(_rec("clean-llama-7b-instruct"))
        assert r["flags"] == []


# ---------------------------------------------------------------------------
# Architecture consistency
# ---------------------------------------------------------------------------

class TestArchConsistency:
    def test_no_weight_inspection_unverifiable(self):
        r = derive_lineage(_rec("m", model_type="llama"))
        assert r["architecture_consistency"] == "UNVERIFIABLE"

    def test_header_only_wi_unverifiable(self):
        r = derive_lineage(_rec("m", model_type="llama"), weight_inspection=_wi_header_only())
        assert r["architecture_consistency"] == "UNVERIFIABLE"

    def test_consistent_llama(self):
        r = derive_lineage(_rec("m", model_type="llama"), weight_inspection=_wi_inspected("transformer"))
        assert r["architecture_consistency"] == "CONSISTENT"

    def test_consistent_bert_as_encoder(self):
        r = derive_lineage(_rec("m", model_type="bert"), weight_inspection=_wi_inspected("transformer_encoder"))
        assert r["architecture_consistency"] == "CONSISTENT"

    def test_consistent_cross_compatible_transformer_types(self):
        # transformer and transformer_encoder are compat variants in the impl
        r = derive_lineage(_rec("m", model_type="llama"), weight_inspection=_wi_inspected("transformer_encoder"))
        assert r["architecture_consistency"] == "CONSISTENT"

    def test_inconsistent_transformer_vs_ssm(self):
        r = derive_lineage(_rec("m", model_type="llama"), weight_inspection=_wi_inspected("ssm"))
        assert r["architecture_consistency"] == "INCONSISTENT"

    def test_inconsistent_diffusion_vs_transformer(self):
        r = derive_lineage(_rec("m", model_type="gpt2"), weight_inspection=_wi_inspected("diffusion"))
        assert r["architecture_consistency"] == "INCONSISTENT"

    def test_unknown_model_type_unverifiable(self):
        r = derive_lineage(_rec("m", model_type="unknown-arch-xyz"),
                           weight_inspection=_wi_inspected("transformer"))
        assert r["architecture_consistency"] == "UNVERIFIABLE"

    def test_unknown_wi_family_unverifiable(self):
        r = derive_lineage(_rec("m", model_type="llama"),
                           weight_inspection=_wi_inspected("unknown"))
        assert r["architecture_consistency"] == "UNVERIFIABLE"


# ---------------------------------------------------------------------------
# Detect merge flags helper (unit)
# ---------------------------------------------------------------------------

class TestDetectMergeFlags:
    def test_no_flags_on_clean_model(self):
        flags = _detect_merge_flags("clean-model", {}, {}, [])
        assert flags == []

    def test_franken_indicator(self):
        flags = _detect_merge_flags("franken-model", {}, {}, [])
        assert len(flags) > 0

    def test_dare_indicator(self):
        flags = _detect_merge_flags("model-dare-v1", {}, {}, [])
        assert len(flags) > 0

    def test_mergekit_config_key(self):
        flags = _detect_merge_flags("my-model", {"mergekit_config": {}}, {}, [])
        assert len(flags) > 0


# ---------------------------------------------------------------------------
# Check arch consistency helper (unit)
# ---------------------------------------------------------------------------

class TestCheckArchConsistency:
    def test_none_wi_returns_unverifiable(self):
        assert _check_arch_consistency({}, {}, None) == "UNVERIFIABLE"

    def test_non_inspected_wi_returns_unverifiable(self):
        assert _check_arch_consistency(
            {"model_type": "llama"}, {},
            {"status": "NO_FILE", "derived_facts": {"architecture_family": "transformer"}}
        ) == "UNVERIFIABLE"

    def test_consistent(self):
        assert _check_arch_consistency(
            {"model_type": "mistral"}, {},
            {"status": "INSPECTED", "derived_facts": {"architecture_family": "transformer"}}
        ) == "CONSISTENT"

    def test_inconsistent(self):
        assert _check_arch_consistency(
            {"model_type": "llama"}, {},
            {"status": "INSPECTED", "derived_facts": {"architecture_family": "diffusion"}}
        ) == "INCONSISTENT"

    def test_mamba_consistent(self):
        assert _check_arch_consistency(
            {"model_type": "mamba"}, {},
            {"status": "INSPECTED", "derived_facts": {"architecture_family": "ssm"}}
        ) == "CONSISTENT"


# ---------------------------------------------------------------------------
# MODEL_TYPE_TO_FAMILY export
# ---------------------------------------------------------------------------

class TestModelTypeMappingExport:
    def test_is_dict(self):
        assert isinstance(MODEL_TYPE_TO_FAMILY, dict)

    def test_llama_maps_to_transformer(self):
        assert MODEL_TYPE_TO_FAMILY["llama"] == "transformer"

    def test_mamba_maps_to_ssm(self):
        assert MODEL_TYPE_TO_FAMILY["mamba"] == "ssm"

    def test_bert_maps_to_encoder(self):
        assert MODEL_TYPE_TO_FAMILY["bert"] == "transformer_encoder"

"""Base-model lineage graph derivation for registered model artifacts.

Derives the ancestry chain (base model → fine-tuned model → …) from
artifact-native and provider-declared sources, without network access.

Sources consulted, weakest to strongest:
  user_entered     — operator-supplied ``base_model`` key in metadata
  provider_declared — HF model card ``base_model`` field; config.json
                      ``_name_or_path`` / ``base_model``

The lineage graph is intentionally shallow: we derive what the artifact
tells us and explicitly enumerate what cannot be verified from the bytes alone.

Architecture consistency cross-check
-------------------------------------
When weight_inspector results are available, we compare the architecture
family inferred from tensor names against the family implied by the declared
``model_type`` / ``architectures`` field.  A mismatch is a strong signal
that the artifact does not correspond to the model the metadata describes.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Strips HF architecture class suffixes: "LlamaForCausalLM" → "llama"
_HF_ARCH_SUFFIX_RE = re.compile(
    r"(forconditionalgeneration|forcausallm|forseq2seqlm|"
    r"forsequenceclassification|forquestionanswering|formultiplechoice|"
    r"formaskdlm|model)$"
)

LINEAGE_VERSION = "1.0"

# model_type (config.json / HF card) → architecture family label
_MODEL_TYPE_TO_FAMILY: dict[str, str] = {
    "llama": "transformer",
    "llama2": "transformer",
    "llama3": "transformer",
    "mistral": "transformer",
    "mixtral": "transformer",
    "falcon": "transformer",
    "gpt2": "transformer",
    "gpt_neo": "transformer",
    "gpt_neox": "transformer",
    "gpt_j": "transformer",
    "bloom": "transformer",
    "opt": "transformer",
    "gemma": "transformer",
    "gemma2": "transformer",
    "gemma3": "transformer",
    "phi": "transformer",
    "phi3": "transformer",
    "qwen": "transformer",
    "qwen2": "transformer",
    "qwen3": "transformer",
    "internlm": "transformer",
    "baichuan": "transformer",
    "chatglm": "transformer",
    "stablelm": "transformer",
    "openelm": "transformer",
    "command-r": "transformer",
    "cohere": "transformer",
    "deepseek": "transformer",
    "t5": "transformer_encoder",
    "bert": "transformer_encoder",
    "roberta": "transformer_encoder",
    "deberta": "transformer_encoder",
    "electra": "transformer_encoder",
    "albert": "transformer_encoder",
    "mamba": "ssm",
    "mamba2": "ssm",
    "rwkv": "ssm",
    "jamba": "ssm",
    "stable-diffusion": "diffusion",
    "unet": "diffusion",
}

# Phrases in model name / tags that suggest a merge model
_MERGE_INDICATORS = frozenset({
    "merge", "slerp", "ties", "dare", "franken", "frankenmoe",
    "frankenmerge", "linear_merge", "weighted_merge",
})


def derive_lineage(
    model_record: dict[str, Any],
    weight_inspection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive the lineage graph for a registered model.

    Parameters
    ----------
    model_record:
        Registered model record (``id`` / ``model_id`` + ``metadata``).
    weight_inspection:
        Optional output of :func:`aiaf.registry.weight_inspector.inspect_file`.
        Used to cross-check declared architecture family.
    """
    model_record = model_record if isinstance(model_record, dict) else {}
    metadata = model_record.get("metadata") or {}
    hf_card = metadata.get("hf_model_card") or {}

    current_id = str(
        model_record.get("model_id") or model_record.get("id") or "unknown"
    )

    # ── Collect base_model candidates ────────────────────────────────────────
    candidates: list[dict[str, str]] = []

    # config.json / model metadata fields (ARTIFACT_DERIVED → PROVIDER_DECLARED)
    for field in ("base_model", "_name_or_path", "parent_model"):
        val = metadata.get(field)
        if val and isinstance(val, str):
            stripped = val.strip()
            if stripped and stripped != current_id:
                candidates.append({"value": stripped, "source": "config_json",
                                   "origin": "provider_declared"})
                break  # prefer the first match

    # HF model card base_model (PROVIDER_DECLARED)
    hf_base = hf_card.get("base_model")
    if hf_base:
        if isinstance(hf_base, list):
            # Multiple base models → merge model; record all
            for b in hf_base:
                if isinstance(b, str) and b.strip() and b.strip() != current_id:
                    candidates.append({"value": b.strip(), "source": "hf_model_card",
                                       "origin": "provider_declared"})
        elif isinstance(hf_base, str) and hf_base.strip() != current_id:
            candidates.append({"value": hf_base.strip(), "source": "hf_model_card",
                                "origin": "provider_declared"})

    # User-entered (weakest)
    user_base = metadata.get("user_base_model")
    if user_base and isinstance(user_base, str):
        stripped = user_base.strip()
        if stripped and stripped != current_id:
            candidates.append({"value": stripped, "source": "user_entered",
                                "origin": "user_entered"})

    # ── Pick strongest candidate ─────────────────────────────────────────────
    base_model: str | None = None
    lineage_source = "unverifiable"
    for c in candidates:
        if c["source"] in ("config_json", "hf_model_card"):
            base_model = c["value"]
            lineage_source = c["source"]
            break
    if base_model is None and candidates:
        base_model = candidates[0]["value"]
        lineage_source = candidates[0]["source"]

    # ── Build chain ──────────────────────────────────────────────────────────
    if base_model:
        lineage_chain = [base_model, current_id]
        lineage_depth = 2
        lineage_completeness = "PARTIAL"  # we can't verify the base further
    else:
        lineage_chain = [current_id]
        lineage_depth = 1
        lineage_completeness = "UNKNOWN"

    # ── Merge-model detection ────────────────────────────────────────────────
    flags = _detect_merge_flags(current_id, metadata, hf_card, candidates)

    # ── Architecture consistency cross-check ──────────────────────────────────
    arch_consistency = _check_arch_consistency(metadata, hf_card, weight_inspection)

    # ── Decidability bounds for lineage ──────────────────────────────────────
    cannot_verify: list[str] = [
        "Whether the claimed base model identifier resolves to the exact "
        "artifact weights used during fine-tuning (requires bit-for-bit "
        "access to the original base artifact)",
        "Training procedure applied on top of the base model (SFT, RLHF, DPO, "
        "LoRA rank/merge settings) — not recorded in the artifact",
        "Lineage depth beyond 2 without recursive artifact inspection of "
        "each ancestor",
    ]
    if flags:
        cannot_verify.append(
            "Merge composition ratio and source model identities cannot be "
            "independently verified from the artifact without the mergekit "
            "configuration and all source model artifacts"
        )

    return {
        "lineage_version": LINEAGE_VERSION,
        "base_model": base_model,
        "all_base_models": [c["value"] for c in candidates
                             if c["source"] in ("config_json", "hf_model_card")],
        "lineage_chain": lineage_chain,
        "lineage_depth": lineage_depth,
        "lineage_source": lineage_source,
        "lineage_completeness": lineage_completeness,
        "architecture_consistency": arch_consistency,
        "flags": flags,
        "cannot_verify": cannot_verify,
        "evidence_origin": (
            "provider_declared" if lineage_source in ("config_json", "hf_model_card")
            else ("user_entered" if lineage_source == "user_entered" else "unverifiable")
        ),
        "derived_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_merge_flags(
    model_id: str,
    metadata: dict[str, Any],
    hf_card: dict[str, Any],
    candidates: list[dict[str, str]],
) -> list[str]:
    flags: list[str] = []

    lower_id = model_id.lower()
    for indicator in _MERGE_INDICATORS:
        if indicator in lower_id:
            flags.append(f"Model ID contains merge indicator '{indicator}'")
            break

    tags = hf_card.get("tags") or []
    merge_tags = [t for t in tags if any(m in str(t).lower() for m in _MERGE_INDICATORS)]
    if merge_tags:
        flags.append(f"HF model card tags indicate merge: {merge_tags[:4]}")

    hf_base = hf_card.get("base_model")
    if isinstance(hf_base, list) and len(hf_base) > 1:
        flags.append(
            f"Multiple ({len(hf_base)}) base models declared — likely a merge/ensemble"
        )

    if "merge_config" in metadata or "mergekit_config" in metadata:
        flags.append("merge_config / mergekit_config found in model metadata")

    return flags


def _check_arch_consistency(
    metadata: dict[str, Any],
    hf_card: dict[str, Any],
    weight_inspection: dict[str, Any] | None,
) -> str:
    """CONSISTENT | INCONSISTENT | UNVERIFIABLE."""
    if weight_inspection is None:
        return "UNVERIFIABLE"

    wi_status = weight_inspection.get("status")
    if wi_status != "INSPECTED":
        return "UNVERIFIABLE"

    wi_family = (weight_inspection.get("derived_facts") or {}).get("architecture_family")
    if not wi_family or wi_family == "unknown":
        return "UNVERIFIABLE"

    # Declared architecture from model_type / architectures field
    raw_type = (
        metadata.get("model_type")
        or (hf_card.get("architectures") or [None])[0]
        or hf_card.get("model_type")
        or ""
    ).lower().strip()
    declared_type = _HF_ARCH_SUFFIX_RE.sub("", raw_type).strip()

    declared_family = _MODEL_TYPE_TO_FAMILY.get(declared_type.strip())
    if declared_family is None:
        return "UNVERIFIABLE"

    # transformer and transformer_encoder are compatible variants
    compat_set = {"transformer", "transformer_encoder"}
    if declared_family in compat_set and wi_family in compat_set:
        return "CONSISTENT"

    return "CONSISTENT" if declared_family == wi_family else "INCONSISTENT"


# Expose mapping for use by fact_reconciler
MODEL_TYPE_TO_FAMILY = _MODEL_TYPE_TO_FAMILY

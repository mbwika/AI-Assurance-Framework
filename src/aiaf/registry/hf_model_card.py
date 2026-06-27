"""HuggingFace model card and config metadata enrichment.

Extracts publisher-asserted metadata from a downloaded HuggingFace snapshot
directory (README.md + config.json) or from the HF Hub API.  All facts are
tagged ``PROVIDER_DECLARED`` — they are self-asserted by the model's publisher
through the HF platform, not independently verified.

This is Phase 3 of the AIAF interop layer: auto-pulling model-card metadata
elevates intake evidence from ``USER_ENTERED`` to ``PROVIDER_DECLARED``,
improving adoption-verdict accuracy without requiring a human to transcribe
model details manually.

The key integration points:
- Called during the HF snapshot job in ``api.models._register_hf_snapshot_job``
  while the local snapshot directory is still available.
- Also exposed via ``POST /v1/interop/models/{id}/enrich/hf`` for models that
  were registered before Phase 3 or not via the HF downloader.

Evidence origins assigned here
-------------------------------
``PROVIDER_DECLARED``:
    ``license``, ``pipeline_tag``, ``language``, ``base_model``, ``publisher``
    (extracted from README.md frontmatter), ``model_type``, ``architectures``
    (extracted from config.json).  All are self-asserted by the publisher in
    artifacts they control.

``ARTIFACT_DERIVED`` is *not* used here — the README and config are
documentation artifacts, not executable manifests.  The distinction matters
because ``PROVIDER_DECLARED`` (rank 1) is weaker than ``ARTIFACT_DERIVED``
(rank 2): publishers can write anything in their model card.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

HF_MODEL_CARD_VERSION = "1.0"

# Keys pulled from the model card YAML frontmatter.
_FRONTMATTER_FIELDS = (
    "license",
    "pipeline_tag",
    "language",
    "tags",
    "base_model",
    "author",
    "authors",
)

# Keys pulled from config.json.
_CONFIG_FIELDS = (
    "model_type",
    "architectures",
    "_name_or_path",
)

STATUS_SUCCESS = "SUCCESS"
STATUS_NO_CARD = "NO_MODEL_CARD"
STATUS_FETCH_FAILED = "FETCH_FAILED"
STATUS_PARTIAL = "PARTIAL"


# ---------------------------------------------------------------------------
# Parse from local snapshot directory (preferred — no extra network call)
# ---------------------------------------------------------------------------


def parse_snapshot_dir(snapshot_dir: str) -> Dict[str, Any]:
    """Extract PROVIDER_DECLARED metadata from a downloaded HF snapshot.

    Reads ``README.md`` (model card frontmatter) and ``config.json`` from
    ``snapshot_dir``.  Gracefully handles missing files — returns an empty
    result rather than raising.
    """
    path = Path(snapshot_dir)
    result = _empty_result()
    errors: List[str] = []

    # ── Model card ──────────────────────────────────────────────────────────
    readme = path / "README.md"
    if readme.exists():
        try:
            _parse_model_card_text(readme.read_text(encoding="utf-8", errors="replace"), result)
        except Exception as exc:
            errors.append(f"model_card: {exc}")
    else:
        result["status"] = STATUS_NO_CARD

    # ── config.json ─────────────────────────────────────────────────────────
    config_path = path / "config.json"
    if config_path.exists():
        try:
            _parse_config_json(json.loads(config_path.read_bytes()), result)
        except Exception as exc:
            errors.append(f"config_json: {exc}")

    # ── tokenizer_config.json (supplementary) ───────────────────────────────
    tok_config = path / "tokenizer_config.json"
    if tok_config.exists():
        try:
            tc = json.loads(tok_config.read_bytes())
            if not result["tokenizer_class"]:
                result["tokenizer_class"] = tc.get("tokenizer_class")
        except Exception:
            pass

    if errors:
        result["status"] = STATUS_PARTIAL if result["status"] == STATUS_SUCCESS else result["status"]
        result["errors"] = errors

    return result


# ---------------------------------------------------------------------------
# Fetch from HF Hub API (for the enrichment endpoint or URL-only registrations)
# ---------------------------------------------------------------------------


def fetch_from_hub(
    repo_id: str,
    *,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Fetch model card metadata from HuggingFace Hub.

    Requires ``huggingface_hub`` (already a project dependency).  Returns a
    partial result on failure rather than raising, so callers can degrade
    gracefully.
    """
    result = _empty_result()
    try:
        from huggingface_hub import ModelCard  # already in requirements
    except ImportError:
        result["status"] = STATUS_FETCH_FAILED
        result["errors"] = ["huggingface_hub not installed"]
        return result

    try:
        card = ModelCard.load(repo_id, token=token)
        _parse_model_card_text(str(card), result)
    except Exception as exc:
        logger.warning("Could not load model card for %s: %s", repo_id, exc)
        result["status"] = STATUS_FETCH_FAILED
        result["errors"] = [str(exc)]

    # Also try config.json via hf_hub_download
    try:
        from huggingface_hub import hf_hub_download
        config_path = hf_hub_download(repo_id, "config.json", token=token)
        with open(config_path, "rb") as fh:
            _parse_config_json(json.load(fh), result)
    except Exception:
        pass  # config.json is optional

    if "/" in repo_id and not result["publisher"]:
        result["publisher"] = repo_id.split("/")[0]

    return result


# ---------------------------------------------------------------------------
# Integrate into a FactLedger
# ---------------------------------------------------------------------------


def enrich_ledger(card_data: Dict[str, Any], ledger) -> None:
    """Add model card facts into *ledger* as PROVIDER_DECLARED entries.

    Idempotent: existing facts with the same name are not de-duplicated here
    (the FactLedger is append-only).  Only non-None values are added.
    """
    from .evidence_origin import EvidenceOrigin  # local import to avoid circular

    if not card_data or card_data.get("status") not in (STATUS_SUCCESS, STATUS_PARTIAL):
        return

    for field in ("license", "pipeline_tag", "language", "base_model",
                  "model_type", "architectures", "publisher", "tokenizer_class"):
        val = card_data.get(field)
        if val is not None:
            detail = f"from HuggingFace model card / config.json"
            ledger.add(field, val, EvidenceOrigin.PROVIDER_DECLARED, detail=detail)

    tags = card_data.get("tags") or []
    if tags:
        ledger.add(
            "model_tags",
            f"{len(tags)} tag(s): {', '.join(str(t) for t in tags[:10])}",
            EvidenceOrigin.PROVIDER_DECLARED,
            detail="from HuggingFace model card",
        )


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------


def _parse_model_card_text(text: str, result: Dict[str, Any]) -> None:
    """Parse YAML frontmatter from raw model card text via ModelCard."""
    try:
        from huggingface_hub import ModelCard
        card = ModelCard(text)
        data = card.data
    except Exception as exc:
        raise ValueError(f"Cannot parse model card: {exc}") from exc

    result["license"] = _str_or_none(getattr(data, "license", None))
    result["pipeline_tag"] = _str_or_none(getattr(data, "pipeline_tag", None))

    lang = getattr(data, "language", None)
    if lang:
        result["language"] = [str(l) for l in lang] if isinstance(lang, list) else str(lang)

    tags = getattr(data, "tags", None)
    if tags:
        result["tags"] = [str(t) for t in tags]

    result["base_model"] = _str_or_none(getattr(data, "base_model", None))

    # Author — some cards use `author`, others `authors`, some neither.
    author = getattr(data, "authors", None) or getattr(data, "author", None)
    if author:
        if isinstance(author, list):
            result["publisher"] = str(author[0]) if author else None
        else:
            result["publisher"] = str(author)

    result["model_card_signals"] = _model_card_signals(text)
    result["status"] = STATUS_SUCCESS


def _parse_config_json(config: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract model architecture info from config.json."""
    result["model_type"] = config.get("model_type") or result.get("model_type")
    archs = config.get("architectures")
    if archs:
        result["architectures"] = archs if isinstance(archs, list) else [archs]
    if result.get("vocab_size") is None and config.get("vocab_size") is not None:
        result["vocab_size"] = config.get("vocab_size")
    if result.get("context_window") is None:
        for key in ("max_position_embeddings", "n_positions", "max_sequence_length", "seq_length"):
            if config.get(key) is not None:
                result["context_window"] = config.get(key)
                break
    if result.get("torch_dtype") is None and config.get("torch_dtype") is not None:
        result["torch_dtype"] = str(config.get("torch_dtype"))

    # Fallback publisher from _name_or_path (e.g. "meta-llama/Llama-3-8B").
    if not result["publisher"]:
        name_or_path = config.get("_name_or_path", "")
        if name_or_path and "/" in str(name_or_path):
            result["publisher"] = str(name_or_path).split("/")[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_result() -> Dict[str, Any]:
    return {
        "schema_version": HF_MODEL_CARD_VERSION,
        "status": STATUS_SUCCESS,
        "publisher": None,
        "license": None,
        "pipeline_tag": None,
        "language": None,
        "tags": [],
        "base_model": None,
        "model_type": None,
        "architectures": None,
        "tokenizer_class": None,
        "vocab_size": None,
        "context_window": None,
        "torch_dtype": None,
        "model_card_signals": {
            "sections_present": [],
            "dataset_disclosure_present": False,
            "evaluation_disclosure_present": False,
            "limitations_disclosure_present": False,
            "intended_use_present": False,
            "safety_disclosure_present": False,
            "privacy_disclosure_present": False,
        },
        "errors": [],
    }


def _str_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _model_card_signals(text: str) -> Dict[str, Any]:
    lowered = text.lower()
    headings = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = re.sub(r"^#+\s*", "", stripped).strip().lower()
            if heading:
                headings.append(heading)

    def has_any(*terms: str) -> bool:
        return any(term in lowered for term in terms) or any(
            any(term in heading for term in terms) for heading in headings
        )

    return {
        "sections_present": headings[:24],
        "dataset_disclosure_present": has_any(
            "dataset", "training data", "training dataset", "data sources", "corpus"
        ),
        "evaluation_disclosure_present": has_any(
            "evaluation", "benchmark", "metrics", "results", "performance"
        ),
        "limitations_disclosure_present": has_any(
            "limitations", "risks", "caveat", "warnings", "out of scope"
        ),
        "intended_use_present": has_any(
            "intended use", "use case", "uses", "recommended uses", "downstream use"
        ),
        "safety_disclosure_present": has_any(
            "safety", "alignment", "harm", "misuse", "guardrail", "red team"
        ),
        "privacy_disclosure_present": has_any(
            "privacy", "pii", "personal data", "memorization", "data protection"
        ),
    }

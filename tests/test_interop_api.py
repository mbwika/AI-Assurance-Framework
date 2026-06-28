"""Tests for src/aiaf/api/interop.py (Phase 3)."""

import sys
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _make_store(tmp_path):
    ensure_src()
    from aiaf.data.store import DataStore
    return DataStore(db_path=str(tmp_path / "interop.db"))


def _register_model(store, tmp_path, **metadata):
    ensure_src()
    from aiaf.api import models as models_api

    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"fake-model-weights-phase3")
    metadata = {
        "artifact_file_path": str(artifact),
        **metadata,
    }
    rec = models_api._register_from_file(
        str(artifact),
        "https://huggingface.co/acme/demo-model",
        registered_by="tester",
        metadata=metadata,
        artifact_name="model.bin",
    )
    models_api._save_registered_model(store, rec)
    return rec


# ---------------------------------------------------------------------------
# CycloneDX BOM export endpoint
# ---------------------------------------------------------------------------


def test_bom_export_returns_200_for_known_model(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import interop as interop_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    rec = _register_model(store, tmp_path)

    response = interop_api.get_cyclonedx_bom(rec.model_id, api_key="dev-key")
    bom = response.body
    import json
    parsed = json.loads(bom)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.7"


def test_bom_export_includes_runtime_component_inventory(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import interop as interop_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    rec = _register_model(
        store,
        tmp_path,
        prompt_templates=[{"name": "baseline-prompt", "content": "Summarize the report."}],
        system_prompt="System-only policy text",
        mcp_servers=[{"server_id": "mcp-1", "name": "ACME MCP", "endpoint": "https://mcp.example.test"}],
        rag_indexes=[{"store_id": "rag-1", "collection_name": "policies", "store_type": "pgvector"}],
        embedding_model={"name": "text-embedding-3-small", "provider": "openai"},
        runtime_provider={"name": "OpenAI", "service": "responses-api"},
        guardrails=[{"name": "baseline-guardrail", "provider": "aiaf", "mode": "block"}],
        agent_policy_profile="restricted",
        evaluators=[{"name": "frontier-harness", "version": "2.0", "scope": "dangerous-capability"}],
    )

    response = interop_api.get_cyclonedx_bom(rec.model_id, api_key="dev-key")
    import json

    parsed = json.loads(response.body)
    runtime_types = {
        prop["value"]
        for component in parsed["components"]
        for prop in component.get("properties", [])
        if prop.get("name") == "aiaf:runtime_type"
    }
    assert {
        "prompt",
        "system-prompt-hash",
        "mcp-server",
        "rag-index",
        "embedding-model",
        "provider",
        "guardrail",
        "policy",
        "evaluator",
    }.issubset(runtime_types)


def test_bom_export_returns_404_for_unknown_model(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.get_cyclonedx_bom("no-such-model-id", api_key="dev-key")
    assert exc_info.value.status_code == 404


def test_bom_export_has_correct_content_type(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import interop as interop_api

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    rec = _register_model(store, tmp_path)

    response = interop_api.get_cyclonedx_bom(rec.model_id, api_key="dev-key")
    assert "cyclonedx" in response.media_type


# ---------------------------------------------------------------------------
# HF enrichment endpoint
# ---------------------------------------------------------------------------


def test_enrich_hf_returns_404_for_unknown_model(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api
    from aiaf.api.interop import HfEnrichRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.enrich_from_hf(
            "no-such-model-id",
            HfEnrichRequest(repo_id="acme/test-model"),
            api_key="dev-key",
        )
    assert exc_info.value.status_code == 404


def test_enrich_hf_raises_422_when_no_repo_id(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api
    from aiaf.api.interop import HfEnrichRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)

    # Register a model without an HF source URL so repo_id cannot be derived.
    rec = _register_model(store, tmp_path)
    rec_dict = rec.to_dict()
    rec_dict["source_url"] = "https://example.com/not-huggingface"
    store.save_model(rec_dict)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.enrich_from_hf(
            rec.model_id,
            HfEnrichRequest(),
            api_key="dev-key",
        )
    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# Sigstore verification endpoint
# ---------------------------------------------------------------------------


def test_sigstore_verify_returns_404_for_unknown_model(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api
    from aiaf.api.interop import SigstoreVerifyRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.verify_sigstore_signature(
            "no-such-model-id",
            SigstoreVerifyRequest(),
            api_key="dev-key",
        )
    assert exc_info.value.status_code == 404


def test_sigstore_verify_raises_422_when_no_stored_artifact_path(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api
    from aiaf.api.interop import SigstoreVerifyRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    rec = _register_model(store, tmp_path)
    rec_dict = rec.to_dict()
    rec_dict["metadata"] = {}
    store.save_model(rec_dict)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.verify_sigstore_signature(
            rec.model_id,
            SigstoreVerifyRequest(),
            api_key="dev-key",
        )
    assert exc_info.value.status_code == 422


def test_sigstore_verify_not_signed_when_no_bundle(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import interop as interop_api
    from aiaf.api.interop import SigstoreVerifyRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    monkeypatch.setattr(
        interop_api,
        "_approved_sigstore_roots",
        lambda: [tmp_path.resolve()],
    )
    rec = _register_model(store, tmp_path)

    result = interop_api.verify_sigstore_signature(
        rec.model_id,
        SigstoreVerifyRequest(),
        api_key="dev-key",
    )
    # No bundle beside the artifact → NOT_SIGNED; model was not modified.
    assert result["status"] in ("NOT_SIGNED", "NOT_AVAILABLE")
    assert result["verified"] is False


def test_sigstore_verify_rejects_artifact_path_outside_approved_roots(tmp_path, monkeypatch):
    ensure_src()
    from fastapi import HTTPException

    from aiaf.api import interop as interop_api
    from aiaf.api.interop import SigstoreVerifyRequest

    store = _make_store(tmp_path)
    monkeypatch.setattr(interop_api, "get_store", lambda: store)
    monkeypatch.setattr(
        interop_api,
        "_approved_sigstore_roots",
        lambda: [(tmp_path / "approved").resolve()],
    )
    rec = _register_model(store, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        interop_api.verify_sigstore_signature(
            rec.model_id,
            SigstoreVerifyRequest(),
            api_key="dev-key",
        )

    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# _repo_id_from_record helper
# ---------------------------------------------------------------------------


def test_repo_id_from_hf_source_url(tmp_path):
    ensure_src()
    from aiaf.api.interop import _repo_id_from_record

    rec = {"source_url": "https://huggingface.co/meta-llama/Llama-3-8B"}
    assert _repo_id_from_record(rec) == "meta-llama/Llama-3-8B"


def test_repo_id_from_metadata_fallback(tmp_path):
    ensure_src()
    from aiaf.api.interop import _repo_id_from_record

    rec = {
        "source_url": "https://example.com/model",
        "metadata": {"repo_id": "acme/test"},
    }
    assert _repo_id_from_record(rec) == "acme/test"


def test_repo_id_returns_none_for_non_hf_no_metadata():
    ensure_src()
    from aiaf.api.interop import _repo_id_from_record

    rec = {"source_url": "https://example.com/model"}
    assert _repo_id_from_record(rec) is None

"""Tests for src/aiaf/registry/cyclonedx_bom.py (Phase 3)."""


from aiaf.registry.cyclonedx_bom import (
    AIAF_TOOL_VERSION,
    BOM_SCHEMA_VERSION,
    CYCLONEDX_SPEC_VERSION,
    export_bom,
    import_bom,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_record():
    return {
        "model_id": "m-abc123",
        "model_name": "test-model",
        "version": "1.0.0",
        "publisher": "acme-corp",
        "license": "apache-2.0",
        "sha256": "a" * 64,
        "source_url": "https://huggingface.co/acme/test-model",
        "metadata": {},
    }


def _record_with_deps():
    rec = _minimal_record()
    rec["dependencies"] = [
        {"name": "torch", "version": "2.1.0", "ecosystem": "pypi"},
        {"name": "transformers", "version": "4.40.0", "ecosystem": "pypi"},
    ]
    return rec


def _record_with_hf_card():
    rec = _minimal_record()
    rec["metadata"] = {
        "hf_model_card": {
            "pipeline_tag": "text-generation",
            "model_type": "llama",
            "architectures": ["LlamaForCausalLM"],
        },
        "provenance_assessment": {
            "provenance_score": 72,
            "risk_level": "MEDIUM",
        },
    }
    return rec


def _record_with_runtime_components():
    rec = _minimal_record()
    rec["tools"] = ["browser"]
    rec["metadata"] = {
        "prompt_templates": [{"name": "baseline-prompt", "content": "Summarize the report."}],
        "system_prompt": "System-only policy text",
        "mcp_servers": [{"server_id": "mcp-1", "name": "ACME MCP", "endpoint": "https://mcp.example.test"}],
        "rag_indexes": [{"store_id": "rag-1", "collection_name": "policies", "store_type": "pgvector"}],
        "embedding_model": {"name": "text-embedding-3-small", "provider": "openai"},
        "runtime_provider": {"name": "OpenAI", "service": "responses-api"},
        "guardrails": [{"name": "baseline-guardrail", "provider": "aiaf", "mode": "block"}],
        "agent_policy_profile": "restricted",
        "evaluators": [{"name": "frontier-harness", "version": "2.0", "scope": "dangerous-capability"}],
    }
    return rec


# ---------------------------------------------------------------------------
# export_bom — top-level structure
# ---------------------------------------------------------------------------


def test_export_bom_format_and_spec_version():
    bom = export_bom(_minimal_record())
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.7"


def test_export_bom_serial_number_is_urn_uuid():
    bom = export_bom(_minimal_record())
    assert bom["serialNumber"].startswith("urn:uuid:")


def test_export_bom_version_is_int_one():
    bom = export_bom(_minimal_record())
    assert bom["version"] == 1


def test_export_bom_has_all_top_level_keys():
    bom = export_bom(_minimal_record())
    for key in ("bomFormat", "specVersion", "serialNumber", "version",
                 "metadata", "components", "dependencies"):
        assert key in bom, f"Missing key: {key}"


def test_export_bom_tool_attribution():
    bom = export_bom(_minimal_record())
    tools = bom["metadata"]["tools"]
    assert any(t.get("name") == "AIAF" for t in tools)


# ---------------------------------------------------------------------------
# export_bom — component
# ---------------------------------------------------------------------------


def test_component_type_is_machine_learning_model():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    assert comp["type"] == "machine-learning-model"


def test_component_name_and_version():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    assert comp["name"] == "test-model"
    assert comp["version"] == "1.0.0"


def test_sha256_in_hashes():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    assert any(h["alg"] == "SHA-256" and h["content"] == "a" * 64
               for h in comp.get("hashes", []))


def test_source_url_in_external_references():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    refs = comp.get("externalReferences") or []
    assert any("huggingface.co" in r.get("url", "") for r in refs)


def test_publisher_in_component():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    assert comp.get("publisher") == "acme-corp"


def test_license_in_component():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    licenses = comp.get("licenses") or []
    assert len(licenses) >= 1


# ---------------------------------------------------------------------------
# export_bom — dependencies
# ---------------------------------------------------------------------------


def test_dependencies_includes_main_component_ref():
    bom = export_bom(_record_with_deps())
    deps = bom["dependencies"]
    assert len(deps) >= 1
    main_dep = deps[0]
    assert "dependsOn" in main_dep


def test_dependency_components_in_components_list():
    bom = export_bom(_record_with_deps())
    comp_names = {c["name"] for c in bom["components"]}
    assert "torch" in comp_names
    assert "transformers" in comp_names


def test_dependency_components_have_purl():
    bom = export_bom(_record_with_deps())
    for comp in bom["components"]:
        if comp["type"] == "library":
            assert "purl" in comp
            assert comp["purl"].startswith("pkg:pypi/")


def test_runtime_components_are_exported_as_cyclonedx_components():
    bom = export_bom(_record_with_runtime_components())
    runtime_types = {
        prop["value"]
        for component in bom["components"]
        for prop in component.get("properties", [])
        if prop.get("name") == "aiaf:runtime_type"
    }
    assert {
        "prompt",
        "system-prompt-hash",
        "tool",
        "mcp-server",
        "rag-index",
        "embedding-model",
        "provider",
        "guardrail",
        "policy",
        "evaluator",
    }.issubset(runtime_types)


def test_runtime_component_hashes_do_not_embed_raw_prompt_content():
    bom = export_bom(_record_with_runtime_components())
    serialized = str(bom)
    assert "Summarize the report." not in serialized
    assert "System-only policy text" not in serialized


# ---------------------------------------------------------------------------
# export_bom — modelCard block
# ---------------------------------------------------------------------------


def test_model_card_block_present():
    bom = export_bom(_minimal_record())
    comp = bom["components"][0]
    assert "modelCard" in comp


def test_model_card_pipeline_tag_from_hf(tmp_path):
    bom = export_bom(_record_with_hf_card())
    comp = bom["components"][0]
    mc = comp.get("modelCard") or {}
    params = mc.get("modelParameters") or {}
    assert params.get("task") == "text-generation"


# ---------------------------------------------------------------------------
# import_bom tests
# ---------------------------------------------------------------------------


def test_import_bom_extracts_model_name():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["model_name"] == "test-model"


def test_import_bom_extracts_sha256():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["sha256"] == "a" * 64


def test_import_bom_sha256_tagged_locally_observed():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["evidence_origin_hints"].get("sha256") == "locally_observed"


def test_import_bom_publisher_tagged_provider_declared():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["evidence_origin_hints"].get("publisher") == "provider_declared"


def test_import_bom_license_tagged_provider_declared():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["evidence_origin_hints"].get("license") == "provider_declared"


def test_import_bom_extracts_dependencies():
    bom = export_bom(_record_with_deps())
    imported = import_bom(bom)
    names = {d["name"] for d in imported["dependencies"]}
    assert "torch" in names
    assert "transformers" in names


def test_import_bom_reconstructs_runtime_component_inventory():
    bom = export_bom(_record_with_runtime_components())
    imported = import_bom(bom)

    runtime_types = {component["type"] for component in imported["runtime_components"]}
    assert {
        "prompt",
        "system-prompt-hash",
        "tool",
        "mcp-server",
        "rag-index",
        "embedding-model",
        "provider",
        "guardrail",
        "policy",
        "evaluator",
    }.issubset(runtime_types)
    assert imported["metadata"]["system_prompt_hash"] is not None
    assert imported["metadata"]["runtime_provider"]["name"] == "OpenAI"
    assert imported["metadata"]["embedding_model"]["name"] == "text-embedding-3-small"
    assert imported["tools"][0]["name"] == "browser"
    assert imported["evidence_origin_hints"]["runtime_components"] == "provider_declared"


def test_import_bom_prefers_primary_model_over_runtime_embedding_model():
    bom = export_bom(_record_with_runtime_components())
    model_component = bom["components"][0]
    embedding_component = next(
        component
        for component in bom["components"]
        if any(
            prop.get("name") == "aiaf:runtime_type" and prop.get("value") == "embedding-model"
            for prop in component.get("properties", [])
        )
    )
    remaining = [
        component
        for component in bom["components"]
        if component is not embedding_component and component is not model_component
    ]
    bom["components"] = [embedding_component, model_component] + remaining

    imported = import_bom(bom)

    assert imported["model_name"] == "test-model"
    assert imported["version"] == "1.0.0"
    assert imported["metadata"]["embedding_model"]["name"] == "text-embedding-3-small"


def test_import_bom_round_trip_spec_version():
    bom = export_bom(_minimal_record())
    imported = import_bom(bom)
    assert imported["spec_version"] == "1.7"
    assert imported["bom_format"] == "CycloneDX"


def test_import_bom_empty_dict_does_not_raise():
    imported = import_bom({})
    assert "model_name" in imported


def test_export_bom_empty_record_does_not_raise():
    bom = export_bom({})
    assert bom["bomFormat"] == "CycloneDX"


def test_constants():
    assert CYCLONEDX_SPEC_VERSION == "1.7"
    assert AIAF_TOOL_VERSION == "0.2.0"
    assert BOM_SCHEMA_VERSION == "1.0"

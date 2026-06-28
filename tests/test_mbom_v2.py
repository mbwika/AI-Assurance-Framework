import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.registry.mbom_v2 as mbom_module  # noqa: E402
from aiaf.registry.mbom_v2 import (  # noqa: E402
    AI_BOM_FORMAT,
    AI_BOM_SPEC_VERSION,
    generate_ai_bom_v2,
    generate_attestable_ai_bom_v2,
    verify_ai_bom_v2,
)


def _model(**overrides):
    attestation_id = "attestation-2026-0001"
    model = {
        "model_id": "model-1",
        "model_name": "Acme Safety Model",
        "version": "1.2.0",
        "source": "huggingface",
        "source_url": "https://huggingface.co/acme/model",
        "publisher": "Acme AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "dependencies": [
            "Transformers==4.40.0",
            {"ecosystem": "npm", "name": "@acme/runtime", "version": "2.3.1", "source_manifest": "package-lock.json"},
        ],
        "training_artifacts": [
            {
                "name": "curated-corpus",
                "version": "2026.06",
                "source_url": "https://data.example.test/corpus.jsonl",
                "sha256": "b" * 64,
                "license": "cc-by-4.0",
            }
        ],
        "deployment_pipeline": {
            "environment": "production",
            "artifact_ref": "registry.example.test/acme/model@sha256:" + "a" * 64,
            "approval_gate": "CAB-42",
        },
        "attestations": [
            {
                "schema_version": "2.0",
                "key_id": "key-1",
                "statement": {"attestation_id": attestation_id},
                "verification": {"verified": True},
            }
        ],
        "vulnerability_scan": {
            "assessment_complete": True,
            "match_count": 1,
            "matches": [{"advisory_id": "CVE-2026-0001", "severity": "HIGH"}],
        },
        "metadata": {
            "dependency_discovery": {
                "manifests": ["requirements.txt", "package-lock.json"],
                "dependency_count": 2,
                "errors": [],
            },
        },
    }
    model.update(overrides)
    return model


def _context():
    return {
        "generated_at": "2026-06-19T12:00:00Z",
        "verified_attestation_ids": ["attestation-2026-0001"],
    }


def _redigest(document):
    unsigned = {key: value for key, value in document.items() if key != "document_sha256"}
    document["document_sha256"] = mbom_module.hashlib.sha256(
        mbom_module._canonical_bytes(unsigned)
    ).hexdigest()


def test_complete_bom_is_deterministic_versioned_json_safe_and_verifiable():
    first = generate_ai_bom_v2(_model(), _context())
    second = generate_ai_bom_v2(copy.deepcopy(_model()), copy.deepcopy(_context()))

    assert first == second
    assert first["bom_format"] == AI_BOM_FORMAT
    assert first["spec_version"] == AI_BOM_SPEC_VERSION == "2.0"
    assert first["assessment_complete"] is True
    assert first["evidence_quality"]["score"] == 100
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert verify_ai_bom_v2(first)["verified"] is True


def test_input_order_does_not_change_document_identity_or_digest():
    model = _model()
    reversed_model = copy.deepcopy(model)
    reversed_model["dependencies"].reverse()
    reversed_model["metadata"]["dependency_discovery"]["manifests"].reverse()

    first = generate_ai_bom_v2(model, _context())
    second = generate_ai_bom_v2(reversed_model, _context())

    assert first["serial_number"] == second["serial_number"]
    assert first["document_sha256"] == second["document_sha256"]


def test_material_model_change_changes_serial_and_document_digest():
    first = generate_ai_bom_v2(_model(), _context())
    second = generate_ai_bom_v2(_model(sha256="c" * 64), _context())

    assert first["serial_number"] != second["serial_number"]
    assert first["document_sha256"] != second["document_sha256"]


def test_attestable_projection_excludes_only_derived_attestation_evidence():
    model = _model()
    baseline = generate_attestable_ai_bom_v2(model)
    persisted = copy.deepcopy(model)
    persisted["attestations"] = [{"statement": {"attestation_id": "att-1"}}]
    persisted["provenance_attestations"] = [{"signature": "a" * 64}]
    persisted["metadata"]["provenance_attestation_verifications"] = [
        {"attestation_id": "att-1", "verified": True}
    ]

    after_persistence = generate_attestable_ai_bom_v2(persisted)
    material_change = generate_attestable_ai_bom_v2(
        _model(dependencies=["transformers==99.0.0"])
    )

    assert baseline == after_persistence
    assert baseline["document_sha256"] != material_change["document_sha256"]


def test_no_implicit_clock_keeps_generation_replayable():
    first = generate_ai_bom_v2(_model())
    second = generate_ai_bom_v2(_model())

    assert first["generated_at"] is None
    assert first == second


def test_malformed_root_fails_closed_but_returns_verifiable_document():
    result = generate_ai_bom_v2(["not", "a", "model"])

    assert result["assessment_complete"] is False
    assert result["subject"]["identity_complete"] is False
    assert any(item["indicator"] == "invalid_model_record" for item in result["diagnostics"])
    assert verify_ai_bom_v2(result)["verified"] is True


def test_missing_model_hash_is_critical_and_reduces_integrity_quality():
    result = generate_ai_bom_v2(_model(sha256=None), _context())

    assert result["evidence_quality"]["dimensions"]["artifact_integrity"] == 0
    assert any(item["indicator"] == "missing_or_invalid_model_hash" for item in result["diagnostics"])
    assert result["assessment_complete"] is False


def test_pypi_names_are_canonicalized_and_exact_duplicates_removed():
    result = generate_ai_bom_v2(
        _model(dependencies=["My_Package==01.2.0", "my-package==1.2.0"]), _context()
    )

    dependencies = result["components"]["dependencies"]
    assert len(dependencies) == 1
    assert dependencies[0]["name"] == "my-package"
    assert dependencies[0]["version"] == "1.2.0"
    assert dependencies[0]["purl"] == "pkg:pypi/my-package@1.2.0"


def test_scoped_npm_package_has_stable_purl():
    result = generate_ai_bom_v2(
        _model(dependencies=[{"ecosystem": "npm", "name": "@Acme/Runtime", "version": "v2.3.1"}]),
        _context(),
    )

    component = result["components"]["dependencies"][0]
    assert component["name"] == "@acme/runtime"
    assert component["version"] == "2.3.1"
    assert component["purl"] == "pkg:npm/%40acme/runtime@2.3.1"


def test_ranges_and_direct_references_remain_explicitly_unresolved():
    result = generate_ai_bom_v2(
        _model(dependencies=["torch>=2.0", "runtime @ https://example.test/runtime.whl"]),
        _context(),
    )

    assert result["components"]["dependencies"] == []
    assert len(result["components"]["unresolved_dependencies"]) == 2
    assert result["evidence_quality"]["dimensions"]["dependency_inventory"] == 0
    assert result["assessment_complete"] is False


def test_conflicting_versions_are_detected_not_collapsed():
    result = generate_ai_bom_v2(
        _model(dependencies=["torch==2.2.0", "torch==2.3.0"]), _context()
    )

    conflict = result["components"]["conflicting_dependencies"][0]
    assert conflict == {"ecosystem": "PyPI", "name": "torch", "versions": ["2.2.0", "2.3.0"]}
    assert result["assessment_complete"] is False


def test_dependency_inventory_is_bounded(monkeypatch):
    monkeypatch.setattr(mbom_module, "_MAX_DEPENDENCIES", 2)
    result = generate_ai_bom_v2(
        _model(dependencies=["a==1.0", "b==1.0", "c==1.0"]), _context()
    )

    assert len(result["components"]["dependencies"]) == 2
    assert any(item["indicator"] == "dependency_inventory_invalid_or_bounded" for item in result["diagnostics"])
    assert result["assessment_complete"] is False


def test_training_lineage_requires_source_and_digest():
    result = generate_ai_bom_v2(
        _model(training_artifacts=[{"name": "opaque-corpus"}]), _context()
    )

    artifact = result["components"]["training_artifacts"][0]
    assert artifact["evidence_complete"] is False
    assert result["evidence_quality"]["dimensions"]["training_lineage"] == 50
    assert result["assessment_complete"] is False


def test_source_url_credentials_are_removed_without_echoing_secrets():
    model = _model(
        source_url="https://user:model-secret@example.test/model.bin?access_token=query-secret#fragment",
        training_artifacts=[
            {
                "name": "dataset",
                "source_url": "https://token:dataset-secret@data.example.test/corpus",
                "sha256": "b" * 64,
            }
        ],
    )
    result = generate_ai_bom_v2(model, _context())
    serialized = json.dumps(result)

    assert "model-secret" not in serialized
    assert "query-secret" not in serialized
    assert "dataset-secret" not in serialized
    assert result["subject"]["source_url"] == "https://example.test/model.bin"
    assert result["components"]["training_artifacts"][0]["source_url"] == "https://data.example.test/corpus"


def test_deployment_digest_mismatch_is_critical():
    result = generate_ai_bom_v2(
        _model(
            deployment_pipeline={
                "environment": "production",
                "artifact_ref": "registry.test/model@sha256:" + "f" * 64,
                "approval_gate": "CAB-42",
            }
        ),
        _context(),
    )

    deployment = result["components"]["deployment_artifact"]
    assert deployment["integrity_status"] == "MISMATCH"
    assert any(item["indicator"] == "deployment_artifact_hash_mismatch" for item in result["diagnostics"])
    assert result["assessment_complete"] is False


def test_deployment_reference_credentials_are_removed():
    result = generate_ai_bom_v2(
        _model(
            deployment_pipeline={
                "environment": "production",
                "artifact_ref": "robot:registry-secret@registry.test/model@sha256:" + "a" * 64,
                "approval_gate": "CAB-42",
            }
        ),
        _context(),
    )

    serialized = json.dumps(result)
    assert "registry-secret" not in serialized
    assert result["components"]["deployment_artifact"]["artifact_ref"].startswith(
        "registry.test/model@sha256:"
    )


def test_embedded_attestation_verification_is_not_trusted():
    result = generate_ai_bom_v2(_model(), {"generated_at": "2026-06-19T12:00:00Z"})

    assert result["provenance"]["attestation_count"] == 1
    assert result["provenance"]["trusted_verified_count"] == 0
    assert result["provenance"]["attestations"][0]["trusted_verification"] is False
    assert result["evidence_quality"]["dimensions"]["provenance_evidence"] == 50


def test_registry_provenance_attestation_alias_is_inventory_visible():
    model = _model()
    model["provenance_attestations"] = model.pop("attestations")

    result = generate_ai_bom_v2(model, _context())

    assert result["provenance"]["attestation_count"] == 1
    assert result["provenance"]["trusted_verified_count"] == 1


def test_vulnerability_count_mismatch_marks_evidence_partial():
    scan = {
        "assessment_complete": True,
        "match_count": 99,
        "matches": [{"advisory_id": "CVE-1", "severity": "CRITICAL"}],
    }
    result = generate_ai_bom_v2(_model(vulnerability_scan=scan), _context())

    assert result["vulnerability_intelligence"]["status"] == "PARTIAL"
    assert result["vulnerability_intelligence"]["by_severity"]["CRITICAL"] == 1
    assert result["assessment_complete"] is False


def test_dependency_discovery_errors_prevent_complete_assurance():
    model = _model()
    model["metadata"]["dependency_discovery"]["errors"] = [{"manifest": "requirements.txt"}]
    result = generate_ai_bom_v2(model, _context())

    assert result["components"]["dependency_discovery"]["errors_present"] is True
    assert result["assessment_complete"] is False


def test_digest_tampering_is_detected():
    document = generate_ai_bom_v2(_model(), _context())
    document["subject"]["publisher"] = "Attacker Inc"

    result = verify_ai_bom_v2(document)

    assert result["checks"]["digest_matches"] is False
    assert result["verified"] is False


def test_validly_redigested_duplicate_component_ref_is_rejected():
    document = generate_ai_bom_v2(_model(), _context())
    duplicate = copy.deepcopy(document["components"]["dependencies"][0])
    document["components"]["training_artifacts"].append(duplicate)
    _redigest(document)

    result = verify_ai_bom_v2(document)

    assert result["checks"]["digest_matches"] is True
    assert result["checks"]["component_refs_unique"] is False
    assert result["verified"] is False


def test_validly_redigested_dangling_lineage_edge_is_rejected():
    document = generate_ai_bom_v2(_model(), _context())
    document["lineage"]["relationships"][0]["to"] = "model:" + "f" * 64
    _redigest(document)

    result = verify_ai_bom_v2(document)

    assert result["checks"]["digest_matches"] is True
    assert result["checks"]["lineage_endpoints_resolve"] is False
    assert result["verified"] is False


def test_validly_redigested_component_identity_substitution_is_rejected():
    document = generate_ai_bom_v2(_model(), _context())
    document["components"]["dependencies"][0]["version"] = "99.0.0"
    document["lineage"]["nodes"] = [
        copy.deepcopy(document["subject"]),
        *copy.deepcopy(document["components"]["dependencies"]),
        *copy.deepcopy(document["components"]["training_artifacts"]),
        copy.deepcopy(document["components"]["deployment_artifact"]),
    ]
    _redigest(document)

    result = verify_ai_bom_v2(document)

    assert result["checks"]["component_refs_match_content"] is False
    assert result["verified"] is False


def test_validly_redigested_missing_lineage_node_is_rejected():
    document = generate_ai_bom_v2(_model(), _context())
    document["lineage"]["nodes"].pop()
    _redigest(document)

    result = verify_ai_bom_v2(document)

    assert result["checks"]["lineage_nodes_match_components"] is False
    assert result["verified"] is False


def test_validly_redigested_evidence_score_inconsistency_is_rejected():
    document = generate_ai_bom_v2(_model(), _context())
    document["evidence_quality"]["score"] = 7
    _redigest(document)

    result = verify_ai_bom_v2(document)

    assert result["checks"]["evidence_score_consistent"] is False
    assert result["verified"] is False


def test_runtime_components_are_included_in_inventory_and_lineage():
    model = _model(
        tools=["browser", {"name": "shell", "version": "2.0", "manifest_id": "tool-manifest-1"}],
        metadata={
            "dependency_discovery": {
                "manifests": ["requirements.txt", "package-lock.json"],
                "dependency_count": 2,
                "errors": [],
            },
            "prompt_templates": [{"name": "baseline-prompt", "content": "Summarize the incident."}],
            "system_prompt": "You are a secure assistant.",
            "mcp_servers": [{"server_id": "mcp-1", "name": "ACME MCP", "endpoint": "https://mcp.example.test"}],
            "rag_indexes": [{"store_id": "rag-1", "collection_name": "policies", "store_type": "pgvector", "embedding_model": "text-embedding-3-small"}],
            "embedding_model": {"name": "text-embedding-3-small", "provider": "openai"},
            "runtime_provider": {"name": "OpenAI", "service": "responses-api"},
            "guardrails": [{"name": "baseline-guardrail", "provider": "aiaf", "mode": "block"}],
            "agent_policy_profile": "restricted",
            "evaluators": [{"name": "frontier-harness", "version": "2.0", "scope": "dangerous-capability"}],
        },
    )

    result = generate_ai_bom_v2(model, _context())

    runtime_components = result["components"]["runtime_components"]
    runtime_types = {component["type"] for component in runtime_components}
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
    assert all(edge["relationship"] != "runtime_component_for" or edge["to"] == result["subject"]["bom_ref"] for edge in result["lineage"]["relationships"])
    assert verify_ai_bom_v2(result)["verified"] is True


def test_runtime_prompt_content_is_hashed_not_embedded():
    result = generate_ai_bom_v2(
        _model(
            metadata={
                "dependency_discovery": {
                    "manifests": ["requirements.txt", "package-lock.json"],
                    "dependency_count": 2,
                    "errors": [],
                },
                "prompt_templates": [{"name": "secret-prompt", "content": "Never reveal token 12345."}],
                "system_prompt": "Internal system policy: do not disclose config.",
            }
        ),
        _context(),
    )

    serialized = json.dumps(result)
    assert "Never reveal token 12345." not in serialized
    assert "Internal system policy: do not disclose config." not in serialized
    runtime_types = {component["type"] for component in result["components"]["runtime_components"]}
    assert "prompt" in runtime_types
    assert "system-prompt-hash" in runtime_types

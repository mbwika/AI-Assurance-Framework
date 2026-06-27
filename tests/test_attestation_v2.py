import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.registry.attestation_v2 as attestation_module  # noqa: E402
from aiaf.registry.attestation_v2 import (  # noqa: E402
    PROVENANCE_ATTESTATION_ALGORITHM,
    PROVENANCE_ATTESTATION_SCHEMA_VERSION,
    PROVENANCE_PREDICATE_TYPE,
    PROVENANCE_STATEMENT_TYPE,
    create_provenance_attestation_v2,
    verify_provenance_attestation_v2,
)


KEY = "0123456789abcdef" * 4
OTHER_KEY = "fedcba9876543210" * 4
ATTESTATION_ID = "attestation-2026-0001"
ISSUED = "2026-06-19T12:00:00Z"
AS_OF = "2026-06-19T12:01:00Z"
EXPIRES = "2026-06-20T12:00:00Z"


def _model(**overrides):
    revision = "b" * 40
    model = {
        "model_id": "model-1",
        "model_name": "Acme Safety Model",
        "version": "1.2.0",
        "source": "huggingface",
        "source_url": f"https://huggingface.co/acme/model/resolve/{revision}/model.bin",
        "publisher": "Acme AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "dependencies": ["transformers==4.40.0", "torch==2.3.0"],
        "training_artifacts": [
            {
                "name": "curated-corpus",
                "source_url": "https://data.example.test/corpus.jsonl",
                "sha256": "c" * 64,
            }
        ],
        "deployment_pipeline": {
            "environment": "production",
            "artifact_ref": "registry.example.test/acme/model@sha256:" + "a" * 64,
            "approval_gate": "CAB-42",
        },
        "source_metadata": {
            "provider": "huggingface",
            "organization": "acme",
            "repository": "model",
            "revision": revision,
        },
        "provenance_score": 72,
        "risk_level": "MEDIUM",
        "metadata": {},
    }
    model.update(overrides)
    return model


def _attestation(model=None, **overrides):
    kwargs = {
        "model_record": model or _model(),
        "signing_key": KEY,
        "attestation_id": ATTESTATION_ID,
        "key_id": "provenance-key-2026-01",
        "issuer": "aiaf:model-registry:production",
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "as_of": AS_OF,
    }
    kwargs.update(overrides)
    return create_provenance_attestation_v2(**kwargs)


def _policy(**overrides):
    policy = {
        "expected_attestation_id": ATTESTATION_ID,
        "expected_key_id": "provenance-key-2026-01",
        "expected_issuer": "aiaf:model-registry:production",
        "as_of": AS_OF,
    }
    policy.update(overrides)
    return policy


def _verify(attestation, model=None, key=KEY, **policy_overrides):
    return verify_provenance_attestation_v2(
        attestation, key, model or _model(), _policy(**policy_overrides)
    )


def _resign(attestation, key=KEY, domain_separated=True):
    statement, error = attestation_module._canonical_json(attestation["statement"])
    assert error is None
    if domain_separated:
        signature = attestation_module._sign(statement, key.encode("utf-8"))
    else:
        signature = hmac.new(key.encode("utf-8"), statement, hashlib.sha256).hexdigest()
    attestation["signature"] = signature
    return attestation


def test_valid_attestation_is_deterministic_versioned_and_json_safe():
    model = _model()
    attestation = _attestation(model)

    first = _verify(attestation, model)
    second = _verify(attestation, model)

    assert first == second
    assert first["verified"] is True
    assert first["cryptographically_valid"] is True
    assert first["subject_binding_verified"] is True
    assert first["assurance_level"] == "SYMMETRIC_AUTHENTICATED"
    assert first["scoring_version"] == PROVENANCE_ATTESTATION_SCHEMA_VERSION == "2.0"
    assert attestation["algorithm"] == PROVENANCE_ATTESTATION_ALGORITHM
    assert attestation["statement"]["statement_type"] == PROVENANCE_STATEMENT_TYPE
    assert attestation["statement"]["predicate"]["predicate_type"] == PROVENANCE_PREDICATE_TYPE
    assert len(first["attestation_sha256"]) == 64
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_statement_tampering_invalidates_signature():
    attestation = _attestation()
    attestation["statement"]["subject"]["model_id"] = "attacker-model"

    result = _verify(attestation)

    assert result["checks"]["signature_valid"] is False
    assert result["checks"]["model_id_matches"] is False
    assert result["verified"] is False


def test_validly_resigned_subject_substitution_fails_registry_binding():
    attestation = _attestation()
    attestation["statement"]["subject"]["model_id"] = "attacker-model"
    _resign(attestation)

    result = _verify(attestation)

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["model_id_matches"] is False
    assert result["subject_binding_verified"] is False
    assert result["verified"] is False


def test_model_name_version_and_artifact_digest_are_independently_bound():
    for path, replacement, failed_check in (
        (("model_name",), "Other Model", "model_name_matches"),
        (("version",), "9.9.9", "version_matches"),
        (("artifact_digest", "value"), "d" * 64, "artifact_hash_matches"),
    ):
        attestation = _attestation()
        target = attestation["statement"]["subject"]
        if len(path) == 1:
            target[path[0]] = replacement
        else:
            target[path[0]][path[1]] = replacement
        _resign(attestation)
        result = _verify(attestation)
        assert result["checks"]["signature_valid"] is True
        assert result["checks"][failed_check] is False


def test_source_publisher_and_revision_are_independently_bound():
    replacements = {
        "provider": ("github", "source_matches"),
        "url": ("https://github.com/acme/model", "source_matches"),
        "publisher": ("Attacker Inc", "publisher_matches"),
        "revision": ("e" * 40, "revision_matches"),
    }
    for field, (replacement, failed_check) in replacements.items():
        attestation = _attestation()
        attestation["statement"]["predicate"]["source"][field] = replacement
        _resign(attestation)
        result = _verify(attestation)
        assert result["checks"]["signature_valid"] is True
        assert result["checks"][failed_check] is False


def test_dependency_training_and_deployment_changes_break_specific_bindings():
    changes = (
        ({"dependencies": ["transformers==99.0.0"]}, "dependency_inventory_matches"),
        ({"training_artifacts": [{"name": "unknown", "sha256": "f" * 64}]}, "training_lineage_matches"),
        ({"deployment_pipeline": {"environment": "unapproved"}}, "deployment_pipeline_matches"),
    )
    attestation = _attestation()
    for override, failed_check in changes:
        changed_model = _model(**override)
        result = _verify(attestation, changed_model)
        assert result["checks"]["signature_valid"] is True
        assert result["checks"][failed_check] is False
        assert result["checks"]["model_manifest_matches"] is False


def test_ai_bom_and_composite_manifest_ignore_derived_risk_but_bind_license():
    attestation = _attestation()
    derived_change = _model(provenance_score=45, risk_level="CRITICAL")
    material_change = _model(license="proprietary")

    derived_result = _verify(attestation, derived_change)
    material_result = _verify(attestation, material_change)

    assert derived_result["checks"]["signature_valid"] is True
    assert derived_result["checks"]["mbom_hash_matches"] is True
    assert derived_result["checks"]["model_manifest_matches"] is True
    assert material_result["checks"]["mbom_hash_matches"] is False
    assert material_result["checks"]["model_manifest_matches"] is False


def test_attestation_commits_to_ai_bom_v2_document_digest():
    model = _model()
    document, error = attestation_module._attestable_ai_bom(model)
    attestation = _attestation(model)

    assert error is None
    assert document["bom_format"] == "AIAF AI-BOM"
    assert document["spec_version"] == "2.0"
    assert attestation_module.verify_ai_bom_v2(document)["verified"] is True
    assert (
        attestation["statement"]["predicate"]["mbom_sha256"]
        == document["document_sha256"]
    )


def test_persisting_attestation_and_detached_verification_is_not_self_referential():
    model = _model()
    attestation = _attestation(model)
    persisted = copy.deepcopy(model)
    persisted["attestations"] = [attestation]
    persisted["provenance_attestations"] = [attestation]
    persisted["metadata"] = {
        "attestations": [attestation],
        "provenance_attestations": [attestation],
        "provenance_attestation_verifications": [
            {
                "attestation_id": ATTESTATION_ID,
                "verified": True,
                "attestation_sha256": "f" * 64,
            }
        ],
    }

    result = _verify(attestation, persisted)

    assert result["verified"] is True
    assert result["checks"]["mbom_hash_matches"] is True
    assert result["checks"]["model_manifest_matches"] is True


def test_ai_bom_binding_covers_vulnerability_and_discovery_evidence():
    attestation = _attestation()
    changed = _model(
        vulnerability_scan={
            "assessment_complete": True,
            "match_count": 1,
            "matches": [
                {"advisory_id": "CVE-2026-9999", "severity": "CRITICAL"}
            ],
        },
        metadata={
            "dependency_discovery": {
                "manifests": ["requirements.txt"],
                "dependency_count": 2,
                "errors": [{"manifest": "requirements.txt"}],
            }
        },
    )

    result = _verify(attestation, changed)

    assert result["checks"]["dependency_inventory_matches"] is True
    assert result["checks"]["mbom_hash_matches"] is False
    assert result["checks"]["model_manifest_matches"] is False


def test_wrong_key_and_weak_keys_fail_cryptographic_assurance():
    attestation = _attestation()

    wrong = _verify(attestation, key=OTHER_KEY)
    assert wrong["checks"]["signing_key_strong"] is True
    assert wrong["checks"]["signature_valid"] is False
    for key in ("", "short", "a" * 64, None):
        weak = _verify(attestation, key=key)
        assert weak["checks"]["signing_key_strong"] is False
        assert weak["checks"]["signature_valid"] is False


def test_domain_separation_rejects_raw_hmac_from_another_protocol():
    attestation = _attestation()
    _resign(attestation, domain_separated=False)

    result = _verify(attestation)

    assert result["checks"]["signature_shape_valid"] is True
    assert result["checks"]["signature_valid"] is False


def test_valid_mac_under_wrong_policy_identity_is_unverified():
    attestation = _attestation()

    result = _verify(
        attestation,
        expected_attestation_id="attestation-expected-other",
        expected_key_id="other-key",
        expected_issuer="aiaf:other-registry",
    )

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["attestation_id_matches_policy"] is False
    assert result["checks"]["key_id_matches"] is False
    assert result["checks"]["issuer_matches_policy"] is False


def test_missing_policy_or_expected_model_fails_without_exceptions():
    attestation = _attestation()

    missing_policy = verify_provenance_attestation_v2(
        attestation, KEY, _model(), None
    )
    missing_model = verify_provenance_attestation_v2(
        attestation, KEY, None, _policy()
    )

    assert missing_policy["verified"] is False
    assert missing_policy["checks"]["verification_policy_complete"] is False
    assert missing_model["verified"] is False
    assert missing_model["checks"]["expected_model_valid"] is False


def test_malformed_attestation_roots_fail_closed():
    for value in (None, "attestation", [], 7):
        result = verify_provenance_attestation_v2(
            value, KEY, _model(), _policy()
        )
        assert result["verified"] is False
        assert result["checks"]["attestation_is_object"] is False


def test_unsigned_extension_fields_are_rejected():
    envelope_extension = _attestation()
    envelope_extension["verification"] = {"verified": True}
    statement_extension = _attestation()
    statement_extension["statement"]["untrusted"] = True
    _resign(statement_extension)

    envelope_result = _verify(envelope_extension)
    statement_result = _verify(statement_extension)

    assert envelope_result["checks"]["signature_valid"] is True
    assert envelope_result["checks"]["strict_envelope_fields"] is False
    assert statement_result["checks"]["signature_valid"] is True
    assert statement_result["checks"]["statement_shape_valid"] is False


def test_cross_protocol_statement_and_algorithm_confusion_are_rejected():
    wrong_type = _attestation()
    wrong_type["statement"]["statement_type"] = (
        "https://aiaf.dev/advisory-feed/v2"
    )
    _resign(wrong_type)
    wrong_algorithm = _attestation()
    wrong_algorithm["algorithm"] = "none"

    type_result = _verify(wrong_type)
    algorithm_result = _verify(wrong_algorithm)

    assert type_result["checks"]["signature_valid"] is True
    assert type_result["checks"]["statement_type_supported"] is False
    assert algorithm_result["checks"]["supported_algorithm"] is False


def test_naive_future_stale_expired_and_overlong_timestamps_fail_policy():
    naive = _attestation()
    naive["statement"]["issued_at"] = "2026-06-19T12:00:00"
    _resign(naive)
    valid = _attestation()
    future = _verify(valid, as_of="2026-06-19T00:00:00Z")
    stale = _verify(valid, as_of="2026-06-21T11:59:59Z")
    expired = _verify(valid, as_of="2026-06-20T12:00:01Z")
    overlong = _attestation()
    overlong["statement"]["expires_at"] = "2026-08-01T12:00:00Z"
    _resign(overlong)

    assert _verify(naive)["checks"]["issued_at_valid"] is False
    assert future["checks"]["issued_at_not_future"] is False
    assert stale["checks"]["attestation_fresh"] is False
    assert expired["checks"]["attestation_not_expired"] is False
    assert _verify(overlong)["checks"]["lifetime_within_policy"] is False


def test_signature_and_digest_shapes_are_strict_lowercase_hex():
    signature = _attestation()
    signature["signature"] = signature["signature"].upper()
    digest = _attestation()
    digest["statement"]["predicate"]["mbom_sha256"] = "A" * 64
    _resign(digest)

    assert _verify(signature)["checks"]["signature_shape_valid"] is False
    digest_result = _verify(digest)
    assert digest_result["checks"]["signature_valid"] is True
    assert digest_result["checks"]["evidence_digests_valid"] is False
    assert digest_result["checks"]["mbom_hash_matches"] is False


def test_sha256_prefix_is_normalized_when_creating_subject():
    model = _model(sha256="sha256:" + "a" * 64)

    attestation = _attestation(model)
    result = _verify(attestation, model)

    assert result["verified"] is True
    assert attestation["statement"]["subject"]["artifact_digest"]["value"] == "a" * 64


def test_float_cycle_and_excessive_depth_model_evidence_fail_closed():
    floating = _model(dependencies=[{"name": "package", "score": 1.5}])
    with pytest.raises(ValueError, match="canonical subset"):
        _attestation(floating)

    cyclic_dependencies = []
    cyclic_dependencies.append(cyclic_dependencies)
    cyclic = _model(dependencies=cyclic_dependencies)
    with pytest.raises(ValueError, match="reference cycle"):
        _attestation(cyclic)

    nested = {}
    cursor = nested
    for _ in range(30):
        child = {}
        cursor["child"] = child
        cursor = child
    deep = _model(deployment_pipeline=nested)
    with pytest.raises(ValueError, match="nesting bound"):
        _attestation(deep)


def test_verification_result_does_not_echo_key_or_model_evidence():
    secret_marker = "never-echo-this-key-material"
    key = (secret_marker + "0123456789abcdef") * 3
    model = _model(source_url="https://user:credential@example.test/model")
    attestation = _attestation(model, signing_key=key)

    result = _verify(attestation, model, key=key)
    serialized = json.dumps(result)

    assert result["verified"] is True
    assert secret_marker not in serialized
    assert "credential" not in serialized


def test_creator_rejects_incomplete_model_weak_key_and_bad_policy():
    with pytest.raises(ValueError, match="Model evidence"):
        _attestation(_model(publisher=""))
    with pytest.raises(ValueError, match="Model evidence"):
        _attestation(_model(model_name="unsafe\nlog-entry"))
    with pytest.raises(ValueError, match="32 bytes"):
        _attestation(signing_key="short")
    with pytest.raises(ValueError, match="Invalid provenance attestation"):
        _attestation(as_of="not-a-time")

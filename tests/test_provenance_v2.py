import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from aiaf.registry.attestation import (  # noqa: E402
    create_provenance_attestation,
    verify_provenance_attestation,
)
from aiaf.registry.provenance_v2 import (  # noqa: E402
    PROVENANCE_SCORING_VERSION,
    assess_provenance_v2,
    determine_provenance_risk,
)


DIGEST = "a" * 64
REVISION = "b" * 40
SIGNING_KEY = "test-only-signing-key"
KEY_ID = "test-key"


def _record():
    source_url = (
        "https://huggingface.co/acme/model/resolve/"
        f"{REVISION}/model.safetensors"
    )
    return {
        "model_id": "model-1",
        "model_name": "Acme Model",
        "version": "1.0.0",
        "source": "huggingface",
        "source_url": source_url,
        "publisher": "Acme AI",
        "sha256": DIGEST,
        "license": "apache-2.0",
        "training_data": "documented curated corpus",
        "training_artifacts": [
            {
                "name": "training-corpus",
                "source_url": "https://data.example.test/corpus.jsonl",
                "sha256": "c" * 64,
            }
        ],
        "dependencies": ["transformers==4.40.0", "torch==2.3.0"],
        "model_card": ["model-card.md"],
        "source_metadata": {
            "provider": "huggingface",
            "organization": "acme",
            "repository": "model",
            "source_url": source_url,
            "revision": REVISION,
            "retrieval_time": "2026-06-01T00:00:00Z",
        },
        "dependency_discovery": {
            "manifests": ["requirements.txt"],
            "dependency_count": 2,
            "errors": [],
        },
        "mbom": {"bom_format": "AIAF AI-BOM"},
        "deployment_pipeline": {
            "environment": "production",
            "artifact_ref": f"registry.example.test/acme/model@sha256:{DIGEST}",
            "approval_gate": "CAB-42",
        },
    }


def _context(record, *, include_attestation=True):
    trusted = {
        "source_identity": {
            "verified": True,
            "checks": {"identity_matches": True, "source_matches": True},
        },
        "publisher_identity": {
            "verified": True,
            "checks": {"publisher_matches": True, "identity_verified": True},
            "organization": "Acme AI",
            "publisher": "Acme AI",
        },
        "artifact_integrity": {
            "verified": True,
            "hash_matches": True,
            "observed_sha256": DIGEST,
            "expected_sha256": DIGEST,
        },
        "release": {
            "verified": True,
            "checks": {"artifact_matches": True, "signature_valid": True},
        },
    }
    if include_attestation:
        attestation = create_provenance_attestation(record, SIGNING_KEY, KEY_ID)
        verification = verify_provenance_attestation(
            attestation,
            SIGNING_KEY,
            expected_model=record,
            expected_key_id=KEY_ID,
        )
        record["provenance_attestations"] = [attestation]
        trusted["provenance_attestations"] = [verification]
    return {
        "as_of": "2026-06-19T00:00:00Z",
        "max_source_age_days": 365,
        "trusted_evidence": trusted,
    }


def _assess(record=None, context=None):
    record = _record() if record is None else record
    context = _context(record) if context is None else context
    return assess_provenance_v2(record, context)


def _indicators(result):
    return set(result["indicators"])


def _caps(result):
    return {gate["gate"]: gate["maximum_score"] for gate in result["trust_caps"]}


def test_verified_evidence_is_low_risk_deterministic_and_json_safe():
    record = _record()
    context = _context(record)

    first = assess_provenance_v2(record, context)
    second = assess_provenance_v2(record, context)

    assert first == second
    assert first["scoring_version"] == PROVENANCE_SCORING_VERSION == "2.0"
    assert first["risk_level"] == "LOW"
    assert 85 <= first["provenance_score"] <= first["point_estimate"] <= 100
    assert first["lower_confidence_bound"] == first["provenance_score"]
    assert first["point_estimate"] <= first["upper_confidence_bound"] <= 100
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_malformed_record_fails_closed():
    result = assess_provenance_v2("not-an-object")

    assert result["assessment_complete"] is False
    assert result["provenance_score"] <= 10
    assert result["risk_level"] == "CRITICAL"
    assert "malformed_model_record" in _indicators(result)


def test_caller_supplied_score_and_embedded_verifications_are_ignored():
    spoofed = _record()
    spoofed["provenance_score"] = 100
    spoofed["source_identity_verification"] = True
    spoofed["publisher_identity_verification"] = True
    spoofed["integrity_verification"] = {
        "verified": True,
        "observed_sha256": DIGEST,
    }

    result = assess_provenance_v2(spoofed, {"as_of": "2026-06-19T00:00:00Z"})

    assert result["evidence"]["caller_score_ignored"] is True
    assert result["provenance_score"] <= 75
    assert result["risk_level"] != "LOW"
    assert {"no_verified_signed_provenance", "publisher_identity_not_verified"} <= set(_caps(result))


def test_partial_trusted_checklists_receive_no_verification_credit():
    record = _record()
    context = _context(record, include_attestation=False)
    context["trusted_evidence"]["source_identity"]["checks"] = {
        "identity_matches": True
    }

    result = assess_provenance_v2(record, context)

    assert result["dimensions"]["source_identity"]["checks"][-1]["satisfied"] is False
    assert "source_identity_not_verified" in _caps(result)


def test_missing_malformed_and_mismatched_hashes_apply_fail_closed_caps():
    missing = _record()
    missing.pop("sha256")
    malformed = _record()
    malformed["sha256"] = "abc"
    mismatch = _record()
    mismatch_context = _context(mismatch, include_attestation=False)
    mismatch_context["trusted_evidence"]["artifact_integrity"] = {
        "verified": False,
        "hash_matches": False,
        "observed_sha256": "d" * 64,
        "expected_sha256": DIGEST,
    }

    missing_result = assess_provenance_v2(missing, _context(missing, include_attestation=False))
    malformed_result = assess_provenance_v2(malformed, _context(malformed, include_attestation=False))
    mismatch_result = assess_provenance_v2(mismatch, mismatch_context)

    assert missing_result["provenance_score"] <= 35
    assert malformed_result["provenance_score"] <= 20
    assert mismatch_result["provenance_score"] == 0
    assert "artifact_integrity_mismatch" in _indicators(mismatch_result)


def test_unsigned_attestation_shape_cannot_claim_cryptographic_credit():
    record = _record()
    record["provenance_attestations"] = [
        create_provenance_attestation(record, SIGNING_KEY, KEY_ID)
    ]
    context = _context(record, include_attestation=False)
    record["provenance_attestations"][0]["verification"] = {
        "verified": True,
        "checks": {check: True for check in ("signature_valid", "model_id_matches")},
    }

    result = assess_provenance_v2(record, context)

    checks = result["dimensions"]["signed_attestation"]["checks"]
    assert checks[0]["satisfied"] is True
    assert checks[1]["satisfied"] is True
    assert checks[2]["satisfied"] is False
    assert result["provenance_score"] <= 75


def test_failed_attestation_verification_caps_trust():
    record = _record()
    context = _context(record)
    context["trusted_evidence"]["provenance_attestations"][0] = {
        "verified": False,
        "checks": {"signature_valid": False},
    }

    result = assess_provenance_v2(record, context)

    assert result["provenance_score"] <= 25
    assert "failed_provenance_attestation_verification" in _indicators(result)


def test_attestation_subject_and_artifact_mismatch_apply_critical_caps():
    wrong_subject = _record()
    wrong_subject_context = _context(wrong_subject)
    wrong_subject["provenance_attestations"][0]["statement"]["subject"]["model_id"] = "other"
    wrong_hash = _record()
    wrong_hash_context = _context(wrong_hash)
    wrong_hash["provenance_attestations"][0]["statement"]["subject"]["sha256"] = "e" * 64

    subject_result = assess_provenance_v2(wrong_subject, wrong_subject_context)
    hash_result = assess_provenance_v2(wrong_hash, wrong_hash_context)

    assert subject_result["provenance_score"] <= 10
    assert "attestation_subject_mismatch" in _indicators(subject_result)
    assert hash_result["provenance_score"] == 0
    assert "attestation_artifact_hash_mismatch" in _indicators(hash_result)


def test_conflicting_attestations_are_detected_even_when_shapes_are_valid():
    record = _record()
    context = _context(record)
    conflicting = copy.deepcopy(record["provenance_attestations"][0])
    conflicting["statement"]["predicate"]["mbom_sha256"] = "f" * 64
    record["provenance_attestations"].append(conflicting)
    context["trusted_evidence"]["provenance_attestations"].append(
        context["trusted_evidence"]["provenance_attestations"][0]
    )

    result = assess_provenance_v2(record, context)

    assert result["provenance_score"] <= 10
    assert "conflicting_provenance_attestations" in _indicators(result)


def test_source_provider_and_tracking_contradictions_apply_caps():
    provider_mismatch = _record()
    provider_mismatch["source"] = "github"
    tracking_mismatch = _record()
    tracking_mismatch["source_metadata"]["provider"] = "github"

    provider_result = _assess(provider_mismatch, _context(provider_mismatch))
    tracking_result = _assess(tracking_mismatch, _context(tracking_mismatch))

    assert provider_result["provenance_score"] <= 45
    assert "source_provider_mismatch" in _indicators(provider_result)
    assert tracking_result["provenance_score"] <= 45
    assert "source_tracking_provider_mismatch" in _indicators(tracking_result)


def test_credential_bearing_url_is_capped_without_secret_echo():
    record = _record()
    secret = "super-secret-token"
    record["source_url"] = f"https://user:{secret}@huggingface.co/acme/model"

    result = assess_provenance_v2(record, _context(record))

    assert result["provenance_score"] <= 20
    assert result["evidence"]["source_host"] == "huggingface.co"
    assert secret not in json.dumps(result)


def test_verified_identity_integrity_and_immutable_revision_improve_score():
    weak_record = _record()
    weak_record["source_metadata"].pop("revision")
    weak_record["source_url"] = "https://huggingface.co/acme/model/model.safetensors"
    weak_record["source_metadata"]["source_url"] = weak_record["source_url"]
    weak_context = {
        "as_of": "2026-06-19T00:00:00Z",
        "trusted_evidence": {},
    }
    strong_record = _record()

    weak = assess_provenance_v2(weak_record, weak_context)
    strong = assess_provenance_v2(strong_record, _context(strong_record))

    assert strong["provenance_score"] > weak["provenance_score"]
    assert strong["confidence"] > weak["confidence"]


def test_training_lineage_coverage_is_monotonic():
    partial = _record()
    partial["training_artifacts"].append({"name": "unknown-corpus"})
    full = copy.deepcopy(partial)
    full["training_artifacts"][1].update(
        {"source_url": "https://data.example.test/second", "sha256": "d" * 64}
    )

    partial_result = assess_provenance_v2(partial, _context(partial))
    full_result = assess_provenance_v2(full, _context(full))

    assert full_result["dimensions"]["training_lineage"]["score"] > partial_result["dimensions"]["training_lineage"]["score"]
    assert full_result["provenance_score"] >= partial_result["provenance_score"]


def test_bounded_collections_mark_assessment_incomplete():
    dependencies = _record()
    dependencies["dependencies"] = [f"pkg{i}==1.0" for i in range(2_001)]
    attestations = _record()
    valid = create_provenance_attestation(attestations, SIGNING_KEY, KEY_ID)
    attestations["provenance_attestations"] = [valid] * 101

    dependency_result = assess_provenance_v2(dependencies, _context(dependencies))
    attestation_result = assess_provenance_v2(
        attestations, _context(attestations, include_attestation=False)
    )

    assert dependency_result["assessment_complete"] is False
    assert dependency_result["evidence_quality"]["dependency_count"] == 2_000
    assert "dependency_inventory_limit_exceeded" in _indicators(dependency_result)
    assert attestation_result["assessment_complete"] is False
    assert "attestation_analysis_limit_exceeded" in _indicators(attestation_result)


def test_deployment_digest_mismatch_invalidates_release_provenance():
    record = _record()
    record["deployment_pipeline"]["artifact_ref"] = (
        "registry.example.test/acme/model@sha256:" + "f" * 64
    )

    result = assess_provenance_v2(record, _context(record))

    assert result["provenance_score"] <= 5
    assert "deployment_artifact_hash_mismatch" in _indicators(result)


def test_freshness_policy_is_deterministic_and_stale_evidence_cannot_be_low_risk():
    fresh_record = _record()
    stale_record = _record()
    stale_record["source_metadata"]["retrieval_time"] = "2024-01-01T00:00:00Z"
    context = _context(fresh_record)

    fresh = assess_provenance_v2(fresh_record, context)
    stale = assess_provenance_v2(stale_record, _context(stale_record))

    assert fresh == assess_provenance_v2(fresh_record, context)
    assert stale["provenance_score"] <= 75
    assert stale["risk_level"] != "LOW"
    assert "stale_source_evidence" in _indicators(stale)


def test_future_and_malformed_time_contexts_fail_conservatively():
    future = _record()
    future["source_metadata"]["retrieval_time"] = "2027-01-01T00:00:00Z"
    malformed = _record()
    malformed_context = _context(malformed)
    malformed_context["as_of"] = "yesterday-ish"

    future_result = assess_provenance_v2(future, _context(future))
    malformed_result = assess_provenance_v2(malformed, malformed_context)

    assert future_result["provenance_score"] <= 40
    assert "future_source_retrieval_time" in _indicators(future_result)
    assert malformed_result["assessment_complete"] is False
    assert "malformed_provenance_context" in _indicators(malformed_result)


def test_risk_mapper_handles_boundaries_and_non_finite_values():
    assert determine_provenance_risk(85) == "LOW"
    assert determine_provenance_risk(70) == "MEDIUM"
    assert determine_provenance_risk(50) == "HIGH"
    assert determine_provenance_risk(49.99) == "CRITICAL"
    assert determine_provenance_risk(float("nan")) == "CRITICAL"
    assert determine_provenance_risk(float("inf")) == "CRITICAL"
    assert determine_provenance_risk("invalid") == "CRITICAL"

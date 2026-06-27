import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from aiaf.analysis.supply_chain import (  # noqa: E402
    SUPPLY_CHAIN_SCORING_VERSION,
    analyze_dependency_risks,
    analyze_dependency_vulnerabilities,
    analyze_deployment_pipeline_risks,
    analyze_provenance_attestation_risks,
    analyze_training_artifact_risks,
    validate_supply_chain,
)
from aiaf.registry.attestation import (  # noqa: E402
    create_provenance_attestation,
    verify_provenance_attestation,
)
from aiaf.registry.attestation_v2 import (  # noqa: E402
    create_provenance_attestation_v2,
    verify_provenance_attestation_v2,
)


V2_KEY = "0123456789abcdef" * 4
V2_ISSUED = "2026-06-20T12:00:00Z"
V2_AS_OF = "2026-06-20T12:01:00Z"
V2_EXPIRES = "2026-06-21T12:00:00Z"


def _indicators(risks):
    return {risk["indicator"] for risk in risks}


def _complete_artifact():
    digest = "a" * 64
    artifact = {
        "model_id": "model-1",
        "model_name": "assured-model",
        "version": "1.0.0",
        "source": "internal-registry",
        "source_url": "https://registry.example.test/models/assured-model",
        "publisher": "Example AI",
        "sha256": digest,
        "license": "apache-2.0",
        "dependencies": [
            {
                "name": "requests",
                "version": "==2.31.0",
                "ecosystem": "pypi",
                "sha256": "b" * 64,
            }
        ],
        "training_artifacts": [
            {
                "name": "curated-data",
                "source_url": "https://data.example.test/curated-data.jsonl",
                "sha256": "c" * 64,
            }
        ],
        "deployment_pipeline": {
            "environment": "production",
            "artifact_ref": f"registry.example.test/assured-model@sha256:{digest}",
            "approval_gate": "CAB-123",
            "deployed_by": "release-bot",
            "approved_by": "release-manager",
        },
        "vulnerability_scan": {
            "status": "COMPLETE",
            "dependency_count": 1,
            "scanned_dependency_count": 1,
            "unresolved_dependencies": [],
            "matches": [],
            "match_count": 0,
        },
    }
    attestation = create_provenance_attestation(artifact, "signing-key", "key-1")
    attestation["verification"] = verify_provenance_attestation(
        attestation,
        "signing-key",
        expected_model=artifact,
        expected_key_id="key-1",
    )
    artifact["provenance_attestations"] = [attestation]
    return artifact


def _v2_attestation(artifact, attestation_id="attestation-v2-0001"):
    attestation = create_provenance_attestation_v2(
        artifact,
        V2_KEY,
        attestation_id=attestation_id,
        key_id="provenance-key-v2",
        issuer="aiaf:model-registry:test",
        issued_at=V2_ISSUED,
        expires_at=V2_EXPIRES,
        as_of=V2_AS_OF,
    )
    verification = verify_provenance_attestation_v2(
        attestation,
        V2_KEY,
        artifact,
        {
            "expected_attestation_id": attestation_id,
            "expected_key_id": "provenance-key-v2",
            "expected_issuer": "aiaf:model-registry:test",
            "as_of": V2_AS_OF,
        },
    )
    assert verification["verified"] is True
    return attestation, verification


def test_complete_verified_evidence_is_zero_risk_and_versioned():
    artifact = _complete_artifact()

    first = validate_supply_chain(artifact)
    second = validate_supply_chain(artifact)

    assert first == second
    assert first["valid"] is True
    assert first["risk_score"] == 0
    assert first["severity"] == "LOW"
    assert first["indicators"] == []
    assert first["assessment_complete"] is True
    assert first["scoring_version"] == SUPPLY_CHAIN_SCORING_VERSION == "2.0"
    assert first["evidence_quality"]["coverage_ratio"] == 1.0
    assert first["evidence_quality"]["verified_attestation"] is True
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_malformed_root_and_metadata_fail_closed():
    malformed_root = validate_supply_chain("not-an-object")
    malformed_metadata = validate_supply_chain({"metadata": ["not-an-object"]})

    assert malformed_root["assessment_complete"] is False
    assert "malformed_supply_chain_artifact" in malformed_root["indicators"]
    assert malformed_metadata["assessment_complete"] is False
    assert "malformed_supply_chain_metadata" in malformed_metadata["indicators"]


def test_dependency_pinning_is_ecosystem_aware():
    risks = analyze_dependency_risks(
        [
            "requests==2.31.0",
            {
                "name": "lodash",
                "version": "4.17.21",
                "ecosystem": "npm",
                "sha256": "a" * 64,
            },
        ]
    )

    assert risks == []


def test_wildcard_and_prerelease_are_not_treated_as_stable_exact_pins():
    risks = analyze_dependency_risks(
        ["requests==2.*", "transformers==4.40.0rc1"]
    )
    indicators = _indicators(risks)

    assert "wildcard_dependency" in indicators
    assert "unpinned_dependency" in indicators
    assert "pre_release_dependency" in indicators


def test_vcs_dependency_requires_full_immutable_commit():
    mutable = analyze_dependency_risks(
        ["weights @ git+https://git.example.test/weights.git@main"]
    )
    immutable = analyze_dependency_risks(
        [f"weights @ git+https://git.example.test/weights.git@{'a' * 40}"]
    )

    assert "mutable_vcs_dependency" in _indicators(mutable)
    assert "mutable_vcs_dependency" not in _indicators(immutable)
    assert "direct_url_dependency" in _indicators(immutable)


def test_dependency_urls_detect_transport_and_embedded_credentials():
    risks = analyze_dependency_risks(
        ["weights @ http://build-user:secret@packages.example.test/weights.whl"]
    )

    assert {
        "insecure_dependency_source",
        "dependency_url_contains_credentials",
    }.issubset(_indicators(risks))
    assert "secret" not in json.dumps(risks)
    assert "<redacted>@" in json.dumps(risks)


def test_conflicting_exact_dependency_versions_are_detected():
    risks = analyze_dependency_risks(
        ["requests==2.31.0", "Requests==2.32.0"]
    )

    conflict = next(
        risk for risk in risks if risk["indicator"] == "dependency_version_conflict"
    )
    assert conflict["severity"] == "HIGH"
    assert conflict["dependency"]["versions"] == ["2.31.0", "2.32.0"]


def test_dependency_analysis_is_bounded_and_reports_incomplete_coverage():
    risks = analyze_dependency_risks(
        [f"package-{index}==1.0.0" for index in range(2_001)]
    )

    limit = next(
        risk for risk in risks if risk["indicator"] == "dependency_analysis_limit_exceeded"
    )
    assert limit["dependency"] == {"provided": 2_001, "analyzed": 2_000}


def test_dependency_finding_amplification_is_bounded():
    dependencies = [
        {
            "name": f"package-{index}",
            "version": "*",
            "source": f"http://user:secret@packages.example.test/{index}",
        }
        for index in range(2_000)
    ]

    risks = analyze_dependency_risks(dependencies)

    assert len(risks) == 2_000
    assert risks[-1]["indicator"] == "supply_chain_risk_limit_exceeded"
    assert "secret" not in json.dumps(risks)


def test_training_lineage_detects_mutable_revision_and_conflicting_digests():
    risks = analyze_training_artifact_risks(
        [
            {
                "name": "training-set",
                "source": "git+https://git.example.test/data.git",
                "source_type": "git",
                "revision": "main",
                "sha256": "a" * 64,
            },
            {
                "name": "training set",
                "source_url": "https://data.example.test/training-set",
                "sha256": "b" * 64,
            },
        ]
    )

    assert {
        "training_artifact_unpinned_revision",
        "training_artifact_integrity_conflict",
    }.issubset(_indicators(risks))


def test_training_hash_shape_and_sensitive_data_are_independent_risks():
    risks = analyze_training_artifact_risks(
        [
            {
                "name": "clinical-data",
                "source_url": "https://data.example.test/clinical",
                "sha256": "not-a-digest",
                "sensitivity": "PHI",
            }
        ]
    )

    assert {
        "training_artifact_malformed_hash",
        "training_artifact_privacy_risk",
    }.issubset(_indicators(risks))


def test_pipeline_false_approval_and_malformed_digest_do_not_pass():
    risks = analyze_deployment_pipeline_risks(
        {
            "environment": "production",
            "approval_gate": "disabled",
            "artifact_ref": "registry.example.test/model@sha256:abc",
        }
    )

    assert {
        "deployment_pipeline_missing_approval",
        "deployment_pipeline_malformed_digest",
    }.issubset(_indicators(risks))


def test_pipeline_digest_is_bound_to_assessed_artifact():
    risks = analyze_deployment_pipeline_risks(
        {
            "environment": "production",
            "approval_gate": "CAB-1",
            "artifact_ref": f"registry.example.test/model@sha256:{'b' * 64}",
        },
        expected_sha256="a" * 64,
    )

    mismatch = next(
        risk for risk in risks if risk["indicator"] == "deployment_artifact_hash_mismatch"
    )
    assert mismatch["severity"] == "CRITICAL"


def test_well_shaped_attestation_is_not_mistaken_for_verified_evidence():
    artifact = _complete_artifact()
    attestation = dict(artifact["provenance_attestations"][0])
    attestation.pop("verification")

    risks = analyze_provenance_attestation_risks(
        [attestation], expected_artifact=artifact
    )

    assert "malformed_provenance_attestation" not in _indicators(risks)
    assert "unverified_provenance_attestation" in _indicators(risks)


def test_strict_v2_attestation_requires_detached_trusted_id_context():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)

    without_context = analyze_provenance_attestation_risks(
        [attestation], expected_artifact=artifact
    )
    with_context = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert "malformed_provenance_attestation" not in _indicators(without_context)
    assert "unverified_provenance_attestation" in _indicators(without_context)
    assert "unverified_provenance_attestation" not in _indicators(with_context)


def test_v2_detached_statement_digest_strengthens_id_binding():
    artifact = _complete_artifact()
    attestation, verification = _v2_attestation(artifact)
    context = {
        "verified_attestation_ids": ["attestation-v2-0001"],
        "verified_attestation_digests": {
            "attestation-v2-0001": verification["attestation_sha256"]
        },
    }

    trusted = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context=context,
    )
    tampered = json.loads(json.dumps(attestation))
    tampered["statement"]["subject"]["model_name"] = "substituted-model"
    rejected = analyze_provenance_attestation_risks(
        [tampered],
        expected_artifact=artifact,
        verification_context=context,
    )

    assert "provenance_verification_binding_mismatch" not in _indicators(trusted)
    assert {
        "provenance_verification_binding_mismatch",
        "unverified_provenance_attestation",
        "provenance_model_name_mismatch",
    }.issubset(_indicators(rejected))


def test_wrong_v2_attestation_id_does_not_share_trust():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={"verified_attestation_ids": ["other-attestation"]},
    )

    assert "unverified_provenance_attestation" in _indicators(risks)


def test_v2_inline_verification_extension_breaks_strict_envelope_shape():
    artifact = _complete_artifact()
    attestation, verification = _v2_attestation(artifact)
    attestation["verification"] = verification

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert "malformed_provenance_attestation" in _indicators(risks)
    artifact["provenance_attestations"] = [attestation]
    result = validate_supply_chain(
        artifact,
        {"verified_attestation_ids": ["attestation-v2-0001"]},
    )
    assert result["evidence_quality"]["verified_attestation"] is False


def test_malformed_detached_context_fails_closed():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": "attestation-v2-0001"
        },
    )

    assert {
        "malformed_attestation_verification_context",
        "unverified_provenance_attestation",
    }.issubset(_indicators(risks))


def test_detached_digest_must_belong_to_a_trusted_id():
    artifact = _complete_artifact()
    attestation, verification = _v2_attestation(artifact)

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": [],
            "verified_attestation_digests": {
                "attestation-v2-0001": verification["attestation_sha256"]
            },
        },
    )

    assert "malformed_attestation_verification_context" in _indicators(risks)
    assert "unverified_provenance_attestation" in _indicators(risks)


def test_duplicate_v2_attestation_ids_are_rejected_even_when_trusted():
    artifact = _complete_artifact()
    first, _ = _v2_attestation(artifact)
    second = json.loads(json.dumps(first))

    risks = analyze_provenance_attestation_risks(
        [first, second],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert "duplicate_provenance_attestation_id" in _indicators(risks)


def test_artifact_metadata_cannot_self_assert_v2_verification():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)
    artifact["provenance_attestations"] = [attestation]
    artifact.setdefault("metadata", {})["verified_attestation_ids"] = [
        "attestation-v2-0001"
    ]

    result = validate_supply_chain(artifact)

    assert "unverified_provenance_attestation" in result["indicators"]
    assert result["evidence_quality"]["verified_attestation"] is False


def test_validate_supply_chain_propagates_detached_v2_context():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)
    artifact["provenance_attestations"] = [attestation]

    result = validate_supply_chain(
        artifact,
        {"verified_attestation_ids": ["attestation-v2-0001"]},
    )

    assert "unverified_provenance_attestation" not in result["indicators"]
    assert result["evidence_quality"]["verified_attestation"] is True


def test_v2_model_name_and_version_bindings_are_checked():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)
    changed = dict(artifact)
    changed["model_name"] = "different-name"
    changed["version"] = "9.9.9"

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=changed,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert {
        "provenance_model_name_mismatch",
        "provenance_version_mismatch",
    }.issubset(_indicators(risks))


def test_v2_detached_trust_does_not_hide_changed_bound_evidence():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)
    changed = json.loads(json.dumps(artifact))
    changed["dependencies"] = ["transformers==99.0.0"]
    changed["training_artifacts"] = [
        {
            "name": "replacement-data",
            "source_url": "https://data.example.test/replacement.jsonl",
            "sha256": "f" * 64,
        }
    ]
    changed["deployment_pipeline"]["approval_gate"] = "CAB-CHANGED"

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=changed,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert {
        "provenance_dependency_inventory_mismatch",
        "provenance_training_lineage_mismatch",
        "provenance_deployment_pipeline_mismatch",
    }.issubset(_indicators(risks))


def test_v2_detached_trust_is_rejected_after_attestation_expiry():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=artifact,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"],
            "as_of": "2026-06-22T12:00:00Z",
        },
    )

    assert {
        "provenance_attestation_time_invalid",
        "unverified_provenance_attestation",
    }.issubset(_indicators(risks))


def test_v2_source_revision_is_bound_to_current_evidence():
    artifact = _complete_artifact()
    artifact["source_metadata"] = {"revision": "b" * 40}
    attestation, _ = _v2_attestation(artifact)
    changed = dict(artifact)
    changed["source_metadata"] = {"revision": "c" * 40}

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=changed,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    source_risks = [
        risk
        for risk in risks
        if risk["indicator"] == "provenance_source_mismatch"
    ]
    assert source_risks
    assert any(risk["dependency"]["field"] == "revision" for risk in source_risks)


def test_v2_supply_chain_recomputes_ai_bom_for_vulnerability_drift():
    artifact = _complete_artifact()
    attestation, _ = _v2_attestation(artifact)
    changed = json.loads(json.dumps(artifact))
    changed["vulnerability_scan"] = {
        "assessment_complete": True,
        "match_count": 1,
        "matches": [
            {"advisory_id": "CVE-2026-4242", "severity": "CRITICAL"}
        ],
    }

    risks = analyze_provenance_attestation_risks(
        [attestation],
        expected_artifact=changed,
        verification_context={
            "verified_attestation_ids": ["attestation-v2-0001"]
        },
    )

    assert "provenance_mbom_hash_mismatch" in _indicators(risks)


def test_attestation_subject_and_hash_mismatch_are_critical():
    artifact = _complete_artifact()
    attestation = json.loads(json.dumps(artifact["provenance_attestations"][0]))
    attestation["statement"]["subject"]["model_id"] = "different-model"
    attestation["statement"]["subject"]["sha256"] = "d" * 64

    risks = analyze_provenance_attestation_risks(
        [attestation], expected_artifact=artifact
    )

    assert {
        "provenance_subject_mismatch",
        "provenance_artifact_hash_mismatch",
    }.issubset(_indicators(risks))
    assert all(
        risk["severity"] == "CRITICAL"
        for risk in risks
        if risk["indicator"]
        in {"provenance_subject_mismatch", "provenance_artifact_hash_mismatch"}
    )


def test_conflicting_attestations_cannot_jointly_establish_provenance():
    artifact = _complete_artifact()
    first = artifact["provenance_attestations"][0]
    second = json.loads(json.dumps(first))
    second["statement"]["subject"]["sha256"] = "d" * 64

    risks = analyze_provenance_attestation_risks(
        [first, second], expected_artifact=artifact
    )

    assert "conflicting_provenance_attestations" in _indicators(risks)


def test_vulnerability_scan_checks_inventory_and_internal_count_coherence():
    risks = analyze_dependency_vulnerabilities(
        {
            "status": "COMPLETE",
            "dependency_count": 2,
            "scanned_dependency_count": 1,
            "unresolved_dependencies": [],
            "matches": [],
            "match_count": 1,
        },
        expected_dependencies=["requests==2.31.0"],
    )

    assert {
        "vulnerability_scan_inventory_mismatch",
        "vulnerability_scan_inconsistent_counts",
    }.issubset(_indicators(risks))


def test_vulnerability_match_outside_inventory_is_not_silently_accepted():
    match = {
        "advisory_id": "OSV-1",
        "package_name": "urllib3",
        "ecosystem": "PyPI",
        "installed_version": "2.0.0",
        "severity": "CRITICAL",
    }
    risks = analyze_dependency_vulnerabilities(
        {
            "status": "VULNERABILITIES_FOUND",
            "dependency_count": 1,
            "scanned_dependency_count": 1,
            "unresolved_dependencies": [],
            "matches": [match],
            "match_count": 1,
        },
        expected_dependencies=["requests==2.31.0"],
    )

    assert {
        "vulnerability_match_outside_inventory",
        "known_vulnerable_dependency",
    }.issubset(_indicators(risks))


def test_stale_or_unverified_advisory_intelligence_is_explicit():
    stale = analyze_dependency_vulnerabilities(
        {
            "status": "COMPLETE",
            "advisory_intelligence": {"status": "STALE"},
            "matches": [],
        }
    )
    mixed = analyze_dependency_vulnerabilities(
        {
            "status": "COMPLETE",
            "advisory_intelligence": {"status": "MIXED"},
            "matches": [],
        }
    )

    assert "vulnerability_intelligence_stale" in _indicators(stale)
    assert "vulnerability_intelligence_unverified" in _indicators(mixed)

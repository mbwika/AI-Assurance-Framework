"""Bounded, evidence-aware supply-chain analysis for AI artifacts."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from ..registry.mbom_v2 import (
    generate_attestable_ai_bom_v2,
    verify_ai_bom_v2,
)


SUPPLY_CHAIN_SCORING_VERSION = "2.0"
_MAX_DEPENDENCIES = 2_000
_MAX_TRAINING_ARTIFACTS = 500
_MAX_ATTESTATIONS = 100
_MAX_VULNERABILITY_MATCHES = 5_000
_MAX_TEXT_CHARS = 4_096
_MAX_RISKS = 2_000

KNOWN_TYPOSQUATS = {
    "reqeusts": "requests",
    "request": "requests",
    "urlib3": "urllib3",
    "urllib": "urllib3",
    "transformer": "transformers",
    "tensor-flow": "tensorflow",
    "py-torch": "torch",
}

RISK_WEIGHTS = {
    "malformed_supply_chain_artifact": 3.0,
    "malformed_supply_chain_metadata": 2.0,
    "missing_source_url": 1.0,
    "malformed_source_url": 1.5,
    "insecure_model_source": 2.5,
    "source_url_contains_credentials": 3.0,
    "missing_integrity_hash": 2.0,
    "malformed_integrity_hash": 2.5,
    "missing_license": 1.0,
    "unknown_publisher": 1.0,
    "missing_dependency_inventory": 1.0,
    "malformed_dependency_inventory": 2.0,
    "dependency_analysis_limit_exceeded": 2.0,
    "malformed_dependency": 1.5,
    "unpinned_dependency": 1.0,
    "wildcard_dependency": 1.5,
    "direct_url_dependency": 1.0,
    "insecure_dependency_source": 2.5,
    "dependency_url_contains_credentials": 3.0,
    "mutable_vcs_dependency": 2.5,
    "local_path_dependency": 2.0,
    "pre_release_dependency": 1.0,
    "suspicious_dependency_name": 2.0,
    "missing_dependency_hash": 0.5,
    "malformed_dependency_hash": 1.5,
    "dependency_version_conflict": 2.5,
    "missing_training_artifacts": 1.0,
    "malformed_training_artifact_inventory": 2.0,
    "training_artifact_analysis_limit_exceeded": 2.0,
    "malformed_training_artifact": 1.5,
    "training_artifact_missing_hash": 1.0,
    "training_artifact_malformed_hash": 2.0,
    "training_artifact_unknown_source": 1.0,
    "training_artifact_insecure_source": 2.0,
    "training_artifact_unpinned_revision": 1.5,
    "training_artifact_privacy_risk": 1.5,
    "training_artifact_integrity_conflict": 3.0,
    "missing_deployment_pipeline": 1.0,
    "malformed_deployment_pipeline": 2.0,
    "deployment_pipeline_missing_approval": 1.0,
    "deployment_pipeline_self_approval": 2.0,
    "deployment_pipeline_missing_environment": 0.5,
    "deployment_pipeline_missing_artifact": 1.0,
    "deployment_pipeline_unpinned_artifact": 1.5,
    "deployment_pipeline_malformed_digest": 2.0,
    "deployment_artifact_hash_mismatch": 4.0,
    "missing_provenance_attestation": 1.0,
    "provenance_attestation_analysis_limit_exceeded": 2.0,
    "malformed_provenance_attestation": 2.0,
    "malformed_attestation_verification_context": 2.5,
    "unverified_provenance_attestation": 2.0,
    "provenance_verification_binding_mismatch": 4.0,
    "duplicate_provenance_attestation_id": 4.0,
    "provenance_subject_mismatch": 4.0,
    "provenance_model_name_mismatch": 2.5,
    "provenance_version_mismatch": 2.5,
    "provenance_artifact_hash_mismatch": 4.0,
    "provenance_mbom_hash_mismatch": 3.0,
    "provenance_dependency_inventory_mismatch": 3.0,
    "provenance_training_lineage_mismatch": 3.0,
    "provenance_deployment_pipeline_mismatch": 4.0,
    "provenance_model_manifest_mismatch": 4.0,
    "provenance_source_mismatch": 2.5,
    "provenance_attestation_time_invalid": 1.5,
    "conflicting_provenance_attestations": 4.0,
    "missing_vulnerability_scan": 1.0,
    "malformed_vulnerability_scan": 2.0,
    "vulnerability_intelligence_unavailable": 1.5,
    "vulnerability_intelligence_unverified": 2.0,
    "vulnerability_intelligence_stale": 2.5,
    "vulnerability_scan_partial": 1.0,
    "vulnerability_scan_inventory_mismatch": 2.5,
    "vulnerability_scan_inconsistent_counts": 2.0,
    "vulnerability_match_limit_exceeded": 2.0,
    "malformed_vulnerability_match": 2.0,
    "vulnerability_match_outside_inventory": 2.5,
    "known_vulnerable_dependency": 4.0,
    "supply_chain_risk_limit_exceeded": 2.0,
}

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_INCOMPLETE_INDICATORS = {
    "malformed_supply_chain_artifact",
    "malformed_supply_chain_metadata",
    "malformed_dependency_inventory",
    "dependency_analysis_limit_exceeded",
    "malformed_dependency",
    "malformed_training_artifact_inventory",
    "training_artifact_analysis_limit_exceeded",
    "malformed_training_artifact",
    "malformed_deployment_pipeline",
    "provenance_attestation_analysis_limit_exceeded",
    "malformed_provenance_attestation",
    "malformed_attestation_verification_context",
    "duplicate_provenance_attestation_id",
    "malformed_vulnerability_scan",
    "vulnerability_match_limit_exceeded",
    "malformed_vulnerability_match",
    "supply_chain_risk_limit_exceeded",
}
_DISABLED_VALUES = {"", "0", "false", "none", "no", "disabled", "off"}
_V1_ATTESTATION_TYPE = "https://aiaf.dev/attestation/model-provenance/v1"
_V2_ATTESTATION_TYPE = "https://aiaf.dev/attestation/model-provenance/v2"
_V2_PREDICATE_TYPE = (
    "https://aiaf.dev/attestation/model-provenance-predicate/v2"
)
_V2_ENVELOPE_FIELDS = frozenset(
    {"schema_version", "algorithm", "key_id", "statement", "signature"}
)
_V2_STATEMENT_FIELDS = frozenset(
    {
        "statement_type",
        "attestation_id",
        "subject",
        "predicate",
        "issued_at",
        "expires_at",
    }
)
_V2_SUBJECT_FIELDS = frozenset(
    {"model_id", "model_name", "version", "artifact_digest"}
)
_V2_PREDICATE_FIELDS = frozenset(
    {
        "predicate_type",
        "issuer",
        "source",
        "mbom_sha256",
        "dependency_inventory_sha256",
        "training_lineage_sha256",
        "deployment_pipeline_sha256",
        "model_manifest_sha256",
    }
)
_V2_SOURCE_FIELDS = frozenset({"provider", "url", "publisher", "revision"})
_V2_ARTIFACT_DIGEST_FIELDS = frozenset({"algorithm", "value"})
_ATTESTATION_CONTEXT_FIELDS = frozenset(
    {"verified_attestation_ids", "verified_attestation_digests", "as_of"}
)
_ATTESTATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_ALLOWED_SCAN_STATUSES = {
    "NO_DEPENDENCIES",
    "NO_ADVISORY_DATA",
    "VULNERABILITIES_FOUND",
    "PARTIAL",
    "COMPLETE",
    # v2 advisory-matcher clean-scan statuses.
    "NO_KNOWN_VULNERABILITIES",
    "NO_APPLICABLE_DEPENDENCIES",
}
_URL_USERINFO = re.compile(
    r"(?P<prefix>[a-z][a-z0-9+.-]*://)[^/@\s]+@", re.IGNORECASE
)


def validate_supply_chain(
    artifact: Dict[str, Any],
    assessment_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assess provenance, dependencies, lineage, deployment, and advisories."""
    artifact_risks: List[Dict[str, Any]] = []
    if not isinstance(artifact, dict):
        artifact = {}
        artifact_risks.append(
            _risk(
                "artifact",
                "malformed_supply_chain_artifact",
                "HIGH",
                "Supply-chain evidence must be an object.",
            )
        )

    metadata = artifact.get("metadata")
    if metadata is None:
        metadata = {}
    elif not isinstance(metadata, dict):
        metadata = {}
        artifact_risks.append(
            _risk(
                "metadata",
                "malformed_supply_chain_metadata",
                "HIGH",
                "Supply-chain metadata must be an object.",
            )
        )

    source_url = artifact.get("source_url")
    if not source_url:
        artifact_risks.append(
            _risk("model", "missing_source_url", "MEDIUM", "Model source URL is missing.")
        )
    else:
        artifact_risks.extend(_source_url_risks(source_url, "model"))

    artifact_hash = artifact.get("sha256") or artifact.get("sha256_hash")
    if not artifact_hash:
        artifact_risks.append(
            _risk(
                "model",
                "missing_integrity_hash",
                "HIGH",
                "Model artifact has no SHA-256 integrity evidence.",
            )
        )
    elif not _valid_sha256(artifact_hash):
        artifact_risks.append(
            _risk(
                "model",
                "malformed_integrity_hash",
                "HIGH",
                "Model integrity evidence is not a valid SHA-256 digest.",
            )
        )

    if not artifact.get("license"):
        artifact_risks.append(
            _risk("model", "missing_license", "MEDIUM", "Model license is missing.")
        )
    if _normalized(artifact.get("publisher")) in {"", "unknown", "unspecified"}:
        artifact_risks.append(
            _risk("model", "unknown_publisher", "MEDIUM", "Model publisher is unknown.")
        )

    dependencies = artifact.get("dependencies")
    if dependencies is None:
        mbom = artifact.get("mbom")
        mbom = mbom if isinstance(mbom, dict) else {}
        dependencies = mbom.get("dependencies")
    dependency_risks = analyze_dependency_risks(dependencies)
    dependency_items, _ = _bounded_items(dependencies, _MAX_DEPENDENCIES)
    if not dependency_items:
        artifact_risks.append(
            _risk(
                "dependencies",
                "missing_dependency_inventory",
                "MEDIUM",
                "No dependency inventory was provided.",
            )
        )

    training_artifacts = artifact.get("training_artifacts")
    if training_artifacts is None:
        training_artifacts = metadata.get("training_artifacts")
    training_artifact_risks = analyze_training_artifact_risks(training_artifacts)
    training_items, _ = _bounded_items(training_artifacts, _MAX_TRAINING_ARTIFACTS)
    if not training_items:
        artifact_risks.append(
            _risk(
                "training_artifacts",
                "missing_training_artifacts",
                "MEDIUM",
                "No training-artifact lineage was provided.",
            )
        )

    deployment_pipeline = artifact.get("deployment_pipeline")
    if deployment_pipeline is None:
        deployment_pipeline = metadata.get("deployment_pipeline")
    deployment_pipeline_risks = analyze_deployment_pipeline_risks(
        deployment_pipeline, expected_sha256=artifact_hash
    )
    if not deployment_pipeline:
        artifact_risks.append(
            _risk(
                "deployment_pipeline",
                "missing_deployment_pipeline",
                "MEDIUM",
                "No deployment-pipeline evidence was provided.",
            )
        )

    attestations = artifact.get("provenance_attestations")
    if attestations is None:
        attestations = metadata.get("provenance_attestations")
    attestation_risks = analyze_provenance_attestation_risks(
        attestations,
        expected_artifact=artifact,
        verification_context=assessment_context,
    )
    attestation_items, _ = _bounded_items(attestations, _MAX_ATTESTATIONS)
    if not attestation_items:
        artifact_risks.append(
            _risk(
                "provenance_attestations",
                "missing_provenance_attestation",
                "MEDIUM",
                "No signed provenance attestation was provided.",
            )
        )

    vulnerability_scan = artifact.get("vulnerability_scan")
    if vulnerability_scan is None:
        vulnerability_scan = metadata.get("vulnerability_scan")
    vulnerability_risks = analyze_dependency_vulnerabilities(
        vulnerability_scan, expected_dependencies=dependencies
    )
    if dependency_items and not vulnerability_scan:
        artifact_risks.append(
            _risk(
                "vulnerability_scan",
                "missing_vulnerability_scan",
                "MEDIUM",
                "Dependencies have not been checked against vulnerability intelligence.",
            )
        )

    all_risks = _deduplicate_risks(
        artifact_risks
        + dependency_risks
        + training_artifact_risks
        + deployment_pipeline_risks
        + attestation_risks
        + vulnerability_risks
    )
    risk_limit_reached = len(all_risks) > _MAX_RISKS
    if risk_limit_reached:
        all_risks = all_risks[: _MAX_RISKS - 1]
        all_risks.append(
            _risk(
                "supply_chain",
                "supply_chain_risk_limit_exceeded",
                "HIGH",
                "Supply-chain findings exceeded the bounded result limit.",
            )
        )

    indicator_counts = Counter(risk["indicator"] for risk in all_risks)
    indicators = list(dict.fromkeys(risk["indicator"] for risk in all_risks))
    score_breakdown = []
    raw_score = 0.0
    for indicator in indicators:
        count = indicator_counts[indicator]
        weight = RISK_WEIGHTS.get(indicator, 1.0)
        contribution = weight * min(count, 3)
        raw_score += contribution
        score_breakdown.append(
            {
                "indicator": indicator,
                "weight": weight,
                "occurrences": count,
                "scored_occurrences": min(count, 3),
                "contribution": contribution,
            }
        )
    score = round(min(raw_score, 10.0), 2)
    severity = _highest_severity(_severity(score), all_risks)
    assessment_complete = not risk_limit_reached and not any(
        indicator in _INCOMPLETE_INDICATORS for indicator in indicators
    )
    evidence_quality = _evidence_quality(
        source_url=source_url,
        artifact_hash=artifact_hash,
        dependencies=dependency_items,
        training_artifacts=training_items,
        deployment_pipeline=deployment_pipeline,
        attestations=attestation_items,
        vulnerability_scan=vulnerability_scan,
        attestation_risks=attestation_risks,
        all_risks=all_risks,
    )
    return {
        "risk_score": score,
        "score": score,
        "raw_risk_score": round(raw_score, 2),
        "severity": severity,
        "valid": score == 0 and assessment_complete,
        "indicators": indicators,
        "artifact_risks": artifact_risks,
        "dependency_risks": dependency_risks,
        "training_artifact_risks": training_artifact_risks,
        "deployment_pipeline_risks": deployment_pipeline_risks,
        "attestation_risks": attestation_risks,
        "vulnerability_risks": vulnerability_risks,
        "vulnerability_scan": vulnerability_scan if isinstance(vulnerability_scan, dict) else {},
        "scoring_version": SUPPLY_CHAIN_SCORING_VERSION,
        "assessment_complete": assessment_complete,
        "evidence_quality": evidence_quality,
        "score_breakdown": score_breakdown,
    }


def analyze_dependency_risks(dependencies: Any) -> List[Dict[str, Any]]:
    """Identify bounded, ecosystem-aware dependency inventory risks."""
    items, state = _bounded_items(dependencies, _MAX_DEPENDENCIES)
    risks: List[Dict[str, Any]] = []
    if state == "malformed":
        return [
            _risk(
                "dependencies",
                "malformed_dependency_inventory",
                "HIGH",
                "Dependency inventory must be a sequence, object, or line-delimited string.",
            )
        ]
    if state == "truncated":
        risks.append(
            _risk(
                {"provided": _item_count(dependencies), "analyzed": _MAX_DEPENDENCIES},
                "dependency_analysis_limit_exceeded",
                "HIGH",
                "Dependency inventory exceeds the bounded analysis limit.",
            )
        )

    versions_by_identity: Dict[Tuple[str, str], set] = defaultdict(set)
    evidence_by_identity: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
    for index, raw_dependency in enumerate(items):
        dependency, parse_error = _dependency_record(raw_dependency)
        if parse_error:
            risks.append(
                _risk(
                    {"index": index, "value": _safe_evidence(raw_dependency)},
                    "malformed_dependency",
                    "HIGH",
                    parse_error,
                )
            )
            continue
        name = dependency["name"]
        spec = dependency["spec"]
        source = dependency["source"]
        ecosystem = dependency["ecosystem"]
        identity = (ecosystem, _canonical_package_name(name, ecosystem))
        exact_version = _exact_version(dependency)
        if exact_version:
            versions_by_identity[identity].add(exact_version)
            evidence_by_identity[identity].append(raw_dependency)

        if "*" in spec:
            risks.append(
                _risk(raw_dependency, "wildcard_dependency", "HIGH", "Dependency uses a wildcard version.")
            )
        source_values = (spec, source)
        if _is_local_path(*source_values):
            risks.append(
                _risk(raw_dependency, "local_path_dependency", "HIGH", "Dependency resolves from a local path.")
            )
        if _is_direct_url(*source_values):
            if _uses_plain_http(*source_values):
                risks.append(
                    _risk(raw_dependency, "insecure_dependency_source", "HIGH", "Dependency uses an unauthenticated HTTP source.")
                )
            else:
                risks.append(
                    _risk(raw_dependency, "direct_url_dependency", "MEDIUM", "Dependency bypasses the ecosystem registry.")
                )
            if _url_contains_credentials(*source_values):
                risks.append(
                    _risk(raw_dependency, "dependency_url_contains_credentials", "CRITICAL", "Dependency URL embeds credentials.")
                )
            if _is_vcs_url(*source_values) and not _has_immutable_vcs_ref(*source_values):
                risks.append(
                    _risk(raw_dependency, "mutable_vcs_dependency", "HIGH", "VCS dependency is not pinned to an immutable commit.")
                )
        if spec and not _is_exactly_pinned(spec, ecosystem) and not _is_direct_url(*source_values):
            risks.append(
                _risk(raw_dependency, "unpinned_dependency", "MEDIUM", "Dependency is not exactly pinned.")
            )
        if _is_prerelease(exact_version or spec):
            risks.append(
                _risk(raw_dependency, "pre_release_dependency", "MEDIUM", "Dependency references a pre-release version.")
            )
        canonical_name = _canonical_package_name(name, ecosystem)
        if canonical_name in KNOWN_TYPOSQUATS:
            risks.append(
                _risk(
                    raw_dependency,
                    "suspicious_dependency_name",
                    "HIGH",
                    f"Dependency resembles {KNOWN_TYPOSQUATS[canonical_name]}.",
                )
            )
        if isinstance(raw_dependency, dict):
            digest = raw_dependency.get("sha256") or raw_dependency.get("hash")
            if not digest:
                risks.append(
                    _risk(raw_dependency, "missing_dependency_hash", "LOW", "Structured dependency has no hash evidence.")
                )
            elif not _valid_sha256(digest):
                risks.append(
                    _risk(raw_dependency, "malformed_dependency_hash", "HIGH", "Dependency hash is not a valid SHA-256 digest.")
                )

    for identity in sorted(versions_by_identity):
        versions = sorted(versions_by_identity[identity])
        if len(versions) > 1:
            risks.append(
                _risk(
                    {
                        "ecosystem": identity[0],
                        "name": identity[1],
                        "versions": versions,
                        "records": [_safe_evidence(item) for item in evidence_by_identity[identity][:10]],
                    },
                    "dependency_version_conflict",
                    "HIGH",
                    "Dependency inventory contains conflicting exact versions.",
                )
            )
    return _limit_risks(risks, "Dependency analysis produced more findings than the bounded result limit.")


def analyze_training_artifact_risks(training_artifacts: Any) -> List[Dict[str, Any]]:
    """Identify bounded training lineage, integrity, and privacy risks."""
    artifacts, state = _bounded_items(training_artifacts, _MAX_TRAINING_ARTIFACTS)
    risks: List[Dict[str, Any]] = []
    if state == "malformed":
        return [
            _risk(
                "training_artifacts",
                "malformed_training_artifact_inventory",
                "HIGH",
                "Training-artifact inventory must be a sequence or object.",
            )
        ]
    if state == "truncated":
        risks.append(
            _risk(
                {"provided": _item_count(training_artifacts), "analyzed": _MAX_TRAINING_ARTIFACTS},
                "training_artifact_analysis_limit_exceeded",
                "HIGH",
                "Training-artifact inventory exceeds the bounded analysis limit.",
            )
        )

    hashes_by_name: Dict[str, set] = defaultdict(set)
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            risks.append(
                _risk(
                    {"index": index, "value": _safe_evidence(artifact)},
                    "malformed_training_artifact",
                    "HIGH",
                    "Training artifact must be an object.",
                )
            )
            continue
        name = _bounded_text(artifact.get("name") or artifact.get("dataset") or f"training-artifact-{index + 1}")
        source = artifact.get("source_url") or artifact.get("source")
        digest = artifact.get("sha256") or artifact.get("hash")
        if not source:
            risks.append(
                _risk(name, "training_artifact_unknown_source", "MEDIUM", "Training artifact has no source evidence.")
            )
        elif _uses_plain_http(str(source)):
            risks.append(
                _risk(name, "training_artifact_insecure_source", "HIGH", "Training artifact uses an unauthenticated HTTP source.")
            )
        if not digest:
            risks.append(
                _risk(name, "training_artifact_missing_hash", "MEDIUM", "Training artifact has no integrity hash.")
            )
        elif not _valid_sha256(digest):
            risks.append(
                _risk(name, "training_artifact_malformed_hash", "HIGH", "Training artifact hash is not a valid SHA-256 digest.")
            )
        else:
            hashes_by_name[_normalized(name)].add(_digest_value(digest))
        source_type = _normalized(artifact.get("source_type") or artifact.get("type"))
        if (
            source_type in {"git", "huggingface", "repository", "dataset_repository"}
            or _is_vcs_url(str(source or ""))
        ) and not _immutable_revision(artifact.get("revision") or artifact.get("commit")):
            risks.append(
                _risk(name, "training_artifact_unpinned_revision", "HIGH", "Repository-backed training data is not pinned to an immutable revision.")
            )
        sensitivity = _normalized(artifact.get("sensitivity"))
        if artifact.get("contains_pii") is True or sensitivity in {"pii", "phi", "secret", "restricted"}:
            risks.append(
                _risk(name, "training_artifact_privacy_risk", "HIGH", "Training artifact may contain sensitive data.")
            )

    for name, digests in sorted(hashes_by_name.items()):
        if name and len(digests) > 1:
            risks.append(
                _risk(
                    {"name": name, "sha256": sorted(digests)},
                    "training_artifact_integrity_conflict",
                    "CRITICAL",
                    "The same training-artifact identity has conflicting digests.",
                )
            )
    return _limit_risks(risks, "Training-lineage analysis produced more findings than the bounded result limit.")


def analyze_deployment_pipeline_risks(
    deployment_pipeline: Any, *, expected_sha256: Any = None
) -> List[Dict[str, Any]]:
    """Identify release traceability, approval, and artifact-binding risks."""
    if deployment_pipeline in (None, ""):
        return []
    if not isinstance(deployment_pipeline, dict):
        return [
            _risk(
                "deployment_pipeline",
                "malformed_deployment_pipeline",
                "HIGH",
                "Deployment pipeline evidence must be an object.",
            )
        ]

    risks: List[Dict[str, Any]] = []
    if not deployment_pipeline.get("environment"):
        risks.append(
            _risk("deployment_pipeline", "deployment_pipeline_missing_environment", "LOW", "Deployment environment is missing.")
        )
    approval = deployment_pipeline.get("approval_gate") or deployment_pipeline.get("change_ticket")
    if not _effective_evidence(approval):
        risks.append(
            _risk("deployment_pipeline", "deployment_pipeline_missing_approval", "MEDIUM", "Deployment approval evidence is missing.")
        )
    actor = _normalized(deployment_pipeline.get("deployed_by") or deployment_pipeline.get("actor"))
    approver = _normalized(deployment_pipeline.get("approved_by") or deployment_pipeline.get("approver"))
    if actor and approver and actor == approver:
        risks.append(
            _risk(
                {"actor": actor},
                "deployment_pipeline_self_approval",
                "HIGH",
                "The same principal deploys and approves the artifact.",
            )
        )
    artifact_ref = deployment_pipeline.get("artifact_ref") or deployment_pipeline.get("image")
    if not artifact_ref:
        risks.append(
            _risk("deployment_pipeline", "deployment_pipeline_missing_artifact", "MEDIUM", "Deployment evidence does not identify the released artifact.")
        )
        return risks
    reference = _bounded_text(artifact_ref)
    digest = _artifact_reference_digest(reference)
    if "@sha256:" in reference.lower():
        if digest is None:
            risks.append(
                _risk(reference, "deployment_pipeline_malformed_digest", "HIGH", "Deployment reference contains an invalid SHA-256 digest.")
            )
    elif _reference_is_mutable(reference):
        risks.append(
            _risk(reference, "deployment_pipeline_unpinned_artifact", "HIGH", "Deployment artifact is mutable or not digest-pinned.")
        )
    if digest and _valid_sha256(expected_sha256) and digest != _digest_value(expected_sha256):
        risks.append(
            _risk(
                {"deployed_sha256": digest, "expected_sha256": _digest_value(expected_sha256)},
                "deployment_artifact_hash_mismatch",
                "CRITICAL",
                "Deployment reference does not match the assessed model artifact.",
            )
        )
    return risks


def analyze_provenance_attestation_risks(
    attestations: Any,
    *,
    expected_artifact: Optional[Dict[str, Any]] = None,
    verification_context: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Validate dual-read attestation evidence and trusted verification binding."""
    items, state = _bounded_items(attestations, _MAX_ATTESTATIONS)
    risks: List[Dict[str, Any]] = []
    if state == "malformed":
        return [
            _risk(
                "provenance_attestations",
                "malformed_provenance_attestation",
                "HIGH",
                "Provenance attestations must be a sequence or object.",
            )
        ]
    if state == "truncated":
        risks.append(
            _risk(
                {"provided": _item_count(attestations), "analyzed": _MAX_ATTESTATIONS},
                "provenance_attestation_analysis_limit_exceeded",
                "HIGH",
                "Provenance attestations exceed the bounded analysis limit.",
            )
        )

    trusted_ids, trusted_digests, context_as_of, context_valid = (
        _attestation_verification_context(verification_context)
    )
    if not context_valid:
        risks.append(
            _risk(
                "verification_context",
                "malformed_attestation_verification_context",
                "HIGH",
                "Detached attestation verification context is malformed or exceeds bounds.",
            )
        )

    expected_artifact = expected_artifact if isinstance(expected_artifact, dict) else {}
    expected_model_id = expected_artifact.get("model_id") or expected_artifact.get("id")
    expected_model_name = expected_artifact.get("model_name")
    expected_version = expected_artifact.get("version")
    expected_hash = expected_artifact.get("sha256") or expected_artifact.get("sha256_hash")
    expected_mbom_hash = expected_artifact.get("mbom_sha256")
    if not expected_mbom_hash and isinstance(expected_artifact.get("mbom"), dict):
        expected_mbom = expected_artifact["mbom"]
        if (
            expected_mbom.get("spec_version") == "2.0"
            and verify_ai_bom_v2(expected_mbom).get("verified")
        ):
            expected_mbom_hash = expected_mbom.get("document_sha256")
        else:
            expected_mbom_hash = hashlib.sha256(
                _canonical_json(expected_mbom)
            ).hexdigest()
    expected_v2_ai_bom_hash = _current_ai_bom_document_digest(
        expected_artifact
    )
    expected_dependency_hash = _expected_evidence_digest(
        expected_artifact,
        "dependencies",
        [],
        explicit_digest_field="dependency_inventory_sha256",
    )
    expected_training_hash = _expected_evidence_digest(
        expected_artifact,
        "training_artifacts",
        [],
        explicit_digest_field="training_lineage_sha256",
    )
    expected_deployment_hash = _expected_evidence_digest(
        expected_artifact,
        "deployment_pipeline",
        {},
        explicit_digest_field="deployment_pipeline_sha256",
    )
    expected_model_manifest_hash = _nested_evidence_value(
        expected_artifact, "model_manifest_sha256"
    )
    bindings = set()
    attestation_ids: Dict[str, int] = {}
    for index, attestation in enumerate(items):
        view = _attestation_view(attestation)
        if view is None:
            risks.append(
                _risk(
                    {"index": index},
                    "malformed_provenance_attestation",
                    "HIGH",
                    "Provenance attestation schema, statement, or signature is malformed.",
                )
            )
            continue
        subject_id = view["model_id"]
        subject_hash = view["artifact_hash"]
        mbom_hash = view["mbom_sha256"]
        bindings.add((str(subject_id), str(subject_hash), str(mbom_hash)))
        attestation_id = view["attestation_id"]
        if attestation_id:
            if attestation_id in attestation_ids:
                risks.append(
                    _risk(
                        {
                            "index": index,
                            "first_index": attestation_ids[attestation_id],
                            "attestation_id": attestation_id,
                        },
                        "duplicate_provenance_attestation_id",
                        "CRITICAL",
                        "A provenance attestation ID is reused within the assessed evidence set.",
                    )
                )
            else:
                attestation_ids[attestation_id] = index
        if expected_model_id and subject_id != expected_model_id:
            risks.append(
                _risk(
                    {"index": index, "attested": subject_id, "expected": expected_model_id},
                    "provenance_subject_mismatch",
                    "CRITICAL",
                    "Attestation subject does not match the assessed model identity.",
                )
            )
        if (
            view["schema_version"] == "2.0"
            and expected_model_name not in (None, "")
            and view["model_name"] != expected_model_name
        ):
            risks.append(
                _risk(
                    {"index": index, "field": "model_name"},
                    "provenance_model_name_mismatch",
                    "HIGH",
                    "Attested model name does not match current model evidence.",
                )
            )
        if (
            view["schema_version"] == "2.0"
            and expected_version not in (None, "")
            and view["version"] != expected_version
        ):
            risks.append(
                _risk(
                    {"index": index, "field": "version"},
                    "provenance_version_mismatch",
                    "HIGH",
                    "Attested model version does not match current model evidence.",
                )
            )
        if _valid_sha256(expected_hash) and _digest_value(subject_hash) != _digest_value(expected_hash):
            risks.append(
                _risk(
                    {"index": index, "attested": subject_hash, "expected": _digest_value(expected_hash)},
                    "provenance_artifact_hash_mismatch",
                    "CRITICAL",
                    "Attestation digest does not match the assessed model artifact.",
                )
            )
        expected_attested_bom_hash = (
            expected_v2_ai_bom_hash
            if view["schema_version"] == "2.0"
            else expected_mbom_hash
        )
        if (
            expected_attested_bom_hash
            and _digest_value(mbom_hash)
            != _digest_value(expected_attested_bom_hash)
        ):
            risks.append(
                _risk(
                    {
                        "index": index,
                        "attested": mbom_hash,
                        "expected": _digest_value(
                            expected_attested_bom_hash
                        ),
                    },
                    "provenance_mbom_hash_mismatch",
                    "HIGH",
                    "Attestation AI-BOM digest does not match current evidence.",
                )
            )
        if view["schema_version"] == "2.0":
            signed_bindings = (
                (
                    "dependency_inventory_sha256",
                    expected_dependency_hash,
                    "provenance_dependency_inventory_mismatch",
                    "HIGH",
                    "Attested dependency inventory does not match current model evidence.",
                ),
                (
                    "training_lineage_sha256",
                    expected_training_hash,
                    "provenance_training_lineage_mismatch",
                    "HIGH",
                    "Attested training lineage does not match current model evidence.",
                ),
                (
                    "deployment_pipeline_sha256",
                    expected_deployment_hash,
                    "provenance_deployment_pipeline_mismatch",
                    "CRITICAL",
                    "Attested deployment pipeline does not match current model evidence.",
                ),
                (
                    "model_manifest_sha256",
                    expected_model_manifest_hash,
                    "provenance_model_manifest_mismatch",
                    "CRITICAL",
                    "Attested model manifest does not match explicitly supplied current evidence.",
                ),
            )
            for field, expected_digest, indicator, severity, detail in signed_bindings:
                if expected_digest and not hmac.compare_digest(
                    view[field], _digest_value(expected_digest)
                ):
                    risks.append(
                        _risk(
                            {"index": index, "field": field},
                            indicator,
                            severity,
                            detail,
                        )
                    )
        for field in ("source", "source_url", "publisher"):
            expected = expected_artifact.get(field)
            if expected not in (None, "") and view[field] != expected:
                risks.append(
                    _risk(
                        {"index": index, "field": field},
                        "provenance_source_mismatch",
                        "HIGH",
                        f"Attested {field} does not match current model evidence.",
                    )
                )
        if view["schema_version"] == "2.0":
            source_metadata = expected_artifact.get("source_metadata")
            if not isinstance(source_metadata, dict):
                metadata = expected_artifact.get("metadata")
                source_metadata = (
                    metadata.get("source_metadata")
                    if isinstance(metadata, dict)
                    and isinstance(metadata.get("source_metadata"), dict)
                    else {}
                )
            expected_revision = source_metadata.get("revision")
            if (
                expected_revision not in (None, "")
                and view["revision"] != expected_revision
            ):
                risks.append(
                    _risk(
                        {"index": index, "field": "revision"},
                        "provenance_source_mismatch",
                        "HIGH",
                        "Attested source revision does not match current model evidence.",
                    )
                )
        if view["schema_version"] == "2.0":
            issued_at = _strict_attestation_datetime(view["issued_at"])
            expires_at = _strict_attestation_datetime(view["expires_at"])
        else:
            issued_at = _parse_datetime(view["issued_at"])
            expires_at = None
        time_invalid = issued_at is None
        if view["schema_version"] == "2.0":
            time_invalid = (
                time_invalid
                or expires_at is None
                or expires_at <= issued_at
                or (
                    context_as_of is not None
                    and (
                        issued_at > context_as_of
                        or expires_at <= context_as_of
                    )
                )
            )
        if time_invalid:
            risks.append(
                _risk(
                    {"index": index},
                    "provenance_attestation_time_invalid",
                    "MEDIUM",
                    "Attestation issuance time is missing or invalid.",
                )
            )
        verification_passed, binding_mismatch = _attestation_verification_passed(
            attestation,
            view,
            trusted_ids,
            trusted_digests,
            context_valid,
            not time_invalid,
        )
        if binding_mismatch:
            risks.append(
                _risk(
                    {
                        "index": index,
                        "attestation_id": attestation_id,
                    },
                    "provenance_verification_binding_mismatch",
                    "CRITICAL",
                    "Detached verification digest does not bind the supplied attestation statement.",
                )
            )
        if not verification_passed:
            risks.append(
                _risk(
                    {"index": index, "key_id": attestation.get("key_id")},
                    "unverified_provenance_attestation",
                    "HIGH",
                    "Attestation shape is valid but cryptographic verification evidence is absent or failed.",
                )
            )
    if len(bindings) > 1:
        risks.append(
            _risk(
                {"binding_count": len(bindings)},
                "conflicting_provenance_attestations",
                "CRITICAL",
                "Provenance attestations bind conflicting subjects or artifact digests.",
            )
        )
    return _limit_risks(risks, "Provenance analysis produced more findings than the bounded result limit.")


def analyze_dependency_vulnerabilities(
    vulnerability_scan: Any, *, expected_dependencies: Any = None
) -> List[Dict[str, Any]]:
    """Validate persisted vulnerability-scan completeness and advisory matches."""
    if vulnerability_scan in (None, ""):
        return []
    if not isinstance(vulnerability_scan, dict):
        return [
            _risk(
                "vulnerability_scan",
                "malformed_vulnerability_scan",
                "HIGH",
                "Vulnerability scan evidence must be an object.",
            )
        ]
    risks: List[Dict[str, Any]] = []
    status = str(vulnerability_scan.get("status") or "").upper()
    if status not in _ALLOWED_SCAN_STATUSES:
        risks.append(
            _risk("vulnerability_scan", "malformed_vulnerability_scan", "HIGH", "Vulnerability scan status is missing or unsupported.")
        )
    if status == "NO_ADVISORY_DATA":
        risks.append(
            _risk("vulnerability_scan", "vulnerability_intelligence_unavailable", "HIGH", "No vulnerability advisories were available during the scan.")
        )
    if status == "PARTIAL" or vulnerability_scan.get("unresolved_dependencies"):
        risks.append(
            _risk(
                vulnerability_scan.get("unresolved_dependencies", []),
                "vulnerability_scan_partial",
                "MEDIUM",
                "One or more dependencies could not be matched to advisories.",
            )
        )

    intelligence = vulnerability_scan.get("advisory_intelligence")
    if isinstance(intelligence, dict):
        intelligence_status = str(intelligence.get("status") or "").upper()
        if intelligence_status == "STALE":
            risks.append(
                _risk("advisory_intelligence", "vulnerability_intelligence_stale", "HIGH", "Authenticated advisory intelligence is stale.")
            )
        elif intelligence_status in {"UNVERIFIED", "MIXED", ""}:
            risks.append(
                _risk("advisory_intelligence", "vulnerability_intelligence_unverified", "HIGH", "Advisory intelligence is not fully authenticated.")
            )

    expected_items, _ = _bounded_items(expected_dependencies, _MAX_DEPENDENCIES)
    expected_coordinates = []
    for item in expected_items:
        coordinate, error = _dependency_record(item)
        if not error and coordinate["name"]:
            expected_coordinates.append(coordinate)
    expected_count = len(expected_items)
    scan_count = _nonnegative_int(vulnerability_scan.get("dependency_count"))
    scanned_count = _nonnegative_int(vulnerability_scan.get("scanned_dependency_count"))
    unresolved = vulnerability_scan.get("unresolved_dependencies")
    unresolved_count = len(unresolved) if isinstance(unresolved, list) else 0
    if expected_count and scan_count is not None and scan_count != expected_count:
        risks.append(
            _risk(
                {"expected": expected_count, "scanned_inventory": scan_count},
                "vulnerability_scan_inventory_mismatch",
                "HIGH",
                "Vulnerability scan was produced for a different dependency inventory size.",
            )
        )
    if scan_count is not None and scanned_count is not None and scanned_count + unresolved_count != scan_count:
        risks.append(
            _risk(
                {"dependency_count": scan_count, "scanned": scanned_count, "unresolved": unresolved_count},
                "vulnerability_scan_inconsistent_counts",
                "HIGH",
                "Vulnerability scan coverage counts are internally inconsistent.",
            )
        )

    matches = vulnerability_scan.get("matches", [])
    if not isinstance(matches, list):
        risks.append(
            _risk("matches", "malformed_vulnerability_scan", "HIGH", "Vulnerability matches must be a list.")
        )
        matches = []
    if len(matches) > _MAX_VULNERABILITY_MATCHES:
        risks.append(
            _risk(
                {"provided": len(matches), "analyzed": _MAX_VULNERABILITY_MATCHES},
                "vulnerability_match_limit_exceeded",
                "HIGH",
                "Vulnerability matches exceed the bounded analysis limit.",
            )
        )
    inventory = {
        (coordinate["ecosystem"], _canonical_package_name(coordinate["name"], coordinate["ecosystem"]))
        for coordinate in expected_coordinates
    }
    seen_matches = set()
    for index, match in enumerate(matches[:_MAX_VULNERABILITY_MATCHES]):
        if not isinstance(match, dict) or not match.get("advisory_id") or not match.get("package_name"):
            risks.append(
                _risk(
                    {"index": index},
                    "malformed_vulnerability_match",
                    "HIGH",
                    "Vulnerability match lacks advisory or package identity.",
                )
            )
            continue
        ecosystem = _normalized_ecosystem(match.get("ecosystem"))
        package_name = _canonical_package_name(match.get("package_name"), ecosystem)
        match_key = (str(match.get("advisory_id")), ecosystem, package_name, str(match.get("installed_version")))
        if match_key in seen_matches:
            continue
        seen_matches.add(match_key)
        if inventory and (ecosystem, package_name) not in inventory:
            risks.append(
                _risk(
                    match,
                    "vulnerability_match_outside_inventory",
                    "HIGH",
                    "Vulnerability match names a dependency absent from the assessed inventory.",
                )
            )
        severity = str(match.get("severity") or "HIGH").upper()
        if severity not in _SEVERITY_ORDER:
            severity = "HIGH"
        risks.append(
            _risk(
                match,
                "known_vulnerable_dependency",
                severity,
                f"{match.get('package_name')} {match.get('installed_version', '')} matches advisory {match.get('advisory_id')}.",
            )
        )
    declared_match_count = _nonnegative_int(vulnerability_scan.get("match_count"))
    if declared_match_count is not None and declared_match_count != len(matches):
        risks.append(
            _risk(
                {"declared": declared_match_count, "observed": len(matches)},
                "vulnerability_scan_inconsistent_counts",
                "HIGH",
                "Declared vulnerability match count does not match supplied evidence.",
            )
        )
    return _limit_risks(risks, "Vulnerability analysis produced more findings than the bounded result limit.")


def _dependency_record(raw_dependency: Any) -> Tuple[Dict[str, str], Optional[str]]:
    if isinstance(raw_dependency, dict):
        name = _bounded_text(raw_dependency.get("name"))
        version = _bounded_text(raw_dependency.get("version") or raw_dependency.get("specifier"))
        source = _bounded_text(raw_dependency.get("source") or raw_dependency.get("url"))
        ecosystem = _normalized_ecosystem(raw_dependency.get("ecosystem"))
        if not name:
            return _empty_coordinate(), "Structured dependency is missing a package name."
        if not version and not source:
            return {
                "name": name,
                "spec": "",
                "source": "",
                "ecosystem": ecosystem,
            }, None
        return {
            "name": name,
            "spec": version or source,
            "source": source,
            "ecosystem": ecosystem,
        }, None
    if not isinstance(raw_dependency, str):
        return _empty_coordinate(), "Dependency entry must be a string or object."
    value = _bounded_text(raw_dependency)
    if not value:
        return _empty_coordinate(), "Dependency entry is empty."
    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        match = re.fullmatch(r"(@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@(.+)", value)
        if match:
            return {
                "name": match.group(1),
                "spec": match.group(2),
                "source": "",
                "ecosystem": "npm",
            }, None
        return _empty_coordinate(), "Dependency string is not a valid package requirement."
    source = requirement.url or ""
    return {
        "name": requirement.name,
        "spec": source or str(requirement.specifier),
        "source": source,
        "ecosystem": "pypi",
    }, None


def _empty_coordinate() -> Dict[str, str]:
    return {"name": "", "spec": "", "source": "", "ecosystem": "unknown"}


def _bounded_items(value: Any, limit: int) -> Tuple[List[Any], str]:
    if value in (None, ""):
        return [], "ok"
    if isinstance(value, dict):
        if "items" in value:
            contained = value.get("items")
            if not isinstance(contained, (list, tuple)):
                return [], "malformed"
            items = list(contained)
        else:
            items = [value]
    elif isinstance(value, str):
        items = [line.strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return [], "malformed"
    return items[:limit], "truncated" if len(items) > limit else "ok"


def _item_count(value: Any) -> int:
    items, state = _bounded_items(value, 10_000_000)
    return len(items) if state != "malformed" else 0


def _source_url_risks(value: Any, evidence: Any) -> List[Dict[str, Any]]:
    text = _bounded_text(value)
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except (ValueError, TypeError):
        parsed = None
        port = None
    del port
    if parsed is None or parsed.scheme.lower() not in {"https", "http"} or not parsed.hostname:
        return [_risk(evidence, "malformed_source_url", "HIGH", "Model source is not a valid HTTP(S) URL.")]
    risks = []
    if parsed.scheme.lower() == "http":
        risks.append(_risk(evidence, "insecure_model_source", "HIGH", "Model source uses unauthenticated HTTP."))
    if parsed.username is not None or parsed.password is not None:
        risks.append(_risk(evidence, "source_url_contains_credentials", "CRITICAL", "Model source URL embeds credentials."))
    return risks


def _exact_version(dependency: Dict[str, str]) -> Optional[str]:
    spec = dependency["spec"]
    ecosystem = dependency["ecosystem"]
    if not _is_exactly_pinned(spec, ecosystem):
        return None
    if ecosystem == "pypi":
        match = re.fullmatch(r"={2,3}\s*([^,;]+)", spec)
        return match.group(1).strip() if match else None
    return spec.removeprefix("v")


def _is_exactly_pinned(spec: str, ecosystem: str = "") -> bool:
    spec = str(spec or "").strip()
    ecosystem = _normalized_ecosystem(ecosystem)
    if not spec or _is_direct_url(spec):
        return False
    if ecosystem == "pypi":
        try:
            requirement = Requirement(f"placeholder{spec}")
        except InvalidRequirement:
            return False
        specifiers = list(requirement.specifier)
        return (
            len(specifiers) == 1
            and specifiers[0].operator in {"==", "==="}
            and "*" not in specifiers[0].version
        )
    return bool(re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", spec))


def _is_prerelease(value: Any) -> bool:
    text = str(value or "").strip().lstrip("=v")
    try:
        return Version(text).is_prerelease
    except InvalidVersion:
        return bool(re.search(r"(?:^|[.-])(alpha|beta|a|b|rc|dev|pre|preview)\d*(?:$|[.-])", text, re.IGNORECASE))


def _canonical_package_name(name: Any, ecosystem: str) -> str:
    normalized = str(name or "").strip().lower()
    if _normalized_ecosystem(ecosystem) == "pypi":
        return re.sub(r"[-_.]+", "-", normalized)
    return normalized


def _normalized_ecosystem(value: Any) -> str:
    normalized = _normalized(value)
    return {
        "python": "pypi",
        "pip": "pypi",
        "pypi": "pypi",
        "node": "npm",
        "nodejs": "npm",
        "npm": "npm",
    }.get(normalized, normalized or "unknown")


def _is_direct_url(*values: str) -> bool:
    return any(
        "://" in str(value) or str(value).lower().startswith(("git+", "ssh+", "file:"))
        for value in values
        if value
    )


def _uses_plain_http(*values: str) -> bool:
    return any(re.search(r"(?:^|[+])http://", str(value), re.IGNORECASE) for value in values if value)


def _is_vcs_url(*values: str) -> bool:
    return any(
        str(value).lower().startswith(("git+", "hg+", "svn+", "bzr+"))
        or str(value).lower().endswith(".git")
        or ".git@" in str(value).lower()
        for value in values
        if value
    )


def _has_immutable_vcs_ref(*values: str) -> bool:
    for value in values:
        text = str(value or "")
        match = re.search(r"@([0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?:[#?]|$)", text)
        if match:
            return True
    return False


def _is_local_path(*values: str) -> bool:
    for value in values:
        text = str(value or "").strip().lower()
        if text.startswith(("file:", "./", "../", "/", "~")):
            return True
    return False


def _url_contains_credentials(*values: str) -> bool:
    for value in values:
        text = str(value or "")
        if text.lower().startswith(("git+", "ssh+", "hg+", "svn+", "bzr+")):
            text = text.split("+", 1)[1]
        try:
            parsed = urlsplit(text)
        except ValueError:
            continue
        if parsed.username is not None or parsed.password is not None:
            return True
    return False


def _immutable_revision(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", str(value or "").strip()))


def _artifact_reference_digest(reference: str) -> Optional[str]:
    match = re.search(r"@sha256:([0-9a-fA-F]+)(?:$|[?#])", reference, re.IGNORECASE)
    if not match or len(match.group(1)) != 64:
        return None
    return match.group(1).lower()


def _reference_is_mutable(reference: str) -> bool:
    lower = reference.lower()
    if "@sha256:" in lower:
        return False
    if lower.endswith((":latest", ":dev", ":main", ":master", ":edge", ":nightly")):
        return True
    return "@" not in reference


def _valid_attestation_shape(value: Any) -> bool:
    return _attestation_view(value) is not None


def _attestation_view(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    if value.get("schema_version") == "2.0":
        return _v2_attestation_view(value)
    return _v1_attestation_view(value)


def _v1_attestation_view(value: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    statement = value.get("statement")
    if not isinstance(statement, dict):
        return None
    subject = statement.get("subject")
    predicate = statement.get("predicate")
    valid = (
        value.get("schema_version") in (None, "1.0")
        and value.get("algorithm") == "HMAC-SHA256"
        and bool(_bounded_text(value.get("key_id")))
        and _valid_sha256(value.get("signature"))
        and statement.get("statement_type") == _V1_ATTESTATION_TYPE
        and isinstance(subject, dict)
        and bool(subject.get("model_id"))
        and _valid_sha256(subject.get("sha256"))
        and isinstance(predicate, dict)
        and _valid_sha256(predicate.get("mbom_sha256"))
    )
    if not valid:
        return None
    return {
        "schema_version": "1.0",
        "attestation_id": None,
        "model_id": subject.get("model_id"),
        "model_name": subject.get("model_name"),
        "version": predicate.get("version"),
        "artifact_hash": _digest_value(subject.get("sha256")),
        "mbom_sha256": _digest_value(predicate.get("mbom_sha256")),
        "source": predicate.get("source"),
        "source_url": predicate.get("source_url"),
        "publisher": predicate.get("publisher"),
        "issued_at": statement.get("issued_at"),
        "expires_at": None,
        "statement_sha256": hashlib.sha256(_canonical_json(statement)).hexdigest(),
    }


def _v2_attestation_view(value: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if set(value) != _V2_ENVELOPE_FIELDS:
        return None
    statement = value.get("statement")
    if not isinstance(statement, dict) or set(statement) != _V2_STATEMENT_FIELDS:
        return None
    subject = statement.get("subject")
    predicate = statement.get("predicate")
    if (
        not isinstance(subject, dict)
        or set(subject) != _V2_SUBJECT_FIELDS
        or not isinstance(predicate, dict)
        or set(predicate) != _V2_PREDICATE_FIELDS
    ):
        return None
    artifact_digest = subject.get("artifact_digest")
    source = predicate.get("source")
    if (
        not isinstance(artifact_digest, dict)
        or set(artifact_digest) != _V2_ARTIFACT_DIGEST_FIELDS
        or not isinstance(source, dict)
        or set(source) != _V2_SOURCE_FIELDS
    ):
        return None
    attestation_id = statement.get("attestation_id")
    digest_fields = (
        "mbom_sha256",
        "dependency_inventory_sha256",
        "training_lineage_sha256",
        "deployment_pipeline_sha256",
        "model_manifest_sha256",
    )
    valid = (
        value.get("algorithm") == "HMAC-SHA256"
        and _valid_attestation_identity(value.get("key_id"))
        and _valid_lower_sha256(value.get("signature"))
        and statement.get("statement_type") == _V2_ATTESTATION_TYPE
        and isinstance(attestation_id, str)
        and bool(_ATTESTATION_ID.fullmatch(attestation_id))
        and _valid_attestation_identity(subject.get("model_id"))
        and _valid_attestation_text(subject.get("model_name"))
        and _valid_attestation_text(subject.get("version"))
        and artifact_digest.get("algorithm") == "SHA-256"
        and _valid_lower_sha256(artifact_digest.get("value"))
        and predicate.get("predicate_type") == _V2_PREDICATE_TYPE
        and _valid_attestation_identity(predicate.get("issuer"))
        and _valid_attestation_text(source.get("provider"))
        and _valid_attestation_text(source.get("url"))
        and _valid_attestation_text(source.get("publisher"))
        and (
            source.get("revision") is None
            or _valid_attestation_text(source.get("revision"))
        )
        and all(
            _valid_lower_sha256(predicate.get(field))
            for field in digest_fields
        )
    )
    if not valid:
        return None
    statement_bytes = _canonical_json(statement)
    return {
        "schema_version": "2.0",
        "attestation_id": attestation_id,
        "model_id": subject.get("model_id"),
        "model_name": subject.get("model_name"),
        "version": subject.get("version"),
        "artifact_hash": _digest_value(artifact_digest.get("value")),
        "mbom_sha256": _digest_value(predicate.get("mbom_sha256")),
        "source": source.get("provider"),
        "source_url": source.get("url"),
        "publisher": source.get("publisher"),
        "revision": source.get("revision"),
        "issued_at": statement.get("issued_at"),
        "expires_at": statement.get("expires_at"),
        "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
        "dependency_inventory_sha256": _digest_value(
            predicate.get("dependency_inventory_sha256")
        ),
        "training_lineage_sha256": _digest_value(
            predicate.get("training_lineage_sha256")
        ),
        "deployment_pipeline_sha256": _digest_value(
            predicate.get("deployment_pipeline_sha256")
        ),
        "model_manifest_sha256": _digest_value(
            predicate.get("model_manifest_sha256")
        ),
    }


def _attestation_verification_passed(
    attestation: Dict[str, Any],
    view: Dict[str, Any],
    trusted_ids: set,
    trusted_digests: Dict[str, str],
    context_valid: bool,
    temporal_valid: bool,
) -> Tuple[bool, bool]:
    if view["schema_version"] == "2.0":
        attestation_id = view["attestation_id"]
        if (
            not context_valid
            or not temporal_valid
            or attestation_id not in trusted_ids
        ):
            return False, False
        expected_digest = trusted_digests.get(attestation_id)
        if expected_digest is not None and not hmac.compare_digest(
            expected_digest, view["statement_sha256"]
        ):
            return False, True
        return True, False
    verification = attestation.get("verification")
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        return False, False
    checks = verification.get("checks")
    required = {
        "signing_key_present",
        "supported_algorithm",
        "signature_valid",
        "model_id_matches",
        "artifact_hash_matches",
        "mbom_hash_matches",
    }
    passed = isinstance(checks, dict) and required.issubset(checks) and all(
        checks.get(check) is True for check in required
    )
    return passed, False


def _attestation_verification_context(
    value: Optional[Dict[str, Any]],
) -> Tuple[set, Dict[str, str], Optional[datetime], bool]:
    if value is None:
        return set(), {}, None, True
    if not isinstance(value, dict) or not set(value).issubset(
        _ATTESTATION_CONTEXT_FIELDS
    ):
        return set(), {}, None, False
    identifiers = value.get("verified_attestation_ids", [])
    digests = value.get("verified_attestation_digests", {})
    if (
        not isinstance(identifiers, list)
        or len(identifiers) > _MAX_ATTESTATIONS
        or not isinstance(digests, dict)
        or len(digests) > _MAX_ATTESTATIONS
    ):
        return set(), {}, None, False
    as_of = None
    if "as_of" in value:
        as_of = _strict_attestation_datetime(value.get("as_of"))
        if as_of is None:
            return set(), {}, None, False
    trusted_ids = set()
    for identifier in identifiers:
        if not isinstance(identifier, str) or not _ATTESTATION_ID.fullmatch(
            identifier
        ):
            return set(), {}, None, False
        trusted_ids.add(identifier)
    trusted_digests = {}
    for identifier, digest in digests.items():
        if (
            identifier not in trusted_ids
            or not isinstance(identifier, str)
            or not _ATTESTATION_ID.fullmatch(identifier)
            or not _valid_sha256(digest)
        ):
            return set(), {}, None, False
        trusted_digests[identifier] = _digest_value(digest)
    return trusted_ids, trusted_digests, as_of, True


def _expected_evidence_digest(
    artifact: Dict[str, Any],
    field: str,
    default: Any,
    *,
    explicit_digest_field: str,
) -> Optional[str]:
    explicit = _nested_evidence_value(artifact, explicit_digest_field)
    if _valid_sha256(explicit):
        return _digest_value(explicit)
    metadata = artifact.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    value = artifact.get(field)
    if value is None:
        value = metadata.get(field, default)
    try:
        return hashlib.sha256(_canonical_json(value)).hexdigest()
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def _nested_evidence_value(
    artifact: Dict[str, Any], field: str
) -> Any:
    value = artifact.get(field)
    if value is not None:
        return value
    metadata = artifact.get("metadata")
    return metadata.get(field) if isinstance(metadata, dict) else None


def _current_ai_bom_document_digest(
    artifact: Dict[str, Any],
) -> Optional[str]:
    try:
        document = generate_attestable_ai_bom_v2(artifact)
        verification = verify_ai_bom_v2(document)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None
    if not verification.get("verified"):
        return None
    digest = document.get("document_sha256")
    return _digest_value(digest) if _valid_sha256(digest) else None


def _evidence_quality(**evidence: Any) -> Dict[str, Any]:
    dimensions = {
        "source": bool(evidence["source_url"]),
        "artifact_integrity": _valid_sha256(evidence["artifact_hash"]),
        "dependencies": bool(evidence["dependencies"]),
        "training_lineage": bool(evidence["training_artifacts"]),
        "deployment_pipeline": isinstance(evidence["deployment_pipeline"], dict) and bool(evidence["deployment_pipeline"]),
        "provenance_attestation": bool(evidence["attestations"]),
        "vulnerability_scan": isinstance(evidence["vulnerability_scan"], dict) and bool(evidence["vulnerability_scan"]),
    }
    verification_failure_indicators = {
        "malformed_provenance_attestation",
        "malformed_attestation_verification_context",
        "unverified_provenance_attestation",
        "provenance_verification_binding_mismatch",
        "duplicate_provenance_attestation_id",
    }
    verified_attestation = bool(evidence["attestations"]) and not any(
        risk["indicator"] in verification_failure_indicators
        for risk in evidence["attestation_risks"]
    )
    malformed_count = sum(
        risk["indicator"] in _INCOMPLETE_INDICATORS for risk in evidence["all_risks"]
    )
    coverage = sum(dimensions.values()) / len(dimensions)
    confidence = coverage * (1.0 if verified_attestation else 0.9)
    confidence *= max(0.5, 1.0 - min(malformed_count, 5) * 0.1)
    return {
        "coverage_ratio": round(coverage, 3),
        "confidence": round(confidence, 3),
        "verified_attestation": verified_attestation,
        "dimensions": dimensions,
        "missing_dimensions": sorted(name for name, present in dimensions.items() if not present),
    }


def _valid_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", str(value or "").strip()))


def _valid_lower_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value)) if isinstance(value, str) else False


def _valid_attestation_identity(value: Any) -> bool:
    return isinstance(value, str) and bool(_ATTESTATION_ID.fullmatch(value))


def _valid_attestation_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= _MAX_TEXT_CHARS
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _digest_value(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text.removeprefix("sha256:")


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _strict_attestation_datetime(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _effective_evidence(value: Any) -> bool:
    if value is True:
        return True
    if value in (False, None):
        return False
    if isinstance(value, str):
        return _normalized(value) not in _DISABLED_VALUES
    if isinstance(value, dict):
        return value.get("verified") is True or value.get("approved") is True
    return False


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _nonnegative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed >= 0 else None


def _safe_evidence(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _redact_url_credentials(_bounded_text(value)) if isinstance(value, str) else value
    if isinstance(value, dict):
        return {str(key)[:128]: _safe_evidence(item) for key, item in list(value.items())[:30]}
    if isinstance(value, (list, tuple)):
        return [_safe_evidence(item) for item in list(value)[:30]]
    return _bounded_text(repr(value))


def _bounded_text(value: Any) -> str:
    return str(value or "").strip()[:_MAX_TEXT_CHARS]


def _redact_url_credentials(value: str) -> str:
    return _URL_USERINFO.sub(r"\g<prefix><redacted>@", value)


def _normalized(value: Any) -> str:
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _risk(dependency: Any, indicator: str, severity: str, detail: str) -> Dict[str, Any]:
    return {
        "dependency": _safe_evidence(dependency),
        "indicator": indicator,
        "severity": severity,
        "detail": detail,
    }


def _deduplicate_risks(risks: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    seen = set()
    for risk in risks:
        key = (
            risk.get("indicator"),
            json.dumps(risk.get("dependency"), sort_keys=True, default=str),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(risk)
    return result


def _limit_risks(risks: Iterable[Dict[str, Any]], detail: str) -> List[Dict[str, Any]]:
    deduplicated = _deduplicate_risks(risks)
    if len(deduplicated) <= _MAX_RISKS:
        return deduplicated
    return deduplicated[: _MAX_RISKS - 1] + [
        _risk(
            {"limit": _MAX_RISKS},
            "supply_chain_risk_limit_exceeded",
            "HIGH",
            detail,
        )
    ]


def _severity(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 5:
        return "HIGH"
    if score > 0:
        return "MEDIUM"
    return "LOW"


def _highest_severity(base: str, risks: Sequence[Dict[str, Any]]) -> str:
    selected = base
    for risk in risks:
        severity = str(risk.get("severity") or "LOW").upper()
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(selected, 0):
            selected = severity
    return selected

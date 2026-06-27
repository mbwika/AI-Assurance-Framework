"""Evidence-derived, uncertainty-aware provenance scoring for model artifacts."""

import math
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

PROVENANCE_SCORING_VERSION = "2.0"
_MAX_DEPENDENCIES = 2_000
_MAX_TRAINING_ARTIFACTS = 500
_MAX_ATTESTATIONS = 100
_MAX_TEXT_CHARS = 512
_SUPPORTED_STATEMENT = "https://aiaf.dev/attestation/model-provenance/v1"
_REQUIRED_VERIFICATION_CHECKS = {
    "signing_key_present",
    "supported_algorithm",
    "signature_valid",
    "model_id_matches",
    "artifact_hash_matches",
    "mbom_hash_matches",
    "key_id_matches",
}
_DIMENSION_WEIGHTS = {
    "source_identity": 0.18,
    "publisher_identity": 0.12,
    "artifact_integrity": 0.25,
    "training_lineage": 0.15,
    "component_inventory": 0.10,
    "release_traceability": 0.10,
    "signed_attestation": 0.10,
}


def assess_provenance_v2(
    model_record: dict[str, Any],
    assessment_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive a conservative 0-100 provenance trust score from evidence."""
    factors: list[dict[str, Any]] = []
    recommendations: list[str] = []
    trust_caps: list[dict[str, Any]] = []
    assessment_complete = True
    malformed_root = not isinstance(model_record, dict)
    if malformed_root:
        model_record = {}
        assessment_complete = False
        _factor(
            factors,
            "malformed_model_record",
            "CRITICAL",
            "Model provenance evidence must be an object.",
            "Provide a structured registry model record.",
        )
        _cap(trust_caps, "malformed_model_record", 10.0, "Malformed model evidence cannot establish provenance.")

    metadata = model_record.get("metadata")
    if metadata is None:
        metadata = {}
    elif not isinstance(metadata, dict):
        metadata = {}
        assessment_complete = False
        _factor(
            factors,
            "malformed_model_metadata",
            "HIGH",
            "Model metadata must be an object.",
            "Provide structured provenance metadata.",
        )
        _cap(trust_caps, "malformed_model_metadata", 40.0, "Malformed metadata limits provenance confidence.")

    context, context_complete = _context(assessment_context, factors)
    assessment_complete = assessment_complete and context_complete

    model_id = _bounded_text(model_record.get("model_id") or model_record.get("id"))
    model_name = _bounded_text(model_record.get("model_name"))
    version = _bounded_text(model_record.get("version"))
    source = _normalize(model_record.get("source"))
    source_url = model_record.get("source_url")
    publisher = _bounded_text(model_record.get("publisher"))
    artifact_hash = model_record.get("sha256") or model_record.get("sha256_hash")

    if not model_id or not model_name or not version:
        _factor(
            factors,
            "incomplete_model_identity",
            "HIGH",
            "Stable model identity or version evidence is missing.",
            "Bind provenance to model id, name, and immutable version.",
        )
        _cap(trust_caps, "incomplete_model_identity", 70.0, "Incomplete subject identity prevents high provenance trust.")

    source_info = _source_evidence(
        model_record,
        metadata,
        source,
        source_url,
        context,
        factors,
        trust_caps,
    )
    publisher_info = _publisher_evidence(
        model_record, metadata, publisher, context, factors
    )
    integrity_info = _integrity_evidence(
        model_record, metadata, artifact_hash, context, factors, trust_caps
    )
    attestation_info, attestation_complete = _attestation_evidence(
        model_record,
        metadata,
        model_id,
        artifact_hash,
        source,
        source_url,
        publisher,
        context,
        factors,
        trust_caps,
    )
    assessment_complete = assessment_complete and attestation_complete
    lineage_info, lineage_complete = _lineage_evidence(
        model_record, metadata, factors
    )
    assessment_complete = assessment_complete and lineage_complete
    inventory_info, inventory_complete = _inventory_evidence(
        model_record, metadata, attestation_info, factors
    )
    assessment_complete = assessment_complete and inventory_complete
    release_info = _release_evidence(
        model_record, metadata, artifact_hash, context, factors, trust_caps
    )

    dimensions = {
        "source_identity": _dimension(
            "source_identity",
            [
                _check("source_declared", 10, bool(source), 0.35),
                _check("source_url_valid", 15, source_info["url_valid"], 0.45),
                _check("secure_transport", 10, source_info["secure_transport"], 0.45),
                _check("provider_consistent", 15, source_info["provider_consistent"], 0.6),
                _check("organization_repository", 15, source_info["repository_identity"], 0.55),
                _check("immutable_revision", 15, source_info["immutable_revision"], 0.75),
                _check("source_evidence_fresh", 10, source_info["fresh"], 0.65),
                _check("verified_source_identity", 20, source_info["identity_verified"], 1.0),
            ],
        ),
        "publisher_identity": _dimension(
            "publisher_identity",
            [
                _check("publisher_declared", 25, bool(publisher), 0.35),
                _check("publisher_organization_bound", 20, publisher_info["organization_bound"], 0.6),
                _check("publisher_identity_verified", 45, publisher_info["verified"], 1.0),
                _check("attested_publisher_matches", 10, attestation_info["publisher_matches"], 0.9),
            ],
        ),
        "artifact_integrity": _dimension(
            "artifact_integrity",
            [
                _check("valid_sha256", 25, integrity_info["hash_valid"], 0.5),
                _check("observed_hash_matches", 55, integrity_info["verified_match"], 1.0),
                _check("attested_hash_matches", 20, attestation_info["artifact_hash_matches"], 1.0),
            ],
        ),
        "training_lineage": _dimension(
            "training_lineage",
            [
                _ratio_check("training_source_coverage", 30, lineage_info["source_coverage"], 0.55),
                _ratio_check("training_hash_coverage", 30, lineage_info["hash_coverage"], 0.65),
                _check("training_data_disclosed", 15, lineage_info["training_disclosed"], 0.4),
                _check("license_declared", 10, lineage_info["license_declared"], 0.4),
                _check("model_card_present", 15, lineage_info["model_card_present"], 0.55),
            ],
        ),
        "component_inventory": _dimension(
            "component_inventory",
            [
                _check("dependency_inventory_present", 30, inventory_info["inventory_present"], 0.45),
                _ratio_check("dependency_pin_coverage", 25, inventory_info["pin_coverage"], 0.55),
                _check("manifest_discovery_complete", 20, inventory_info["discovery_complete"], 0.7),
                _check("mbom_present", 10, inventory_info["mbom_present"], 0.5),
                _check("attested_mbom_matches", 15, attestation_info["mbom_hash_matches"], 1.0),
            ],
        ),
        "release_traceability": _dimension(
            "release_traceability",
            [
                _check("deployment_environment", 15, release_info["environment"], 0.4),
                _check("deployment_approval", 20, release_info["approval"], 0.55),
                _check("immutable_artifact_reference", 25, release_info["immutable_reference"], 0.75),
                _check("deployed_hash_matches", 30, release_info["hash_matches"], 1.0),
                _check("release_attestation_verified", 10, release_info["attestation_verified"], 1.0),
            ],
        ),
        "signed_attestation": _dimension(
            "signed_attestation",
            [
                _check("attestation_present", 15, attestation_info["present"], 0.35),
                _check("attestation_shape_valid", 15, attestation_info["shape_valid"], 0.5),
                _check("signature_verified", 35, attestation_info["signature_verified"], 1.0),
                _check("subject_binding_verified", 25, attestation_info["subject_binding_verified"], 1.0),
                _check("key_identity_verified", 10, attestation_info["key_identity_verified"], 1.0),
            ],
        ),
    }

    point_estimate = sum(
        _DIMENSION_WEIGHTS[name] * dimension["score"]
        for name, dimension in dimensions.items()
    )
    lower_estimate = sum(
        _DIMENSION_WEIGHTS[name] * dimension["lower_bound"]
        for name, dimension in dimensions.items()
    )
    upper_estimate = sum(
        _DIMENSION_WEIGHTS[name] * dimension["upper_bound"]
        for name, dimension in dimensions.items()
    )
    confidence = sum(
        _DIMENSION_WEIGHTS[name] * dimension["confidence"]
        for name, dimension in dimensions.items()
    )

    if not attestation_info["signature_verified"]:
        _cap(
            trust_caps,
            "no_verified_signed_provenance",
            75.0,
            "Unverified signed provenance cannot produce a LOW-risk trust classification.",
        )
    if not publisher_info["verified"]:
        _cap(
            trust_caps,
            "publisher_identity_not_verified",
            80.0,
            "Unverified publisher identity limits provenance trust.",
        )
    if not source_info["identity_verified"]:
        _cap(
            trust_caps,
            "source_identity_not_verified",
            80.0,
            "Unverified source identity limits provenance trust.",
        )

    conservative_score = lower_estimate
    for gate in trust_caps:
        conservative_score = min(conservative_score, gate["maximum_score"])
    conservative_score = round(max(0.0, min(100.0, conservative_score)), 2)
    point_estimate = round(max(0.0, min(100.0, point_estimate)), 2)
    upper_estimate = round(max(point_estimate, min(100.0, upper_estimate)), 2)
    lower_estimate = round(min(point_estimate, max(0.0, lower_estimate)), 2)
    risk_level = determine_provenance_risk(conservative_score)

    for factor in factors:
        recommendation = factor.get("recommendation")
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    return {
        "scoring_version": PROVENANCE_SCORING_VERSION,
        "methodology": "evidence_derived_confidence_weighted_provenance",
        "score_scale": {"minimum": 0.0, "maximum": 100.0, "direction": "higher_is_better"},
        "provenance_score": conservative_score,
        "score": conservative_score,
        "point_estimate": point_estimate,
        "lower_confidence_bound": conservative_score,
        "uncapped_lower_bound": lower_estimate,
        "upper_confidence_bound": upper_estimate,
        "risk_level": risk_level,
        "severity": risk_level,
        "confidence": round(confidence, 3),
        "assessment_complete": assessment_complete,
        "indicators": _unique(factor["indicator"] for factor in factors),
        "factors": factors,
        "dimensions": dimensions,
        "trust_caps": sorted(
            trust_caps, key=lambda item: (item["maximum_score"], item["gate"])
        ),
        "evidence_quality": {
            "confidence": round(confidence, 3),
            "verified_dimension_count": sum(
                dimension["confidence"] >= 0.8 for dimension in dimensions.values()
            ),
            "dimension_count": len(dimensions),
            "verified_attestation_count": attestation_info["verified_count"],
            "training_artifact_count": lineage_info["artifact_count"],
            "dependency_count": inventory_info["dependency_count"],
        },
        "evidence": {
            "model_id_bound": bool(model_id),
            "model_name_bound": bool(model_name),
            "version_bound": bool(version),
            "source": source or None,
            "source_host": source_info["host"],
            "publisher_declared": bool(publisher),
            "artifact_hash_present": bool(artifact_hash),
            "artifact_hash_valid": integrity_info["hash_valid"],
            "caller_score_ignored": model_record.get("provenance_score") is not None,
        },
        "recommendations": recommendations,
    }


def determine_provenance_risk(score: Any) -> str:
    """Map a bounded provenance trust score to inverse risk severity."""
    try:
        value = float(score)
    except (TypeError, ValueError, OverflowError):
        return "CRITICAL"
    if not math.isfinite(value):
        return "CRITICAL"
    if value >= 85:
        return "LOW"
    if value >= 70:
        return "MEDIUM"
    if value >= 50:
        return "HIGH"
    return "CRITICAL"


def _context(value, factors):
    result = {"as_of": None, "max_source_age_days": 365, "trusted_evidence": {}}
    if value is None:
        return result, True
    if not isinstance(value, dict):
        _factor(
            factors,
            "malformed_provenance_context",
            "HIGH",
            "Provenance assessment context must be an object.",
            "Provide an explicit assessment time and bounded freshness policy.",
        )
        return result, False
    complete = True
    trusted_evidence = value.get("trusted_evidence")
    if trusted_evidence is not None:
        if isinstance(trusted_evidence, dict):
            result["trusted_evidence"] = trusted_evidence
        else:
            complete = False
            _factor(
                factors,
                "malformed_trusted_provenance_evidence",
                "HIGH",
                "Trusted provenance evidence must be an object.",
                "Pass verifier outputs through the trusted assessment context.",
            )
    if value.get("as_of") is not None:
        result["as_of"] = _parse_datetime(value.get("as_of"))
        if result["as_of"] is None:
            complete = False
            _factor(
                factors,
                "malformed_provenance_context",
                "HIGH",
                "Assessment time is malformed.",
                "Use an ISO-8601 assessment time with timezone.",
            )
    if value.get("max_source_age_days") is not None:
        age = _positive_int(value.get("max_source_age_days"))
        if age is None or age > 3_650:
            complete = False
            _factor(
                factors,
                "malformed_provenance_context",
                "HIGH",
                "Source freshness limit must be between 1 and 3650 days.",
                "Use a bounded source-evidence freshness period.",
            )
        else:
            result["max_source_age_days"] = age
    return result, complete


def _source_evidence(record, metadata, source, source_url, context, factors, caps):
    text = _bounded_text(source_url)
    host = None
    secure = False
    valid = False
    credentials = False
    try:
        parsed = urlsplit(text)
        _ = parsed.port
        host = (parsed.hostname or "").lower() or None
        valid = parsed.scheme.lower() in {"https", "http"} and host is not None
        secure = valid and parsed.scheme.lower() == "https"
        credentials = parsed.username is not None or parsed.password is not None
    except (TypeError, ValueError):
        parsed = None
    if not valid:
        _factor(factors, "missing_or_malformed_source_url", "HIGH", "Model source URL is absent or malformed.", "Record a canonical HTTPS source URL.")
        _cap(caps, "missing_or_malformed_source_url", 55.0, "Unknown source location limits provenance trust.")
    elif not secure:
        _factor(factors, "insecure_source_transport", "HIGH", "Model source uses unauthenticated HTTP.", "Use HTTPS or an authenticated artifact registry.")
        _cap(caps, "insecure_source_transport", 40.0, "Insecure source transport permits substitution.")
    if credentials:
        _factor(factors, "source_url_contains_credentials", "CRITICAL", "Model source URL embeds credentials.", "Remove URL credentials and rotate the exposed secret.")
        _cap(caps, "source_url_contains_credentials", 20.0, "Credential-bearing source evidence is unsafe.")

    detected = _provider_for_host(host)
    provider_consistent = bool(source and detected and source == detected)
    if source and detected and source != detected:
        _factor(factors, "source_provider_mismatch", "HIGH", "Declared source provider conflicts with the source host.", "Reconcile provider identity with the canonical source URL.")
        _cap(caps, "source_provider_mismatch", 50.0, "Contradictory provider identity limits provenance trust.")
    source_meta = record.get("source_metadata") or metadata.get("source_metadata") or metadata.get("source_tracking")
    source_meta = source_meta if isinstance(source_meta, dict) else {}
    tracked_provider = _normalize(source_meta.get("provider"))
    if tracked_provider and source and tracked_provider != source:
        _factor(factors, "source_tracking_provider_mismatch", "HIGH", "Source tracking provider conflicts with the model record.", "Regenerate source tracking from the canonical record.")
        _cap(caps, "source_tracking_provider_mismatch", 45.0, "Contradictory source tracking limits trust.")
    meta_url = source_meta.get("source_url")
    if meta_url and text and str(meta_url).strip() != text:
        _factor(factors, "source_tracking_url_mismatch", "HIGH", "Source tracking URL conflicts with the model record.", "Regenerate source tracking from the canonical record.")
        _cap(caps, "source_tracking_url_mismatch", 45.0, "Contradictory source tracking limits trust.")
    repository_identity = bool(source_meta.get("organization") and source_meta.get("repository"))
    revision = source_meta.get("revision") or source_meta.get("commit") or record.get("source_revision")
    immutable_revision = _immutable_revision(revision) or _url_contains_immutable_revision(text)
    identity_verification = context["trusted_evidence"].get("source_identity")
    identity_verified = _verification_passed(identity_verification, ("identity_matches", "source_matches"))
    retrieval_time = _parse_datetime(source_meta.get("retrieval_time"))
    fresh = False
    if source_meta.get("retrieval_time") and retrieval_time is None:
        _factor(factors, "invalid_source_retrieval_time", "MEDIUM", "Source retrieval time is malformed.", "Record a timezone-aware retrieval time.")
    if retrieval_time and context["as_of"]:
        if retrieval_time > context["as_of"]:
            _factor(factors, "future_source_retrieval_time", "HIGH", "Source retrieval time is later than the assessment time.", "Correct source evidence timestamps.")
            _cap(caps, "future_source_retrieval_time", 40.0, "Future-dated source evidence is not trustworthy.")
        elif (context["as_of"] - retrieval_time).days > context["max_source_age_days"]:
            _factor(factors, "stale_source_evidence", "MEDIUM", "Source tracking evidence exceeds the freshness policy.", "Refresh source identity and artifact retrieval evidence.")
            _cap(caps, "stale_source_evidence", 75.0, "Stale source evidence cannot establish current low-risk provenance.")
        else:
            fresh = True
    return {
        "host": host,
        "url_valid": valid,
        "secure_transport": secure,
        "provider_consistent": provider_consistent,
        "repository_identity": repository_identity,
        "immutable_revision": immutable_revision,
        "fresh": fresh,
        "identity_verified": identity_verified,
    }


def _publisher_evidence(record, metadata, publisher, context, factors):
    verification = context["trusted_evidence"].get("publisher_identity")
    verified = _verification_passed(verification, ("publisher_matches", "identity_verified"))
    organization_bound = False
    if isinstance(verification, dict):
        organization_bound = bool(verification.get("organization") or verification.get("issuer"))
        expected = verification.get("publisher")
        if expected and publisher and _normalize(expected) != _normalize(publisher):
            verified = False
            _factor(factors, "publisher_identity_mismatch", "HIGH", "Verified publisher identity conflicts with the model record.", "Reconcile publisher identity before registration.")
    return {"verified": verified, "organization_bound": organization_bound}


def _integrity_evidence(record, metadata, artifact_hash, context, factors, caps):
    valid = _valid_sha256(artifact_hash)
    if not artifact_hash:
        _factor(factors, "missing_artifact_hash", "CRITICAL", "Model artifact has no SHA-256 digest.", "Compute and persist the model artifact digest.")
        _cap(caps, "missing_artifact_hash", 35.0, "Missing artifact integrity evidence prevents provenance assurance.")
    elif not valid:
        _factor(factors, "malformed_artifact_hash", "CRITICAL", "Model artifact digest is malformed.", "Replace malformed integrity evidence with a valid SHA-256 digest.")
        _cap(caps, "malformed_artifact_hash", 20.0, "Malformed integrity evidence cannot establish artifact identity.")
    verification = context["trusted_evidence"].get("artifact_integrity")
    verified_match = False
    if isinstance(verification, dict):
        observed = verification.get("observed_sha256") or verification.get("actual_sha256")
        expected = verification.get("expected_sha256") or artifact_hash
        declared_verified = verification.get("verified") is True or verification.get("hash_matches") is True
        if declared_verified and _valid_sha256(observed) and _valid_sha256(expected):
            verified_match = _digest(observed) == _digest(expected) == _digest(artifact_hash)
        explicit_failure = verification.get("verified") is False or verification.get("hash_matches") is False
        mismatch = (
            _valid_sha256(observed)
            and _valid_sha256(artifact_hash)
            and _digest(observed) != _digest(artifact_hash)
        )
        if explicit_failure or mismatch:
            _factor(factors, "artifact_integrity_mismatch", "CRITICAL", "Observed artifact digest does not match the registry record.", "Quarantine the artifact and investigate substitution.")
            _cap(caps, "artifact_integrity_mismatch", 0.0, "Observed artifact tampering invalidates provenance trust.")
    return {"hash_valid": valid, "verified_match": verified_match}


def _attestation_evidence(record, metadata, model_id, artifact_hash, source, source_url, publisher, context, factors, caps):
    raw = record.get("provenance_attestations")
    if raw is None:
        raw = metadata.get("provenance_attestations")
    items, state = _bounded_items(raw, _MAX_ATTESTATIONS)
    complete = state != "malformed" and state != "truncated"
    if state == "malformed":
        _factor(factors, "malformed_attestation_inventory", "HIGH", "Provenance attestations must be a list or object.", "Provide structured signed attestation evidence.")
    if state == "truncated":
        _factor(factors, "attestation_analysis_limit_exceeded", "HIGH", "Provenance attestations exceed the analysis bound.", "Segment or summarize attestation evidence.")
    present = bool(items)
    shape_valid_count = 0
    verified_count = 0
    signature_verified = False
    subject_verified = False
    key_verified = False
    artifact_matches = False
    mbom_matches = False
    publisher_matches = False
    bindings = set()
    trusted_verifications = context["trusted_evidence"].get("provenance_attestations")
    if not isinstance(trusted_verifications, (list, tuple)):
        trusted_verifications = []
    for index, item in enumerate(items):
        if not _valid_attestation_shape(item):
            _factor(factors, "malformed_provenance_attestation", "HIGH", "Provenance attestation shape is invalid.", "Use the supported model provenance statement schema.", evidence={"index": index})
            continue
        shape_valid_count += 1
        statement = item["statement"]
        subject = statement["subject"]
        predicate = statement["predicate"]
        binding = (str(subject.get("model_id")), _digest(subject.get("sha256")), _digest(predicate.get("mbom_sha256")))
        bindings.add(binding)
        verification = (
            trusted_verifications[index]
            if index < len(trusted_verifications)
            else None
        )
        passed = _attestation_verification_passed(verification)
        checks = verification.get("checks", {}) if isinstance(verification, dict) else {}
        if passed:
            verified_count += 1
            signature_verified = True
            key_verified = key_verified or checks.get("key_id_matches", True) is True
            subject_verified = True
            artifact_matches = True
            mbom_matches = True
        elif isinstance(verification, dict) and verification.get("verified") is False:
            _factor(factors, "failed_provenance_attestation_verification", "CRITICAL", "Cryptographic provenance verification failed.", "Reject the attestation and investigate signing or subject tampering.", evidence={"index": index})
            _cap(caps, "failed_provenance_attestation_verification", 25.0, "Failed signature verification invalidates signed provenance.")
        if model_id and subject.get("model_id") != model_id:
            subject_verified = False
            _factor(factors, "attestation_subject_mismatch", "CRITICAL", "Attestation subject id does not match the model record.", "Reject the mismatched attestation.", evidence={"index": index})
            _cap(caps, "attestation_subject_mismatch", 10.0, "Mismatched attestation subject invalidates provenance binding.")
        if _valid_sha256(artifact_hash) and _digest(subject.get("sha256")) != _digest(artifact_hash):
            artifact_matches = False
            _factor(factors, "attestation_artifact_hash_mismatch", "CRITICAL", "Attested artifact digest does not match the model record.", "Quarantine the record and artifact.", evidence={"index": index})
            _cap(caps, "attestation_artifact_hash_mismatch", 0.0, "Attested artifact mismatch invalidates provenance trust.")
        source_fields_match = (
            (not source or _normalize(predicate.get("source")) == source)
            and (not source_url or predicate.get("source_url") == source_url)
            and (not publisher or _normalize(predicate.get("publisher")) == _normalize(publisher))
        )
        if not source_fields_match:
            _factor(factors, "attestation_source_mismatch", "HIGH", "Attested source or publisher conflicts with the model record.", "Reconcile source metadata and issue a new attestation.", evidence={"index": index})
            _cap(caps, "attestation_source_mismatch", 35.0, "Contradictory attested source limits provenance trust.")
        else:
            publisher_matches = publisher_matches or bool(publisher)
    if len(bindings) > 1:
        _factor(factors, "conflicting_provenance_attestations", "CRITICAL", "Attestations bind conflicting model or AI-BOM identities.", "Revoke conflicting attestations and establish one canonical subject.")
        _cap(caps, "conflicting_provenance_attestations", 10.0, "Conflicting signed bindings invalidate provenance coherence.")
    return {
        "present": present,
        "shape_valid": shape_valid_count > 0,
        "verified_count": verified_count,
        "signature_verified": signature_verified,
        "subject_binding_verified": subject_verified and artifact_matches,
        "key_identity_verified": key_verified,
        "artifact_hash_matches": artifact_matches,
        "mbom_hash_matches": mbom_matches,
        "publisher_matches": publisher_matches,
    }, complete


def _lineage_evidence(record, metadata, factors):
    raw = record.get("training_artifacts")
    if raw is None:
        raw = metadata.get("training_artifacts")
    items, state = _bounded_items(raw, _MAX_TRAINING_ARTIFACTS)
    complete = state == "ok"
    if state == "malformed":
        _factor(factors, "malformed_training_lineage", "HIGH", "Training artifacts must be a list or object.", "Provide structured training lineage evidence.")
    if state == "truncated":
        _factor(factors, "training_lineage_limit_exceeded", "HIGH", "Training lineage exceeds the analysis bound.", "Segment or summarize training lineage evidence.")
    structured = [item for item in items if isinstance(item, dict)]
    if len(structured) != len(items):
        complete = False
        _factor(factors, "malformed_training_artifact", "MEDIUM", "Training lineage contains unstructured entries.", "Record source and hash for each training artifact.")
    count = len(items)
    source_coverage = sum(bool(item.get("source") or item.get("source_url")) for item in structured) / count if count else 0.0
    hash_coverage = sum(_valid_sha256(item.get("sha256") or item.get("hash")) for item in structured) / count if count else 0.0
    model_card = record.get("model_card") or metadata.get("model_card") or metadata.get("documentation_url")
    return {
        "artifact_count": count,
        "source_coverage": source_coverage,
        "hash_coverage": hash_coverage,
        "training_disclosed": bool(record.get("training_data") or metadata.get("training_data") or count),
        "license_declared": bool(record.get("license") or metadata.get("license")),
        "model_card_present": _effective_evidence(model_card),
    }, complete


def _inventory_evidence(record, metadata, attestation, factors):
    raw = record.get("dependencies")
    if raw is None:
        raw = metadata.get("dependencies")
    items, state = _bounded_items(raw, _MAX_DEPENDENCIES)
    complete = state == "ok"
    if state == "malformed":
        _factor(factors, "malformed_dependency_inventory", "HIGH", "Dependency inventory must be a list, object, or text.", "Provide a bounded AI-BOM dependency inventory.")
    if state == "truncated":
        _factor(factors, "dependency_inventory_limit_exceeded", "HIGH", "Dependency inventory exceeds the analysis bound.", "Segment or summarize the dependency inventory.")
    pinned = sum(_dependency_is_pinned(item) for item in items)
    discovery = record.get("dependency_discovery") or metadata.get("dependency_discovery")
    discovery = discovery if isinstance(discovery, dict) else {}
    errors = discovery.get("errors")
    discovery_complete = bool(discovery.get("manifests")) and not errors
    mbom = record.get("mbom") or metadata.get("mbom")
    return {
        "dependency_count": len(items),
        "inventory_present": bool(items),
        "pin_coverage": pinned / len(items) if items else 0.0,
        "discovery_complete": discovery_complete,
        "mbom_present": isinstance(mbom, dict) and bool(mbom),
    }, complete


def _release_evidence(record, metadata, artifact_hash, context, factors, caps):
    pipeline = record.get("deployment_pipeline")
    if pipeline is None:
        pipeline = metadata.get("deployment_pipeline")
    if pipeline in (None, ""):
        pipeline = {}
    if not isinstance(pipeline, dict):
        _factor(factors, "malformed_deployment_evidence", "HIGH", "Deployment pipeline evidence must be an object.", "Provide structured release traceability evidence.")
        pipeline = {}
    artifact_ref = _bounded_text(pipeline.get("artifact_ref") or pipeline.get("image"))
    digest = _reference_digest(artifact_ref)
    contains_digest = "@sha256:" in artifact_ref.lower()
    if contains_digest and digest is None:
        _factor(factors, "malformed_deployment_digest", "HIGH", "Deployment reference contains a malformed digest.", "Use a complete SHA-256 artifact reference.")
    hash_matches = bool(digest and _valid_sha256(artifact_hash) and digest == _digest(artifact_hash))
    if digest and _valid_sha256(artifact_hash) and not hash_matches:
        _factor(factors, "deployment_artifact_hash_mismatch", "CRITICAL", "Deployment digest does not match the registered model artifact.", "Stop deployment and investigate artifact substitution.")
        _cap(caps, "deployment_artifact_hash_mismatch", 5.0, "Deployment substitution invalidates provenance trust.")
    approval = _effective_evidence(pipeline.get("approval_gate") or pipeline.get("change_ticket"))
    release_verification = context["trusted_evidence"].get("release")
    attestation_verified = _verification_passed(release_verification, ("artifact_matches", "signature_valid"))
    return {
        "environment": bool(pipeline.get("environment")),
        "approval": approval,
        "immutable_reference": digest is not None,
        "hash_matches": hash_matches,
        "attestation_verified": attestation_verified,
    }


def _dimension(name, checks):
    total = sum(check["weight"] for check in checks)
    earned = sum(check["earned"] for check in checks)
    score = 100.0 * earned / total if total else 0.0
    confidence = (
        sum(check["weight"] * check["evidence_strength"] for check in checks if check["satisfied"])
        / total
        if total
        else 0.0
    )
    lower = score * (0.7 + 0.3 * confidence)
    upper = score + (100.0 - score) * (1.0 - confidence) * 0.2
    return {
        "score": round(score, 3),
        "lower_bound": round(lower, 3),
        "upper_bound": round(min(100.0, upper), 3),
        "confidence": round(confidence, 3),
        "checks": checks,
    }


def _check(name, weight, satisfied, evidence_strength):
    return {
        "check": name,
        "weight": float(weight),
        "satisfied": bool(satisfied),
        "earned": float(weight) if satisfied else 0.0,
        "evidence_strength": float(evidence_strength) if satisfied else 0.0,
    }


def _ratio_check(name, weight, ratio, evidence_strength):
    ratio = max(0.0, min(1.0, float(ratio)))
    return {
        "check": name,
        "weight": float(weight),
        "satisfied": ratio >= 1.0,
        "coverage": round(ratio, 3),
        "earned": float(weight) * ratio,
        "evidence_strength": float(evidence_strength) * ratio,
    }


def _valid_attestation_shape(value):
    if not isinstance(value, dict) or value.get("algorithm") != "HMAC-SHA256":
        return False
    statement = value.get("statement")
    if not isinstance(statement, dict) or statement.get("statement_type") != _SUPPORTED_STATEMENT:
        return False
    subject = statement.get("subject")
    predicate = statement.get("predicate")
    return (
        isinstance(subject, dict)
        and bool(subject.get("model_id"))
        and _valid_sha256(subject.get("sha256"))
        and isinstance(predicate, dict)
        and _valid_sha256(predicate.get("mbom_sha256"))
        and _valid_sha256(value.get("signature"))
        and bool(value.get("key_id"))
    )


def _attestation_verification_passed(value):
    if not isinstance(value, dict) or value.get("verified") is not True:
        return False
    checks = value.get("checks")
    return isinstance(checks, dict) and _REQUIRED_VERIFICATION_CHECKS.issubset(checks) and all(
        checks.get(check) is True for check in _REQUIRED_VERIFICATION_CHECKS
    )


def _verification_passed(value, expected_checks):
    if value is True:
        return True
    if not isinstance(value, dict) or value.get("verified") is not True:
        return False
    checks = value.get("checks")
    if not isinstance(checks, dict):
        return False
    expected = set(expected_checks)
    return expected.issubset(checks) and all(checks.get(check) is True for check in expected)


def _bounded_items(value, limit):
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


def _dependency_is_pinned(value):
    if isinstance(value, dict):
        version = str(value.get("version") or "").strip()
        ecosystem = _normalize(value.get("ecosystem"))
        if ecosystem in {"npm", "node", "nodejs"}:
            return bool(re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9.-]+)?", version))
        return bool(re.fullmatch(r"={2,3}[^*,<>=~!\s]+", version))
    text = str(value or "").strip()
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+={2,3}[^*,<>=~!\s]+", text))


def _provider_for_host(host):
    if not host:
        return None
    if host == "huggingface.co" or host.endswith(".huggingface.co"):
        return "huggingface"
    if host == "github.com" or host.endswith(".github.com"):
        return "github"
    if host in {"modelscope.cn", "modelscope.com"} or host.endswith((".modelscope.cn", ".modelscope.com")):
        return "modelscope"
    return None


def _url_contains_immutable_revision(value):
    text = str(value or "")
    return bool(
        re.search(r"/(?:commit|tree|resolve)/[0-9a-fA-F]{40}(?:/|$)", text)
        or re.search(r"[?&](?:revision|commit)=[0-9a-fA-F]{40}(?:&|$)", text)
    )


def _immutable_revision(value):
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", str(value or "").strip()))


def _reference_digest(value):
    match = re.search(r"@sha256:([0-9a-fA-F]{64})(?:$|[?#])", str(value or ""), re.IGNORECASE)
    return match.group(1).lower() if match else None


def _valid_sha256(value):
    return bool(re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", str(value or "").strip()))


def _digest(value):
    return str(value or "").strip().lower().removeprefix("sha256:")


def _effective_evidence(value):
    if value is True:
        return True
    if value in (None, False):
        return False
    if isinstance(value, str):
        return _normalize(value) not in {"", "false", "none", "no", "disabled", "off"}
    if isinstance(value, dict):
        return value.get("verified") is True or value.get("approved") is True
    if isinstance(value, (list, tuple)):
        return bool(value)
    return False


def _parse_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _positive_int(value):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed > 0 else None


def _factor(factors, indicator, severity, detail, recommendation, evidence=None):
    candidate = {
        "indicator": indicator,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }
    if evidence is not None:
        candidate["evidence"] = evidence
    if candidate not in factors:
        factors.append(candidate)


def _cap(caps, gate, maximum_score, reason):
    candidate = {
        "gate": gate,
        "maximum_score": float(maximum_score),
        "reason": reason,
    }
    if candidate not in caps:
        caps.append(candidate)


def _bounded_text(value):
    return str(value or "").strip()[:_MAX_TEXT_CHARS]


def _normalize(value):
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))

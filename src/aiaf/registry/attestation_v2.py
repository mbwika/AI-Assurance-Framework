"""Hardened model-provenance attestations with explicit evidence bindings."""

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .mbom_v2 import generate_attestable_ai_bom_v2, verify_ai_bom_v2

PROVENANCE_ATTESTATION_SCHEMA_VERSION = "2.0"
PROVENANCE_ATTESTATION_ALGORITHM = "HMAC-SHA256"
PROVENANCE_STATEMENT_TYPE = "https://aiaf.dev/attestation/model-provenance/v2"
PROVENANCE_PREDICATE_TYPE = "https://aiaf.dev/attestation/model-provenance-predicate/v2"

_DOMAIN_SEPARATOR = b"AIAF-PROVENANCE-ATTESTATION-V2\x00"
_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 4_096
_MAX_CANONICAL_BYTES = 10 * 1024 * 1024
_MAX_JSON_DEPTH = 24
_MAX_JSON_NODES = 250_000
_MAX_STRING_BYTES = 1024 * 1024
_MAX_OBJECT_KEY_BYTES = 256
_MAX_IDENTITY_BYTES = 256
_MAX_TEXT_BYTES = 4_096
_MAX_INTEGER = 2**63 - 1
_DEFAULT_MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60
_DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
_DEFAULT_MAX_FUTURE_SKEW_SECONDS = 5 * 60
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_ENVELOPE_FIELDS = frozenset(
    {"schema_version", "algorithm", "key_id", "statement", "signature"}
)
_STATEMENT_FIELDS = frozenset(
    {"statement_type", "attestation_id", "subject", "predicate", "issued_at", "expires_at"}
)
_SUBJECT_FIELDS = frozenset({"model_id", "model_name", "version", "artifact_digest"})
_ARTIFACT_DIGEST_FIELDS = frozenset({"algorithm", "value"})
_PREDICATE_FIELDS = frozenset(
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
_SOURCE_FIELDS = frozenset({"provider", "url", "publisher", "revision"})
_CHECK_NAMES = (
    "attestation_is_object",
    "strict_envelope_fields",
    "schema_version_supported",
    "supported_algorithm",
    "key_id_valid",
    "statement_shape_valid",
    "statement_type_supported",
    "predicate_type_supported",
    "attestation_id_valid",
    "issuer_valid",
    "subject_identity_valid",
    "artifact_digest_valid",
    "evidence_digests_valid",
    "canonical_statement_valid",
    "canonical_statement_bounded",
    "signature_shape_valid",
    "signing_key_strong",
    "signature_valid",
    "verification_policy_complete",
    "attestation_id_matches_policy",
    "key_id_matches",
    "issuer_matches_policy",
    "as_of_valid",
    "issued_at_valid",
    "expires_at_valid",
    "issued_at_not_future",
    "attestation_fresh",
    "expiration_after_issuance",
    "lifetime_within_policy",
    "attestation_not_expired",
    "expected_model_valid",
    "model_id_matches",
    "model_name_matches",
    "version_matches",
    "artifact_hash_matches",
    "source_matches",
    "publisher_matches",
    "revision_matches",
    "mbom_hash_matches",
    "dependency_inventory_matches",
    "training_lineage_matches",
    "deployment_pipeline_matches",
    "model_manifest_matches",
)


def create_provenance_attestation_v2(
    model_record: dict[str, Any],
    signing_key: Any,
    *,
    attestation_id: str,
    key_id: str,
    issuer: str,
    issued_at: str,
    expires_at: str,
    as_of: str,
    max_lifetime_seconds: int = _DEFAULT_MAX_LIFETIME_SECONDS,
    max_age_seconds: int = _DEFAULT_MAX_AGE_SECONDS,
    max_future_skew_seconds: int = _DEFAULT_MAX_FUTURE_SKEW_SECONDS,
) -> dict[str, Any]:
    """Create and self-check a schema-2 provenance attestation."""
    evidence, evidence_error = _model_evidence(model_record)
    if evidence_error:
        raise ValueError(f"Model evidence is not attestable: {evidence_error}")
    statement = {
        "statement_type": PROVENANCE_STATEMENT_TYPE,
        "attestation_id": attestation_id,
        "subject": evidence["subject"],
        "predicate": {
            "predicate_type": PROVENANCE_PREDICATE_TYPE,
            "issuer": issuer,
            "source": evidence["source"],
            "mbom_sha256": evidence["mbom_sha256"],
            "dependency_inventory_sha256": evidence["dependency_inventory_sha256"],
            "training_lineage_sha256": evidence["training_lineage_sha256"],
            "deployment_pipeline_sha256": evidence["deployment_pipeline_sha256"],
            "model_manifest_sha256": evidence["model_manifest_sha256"],
        },
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    statement_bytes, statement_error = _canonical_json(statement)
    key = _key_bytes(signing_key)
    if statement_error or statement_bytes is None:
        raise ValueError(f"Attestation statement is not canonically signable: {statement_error}")
    if key is None:
        raise ValueError("Attestation signing key must contain at least 32 bytes")
    attestation = {
        "schema_version": PROVENANCE_ATTESTATION_SCHEMA_VERSION,
        "algorithm": PROVENANCE_ATTESTATION_ALGORITHM,
        "key_id": key_id,
        "statement": statement,
        "signature": _sign(statement_bytes, key),
    }
    policy = {
        "expected_attestation_id": attestation_id,
        "expected_key_id": key_id,
        "expected_issuer": issuer,
        "as_of": as_of,
        "max_lifetime_seconds": max_lifetime_seconds,
        "max_age_seconds": max_age_seconds,
        "max_future_skew_seconds": max_future_skew_seconds,
    }
    verification = verify_provenance_attestation_v2(
        attestation, signing_key, model_record, policy
    )
    if not verification["verified"]:
        raise ValueError(
            "Invalid provenance attestation: " + ", ".join(verification["failed_checks"])
        )
    return attestation


def verify_provenance_attestation_v2(
    attestation: Any,
    signing_key: Any,
    expected_model: Any,
    verification_context: dict[str, Any] | None,
) -> dict[str, Any]:
    """Verify envelope integrity, trusted subject bindings, and time policy."""
    checks = {name: False for name in _CHECK_NAMES}
    diagnostics: list[dict[str, Any]] = []
    envelope = attestation if isinstance(attestation, dict) else {}
    checks["attestation_is_object"] = isinstance(attestation, dict)
    checks["strict_envelope_fields"] = checks["attestation_is_object"] and set(envelope) == _ENVELOPE_FIELDS
    checks["schema_version_supported"] = (
        envelope.get("schema_version") == PROVENANCE_ATTESTATION_SCHEMA_VERSION
    )
    checks["supported_algorithm"] = (
        envelope.get("algorithm") == PROVENANCE_ATTESTATION_ALGORITHM
    )
    checks["key_id_valid"] = _valid_identity(envelope.get("key_id"))

    statement = envelope.get("statement")
    shape = _statement_shape(statement)
    checks.update(shape["checks"])
    diagnostics.extend(shape["diagnostics"])
    statement_object = statement if isinstance(statement, dict) else {}
    subject = statement_object.get("subject") if isinstance(statement_object.get("subject"), dict) else {}
    predicate = statement_object.get("predicate") if isinstance(statement_object.get("predicate"), dict) else {}
    source = predicate.get("source") if isinstance(predicate.get("source"), dict) else {}

    statement_bytes, statement_error = _canonical_json(statement_object)
    checks["canonical_statement_valid"] = statement_bytes is not None
    checks["canonical_statement_bounded"] = statement_bytes is not None and len(statement_bytes) <= _MAX_CANONICAL_BYTES
    if statement_error:
        diagnostics.append(
            {
                "indicator": "invalid_canonical_statement",
                "severity": "HIGH",
                "detail": statement_error,
            }
        )
    signature = envelope.get("signature")
    checks["signature_shape_valid"] = isinstance(signature, str) and bool(
        _SIGNATURE.fullmatch(signature)
    )
    key = _key_bytes(signing_key)
    checks["signing_key_strong"] = key is not None
    if (
        statement_bytes is not None
        and checks["canonical_statement_bounded"]
        and checks["supported_algorithm"]
        and checks["signature_shape_valid"]
        and key is not None
    ):
        checks["signature_valid"] = hmac.compare_digest(
            signature, _sign(statement_bytes, key)
        )

    policy, policy_complete = _verification_policy(verification_context, diagnostics)
    checks["verification_policy_complete"] = policy_complete
    checks["attestation_id_matches_policy"] = policy_complete and _safe_equal(
        statement_object.get("attestation_id"), policy["expected_attestation_id"]
    )
    checks["key_id_matches"] = policy_complete and _safe_equal(
        envelope.get("key_id"), policy["expected_key_id"]
    )
    checks["issuer_matches_policy"] = policy_complete and _safe_equal(
        predicate.get("issuer"), policy["expected_issuer"]
    )

    issued = _strict_datetime(statement_object.get("issued_at"))
    expires = _strict_datetime(statement_object.get("expires_at"))
    checks["as_of_valid"] = policy_complete and policy["as_of"] is not None
    checks["issued_at_valid"] = issued is not None
    checks["expires_at_valid"] = expires is not None
    if issued is not None and expires is not None:
        checks["expiration_after_issuance"] = expires > issued
        lifetime = (expires - issued).total_seconds()
        checks["lifetime_within_policy"] = (
            policy_complete and 0 < lifetime <= policy["max_lifetime_seconds"]
        )
    if policy_complete and policy["as_of"] is not None:
        as_of = policy["as_of"]
        if issued is not None:
            checks["issued_at_not_future"] = issued <= as_of + timedelta(
                seconds=policy["max_future_skew_seconds"]
            )
            checks["attestation_fresh"] = issued >= as_of - timedelta(
                seconds=policy["max_age_seconds"]
            )
        if expires is not None:
            checks["attestation_not_expired"] = expires > as_of

    evidence, evidence_error = _model_evidence(expected_model)
    checks["expected_model_valid"] = evidence_error is None
    if evidence_error:
        diagnostics.append(
            {
                "indicator": "invalid_expected_model_evidence",
                "severity": "HIGH",
                "detail": evidence_error,
            }
        )
    else:
        expected_subject = evidence["subject"]
        checks["model_id_matches"] = _safe_equal(
            subject.get("model_id"), expected_subject["model_id"]
        )
        checks["model_name_matches"] = _safe_equal(
            subject.get("model_name"), expected_subject["model_name"]
        )
        checks["version_matches"] = _safe_equal(
            subject.get("version"), expected_subject["version"]
        )
        artifact = subject.get("artifact_digest") if isinstance(subject.get("artifact_digest"), dict) else {}
        checks["artifact_hash_matches"] = _digest_equal(
            artifact.get("value"), expected_subject["artifact_digest"]["value"]
        )
        checks["source_matches"] = _safe_equal(source.get("provider"), evidence["source"]["provider"]) and _safe_equal(
            source.get("url"), evidence["source"]["url"]
        )
        checks["publisher_matches"] = _safe_equal(
            source.get("publisher"), evidence["source"]["publisher"]
        )
        checks["revision_matches"] = _optional_equal(
            source.get("revision"), evidence["source"]["revision"]
        )
        checks["mbom_hash_matches"] = _digest_equal(
            predicate.get("mbom_sha256"), evidence["mbom_sha256"]
        )
        checks["dependency_inventory_matches"] = _digest_equal(
            predicate.get("dependency_inventory_sha256"),
            evidence["dependency_inventory_sha256"],
        )
        checks["training_lineage_matches"] = _digest_equal(
            predicate.get("training_lineage_sha256"),
            evidence["training_lineage_sha256"],
        )
        checks["deployment_pipeline_matches"] = _digest_equal(
            predicate.get("deployment_pipeline_sha256"),
            evidence["deployment_pipeline_sha256"],
        )
        checks["model_manifest_matches"] = _digest_equal(
            predicate.get("model_manifest_sha256"), evidence["model_manifest_sha256"]
        )

    failed_checks = [name for name, passed in checks.items() if not passed]
    digest = hashlib.sha256(statement_bytes).hexdigest() if statement_bytes is not None else None
    cryptographic_checks = (
        "canonical_statement_valid",
        "canonical_statement_bounded",
        "supported_algorithm",
        "signature_shape_valid",
        "signing_key_strong",
        "signature_valid",
    )
    binding_checks = (
        "model_id_matches",
        "model_name_matches",
        "version_matches",
        "artifact_hash_matches",
        "source_matches",
        "publisher_matches",
        "revision_matches",
        "mbom_hash_matches",
        "dependency_inventory_matches",
        "training_lineage_matches",
        "deployment_pipeline_matches",
        "model_manifest_matches",
    )
    return {
        "scoring_version": PROVENANCE_ATTESTATION_SCHEMA_VERSION,
        "verified": not failed_checks,
        "cryptographically_valid": all(checks[name] for name in cryptographic_checks),
        "subject_binding_verified": all(checks[name] for name in binding_checks),
        "assurance_level": "SYMMETRIC_AUTHENTICATED" if not failed_checks else "UNVERIFIED",
        "checks": checks,
        "failed_checks": failed_checks,
        "attestation_sha256": digest,
        "diagnostics": diagnostics,
    }


def _statement_shape(value):
    checks = {
        "statement_shape_valid": False,
        "statement_type_supported": False,
        "predicate_type_supported": False,
        "attestation_id_valid": False,
        "issuer_valid": False,
        "subject_identity_valid": False,
        "artifact_digest_valid": False,
        "evidence_digests_valid": False,
    }
    diagnostics = []
    if not isinstance(value, dict) or set(value) != _STATEMENT_FIELDS:
        return {"checks": checks, "diagnostics": diagnostics}
    subject = value.get("subject")
    predicate = value.get("predicate")
    if not isinstance(subject, dict) or set(subject) != _SUBJECT_FIELDS:
        return {"checks": checks, "diagnostics": diagnostics}
    artifact = subject.get("artifact_digest")
    if not isinstance(artifact, dict) or set(artifact) != _ARTIFACT_DIGEST_FIELDS:
        return {"checks": checks, "diagnostics": diagnostics}
    if not isinstance(predicate, dict) or set(predicate) != _PREDICATE_FIELDS:
        return {"checks": checks, "diagnostics": diagnostics}
    source = predicate.get("source")
    if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
        return {"checks": checks, "diagnostics": diagnostics}
    checks["statement_shape_valid"] = True
    checks["statement_type_supported"] = value.get("statement_type") == PROVENANCE_STATEMENT_TYPE
    checks["predicate_type_supported"] = predicate.get("predicate_type") == PROVENANCE_PREDICATE_TYPE
    checks["attestation_id_valid"] = _valid_identity(value.get("attestation_id"))
    checks["issuer_valid"] = _valid_identity(predicate.get("issuer"))
    checks["subject_identity_valid"] = all(
        _valid_text(subject.get(field)) for field in ("model_id", "model_name", "version")
    )
    checks["artifact_digest_valid"] = (
        artifact.get("algorithm") == "SHA-256" and _valid_digest(artifact.get("value"))
    )
    checks["evidence_digests_valid"] = all(
        _valid_digest(predicate.get(field))
        for field in (
            "mbom_sha256",
            "dependency_inventory_sha256",
            "training_lineage_sha256",
            "deployment_pipeline_sha256",
            "model_manifest_sha256",
        )
    )
    return {"checks": checks, "diagnostics": diagnostics}


def _model_evidence(model):
    if not isinstance(model, dict):
        return None, "Expected model evidence must be an object."
    metadata = model.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        return None, "Model metadata must be an object."
    model_id = _text(model.get("model_id") or model.get("id"))
    model_name = _text(model.get("model_name"))
    version = _text(model.get("version"))
    artifact_hash = _normalized_digest(model.get("sha256") or model.get("sha256_hash"))
    provider = _text(model.get("source"))
    source_url = _text(model.get("source_url"))
    publisher = _text(model.get("publisher"))
    if not all((model_id, model_name, version, artifact_hash, provider, source_url, publisher)):
        return None, "Model id, name, version, artifact hash, source, URL, and publisher are required."
    source_metadata = model.get("source_metadata") or metadata.get("source_metadata") or {}
    if source_metadata and not isinstance(source_metadata, dict):
        return None, "Source metadata must be an object."
    revision = _text(
        source_metadata.get("revision")
        or source_metadata.get("commit")
        or model.get("source_revision")
    ) or None
    dependencies = model.get("dependencies")
    if dependencies is None:
        dependencies = metadata.get("dependencies") or []
    training = model.get("training_artifacts")
    if training is None:
        training = metadata.get("training_artifacts") or []
    deployment = model.get("deployment_pipeline")
    if deployment is None:
        deployment = metadata.get("deployment_pipeline") or {}
    dependency_digest, dependency_error = _digest_json(dependencies)
    training_digest, training_error = _digest_json(training)
    deployment_digest, deployment_error = _digest_json(deployment)
    ai_bom, ai_bom_error = _attestable_ai_bom(model)
    error = (
        dependency_error
        or training_error
        or deployment_error
        or ai_bom_error
    )
    if error:
        return None, f"Model evidence is outside the canonical subset: {error}"
    mbom_digest = ai_bom["document_sha256"]
    subject = {
        "model_id": model_id,
        "model_name": model_name,
        "version": version,
        "artifact_digest": {"algorithm": "SHA-256", "value": artifact_hash},
    }
    source = {
        "provider": provider,
        "url": source_url,
        "publisher": publisher,
        "revision": revision,
    }
    manifest = {
        "subject": subject,
        "source": source,
        "license": _text(model.get("license")) or None,
        "dependency_inventory_sha256": dependency_digest,
        "training_lineage_sha256": training_digest,
        "deployment_pipeline_sha256": deployment_digest,
        "mbom_sha256": mbom_digest,
    }
    manifest_digest, manifest_error = _digest_json(manifest)
    if manifest_error:
        return None, f"Model manifest is outside the canonical subset: {manifest_error}"
    return {
        "subject": subject,
        "source": source,
        "mbom_sha256": mbom_digest,
        "dependency_inventory_sha256": dependency_digest,
        "training_lineage_sha256": training_digest,
        "deployment_pipeline_sha256": deployment_digest,
        "model_manifest_sha256": manifest_digest,
    }, None


def _attestable_ai_bom(model):
    """Build the stable pre-attestation AI-BOM committed by schema-2 statements."""
    if not isinstance(model, dict):
        return None, "AI-BOM input must be an object."
    metadata = model.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return None, "AI-BOM metadata must be an object."
    try:
        document = generate_attestable_ai_bom_v2(model)
        verification = verify_ai_bom_v2(document)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return None, f"AI-BOM generation failed: {type(exc).__name__}"
    if not verification.get("verified"):
        return None, "Generated AI-BOM failed internal integrity verification."
    digest = document.get("document_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        return None, "Generated AI-BOM has no valid document digest."
    return document, None


def _verification_policy(value, diagnostics):
    result = {
        "expected_attestation_id": "",
        "expected_key_id": "",
        "expected_issuer": "",
        "as_of": None,
        "max_lifetime_seconds": _DEFAULT_MAX_LIFETIME_SECONDS,
        "max_age_seconds": _DEFAULT_MAX_AGE_SECONDS,
        "max_future_skew_seconds": _DEFAULT_MAX_FUTURE_SKEW_SECONDS,
    }
    if not isinstance(value, dict):
        diagnostics.append(
            {
                "indicator": "missing_attestation_verification_policy",
                "severity": "HIGH",
                "detail": "Attestation verification requires explicit identity and time policy.",
            }
        )
        return result, False
    complete = True
    for field in ("expected_attestation_id", "expected_key_id", "expected_issuer"):
        candidate = value.get(field)
        if not _valid_identity(candidate):
            complete = False
        else:
            result[field] = candidate
    result["as_of"] = _strict_datetime(value.get("as_of"))
    if result["as_of"] is None:
        complete = False
    bounds = {
        "max_lifetime_seconds": (60, 366 * 24 * 60 * 60),
        "max_age_seconds": (0, 366 * 24 * 60 * 60),
        "max_future_skew_seconds": (0, 60 * 60),
    }
    for field, limits in bounds.items():
        if value.get(field) is None:
            continue
        candidate = _bounded_integer(value.get(field), limits)
        if candidate is None:
            complete = False
        else:
            result[field] = candidate
    if not complete:
        diagnostics.append(
            {
                "indicator": "invalid_attestation_verification_policy",
                "severity": "HIGH",
                "detail": "Expected attestation, key, issuer, time, or freshness policy is incomplete.",
            }
        )
    return result, complete


def _canonical_json(value):
    valid, reason = _canonical_subset(value)
    if not valid:
        return None, reason
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return None, f"Canonical JSON encoding failed: {type(exc).__name__}"
    if len(encoded) > _MAX_CANONICAL_BYTES:
        return None, "Canonical evidence exceeds the byte bound."
    return encoded, None


def _canonical_subset(value):
    seen = set()
    nodes = 0

    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            return False, "Canonical evidence exceeds the node bound."
        if depth > _MAX_JSON_DEPTH:
            return False, "Canonical evidence exceeds the nesting bound."
        if item is None or isinstance(item, (bool, str, int)):
            if isinstance(item, str) and len(item.encode("utf-8")) > _MAX_STRING_BYTES:
                return False, "Canonical evidence contains an oversized string."
            if isinstance(item, int) and not isinstance(item, bool) and abs(item) > _MAX_INTEGER:
                return False, "Canonical evidence contains an out-of-range integer."
            return True, None
        if isinstance(item, float):
            return False, "Floating-point values are outside the canonical evidence subset."
        if isinstance(item, (list, dict)):
            identity = id(item)
            if identity in seen:
                return False, "Canonical evidence contains a reference cycle."
            seen.add(identity)
            if isinstance(item, list):
                children = enumerate(item)
            else:
                for key in item:
                    if not isinstance(key, str):
                        return False, "Canonical evidence object keys must be strings."
                    if len(key.encode("utf-8")) > _MAX_OBJECT_KEY_BYTES:
                        return False, "Canonical evidence contains an oversized object key."
                children = item.items()
            for _, child in children:
                valid, child_reason = walk(child, depth + 1)
                if not valid:
                    return valid, child_reason
            seen.remove(identity)
            return True, None
        return False, "Canonical evidence contains a non-JSON value."

    return walk(value, 0)


def _digest_json(value):
    encoded, error = _canonical_json(value)
    return (hashlib.sha256(encoded).hexdigest(), None) if encoded is not None else (None, error)


def _sign(statement_bytes, key):
    return hmac.new(key, _DOMAIN_SEPARATOR + statement_bytes, hashlib.sha256).hexdigest()


def _key_bytes(value):
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        return None
    if not _MIN_KEY_BYTES <= len(encoded) <= _MAX_KEY_BYTES:
        return None
    if not encoded.strip() or len(set(encoded)) < 8:
        return None
    return encoded


def _strict_datetime(value):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _valid_identity(value):
    if not isinstance(value, str):
        return False
    encoded = value.encode("utf-8")
    return (
        0 < len(encoded) <= _MAX_IDENTITY_BYTES
        and value == value.strip()
        and bool(_IDENTITY.fullmatch(value))
    )


def _valid_text(value):
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    encoded = value.encode("utf-8")
    return len(encoded) <= _MAX_TEXT_BYTES and not _CONTROL_CHARACTER.search(value)


def _text(value):
    if value is None:
        return ""
    text = str(value).strip()
    return text if _valid_text(text) else ""


def _normalized_digest(value):
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    return text if _valid_digest(text) else ""


def _valid_digest(value):
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _digest_equal(left, right):
    return _valid_digest(left) and _valid_digest(right) and hmac.compare_digest(left, right)


def _safe_equal(left, right):
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _optional_equal(left, right):
    if left is None or right is None:
        return left is None and right is None
    return _safe_equal(left, right)


def _bounded_integer(value, bounds):
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if bounds[0] <= value <= bounds[1] else None

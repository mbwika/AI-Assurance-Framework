"""Hardened, deterministic advisory-feed envelope verification."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional


ADVISORY_FEED_V2_SCHEMA_VERSION = "2.0"
ADVISORY_FEED_V2_ALGORITHM = "HMAC-SHA256"

_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 4_096
_MAX_ADVISORIES = 10_000
_MAX_CANONICAL_BYTES = 10 * 1024 * 1024
_MAX_JSON_DEPTH = 24
_MAX_JSON_NODES = 250_000
_MAX_STRING_BYTES = 1024 * 1024
_MAX_OBJECT_KEY_BYTES = 256
_MAX_IDENTITY_BYTES = 256
_MAX_SEQUENCE = 2**63 - 1
_DEFAULT_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_DEFAULT_MAX_FEED_AGE_SECONDS = 24 * 60 * 60
_DEFAULT_MAX_FUTURE_SKEW_SECONDS = 5 * 60
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_FIELDS = frozenset(
    {
        "schema_version",
        "feed_id",
        "sequence",
        "previous_feed_sha256",
        "generated_at",
        "expires_at",
        "source",
        "advisory_count",
        "advisories",
        "algorithm",
        "key_id",
        "signature",
    }
)
_PAYLOAD_FIELDS = (
    "schema_version",
    "feed_id",
    "sequence",
    "previous_feed_sha256",
    "generated_at",
    "expires_at",
    "source",
    "advisory_count",
    "advisories",
    "algorithm",
    "key_id",
)
_CHECK_NAMES = (
    "feed_is_object",
    "strict_envelope_fields",
    "schema_version_supported",
    "supported_algorithm",
    "feed_id_valid",
    "source_valid",
    "key_id_valid",
    "sequence_valid",
    "chain_field_valid",
    "advisories_valid",
    "advisory_count_matches",
    "canonical_payload_valid",
    "canonical_payload_bounded",
    "signature_shape_valid",
    "signing_key_strong",
    "signature_valid",
    "trust_policy_complete",
    "feed_id_matches_policy",
    "source_matches_policy",
    "key_id_matches_policy",
    "sequence_matches_policy",
    "previous_digest_matches_policy",
    "as_of_valid",
    "generated_at_valid",
    "expires_at_valid",
    "generated_at_not_future",
    "generated_at_fresh",
    "expiration_after_generation",
    "lifetime_within_policy",
    "feed_not_expired",
)


def create_advisory_feed_v2(
    *,
    feed_id: str,
    sequence: int,
    previous_feed_sha256: Optional[str],
    generated_at: str,
    expires_at: str,
    advisories: List[Dict[str, Any]],
    signing_key: Any,
    key_id: str,
    source: str,
    as_of: str,
    max_lifetime_seconds: int = _DEFAULT_MAX_LIFETIME_SECONDS,
    max_feed_age_seconds: int = _DEFAULT_MAX_FEED_AGE_SECONDS,
    max_future_skew_seconds: int = _DEFAULT_MAX_FUTURE_SKEW_SECONDS,
) -> Dict[str, Any]:
    """Create a schema-2 feed and verify it against its explicit trust policy."""
    feed = {
        "schema_version": ADVISORY_FEED_V2_SCHEMA_VERSION,
        "feed_id": feed_id,
        "sequence": sequence,
        "previous_feed_sha256": previous_feed_sha256,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "source": source,
        "advisory_count": len(advisories) if isinstance(advisories, list) else None,
        "advisories": advisories,
        "algorithm": ADVISORY_FEED_V2_ALGORITHM,
        "key_id": key_id,
    }
    payload, payload_error = _canonical_payload(feed)
    key = _key_bytes(signing_key)
    if payload_error or payload is None:
        raise ValueError(f"Advisory feed is not canonically signable: {payload_error}")
    if key is None:
        raise ValueError("Advisory feed signing key must contain at least 32 bytes")
    feed["signature"] = hmac.new(key, payload, hashlib.sha256).hexdigest()
    context = {
        "expected_feed_id": feed_id,
        "expected_source": source,
        "expected_key_id": key_id,
        "expected_sequence": sequence,
        "expected_previous_feed_sha256": previous_feed_sha256,
        "as_of": as_of,
        "max_lifetime_seconds": max_lifetime_seconds,
        "max_feed_age_seconds": max_feed_age_seconds,
        "max_future_skew_seconds": max_future_skew_seconds,
    }
    verification = verify_advisory_feed_v2(feed, signing_key, context)
    if not verification["verified"]:
        raise ValueError(
            "Invalid advisory feed: " + ", ".join(verification["failed_checks"])
        )
    return feed


def verify_advisory_feed_v2(
    feed: Any,
    signing_key: Any,
    verification_context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Verify cryptographic integrity, feed policy, freshness, and hash-chain state.

    The caller must provide expected feed, source, key, sequence, previous
    digest, and an explicit ``as_of``. This binds a valid MAC to an authorized
    feed identity and replay state rather than treating possession of any key
    as sufficient trust.
    """
    checks = {name: False for name in _CHECK_NAMES}
    diagnostics: List[Dict[str, Any]] = []
    feed_object = feed if isinstance(feed, dict) else {}
    checks["feed_is_object"] = isinstance(feed, dict)
    checks["strict_envelope_fields"] = checks["feed_is_object"] and set(feed_object) == _ALLOWED_FIELDS
    checks["schema_version_supported"] = (
        feed_object.get("schema_version") == ADVISORY_FEED_V2_SCHEMA_VERSION
    )
    checks["supported_algorithm"] = (
        feed_object.get("algorithm") == ADVISORY_FEED_V2_ALGORITHM
    )
    checks["feed_id_valid"] = _valid_identity(feed_object.get("feed_id"))
    checks["source_valid"] = _valid_identity(feed_object.get("source"))
    checks["key_id_valid"] = _valid_identity(feed_object.get("key_id"))
    sequence = feed_object.get("sequence")
    checks["sequence_valid"] = _valid_sequence(sequence)
    checks["chain_field_valid"] = _valid_chain_field(
        sequence, feed_object.get("previous_feed_sha256")
    )

    advisories = feed_object.get("advisories")
    advisory_validation = _validate_advisories(advisories)
    checks["advisories_valid"] = advisory_validation["valid"]
    advisory_count = feed_object.get("advisory_count")
    checks["advisory_count_matches"] = (
        isinstance(advisory_count, int)
        and not isinstance(advisory_count, bool)
        and isinstance(advisories, list)
        and advisory_count == len(advisories)
    )
    diagnostics.extend(advisory_validation["diagnostics"])

    payload, payload_error = _canonical_payload(feed_object)
    checks["canonical_payload_valid"] = payload is not None
    checks["canonical_payload_bounded"] = payload is not None and len(payload) <= _MAX_CANONICAL_BYTES
    if payload_error:
        diagnostics.append(
            {
                "indicator": "invalid_canonical_payload",
                "severity": "HIGH",
                "detail": payload_error,
            }
        )

    signature = feed_object.get("signature")
    checks["signature_shape_valid"] = isinstance(signature, str) and bool(
        _SIGNATURE.fullmatch(signature)
    )
    key = _key_bytes(signing_key)
    checks["signing_key_strong"] = key is not None
    if (
        payload is not None
        and checks["canonical_payload_bounded"]
        and checks["signature_shape_valid"]
        and key is not None
        and checks["supported_algorithm"]
    ):
        expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        checks["signature_valid"] = hmac.compare_digest(signature, expected_signature)

    context, context_complete = _verification_policy(verification_context, diagnostics)
    checks["trust_policy_complete"] = context_complete
    checks["feed_id_matches_policy"] = context_complete and hmac.compare_digest(
        str(feed_object.get("feed_id") or ""), context["expected_feed_id"]
    )
    checks["source_matches_policy"] = context_complete and hmac.compare_digest(
        str(feed_object.get("source") or ""), context["expected_source"]
    )
    checks["key_id_matches_policy"] = context_complete and hmac.compare_digest(
        str(feed_object.get("key_id") or ""), context["expected_key_id"]
    )
    checks["sequence_matches_policy"] = (
        context_complete and sequence == context["expected_sequence"]
    )
    checks["previous_digest_matches_policy"] = context_complete and _digest_equal(
        feed_object.get("previous_feed_sha256"),
        context["expected_previous_feed_sha256"],
    )

    generated = _strict_datetime(feed_object.get("generated_at"))
    expires = _strict_datetime(feed_object.get("expires_at"))
    checks["as_of_valid"] = context_complete and context["as_of"] is not None
    checks["generated_at_valid"] = generated is not None
    checks["expires_at_valid"] = expires is not None
    if generated is not None and expires is not None:
        checks["expiration_after_generation"] = expires > generated
        lifetime = (expires - generated).total_seconds()
        checks["lifetime_within_policy"] = (
            0 < lifetime <= context["max_lifetime_seconds"]
            if context_complete
            else False
        )
    if context_complete and context["as_of"] is not None:
        as_of = context["as_of"]
        if generated is not None:
            checks["generated_at_not_future"] = generated <= as_of + timedelta(
                seconds=context["max_future_skew_seconds"]
            )
            checks["generated_at_fresh"] = generated >= as_of - timedelta(
                seconds=context["max_feed_age_seconds"]
            )
        if expires is not None:
            checks["feed_not_expired"] = expires > as_of

    failed_checks = [name for name, passed in checks.items() if not passed]
    feed_sha256 = hashlib.sha256(payload).hexdigest() if payload is not None else None
    cryptographic_checks = (
        "canonical_payload_valid",
        "canonical_payload_bounded",
        "supported_algorithm",
        "signature_shape_valid",
        "signing_key_strong",
        "signature_valid",
    )
    return {
        "scoring_version": ADVISORY_FEED_V2_SCHEMA_VERSION,
        "verified": not failed_checks,
        "cryptographically_valid": all(checks[name] for name in cryptographic_checks),
        "assurance_level": "SYMMETRIC_AUTHENTICATED" if not failed_checks else "UNVERIFIED",
        "checks": checks,
        "failed_checks": failed_checks,
        "feed_sha256": feed_sha256,
        "advisory_count": len(advisories) if isinstance(advisories, list) else 0,
        "unique_advisory_count": advisory_validation["unique_count"],
        "diagnostics": diagnostics,
    }


def _verification_policy(value, diagnostics):
    result = {
        "expected_feed_id": "",
        "expected_source": "",
        "expected_key_id": "",
        "expected_sequence": None,
        "expected_previous_feed_sha256": None,
        "as_of": None,
        "max_lifetime_seconds": _DEFAULT_MAX_LIFETIME_SECONDS,
        "max_feed_age_seconds": _DEFAULT_MAX_FEED_AGE_SECONDS,
        "max_future_skew_seconds": _DEFAULT_MAX_FUTURE_SKEW_SECONDS,
    }
    if not isinstance(value, dict):
        diagnostics.append(
            {
                "indicator": "missing_verification_policy",
                "severity": "HIGH",
                "detail": "Feed verification requires an explicit trust and replay policy.",
            }
        )
        return result, False
    complete = True
    for field in ("expected_feed_id", "expected_source", "expected_key_id"):
        candidate = value.get(field)
        if not _valid_identity(candidate):
            complete = False
        else:
            result[field] = str(candidate)
    sequence = value.get("expected_sequence")
    if not _valid_sequence(sequence):
        complete = False
    else:
        result["expected_sequence"] = sequence
    if "expected_previous_feed_sha256" not in value:
        complete = False
    else:
        previous = value.get("expected_previous_feed_sha256")
        if sequence == 1:
            if previous is not None:
                complete = False
        elif not _valid_digest(previous):
            complete = False
        result["expected_previous_feed_sha256"] = previous
    result["as_of"] = _strict_datetime(value.get("as_of"))
    if result["as_of"] is None:
        complete = False
    policies = {
        "max_lifetime_seconds": (60, 31 * 24 * 60 * 60),
        "max_feed_age_seconds": (0, 31 * 24 * 60 * 60),
        "max_future_skew_seconds": (0, 60 * 60),
    }
    for field, bounds in policies.items():
        if value.get(field) is None:
            continue
        candidate = _bounded_integer(value.get(field), bounds)
        if candidate is None:
            complete = False
        else:
            result[field] = candidate
    if not complete:
        diagnostics.append(
            {
                "indicator": "invalid_verification_policy",
                "severity": "HIGH",
                "detail": "Expected identity, replay state, time, or freshness policy is incomplete.",
            }
        )
    return result, complete


def _validate_advisories(value):
    diagnostics: List[Dict[str, Any]] = []
    if not isinstance(value, list) or not value:
        return {
            "valid": False,
            "unique_count": 0,
            "diagnostics": [
                {
                    "indicator": "invalid_advisory_collection",
                    "severity": "HIGH",
                    "detail": "Feed advisories must be a non-empty list.",
                }
            ],
        }
    if len(value) > _MAX_ADVISORIES:
        return {
            "valid": False,
            "unique_count": 0,
            "diagnostics": [
                {
                    "indicator": "advisory_count_limit_exceeded",
                    "severity": "HIGH",
                    "detail": "Feed advisory count exceeds the verification bound.",
                }
            ],
        }
    identifiers = set()
    valid = True
    for index, advisory in enumerate(value):
        if not isinstance(advisory, dict):
            valid = False
            _bounded_diagnostic(diagnostics, "invalid_advisory_record", index)
            continue
        identifier = advisory.get("id") or advisory.get("advisory_id")
        if not _valid_identity(identifier):
            valid = False
            _bounded_diagnostic(diagnostics, "invalid_advisory_identity", index)
            continue
        normalized = str(identifier).casefold()
        if normalized in identifiers:
            valid = False
            _bounded_diagnostic(diagnostics, "duplicate_advisory_identity", index)
        identifiers.add(normalized)
        affected = advisory.get("affected")
        package = advisory.get("package") or advisory.get("package_name")
        if not ((isinstance(affected, list) and bool(affected)) or package):
            valid = False
            _bounded_diagnostic(diagnostics, "advisory_missing_affected_package", index)
    return {"valid": valid, "unique_count": len(identifiers), "diagnostics": diagnostics}


def _canonical_payload(feed):
    payload = {field: feed.get(field) for field in _PAYLOAD_FIELDS}
    valid, reason = _canonical_subset(payload)
    if not valid:
        return None, reason
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return None, f"Canonical JSON encoding failed: {type(exc).__name__}"
    if len(encoded) > _MAX_CANONICAL_BYTES:
        return None, "Canonical payload exceeds the byte bound."
    return encoded, None


def _canonical_subset(value):
    seen = set()
    nodes = 0

    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            return False, "Canonical payload exceeds the node bound."
        if depth > _MAX_JSON_DEPTH:
            return False, "Canonical payload exceeds the nesting bound."
        if item is None or isinstance(item, (bool, str, int)):
            if isinstance(item, str) and len(item.encode("utf-8")) > _MAX_STRING_BYTES:
                return False, "Canonical payload contains an oversized string."
            if isinstance(item, int) and not isinstance(item, bool) and abs(item) > _MAX_SEQUENCE:
                return False, "Canonical payload contains an out-of-range integer."
            return True, None
        if isinstance(item, float):
            return False, "Floating-point values are outside the canonical feed subset."
        if isinstance(item, (list, dict)):
            identity = id(item)
            if identity in seen:
                return False, "Canonical payload contains a reference cycle."
            seen.add(identity)
            if isinstance(item, list):
                for child in item:
                    valid, reason = walk(child, depth + 1)
                    if not valid:
                        return valid, reason
            else:
                for key, child in item.items():
                    if not isinstance(key, str):
                        return False, "Canonical payload object keys must be strings."
                    if len(key.encode("utf-8")) > _MAX_OBJECT_KEY_BYTES:
                        return False, "Canonical payload contains an oversized object key."
                    valid, reason = walk(child, depth + 1)
                    if not valid:
                        return valid, reason
            seen.remove(identity)
            return True, None
        return False, "Canonical payload contains a non-JSON value."

    return walk(value, 0)


def _valid_identity(value):
    if not isinstance(value, str):
        return False
    encoded = value.encode("utf-8")
    return (
        0 < len(encoded) <= _MAX_IDENTITY_BYTES
        and value == value.strip()
        and bool(_IDENTITY.fullmatch(value))
    )


def _valid_sequence(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= _MAX_SEQUENCE
    )


def _valid_chain_field(sequence, previous):
    if sequence == 1:
        return previous is None
    return _valid_sequence(sequence) and _valid_digest(previous)


def _valid_digest(value):
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _digest_equal(left, right):
    if left is None or right is None:
        return left is None and right is None
    if not _valid_digest(left) or not _valid_digest(right):
        return False
    return hmac.compare_digest(left, right)


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


def _bounded_integer(value, bounds):
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if bounds[0] <= value <= bounds[1] else None


def _bounded_diagnostic(diagnostics, indicator, index):
    if len(diagnostics) >= 100:
        return
    diagnostics.append(
        {
            "indicator": indicator,
            "severity": "HIGH",
            "detail": "Advisory record failed structural feed validation.",
            "evidence": {"advisory_index": index},
        }
    )

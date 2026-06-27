"""Signed vulnerability advisory feed envelopes."""

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


FEED_SCHEMA_VERSION = "1.0"
SIGNATURE_ALGORITHM = "HMAC-SHA256"


def create_advisory_feed(
    *,
    feed_id: str,
    sequence: int,
    generated_at: str,
    expires_at: str,
    advisories: List[Dict[str, Any]],
    signing_key: str,
    key_id: str = "default",
    source: Optional[str] = None,
) -> Dict[str, Any]:
    if not signing_key:
        raise ValueError("A non-empty advisory feed signing key is required")
    feed = {
        "schema_version": FEED_SCHEMA_VERSION,
        "feed_id": str(feed_id or "").strip(),
        "sequence": int(sequence),
        "generated_at": generated_at,
        "expires_at": expires_at,
        "source": str(source or feed_id or "").strip(),
        "advisories": advisories,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": str(key_id or "default"),
    }
    feed["signature"] = _sign(_signed_payload(feed), signing_key)
    verification = verify_advisory_feed(
        feed, signing_key, expected_key_id=feed["key_id"]
    )
    if not verification["verified"]:
        failed = [name for name, passed in verification["checks"].items() if not passed]
        raise ValueError(f"Invalid advisory feed: {failed}")
    return feed


def verify_advisory_feed(
    feed: Dict[str, Any],
    signing_key: str,
    *,
    expected_key_id: Optional[str] = None,
    as_of: Optional[str] = None,
) -> Dict[str, Any]:
    now = _parse_datetime(as_of) if as_of else datetime.now(timezone.utc)
    generated = _try_datetime(feed.get("generated_at"))
    expires = _try_datetime(feed.get("expires_at"))
    signature = feed.get("signature")
    checks = {
        "signing_key_present": bool(signing_key),
        "schema_version_supported": feed.get("schema_version")
        == FEED_SCHEMA_VERSION,
        "feed_id_present": bool(str(feed.get("feed_id") or "").strip()),
        "sequence_valid": _valid_sequence(feed.get("sequence")),
        "advisories_present": isinstance(feed.get("advisories"), list)
        and bool(feed.get("advisories")),
        "supported_algorithm": feed.get("algorithm") == SIGNATURE_ALGORITHM,
        "key_id_matches": expected_key_id is None
        or feed.get("key_id") == expected_key_id,
        "generated_at_valid": generated is not None,
        "expires_at_valid": expires is not None,
        "generated_at_not_future": generated is not None
        and generated <= now + timedelta(minutes=5),
        "expiration_after_generation": generated is not None
        and expires is not None
        and expires > generated,
        "feed_not_expired": expires is not None and expires > now,
        "signature_valid": False,
    }
    if (
        checks["signing_key_present"]
        and checks["supported_algorithm"]
        and isinstance(signature, str)
    ):
        expected = _sign(_signed_payload(feed), signing_key)
        checks["signature_valid"] = hmac.compare_digest(signature, expected)
    return {
        "verified": all(checks.values()),
        "checks": checks,
        "feed_sha256": hashlib.sha256(
            _canonical_json(_signed_payload(feed))
        ).hexdigest(),
    }


def _signed_payload(feed: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": feed.get("schema_version"),
        "feed_id": feed.get("feed_id"),
        "sequence": feed.get("sequence"),
        "generated_at": feed.get("generated_at"),
        "expires_at": feed.get("expires_at"),
        "source": feed.get("source"),
        "advisories": feed.get("advisories"),
        "algorithm": feed.get("algorithm"),
        "key_id": feed.get("key_id"),
    }


def _sign(value: Dict[str, Any], signing_key: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"), _canonical_json(value), hashlib.sha256
    ).hexdigest()


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _valid_sequence(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _try_datetime(value: Any) -> Optional[datetime]:
    try:
        return _parse_datetime(value)
    except (TypeError, ValueError):
        return None


def _parse_datetime(value: Any) -> datetime:
    normalized = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

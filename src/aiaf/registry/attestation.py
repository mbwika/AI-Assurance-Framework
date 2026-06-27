"""Signed provenance attestations for registered model artifacts."""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .mbom import generate_mbom


def create_provenance_attestation(
    model_record: Dict[str, Any], signing_key: str, key_id: str = "default"
) -> Dict[str, Any]:
    if not signing_key:
        raise ValueError("A non-empty attestation signing key is required")
    if not model_record.get("model_id") or not model_record.get("sha256"):
        raise ValueError("Model identity and SHA-256 evidence are required")
    statement = {
        "statement_type": "https://aiaf.dev/attestation/model-provenance/v1",
        "subject": {
            "model_id": model_record.get("model_id"),
            "model_name": model_record.get("model_name"),
            "sha256": model_record.get("sha256"),
        },
        "predicate": {
            "version": model_record.get("version"),
            "source": model_record.get("source"),
            "source_url": model_record.get("source_url"),
            "publisher": model_record.get("publisher"),
            "mbom_sha256": _sha256_json(generate_mbom(model_record)),
        },
        "issued_at": _utc_now(),
    }
    signature = hmac.new(
        signing_key.encode("utf-8"), _canonical_json(statement), hashlib.sha256
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "statement": statement,
        "signature": signature,
    }


def verify_provenance_attestation(
    attestation: Dict[str, Any],
    signing_key: str,
    expected_model: Optional[Dict[str, Any]] = None,
    expected_key_id: Optional[str] = None,
) -> Dict[str, Any]:
    checks = {
        "signing_key_present": bool(signing_key),
        "supported_algorithm": attestation.get("algorithm") == "HMAC-SHA256",
        "key_id_matches": expected_key_id is None
        or attestation.get("key_id") == expected_key_id,
        "signature_valid": False,
        "model_id_matches": True,
        "artifact_hash_matches": True,
        "mbom_hash_matches": True,
    }
    statement = attestation.get("statement")
    signature = attestation.get("signature")
    if (
        checks["signing_key_present"]
        and checks["supported_algorithm"]
        and isinstance(statement, dict)
        and isinstance(signature, str)
    ):
        expected_signature = hmac.new(
            signing_key.encode("utf-8"), _canonical_json(statement), hashlib.sha256
        ).hexdigest()
        checks["signature_valid"] = hmac.compare_digest(signature, expected_signature)

    if expected_model is not None and isinstance(statement, dict):
        subject = statement.get("subject", {})
        predicate = statement.get("predicate", {})
        checks["model_id_matches"] = subject.get("model_id") == expected_model.get("model_id")
        checks["artifact_hash_matches"] = subject.get("sha256") == expected_model.get("sha256")
        checks["mbom_hash_matches"] = predicate.get("mbom_sha256") == _sha256_json(
            generate_mbom(expected_model)
        )

    return {"verified": all(checks.values()), "checks": checks}


def _sha256_json(value: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

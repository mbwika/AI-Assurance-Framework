"""Signed Tool Manifests.

A tool manifest is a cryptographically signed declaration of a tool's
capability set, input schema, and authorised callers.  It extends the
supply-chain assurance model (which already covers models) to cover *tools* —
the action primitives that make agentic systems powerful and dangerous.

Signing follows the same HMAC-SHA256 pattern used by
``registry.attestation_v2`` so AIAF's evidence taxonomy is consistent:
* ``statement``  — the canonical, deterministic payload that is signed
* ``signature``  — HMAC-SHA256(canonical_json(statement), signing_key)
* ``manifest_id``— first 16 hex chars of SHA-256(canonical_json(statement))

Privacy: no raw signing key is stored. Verification requires the caller
to supply the key at call time.

Storage
-------
Manifests are persisted under ``"tool_manifest:{tool_name}:{version}"``.
Multiple versions of the same tool can coexist.

Evidence origin
---------------
``LOCALLY_OBSERVED`` for verification failures (signature mismatch is
 observed locally).
``INDEPENDENTLY_VERIFIED`` for a manifest whose signature was re-verified
 with a trusted key at assessment time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

MANIFEST_VERSION = "1.0"

_MANIFEST_PREFIX = "tool_manifest:"

_SUPPORTED_ALGORITHMS = frozenset({"hmac-sha256"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _hmac_sign(statement: dict[str, Any], key: bytes) -> str:
    if len(key) < 32:
        raise ManifestError("Signing key must be at least 32 bytes.")
    payload = _canonical_json(statement).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _hmac_verify(statement: dict[str, Any], key: bytes, expected_sig: str) -> bool:
    if len(key) < 32:
        return False
    return hmac.compare_digest(_hmac_sign(statement, key), expected_sig)


def _manifest_key(tool_name: str, version: str) -> str:
    return f"{_MANIFEST_PREFIX}{tool_name}:{version}"


class ManifestError(ValueError):
    pass


# ── Manifest creation ─────────────────────────────────────────────────────────

def create_manifest(
    tool_name: str,
    version: str,
    description: str,
    input_schema: dict[str, Any],
    declared_capabilities: list[str],
    signing_key: bytes,
    *,
    allowed_agents: list[str] | None = None,
    issuer: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Create and sign a tool capability manifest.

    Parameters
    ----------
    tool_name:
        Unique tool identifier (e.g. ``"send_email"``).
    version:
        Semantic version string (e.g. ``"1.0.0"``).
    description:
        Human-readable description of what the tool does.
    input_schema:
        JSON Schema dict describing the tool's input parameters.  Its SHA-256
        is recorded in the manifest so schema drift is detectable.
    declared_capabilities:
        List of capability flags this tool grants its caller
        (e.g. ``["network_egress", "data_read"]``).
    signing_key:
        HMAC signing key — must be at least 32 bytes.
    allowed_agents:
        Optional list of ``agent_id`` values authorised to use this tool.
        ``None`` means unrestricted.
    issuer:
        Optional identifier for the entity that created this manifest.
    expires_at:
        Optional ISO-8601 expiry timestamp.

    Returns
    -------
    Manifest dict with ``statement``, ``signature``, ``manifest_id``,
    ``algorithm``, and ``manifest_version``.
    """
    tool_name = str(tool_name).strip()
    version = str(version).strip()
    if not tool_name:
        raise ManifestError("tool_name must be non-empty")
    if not version:
        raise ManifestError("version must be non-empty")

    schema_hash = _sha256(_canonical_json(input_schema))
    declared_capabilities = sorted({str(c).lower() for c in (declared_capabilities or [])})

    statement: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "tool_name": tool_name,
        "version": version,
        "description": str(description).strip(),
        "schema_hash": schema_hash,
        "declared_capabilities": declared_capabilities,
        "allowed_agents": sorted(allowed_agents) if allowed_agents is not None else None,
        "issuer": str(issuer).strip() if issuer else None,
        "issued_at": _utc_now(),
        "expires_at": expires_at,
    }

    manifest_id = _sha256(_canonical_json(statement))[:16]
    signature = _hmac_sign(statement, signing_key)

    return {
        "manifest_id": manifest_id,
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "hmac-sha256",
        "statement": statement,
        "signature": signature,
    }


# ── Manifest verification ─────────────────────────────────────────────────────

def verify_manifest(
    manifest: dict[str, Any],
    signing_key: bytes,
    *,
    current_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify a signed tool manifest.

    Parameters
    ----------
    manifest:
        Manifest dict as returned by :func:`create_manifest`.
    signing_key:
        The HMAC key used to sign this manifest.
    current_schema:
        If provided, the ``schema_hash`` in the manifest is checked against
        ``SHA-256(canonical_json(current_schema))`` to detect schema drift.

    Returns
    -------
    Dict with ``valid``, ``manifest_id``, ``tool_name``, ``version``,
    ``checks``, ``evidence_origin``, ``verified_at``.
    """
    statement = manifest.get("statement") or {}
    stored_sig = str(manifest.get("signature") or "")
    algorithm = str(manifest.get("algorithm") or "").lower()

    checks: dict[str, bool] = {}

    # Algorithm supported
    checks["algorithm_supported"] = algorithm in _SUPPORTED_ALGORITHMS

    # Signature valid
    try:
        checks["signature_valid"] = (
            checks["algorithm_supported"]
            and _hmac_verify(statement, signing_key, stored_sig)
        )
    except Exception:
        checks["signature_valid"] = False

    # manifest_version supported
    checks["manifest_version_supported"] = (
        str(statement.get("manifest_version") or "") == MANIFEST_VERSION
    )

    # manifest_id integrity
    expected_id = _sha256(_canonical_json(statement))[:16]
    checks["manifest_id_matches"] = (
        str(manifest.get("manifest_id") or "") == expected_id
    )

    # Schema drift (optional)
    if current_schema is not None:
        current_hash = _sha256(_canonical_json(current_schema))
        stored_hash = str(statement.get("schema_hash") or "")
        checks["schema_hash_matches"] = current_hash == stored_hash
    else:
        checks["schema_hash_matches"] = True  # not checked

    valid = all(checks.values())
    evidence_origin = "INDEPENDENTLY_VERIFIED" if valid else "LOCALLY_OBSERVED"

    return {
        "valid": valid,
        "manifest_id": manifest.get("manifest_id"),
        "tool_name": statement.get("tool_name"),
        "version": statement.get("version"),
        "declared_capabilities": statement.get("declared_capabilities") or [],
        "allowed_agents": statement.get("allowed_agents"),
        "checks": checks,
        "evidence_origin": evidence_origin,
        "verified_at": _utc_now(),
    }


# ── Storage operations ────────────────────────────────────────────────────────

def register_manifest(manifest: dict[str, Any], store: Any) -> dict[str, Any]:
    """Persist a manifest in the AIAF store (after signing/verification).

    The manifest is stored as-is; no re-verification is performed here.
    Call :func:`verify_manifest` before registering if integrity matters.
    """
    statement = manifest.get("statement") or {}
    tool_name = str(statement.get("tool_name") or "").strip()
    version = str(statement.get("version") or "").strip()
    if not tool_name or not version:
        raise ManifestError("manifest.statement must have tool_name and version")

    key = _manifest_key(tool_name, version)
    now = _utc_now()
    record: dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            "tool_name": tool_name,
            "version": version,
            "manifest_id": manifest.get("manifest_id"),
            "manifest_version": manifest.get("manifest_version", MANIFEST_VERSION),
            "algorithm": manifest.get("algorithm"),
            "declared_capabilities": statement.get("declared_capabilities") or [],
            "allowed_agents": statement.get("allowed_agents"),
            "schema_hash": statement.get("schema_hash"),
            "issuer": statement.get("issuer"),
            "issued_at": statement.get("issued_at"),
            "expires_at": statement.get("expires_at"),
            "stored_at": now,
            "signature": manifest.get("signature"),
            "statement": statement,
        },
    }
    store.save_model(record)
    return _manifest_summary(record)


def get_manifest(
    tool_name: str,
    version: str,
    store: Any,
) -> dict[str, Any] | None:
    """Return the stored manifest for ``tool_name`` + ``version``, or ``None``."""
    record = store.get_model(_manifest_key(tool_name, version))
    if not record:
        return None
    return _manifest_summary(record)


def list_manifests(
    store: Any,
    *,
    tool_name: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List registered tool manifests, newest first.

    Optionally filter by ``tool_name``.
    """
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_MANIFEST_PREFIX):
            continue
        summary = _manifest_summary(m)
        if tool_name and summary.get("tool_name") != str(tool_name).strip():
            continue
        result.append(summary)
    result.sort(key=lambda s: s.get("stored_at") or "", reverse=True)
    return result[:limit]


def _manifest_summary(record: dict[str, Any]) -> dict[str, Any]:
    meta = record.get("metadata") or {}
    return {
        "tool_name": meta.get("tool_name"),
        "version": meta.get("version"),
        "manifest_id": meta.get("manifest_id"),
        "manifest_version": meta.get("manifest_version", MANIFEST_VERSION),
        "algorithm": meta.get("algorithm"),
        "declared_capabilities": meta.get("declared_capabilities") or [],
        "allowed_agents": meta.get("allowed_agents"),
        "schema_hash": meta.get("schema_hash"),
        "issuer": meta.get("issuer"),
        "issued_at": meta.get("issued_at"),
        "expires_at": meta.get("expires_at"),
        "stored_at": meta.get("stored_at"),
    }

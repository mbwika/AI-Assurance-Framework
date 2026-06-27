"""OpenSSF / Sigstore model signing verifier.

Verifies Sigstore signature bundles for model artifacts using the ``sigstore``
Python package (optional — degrades to NOT_AVAILABLE when not installed).

OpenSSF Model Signing v1.0 (April 2025) signs each model file with a
Sigstore bundle, producing a ``.sigstore.json`` (or ``.sigstore``) file
alongside the artifact.  A valid bundle anchors model identity to the
signer's OIDC identity (e.g. a GitHub Actions workflow), which Sigstore's
Rekor transparency log makes non-repudiable.

This is qualitatively different from AIAF's existing HMAC attestations:
  - HMAC:  symmetric — the same key that signs can also forge.
  - Sigstore:  Rekor-anchored — verification does not require the signer's
    key; it is independently confirmable via the public transparency log.

Evidence origins
----------------
``LOCALLY_OBSERVED``
    The bundle file exists and its format is valid (we observed it).
``INDEPENDENTLY_VERIFIED``
    The Sigstore verification succeeded — the artifact is cryptographically
    bound to the signer's identity via a public transparency log.

Integration
-----------
Called from ``api.interop.verify_sigstore`` (``POST /v1/interop/models/{id}/verify/sigstore``).
On success, AIAF adds a ``sigstore_verification`` fact tagged
``INDEPENDENTLY_VERIFIED`` to the model's evidence ledger, which the adoption
engine treats as identity verification (lifts the PILOT_ONLY ceiling).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SIGSTORE_VERIFIER_VERSION = "1.0"

# Status values
STATUS_VERIFIED = "VERIFIED"
STATUS_NOT_SIGNED = "NOT_SIGNED"
STATUS_VERIFICATION_FAILED = "VERIFICATION_FAILED"
STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"
STATUS_BUNDLE_INVALID = "BUNDLE_INVALID"
STATUS_ERROR = "ERROR"

# Candidate bundle filename suffixes to look for beside an artifact.
_BUNDLE_SUFFIXES = (".sigstore.json", ".sigstore", ".bundle")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_file(
    artifact_path: str,
    *,
    bundle_path: Optional[str] = None,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """Compatibility wrapper that accepts string paths."""
    return verify_resolved_file(
        Path(artifact_path),
        bundle_path=Path(bundle_path) if bundle_path else None,
        expected_identity=expected_identity,
        expected_issuer=expected_issuer,
    )


def verify_resolved_file(
    artifact_path: Path,
    *,
    bundle_path: Optional[Path] = None,
    expected_identity: Optional[str] = None,
    expected_issuer: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a Sigstore signature bundle for ``artifact_path``.

    Parameters
    ----------
    artifact_path:
        Local path to the model artifact to verify.
    bundle_path:
        Explicit path to the ``.sigstore.json`` bundle.  Auto-discovered
        alongside ``artifact_path`` if not supplied.
    expected_identity:
        Subject / email that must match the bundle's signer.  If None, any
        identity is accepted (with a note in the result).
    expected_issuer:
        OIDC issuer URL that must match.  If None, any issuer is accepted.

    Returns a structured dict with ``status``, ``verified``, ``signer_identity``,
    ``issuer``, ``transparency_log_url``, ``artifact_digest``, and
    ``verification_error``.
    """
    apath = artifact_path
    if not apath.exists():
        return _result(
            STATUS_NOT_SIGNED,
            verified=False,
            artifact_path=str(artifact_path),
            note="Artifact file does not exist.",
        )

    # Resolve bundle.
    resolved_bundle = bundle_path or _find_bundle_path(apath)
    if not resolved_bundle:
        return _result(
            STATUS_NOT_SIGNED,
            verified=False,
            artifact_path=str(artifact_path),
            note=(
                "No Sigstore bundle found alongside the artifact "
                f"(tried {', '.join(_BUNDLE_SUFFIXES)})."
            ),
        )

    bpath = resolved_bundle
    if not bpath.exists():
        return _result(
            STATUS_BUNDLE_INVALID,
            verified=False,
            artifact_path=str(artifact_path),
            bundle_path=str(resolved_bundle),
            note="Bundle path provided but file does not exist.",
        )

    # Attempt Sigstore verification.
    return _verify_with_sigstore(
        str(apath),
        str(bpath),
        expected_identity=expected_identity,
        expected_issuer=expected_issuer,
    )


def find_bundle(artifact_path: str) -> Optional[str]:
    """Return the path to a Sigstore bundle beside ``artifact_path``, or None."""
    bundle = _find_bundle_path(Path(artifact_path))
    return str(bundle) if bundle is not None else None


# ---------------------------------------------------------------------------
# Sigstore verification (optional dependency)
# ---------------------------------------------------------------------------


def _verify_with_sigstore(
    artifact_path: str,
    bundle_path: str,
    *,
    expected_identity: Optional[str],
    expected_issuer: Optional[str],
) -> Dict[str, Any]:
    """Attempt verification using the ``sigstore`` Python package."""
    try:
        import sigstore  # noqa: F401
    except ImportError:
        return _result(
            STATUS_NOT_AVAILABLE,
            verified=False,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            note=(
                "The 'sigstore' package is not installed. "
                "Install it with: pip install sigstore"
            ),
        )

    # Compute artifact digest (independent of sigstore).
    try:
        artifact_digest = _sha256_file(artifact_path)
    except Exception as exc:
        return _result(
            STATUS_ERROR,
            verified=False,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            note=f"Could not compute artifact digest: {exc}",
        )

    try:
        return _sigstore_verify(
            artifact_path, bundle_path, artifact_digest,
            expected_identity=expected_identity,
            expected_issuer=expected_issuer,
        )
    except Exception as exc:
        logger.warning("Sigstore verification error for %s: %s", artifact_path, exc)
        return _result(
            STATUS_ERROR,
            verified=False,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            artifact_digest=artifact_digest,
            note=f"Verification error: {exc}",
        )


def _sigstore_verify(
    artifact_path: str,
    bundle_path: str,
    artifact_digest: str,
    *,
    expected_identity: Optional[str],
    expected_issuer: Optional[str],
) -> Dict[str, Any]:
    """Inner sigstore verification — called only when sigstore is installed."""
    from sigstore.verify import Verifier  # type: ignore[import]
    from sigstore.models import Bundle  # type: ignore[import]

    with open(bundle_path) as fh:
        bundle_json = fh.read()

    try:
        bundle = Bundle.from_json(bundle_json)
    except Exception as exc:
        return _result(
            STATUS_BUNDLE_INVALID,
            verified=False,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            artifact_digest=artifact_digest,
            note=f"Invalid bundle format: {exc}",
        )

    # Build verification policy.
    try:
        from sigstore.verify.policy import AnyOf, Identity  # type: ignore[import]
        if expected_identity or expected_issuer:
            policy = AnyOf(
                [Identity(identity=expected_identity, issuer=expected_issuer)]
            )
        else:
            from sigstore.verify.policy import UnsafeNoOp  # type: ignore[import]
            policy = UnsafeNoOp()
    except ImportError:
        policy = None

    with open(artifact_path, "rb") as fh:
        artifact_bytes = fh.read()

    verifier = Verifier.production()
    try:
        if policy is not None:
            result_obj = verifier.verify_artifact(artifact_bytes, bundle, policy)
        else:
            result_obj = verifier.verify_artifact(artifact_bytes, bundle)

        signer = _extract_signer(bundle)
        issuer = _extract_issuer(bundle)
        log_url = _extract_log_url(bundle)

        return _result(
            STATUS_VERIFIED,
            verified=True,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            artifact_digest=artifact_digest,
            signer_identity=signer,
            issuer=issuer,
            transparency_log_url=log_url,
        )
    except Exception as exc:
        signer = _extract_signer(bundle)
        return _result(
            STATUS_VERIFICATION_FAILED,
            verified=False,
            artifact_path=artifact_path,
            bundle_path=bundle_path,
            artifact_digest=artifact_digest,
            signer_identity=signer,
            note=f"Signature invalid: {exc}",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_bundle_path(artifact_path: Path) -> Optional[Path]:
    """Discover a Sigstore bundle file beside the artifact."""
    base = str(artifact_path)
    for suffix in _BUNDLE_SUFFIXES:
        candidate = base + suffix
        candidate_path = Path(candidate)
        if candidate_path.exists():
            return candidate_path
    return None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_signer(bundle: Any) -> Optional[str]:
    """Best-effort signer identity extraction from a Sigstore bundle."""
    try:
        cert = bundle.signing_certificate  # type: ignore[attr-defined]
        for san in cert.san_extension or []:
            return str(san)
    except Exception:
        pass
    try:
        return str(bundle.signing_certificate.subject)  # type: ignore[attr-defined]
    except Exception:
        return None


def _extract_issuer(bundle: Any) -> Optional[str]:
    """Best-effort issuer extraction."""
    try:
        for ext in bundle.signing_certificate.extensions or []:  # type: ignore[attr-defined]
            if "oidcIssuer" in str(ext) or "issuer" in str(ext).lower():
                return str(ext.value)
    except Exception:
        return None
    return None


def _extract_log_url(bundle: Any) -> Optional[str]:
    """Best-effort Rekor log entry URL."""
    try:
        tlog = bundle.log_entry  # type: ignore[attr-defined]
        if hasattr(tlog, "integrated_time"):
            return "https://rekor.sigstore.dev"
    except Exception:
        pass
    return None


def _result(
    status: str,
    *,
    verified: bool,
    artifact_path: str = "",
    bundle_path: Optional[str] = None,
    artifact_digest: Optional[str] = None,
    signer_identity: Optional[str] = None,
    issuer: Optional[str] = None,
    transparency_log_url: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "verifier_version": SIGSTORE_VERIFIER_VERSION,
        "status": status,
        "verified": verified,
        "artifact_path": str(artifact_path),
        "bundle_path": str(bundle_path) if bundle_path else None,
        "artifact_digest": artifact_digest,
        "signer_identity": signer_identity,
        "issuer": issuer,
        "transparency_log_url": transparency_log_url,
        "note": note,
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

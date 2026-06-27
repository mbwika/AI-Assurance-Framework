"""Tests for src/aiaf/registry/sigstore_verifier.py (Phase 3)."""

import os
import tempfile
from pathlib import Path

import pytest

from aiaf.registry.sigstore_verifier import (
    SIGSTORE_VERIFIER_VERSION,
    STATUS_BUNDLE_INVALID,
    STATUS_NOT_AVAILABLE,
    STATUS_NOT_SIGNED,
    STATUS_VERIFIED,
    STATUS_VERIFICATION_FAILED,
    find_bundle,
    verify_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_file(path: Path, content: bytes = b"model weights") -> Path:
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# find_bundle tests
# ---------------------------------------------------------------------------


def test_find_bundle_returns_none_when_no_bundle(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    assert find_bundle(str(artifact)) is None


def test_find_bundle_finds_sigstore_json(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    bundle = tmp_path / "model.bin.sigstore.json"
    bundle.write_text('{"bundle": true}')
    found = find_bundle(str(artifact))
    assert found == str(bundle)


def test_find_bundle_finds_sigstore_extension(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    bundle = tmp_path / "model.bin.sigstore"
    bundle.write_text('{"bundle": true}')
    found = find_bundle(str(artifact))
    assert found == str(bundle)


# ---------------------------------------------------------------------------
# verify_file — no bundle / no artifact tests
# ---------------------------------------------------------------------------


def test_verify_file_not_signed_when_artifact_missing(tmp_path):
    result = verify_file(str(tmp_path / "nonexistent.bin"))
    assert result["status"] == STATUS_NOT_SIGNED
    assert result["verified"] is False


def test_verify_file_not_signed_when_no_bundle(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    result = verify_file(str(artifact))
    assert result["status"] == STATUS_NOT_SIGNED
    assert result["verified"] is False


def test_verify_file_bundle_invalid_when_bundle_path_missing(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    result = verify_file(str(artifact), bundle_path=str(tmp_path / "no_bundle.sigstore.json"))
    assert result["status"] == STATUS_BUNDLE_INVALID
    assert result["verified"] is False


# ---------------------------------------------------------------------------
# verify_file — sigstore not installed / NOT_AVAILABLE
# ---------------------------------------------------------------------------


def test_verify_file_not_available_when_sigstore_not_installed(tmp_path, monkeypatch):
    """Simulate sigstore package absent."""
    artifact = _write_file(tmp_path / "model.bin")
    bundle = tmp_path / "model.bin.sigstore.json"
    bundle.write_text('{"bundle": true}')

    # Patch the import inside the module to raise ImportError
    import builtins
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "sigstore":
            raise ImportError("No module named 'sigstore'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    result = verify_file(str(artifact), bundle_path=str(bundle))
    assert result["status"] == STATUS_NOT_AVAILABLE
    assert result["verified"] is False


# ---------------------------------------------------------------------------
# Result schema tests
# ---------------------------------------------------------------------------


def test_result_has_required_fields(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    result = verify_file(str(artifact))
    for field in (
        "verifier_version", "status", "verified", "artifact_path",
        "bundle_path", "artifact_digest", "signer_identity",
        "issuer", "transparency_log_url", "note", "verified_at",
    ):
        assert field in result, f"Missing field: {field}"


def test_verifier_version_constant():
    assert SIGSTORE_VERIFIER_VERSION == "1.0"


def test_verified_at_is_utc_iso(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    result = verify_file(str(artifact))
    assert "T" in result["verified_at"]
    assert result["verified_at"].endswith("Z")


def test_not_signed_result_has_false_verified(tmp_path):
    artifact = _write_file(tmp_path / "model.bin")
    result = verify_file(str(artifact))
    assert result["verified"] is False
    assert result["status"] == STATUS_NOT_SIGNED

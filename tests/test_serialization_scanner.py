"""Tests for the serialization security scanner (Phase 2)."""

import io
import json
import pickle
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from aiaf.registry.serialization_scanner import (
    STATUS_CLEAN,
    STATUS_ERROR,
    STATUS_NO_FILE,
    STATUS_UNSAFE,
    STATUS_UNSUPPORTED,
    SCAN_VERSION,
    scan_file,
)


# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------


def _write_safe_pickle(path: str) -> None:
    """Write a pickle that only uses safe (torch-like) globals."""
    import collections
    with open(path, "wb") as f:
        pickle.dump(collections.OrderedDict([("weight", [1.0, 2.0])]), f, protocol=2)


def _write_dangerous_pickle(path: str) -> None:
    """Write a pickle containing an os.system GLOBAL (no execution on dumps)."""
    class _ExploitFixture:
        def __reduce__(self):
            import os
            return (os.system, ("echo test",))
    with open(path, "wb") as f:
        pickle.dump(_ExploitFixture(), f, protocol=2)


def _write_zip_pytorch(path: str, dangerous: bool = False) -> None:
    """Write a minimal ZIP-based PyTorch-style archive with a data.pkl inside."""
    buf = io.BytesIO()
    if dangerous:
        class _ExploitFixture:
            def __reduce__(self):
                import os
                return (os.system, ("echo test",))
        data = pickle.dumps(_ExploitFixture(), protocol=2)
    else:
        import collections
        data = pickle.dumps(collections.OrderedDict(), protocol=2)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", data)
        zf.writestr("archive/data/0", b"\x00" * 16)  # fake tensor blob


def _write_valid_safetensors(path: str) -> None:
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header)))
        f.write(header)


def _write_malformed_safetensors(path: str) -> None:
    # Write a header_size that is absurdly large
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", 200 * 1024 * 1024 + 1))
        f.write(b"\xff" * 16)


def _write_invalid_safetensors_json(path: str) -> None:
    bad_json = b"not valid json {{{"
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(bad_json)))
        f.write(bad_json)


def _write_onnx(path: str, valid: bool = True) -> None:
    if valid:
        # ONNX protobuf starts with 0x0A (field 1, length-delimited)
        with open(path, "wb") as f:
            f.write(b"\x0a\x04test")
    else:
        with open(path, "wb") as f:
            f.write(b"\xff\xfe\x00\x00")


# ---------------------------------------------------------------------------
# Tests: basic output shape
# ---------------------------------------------------------------------------


def test_scan_file_returns_required_keys():
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        _write_safe_pickle(f.name)
        result = scan_file(f.name)
    assert set(result.keys()) >= {
        "scan_version", "scanner", "format_detected", "status",
        "findings", "by_severity", "match_count", "scanned_at",
        "assessment_complete", "file_path",
    }
    assert result["scan_version"] == SCAN_VERSION


def test_nonexistent_file_returns_no_file():
    result = scan_file("/tmp/aiaf_test_nonexistent_model_xyz.pkl")
    assert result["status"] == STATUS_NO_FILE
    assert result["assessment_complete"] is False


# ---------------------------------------------------------------------------
# Tests: safe pickle
# ---------------------------------------------------------------------------


def test_safe_ordered_dict_pickle_is_clean():
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        _write_safe_pickle(f.name)
        result = scan_file(f.name)
    assert result["status"] == STATUS_CLEAN
    assert result["match_count"] == 0
    assert result["assessment_complete"] is True


# ---------------------------------------------------------------------------
# Tests: dangerous pickle
# ---------------------------------------------------------------------------


def test_dangerous_os_pickle_is_flagged():
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        _write_dangerous_pickle(f.name)
        result = scan_file(f.name)
    assert result["status"] == STATUS_UNSAFE
    assert result["match_count"] > 0
    assert any(
        "os" in str(finding.get("module", ""))
        for finding in result["findings"]
    )
    assert result["by_severity"].get("CRITICAL", 0) > 0


def test_dangerous_pickle_finding_has_required_keys():
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        _write_dangerous_pickle(f.name)
        result = scan_file(f.name)
    finding = result["findings"][0]
    assert "type" in finding
    assert "severity" in finding
    assert "description" in finding


# ---------------------------------------------------------------------------
# Tests: ZIP (PyTorch-style) pickle
# ---------------------------------------------------------------------------


def test_clean_zip_pytorch_is_clean():
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
        fname = f.name
    _write_zip_pytorch(fname, dangerous=False)
    result = scan_file(fname)
    assert result["status"] == STATUS_CLEAN
    assert result["format_detected"] == "pytorch_pickle"


def test_dangerous_zip_pytorch_is_flagged():
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
        fname = f.name
    _write_zip_pytorch(fname, dangerous=True)
    result = scan_file(fname)
    assert result["status"] == STATUS_UNSAFE
    assert result["match_count"] > 0


# ---------------------------------------------------------------------------
# Tests: safetensors
# ---------------------------------------------------------------------------


def test_valid_safetensors_is_clean():
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
        _write_valid_safetensors(f.name)
        result = scan_file(f.name)
    assert result["status"] == STATUS_CLEAN
    assert result["format_detected"] == "safetensors"


def test_malformed_safetensors_header_length_is_flagged():
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
        _write_malformed_safetensors(f.name)
        result = scan_file(f.name)
    assert result["status"] == STATUS_UNSAFE
    assert any("header" in str(f.get("type", "")).lower() for f in result["findings"])
    assert result["by_severity"].get("CRITICAL", 0) > 0


def test_invalid_safetensors_json_header_is_flagged():
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
        _write_invalid_safetensors_json(f.name)
        result = scan_file(f.name)
    assert result["status"] in (STATUS_UNSAFE, "SUSPICIOUS")


# ---------------------------------------------------------------------------
# Tests: ONNX
# ---------------------------------------------------------------------------


def test_valid_onnx_is_clean():
    with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
        _write_onnx(f.name, valid=True)
        result = scan_file(f.name)
    assert result["format_detected"] == "onnx"
    assert result["status"] == STATUS_CLEAN


def test_invalid_onnx_magic_is_flagged():
    with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as f:
        _write_onnx(f.name, valid=False)
        result = scan_file(f.name)
    assert result["format_detected"] == "onnx"
    assert len(result["findings"]) > 0

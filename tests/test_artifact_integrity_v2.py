"""Adversarial tests for bounded, race-aware artifact integrity v2."""

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _indicators(result):
    return {item["indicator"] for item in result["diagnostics"]}


def test_file_measurement_and_verification_are_content_bound(tmp_path):
    ensure_src()
    from aiaf.registry import (
        measure_artifact_integrity_v2,
        verify_artifact_integrity_v2,
    )

    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"model-weights")
    measured = measure_artifact_integrity_v2(artifact)

    assert measured["measured"] is True
    assert measured["status"] == "MEASURED"
    assert measured["evidence"]["artifact_kind"] == "FILE"
    assert measured["evidence"]["digest"] == hashlib.sha256(
        b"model-weights"
    ).hexdigest()
    assert measured["evidence"]["byte_size"] == 13
    assert json.loads(json.dumps(measured))["measured"] is True
    assert verify_artifact_integrity_v2(
        artifact, measured["evidence"]
    )["verified"] is True

    artifact.write_bytes(b"changed-model")
    verification = verify_artifact_integrity_v2(
        artifact, measured["evidence"]
    )
    assert verification["verified"] is False
    assert verification["status"] == "MISMATCH"
    assert "digest_matches" in verification["failed_checks"]


def test_directory_root_is_deterministic_and_path_sensitive(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (left / "b.txt").write_bytes(b"b")
    (left / "a.txt").write_bytes(b"a")
    (right / "a.txt").write_bytes(b"a")
    (right / "b.txt").write_bytes(b"b")

    first = measure_artifact_integrity_v2(left, {"include_manifest": True})
    second = measure_artifact_integrity_v2(right, {"include_manifest": True})
    assert first["evidence"] == second["evidence"]
    assert [item["path"] for item in first["evidence"]["manifest"]] == [
        "a.txt",
        "b.txt",
    ]

    (right / "b.txt").rename(right / "c.txt")
    renamed = measure_artifact_integrity_v2(right)
    assert renamed["evidence"]["digest"] != first["evidence"]["digest"]


def test_manifest_reports_missing_unexpected_modified_and_size_changes(tmp_path):
    ensure_src()
    from aiaf.registry import (
        measure_artifact_integrity_v2,
        verify_artifact_integrity_v2,
    )

    artifact = tmp_path / "bundle"
    artifact.mkdir()
    (artifact / "missing.txt").write_bytes(b"remove")
    (artifact / "modified.txt").write_bytes(b"same-size")
    (artifact / "resized.txt").write_bytes(b"short")
    expected = measure_artifact_integrity_v2(
        artifact, {"include_manifest": True}
    )["evidence"]

    (artifact / "missing.txt").unlink()
    (artifact / "modified.txt").write_bytes(b"diff-size")
    (artifact / "resized.txt").write_bytes(b"considerably-longer")
    (artifact / "unexpected.txt").write_bytes(b"new")
    result = verify_artifact_integrity_v2(artifact, expected)

    assert result["verified"] is False
    assert result["mismatches"]["missing_paths"] == ["missing.txt"]
    assert result["mismatches"]["unexpected_paths"] == ["unexpected.txt"]
    assert result["mismatches"]["modified_paths"] == [
        "modified.txt",
        "resized.txt",
    ]
    assert result["mismatches"]["size_mismatch_paths"] == ["resized.txt"]


@pytest.mark.parametrize(
    "evidence_mutation",
    [
        lambda value: {**value, "digest": value["digest"].upper()},
        lambda value: {**value, "unknown": True},
        lambda value: {**value, "file_count": True},
        lambda value: {**value, "byte_size": -1},
    ],
)
def test_malformed_expected_evidence_fails_closed(tmp_path, evidence_mutation):
    ensure_src()
    from aiaf.registry import (
        measure_artifact_integrity_v2,
        verify_artifact_integrity_v2,
    )

    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"bytes")
    evidence = measure_artifact_integrity_v2(artifact)["evidence"]
    result = verify_artifact_integrity_v2(
        artifact, evidence_mutation(evidence)
    )
    assert result["verified"] is False
    assert result["status"] == "INVALID_EVIDENCE"
    assert "invalid_expected_evidence" in _indicators(result)


def test_policy_bounds_fail_closed_without_partial_digest(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    artifact = tmp_path / "large.bin"
    artifact.write_bytes(b"0123456789")
    result = measure_artifact_integrity_v2(
        artifact, {"max_total_bytes": 5}
    )
    assert result["measured"] is False
    assert result["status"] == "PARTIAL"
    assert result["evidence"] is None
    assert "artifact_byte_limit_reached" in _indicators(result)

    invalid = measure_artifact_integrity_v2(
        artifact, {"max_files": True}
    )
    assert invalid["status"] == "INVALID_POLICY"
    assert invalid["evidence"] is None


def test_file_and_depth_limits_make_directory_measurement_partial(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    artifact = tmp_path / "tree"
    nested = artifact / "one" / "two"
    nested.mkdir(parents=True)
    (artifact / "a").write_bytes(b"a")
    (artifact / "b").write_bytes(b"b")
    (nested / "deep").write_bytes(b"deep")

    file_limited = measure_artifact_integrity_v2(
        artifact, {"max_files": 1}
    )
    assert file_limited["measured"] is False
    assert file_limited["status"] == "PARTIAL"
    assert file_limited["evidence"] is None
    assert "artifact_file_limit_reached" in _indicators(file_limited)

    depth_limited = measure_artifact_integrity_v2(
        artifact, {"max_depth": 1}
    )
    assert depth_limited["status"] == "PARTIAL"
    assert "directory_depth_limit_reached" in _indicators(depth_limited)


def test_symlinks_are_rejected_at_top_level_and_inside_tree(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported")

    top = measure_artifact_integrity_v2(link)
    assert top["status"] == "INVALID_TARGET"
    assert "symlink_artifact_rejected" in _indicators(top)

    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "linked").symlink_to(target)
    nested = measure_artifact_integrity_v2(directory)
    assert nested["status"] == "PARTIAL"
    assert nested["evidence"] is None
    assert "artifact_symlink_rejected" in _indicators(nested)


def test_special_directory_entry_is_rejected(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are not supported")
    artifact = tmp_path / "tree"
    artifact.mkdir()
    try:
        os.mkfifo(artifact / "pipe")
    except OSError:
        pytest.skip("FIFOs are not supported by this filesystem")
    result = measure_artifact_integrity_v2(artifact)
    assert result["status"] == "PARTIAL"
    assert "special_artifact_entry_rejected" in _indicators(result)


def test_empty_directory_has_a_stable_non_file_root(tmp_path):
    ensure_src()
    from aiaf.registry import measure_artifact_integrity_v2

    artifact = tmp_path / "empty"
    artifact.mkdir()
    first = measure_artifact_integrity_v2(artifact)
    second = measure_artifact_integrity_v2(artifact)
    assert first["measured"] is True
    assert first["evidence"]["artifact_kind"] == "DIRECTORY"
    assert first["evidence"]["file_count"] == 0
    assert first["evidence"]["digest"] == second["evidence"]["digest"]


def test_in_read_mutation_is_detected(monkeypatch, tmp_path):
    ensure_src()
    from aiaf.registry import artifact_integrity_v2 as integrity

    artifact = tmp_path / "changing.bin"
    artifact.write_bytes(b"before")
    real_read = integrity.os.read
    mutated = False

    def mutate_after_first_read(descriptor, size):
        nonlocal mutated
        chunk = real_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            artifact.write_bytes(b"after-and-longer")
        return chunk

    monkeypatch.setattr(integrity.os, "read", mutate_after_first_read)
    result = integrity.measure_artifact_integrity_v2(artifact)
    assert result["measured"] is False
    assert result["status"] == "UNSTABLE_ARTIFACT"
    assert "artifact_changed_during_measurement" in _indicators(result)


def test_queued_directory_symlink_swap_cannot_escape_root(monkeypatch, tmp_path):
    ensure_src()
    from aiaf.registry import artifact_integrity_v2 as integrity

    artifact = tmp_path / "artifact"
    queued = artifact / "queued"
    outside = tmp_path / "outside"
    queued.mkdir(parents=True)
    outside.mkdir()
    (queued / "inside.txt").write_bytes(b"inside")
    (outside / "secret.txt").write_bytes(b"outside-secret")

    real_reader = integrity._read_directory_entries
    swapped = False

    def swap_before_queued_open(path, expected_snapshot, max_entries):
        nonlocal swapped
        if Path(path) == queued and not swapped:
            swapped = True
            (queued / "inside.txt").unlink()
            queued.rmdir()
            queued.symlink_to(outside, target_is_directory=True)
        return real_reader(path, expected_snapshot, max_entries)

    monkeypatch.setattr(
        integrity, "_read_directory_entries", swap_before_queued_open
    )
    result = integrity.measure_artifact_integrity_v2(artifact, {"include_manifest": True})

    assert result["measured"] is False
    assert result["evidence"] is None
    assert result["coverage"]["files_measured"] == 0
    assert "directory_unreadable" in _indicators(result)


def test_directory_entry_bound_applies_before_materializing_all_entries(
    monkeypatch, tmp_path
):
    ensure_src()
    from aiaf.registry import artifact_integrity_v2 as integrity

    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "a").write_bytes(b"a")
    (artifact / "b").write_bytes(b"b")
    monkeypatch.setattr(integrity, "_MAX_DIRECTORY_ENTRIES", 1)

    result = integrity.measure_artifact_integrity_v2(artifact)

    assert result["measured"] is False
    assert result["status"] == "PARTIAL"
    assert result["evidence"] is None
    assert "directory_entry_limit_reached" in _indicators(result)

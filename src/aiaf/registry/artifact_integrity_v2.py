"""Race-aware, bounded artifact integrity measurement and verification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Dict, List, Optional, Tuple
import unicodedata


ARTIFACT_INTEGRITY_SCORING_VERSION = "2.0"
FILE_DIGEST_ALGORITHM = "SHA-256"
DIRECTORY_DIGEST_ALGORITHM = "AIAF-MERKLE-SHA256-V2"

_FILE_DOMAIN = b"AIAF-ARTIFACT-FILE-LEAF-V2\x00"
_NODE_DOMAIN = b"AIAF-ARTIFACT-MERKLE-NODE-V2\x00"
_UNARY_DOMAIN = b"AIAF-ARTIFACT-MERKLE-UNARY-V2\x00"
_ROOT_DOMAIN = b"AIAF-ARTIFACT-MERKLE-ROOT-V2\x00"
_EMPTY_DOMAIN = b"AIAF-ARTIFACT-MERKLE-EMPTY-V2\x00"
_MAX_TOTAL_BYTES = 100 * 1024 * 1024 * 1024
_MAX_FILES = 100_000
_MAX_DIRECTORIES = 20_000
_MAX_DIRECTORY_ENTRIES = _MAX_FILES + _MAX_DIRECTORIES
_MAX_DEPTH = 32
_MAX_PATH_BYTES = 4_096
_MAX_DIAGNOSTICS = 500
_MAX_MISMATCHES = 250
_READ_CHUNK_BYTES = 1024 * 1024
_SHA256_HEX = frozenset("0123456789abcdef")
_CONTEXT_FIELDS = frozenset(
    {"max_total_bytes", "max_files", "max_depth", "include_manifest"}
)
_EVIDENCE_FIELDS = frozenset(
    {
        "artifact_kind",
        "algorithm",
        "digest",
        "byte_size",
        "file_count",
        "manifest_sha256",
        "manifest",
    }
)
_MANIFEST_FIELDS = frozenset({"path", "sha256", "byte_size"})


@dataclass(frozen=True)
class _Snapshot:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _DirectoryEntry:
    name: str
    snapshot: _Snapshot


@dataclass
class _Policy:
    max_total_bytes: int = _MAX_TOTAL_BYTES
    max_files: int = _MAX_FILES
    max_depth: int = _MAX_DEPTH
    include_manifest: bool = False
    valid: bool = True


@dataclass
class _Scan:
    target_valid: bool
    complete: bool
    stable: bool
    artifact_kind: Optional[str]
    algorithm: Optional[str]
    digest: Optional[str]
    byte_size: int
    records: List[Dict[str, Any]]
    directories_examined: int
    diagnostics: List[Dict[str, Any]]


def measure_artifact_integrity_v2(
    path: Any,
    scan_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Measure one regular file or directory snapshot without following links."""
    diagnostics: List[Dict[str, Any]] = []
    policy = _policy(scan_context, diagnostics)
    scan = _scan_artifact(path, policy, diagnostics)
    evidence = _evidence(scan, include_manifest=policy.include_manifest)
    measured = (
        policy.valid
        and scan.target_valid
        and scan.complete
        and scan.stable
        and evidence is not None
    )
    return {
        "measured": measured,
        "scoring_version": ARTIFACT_INTEGRITY_SCORING_VERSION,
        "status": _measurement_status(policy, scan, measured),
        "evidence": evidence,
        "coverage": _coverage(scan, policy),
        "diagnostics": scan.diagnostics[:_MAX_DIAGNOSTICS],
    }


def verify_artifact_integrity_v2(
    path: Any,
    expected_evidence: Any,
    verification_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify artifact bytes, structure, and optional per-file manifest evidence."""
    diagnostics: List[Dict[str, Any]] = []
    policy = _policy(verification_context, diagnostics)
    expected, expected_valid = _expected_evidence(
        expected_evidence, policy, diagnostics
    )
    scan = _scan_artifact(path, policy, diagnostics)

    checks = {
        "verification_policy_valid": policy.valid,
        "expected_evidence_valid": expected_valid,
        "target_valid": scan.target_valid,
        "scan_complete": scan.complete,
        "artifact_stable": scan.stable,
        "artifact_kind_matches": False,
        "algorithm_matches": False,
        "digest_matches": False,
        "byte_size_matches": False,
        "file_count_matches": False,
        "manifest_sha256_matches": False,
        "file_manifest_matches": False,
    }
    mismatches = {
        "missing_paths": [],
        "unexpected_paths": [],
        "modified_paths": [],
        "size_mismatch_paths": [],
    }
    if expected_valid:
        checks["artifact_kind_matches"] = (
            scan.artifact_kind == expected["artifact_kind"]
        )
        checks["algorithm_matches"] = scan.algorithm == expected["algorithm"]
        checks["digest_matches"] = _digest_equal(
            scan.digest, expected["digest"]
        )
        checks["byte_size_matches"] = scan.byte_size == expected["byte_size"]
        checks["file_count_matches"] = (
            expected["file_count"] is None
            or len(scan.records) == expected["file_count"]
        )
        observed_manifest_sha256 = _manifest_sha256(scan.records)
        checks["manifest_sha256_matches"] = (
            expected["manifest_sha256"] is None
            or _digest_equal(
                observed_manifest_sha256, expected["manifest_sha256"]
            )
        )
        if expected["manifest"] is None:
            checks["file_manifest_matches"] = True
        else:
            mismatches = _manifest_mismatches(
                expected["manifest"], scan.records
            )
            checks["file_manifest_matches"] = not any(mismatches.values())

    failed_checks = [name for name, passed in checks.items() if not passed]
    verified = not failed_checks
    return {
        "verified": verified,
        "scoring_version": ARTIFACT_INTEGRITY_SCORING_VERSION,
        "status": _verification_status(
            policy, expected_valid, scan, verified
        ),
        "checks": checks,
        "failed_checks": failed_checks,
        "observed_evidence": _evidence(scan, include_manifest=False),
        "mismatches": mismatches,
        "coverage": _coverage(scan, policy),
        "diagnostics": scan.diagnostics[:_MAX_DIAGNOSTICS],
    }


def _scan_artifact(path, policy, diagnostics):
    target = _target(path, diagnostics)
    if target is None:
        return _Scan(
            False, False, False, None, None, None, 0, [], 0, diagnostics
        )
    if not policy.valid:
        return _Scan(
            True, False, False, None, None, None, 0, [], 0, diagnostics
        )
    try:
        metadata = os.lstat(target)
        if stat.S_ISREG(metadata.st_mode):
            return _scan_file(target, policy, diagnostics)
        if stat.S_ISDIR(metadata.st_mode):
            return _scan_directory(target, policy, diagnostics)
        _diagnostic(
            diagnostics,
            "unsupported_artifact_type",
            "CRITICAL",
            "Only regular files and directories can be integrity measured.",
        )
    except OSError:
        _diagnostic(
            diagnostics,
            "artifact_scan_failed",
            "HIGH",
            "Artifact evidence could not be read safely.",
        )
    return _Scan(
        False, False, False, None, None, None, 0, [], 0, diagnostics
    )


def _scan_file(path, policy, diagnostics):
    try:
        digest, byte_size, stable, snapshot = _hash_regular_file(
            path, policy.max_total_bytes
        )
    except _BoundExceeded:
        _diagnostic(
            diagnostics,
            "artifact_byte_limit_reached",
            "HIGH",
            "Artifact exceeds the configured byte bound.",
        )
        return _Scan(
            True,
            False,
            True,
            "FILE",
            FILE_DIGEST_ALGORITHM,
            None,
            0,
            [],
            0,
            diagnostics,
        )
    except OSError:
        _diagnostic(
            diagnostics,
            "artifact_file_unreadable",
            "HIGH",
            "Artifact file could not be opened as a stable regular file.",
        )
        return _Scan(
            True,
            False,
            False,
            "FILE",
            FILE_DIGEST_ALGORITHM,
            None,
            0,
            [],
            0,
            diagnostics,
        )
    if not stable:
        _diagnostic(
            diagnostics,
            "artifact_changed_during_measurement",
            "CRITICAL",
            "Artifact metadata changed while its digest was being measured.",
        )
    record = {
        "path": ".",
        "sha256": digest,
        "byte_size": byte_size,
    }
    path_stable = _path_matches_snapshot(path, snapshot)
    if not path_stable:
        stable = False
        _diagnostic(
            diagnostics,
            "artifact_path_replaced",
            "CRITICAL",
            "Artifact path identity changed during measurement.",
        )
    return _Scan(
        True,
        True,
        stable,
        "FILE",
        FILE_DIGEST_ALGORITHM,
        digest,
        byte_size,
        [record],
        0,
        diagnostics,
    )


def _scan_directory(root, policy, diagnostics):
    root_before = _snapshot(os.lstat(root))
    records: List[Dict[str, Any]] = []
    snapshots: List[Tuple[Path, _Snapshot]] = [(root, root_before)]
    directories_examined = 0
    entries_examined = 0
    complete = True
    stable = True
    total_bytes = 0
    collision_keys: Dict[str, Tuple[str, str]] = {}
    stack: List[Tuple[Path, str, int, _Snapshot]] = [
        (root, "", 0, root_before)
    ]

    while stack:
        directory, relative, depth, expected_directory = stack.pop()
        if depth > policy.max_depth:
            complete = False
            _diagnostic(
                diagnostics,
                "directory_depth_limit_reached",
                "HIGH",
                "Directory traversal reached the configured depth bound.",
            )
            continue
        directories_examined += 1
        if directories_examined > _MAX_DIRECTORIES:
            complete = False
            _diagnostic(
                diagnostics,
                "directory_count_limit_reached",
                "HIGH",
                "Directory traversal reached the directory-count bound.",
            )
            break
        try:
            entries = _read_directory_entries(
                directory,
                expected_directory,
                _MAX_DIRECTORY_ENTRIES - entries_examined,
            )
            entries_examined += len(entries)
        except _DirectoryEntryLimit:
            complete = False
            _diagnostic(
                diagnostics,
                "directory_entry_limit_reached",
                "HIGH",
                "Directory traversal reached the entry-count bound.",
            )
            break
        except OSError:
            complete = False
            _diagnostic(
                diagnostics,
                "directory_unreadable",
                "HIGH",
                "A directory could not be enumerated safely.",
            )
            continue
        for entry in entries:
            logical = f"{relative}/{entry.name}" if relative else entry.name
            normalized = _safe_relative_path(logical)
            if normalized is None:
                complete = False
                _diagnostic(
                    diagnostics,
                    "unsafe_artifact_path",
                    "HIGH",
                    "An artifact entry has an unsafe or oversized path.",
                    {"path_sha256": _path_digest(logical)},
                )
                continue
            collision_key = normalized.casefold()
            previous = collision_keys.get(collision_key)
            if previous is not None and previous[1] != logical:
                complete = False
                _diagnostic(
                    diagnostics,
                    "ambiguous_artifact_path",
                    "HIGH",
                    "Artifact entries collide under portable path normalization.",
                    {"path_sha256": _path_digest(normalized)},
                )
            else:
                collision_keys[collision_key] = (normalized, logical)
            entry_path = directory / entry.name
            try:
                if stat.S_ISLNK(entry.snapshot.mode):
                    complete = False
                    _diagnostic(
                        diagnostics,
                        "artifact_symlink_rejected",
                        "HIGH",
                        "Symlink entries are not included in artifact integrity roots.",
                        {"path_sha256": _path_digest(normalized)},
                    )
                    continue
                if stat.S_ISDIR(entry.snapshot.mode):
                    snapshots.append((entry_path, entry.snapshot))
                    stack.append(
                        (entry_path, normalized, depth + 1, entry.snapshot)
                    )
                    continue
                if not stat.S_ISREG(entry.snapshot.mode):
                    complete = False
                    _diagnostic(
                        diagnostics,
                        "special_artifact_entry_rejected",
                        "HIGH",
                        "Non-regular artifact entries cannot be integrity measured.",
                        {"path_sha256": _path_digest(normalized)},
                    )
                    continue
                if len(records) >= policy.max_files:
                    complete = False
                    _diagnostic(
                        diagnostics,
                        "artifact_file_limit_reached",
                        "HIGH",
                        "Artifact traversal reached the configured file bound.",
                    )
                    stack.clear()
                    break
                remaining = policy.max_total_bytes - total_bytes
                digest, byte_size, file_stable, file_snapshot = (
                    _hash_regular_file(entry_path, remaining)
                )
                file_stable = file_stable and _same_snapshot(
                    entry.snapshot, file_snapshot
                )
                total_bytes += byte_size
                stable = stable and file_stable
                if not file_stable:
                    _diagnostic(
                        diagnostics,
                        "artifact_changed_during_measurement",
                        "CRITICAL",
                        "An artifact file changed while its digest was being measured.",
                        {"path_sha256": _path_digest(normalized)},
                    )
                snapshots.append((entry_path, file_snapshot))
                records.append(
                    {
                        "path": normalized,
                        "sha256": digest,
                        "byte_size": byte_size,
                    }
                )
            except _BoundExceeded:
                complete = False
                _diagnostic(
                    diagnostics,
                    "artifact_byte_limit_reached",
                    "HIGH",
                    "Artifact traversal reached the configured byte bound.",
                )
                stack.clear()
                break
            except OSError:
                complete = False
                _diagnostic(
                    diagnostics,
                    "artifact_entry_unreadable",
                    "HIGH",
                    "An artifact entry could not be read as a stable regular file.",
                    {"path_sha256": _path_digest(normalized)},
                )

    records.sort(key=lambda item: item["path"])
    for path, expected_snapshot in snapshots:
        if not _path_matches_snapshot(path, expected_snapshot):
            stable = False
            _diagnostic(
                diagnostics,
                "artifact_tree_changed_during_measurement",
                "CRITICAL",
                "Artifact tree identity or metadata changed during measurement.",
                {"path_sha256": _path_digest(path)},
            )
            break
    if not stable:
        complete = False
    digest = _directory_root(records) if complete else None
    return _Scan(
        True,
        complete,
        stable,
        "DIRECTORY",
        DIRECTORY_DIGEST_ALGORITHM,
        digest,
        total_bytes,
        records,
        directories_examined,
        diagnostics,
    )


def _read_directory_entries(path, expected_snapshot, max_entries):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = _snapshot(os.fstat(descriptor))
        if (
            not stat.S_ISDIR(opened.mode)
            or not _same_snapshot(expected_snapshot, opened)
        ):
            raise OSError("directory identity changed before enumeration")
        with os.scandir(descriptor) as iterator:
            entries = []
            for entry in iterator:
                if len(entries) >= max_entries:
                    raise _DirectoryEntryLimit
                entries.append(_DirectoryEntry(
                    name=entry.name,
                    snapshot=_snapshot(entry.stat(follow_symlinks=False)),
                ))
        return sorted(
            entries,
            key=lambda item: unicodedata.normalize("NFC", item.name),
        )
    finally:
        os.close(descriptor)


def _hash_regular_file(path, max_bytes):
    before = _snapshot(os.lstat(path))
    if not stat.S_ISREG(before.mode):
        raise OSError("not a regular file")
    if before.size > max_bytes:
        raise _BoundExceeded
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    byte_size = 0
    try:
        opened = _snapshot(os.fstat(descriptor))
        if not _same_identity(before, opened) or not stat.S_ISREG(opened.mode):
            raise OSError("file identity changed before read")
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            byte_size += len(chunk)
            if byte_size > max_bytes:
                raise _BoundExceeded
            digest.update(chunk)
        after = _snapshot(os.fstat(descriptor))
        stable = _same_snapshot(opened, after) and byte_size == after.size
        return digest.hexdigest(), byte_size, stable, after
    finally:
        os.close(descriptor)


def _expected_evidence(value, policy, diagnostics):
    if not isinstance(value, dict) or not set(value).issubset(_EVIDENCE_FIELDS):
        _diagnostic(
            diagnostics,
            "invalid_expected_evidence",
            "CRITICAL",
            "Expected integrity evidence must be a strict supported object.",
        )
        return _empty_expected(), False
    kind = value.get("artifact_kind")
    algorithm = value.get("algorithm")
    digest = value.get("digest")
    byte_size = value.get("byte_size")
    file_count = value.get("file_count")
    manifest_sha256 = value.get("manifest_sha256")
    valid = (
        kind in {"FILE", "DIRECTORY"}
        and algorithm
        == (
            FILE_DIGEST_ALGORITHM
            if kind == "FILE"
            else DIRECTORY_DIGEST_ALGORITHM
        )
        and _valid_digest(digest)
        and _valid_nonnegative_integer(byte_size)
        and byte_size <= policy.max_total_bytes
        and (
            (
                kind == "FILE"
                and (
                    file_count is None
                    or (
                        _valid_nonnegative_integer(file_count)
                        and file_count == 1
                    )
                )
            )
            or (
                kind == "DIRECTORY"
                and _valid_nonnegative_integer(file_count)
                and file_count <= policy.max_files
            )
        )
        and (manifest_sha256 is None or _valid_digest(manifest_sha256))
    )
    manifest, manifest_valid = _expected_manifest(
        value.get("manifest"), policy
    )
    valid = valid and manifest_valid
    if manifest is not None:
        if kind != "DIRECTORY" or len(manifest) != file_count:
            valid = False
        computed_manifest = _manifest_sha256(manifest)
        if manifest_sha256 is not None and not _digest_equal(
            computed_manifest, manifest_sha256
        ):
            valid = False
    if not valid:
        _diagnostic(
            diagnostics,
            "invalid_expected_evidence",
            "CRITICAL",
            "Expected integrity evidence is incomplete, inconsistent, or malformed.",
        )
    return {
        "artifact_kind": kind,
        "algorithm": algorithm,
        "digest": digest,
        "byte_size": byte_size,
        "file_count": file_count,
        "manifest_sha256": manifest_sha256,
        "manifest": manifest,
    }, valid


def _expected_manifest(value, policy):
    if value is None:
        return None, True
    if not isinstance(value, list) or len(value) > policy.max_files:
        return None, False
    normalized = []
    seen = set()
    portable_paths = set()
    total_bytes = 0
    for item in value:
        if not isinstance(item, dict) or set(item) != _MANIFEST_FIELDS:
            return None, False
        path = _safe_relative_path(item.get("path"))
        digest = item.get("sha256")
        byte_size = item.get("byte_size")
        if (
            path is None
            or path == "."
            or path in seen
            or path.casefold() in portable_paths
            or not _valid_digest(digest)
            or not _valid_nonnegative_integer(byte_size)
            or byte_size > policy.max_total_bytes
        ):
            return None, False
        seen.add(path)
        portable_paths.add(path.casefold())
        total_bytes += byte_size
        if total_bytes > policy.max_total_bytes:
            return None, False
        normalized.append(
            {"path": path, "sha256": digest, "byte_size": byte_size}
        )
    return sorted(normalized, key=lambda item: item["path"]), True


def _manifest_mismatches(expected, observed):
    expected_by_path = {item["path"]: item for item in expected}
    observed_by_path = {item["path"]: item for item in observed}
    missing = sorted(set(expected_by_path) - set(observed_by_path))
    unexpected = sorted(set(observed_by_path) - set(expected_by_path))
    modified = []
    size_mismatch = []
    for path in sorted(set(expected_by_path) & set(observed_by_path)):
        expected_item = expected_by_path[path]
        observed_item = observed_by_path[path]
        if not _digest_equal(
            expected_item["sha256"], observed_item["sha256"]
        ):
            modified.append(path)
        if expected_item["byte_size"] != observed_item["byte_size"]:
            size_mismatch.append(path)
    return {
        "missing_paths": missing[:_MAX_MISMATCHES],
        "unexpected_paths": unexpected[:_MAX_MISMATCHES],
        "modified_paths": modified[:_MAX_MISMATCHES],
        "size_mismatch_paths": size_mismatch[:_MAX_MISMATCHES],
    }


def _evidence(scan, *, include_manifest):
    if (
        not scan.target_valid
        or scan.digest is None
        or scan.artifact_kind is None
        or scan.algorithm is None
    ):
        return None
    evidence = {
        "artifact_kind": scan.artifact_kind,
        "algorithm": scan.algorithm,
        "digest": scan.digest,
        "byte_size": scan.byte_size,
        "file_count": len(scan.records),
        "manifest_sha256": _manifest_sha256(scan.records),
    }
    if include_manifest and scan.artifact_kind == "DIRECTORY":
        evidence["manifest"] = scan.records
    return evidence


def _directory_root(records):
    if not records:
        node = hashlib.sha256(_EMPTY_DOMAIN).digest()
    else:
        nodes = [_file_leaf(item) for item in records]
        while len(nodes) > 1:
            next_level = []
            for index in range(0, len(nodes), 2):
                if index + 1 < len(nodes):
                    next_level.append(
                        hashlib.sha256(
                            _NODE_DOMAIN + nodes[index] + nodes[index + 1]
                        ).digest()
                    )
                else:
                    next_level.append(
                        hashlib.sha256(_UNARY_DOMAIN + nodes[index]).digest()
                    )
            nodes = next_level
        node = nodes[0]
    return hashlib.sha256(
        _ROOT_DOMAIN + len(records).to_bytes(8, "big") + node
    ).hexdigest()


def _file_leaf(record):
    path = record["path"].encode("utf-8")
    return hashlib.sha256(
        _FILE_DOMAIN
        + len(path).to_bytes(4, "big")
        + path
        + record["byte_size"].to_bytes(8, "big")
        + bytes.fromhex(record["sha256"])
    ).digest()


def _manifest_sha256(records):
    canonical = json.dumps(
        sorted(records, key=lambda item: item["path"]),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _policy(value, diagnostics):
    if value is None:
        return _Policy()
    if not isinstance(value, dict) or not set(value).issubset(_CONTEXT_FIELDS):
        _diagnostic(
            diagnostics,
            "invalid_verification_policy",
            "CRITICAL",
            "Verification context contains unsupported fields or is not an object.",
        )
        return _Policy(valid=False)
    policy = _Policy()
    bounds = (
        ("max_total_bytes", _MAX_TOTAL_BYTES),
        ("max_files", _MAX_FILES),
        ("max_depth", _MAX_DEPTH),
    )
    for field, absolute_maximum in bounds:
        if field not in value:
            continue
        candidate = value[field]
        if (
            not isinstance(candidate, int)
            or isinstance(candidate, bool)
            or candidate < 1
            or candidate > absolute_maximum
        ):
            policy.valid = False
        else:
            setattr(policy, field, candidate)
    if "include_manifest" in value:
        if isinstance(value["include_manifest"], bool):
            policy.include_manifest = value["include_manifest"]
        else:
            policy.valid = False
    if not policy.valid:
        _diagnostic(
            diagnostics,
            "invalid_verification_policy",
            "CRITICAL",
            "Verification bounds must be positive and no greater than hard safety limits.",
        )
    return policy


def _target(value, diagnostics):
    if not isinstance(value, (str, os.PathLike)):
        _diagnostic(
            diagnostics,
            "invalid_artifact_path",
            "CRITICAL",
            "Artifact path must be text or path-like.",
        )
        return None
    try:
        target = Path(value)
        metadata = os.lstat(target)
        if stat.S_ISLNK(metadata.st_mode):
            _diagnostic(
                diagnostics,
                "symlink_artifact_rejected",
                "CRITICAL",
                "Top-level symlink artifacts are not integrity measured.",
            )
            return None
        return target
    except (OSError, TypeError, ValueError):
        _diagnostic(
            diagnostics,
            "artifact_not_found_or_invalid",
            "HIGH",
            "Artifact path does not identify a readable filesystem object.",
        )
        return None


def _safe_relative_path(value):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8")) > _MAX_PATH_BYTES:
        return None
    if any(ord(character) < 32 for character in normalized):
        return None
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and path.parts[0].endswith(":"))
    ):
        return None
    return path.as_posix()


def _snapshot(metadata):
    return _Snapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def _same_identity(left, right):
    return (
        left.device == right.device
        and left.inode == right.inode
        and stat.S_IFMT(left.mode) == stat.S_IFMT(right.mode)
    )


def _same_snapshot(left, right):
    return (
        _same_identity(left, right)
        and left.size == right.size
        and left.mtime_ns == right.mtime_ns
        and left.ctime_ns == right.ctime_ns
    )


def _path_matches_snapshot(path, expected):
    try:
        return _same_snapshot(expected, _snapshot(os.lstat(path)))
    except OSError:
        return False


def _valid_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _SHA256_HEX for character in value)
    )


def _digest_equal(left, right):
    return _valid_digest(left) and _valid_digest(right) and hmac.compare_digest(
        left, right
    )


def _valid_nonnegative_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _empty_expected():
    return {
        "artifact_kind": None,
        "algorithm": None,
        "digest": None,
        "byte_size": None,
        "file_count": None,
        "manifest_sha256": None,
        "manifest": None,
    }


def _coverage(scan, policy):
    return {
        "files_measured": len(scan.records),
        "directories_examined": scan.directories_examined,
        "bytes_measured": scan.byte_size,
        "max_files": policy.max_files,
        "max_depth": policy.max_depth,
        "max_total_bytes": policy.max_total_bytes,
    }


def _measurement_status(policy, scan, measured):
    if not policy.valid:
        return "INVALID_POLICY"
    if not scan.target_valid:
        return "INVALID_TARGET"
    if not scan.stable:
        return "UNSTABLE_ARTIFACT"
    if not scan.complete:
        return "PARTIAL"
    return "MEASURED" if measured else "FAILED"


def _verification_status(policy, expected_valid, scan, verified):
    if not policy.valid:
        return "INVALID_POLICY"
    if not expected_valid:
        return "INVALID_EVIDENCE"
    if not scan.target_valid:
        return "INVALID_TARGET"
    if not scan.stable:
        return "UNSTABLE_ARTIFACT"
    if not scan.complete:
        return "PARTIAL"
    return "VERIFIED" if verified else "MISMATCH"


def _path_digest(value):
    return hashlib.sha256(
        str(value).encode("utf-8", errors="replace")
    ).hexdigest()


def _diagnostic(diagnostics, indicator, severity, detail, evidence=None):
    if len(diagnostics) >= _MAX_DIAGNOSTICS:
        return
    item = {
        "indicator": indicator,
        "severity": severity,
        "detail": detail,
    }
    if evidence:
        item["evidence"] = evidence
    diagnostics.append(item)


class _BoundExceeded(Exception):
    pass


class _DirectoryEntryLimit(Exception):
    pass

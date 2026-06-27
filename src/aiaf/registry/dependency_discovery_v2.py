"""Bounded, deterministic dependency-manifest discovery for untrusted artifacts."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, Dict, List, Tuple
import unicodedata
from urllib.parse import urlsplit, urlunsplit
import zipfile

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


DEPENDENCY_DISCOVERY_SCORING_VERSION = "2.0"

_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_TOTAL_MANIFEST_BYTES = 20 * 1024 * 1024
_MAX_MANIFESTS = 256
_MAX_FILES = 20_000
_MAX_DIRECTORY_DEPTH = 12
_MAX_ARCHIVE_MEMBERS = 10_000
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 100
_MAX_DEPENDENCIES = 20_000
_MAX_LINES = 50_000
_MAX_JSON_NODES = 250_000
_MAX_JSON_DEPTH = 32
_MAX_DIAGNOSTICS = 500
_MAX_TEXT = 2_048
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
_NPM_EXACT = re.compile(
    r"^[v=]?([0-9]+)\.([0-9]+)\.([0-9]+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_REQUIREMENT_HASH = re.compile(r"(?:^|\s)--hash(?:=|\s+)(sha256:[0-9a-fA-F]{64})(?=\s|$)")


@dataclass(frozen=True)
class _Candidate:
    path: str
    content: bytes


@dataclass(frozen=True)
class _DirectoryEntry:
    name: str
    metadata: os.stat_result


@dataclass
class _ScanState:
    artifact_type: str = "UNKNOWN"
    files_examined: int = 0
    members_examined: int = 0
    candidate_count: int = 0
    total_manifest_bytes: int = 0
    inventory_complete: bool = True


def discover_dependencies_v2(path: Any, artifact_name: str = "") -> Dict[str, Any]:
    """Discover dependency evidence with explicit completeness and resolution state."""
    diagnostics: List[Dict[str, Any]] = []
    state = _ScanState()
    target = _validated_target(path, diagnostics)
    if target is None:
        return _result([], [], diagnostics, state, valid_target=False)

    try:
        candidates = _collect_candidates(target, artifact_name, state, diagnostics)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        state.inventory_complete = False
        _diagnostic(
            diagnostics,
            "artifact_scan_failed",
            "HIGH",
            "The artifact could not be scanned safely.",
        )
        candidates = []

    candidates = _remove_ambiguous_candidates(candidates, state, diagnostics)
    dependencies: List[Dict[str, Any]] = []
    manifests: List[Dict[str, Any]] = []
    for candidate in sorted(candidates, key=lambda item: item.path):
        manifest_type = _manifest_type(candidate.path)
        parsed, parse_complete = _parse_manifest(
            manifest_type, candidate.path, candidate.content, diagnostics
        )
        if len(dependencies) + len(parsed) > _MAX_DEPENDENCIES:
            available = max(0, _MAX_DEPENDENCIES - len(dependencies))
            parsed = parsed[:available]
            parse_complete = False
            state.inventory_complete = False
            _diagnostic(
                diagnostics,
                "dependency_limit_reached",
                "HIGH",
                "Dependency output reached the global analysis bound.",
            )
        dependencies.extend(parsed)
        manifests.append(
            {
                "path": candidate.path,
                "type": manifest_type,
                "sha256": hashlib.sha256(candidate.content).hexdigest(),
                "byte_size": len(candidate.content),
                "dependency_count": len(parsed),
                "parse_status": "COMPLETE" if parse_complete else "PARTIAL",
            }
        )
        if not parse_complete:
            state.inventory_complete = False
        if len(dependencies) >= _MAX_DEPENDENCIES:
            break

    normalized = _deduplicate(dependencies)
    conflicts = _conflicts(normalized)
    if conflicts:
        _diagnostic(
            diagnostics,
            "conflicting_exact_versions",
            "HIGH",
            "A package identity resolves to multiple exact versions.",
            {"package_count": len(conflicts)},
        )
    return _result(
        normalized,
        manifests,
        diagnostics,
        state,
        valid_target=True,
        conflicts=conflicts,
    )


def _result(
    dependencies,
    manifests,
    diagnostics,
    state,
    *,
    valid_target,
    conflicts=None,
):
    conflicts = conflicts or []
    exact_count = sum(item["resolution"] == "EXACT" for item in dependencies)
    unresolved_count = len(dependencies) - exact_count
    resolution_complete = bool(dependencies) and unresolved_count == 0 and not conflicts
    inventory_complete = valid_target and state.inventory_complete
    if not valid_target:
        status = "INVALID_TARGET"
    elif not manifests:
        status = "NO_MANIFESTS" if inventory_complete else "PARTIAL"
    elif inventory_complete and resolution_complete:
        status = "COMPLETE"
    else:
        status = "PARTIAL"
    return {
        "scoring_version": DEPENDENCY_DISCOVERY_SCORING_VERSION,
        "artifact_type": state.artifact_type,
        "dependencies": dependencies,
        "manifests": manifests,
        "dependency_count": len(dependencies),
        "exact_dependency_count": exact_count,
        "unresolved_dependency_count": unresolved_count,
        "conflicting_dependencies": conflicts,
        "coverage": {
            "files_examined": state.files_examined,
            "archive_members_examined": state.members_examined,
            "manifest_candidates": state.candidate_count,
            "manifests_parsed": len(manifests),
            "manifest_bytes_read": state.total_manifest_bytes,
        },
        "inventory_complete": inventory_complete,
        "resolution_complete": resolution_complete,
        "assessment_status": status,
        "diagnostics": diagnostics[:_MAX_DIAGNOSTICS],
    }


def _validated_target(path, diagnostics):
    if not isinstance(path, (str, os.PathLike)):
        _diagnostic(diagnostics, "invalid_artifact_path", "CRITICAL", "Artifact path must be text or path-like.")
        return None
    try:
        target = Path(path)
        if target.is_symlink():
            _diagnostic(diagnostics, "symlink_artifact_rejected", "HIGH", "Top-level symlink artifacts are not scanned.")
            return None
        if not target.exists():
            _diagnostic(diagnostics, "artifact_not_found", "HIGH", "Artifact path does not exist.")
            return None
        return target
    except (OSError, ValueError, TypeError):
        _diagnostic(diagnostics, "invalid_artifact_path", "CRITICAL", "Artifact path could not be validated.")
        return None


def _collect_candidates(target, artifact_name, state, diagnostics):
    metadata = os.lstat(target)
    if stat.S_ISDIR(metadata.st_mode):
        state.artifact_type = "DIRECTORY"
        return _directory_candidates(target, metadata, state, diagnostics)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("unsupported artifact type")
    if _is_zip_archive(target, metadata):
        state.artifact_type = "ZIP"
        return _zip_candidates(target, metadata, state, diagnostics)
    if _is_tar_archive(target, metadata):
        state.artifact_type = "TAR"
        return _tar_candidates(target, metadata, state, diagnostics)
    state.artifact_type = "FILE"
    state.files_examined = 1
    logical_name = _safe_logical_path(artifact_name or target.name)
    if logical_name is None or not _is_manifest(logical_name):
        return []
    size = metadata.st_size
    state.candidate_count = 1
    if size > _MAX_MANIFEST_BYTES:
        state.inventory_complete = False
        _diagnostic(diagnostics, "manifest_too_large", "HIGH", "Manifest exceeds the per-file byte bound.")
        return []
    content = _read_regular_file(
        target, _MAX_MANIFEST_BYTES, expected_metadata=metadata
    )
    state.total_manifest_bytes = len(content)
    return [_Candidate(logical_name, content)]


def _directory_candidates(root, root_metadata, state, diagnostics):
    candidates = []
    stack: List[Tuple[Path, str, int, os.stat_result]] = [
        (root, "", 0, root_metadata)
    ]
    while stack:
        directory, relative, depth, expected_directory = stack.pop()
        if depth > _MAX_DIRECTORY_DEPTH:
            state.inventory_complete = False
            _diagnostic(diagnostics, "directory_depth_limit_reached", "HIGH", "Directory traversal reached the depth bound.")
            continue
        try:
            entries = _read_directory_entries(
                directory,
                expected_directory,
                _MAX_FILES - state.files_examined,
            )
        except _DirectoryEntryLimit:
            state.inventory_complete = False
            _diagnostic(diagnostics, "file_limit_reached", "HIGH", "Directory traversal reached the file bound.")
            return candidates
        except OSError:
            state.inventory_complete = False
            _diagnostic(diagnostics, "directory_unreadable", "HIGH", "A directory could not be enumerated safely.")
            continue
        for entry in entries:
            state.files_examined += 1
            if state.files_examined > _MAX_FILES:
                state.inventory_complete = False
                _diagnostic(diagnostics, "file_limit_reached", "HIGH", "Directory traversal reached the file bound.")
                return candidates
            logical = f"{relative}/{entry.name}" if relative else entry.name
            entry_path = directory / entry.name
            try:
                if stat.S_ISLNK(entry.metadata.st_mode):
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "symlink_entry_skipped", "HIGH", "A symlink entry was excluded, so dependency inventory coverage is partial.", {"path_sha256": _path_digest(logical)})
                    continue
                if stat.S_ISDIR(entry.metadata.st_mode):
                    stack.append(
                        (entry_path, logical, depth + 1, entry.metadata)
                    )
                    continue
                if not stat.S_ISREG(entry.metadata.st_mode) or not _is_manifest(logical):
                    continue
                state.candidate_count += 1
                if state.candidate_count > _MAX_MANIFESTS:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "manifest_limit_reached", "HIGH", "Manifest discovery reached the candidate bound.")
                    return candidates
                size = entry.metadata.st_size
                if size > _MAX_MANIFEST_BYTES:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "manifest_too_large", "HIGH", "A manifest exceeds the per-file byte bound.", {"path_sha256": _path_digest(logical)})
                    continue
                if state.total_manifest_bytes + size > _MAX_TOTAL_MANIFEST_BYTES:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "manifest_byte_limit_reached", "HIGH", "Manifest discovery reached the aggregate byte bound.")
                    return candidates
                content = _read_regular_file(
                    entry_path,
                    _MAX_MANIFEST_BYTES,
                    expected_metadata=entry.metadata,
                )
                state.total_manifest_bytes += len(content)
                candidates.append(_Candidate(_safe_logical_path(logical) or entry.name, content))
            except OSError:
                state.inventory_complete = False
                _diagnostic(diagnostics, "file_unreadable", "HIGH", "A candidate file could not be read safely.", {"path_sha256": _path_digest(logical)})
    return candidates


def _zip_candidates(target, target_metadata, state, diagnostics):
    candidates = []
    total_uncompressed = 0
    with _stable_regular_stream(target, target_metadata) as stream:
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                state.inventory_complete = False
                _diagnostic(diagnostics, "archive_member_limit_reached", "HIGH", "ZIP member count exceeds the analysis bound.")
            for member in members[:_MAX_ARCHIVE_MEMBERS]:
                state.members_examined += 1
                total_uncompressed += max(0, member.file_size)
                if total_uncompressed > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_size_limit_reached", "CRITICAL", "Declared ZIP expansion exceeds the analysis bound.")
                    break
                logical = _safe_logical_path(member.filename)
                if logical is None:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "unsafe_archive_member_path", "HIGH", "An unsafe ZIP member path was rejected.", {"path_sha256": _path_digest(member.filename)})
                    continue
                if stat.S_ISLNK(member.external_attr >> 16):
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_link_manifest_rejected", "HIGH", "ZIP links are not followed, so dependency inventory coverage is partial.", {"path_sha256": _path_digest(logical)})
                    continue
                if member.is_dir() or not _is_manifest(logical):
                    continue
                state.candidate_count += 1
                if not _candidate_allowed(member.file_size, state, diagnostics, logical):
                    continue
                if member.flag_bits & 0x1:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "encrypted_archive_manifest", "HIGH", "Encrypted dependency manifests cannot be assessed.", {"path_sha256": _path_digest(logical)})
                    continue
                ratio = member.file_size / max(1, member.compress_size)
                if ratio > _MAX_COMPRESSION_RATIO:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "suspicious_compression_ratio", "CRITICAL", "A manifest exceeds the safe compression-ratio bound.", {"path_sha256": _path_digest(logical)})
                    continue
                content = archive.read(member)
                if len(content) != member.file_size:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_member_size_mismatch", "CRITICAL", "A ZIP manifest did not match its declared byte size.", {"path_sha256": _path_digest(logical)})
                    continue
                state.total_manifest_bytes += len(content)
                candidates.append(_Candidate(logical, content))
    return candidates


def _tar_candidates(target, target_metadata, state, diagnostics):
    candidates = []
    total_uncompressed = 0
    with _stable_regular_stream(target, target_metadata) as file_stream:
        with tarfile.open(fileobj=file_stream, mode="r:*") as archive:
            for member in archive:
                state.members_examined += 1
                if state.members_examined > _MAX_ARCHIVE_MEMBERS:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_member_limit_reached", "HIGH", "TAR member count exceeds the analysis bound.")
                    break
                total_uncompressed += max(0, member.size)
                if total_uncompressed > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_size_limit_reached", "CRITICAL", "Declared TAR content exceeds the analysis bound.")
                    break
                logical = _safe_logical_path(member.name)
                if logical is None:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "unsafe_archive_member_path", "HIGH", "An unsafe TAR member path was rejected.", {"path_sha256": _path_digest(member.name)})
                    continue
                if member.issym() or member.islnk():
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_link_manifest_rejected", "HIGH", "TAR links are not followed, so dependency inventory coverage is partial.", {"path_sha256": _path_digest(logical)})
                    continue
                if not member.isfile() or not _is_manifest(logical):
                    continue
                state.candidate_count += 1
                if not _candidate_allowed(member.size, state, diagnostics, logical):
                    continue
                member_stream = archive.extractfile(member)
                if member_stream is None:
                    state.inventory_complete = False
                    continue
                content = member_stream.read(_MAX_MANIFEST_BYTES + 1)
                if len(content) > _MAX_MANIFEST_BYTES:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "manifest_too_large", "HIGH", "A TAR manifest exceeds the byte bound.", {"path_sha256": _path_digest(logical)})
                    continue
                if len(content) != member.size:
                    state.inventory_complete = False
                    _diagnostic(diagnostics, "archive_member_size_mismatch", "CRITICAL", "A TAR manifest did not match its declared byte size.", {"path_sha256": _path_digest(logical)})
                    continue
                state.total_manifest_bytes += len(content)
                candidates.append(_Candidate(logical, content))
    return candidates


def _candidate_allowed(size, state, diagnostics, logical):
    if state.candidate_count > _MAX_MANIFESTS:
        state.inventory_complete = False
        _diagnostic(diagnostics, "manifest_limit_reached", "HIGH", "Archive manifest count exceeds the analysis bound.")
        return False
    if size > _MAX_MANIFEST_BYTES:
        state.inventory_complete = False
        _diagnostic(diagnostics, "manifest_too_large", "HIGH", "An archive manifest exceeds the per-file byte bound.", {"path_sha256": _path_digest(logical)})
        return False
    if state.total_manifest_bytes + size > _MAX_TOTAL_MANIFEST_BYTES:
        state.inventory_complete = False
        _diagnostic(diagnostics, "manifest_byte_limit_reached", "HIGH", "Archive manifests exceed the aggregate byte bound.")
        return False
    return True


def _remove_ambiguous_candidates(candidates, state, diagnostics):
    grouped: Dict[str, List[_Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.path.casefold(), []).append(candidate)
    safe = []
    for values in grouped.values():
        if len(values) == 1:
            safe.append(values[0])
            continue
        state.inventory_complete = False
        _diagnostic(diagnostics, "ambiguous_duplicate_manifest", "HIGH", "Duplicate normalized manifest paths were excluded.", {"path_sha256": _path_digest(values[0].path), "duplicate_count": len(values)})
    return safe


def _parse_manifest(manifest_type, path, content, diagnostics):
    try:
        if manifest_type in {"requirements", "constraints"}:
            return _parse_requirements(path, content, diagnostics)
        if manifest_type == "pyproject":
            return _parse_pyproject(path, content, diagnostics)
        if manifest_type == "pipfile_lock":
            return _parse_pipfile_lock(path, content, diagnostics)
        if manifest_type == "poetry_lock":
            return _parse_poetry_lock(path, content, diagnostics)
        if manifest_type == "uv_lock":
            return _parse_uv_lock(path, content, diagnostics)
        if manifest_type == "package_json":
            return _parse_package_json(path, content, diagnostics)
        if manifest_type == "package_lock":
            return _parse_package_lock(path, content, diagnostics)
    except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, RecursionError, ValueError, TypeError):
        _diagnostic(diagnostics, "manifest_parse_failed", "HIGH", "A dependency manifest is malformed or structurally unsafe.", {"path_sha256": _path_digest(path), "manifest_type": manifest_type})
        return [], False
    return [], False


def _parse_requirements(path, content, diagnostics):
    text = content.decode("utf-8")
    lines = text.splitlines()
    complete = True
    if len(lines) > _MAX_LINES:
        lines = lines[:_MAX_LINES]
        complete = False
        _diagnostic(diagnostics, "manifest_line_limit_reached", "HIGH", "Requirements parsing reached the line bound.", {"path_sha256": _path_digest(path)})
    logical_lines = []
    pending = ""
    for raw in lines:
        stripped = raw.strip()
        pending = pending + stripped
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical_lines.append(pending.strip())
        pending = ""
    if pending:
        logical_lines.append(pending)
    dependencies = []
    for line in logical_lines:
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            _diagnostic(diagnostics, "requirements_include_observed", "INFO", "A requirements include was observed; matching manifests are scanned independently.", {"path_sha256": _path_digest(path)})
            continue
        if line.startswith(("-e ", "--editable ")):
            complete = False
            _diagnostic(diagnostics, "editable_requirement_unresolved", "MEDIUM", "Editable requirements cannot establish immutable package identity.", {"path_sha256": _path_digest(path)})
            continue
        line = _strip_inline_comment(line)
        hashes = sorted(set(match.group(1).lower() for match in _REQUIREMENT_HASH.finditer(line)))
        requirement_text = _REQUIREMENT_HASH.sub("", line).strip()
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            complete = False
            _diagnostic(diagnostics, "invalid_python_requirement", "MEDIUM", "A Python requirement could not be normalized.", {"path_sha256": _path_digest(path)})
            continue
        dependencies.append(_python_record(requirement, path, "runtime", hashes))
    return dependencies, complete


def _parse_pyproject(path, content, diagnostics):
    data = tomllib.loads(content.decode("utf-8"))
    _validate_structure(data)
    dependencies = []
    complete = True
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for raw in project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else []:
        record = _python_from_text(raw, path, "runtime", diagnostics)
        if record:
            dependencies.append(record)
        else:
            complete = False
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group, values in sorted(optional.items()):
            if not isinstance(values, list):
                complete = False
                continue
            for raw in values:
                record = _python_from_text(raw, path, f"optional:{_safe_scope(group)}", diagnostics)
                if record:
                    dependencies.append(record)
                else:
                    complete = False
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    poetry_dependencies = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if isinstance(poetry_dependencies, dict):
        for name, spec in sorted(poetry_dependencies.items()):
            if str(name).lower() == "python":
                continue
            record = _poetry_declaration(name, spec, path, "runtime")
            if record:
                dependencies.append(record)
            else:
                complete = False
    return dependencies, complete


def _parse_pipfile_lock(path, content, diagnostics):
    data = json.loads(content.decode("utf-8"))
    _validate_structure(data)
    dependencies = []
    complete = True
    for section, scope in (("default", "runtime"), ("develop", "development")):
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, details in sorted(values.items()):
            details = {"version": details} if isinstance(details, str) else details
            if not isinstance(details, dict):
                complete = False
                continue
            raw_version = details.get("version") or details.get("ref")
            hashes = _normalized_hashes(details.get("hashes"))
            record = _locked_python_record(name, raw_version, path, scope, hashes)
            if record:
                dependencies.append(record)
            elif details.get("git") or details.get("path"):
                direct_record = _declared_record(
                    "PyPI",
                    name,
                    raw_version,
                    path,
                    scope,
                    direct=True,
                    source={key: details.get(key) for key in ("git", "path", "ref") if key in details},
                )
                if direct_record:
                    dependencies.append(direct_record)
                else:
                    complete = False
            else:
                complete = False
    return dependencies, complete


def _parse_poetry_lock(path, content, diagnostics):
    data = tomllib.loads(content.decode("utf-8"))
    _validate_structure(data)
    packages = data.get("package")
    if not isinstance(packages, list):
        return [], False
    dependencies = []
    complete = True
    for package in packages:
        if not isinstance(package, dict):
            complete = False
            continue
        name = package.get("name")
        version = package.get("version")
        scope = "development" if package.get("category") == "dev" else "runtime"
        hashes = _normalized_hashes(
            [item.get("hash") for item in package.get("files", []) if isinstance(item, dict)]
            if isinstance(package.get("files"), list)
            else []
        )
        record = _locked_python_record(name, version, path, scope, hashes)
        if record:
            dependencies.append(record)
        else:
            complete = False
    return dependencies, complete


def _parse_uv_lock(path, content, diagnostics):
    data = tomllib.loads(content.decode("utf-8"))
    _validate_structure(data)
    packages = data.get("package")
    if not isinstance(packages, list):
        return [], False
    dependencies = []
    complete = True
    for package in packages:
        if not isinstance(package, dict):
            complete = False
            continue
        source = package.get("source") if isinstance(package.get("source"), dict) else {}
        direct = any(key in source for key in ("git", "url", "editable", "directory"))
        record = _locked_python_record(package.get("name"), package.get("version"), path, "runtime", [])
        if record and not direct:
            dependencies.append(record)
        elif package.get("name"):
            direct_record = _declared_record("PyPI", package.get("name"), package.get("version"), path, "runtime", direct=True, source=source)
            if direct_record:
                dependencies.append(direct_record)
            else:
                complete = False
        else:
            complete = False
    return dependencies, complete


def _parse_package_json(path, content, diagnostics):
    data = json.loads(content.decode("utf-8"))
    _validate_structure(data)
    dependencies = []
    complete = True
    sections = (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    )
    for section, scope in sections:
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, version in sorted(values.items()):
            record = _npm_record(name, version, path, scope, [])
            if record:
                dependencies.append(record)
            else:
                complete = False
    return dependencies, complete


def _parse_package_lock(path, content, diagnostics):
    data = json.loads(content.decode("utf-8"))
    _validate_structure(data)
    dependencies = []
    complete = True
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, details in sorted(packages.items()):
            if not package_path or not isinstance(details, dict):
                continue
            name = details.get("name") or _npm_name_from_lock_path(package_path)
            version = details.get("version")
            scope = "development" if details.get("dev") is True else ("optional" if details.get("optional") is True else "runtime")
            integrity = _safe_integrity(details.get("integrity"))
            record = _npm_record(name, version, path, scope, [integrity] if integrity else [])
            if record:
                dependencies.append(record)
            else:
                complete = False
    else:
        root_dependencies = data.get("dependencies")
        if not isinstance(root_dependencies, dict):
            return [], False
        parsed, nested_complete = _walk_npm_lock_v1(root_dependencies, path)
        dependencies.extend(parsed)
        complete = complete and nested_complete
    return dependencies, complete


def _walk_npm_lock_v1(root, path):
    output = []
    complete = True
    stack = list(root.items())
    examined = 0
    while stack:
        name, details = stack.pop()
        examined += 1
        if examined > _MAX_DEPENDENCIES:
            return output, False
        if not isinstance(details, dict):
            complete = False
            continue
        integrity = _safe_integrity(details.get("integrity"))
        scope = "development" if details.get("dev") is True else ("optional" if details.get("optional") is True else "runtime")
        record = _npm_record(name, details.get("version"), path, scope, [integrity] if integrity else [])
        if record:
            output.append(record)
        else:
            complete = False
        nested = details.get("dependencies")
        if isinstance(nested, dict):
            stack.extend(nested.items())
    return output, complete


def _python_from_text(value, path, scope, diagnostics):
    if not isinstance(value, str):
        return None
    try:
        return _python_record(Requirement(value), path, scope, [])
    except InvalidRequirement:
        _diagnostic(diagnostics, "invalid_python_requirement", "MEDIUM", "A Python dependency declaration could not be normalized.", {"path_sha256": _path_digest(path)})
        return None


def _python_record(requirement, path, scope, hashes):
    name = canonicalize_name(requirement.name)
    marker = _safe_text(str(requirement.marker)) if requirement.marker else None
    extras = sorted(canonicalize_name(item) for item in requirement.extras)
    if requirement.url:
        resolution = "DIRECT"
        version = None
        requirement_value = None
        direct_digest = _direct_reference_digest(requirement.url)
    else:
        version = _exact_python_version(requirement)
        resolution = "EXACT" if version else ("RANGE" if str(requirement.specifier) else "UNPINNED")
        requirement_value = str(requirement.specifier) or None
        direct_digest = None
    return _record("PyPI", name, version, requirement_value, marker, extras, scope, resolution, path, hashes, direct_digest)


def _locked_python_record(name, raw_version, path, scope, hashes):
    if not isinstance(name, str) or not isinstance(raw_version, str):
        return None
    version_text = raw_version.strip()
    if version_text.startswith("=="):
        version_text = version_text[2:]
    try:
        version = str(Version(version_text))
    except InvalidVersion:
        return None
    return _record("PyPI", canonicalize_name(name), version, f"=={version}", None, [], scope, "EXACT", path, hashes, None)


def _poetry_declaration(name, spec, path, scope):
    if not isinstance(name, str):
        return None
    if isinstance(spec, str):
        direct = spec.startswith(("git+", "http://", "https://", "file:"))
        return _declared_record("PyPI", name, spec, path, scope, direct=direct)
    if not isinstance(spec, dict):
        return None
    direct = any(key in spec for key in ("git", "url", "path"))
    source = {key: spec.get(key) for key in ("git", "url", "path") if key in spec}
    return _declared_record("PyPI", name, spec.get("version"), path, scope, direct=direct, source=source)


def _declared_record(ecosystem, name, spec, path, scope, *, direct=False, source=None):
    safe_name = canonicalize_name(name) if ecosystem == "PyPI" and isinstance(name, str) else _safe_npm_name(name)
    if not safe_name:
        return None
    spec_text = _safe_text(spec) if isinstance(spec, str) else None
    if direct:
        source_digest = _direct_reference_digest(
            source if source is not None else spec_text
        )
        return _record(ecosystem, safe_name, None, None, None, [], scope, "DIRECT", path, [], source_digest)
    if ecosystem == "PyPI" and spec_text:
        candidate = _locked_python_record(safe_name, spec_text, path, scope, [])
        if candidate:
            return candidate
    return _record(ecosystem, safe_name, None, spec_text, None, [], scope, "RANGE" if spec_text and spec_text not in {"*", "latest"} else "UNPINNED", path, [], None)


def _npm_record(name, raw_version, path, scope, hashes):
    safe_name = _safe_npm_name(name)
    if not safe_name or not isinstance(raw_version, str):
        return None
    spec = raw_version.strip()
    version = _exact_npm_version(spec)
    if version:
        resolution = "EXACT"
        requirement = version
        direct_digest = None
    elif spec.startswith(("git+", "http://", "https://", "file:", "github:")):
        version = None
        resolution = "DIRECT"
        requirement = None
        direct_digest = _direct_reference_digest(spec)
    else:
        version = None
        resolution = "UNPINNED" if spec in {"", "*", "latest"} else "RANGE"
        requirement = _safe_text(spec)
        direct_digest = None
    return _record("npm", safe_name, version, requirement, None, [], scope, resolution, path, hashes, direct_digest)


def _record(ecosystem, name, version, requirement, marker, extras, scope, resolution, path, hashes, direct_digest):
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "requirement": requirement,
        "marker": marker,
        "extras": extras,
        "scopes": [_safe_scope(scope)],
        "resolution": resolution,
        "source_manifests": [path],
        "hashes": sorted(set(item for item in hashes if item)),
        "direct_reference_sha256": direct_digest,
    }


def _deduplicate(dependencies):
    merged = {}
    for item in dependencies:
        identity = (
            item["ecosystem"],
            item["name"],
            item["version"],
            item["requirement"],
            item["marker"],
            tuple(item["extras"]),
            item["resolution"],
            item["direct_reference_sha256"],
        )
        if identity not in merged:
            merged[identity] = item
            continue
        existing = merged[identity]
        existing["scopes"] = sorted(set(existing["scopes"] + item["scopes"]))
        existing["source_manifests"] = sorted(set(existing["source_manifests"] + item["source_manifests"]))
        existing["hashes"] = sorted(set(existing["hashes"] + item["hashes"]))
    return sorted(
        merged.values(),
        key=lambda item: (
            item["ecosystem"],
            item["name"],
            item["version"] or "",
            item["requirement"] or "",
            item["marker"] or "",
        ),
    )


def _conflicts(dependencies):
    versions: Dict[Tuple[str, str], set] = {}
    for item in dependencies:
        if item["resolution"] == "EXACT":
            versions.setdefault((item["ecosystem"], item["name"]), set()).add(item["version"])
    return [
        {"ecosystem": ecosystem, "name": name, "versions": sorted(found)}
        for (ecosystem, name), found in sorted(versions.items())
        if len(found) > 1
    ]


def _exact_python_version(requirement):
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="} or "*" in specifiers[0].version:
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


def _normalized_hashes(value):
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        if not isinstance(item, str):
            continue
        lowered = item.lower()
        if lowered.startswith("sha256:") and _SHA256.fullmatch(lowered[7:]):
            output.append(lowered)
    return sorted(set(output))


def _safe_integrity(value):
    text = _safe_text(value)
    if text and re.fullmatch(r"sha(?:256|384|512)-[A-Za-z0-9+/=]+", text):
        return text
    return None


def _validate_structure(value):
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("structured manifest exceeds bounds")
        if isinstance(current, dict):
            stack.extend((key, depth + 1) for key in current.keys())
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _is_manifest(path):
    return _manifest_type(path) != "unknown"


def _manifest_type(path):
    basename = PurePosixPath(path).name.lower()
    if fnmatch.fnmatch(basename, "requirements*.txt"):
        return "requirements"
    if fnmatch.fnmatch(basename, "constraints*.txt"):
        return "constraints"
    return {
        "pyproject.toml": "pyproject",
        "pipfile.lock": "pipfile_lock",
        "poetry.lock": "poetry_lock",
        "uv.lock": "uv_lock",
        "package.json": "package_json",
        "package-lock.json": "package_lock",
        "npm-shrinkwrap.json": "package_lock",
    }.get(basename, "unknown")


def _safe_logical_path(value):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    value = unicodedata.normalize("NFC", value)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and path.parts[0].endswith(":"))
    ):
        return None
    text = path.as_posix()
    return text if len(text.encode("utf-8")) <= _MAX_TEXT else None


def _npm_name_from_lock_path(path):
    parts = PurePosixPath(path).parts
    indexes = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not indexes:
        return None
    tail = parts[indexes[-1] + 1 :]
    if not tail:
        return None
    if tail[0].startswith("@") and len(tail) >= 2:
        return f"{tail[0]}/{tail[1]}"
    return tail[0]


def _safe_npm_name(value):
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if _NPM_NAME.fullmatch(candidate) else None


def _exact_npm_version(value):
    match = _NPM_EXACT.fullmatch(value)
    if not match:
        return None
    for release_part in match.groups()[:3]:
        if len(release_part) > 1 and release_part.startswith("0"):
            return None
    return value.lstrip("v=")


def _direct_reference_digest(value):
    redacted = _redact_reference_value(value)
    return hashlib.sha256(_canonical_bytes(redacted)).hexdigest()


def _redact_reference_value(value):
    if isinstance(value, dict):
        return {
            str(key): _redact_reference_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_redact_reference_value(item) for item in value]
    if not isinstance(value, str):
        return value
    text = value.strip()
    candidate = text[4:] if text.startswith("git+") else text
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname
            if parsed.port:
                host += f":{parsed.port}"
            sanitized = urlunsplit((parsed.scheme, host, parsed.path, "", ""))
            return "git+" + sanitized if text.startswith("git+") else sanitized
    except ValueError:
        pass
    text = re.sub(r"(://)[^/@]+@", r"\1", text)
    return text.split("#", 1)[0].split("?", 1)[0]


def _is_zip_archive(path, expected_metadata):
    with _stable_regular_stream(path, expected_metadata) as stream:
        return zipfile.is_zipfile(stream)


def _is_tar_archive(path, expected_metadata):
    with _stable_regular_stream(path, expected_metadata) as stream:
        try:
            with tarfile.open(fileobj=stream, mode="r:*"):
                return True
        except tarfile.TarError:
            return False


@contextmanager
def _stable_regular_stream(path, expected_metadata):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    stream = None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_snapshot(expected_metadata, opened)
        ):
            raise OSError("archive changed before open")
        stream = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        yield stream
        after = os.fstat(stream.fileno())
        current = os.lstat(path)
        if (
            not _same_snapshot(opened, after)
            or not _same_snapshot(opened, current)
        ):
            raise OSError("archive changed during scan")
    finally:
        if stream is not None:
            stream.close()
        elif descriptor >= 0:
            os.close(descriptor)


def _read_directory_entries(path, expected_metadata, max_entries):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not _same_snapshot(expected_metadata, opened)
        ):
            raise OSError("directory changed before enumeration")
        with os.scandir(descriptor) as iterator:
            entries = []
            for entry in iterator:
                if len(entries) >= max_entries:
                    raise _DirectoryEntryLimit
                entries.append(_DirectoryEntry(
                    name=entry.name,
                    metadata=entry.stat(follow_symlinks=False),
                ))
        return sorted(
            entries,
            key=lambda entry: unicodedata.normalize("NFC", entry.name),
        )
    finally:
        os.close(descriptor)


def _read_regular_file(path, limit, expected_metadata=None):
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or (
            expected_metadata is not None
            and not _same_snapshot(expected_metadata, before)
        )
    ):
        raise OSError("candidate is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise OSError("candidate changed during validation")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > limit:
            raise OSError("candidate exceeds read bound")
        after = os.fstat(descriptor)
        if not _same_snapshot(opened, after) or len(content) != after.st_size:
            raise OSError("candidate changed during read")
        return content
    finally:
        os.close(descriptor)


def _same_snapshot(left, right):
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _safe_scope(value):
    text = _safe_text(str(value)) or "unknown"
    return text[:128]


def _safe_text(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value.encode("utf-8")) > _MAX_TEXT or any(ord(char) < 32 for char in value):
        return None
    return value


def _strip_inline_comment(value):
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def _path_digest(value):
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _diagnostic(diagnostics, indicator, severity, detail, evidence=None):
    if len(diagnostics) >= _MAX_DIAGNOSTICS:
        return
    item = {"indicator": indicator, "severity": severity, "detail": detail}
    if evidence:
        item["evidence"] = evidence
    diagnostics.append(item)


class _DirectoryEntryLimit(Exception):
    pass

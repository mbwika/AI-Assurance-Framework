"""Bounded dependency discovery for model directories and archives."""

import fnmatch
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Tuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000


def discover_dependencies(path: str, artifact_name: str = "") -> Dict[str, Any]:
    """Discover dependencies without extracting untrusted archives."""
    dependencies: List[Dict[str, Any]] = []
    manifests = []
    errors = []
    try:
        for manifest_name, content in _manifest_contents(Path(path), artifact_name):
            try:
                parsed = _parse_manifest(manifest_name, content)
                dependencies.extend(parsed)
                manifests.append(manifest_name)
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                errors.append({"manifest": manifest_name, "error": str(exc)})
    except (OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        errors.append({"manifest": artifact_name or Path(path).name, "error": str(exc)})

    deduplicated = []
    seen = set()
    for dependency in dependencies:
        identity = (
            dependency.get("ecosystem"),
            dependency.get("name", "").lower(),
            dependency.get("version"),
            dependency.get("source"),
        )
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(dependency)

    return {
        "dependencies": deduplicated,
        "manifests": sorted(set(manifests)),
        "dependency_count": len(deduplicated),
        "errors": errors,
    }


def merge_dependencies(declared: Any, discovered: List[Dict[str, Any]]) -> List[Any]:
    """Combine declared and discovered inventory without duplicate records."""
    declared_items = declared if isinstance(declared, list) else ([declared] if declared else [])
    combined = list(declared_items)
    known = {_dependency_identity(item) for item in declared_items}
    known_coordinates = {_dependency_coordinates(item) for item in declared_items}
    for dependency in discovered:
        identity = _dependency_identity(dependency)
        coordinates = _dependency_coordinates(dependency)
        if identity not in known and coordinates not in known_coordinates:
            combined.append(dependency)
            known.add(identity)
            known_coordinates.add(coordinates)
    return combined


def _manifest_contents(path: Path, artifact_name: str = "") -> Iterable[Tuple[str, bytes]]:
    if path.is_dir():
        for candidate in path.rglob("*"):
            if candidate.is_file() and _is_manifest(candidate.name):
                try:
                    if candidate.stat().st_size <= MAX_MANIFEST_BYTES:
                        yield _normalize_manifest_name(candidate.relative_to(path).as_posix()), candidate.read_bytes()
                except OSError:
                    continue
        return

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for index, member in enumerate(archive.infolist()):
                if index >= MAX_ARCHIVE_MEMBERS:
                    break
                name = PurePosixPath(member.filename).name
                if not member.is_dir() and _is_manifest(name) and member.file_size <= MAX_MANIFEST_BYTES:
                    yield _normalize_manifest_name(member.filename), archive.read(member)
        return

    if tarfile.is_tarfile(path):
        with tarfile.open(path, mode="r:*") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_ARCHIVE_MEMBERS:
                    break
                name = PurePosixPath(member.name).name
                if member.isfile() and _is_manifest(name) and member.size <= MAX_MANIFEST_BYTES:
                    extracted = archive.extractfile(member)
                    if extracted:
                        yield _normalize_manifest_name(member.name), extracted.read(MAX_MANIFEST_BYTES + 1)
        return

    logical_name = artifact_name or path.name
    if path.is_file() and _is_manifest(logical_name) and path.stat().st_size <= MAX_MANIFEST_BYTES:
        yield logical_name, path.read_bytes()


def _is_manifest(name: str) -> bool:
    lowered = name.lower()
    return (
        fnmatch.fnmatch(lowered, "requirements*.txt")
        or fnmatch.fnmatch(lowered, "constraints*.txt")
        or lowered in {"pyproject.toml", "pipfile.lock", "package.json"}
    )


def _parse_manifest(name: str, content: bytes) -> List[Dict[str, Any]]:
    basename = PurePosixPath(name).name.lower()
    text = content.decode("utf-8")
    if fnmatch.fnmatch(basename, "requirements*.txt") or fnmatch.fnmatch(
        basename, "constraints*.txt"
    ):
        return _parse_requirements(name, text)
    if basename == "pyproject.toml":
        return _parse_pyproject(name, content)
    if basename == "pipfile.lock":
        return _parse_pipfile_lock(name, text)
    if basename == "package.json":
        return _parse_package_json(name, text)
    return []


def _parse_requirements(name: str, text: str) -> List[Dict[str, Any]]:
    dependencies = []
    for line in text.splitlines():
        requirement = line.strip()
        if not requirement or requirement.startswith(("#", "-r", "--requirement")):
            continue
        requirement = requirement.split(" #", 1)[0].strip()
        dependencies.append(_python_requirement(requirement, name))
    return dependencies


def _parse_pyproject(name: str, content: bytes) -> List[Dict[str, Any]]:
    data = tomllib.loads(content.decode("utf-8"))
    dependencies = []
    project = data.get("project", {})
    for requirement in project.get("dependencies", []):
        dependencies.append(_python_requirement(str(requirement), name))
    for group in project.get("optional-dependencies", {}).values():
        for requirement in group:
            dependencies.append(_python_requirement(str(requirement), name))

    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for package, spec in poetry.items():
        if package.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else spec.get("version", "")
        dependencies.append(_record(package, str(version), "pypi", name))
    return dependencies


def _parse_pipfile_lock(name: str, text: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    dependencies = []
    for section in ("default", "develop"):
        for package, details in data.get(section, {}).items():
            if isinstance(details, str):
                version = details
                hashes = []
            else:
                version = details.get("version") or details.get("ref") or ""
                hashes = details.get("hashes", [])
            record = _record(package, version, "pypi", name)
            if hashes:
                record["hashes"] = hashes
            dependencies.append(record)
    return dependencies


def _parse_package_json(name: str, text: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    dependencies = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for package, version in data.get(section, {}).items():
            record = _record(package, str(version), "npm", name)
            record["scope"] = section
            dependencies.append(record)
    return dependencies


def _python_requirement(requirement: str, manifest: str) -> Dict[str, Any]:
    if " @ " in requirement:
        package, source = requirement.split(" @ ", 1)
        record = _record(package.strip(), source.strip(), "pypi", manifest)
        record["source"] = source.strip()
        return record
    for marker in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if marker in requirement:
            package, version = requirement.split(marker, 1)
            return _record(package.split("[", 1)[0].strip(), marker + version.strip(), "pypi", manifest)
    return _record(requirement.split("[", 1)[0].strip(), "", "pypi", manifest)


def _record(name: str, version: str, ecosystem: str, manifest: str) -> Dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "source_manifest": manifest,
    }


def _dependency_identity(dependency: Any):
    if isinstance(dependency, dict):
        return (
            dependency.get("ecosystem"),
            str(dependency.get("name", "")).lower(),
            dependency.get("version"),
            dependency.get("source"),
        )
    return ("declared", str(dependency).lower(), None, None)


def _dependency_coordinates(dependency: Any):
    if isinstance(dependency, dict):
        return (
            str(dependency.get("name", "")).lower(),
            str(dependency.get("version") or dependency.get("source") or ""),
        )
    value = str(dependency).strip()
    if " @ " in value:
        name, version = value.split(" @ ", 1)
        return (name.strip().lower(), version.strip())
    for marker in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if marker in value:
            name, version = value.split(marker, 1)
            return (name.split("[", 1)[0].strip().lower(), marker + version.strip())
    return (value.split("[", 1)[0].lower(), "")


def _normalize_manifest_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name

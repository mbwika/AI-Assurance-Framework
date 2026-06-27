import io
import json
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.registry.dependency_discovery_v2 as discovery_module  # noqa: E402
from aiaf.registry.dependency_discovery_v2 import (  # noqa: E402
    DEPENDENCY_DISCOVERY_SCORING_VERSION,
    discover_dependencies_v2,
)


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _by_name(result):
    return {item["name"]: item for item in result["dependencies"]}


def test_requirements_are_structurally_normalized_with_resolution_state(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "My_Package[security]==01.2.0; python_version >= '3.10'\n"
        "torch>=2.3\n"
        "requests\n",
    )

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert result["scoring_version"] == DEPENDENCY_DISCOVERY_SCORING_VERSION == "2.0"
    assert dependencies["my-package"]["version"] == "1.2.0"
    assert dependencies["my-package"]["extras"] == ["security"]
    assert dependencies["my-package"]["marker"] == 'python_version >= "3.10"'
    assert dependencies["torch"]["resolution"] == "RANGE"
    assert dependencies["requests"]["resolution"] == "UNPINNED"
    assert result["inventory_complete"] is True
    assert result["resolution_complete"] is False
    assert result["assessment_status"] == "PARTIAL"


def test_hash_pinned_continuation_is_retained(tmp_path):
    requirement = "requests==2.32.0 " + "\\" + "\n  --hash=sha256:" + "a" * 64 + "\n"
    _write(
        tmp_path / "requirements.txt",
        requirement,
    )

    result = discover_dependencies_v2(tmp_path)

    assert result["dependencies"][0]["hashes"] == ["sha256:" + "a" * 64]
    assert result["resolution_complete"] is True


def test_direct_reference_is_digest_only_and_never_echoes_credentials(tmp_path):
    secret = "super-secret-token"
    _write(
        tmp_path / "requirements.txt",
        f"private-runtime @ https://user:{secret}@packages.example.test/runtime.whl\n",
    )

    result = discover_dependencies_v2(tmp_path)
    serialized = json.dumps(result)
    dependency = result["dependencies"][0]

    assert secret not in serialized
    assert "packages.example.test" not in serialized
    assert dependency["resolution"] == "DIRECT"
    assert len(dependency["direct_reference_sha256"]) == 64
    assert result["inventory_complete"] is True
    assert result["resolution_complete"] is False


def test_direct_reference_digest_excludes_credentials_and_query_tokens(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write(
        first / "requirements.txt",
        "private @ https://user:secret-one@example.test/runtime.whl?token=one\n",
    )
    _write(
        second / "requirements.txt",
        "private @ https://robot:secret-two@example.test/runtime.whl?token=two\n",
    )

    left = discover_dependencies_v2(first)["dependencies"][0]
    right = discover_dependencies_v2(second)["dependencies"][0]

    assert left["direct_reference_sha256"] == right["direct_reference_sha256"]


def test_requirements_include_is_reported_without_following_arbitrary_path(tmp_path):
    _write(tmp_path / "requirements.txt", "-r ../outside.txt\nrequests==2.32.0\n")

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 1
    assert any(item["indicator"] == "requirements_include_observed" for item in result["diagnostics"])
    assert "outside.txt" not in json.dumps(result)


def test_pyproject_pep621_optional_and_poetry_declarations(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
dependencies = ["httpx==0.27.0"]
[project.optional-dependencies]
test = ["pytest>=8"]
[tool.poetry.dependencies]
python = ">=3.10"
requests = "^2.32"
""",
    )

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert dependencies["httpx"]["resolution"] == "EXACT"
    assert dependencies["pytest"]["scopes"] == ["optional:test"]
    assert dependencies["requests"]["resolution"] == "RANGE"


def test_pipfile_lock_resolves_versions_and_sha256_hashes(tmp_path):
    payload = {
        "default": {
            "Requests": {"version": "==2.32.0", "hashes": ["sha256:" + "b" * 64]}
        },
        "develop": {"pytest": {"version": "==8.2.0"}},
    }
    _write(tmp_path / "Pipfile.lock", json.dumps(payload))

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert dependencies["requests"]["version"] == "2.32.0"
    assert dependencies["requests"]["hashes"] == ["sha256:" + "b" * 64]
    assert dependencies["pytest"]["scopes"] == ["development"]
    assert result["resolution_complete"] is True


def test_poetry_lock_resolves_package_inventory(tmp_path):
    _write(
        tmp_path / "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.32.0"
category = "main"
files = [{file = "requests.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]
[[package]]
name = "pytest"
version = "8.2.0"
category = "dev"
files = []
""",
    )

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 2
    assert _by_name(result)["pytest"]["scopes"] == ["development"]
    assert result["resolution_complete"] is True


def test_uv_lock_distinguishes_registry_and_direct_packages(tmp_path):
    _write(
        tmp_path / "uv.lock",
        """
version = 1
[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "private-runtime"
version = "1.0.0"
source = { git = "https://token:secret@example.test/repo.git" }
""",
    )

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert dependencies["requests"]["resolution"] == "EXACT"
    assert dependencies["private-runtime"]["resolution"] == "DIRECT"
    assert "secret" not in json.dumps(result)
    assert result["inventory_complete"] is True
    assert result["resolution_complete"] is False


def test_package_json_records_ranges_scopes_and_direct_digest(tmp_path):
    payload = {
        "dependencies": {"lodash": "^4.17.0"},
        "devDependencies": {"vitest": "1.6.0"},
        "optionalDependencies": {"private": "git+https://token:secret@example.test/repo"},
    }
    _write(tmp_path / "package.json", json.dumps(payload))

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert dependencies["lodash"]["resolution"] == "RANGE"
    assert dependencies["vitest"]["resolution"] == "EXACT"
    assert dependencies["vitest"]["scopes"] == ["development"]
    assert dependencies["private"]["resolution"] == "DIRECT"
    assert "secret" not in json.dumps(result)


def test_package_lock_v2_derives_scoped_names_and_integrity(tmp_path):
    payload = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21", "integrity": "sha512-YWJjZA=="},
            "node_modules/@acme/runtime": {"version": "2.3.1", "dev": True},
        },
    }
    _write(tmp_path / "package-lock.json", json.dumps(payload))

    result = discover_dependencies_v2(tmp_path)
    dependencies = _by_name(result)

    assert dependencies["lodash"]["hashes"] == ["sha512-YWJjZA=="]
    assert dependencies["@acme/runtime"]["version"] == "2.3.1"
    assert dependencies["@acme/runtime"]["scopes"] == ["development"]
    assert result["resolution_complete"] is True


def test_package_lock_v1_walks_nested_dependencies(tmp_path):
    payload = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {
                "version": "1.0.0",
                "dependencies": {"b": {"version": "2.0.0"}},
            }
        },
    }
    _write(tmp_path / "npm-shrinkwrap.json", json.dumps(payload))

    result = discover_dependencies_v2(tmp_path)

    assert {(item["name"], item["version"]) for item in result["dependencies"]} == {
        ("a", "1.0.0"),
        ("b", "2.0.0"),
    }


def test_duplicate_coordinates_merge_manifest_and_scope_evidence(tmp_path):
    _write(tmp_path / "requirements.txt", "requests==2.32.0\n")
    _write(
        tmp_path / "pyproject.toml",
        '[project.optional-dependencies]\ntest = ["requests==2.32.0"]\n',
    )

    result = discover_dependencies_v2(tmp_path)
    dependency = result["dependencies"][0]

    assert result["dependency_count"] == 1
    assert dependency["source_manifests"] == ["pyproject.toml", "requirements.txt"]
    assert dependency["scopes"] == ["optional:test", "runtime"]


def test_conflicting_exact_versions_are_explicit(tmp_path):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path / "requirements-prod.txt", "requests==2.32.0\n")

    result = discover_dependencies_v2(tmp_path)

    assert result["conflicting_dependencies"] == [
        {"ecosystem": "PyPI", "name": "requests", "versions": ["2.31.0", "2.32.0"]}
    ]
    assert result["resolution_complete"] is False


def test_malformed_manifest_fails_without_echoing_content(tmp_path):
    secret = "do-not-echo-this-secret"
    _write(tmp_path / "package-lock.json", '{"secret":"' + secret + '", broken')

    result = discover_dependencies_v2(tmp_path)

    assert result["inventory_complete"] is False
    assert result["manifests"][0]["parse_status"] == "PARTIAL"
    assert secret not in json.dumps(result)
    assert any(item["indicator"] == "manifest_parse_failed" for item in result["diagnostics"])


def test_structural_depth_limit_rejects_nested_json(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_JSON_DEPTH", 3)
    payload = {"dependencies": {"a": {"dependencies": {"b": {"version": "1.0.0"}}}}}
    _write(tmp_path / "package-lock.json", json.dumps(payload))

    result = discover_dependencies_v2(tmp_path)

    assert result["inventory_complete"] is False
    assert result["dependency_count"] == 0


def test_requirements_line_limit_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_LINES", 2)
    _write(tmp_path / "requirements.txt", "a==1.0\nb==1.0\nc==1.0\n")

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 2
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "manifest_line_limit_reached" for item in result["diagnostics"])


def test_directory_file_limit_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_FILES", 1)
    _write(tmp_path / "a.txt", "irrelevant")
    _write(tmp_path / "requirements.txt", "a==1.0")

    result = discover_dependencies_v2(tmp_path)

    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "file_limit_reached" for item in result["diagnostics"])


def test_directory_depth_limit_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_DIRECTORY_DEPTH", 1)
    _write(tmp_path / "one" / "two" / "requirements.txt", "a==1.0")

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "directory_depth_limit_reached" for item in result["diagnostics"])


def test_directory_symlink_is_skipped_without_following(tmp_path):
    outside = _write(tmp_path.parent / f"{tmp_path.name}-outside.txt", "secret-package==9.9.9")
    link = tmp_path / "requirements.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert result["assessment_status"] == "PARTIAL"
    assert any(item["indicator"] == "symlink_entry_skipped" for item in result["diagnostics"])


def test_nonmanifest_archive_link_still_makes_inventory_partial(tmp_path):
    archive_path = tmp_path / "model.tar"
    with tarfile.open(archive_path, "w") as archive:
        link = tarfile.TarInfo("vendor")
        link.type = tarfile.SYMTYPE
        link.linkname = "external-dependencies"
        archive.addfile(link)

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert result["assessment_status"] == "PARTIAL"
    assert any(
        item["indicator"] == "archive_link_manifest_rejected"
        for item in result["diagnostics"]
    )


def test_queued_directory_symlink_swap_cannot_escape_artifact(monkeypatch, tmp_path):
    queued = tmp_path / "queued"
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    queued.mkdir()
    outside.mkdir()
    _write(queued / "requirements.txt", "inside==1.0")
    _write(outside / "requirements.txt", "outside-secret==9.9.9")

    real_reader = discovery_module._read_directory_entries
    swapped = False

    def swap_before_queued_open(path, expected_metadata, max_entries):
        nonlocal swapped
        if Path(path) == queued and not swapped:
            swapped = True
            (queued / "requirements.txt").unlink()
            queued.rmdir()
            queued.symlink_to(outside, target_is_directory=True)
        return real_reader(path, expected_metadata, max_entries)

    monkeypatch.setattr(
        discovery_module, "_read_directory_entries", swap_before_queued_open
    )
    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert "outside-secret" not in json.dumps(result)
    assert any(
        item["indicator"] == "directory_unreadable"
        for item in result["diagnostics"]
    )


def test_manifest_mutation_during_read_is_rejected(monkeypatch, tmp_path):
    manifest = _write(tmp_path / "requirements.txt", "before==1.0")
    real_read = discovery_module.os.read
    mutated = False

    def mutate_after_first_read(descriptor, size):
        nonlocal mutated
        chunk = real_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            manifest.write_text("after-and-longer==2.0", encoding="utf-8")
        return chunk

    monkeypatch.setattr(discovery_module.os, "read", mutate_after_first_read)
    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert result["assessment_status"] == "PARTIAL"
    assert any(
        item["indicator"] == "file_unreadable"
        for item in result["diagnostics"]
    )


def test_special_top_level_artifact_is_rejected_without_opening(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are not supported")
    fifo = tmp_path / "artifact.pipe"
    try:
        os.mkfifo(fifo)
    except OSError:
        pytest.skip("FIFOs are not supported by this filesystem")

    result = discover_dependencies_v2(fifo)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert result["assessment_status"] == "PARTIAL"
    assert any(
        item["indicator"] == "artifact_scan_failed"
        for item in result["diagnostics"]
    )


def test_oversized_manifest_is_not_partially_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_MANIFEST_BYTES", 8)
    _write(tmp_path / "requirements.txt", "requests==2.32.0")

    result = discover_dependencies_v2(tmp_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "manifest_too_large" for item in result["diagnostics"])


def test_zip_traversal_member_is_rejected_without_extraction(tmp_path):
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../requirements.txt", "evil==1.0")
        archive.writestr("safe/requirements.txt", "safe==1.0")

    result = discover_dependencies_v2(archive_path)

    assert [item["name"] for item in result["dependencies"]] == ["safe"]
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "unsafe_archive_member_path" for item in result["diagnostics"])


def test_duplicate_zip_manifest_paths_are_all_excluded(tmp_path):
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("requirements.txt", "first==1.0")
        with pytest.warns(UserWarning):
            archive.writestr("requirements.txt", "second==2.0")

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "ambiguous_duplicate_manifest" for item in result["diagnostics"])


def test_zip_symlink_manifest_is_rejected(tmp_path):
    archive_path = tmp_path / "model.zip"
    link = zipfile.ZipInfo("requirements.txt")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(link, "../outside.txt")

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "archive_link_manifest_rejected" for item in result["diagnostics"])


def test_windows_drive_archive_path_is_rejected(tmp_path):
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("C:/requirements.txt", "evil==1.0")

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert any(item["indicator"] == "unsafe_archive_member_path" for item in result["diagnostics"])


def test_zip_compression_ratio_limit_rejects_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_COMPRESSION_RATIO", 2)
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("requirements.txt", ("a==1.0\n" * 1000))

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert any(item["indicator"] == "suspicious_compression_ratio" for item in result["diagnostics"])


def test_zip_replacement_between_detection_and_scan_is_rejected(
    monkeypatch, tmp_path
):
    archive_path = tmp_path / "model.zip"
    replacement = tmp_path / "replacement.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("requirements.txt", "trusted==1.0")
    with zipfile.ZipFile(replacement, "w") as archive:
        archive.writestr("requirements.txt", "substituted==9.9.9")

    real_scanner = discovery_module._zip_candidates
    replaced = False

    def replace_before_scan(target, target_metadata, state, diagnostics):
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, target)
        return real_scanner(target, target_metadata, state, diagnostics)

    monkeypatch.setattr(discovery_module, "_zip_candidates", replace_before_scan)
    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert result["assessment_status"] == "PARTIAL"
    assert "substituted" not in json.dumps(result)
    assert any(
        item["indicator"] == "artifact_scan_failed"
        for item in result["diagnostics"]
    )


def test_archive_member_limit_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery_module, "_MAX_ARCHIVE_MEMBERS", 1)
    archive_path = tmp_path / "model.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("metadata.txt", "none")
        archive.writestr("requirements.txt", "a==1.0")

    result = discover_dependencies_v2(archive_path)

    assert result["dependency_count"] == 0
    assert result["inventory_complete"] is False
    assert any(item["indicator"] == "archive_member_limit_reached" for item in result["diagnostics"])


def test_tar_traversal_and_link_manifests_are_rejected(tmp_path):
    archive_path = tmp_path / "model.tar"
    with tarfile.open(archive_path, "w") as archive:
        unsafe = b"evil==1.0"
        unsafe_info = tarfile.TarInfo("../requirements.txt")
        unsafe_info.size = len(unsafe)
        archive.addfile(unsafe_info, io.BytesIO(unsafe))
        link_info = tarfile.TarInfo("linked/requirements.txt")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "../outside.txt"
        archive.addfile(link_info)
        safe = b"safe==1.0"
        safe_info = tarfile.TarInfo("safe/requirements.txt")
        safe_info.size = len(safe)
        archive.addfile(safe_info, io.BytesIO(safe))

    result = discover_dependencies_v2(archive_path)

    assert [item["name"] for item in result["dependencies"]] == ["safe"]
    indicators = {item["indicator"] for item in result["diagnostics"]}
    assert "unsafe_archive_member_path" in indicators
    assert "archive_link_manifest_rejected" in indicators


def test_output_is_deterministic_across_creation_order(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write(first / "requirements-b.txt", "b==2.0")
    _write(first / "requirements-a.txt", "a==1.0")
    _write(second / "requirements-a.txt", "a==1.0")
    _write(second / "requirements-b.txt", "b==2.0")

    left = discover_dependencies_v2(first)
    right = discover_dependencies_v2(second)

    assert left == right


def test_no_manifests_is_distinct_from_failed_scan(tmp_path):
    _write(tmp_path / "model.bin", "not a manifest")

    result = discover_dependencies_v2(tmp_path)

    assert result["assessment_status"] == "NO_MANIFESTS"
    assert result["inventory_complete"] is True
    assert result["resolution_complete"] is False


def test_invalid_and_symlink_targets_fail_closed(tmp_path):
    missing = discover_dependencies_v2(tmp_path / "missing")
    assert missing["assessment_status"] == "INVALID_TARGET"
    assert missing["inventory_complete"] is False

    real = _write(tmp_path / "requirements-real.txt", "a==1.0")
    link = tmp_path / "requirements.txt"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")
    linked = discover_dependencies_v2(link)
    assert linked["assessment_status"] == "INVALID_TARGET"
    assert any(item["indicator"] == "symlink_artifact_rejected" for item in linked["diagnostics"])

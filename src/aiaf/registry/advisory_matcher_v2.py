"""Deterministic, bounded dependency-to-advisory matching.

This module consumes exact dependency coordinates and normalized OSV-style
advisory records. It performs no I/O and deliberately distinguishes "no known
match" from an incomplete or indeterminate assessment.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ADVISORY_MATCHER_SCORING_VERSION = "2.0"

_MAX_DEPENDENCIES = 2_000
_MAX_ADVISORIES = 10_000
_MAX_CANDIDATE_EVALUATIONS = 50_000
_MAX_RANGES_PER_ADVISORY = 100
_MAX_EVENTS_PER_RANGE = 100
_MAX_VERSIONS_PER_ADVISORY = 10_000
_MAX_DIAGNOSTICS = 250
_MAX_TEXT = 512
_SUPPORTED_ECOSYSTEMS = frozenset({"PyPI", "npm"})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
_MARKER_VARIABLES = frozenset(
    {
        "implementation_name",
        "implementation_version",
        "os_name",
        "platform_machine",
        "platform_python_implementation",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_full_version",
        "python_version",
        "sys_platform",
        "extra",
    }
)
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
_SEMVER = re.compile(
    r"^[v=]?([0-9]+)\.([0-9]+)\.([0-9]+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_PLACEHOLDER_IDENTIFIERS = frozenset(
    {"-", "N/A", "NA", "NONE", "NULL", "TBD", "UNKNOWN", "UNSPECIFIED"}
)


@dataclass(frozen=True)
class _Dependency:
    name: str
    ecosystem: str
    version: str
    marker: str
    source_index: int


@dataclass(frozen=True)
class _SemVer:
    release: tuple[int, int, int]
    prerelease: tuple[tuple[int, Any], ...]


def match_dependency_advisories_v2(
    dependencies: Any,
    advisories: Any,
    assessment_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Match exact dependency versions against normalized advisory evidence.

    Supported ecosystems are PyPI and npm. Environment markers are evaluated
    only when every referenced marker variable is explicitly supplied in
    ``assessment_context.marker_environment``. Unknown applicability is scanned
    conservatively and marks the assessment partial.
    """
    diagnostics: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []
    assessment_complete = True

    context, context_complete = _context(assessment_context, diagnostics)
    assessment_complete = assessment_complete and context_complete

    dependency_items, dependency_state = _bounded_collection(
        dependencies, _MAX_DEPENDENCIES, allow_text=True
    )
    if dependency_state != "ok":
        assessment_complete = False
        _diagnostic(
            diagnostics,
            "dependency_inventory_" + dependency_state,
            "HIGH",
            "Dependency inventory is malformed or exceeds the analysis bound.",
        )

    parsed_dependencies: list[_Dependency] = []
    skipped_dependencies: list[dict[str, Any]] = []
    applicability_unknown = 0
    for index, item in enumerate(dependency_items):
        dependency, reason = _parse_dependency(
            item, index, context["default_ecosystem"]
        )
        if dependency is None:
            assessment_complete = False
            unresolved.append(
                {"dependency_index": index, "reason": reason or "invalid_dependency"}
            )
            continue
        applicability, marker_reason = _marker_applicability(
            dependency.marker, context["marker_environment"]
        )
        if applicability is False:
            skipped_dependencies.append(
                {
                    "dependency_index": index,
                    "package_name": dependency.name,
                    "ecosystem": dependency.ecosystem,
                    "reason": "environment_marker_false",
                }
            )
            continue
        if applicability is None:
            assessment_complete = False
            applicability_unknown += 1
            unresolved.append(
                {
                    "dependency_index": index,
                    "package_name": dependency.name,
                    "ecosystem": dependency.ecosystem,
                    "reason": marker_reason,
                    "scanned_conservatively": True,
                }
            )
        parsed_dependencies.append(dependency)

    duplicate_coordinates = _duplicate_coordinates(parsed_dependencies)
    conflicting_versions = _conflicting_versions(parsed_dependencies)
    if conflicting_versions:
        assessment_complete = False
        _diagnostic(
            diagnostics,
            "conflicting_dependency_versions",
            "HIGH",
            "One package identity resolves to multiple exact versions.",
            {"package_count": len(conflicting_versions)},
        )
    dependencies_to_scan = _deduplicate_dependencies(parsed_dependencies)

    advisory_items, advisory_state = _bounded_collection(
        advisories, _MAX_ADVISORIES, allow_text=False
    )
    if advisory_state != "ok":
        assessment_complete = False
        _diagnostic(
            diagnostics,
            "advisory_catalog_" + advisory_state,
            "HIGH",
            "Advisory catalog is malformed or exceeds the analysis bound.",
        )

    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    invalid_advisory_count = 0
    withdrawn_advisory_count = 0
    active_advisory_count = 0
    for advisory_index, item in enumerate(advisory_items):
        advisory, reason = _validate_advisory(item, advisory_index)
        if advisory is None:
            assessment_complete = False
            invalid_advisory_count += 1
            _diagnostic(
                diagnostics,
                "invalid_advisory_record",
                "HIGH",
                reason or "Advisory record is malformed.",
                {"advisory_index": advisory_index},
            )
            continue
        if advisory["withdrawn"]:
            withdrawn_advisory_count += 1
            continue
        active_advisory_count += 1
        index.setdefault(
            (advisory["ecosystem"], advisory["package_name"]), []
        ).append(advisory)

    raw_matches: list[dict[str, Any]] = []
    evaluated_dependencies = 0
    dependencies_with_candidates = 0
    candidate_evaluations = 0
    evaluation_limit_reached = False
    for dependency in dependencies_to_scan:
        candidates = index.get((dependency.ecosystem, dependency.name), [])
        if candidates:
            dependencies_with_candidates += 1
        evaluated_dependencies += 1
        for advisory in candidates:
            if candidate_evaluations >= _MAX_CANDIDATE_EVALUATIONS:
                evaluation_limit_reached = True
                assessment_complete = False
                break
            candidate_evaluations += 1
            outcome, reasons = _affected_outcome(dependency, advisory)
            if outcome == "AFFECTED":
                raw_matches.append(_match_record(dependency, advisory))
            elif outcome == "INDETERMINATE":
                assessment_complete = False
                indeterminate.append(
                    {
                        "dependency_index": dependency.source_index,
                        "package_name": dependency.name,
                        "ecosystem": dependency.ecosystem,
                        "installed_version": dependency.version,
                        "advisory_id": advisory["advisory_id"],
                        "reasons": reasons,
                    }
                )
        if evaluation_limit_reached:
            break

    if evaluation_limit_reached:
        _diagnostic(
            diagnostics,
            "candidate_evaluation_limit_exceeded",
            "HIGH",
            "Dependency/advisory candidate evaluations exceeded the safety bound.",
            {"maximum_evaluations": _MAX_CANDIDATE_EVALUATIONS},
        )

    matches = _merge_alias_matches(raw_matches)
    no_advisory_data = active_advisory_count == 0
    if dependency_state == "malformed":
        status = "PARTIAL"
    elif not dependency_items:
        status = "NO_DEPENDENCIES"
    elif not dependencies_to_scan:
        status = "PARTIAL" if unresolved else "NO_APPLICABLE_DEPENDENCIES"
    elif no_advisory_data:
        status = "NO_ADVISORY_DATA"
        assessment_complete = False
    elif matches:
        status = "VULNERABILITIES_FOUND"
    elif not assessment_complete or indeterminate:
        status = "PARTIAL"
    else:
        status = "NO_KNOWN_VULNERABILITIES"

    return {
        "scoring_version": ADVISORY_MATCHER_SCORING_VERSION,
        "methodology": "bounded_exact_version_osv_range_matching",
        "status": status,
        "assessment_complete": assessment_complete,
        "dependency_count": len(dependency_items),
        "unique_dependency_count": len(dependencies_to_scan),
        "evaluated_dependency_count": evaluated_dependencies,
        "skipped_dependency_count": len(skipped_dependencies),
        "unresolved_dependency_count": len(unresolved),
        "duplicate_coordinate_count": duplicate_coordinates,
        "conflicting_dependency_versions": conflicting_versions,
        "catalog": {
            "record_count": len(advisory_items),
            "active_record_count": active_advisory_count,
            "withdrawn_record_count": withdrawn_advisory_count,
            "invalid_record_count": invalid_advisory_count,
            "candidate_evaluations": candidate_evaluations,
        },
        "coverage": {
            "dependencies_with_candidates": dependencies_with_candidates,
            "dependencies_without_candidates": max(
                0, evaluated_dependencies - dependencies_with_candidates
            ),
            "marker_applicability_unknown": applicability_unknown,
            "indeterminate_evaluation_count": len(indeterminate),
        },
        "matches": matches,
        "match_count": len(matches),
        "raw_match_count": len(raw_matches),
        "by_severity": _count_by(matches, "severity"),
        "unresolved_dependencies": unresolved,
        "skipped_dependencies": skipped_dependencies,
        "indeterminate_evaluations": indeterminate[:_MAX_DIAGNOSTICS],
        "diagnostics": diagnostics,
    }


def _context(value, diagnostics):
    result = {
        "default_ecosystem": "PyPI",
        "marker_environment": None,
    }
    if value is None:
        return result, True
    if not isinstance(value, dict):
        _diagnostic(
            diagnostics,
            "malformed_assessment_context",
            "HIGH",
            "Assessment context must be an object.",
        )
        return result, False
    complete = True
    if value.get("default_ecosystem") is not None:
        ecosystem = _ecosystem(value.get("default_ecosystem"))
        if ecosystem not in _SUPPORTED_ECOSYSTEMS:
            complete = False
            _diagnostic(
                diagnostics,
                "unsupported_default_ecosystem",
                "HIGH",
                "Default ecosystem is unsupported.",
            )
        else:
            result["default_ecosystem"] = ecosystem
    if value.get("marker_environment") is not None:
        environment = value.get("marker_environment")
        if not isinstance(environment, dict):
            complete = False
            _diagnostic(
                diagnostics,
                "malformed_marker_environment",
                "HIGH",
                "Marker environment must be an object.",
            )
        else:
            result["marker_environment"] = {
                str(key): str(item) for key, item in environment.items()
            }
    return result, complete


def _parse_dependency(value, index, default_ecosystem):
    if isinstance(value, dict):
        ecosystem = _ecosystem(value.get("ecosystem") or default_ecosystem)
        name = _package_name(value.get("name"), ecosystem)
        raw_version = str(value.get("version") or "").strip()
        marker = str(value.get("marker") or value.get("markers") or "").strip()
        if not name:
            return None, "missing_package_name"
        if ecosystem not in _SUPPORTED_ECOSYSTEMS:
            return None, "unsupported_ecosystem"
        version = _exact_version(raw_version, ecosystem)
        if not version:
            return None, "exact_version_required"
        return _Dependency(name, ecosystem, version, marker, index), None

    if not isinstance(value, str) or not value.strip():
        return None, "dependency_must_be_string_or_object"
    text = value.strip()
    if default_ecosystem == "npm":
        name, raw_version = _split_npm_coordinate(text)
        version = _exact_version(raw_version, "npm")
        if not name or not version:
            return None, "exact_npm_version_required"
        return _Dependency(_package_name(name, "npm"), "npm", version, "", index), None

    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        return None, "invalid_pep508_requirement"
    if requirement.url:
        return None, "direct_reference_has_no_verified_release_version"
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="}:
        return None, "exact_version_required"
    version = _exact_version(specifiers[0].version, "PyPI")
    if not version:
        return None, "invalid_exact_version"
    return _Dependency(
        _package_name(requirement.name, "PyPI"),
        "PyPI",
        version,
        str(requirement.marker or ""),
        index,
    ), None


def _marker_applicability(marker_text, environment):
    if not marker_text:
        return True, None
    try:
        marker = Marker(marker_text)
    except InvalidMarker:
        return None, "invalid_environment_marker"
    referenced = {
        token
        for token in re.findall(r"\b[a-z_][a-z0-9_]*\b", marker_text.lower())
        if token in _MARKER_VARIABLES
    }
    if environment is None or not referenced.issubset(environment):
        return None, "marker_environment_incomplete"
    try:
        return bool(marker.evaluate(environment=environment)), None
    except (KeyError, TypeError, ValueError):
        return None, "marker_evaluation_failed"


def _validate_advisory(value, index):
    if not isinstance(value, dict):
        return None, "Advisory record must be an object."
    advisory_id = _text(value.get("advisory_id") or value.get("id"))
    ecosystem = _ecosystem(value.get("ecosystem"))
    package_name = _package_name(value.get("package_name"), ecosystem)
    if not advisory_id or not package_name or not ecosystem:
        return None, "Advisory requires id, ecosystem, and package name."
    if ecosystem not in _SUPPORTED_ECOSYSTEMS:
        return None, "Advisory ecosystem is unsupported."
    aliases = _bounded_strings(value.get("aliases"), 100)
    affected_versions, versions_truncated, versions_valid = _version_list(
        value.get("affected_versions")
    )
    ranges, ranges_truncated, ranges_valid = _range_list(value.get("affected_ranges"))
    return {
        "advisory_id": advisory_id,
        "ecosystem": ecosystem,
        "package_name": package_name,
        "aliases": aliases,
        "severity": _severity(value.get("severity")),
        "summary": _text(value.get("summary")),
        "references": _bounded_references(value.get("references")),
        "source": _text(value.get("source")) or "imported",
        "withdrawn": bool(value.get("withdrawn_at") or value.get("withdrawn")),
        "affected_versions": affected_versions,
        "affected_ranges": ranges,
        "evidence_truncated": versions_truncated or ranges_truncated,
        "evidence_valid": versions_valid and ranges_valid,
        "source_index": index,
    }, None


def _affected_outcome(dependency, advisory):
    reasons: list[str] = []
    indeterminate = advisory["evidence_truncated"] or not advisory["evidence_valid"]
    if advisory["evidence_truncated"]:
        reasons.append("advisory_evidence_truncated")
    if not advisory["evidence_valid"]:
        reasons.append("malformed_advisory_range_evidence")

    explicit_versions = advisory["affected_versions"]
    for affected_version in explicit_versions:
        comparison = _compare_versions(
            dependency.version, affected_version, dependency.ecosystem
        )
        if comparison is None:
            indeterminate = True
            reasons.append("uncomparable_affected_version")
        elif comparison == 0:
            return "AFFECTED", []

    ranges = advisory["affected_ranges"]
    for affected_range in ranges:
        outcome, reason = _range_outcome(dependency.version, dependency.ecosystem, affected_range)
        if outcome == "AFFECTED":
            return "AFFECTED", []
        if outcome == "INDETERMINATE":
            indeterminate = True
            if reason:
                reasons.append(reason)

    if not explicit_versions and not ranges:
        return "INDETERMINATE", ["advisory_has_no_affected_version_evidence"]
    if indeterminate:
        return "INDETERMINATE", list(dict.fromkeys(reasons))
    return "NOT_AFFECTED", []


def _range_outcome(version, ecosystem, affected_range):
    range_type = str(affected_range.get("type") or "ECOSYSTEM").upper()
    if range_type == "GIT":
        return "INDETERMINATE", "git_range_requires_commit_identity"
    if range_type not in {"ECOSYSTEM", "SEMVER"}:
        return "INDETERMINATE", "unsupported_range_type"
    comparison_ecosystem = "npm" if range_type == "SEMVER" else ecosystem
    events = affected_range.get("events")
    if not isinstance(events, list) or not events:
        return "INDETERMINATE", "range_has_no_events"

    active = False
    interval_open = False
    introduced_boundary = None
    previous_closure = None
    previous_closure_inclusive = False
    for event in events:
        if not isinstance(event, dict):
            return "INDETERMINATE", "malformed_range_event"
        recognized = [
            key for key in ("introduced", "fixed", "last_affected", "limit") if key in event
        ]
        if len(recognized) != 1:
            return "INDETERMINATE", "ambiguous_range_event"
        event_type = recognized[0]
        if set(event) != {event_type}:
            return "INDETERMINATE", "unexpected_range_event_fields"
        boundary = str(event[event_type]).strip()
        if event_type == "introduced":
            if interval_open:
                return "INDETERMINATE", "overlapping_range_intervals"
            if previous_closure is not None:
                if boundary == "0":
                    return "INDETERMINATE", "out_of_order_range_intervals"
                order = _compare_versions(
                    boundary, previous_closure, comparison_ecosystem
                )
                if order is None:
                    return "INDETERMINATE", "invalid_introduced_boundary"
                if order < 0 or (order == 0 and previous_closure_inclusive):
                    return "INDETERMINATE", "out_of_order_range_intervals"
            interval_open = True
            introduced_boundary = boundary
            if boundary == "0":
                active = True
            else:
                comparison = _compare_versions(version, boundary, comparison_ecosystem)
                if comparison is None:
                    return "INDETERMINATE", "invalid_introduced_boundary"
                active = comparison >= 0
            continue

        if not interval_open:
            return "INDETERMINATE", "range_closure_without_introduction"
        comparison = _compare_versions(version, boundary, comparison_ecosystem)
        if comparison is None:
            return "INDETERMINATE", "invalid_range_boundary"
        if introduced_boundary != "0":
            interval_order = _compare_versions(
                boundary, introduced_boundary, comparison_ecosystem
            )
            if interval_order is None:
                return "INDETERMINATE", "invalid_range_boundary"
            minimum_order = 0 if event_type == "last_affected" else 1
            if interval_order < minimum_order:
                return "INDETERMINATE", "inverted_range_interval"
        if event_type in {"fixed", "limit"}:
            if active and comparison < 0:
                return "AFFECTED", None
        elif active and comparison <= 0:
            return "AFFECTED", None
        active = False
        interval_open = False
        introduced_boundary = None
        previous_closure = boundary
        previous_closure_inclusive = event_type == "last_affected"

    return ("AFFECTED", None) if active else ("NOT_AFFECTED", None)


def _match_record(dependency, advisory):
    return {
        "advisory_id": advisory["advisory_id"],
        "advisory_ids": [advisory["advisory_id"]],
        "aliases": advisory["aliases"],
        "package_name": dependency.name,
        "ecosystem": dependency.ecosystem,
        "installed_version": dependency.version,
        "severity": advisory["severity"],
        "summary": advisory["summary"],
        "fixed_versions": _fixed_versions(advisory["affected_ranges"]),
        "references": advisory["references"],
        "sources": [advisory["source"]],
        "dependency_indices": [dependency.source_index],
    }


def _merge_alias_matches(matches):
    if not matches:
        return []
    parents = list(range(len(matches)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left, right):
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    identifiers: dict[tuple[str, str, str, str], int] = {}
    for index, match in enumerate(matches):
        coordinate = (
            match["ecosystem"],
            match["package_name"],
            match["installed_version"],
        )
        identifiers_to_correlate = set(match["advisory_ids"])
        identifiers_to_correlate.update(
            alias for alias in match["aliases"] if _correlatable_alias(alias)
        )
        for identifier in identifiers_to_correlate:
            key = coordinate + (identifier.upper(),)
            if key in identifiers:
                union(index, identifiers[key])
            else:
                identifiers[key] = index

    groups: dict[int, list[dict[str, Any]]] = {}
    for index, match in enumerate(matches):
        groups.setdefault(find(index), []).append(match)

    merged = []
    for group in groups.values():
        advisory_ids = sorted({item for match in group for item in match["advisory_ids"]})
        aliases = sorted({item for match in group for item in match["aliases"]})
        preferred = _preferred_identifier(
            advisory_ids
            + [alias for alias in aliases if _correlatable_alias(alias)]
        )
        merged.append(
            {
                "advisory_id": preferred,
                "advisory_ids": advisory_ids,
                "aliases": aliases,
                "package_name": group[0]["package_name"],
                "ecosystem": group[0]["ecosystem"],
                "installed_version": group[0]["installed_version"],
                "severity": _highest_severity(item["severity"] for item in group),
                "summary": next((item["summary"] for item in group if item["summary"]), ""),
                "fixed_versions": sorted(
                    {version for item in group for version in item["fixed_versions"]},
                    key=_version_sort_key,
                ),
                "references": _unique_dicts(
                    item for match in group for item in match["references"]
                ),
                "sources": sorted({source for item in group for source in item["sources"]}),
                "dependency_indices": sorted(
                    {index for item in group for index in item["dependency_indices"]}
                ),
                "corroborating_record_count": len(group),
            }
        )
    return sorted(
        merged,
        key=lambda item: (
            item["ecosystem"], item["package_name"], item["installed_version"], item["advisory_id"]
        ),
    )


def _range_list(value):
    if value in (None, ""):
        return [], False, True
    if not isinstance(value, (list, tuple)):
        return [], False, False
    truncated = len(value) > _MAX_RANGES_PER_ADVISORY
    valid = True
    ranges = []
    for item in list(value)[:_MAX_RANGES_PER_ADVISORY]:
        if not isinstance(item, dict):
            valid = False
            continue
        raw_events = item.get("events")
        if not isinstance(raw_events, (list, tuple)):
            valid = False
            events = []
        else:
            if len(raw_events) > _MAX_EVENTS_PER_RANGE:
                truncated = True
            events = list(raw_events)[:_MAX_EVENTS_PER_RANGE]
        ranges.append({"type": _text(item.get("type") or "ECOSYSTEM"), "events": events})
    return ranges, truncated, valid


def _version_list(value):
    if value in (None, ""):
        return [], False, True
    if isinstance(value, str):
        return [_text(value)], False, bool(value.strip())
    if not isinstance(value, (list, tuple, set)):
        return [], False, False
    items = sorted(value, key=str) if isinstance(value, set) else list(value)
    values = [_text(item) for item in items[:_MAX_VERSIONS_PER_ADVISORY]]
    valid = all(values) and len(values) == min(len(items), _MAX_VERSIONS_PER_ADVISORY)
    return values, len(items) > _MAX_VERSIONS_PER_ADVISORY, valid


def _compare_versions(left, right, ecosystem):
    if ecosystem == "npm":
        left_version = _semver(left)
        right_version = _semver(right)
        if left_version is None or right_version is None:
            return None
        return _compare_semver(left_version, right_version)
    if ecosystem == "PyPI":
        try:
            left_version = Version(str(left))
            right_version = Version(str(right))
        except InvalidVersion:
            return None
        return (left_version > right_version) - (left_version < right_version)
    return None


def _semver(value):
    match = _SEMVER.fullmatch(str(value or "").strip())
    if not match:
        return None
    prerelease = ()
    if match.group(4):
        identifiers = []
        for identifier in match.group(4).split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    return None
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
        prerelease = tuple(identifiers)
    return _SemVer(tuple(int(match.group(i)) for i in range(1, 4)), prerelease)


def _compare_semver(left, right):
    if left.release != right.release:
        return (left.release > right.release) - (left.release < right.release)
    if not left.prerelease and not right.prerelease:
        return 0
    if not left.prerelease:
        return 1
    if not right.prerelease:
        return -1
    for left_item, right_item in zip(left.prerelease, right.prerelease, strict=False):
        if left_item == right_item:
            continue
        if left_item[0] != right_item[0]:
            return -1 if left_item[0] == 0 else 1
        return (left_item[1] > right_item[1]) - (left_item[1] < right_item[1])
    return (len(left.prerelease) > len(right.prerelease)) - (
        len(left.prerelease) < len(right.prerelease)
    )


def _exact_version(value, ecosystem):
    text = str(value or "").strip()
    if text.startswith("==="):
        text = text[3:].strip()
    elif text.startswith("=="):
        text = text[2:].strip()
    elif text.startswith((">", "<", "~", "!", "^", "*", "=")):
        return ""
    if "*" in text or "||" in text or " - " in text:
        return ""
    if ecosystem == "npm":
        parsed = _semver(text)
        return text.lstrip("v=") if parsed is not None else ""
    try:
        return str(Version(text))
    except InvalidVersion:
        return ""


def _split_npm_coordinate(value):
    text = value.strip()
    if text.startswith("@"):
        separator = text.rfind("@")
        if separator <= text.find("/"):
            return "", ""
        name, version = text[:separator], text[separator + 1 :]
    elif "@" in text:
        name, version = text.rsplit("@", 1)
    else:
        parts = text.split("==", 1)
        if len(parts) != 2:
            return "", ""
        name, version = parts
    return (name, version) if _NPM_NAME.fullmatch(name) else ("", "")


def _ecosystem(value):
    normalized = str(value or "").strip().lower()
    return {
        "pypi": "PyPI",
        "python": "PyPI",
        "pip": "PyPI",
        "npm": "npm",
        "node": "npm",
        "nodejs": "npm",
    }.get(normalized, str(value or "").strip())


def _package_name(value, ecosystem):
    name = str(value or "").strip().lower()
    if _ecosystem(ecosystem) == "PyPI":
        return str(canonicalize_name(name)) if name else ""
    return name if _NPM_NAME.fullmatch(name) else ""


def _bounded_collection(value, limit, allow_text):
    if value in (None, ""):
        return [], "ok"
    if isinstance(value, dict):
        contained = value.get("items")
        if contained is None:
            items = [value]
        elif isinstance(contained, (list, tuple)):
            items = list(contained)
        else:
            return [], "malformed"
    elif allow_text and isinstance(value, str):
        items = [line.strip() for line in value.splitlines() if line.strip()]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return [], "malformed"
    return items[:limit], "truncated" if len(items) > limit else "ok"


def _deduplicate_dependencies(dependencies):
    return list(
        {
            (item.ecosystem, item.name, item.version, item.marker): item
            for item in dependencies
        }.values()
    )


def _duplicate_coordinates(dependencies):
    identities = [
        (item.ecosystem, item.name, item.version, item.marker) for item in dependencies
    ]
    return len(identities) - len(set(identities))


def _conflicting_versions(dependencies):
    versions: dict[tuple[str, str], set] = {}
    for item in dependencies:
        versions.setdefault((item.ecosystem, item.name), set()).add(item.version)
    return [
        {"ecosystem": key[0], "package_name": key[1], "versions": sorted(values)}
        for key, values in sorted(versions.items())
        if len(values) > 1
    ]


def _fixed_versions(ranges):
    return sorted(
        {
            str(event["fixed"])
            for affected_range in ranges
            for event in affected_range.get("events", [])
            if isinstance(event, dict) and event.get("fixed")
        },
        key=_version_sort_key,
    )


def _preferred_identifier(values):
    unique = sorted(set(values))
    for prefix in ("CVE-", "GHSA-"):
        preferred = [value for value in unique if value.upper().startswith(prefix)]
        if preferred:
            return preferred[0]
    return unique[0]


def _correlatable_alias(value):
    normalized = str(value or "").strip().upper()
    return (
        normalized not in _PLACEHOLDER_IDENTIFIERS
        and 4 <= len(normalized) <= 128
        and not any(character.isspace() or ord(character) < 32 for character in normalized)
        and any(separator in normalized for separator in ("-", ":"))
    )


def _highest_severity(values: Iterable[str]) -> str:
    rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max((value if value in rank else "UNKNOWN" for value in values), key=rank.get)


def _severity(value):
    normalized = str(value or "UNKNOWN").upper()
    return normalized if normalized in _SEVERITIES else "UNKNOWN"


def _bounded_strings(value, limit):
    if value in (None, ""):
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, set):
        items = sorted(value, key=str)
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        items = []
    return list(dict.fromkeys(_text(item) for item in list(items)[:limit] if _text(item)))


def _bounded_references(value):
    if not isinstance(value, (list, tuple)):
        return []
    references = []
    for item in list(value)[:100]:
        if isinstance(item, dict) and item.get("url"):
            references.append(
                {"type": _text(item.get("type") or "WEB"), "url": _text(item.get("url"))}
            )
    return _unique_dicts(references)


def _unique_dicts(values):
    result = []
    seen = set()
    for value in values:
        identity = tuple(sorted(value.items()))
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return result


def _count_by(values: Sequence[dict[str, Any]], field: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in values:
        key = str(item.get(field) or "UNKNOWN")
        result[key] = result.get(key, 0) + 1
    return result


def _diagnostic(diagnostics, indicator, severity, detail, evidence=None):
    if len(diagnostics) >= _MAX_DIAGNOSTICS:
        return
    item = {"indicator": indicator, "severity": severity, "detail": detail}
    if evidence is not None:
        item["evidence"] = evidence
    if item not in diagnostics:
        diagnostics.append(item)


def _version_sort_key(value):
    try:
        return (0, Version(str(value)))
    except InvalidVersion:
        return (1, str(value))


def _text(value):
    return str(value or "").strip()[:_MAX_TEXT]

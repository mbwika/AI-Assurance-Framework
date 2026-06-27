"""Offline vulnerability advisory normalization.

Exact-version and OSV range matching now lives in ``advisory_matcher_v2``;
this module is responsible only for normalizing OSV-style documents into the
package-specific advisory records the matcher consumes.
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def normalize_advisory(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize one OSV-style document into package-specific records."""
    advisory_id = str(document.get("id") or "").strip()
    if not advisory_id:
        raise ValueError("Advisory id is required")
    affected_entries = document.get("affected") or []
    if not affected_entries and document.get("package"):
        affected_entries = [document]
    if not affected_entries:
        raise ValueError(f"Advisory {advisory_id} has no affected packages")

    records = []
    for affected in affected_entries:
        package = affected.get("package") or {}
        package_name = str(package.get("name") or affected.get("package_name") or "").strip()
        ecosystem = _ecosystem(package.get("ecosystem") or affected.get("ecosystem"))
        if not package_name or not ecosystem:
            raise ValueError(
                f"Advisory {advisory_id} affected package requires name and ecosystem"
            )
        severity = _advisory_severity(document, affected)
        identity = f"{advisory_id}|{ecosystem}|{_package_name(package_name, ecosystem)}"
        records.append(
            {
                "record_key": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                "advisory_id": advisory_id,
                "ecosystem": ecosystem,
                "package_name": _package_name(package_name, ecosystem),
                "summary": str(document.get("summary") or document.get("details") or advisory_id),
                "severity": severity,
                "aliases": _strings(document.get("aliases")),
                "affected_versions": _strings(affected.get("versions")),
                "affected_ranges": _ranges(affected.get("ranges")),
                "references": _references(document.get("references")),
                "published_at": document.get("published"),
                "modified_at": document.get("modified"),
                "withdrawn_at": document.get("withdrawn"),
                "source": str(document.get("source") or "imported"),
                "metadata": {
                    "schema_version": document.get("schema_version"),
                    "database_specific": document.get("database_specific") or {},
                },
                "updated_at": _utc_now(),
            }
        )
    return records


def _ranges(value: Any) -> list[dict[str, Any]]:
    ranges = []
    for item in value or []:
        if not isinstance(item, dict):
            continue
        ranges.append(
            {
                "type": str(item.get("type") or "ECOSYSTEM").upper(),
                "repo": item.get("repo"),
                "events": [event for event in item.get("events", []) if isinstance(event, dict)],
            }
        )
    return ranges


def _advisory_severity(document: dict[str, Any], affected: dict[str, Any]) -> str:
    candidates = (
        affected.get("database_specific", {}).get("severity"),
        document.get("database_specific", {}).get("severity"),
        document.get("severity_label"),
    )
    for candidate in candidates:
        normalized = str(candidate or "").upper()
        if normalized in SEVERITIES:
            return normalized
    return "UNKNOWN"


def _references(value: Any) -> list[dict[str, str]]:
    references = []
    for item in value or []:
        if isinstance(item, dict) and item.get("url"):
            references.append(
                {"type": str(item.get("type") or "WEB"), "url": str(item["url"])}
            )
        elif isinstance(item, str):
            references.append({"type": "WEB", "url": item})
    return references


def _strings(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _ecosystem(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return {"pypi": "PyPI", "python": "PyPI", "pip": "PyPI", "npm": "npm"}.get(
        normalized, str(value or "").strip()
    )


def _package_name(value: Any, ecosystem: Any) -> str:
    name = str(value or "").strip().lower()
    if _ecosystem(ecosystem) == "PyPI":
        return re.sub(r"[-_.]+", "-", name)
    return name


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

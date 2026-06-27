"""SIEM Export Formatters.

Converts AIAF incident records into industry-standard formats for
ingestion by Security Information and Event Management (SIEM) systems.

Supported formats
-----------------
* **CEF** — ArcSight Common Event Format v0.
* **LEEF** — IBM QRadar Log Event Extended Format v2.0.
* **JSON** — Canonical JSON dict (easiest to ingest in modern SIEMs).

Evidence origin
---------------
The evidence origin of the underlying incident is preserved in the JSON
format and translated to the appropriate CEF/LEEF severity field.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SIEM_VERSION = "1.0"

_VENDOR = "AI Assurance Framework"
_PRODUCT = "AIAF"
_PRODUCT_VERSION = "1.0"

FORMAT_CEF = "CEF"
FORMAT_LEEF = "LEEF"
FORMAT_JSON = "JSON"

EXPORT_FORMATS: frozenset = frozenset({FORMAT_CEF, FORMAT_LEEF, FORMAT_JSON})

_CEF_SEVERITY: dict[str, int] = {
    "CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1,
}

_LEEF_SEVERITY: dict[str, str] = {
    "CRITICAL": "Critical", "HIGH": "High",
    "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info",
}


class SiemExportError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _cef_escape(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _leef_escape(value: str) -> str:
    return str(value).replace("\t", " ").replace("\n", " ").replace("\r", " ")


# ── Format functions ───────────────────────────────────────────────────────────

def export_incident_cef(incident: dict[str, Any]) -> str:
    """Format one incident as a CEF syslog line."""
    severity = str(incident.get("severity") or "INFO").upper()
    cef_sev = _CEF_SEVERITY.get(severity, 5)
    iid = _cef_escape(str(incident.get("incident_id") or "unknown"))
    title = _cef_escape(str(incident.get("title") or ""))
    model_id = _cef_escape(str(incident.get("model_id") or "unknown"))
    state = _cef_escape(str(incident.get("state") or "OPEN"))
    description = _cef_escape(str(incident.get("description") or ""))
    source = _cef_escape(str(incident.get("source") or "aiaf"))
    created_at = _cef_escape(str(incident.get("created_at") or _utc_now()))
    origin = _cef_escape(str(incident.get("evidence_origin") or "LOCALLY_OBSERVED"))

    header = f"CEF:0|{_VENDOR}|{_PRODUCT}|{_PRODUCT_VERSION}|{iid}|{title}|{cef_sev}"
    ext = (
        f"model_id={model_id} state={state} source={source} "
        f"evidence_origin={origin} start={created_at} msg={description}"
    ).strip()
    return f"{header}|{ext}"


def export_incident_leef(incident: dict[str, Any]) -> str:
    """Format one incident as a LEEF 2.0 syslog line."""
    severity = str(incident.get("severity") or "INFO").upper()
    leef_sev = _LEEF_SEVERITY.get(severity, "Medium")
    iid = _leef_escape(str(incident.get("incident_id") or "unknown"))
    title = _leef_escape(str(incident.get("title") or ""))
    model_id = _leef_escape(str(incident.get("model_id") or "unknown"))
    state = _leef_escape(str(incident.get("state") or "OPEN"))
    source = _leef_escape(str(incident.get("source") or "aiaf"))
    created_at = _leef_escape(str(incident.get("created_at") or _utc_now()))

    header = f"LEEF:2.0|{_VENDOR}|{_PRODUCT}|{_PRODUCT_VERSION}|{iid}"
    fields = "\t".join([
        f"sev={leef_sev}", f"title={title}", f"model_id={model_id}",
        f"state={state}", f"src={source}", f"start={created_at}",
    ])
    return f"{header}\t{fields}"


def export_incident_json(incident: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical JSON-serialisable dict for the incident."""
    return {
        "siem_version": SIEM_VERSION,
        "vendor": _VENDOR,
        "product": _PRODUCT,
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "state": incident.get("state"),
        "model_id": incident.get("model_id"),
        "source": incident.get("source"),
        "description": incident.get("description"),
        "evidence_origin": incident.get("evidence_origin", "LOCALLY_OBSERVED"),
        "finding_count": len(incident.get("findings") or []),
        "tags": incident.get("tags") or [],
        "created_at": incident.get("created_at"),
        "exported_at": _utc_now(),
    }


def export_batch(
    incidents: list[dict[str, Any]],
    export_format: str,
    *,
    max_records: int = 1000,
) -> dict[str, Any]:
    """Export a batch of incidents in the specified format.

    Returns ``{format, count, records, exported_at}``.
    """
    export_format = str(export_format).upper().strip()
    if export_format not in EXPORT_FORMATS:
        raise SiemExportError(
            f"Unknown export format: {export_format!r}. Valid: {sorted(EXPORT_FORMATS)}"
        )

    batch = incidents[:max_records]
    if export_format == FORMAT_CEF:
        records: list[Any] = [export_incident_cef(i) for i in batch]
    elif export_format == FORMAT_LEEF:
        records = [export_incident_leef(i) for i in batch]
    else:
        records = [export_incident_json(i) for i in batch]

    return {
        "siem_version": SIEM_VERSION,
        "format": export_format,
        "count": len(records),
        "records": records,
        "exported_at": _utc_now(),
    }

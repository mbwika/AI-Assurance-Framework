"""NIST OSCAL 1.1.2 System Security Plan (SSP) export for AIAF governance evidence.

The Open Security Controls Assessment Language (OSCAL) SSP format is the
machine-readable standard used by FedRAMP, FISMA, and other US federal
frameworks.  AIAF governance evidence maps cleanly to OSCAL implemented
requirements, enabling direct submission to compliance toolchains.

Reference: https://pages.nist.gov/OSCAL/
"""
import time
import uuid
from typing import Any, Dict, List, Optional

OSCAL_VERSION = "1.1.2"

_AIAF_TO_OSCAL_STATUS = {
    "PASS": "implemented",
    "FAIL": "not-implemented",
    "PARTIAL": "partially-implemented",
    "NOT_EVALUATED": "planned",
    "ACCEPTED": "implemented",
    "IN_PROGRESS": "partially-implemented",
}


def export_oscal_ssp(
    system_name: str,
    controls: List[Dict[str, Any]],
    evidence: Optional[List[Dict[str, Any]]] = None,
    version: str = "0.2.0",
    system_description: str = "AI system assessed by the AI Assurance Framework",
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate an OSCAL 1.1.2 SSP document from AIAF governance data.

    Parameters
    ----------
    system_name:
        Display name for the AI system.
    controls:
        List of control dicts with at minimum ``id`` and ``status`` keys.
        May also include ``description``.
    evidence:
        List of evidence dicts linking to controls via ``control_id``.
    version:
        AIAF framework version string.

    Returns
    -------
    dict
        A JSON-serialisable OSCAL 1.1.2 SSP document.
    """
    evidence = evidence or []
    report = report or {}
    evidence_by_control: Dict[str, List[Dict[str, Any]]] = {}
    for ev in evidence:
        cid = ev.get("control_id", "")
        evidence_by_control.setdefault(cid, []).append(ev)

    scope = report.get("scope") or {}
    executive = report.get("executive_summary") or {}
    governance = report.get("governance") or {}
    compliance = report.get("compliance") or {}
    inventory = report.get("model_inventory") or {}
    generated_at = report.get("generated_at") or time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    report_snapshots = report.get("report_snapshots") or {}

    implemented_requirements: List[Dict[str, Any]] = []
    for control in controls:
        control_id = control.get("id", "unknown")
        status = control.get("status", "NOT_EVALUATED")
        oscal_status = _AIAF_TO_OSCAL_STATUS.get(status.upper() if status else "", "planned")

        statements: List[Dict[str, Any]] = []
        for ev in evidence_by_control.get(control_id, []):
            statements.append({
                "statement-id": f"{control_id.lower().replace('_', '-')}_stmt",
                "uuid": str(uuid.uuid4()),
                "description": ev.get("description", ""),
                "remarks": f"Reference: {ev.get('reference_url', 'N/A')} | SHA-256: {ev.get('sha256', 'N/A')}",
            })

        implemented_requirements.append({
            "uuid": str(uuid.uuid4()),
            "control-id": control_id.lower().replace("_", "-"),
            "description": control.get("description", ""),
            "implementation-status": {"state": oscal_status},
            "props": [
                {"name": "aiaf:control_status", "value": status},
                {"name": "aiaf:objective", "value": str(control.get("objective") or "")},
                {"name": "aiaf:domain", "value": str(control.get("domain") or "")},
                {
                    "name": "aiaf:missing_evidence",
                    "value": ", ".join(str(item) for item in (control.get("missing_evidence") or [])),
                },
                {
                    "name": "aiaf:provided_evidence",
                    "value": ", ".join(str(item) for item in (control.get("provided_evidence") or [])),
                },
            ],
            "statements": statements,
            "remarks": control.get("notes", ""),
        })

    resources = []
    for ev in evidence:
        resources.append(
            {
                "uuid": str(uuid.uuid4()),
                "title": f"Evidence {ev.get('id', 'record')} for {ev.get('control_id', 'control')}",
                "description": (
                    f"Submitted by {ev.get('submitted_by', 'unknown')} with status "
                    f"{ev.get('status', 'UNKNOWN')}"
                ),
                "props": [
                    {"name": "aiaf:control_id", "value": str(ev.get("control_id") or "")},
                    {"name": "aiaf:evidence_type", "value": str(ev.get("evidence_type") or "")},
                    {"name": "aiaf:status", "value": str(ev.get("status") or "")},
                ],
                "rlinks": [
                    {
                        "href": str(ev.get("reference") or ""),
                        "media-type": "text/plain",
                    }
                ]
                if ev.get("reference")
                else [],
                "remarks": f"SHA-256: {ev.get('sha256', 'N/A')}",
            }
        )

    components = []
    for model in inventory.get("models") or []:
        components.append(
            {
                "uuid": str(uuid.uuid4()),
                "type": "service",
                "title": str(model.get("model_name") or model.get("model_id") or "Registered model"),
                "description": (
                    f"Source={model.get('source', 'unknown')}; "
                    f"publisher={model.get('publisher', 'unknown')}; "
                    f"risk={model.get('risk_level', 'UNKNOWN')}; "
                    f"provenance={model.get('provenance_score', 'N/A')}"
                ),
                "props": [
                    {"name": "aiaf:model_id", "value": str(model.get("model_id") or "")},
                    {"name": "aiaf:source_url", "value": str(model.get("source_url") or "")},
                    {"name": "aiaf:sha256", "value": str(model.get("sha256") or "")},
                ],
                "status": {"state": "operational"},
            }
        )

    return {
        "system-security-plan": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"AI Assurance Framework SSP — {system_name}",
                "last-modified": generated_at,
                "version": version,
                "oscal-version": OSCAL_VERSION,
                "remarks": "Generated by AI Assurance Framework (AIAF)",
                "props": [
                    {"name": "aiaf:scope_type", "value": str(scope.get("type") or "PORTFOLIO")},
                    {"name": "aiaf:artifact_id", "value": str(scope.get("artifact_id") or "")},
                    {"name": "aiaf:model_id", "value": str(scope.get("model_id") or "")},
                    {"name": "aiaf:registered_by", "value": str(scope.get("registered_by") or "")},
                    {"name": "aiaf:report_schema_version", "value": str(report.get("schema_version") or "")},
                ],
            },
            "import-profile": {
                "href": "#aiaf-control-catalog",
                "remarks": "AIAF executable control catalog",
            },
            "system-characteristics": {
                "system-name": system_name,
                "description": system_description,
                "security-impact-level": {
                    "security-objective-confidentiality": _impact_label(executive, "confidentiality"),
                    "security-objective-integrity": _impact_label(executive, "integrity"),
                    "security-objective-availability": _impact_label(executive, "availability"),
                },
                "status": {"state": "operational"},
                "remarks": (
                    f"Overall status: {executive.get('overall_status', 'UNKNOWN')}; "
                    f"risk score: {executive.get('current_risk_score', 'N/A')}; "
                    f"open governance gaps: {executive.get('open_governance_gaps', 0)}."
                ),
                "props": [
                    {
                        "name": "aiaf:high_or_critical_findings",
                        "value": str(executive.get("high_or_critical_findings", 0)),
                    },
                    {
                        "name": "aiaf:active_managed_risks",
                        "value": str(executive.get("active_managed_risks", 0)),
                    },
                    {
                        "name": "aiaf:report_snapshots",
                        "value": str(report_snapshots.get("total_snapshots", 0)),
                    },
                    {
                        "name": "aiaf:frameworks_in_scope",
                        "value": str((compliance.get("summary") or {}).get("frameworks_in_scope", 0)),
                    },
                ],
            },
            "system-implementation": {
                "remarks": "AI system components and services assessed through AIAF continuous assurance",
                "components": components,
            },
            "control-implementation": {
                "description": "Controls implemented and verified through AIAF continuous assurance workflows",
                "implemented-requirements": implemented_requirements,
            },
            "back-matter": {"resources": resources},
        }
    }


def _impact_label(executive: Dict[str, Any], objective: str) -> str:
    score = float(executive.get("current_risk_score") or 0.0)
    findings = int(executive.get("high_or_critical_findings") or 0)
    if score >= 8.0 or findings >= 5:
        return "high"
    if score >= 4.0 or findings >= 2:
        return "moderate"
    if objective == "availability" and score < 2.0:
        return "low"
    return "moderate"

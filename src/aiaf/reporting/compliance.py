"""Evidence matrix construction for governance and standards reporting."""

from typing import Any, Dict, List, Optional, Set

from ..mapping.standards import (
    FRAMEWORKS,
    STANDARD_PROFILES,
    describe_framework_reference,
    get_framework_profile,
)


FRAMEWORK_ALIASES = {
    "NIST SSDF": "NIST Secure Software Development Framework",
    "NIST Secure Software Development Framework": "NIST Secure Software Development Framework",
    "NIST AI RMF": "NIST AI RMF",
    "OWASP Top 10 for LLMs": "OWASP Top 10 for LLMs",
    "MITRE ATLAS": "MITRE ATLAS",
    "CIS Controls": "CIS Controls",
}


def build_compliance_matrix(
    finding_items: List[Dict[str, Any]],
    latest_governance: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build per-framework control evidence without asserting certification."""
    declared_scope = _declared_scope(latest_governance)
    scoped_frameworks = declared_scope or set(FRAMEWORKS)
    frameworks = {
        framework: _framework_record(framework, framework in scoped_frameworks)
        for framework in FRAMEWORKS
    }

    if latest_governance:
        for control in latest_governance.get("controls", []):
            _add_control_evidence(frameworks, control)

    for finding in finding_items:
        _add_finding_evidence(frameworks, finding)

    open_control_gaps = []
    for framework, record in frameworks.items():
        _finalize_framework(record, governance_evaluated=latest_governance is not None)
        for control in record["control_evidence"]:
            if record["in_scope"] and control["status"] == "missing":
                open_control_gaps.append(
                    {
                        "framework": framework,
                        "framework_source_url": get_framework_profile(framework).get("source_url", ""),
                        "control_id": control["control_id"],
                        "title": control["title"],
                        "missing_evidence": control["missing_evidence"],
                        "references": control["references"],
                        "reference_details": [
                            describe_framework_reference(framework, reference)
                            for reference in control["references"]
                        ],
                    }
                )

    in_scope = [record for record in frameworks.values() if record["in_scope"]]
    if latest_governance is None:
        status = "NO_EVALUATION"
    elif open_control_gaps:
        status = "CONTROL_GAPS_IDENTIFIED"
    else:
        status = "CONTROL_EVIDENCE_COMPLETE"

    return {
        "status": status,
        "assessment_basis": (
            "Automated evidence completeness against the AIAF control catalog; "
            "this result is not a certification or legal compliance determination."
        ),
        "scope": {
            "source": "declared" if declared_scope else "catalog_default",
            "frameworks": sorted(scoped_frameworks),
            "artifact_id": latest_governance.get("artifact_id") if latest_governance else None,
            "evaluated_at": latest_governance.get("timestamp") if latest_governance else None,
        },
        "summary": {
            "frameworks_in_scope": len(in_scope),
            "frameworks_evidence_complete": sum(
                1 for record in in_scope if record["status"] == "EVIDENCE_COMPLETE"
            ),
            "frameworks_with_gaps": sum(
                1 for record in in_scope if record["status"] == "GAPS_IDENTIFIED"
            ),
            "open_control_gaps": len(open_control_gaps),
            "high_or_critical_findings": sum(
                1
                for finding in finding_items
                if finding.get("severity") in {"HIGH", "CRITICAL"}
            ),
        },
        "open_control_gaps": open_control_gaps,
        "frameworks": frameworks,
    }


def _framework_record(framework: str, in_scope: bool) -> Dict[str, Any]:
    profile = next(
        (item for item in STANDARD_PROFILES.values() if item["name"] == framework),
        {"version": "unknown", "source_url": ""},
    )
    return {
        "in_scope": in_scope,
        "status": "PENDING",
        "version": profile["version"],
        "source_url": profile["source_url"],
        "applicable_controls": 0,
        "satisfied_controls": 0,
        "missing_controls": 0,
        "not_applicable_controls": 0,
        "coverage_percent": 0.0,
        "mapped_references": [],
        "control_evidence": [],
        "finding_evidence": [],
    }


def _add_control_evidence(
    frameworks: Dict[str, Dict[str, Any]], control: Dict[str, Any]
) -> None:
    status = control.get("status", "unknown")
    for framework_name, references in control.get("standards", {}).items():
        framework = _canonical_framework(framework_name)
        if framework not in frameworks:
            continue
        record = frameworks[framework]
        record["control_evidence"].append(
            {
                "control_id": control.get("id"),
                "title": control.get("title"),
                "status": status,
                "provided_evidence": list(control.get("provided_evidence", [])),
                "missing_evidence": list(control.get("missing_evidence", [])),
                "evidence_record_ids": list(
                    control.get("evidence_record_ids", [])
                ),
                "references": list(references),
                "reference_details": [
                    describe_framework_reference(framework, reference)
                    for reference in references
                ],
            }
        )
        record["mapped_references"].extend(references)
        if status == "not_applicable":
            record["not_applicable_controls"] += 1
        else:
            record["applicable_controls"] += 1
            if status == "satisfied":
                record["satisfied_controls"] += 1
            elif status == "missing":
                record["missing_controls"] += 1


def _add_finding_evidence(
    frameworks: Dict[str, Dict[str, Any]], finding: Dict[str, Any]
) -> None:
    for mapped in finding.get("mapping", {}).get("controls", []):
        framework = _canonical_framework(mapped.get("standard"))
        if framework not in frameworks:
            continue
        references = list(mapped.get("controls", []))
        frameworks[framework]["finding_evidence"].append(
            {
                "artifact_id": finding.get("artifact_id"),
                "timestamp": finding.get("timestamp"),
                "finding_type": finding.get("type"),
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score"),
                "references": references,
                "reference_details": [
                    describe_framework_reference(framework, reference)
                    for reference in references
                ],
            }
        )
        frameworks[framework]["mapped_references"].extend(references)


def _finalize_framework(record: Dict[str, Any], governance_evaluated: bool) -> None:
    applicable = record["applicable_controls"]
    satisfied = record["satisfied_controls"]
    record["coverage_percent"] = round((satisfied / applicable) * 100, 1) if applicable else 0.0
    record["mapped_references"] = sorted(set(record["mapped_references"]))

    if not record["in_scope"]:
        record["status"] = "OUT_OF_SCOPE"
    elif not governance_evaluated:
        record["status"] = "NO_EVALUATION"
    elif record["missing_controls"]:
        record["status"] = "GAPS_IDENTIFIED"
    elif applicable:
        record["status"] = "EVIDENCE_COMPLETE"
    else:
        record["status"] = "NO_APPLICABLE_CONTROLS"


def _declared_scope(latest_governance: Optional[Dict[str, Any]]) -> Set[str]:
    if not latest_governance:
        return set()
    scope = latest_governance.get("compliance_scope") or []
    if isinstance(scope, str):
        scope = [scope]
    return {
        framework
        for framework in (_canonical_framework(item) for item in scope)
        if framework in FRAMEWORKS
    }


def _canonical_framework(framework: Optional[str]) -> Optional[str]:
    if framework is None:
        return None
    return FRAMEWORK_ALIASES.get(framework, framework)

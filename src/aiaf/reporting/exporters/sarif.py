"""SARIF 2.1.0 export for AIAF security findings.

The Static Analysis Results Interchange Format (SARIF) is the standard
consumed by GitHub Advanced Security, VS Code, Azure DevOps, and most
modern security dashboards.  AIAF findings are exported as SARIF ``results``
so they can be uploaded to code-scanning or CI/CD pipelines.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
import time
from typing import Any, Dict, List, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "none": "none",
}

_SEVERITY_TO_CVSS = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.5",
    "info": "0.0",
    "none": "0.0",
}


def export_sarif(
    findings: List[Dict[str, Any]],
    tool_version: str = "0.2.0",
    invocation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert a list of AIAF findings to a SARIF 2.1.0 document.

    Parameters
    ----------
    findings:
        List of finding dicts.  Expected keys: ``type``, ``severity``,
        ``description`` / ``details``, ``id``, ``artifact_id``, ``score``,
        ``model_id`` (optional), ``framework_refs`` (optional).
    tool_version:
        AIAF version string to embed in the ``driver`` metadata.

    Returns
    -------
    dict
        A SARIF 2.1.0 JSON-serialisable document.
    """
    rules: Dict[str, Any] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        finding_type = finding.get("type", "unknown")
        rule_id = f"AIAF-{finding_type.upper().replace(' ', '-').replace('_', '-')}"
        severity = (finding.get("severity") or "none").lower()

        if rule_id not in rules:
            owasp_refs = finding.get("framework_refs", {}).get("owasp", [])
            atlas_refs = finding.get("framework_refs", {}).get("mitre_atlas", [])
            tags = owasp_refs + atlas_refs

            rules[rule_id] = {
                "id": rule_id,
                "name": finding_type.replace("_", " ").title(),
                "shortDescription": {"text": finding.get("description", finding_type)},
                "helpUri": "https://github.com/collinsmbwika/AI-Assurance-Framework",
                "properties": {
                    "security-severity": _SEVERITY_TO_CVSS.get(severity, "0.0"),
                    "tags": tags,
                },
            }

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(severity, "none"),
            "message": {
                "text": finding.get("description") or finding.get("details", "Security finding detected")
            },
            "properties": {
                "aiaf:findingId": finding.get("id", ""),
                "aiaf:artifactId": finding.get("artifact_id", ""),
                "aiaf:score": finding.get("score", 0),
            },
        }

        if finding.get("model_id"):
            result["locations"] = [
                {"logicalLocations": [{"fullyQualifiedName": finding["model_id"], "kind": "module"}]}
            ]

        results.append(result)

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Assurance Framework",
                        "version": tool_version,
                        "informationUri": "https://github.com/collinsmbwika/AI-Assurance-Framework",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": timestamp,
                        **({"correlationGuid": invocation_id} if invocation_id else {}),
                    }
                ],
            }
        ],
    }

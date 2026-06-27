"""Orchestration for focused agentic AI assurance evaluations."""

from datetime import datetime, timezone
from typing import Any

from ..analysis import assess_agent_risk_v2
from ..mapping.standards import map_finding_to_controls
from .risk_register_engine import RiskRegisterEngine


class AgenticAssuranceEngine:
    def __init__(self, datastore: object | None = None):
        self.datastore = datastore

    def evaluate(self, artifact: dict[str, Any]) -> dict[str, Any]:
        assessment = assess_agent_risk_v2(artifact)
        # The v2 scorer is uncertainty-aware: a finding is reportable only when
        # the agent is applicable and reaches MEDIUM severity or higher.
        suspicious = bool(assessment.get("applicable")) and assessment.get("suspicious", False)
        finding = {
            "type": "agent_risk",
            "risk_score": assessment["risk_score"],
            "severity": assessment["severity"],
            "indicators": assessment["indicators"],
            "detail": assessment,
        }
        finding["mapping"] = map_finding_to_controls(finding)
        record = {
            "artifact_id": artifact.get("id"),
            "timestamp": _utc_now(),
            "status": "NEEDS_REVIEW" if suspicious else "PASS",
            "assessment": assessment,
            "finding": finding,
            "risk_register": {"observed_risks": [], "observation_count": 0},
        }

        if self.datastore is not None:
            if suspicious:
                try:
                    observed_risks = RiskRegisterEngine(
                        self.datastore
                    ).observe_findings(
                        artifact.get("id"),
                        [finding],
                        observed_at=record["timestamp"],
                        remediation_sla=artifact.get("remediation_sla"),
                    )
                    record["risk_register"] = {
                        "observed_risks": observed_risks,
                        "observation_count": len(observed_risks),
                    }
                except Exception:
                    pass
            try:
                self.datastore.save_audit_log(
                    {
                        "event_type": "agentic_assurance_evaluation",
                        "artifact_id": artifact.get("id"),
                        "details": record,
                    }
                )
            except Exception:
                pass
            try:
                self.datastore.save_metric(
                    "agent_risk_score",
                    assessment["risk_score"],
                    {
                        "artifact_id": artifact.get("id"),
                        "severity": assessment["severity"],
                        "policy_profile": assessment.get("policy_profile"),
                    },
                )
            except Exception:
                pass
        return record


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

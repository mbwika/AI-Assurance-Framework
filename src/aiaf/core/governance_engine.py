"""Governance engine for evaluating AI artifacts against assurance controls."""
from datetime import datetime, timezone
from typing import Any

from ..mapping.control_catalog import evaluate_catalog_controls, summarize_control_evaluations
from ..mapping.standards import FRAMEWORKS
from .evidence_engine import approved_evidence, evidence_summary


class GovernanceEngine:
    def __init__(self, datastore: object | None = None):
        self.datastore = datastore

    def evaluate(self, artifact: dict[str, Any]) -> dict[str, Any]:
        timestamp = _utc_now()
        controls = evaluate_catalog_controls(artifact)
        evidence = self._evidence(artifact.get("id"))
        eligible_evidence = approved_evidence(evidence, timestamp)
        controls = _apply_evidence(controls, eligible_evidence)
        gaps = [control for control in controls if control["status"] == "missing"]
        summary = summarize_control_evaluations(controls)

        record = {
            "artifact_id": artifact.get("id"),
            "timestamp": timestamp,
            "compliance_scope": artifact.get("compliance_scope", []),
            "frameworks": FRAMEWORKS,
            "controls": controls,
            "gaps": gaps,
            "summary": summary,
            "status": "PASS" if not gaps else "NEEDS_REVIEW",
            "evidence": {
                **evidence_summary(evidence, timestamp),
                "applied_evidence_ids": sorted(
                    {
                        evidence_id
                        for control in controls
                        for evidence_id in control.get("evidence_record_ids", [])
                    }
                ),
            },
        }

        if self.datastore is not None:
            try:
                self.datastore.save_audit_log(
                    {
                        "event_type": "governance_evaluation",
                        "artifact_id": artifact.get("id"),
                        "details": record,
                    }
                )
            except Exception:
                pass

        return record

    def _evidence(self, artifact_id: str | None):
        if self.datastore is None or not artifact_id:
            return []
        list_evidence = getattr(self.datastore, "list_control_evidence", None)
        if not list_evidence:
            return []
        try:
            return list_evidence(limit=10000, artifact_id=str(artifact_id))
        except Exception:
            return []


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _apply_evidence(controls, evidence):
    by_control = {}
    for item in evidence:
        by_control.setdefault(item["control_id"], []).append(item)
    for control in controls:
        records = by_control.get(control["id"], [])
        control["evidence_record_ids"] = [item["id"] for item in records]
        if not records or control["status"] == "not_applicable":
            continue
        covered = {
            field for item in records for field in item.get("evidence_fields", [])
        }
        control["missing_evidence"] = [
            missing
            for missing in control["missing_evidence"]
            if not any(option in covered for option in missing.split(" or "))
        ]
        for field in sorted(covered):
            if field not in control["provided_evidence"]:
                control["provided_evidence"].append(field)
        if not control["missing_evidence"]:
            control["status"] = "satisfied"
    return controls

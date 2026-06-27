"""Lifecycle management for deduplicated assurance risks."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


RISK_STATUSES = {"OPEN", "IN_PROGRESS", "ACCEPTED", "RESOLVED"}
RISK_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ACTIONABLE_STATUSES = {"OPEN", "IN_PROGRESS"}


class RiskRegisterEngine:
    def __init__(self, datastore: object):
        self.datastore = datastore

    def observe_findings(
        self,
        artifact_id: Optional[str],
        findings: List[Dict[str, Any]],
        observed_at: Optional[str] = None,
        remediation_sla: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not artifact_id:
            raise ValueError("Risk observations require a non-empty artifact_id")
        timestamp = _normalize_datetime(observed_at) if observed_at else _utc_now()
        observed = []
        for finding in findings:
            finding_type = str(finding.get("type") or "unknown")
            indicators = finding.get("indicators") or [finding_type]
            for indicator_value in dict.fromkeys(str(value) for value in indicators):
                fingerprint = _fingerprint(artifact_id, finding_type, indicator_value)
                risk = {
                    "id": str(uuid.uuid4()),
                    "fingerprint": fingerprint,
                    "artifact_id": artifact_id,
                    "finding_type": finding_type,
                    "indicator": indicator_value,
                    "title": indicator_value.replace("_", " ").strip().title(),
                    "severity": _severity(finding.get("severity")),
                    "status": "OPEN",
                    "details": {
                        "risk_score": float(finding.get("risk_score", 0.0) or 0.0),
                        "mapping": finding.get("mapping", {}),
                        "source_observed_at": timestamp,
                    },
                    "first_seen_at": timestamp,
                    "last_seen_at": timestamp,
                    "occurrence_count": 1,
                    "owner": None,
                    "due_at": _sla_due_at(timestamp, _severity(finding.get("severity")), remediation_sla),
                    "resolution": None,
                    "updated_at": timestamp,
                }
                observed.append(self.datastore.upsert_risk_observation(risk))
        return observed

    def get(self, risk_id: str) -> Optional[Dict[str, Any]]:
        return self.datastore.get_risk(risk_id)

    def list(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        artifact_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        normalized_status = _choice(status, RISK_STATUSES, "status")
        normalized_severity = _choice(severity, RISK_SEVERITIES, "severity")
        return self.datastore.list_risks(
            limit=min(max(int(limit), 1), 1000),
            status=normalized_status,
            artifact_id=artifact_id,
            severity=normalized_severity,
        )

    def update(self, risk_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        current = self.datastore.get_risk(risk_id)
        if not current:
            return None

        selected = {
            key: changes[key]
            for key in ("status", "owner", "due_at", "resolution")
            if key in changes
        }
        if not selected:
            raise ValueError("No risk lifecycle changes were provided")
        if "status" in selected:
            selected["status"] = _choice(selected["status"], RISK_STATUSES, "status")
            if selected["status"] is None:
                raise ValueError("status cannot be empty")
        if "due_at" in selected and selected["due_at"]:
            selected["due_at"] = _normalize_datetime(selected["due_at"])
        for field in ("owner", "resolution"):
            if field in selected and selected[field] is not None:
                selected[field] = str(selected[field]).strip() or None

        next_status = selected.get("status", current["status"])
        next_owner = selected.get("owner", current.get("owner"))
        next_resolution = selected.get("resolution", current.get("resolution"))
        if next_status in {"ACCEPTED", "RESOLVED"} and not next_resolution:
            raise ValueError(f"{next_status} risks require a resolution rationale")
        if next_status != "OPEN" and not next_owner:
            raise ValueError(f"{next_status} risks require an owner")
        if next_status == "OPEN" and current["status"] in {"ACCEPTED", "RESOLVED"}:
            selected.setdefault("resolution", None)

        selected["updated_at"] = _utc_now()
        updated = self.datastore.update_risk(risk_id, selected)
        self.datastore.save_audit_log(
            {
                "event_type": "risk_register_updated",
                "artifact_id": current.get("artifact_id"),
                "details": {
                    "risk_id": risk_id,
                    "previous": {
                        key: current.get(key)
                        for key in ("status", "owner", "due_at", "resolution")
                    },
                    "current": {
                        key: updated.get(key)
                        for key in ("status", "owner", "due_at", "resolution")
                    },
                },
            }
        )
        summary = self.summary()
        self.datastore.save_metric(
            "open_risk_count",
            summary["actionable_risks"],
            {
                "active_risks": summary["active_risks"],
                "overdue_risks": summary["overdue_risks"],
            },
        )
        return updated

    def summary(self, as_of: Optional[str] = None) -> Dict[str, Any]:
        evaluated_at = _normalize_datetime(as_of) if as_of else _utc_now()
        risks = self.datastore.list_risks(limit=10000)
        actionable = [risk for risk in risks if risk.get("status") in ACTIONABLE_STATUSES]
        active = [risk for risk in risks if risk.get("status") != "RESOLVED"]
        overdue = [
            risk
            for risk in actionable
            if risk.get("due_at") and risk["due_at"] < evaluated_at
        ]
        unassigned_priority = [
            risk
            for risk in actionable
            if not risk.get("owner") and risk.get("severity") in {"HIGH", "CRITICAL"}
        ]
        return {
            "evaluated_at": evaluated_at,
            "total_risks": len(risks),
            "active_risks": len(active),
            "actionable_risks": len(actionable),
            "accepted_risks": sum(1 for risk in risks if risk.get("status") == "ACCEPTED"),
            "resolved_risks": sum(1 for risk in risks if risk.get("status") == "RESOLVED"),
            "overdue_risks": len(overdue),
            "unassigned_high_or_critical": len(unassigned_priority),
            "by_status": _count_by(risks, "status"),
            "by_severity": _count_by(risks, "severity"),
            "actionable_by_severity": _count_by(actionable, "severity"),
            "by_type": _count_by(risks, "finding_type"),
        }


def _fingerprint(
    artifact_id: Optional[str], finding_type: str, indicator: str
) -> str:
    identity = f"{artifact_id or 'unidentified'}|{finding_type}|{indicator}".lower()
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _choice(value: Any, choices: set, field: str) -> Optional[str]:
    if value in (None, ""):
        return None
    normalized = str(value).upper()
    if normalized not in choices:
        raise ValueError(f"Invalid {field}: {value}")
    return normalized


def _severity(value: Any) -> str:
    return _choice(value or "LOW", RISK_SEVERITIES, "severity") or "LOW"


def _normalize_datetime(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sla_due_at(
    observed_at: str,
    severity: str,
    remediation_sla: Optional[Dict[str, Any]],
) -> Optional[str]:
    if not isinstance(remediation_sla, dict):
        return None
    value = remediation_sla.get(f"{severity.lower()}_hours")
    if value is None:
        value = remediation_sla.get(severity) or remediation_sla.get(severity.lower())
    if isinstance(value, dict):
        value = value.get("hours")
    try:
        hours = float(value)
    except (TypeError, ValueError):
        return None
    if hours <= 0:
        return None
    baseline = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    return (baseline + timedelta(hours=hours)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _count_by(items: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        value = str(item.get(field) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts

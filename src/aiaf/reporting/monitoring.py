"""Continuous monitoring alert evaluation."""
from typing import Any


def evaluate_monitoring_alerts(report: dict[str, Any]) -> dict[str, Any]:
    """Evaluate assurance report evidence and return prioritized monitoring alerts."""
    alerts: list[dict[str, Any]] = []
    register = report.get("risk_register", {})
    if not register.get("total_risks"):
        alerts.extend(_risk_alerts(report.get("risk_posture", {})))
    alerts.extend(_risk_register_alerts(register))
    alerts.extend(_trend_alerts(report.get("continuous_monitoring", {})))
    alerts.extend(_schedule_alerts(report.get("continuous_monitoring", {})))
    alerts.extend(_trust_alerts(report.get("trustworthiness", {})))
    alerts.extend(_governance_alerts(report.get("governance", {})))
    alerts.extend(_governance_evidence_alerts(report.get("governance_evidence", {})))
    alerts.extend(_agentic_runtime_alerts(report.get("agentic_runtime", {})))
    alerts.extend(_supply_chain_alerts(report.get("supply_chain", {})))
    alerts.extend(_standards_alerts(report.get("standards_coverage", {})))

    alerts.sort(key=lambda alert: _severity_rank(alert["severity"]), reverse=True)
    return {
        "status": "OK" if not alerts else "ATTENTION_REQUIRED",
        "total_alerts": len(alerts),
        "by_severity": _count_by(alerts, "severity"),
        "alerts": alerts,
    }


def _risk_alerts(posture: dict[str, Any]) -> list[dict[str, Any]]:
    by_severity = posture.get("by_severity", {})
    alerts = []
    critical = int(by_severity.get("CRITICAL", 0) or 0)
    high = int(by_severity.get("HIGH", 0) or 0)
    if critical:
        alerts.append(
            _alert(
                "critical_findings_detected",
                "CRITICAL",
                f"{critical} critical security findings require immediate review.",
                {"critical_findings": critical},
            )
        )
    if high:
        alerts.append(
            _alert(
                "high_findings_detected",
                "HIGH",
                f"{high} high-severity security findings require mitigation tracking.",
                {"high_findings": high},
            )
        )
    return alerts


def _risk_register_alerts(register: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    actionable = register.get("actionable_by_severity", {})
    critical = int(actionable.get("CRITICAL", 0) or 0)
    high = int(actionable.get("HIGH", 0) or 0)
    overdue = int(register.get("overdue_risks", 0) or 0)
    unassigned = int(register.get("unassigned_high_or_critical", 0) or 0)
    if critical:
        alerts.append(
            _alert(
                "critical_managed_risks_open",
                "CRITICAL",
                f"{critical} critical managed risks require action.",
                {"critical_risks": critical},
            )
        )
    if high:
        alerts.append(
            _alert(
                "high_managed_risks_open",
                "HIGH",
                f"{high} high-severity managed risks require action.",
                {"high_risks": high},
            )
        )
    if overdue:
        alerts.append(
            _alert(
                "risk_remediation_overdue",
                "HIGH",
                f"{overdue} managed risks are past their remediation due date.",
                {"overdue_risks": overdue},
            )
        )
    if unassigned:
        alerts.append(
            _alert(
                "priority_risks_unassigned",
                "HIGH",
                f"{unassigned} high or critical risks do not have an owner.",
                {"unassigned_high_or_critical": unassigned},
            )
        )
    return alerts


def _trend_alerts(monitoring: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    if monitoring.get("trend") == "WORSENING":
        alerts.append(
            _alert(
                "risk_trend_worsening",
                "HIGH",
                "Average risk score is worsening across recent assessments.",
                {
                    "current_average": monitoring.get("current_average", 0.0),
                    "previous_average": monitoring.get("previous_average", 0.0),
                    "delta": monitoring.get("delta", 0.0),
                },
            )
        )
    # Robust statistical drift over the persisted risk_score history; a sustained
    # deterioration or stale series is a distinct, higher-confidence signal than
    # the coarse worsening label above.
    drift = monitoring.get("drift", {})
    if drift.get("status") in {"DETERIORATING", "STALE"} or drift.get("severity") in {"HIGH", "CRITICAL"}:
        alerts.append(
            _alert(
                "risk_drift_detected",
                "HIGH" if drift.get("severity") in {"HIGH", "CRITICAL"} else "MEDIUM",
                "Robust drift analysis detected sustained risk deterioration or stale metric history.",
                {
                    "status": drift.get("status"),
                    "severity": drift.get("severity"),
                    "risk_score": drift.get("risk_score"),
                    "most_drifted_artifact": drift.get("most_drifted_artifact"),
                    "scoring_version": drift.get("scoring_version"),
                },
            )
        )
    return alerts


def _schedule_alerts(monitoring: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    failed_runs = int(monitoring.get("failed_runs", 0) or 0)
    overdue = int(monitoring.get("overdue_schedules", 0) or 0)
    if failed_runs:
        alerts.append(
            _alert(
                "monitoring_runs_failed",
                "HIGH",
                f"{failed_runs} scheduled assurance runs failed.",
                {"failed_runs": failed_runs},
            )
        )
    if overdue:
        alerts.append(
            _alert(
                "assessment_schedules_overdue",
                "HIGH",
                f"{overdue} enabled assurance schedules are overdue.",
                {"overdue_schedules": overdue},
            )
        )
    return alerts


def _trust_alerts(trust: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    latest_score = float(trust.get("latest_score", 0.0) or 0.0)
    if trust.get("latest_level") == "NO_DATA":
        alerts.append(
            _alert(
                "missing_trustworthiness_metrics",
                "MEDIUM",
                "No trustworthiness metric has been recorded.",
                {},
            )
        )
    elif latest_score < 50.0:
        alerts.append(
            _alert(
                "low_trustworthiness_score",
                "CRITICAL",
                "Latest trustworthiness score is below 50.",
                {"latest_score": latest_score, "latest_level": trust.get("latest_level")},
            )
        )
    elif latest_score < 70.0:
        alerts.append(
            _alert(
                "moderate_trustworthiness_score",
                "HIGH",
                "Latest trustworthiness score is below the preferred operating threshold.",
                {"latest_score": latest_score, "latest_level": trust.get("latest_level")},
            )
        )

    if trust.get("trend") == "WORSENING":
        alerts.append(
            _alert(
                "trustworthiness_trend_worsening",
                "MEDIUM",
                "Trustworthiness score is trending downward.",
                {"delta": trust.get("delta", 0.0)},
            )
        )
    return alerts


def _governance_alerts(governance: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    gaps = governance.get("open_gaps", [])
    if gaps:
        alerts.append(
            _alert(
                "open_governance_gaps",
                "HIGH",
                f"{len(gaps)} governance control gaps require evidence or remediation.",
                {"open_gaps": len(gaps)},
            )
        )
    # Surface analyzer-backed reliability control gaps as a distinct, actionable
    # signal so bias/fairness and factual-reliability evidence is not buried in
    # the aggregate governance gap count.
    by_domain = governance.get("control_summary", {}).get("by_domain", {})
    missing_reliability = int(by_domain.get("Model Reliability", {}).get("missing", 0) or 0)
    if missing_reliability:
        alerts.append(
            _alert(
                "missing_model_reliability_controls",
                "MEDIUM",
                (
                    f"{missing_reliability} model-reliability controls "
                    "(bias/fairness, factual reliability) lack evidence."
                ),
                {"missing_model_reliability_controls": missing_reliability},
            )
        )
    return alerts


def _governance_evidence_alerts(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    pending = int(evidence.get("pending_evidence", 0) or 0)
    expired = int(evidence.get("expired_approved_evidence", 0) or 0)
    if expired:
        alerts.append(
            _alert(
                "approved_control_evidence_expired",
                "HIGH",
                f"{expired} approved governance evidence records have expired.",
                {"expired_approved_evidence": expired},
            )
        )
    if pending:
        alerts.append(
            _alert(
                "control_evidence_pending_review",
                "MEDIUM",
                f"{pending} governance evidence records await independent review.",
                {"pending_evidence": pending},
            )
        )
    return alerts


def _agentic_runtime_alerts(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    denied = int(runtime.get("denied_decisions", 0) or 0)
    approval_required = int(runtime.get("approval_required_decisions", 0) or 0)
    if denied:
        alerts.append(
            _alert(
                "agent_tool_invocations_denied",
                "HIGH",
                f"{denied} runtime agent tool requests were denied by policy.",
                {"denied_decisions": denied},
            )
        )
    if approval_required:
        alerts.append(
            _alert(
                "agent_tool_approvals_required",
                "MEDIUM",
                f"{approval_required} runtime agent tool requests required approval.",
                {"approval_required_decisions": approval_required},
            )
        )
    return alerts


def _supply_chain_alerts(supply_chain: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    supply_chain_findings = int(supply_chain.get("supply_chain_findings", 0) or 0)
    if supply_chain_findings:
        alerts.append(
            _alert(
                "supply_chain_findings_detected",
                "HIGH",
                f"{supply_chain_findings} supply-chain findings require review.",
                {"supply_chain_findings": supply_chain_findings},
            )
        )

    registered = int(supply_chain.get("registered_models", 0) or 0)
    advisory_count = int(supply_chain.get("vulnerability_advisories", 0) or 0)
    feed_status = supply_chain.get("advisory_feed_status", "UNVERIFIED")
    if feed_status == "STALE":
        alerts.append(
            _alert(
                "vulnerability_advisory_feeds_stale",
                "HIGH",
                "One or more authenticated vulnerability advisory feeds have expired.",
                {
                    "stale_advisory_feeds": supply_chain.get(
                        "stale_advisory_feeds", 0
                    )
                },
            )
        )
    elif feed_status == "MIXED":
        alerts.append(
            _alert(
                "vulnerability_advisory_catalog_mixed_trust",
                "HIGH",
                "The vulnerability catalog mixes authenticated and unverified advisory records.",
                {
                    "unverified_advisory_records": supply_chain.get(
                        "unverified_advisory_records", 0
                    )
                },
            )
        )
    elif feed_status == "UNVERIFIED" and (registered or advisory_count):
        alerts.append(
            _alert(
                "vulnerability_advisory_feed_unverified",
                "HIGH",
                "Dependency intelligence is not backed by an authenticated advisory feed.",
                {"advisory_records": advisory_count},
            )
        )
    if registered:
        missing_training = registered - int(supply_chain.get("models_with_training_artifacts", 0) or 0)
        missing_pipeline = registered - int(supply_chain.get("models_with_deployment_pipeline", 0) or 0)
        missing_attestations = registered - int(
            supply_chain.get("models_with_provenance_attestations", 0) or 0
        )
        missing_scans = registered - int(
            supply_chain.get("models_with_vulnerability_scans", 0) or 0
        )
        if missing_training:
            alerts.append(
                _alert(
                    "missing_training_artifact_evidence",
                    "MEDIUM",
                    f"{missing_training} registered models lack training artifact evidence.",
                    {"models_missing_training_artifacts": missing_training},
                )
            )
        if missing_pipeline:
            alerts.append(
                _alert(
                    "missing_deployment_pipeline_evidence",
                    "MEDIUM",
                    f"{missing_pipeline} registered models lack deployment pipeline evidence.",
                    {"models_missing_deployment_pipeline": missing_pipeline},
                )
            )
        if missing_attestations:
            alerts.append(
                _alert(
                    "missing_provenance_attestations",
                    "MEDIUM",
                    f"{missing_attestations} registered models lack signed provenance attestations.",
                    {"models_missing_provenance_attestations": missing_attestations},
                )
            )
        if missing_scans:
            alerts.append(
                _alert(
                    "missing_dependency_vulnerability_scans",
                    "HIGH",
                    f"{missing_scans} registered models lack dependency vulnerability scan evidence.",
                    {"models_missing_vulnerability_scans": missing_scans},
                )
            )
    known_matches = int(supply_chain.get("known_vulnerability_matches", 0) or 0)
    scan_statuses = supply_chain.get("vulnerability_scans_by_status", {})
    no_data_scans = int(scan_statuses.get("NO_ADVISORY_DATA", 0) or 0)
    partial_scans = int(scan_statuses.get("PARTIAL", 0) or 0)
    if known_matches:
        alerts.append(
            _alert(
                "known_dependency_vulnerabilities",
                "CRITICAL",
                f"{known_matches} dependency vulnerability matches require remediation.",
                {
                    "known_vulnerability_matches": known_matches,
                    "affected_models": supply_chain.get(
                        "models_with_known_vulnerabilities", 0
                    ),
                },
            )
        )
    if partial_scans:
        alerts.append(
            _alert(
                "dependency_vulnerability_scans_partial",
                "HIGH",
                f"{partial_scans} model scans contain dependencies without exact versions.",
                {"partial_scans": partial_scans},
            )
        )
    if no_data_scans:
        alerts.append(
            _alert(
                "vulnerability_scans_without_advisory_data",
                "HIGH",
                f"{no_data_scans} model scans ran without active advisory data.",
                {"scans_without_advisory_data": no_data_scans},
            )
        )
    elif registered and not int(
        supply_chain.get("active_vulnerability_advisories", 0) or 0
    ):
        alerts.append(
            _alert(
                "vulnerability_advisory_catalog_empty",
                "HIGH",
                "No dependency vulnerability advisories are available for registered model scans.",
                {},
            )
        )
    return alerts


def _standards_alerts(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    uncovered = coverage.get("uncovered_frameworks", [])
    if not uncovered:
        return []
    return [
        _alert(
            "standards_coverage_gap",
            "LOW",
            "One or more configured standards have no mapped evidence in the current report.",
            {"uncovered_frameworks": uncovered},
        )
    ]


def _alert(alert_id: str, severity: str, message: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": alert_id,
        "severity": severity,
        "message": message,
        "evidence": evidence,
    }


def _count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(field) or "UNKNOWN"
        counts[value] = counts.get(value, 0) + 1
    return counts


def _severity_rank(severity: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 0)

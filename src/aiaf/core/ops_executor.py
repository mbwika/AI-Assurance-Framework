"""Continuous Security Operations execution helpers.

Turns stored Phase D schedules into real work: anomaly scans, vulnerability
scans, report snapshots, red-team runs, and telemetry batch ingest. The
executor is intentionally synchronous so it can be called from an API route,
background loop, or external worker without duplicating schedule semantics.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from ..analysis.telemetry_ingest import detect_anomalies, ingest_event
from .incident_manager import create_incident
from .ops_scheduler import (
    JOB_ANOMALY_SCAN,
    JOB_RED_TEAM,
    JOB_SNAPSHOT,
    JOB_TELEMETRY_INGEST,
    JOB_VULN_SCAN,
    OUTCOME_FAILURE,
    OUTCOME_SKIPPED,
    OUTCOME_SUCCESS,
    due_schedules,
    get_schedule,
    mark_job_run,
)
from .redteam_engine import run_redteam
from .report_snapshot_engine import AssuranceReportSnapshotEngine
from .vulnerability_engine import VulnerabilityIntelligenceEngine

EXECUTOR_VERSION = "1.0"
_TELEMETRY_EVENT_ALIASES = {
    "LATENCY_MS": "LATENCY",
    "LATENCY": "LATENCY",
    "ERROR_RATE": "ERROR_RATE",
    "REFUSAL_RATE": "REFUSAL_RATE",
    "TOKEN_USAGE": "TOKEN_USAGE",
    "INJECTION_ATTEMPT": "INJECTION_ATTEMPT",
    "POLICY_VIOLATION": "POLICY_VIOLATION",
}


class OpsExecutorError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execute_schedule(schedule_id: str, store: Any) -> dict[str, Any]:
    schedule = get_schedule(schedule_id, store)
    if not schedule:
        raise OpsExecutorError(f"Schedule '{schedule_id}' not found.")

    job_type = schedule.get("job_type")
    target_id = schedule.get("target_id")
    config = schedule.get("config") or {}

    try:
        if job_type == JOB_ANOMALY_SCAN:
            result = _run_anomaly_scan(target_id, config, store)
        elif job_type == JOB_VULN_SCAN:
            result = _run_vulnerability_scan(target_id, config, store)
        elif job_type == JOB_RED_TEAM:
            result = _run_redteam(target_id, config, store)
        elif job_type == JOB_SNAPSHOT:
            result = _run_snapshot(target_id, config, store)
        elif job_type == JOB_TELEMETRY_INGEST:
            result = _run_telemetry_ingest(target_id, config, store)
        else:
            raise OpsExecutorError(f"Unsupported job_type '{job_type}'.")
    except Exception as exc:
        mark_job_run(
            schedule_id,
            store,
            outcome=OUTCOME_FAILURE,
            details={"error": str(exc), "executor_version": EXECUTOR_VERSION},
        )
        raise

    outcome = OUTCOME_SUCCESS if result.get("status") != "SKIPPED" else OUTCOME_SKIPPED
    updated = mark_job_run(
        schedule_id,
        store,
        outcome=outcome,
        details={"status": result.get("status"), "executor_version": EXECUTOR_VERSION},
    )
    return {
        "executor_version": EXECUTOR_VERSION,
        "schedule_id": schedule_id,
        "job_type": job_type,
        "target_id": target_id,
        "result": result,
        "schedule": updated,
        "executed_at": _utc_now(),
    }


def execute_due_schedules(
    store: Any,
    *,
    job_type: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    due = due_schedules(store, job_type=job_type)
    if limit is not None:
        due = due[: max(int(limit), 0)]
    results = []
    errors = []
    for schedule in due:
        schedule_id = schedule.get("schedule_id")
        try:
            results.append(execute_schedule(str(schedule_id), store))
        except Exception as exc:
            errors.append({"schedule_id": schedule_id, "error": str(exc)})
    return {
        "executor_version": EXECUTOR_VERSION,
        "due_count": len(due),
        "executed_count": len(results),
        "error_count": len(errors),
        "results": results,
        "errors": errors,
        "executed_at": _utc_now(),
    }


def _run_anomaly_scan(model_id: str, config: dict[str, Any], store: Any) -> dict[str, Any]:
    window_minutes = int(config.get("window_minutes") or 60)
    anomalies = detect_anomalies(model_id, store, window_minutes=window_minutes)
    if (config.get("create_incident", True) and
            anomalies.get("status") in {"ANOMALY_DETECTED", "CRITICAL"}):
        create_incident(
            incident_id=f"ops-anomaly-{uuid.uuid4().hex[:12]}",
            title=f"Telemetry anomaly detected for {model_id}",
            severity="HIGH" if anomalies.get("status") == "CRITICAL" else "MEDIUM",
            source="ops_executor",
            model_id=model_id,
            store=store,
            description="Scheduled anomaly scan detected abnormal telemetry behavior.",
            findings=anomalies.get("findings") or [],
            evidence_origin="LOCALLY_OBSERVED",
            tags=["telemetry", "scheduled", "anomaly"],
        )
    return anomalies


def _run_vulnerability_scan(model_id: str, config: dict[str, Any], store: Any) -> dict[str, Any]:
    result = VulnerabilityIntelligenceEngine(store).scan_model(model_id)
    if not result:
        return {"status": "SKIPPED", "reason": "model_not_found", "model_id": model_id}
    if config.get("create_incident", True):
        matches = result.get("matches") or []
        high_or_critical = [
            item for item in matches
            if str(item.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
        ]
        if high_or_critical:
            create_incident(
                incident_id=f"ops-vuln-{uuid.uuid4().hex[:12]}",
                title=f"Dependency vulnerability findings for {model_id}",
                severity="HIGH",
                source="ops_executor",
                model_id=model_id,
                store=store,
                description="Scheduled vulnerability scan found HIGH/CRITICAL advisory matches.",
                findings=high_or_critical[:25],
                evidence_origin="LOCALLY_OBSERVED",
                tags=["vulnerability", "scheduled", "supply-chain"],
            )
    return result


def _run_redteam(model_id: str, config: dict[str, Any], store: Any) -> dict[str, Any]:
    endpoint_url = str(config.get("endpoint_url") or "").strip()
    if not endpoint_url:
        return {"status": "SKIPPED", "reason": "missing_endpoint_url", "model_id": model_id}
    result = run_redteam(
        endpoint_url,
        backend=str(config.get("backend") or "garak"),
        api_key=config.get("endpoint_api_key"),
        model_name=str(config.get("model_name") or "default"),
        depth=str(config.get("depth") or "quick"),
        timeout=int(config.get("timeout") or 600),
    )

    record = store.get_model(model_id)
    if record:
        metadata = dict(record.get("metadata") or {})
        metadata["redteam_results"] = result
        record["metadata"] = metadata
        store.save_model(record)

    failed = int(result.get("probe_failures") or 0)
    if config.get("create_incident", True) and failed > 0:
        create_incident(
            incident_id=f"ops-redteam-{uuid.uuid4().hex[:12]}",
            title=f"Red-team findings for {model_id}",
            severity="HIGH" if failed >= 3 else "MEDIUM",
            source="ops_executor",
            model_id=model_id,
            store=store,
            description="Scheduled red-team run reported probe failures.",
            findings=result.get("findings") or [],
            evidence_origin="LOCALLY_OBSERVED",
            tags=["redteam", "scheduled"],
        )
    return result


def _run_snapshot(target_id: str, config: dict[str, Any], store: Any) -> dict[str, Any]:
    engine = AssuranceReportSnapshotEngine(
        store,
        signing_key=config.get("signing_key"),
        key_id=str(config.get("key_id") or "ops-scheduler"),
        signing_private_key_pem=config.get("signing_private_key_pem"),
        verification_public_key_pem=config.get("verification_public_key_pem"),
    )
    scope_type = str(config.get("scope_type") or "MODEL").upper()
    kwargs: dict[str, Any] = {
        "created_by": str(config.get("created_by") or "ops-scheduler"),
        "sign": bool(config.get("sign", False)),
    }
    if scope_type == "REGISTRANT":
        kwargs["registered_by"] = str(config.get("registered_by") or target_id)
    elif scope_type == "ARTIFACT":
        kwargs["artifact_id"] = str(config.get("artifact_id") or target_id)
    else:
        kwargs["model_id"] = str(config.get("model_id") or target_id)
    snapshot = engine.create(**kwargs)
    return {"status": "COMPLETED", "snapshot": snapshot}


def _run_telemetry_ingest(model_id: str, config: dict[str, Any], store: Any) -> dict[str, Any]:
    events = list(config.get("events") or [])
    if not events:
        return {"status": "SKIPPED", "reason": "no_events_supplied", "model_id": model_id}
    accepted = []
    for event in events:
        event_type = _TELEMETRY_EVENT_ALIASES.get(
            str(event.get("event_type") or "").upper().strip(),
            str(event.get("event_type") or "").upper().strip(),
        )
        accepted.append(
            ingest_event(
                model_id=str(event.get("model_id") or model_id),
                event_type=event_type,
                value=float(event.get("value") or 0.0),
                store=store,
                metadata=event.get("metadata"),
                timestamp=event.get("timestamp"),
            )
        )
    return {"status": "COMPLETED", "ingested_count": len(accepted), "events": accepted}

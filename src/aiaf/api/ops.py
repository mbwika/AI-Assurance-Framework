"""Continuous Security Operations API.

Provides REST endpoints for Phase D: scheduling, telemetry ingestion,
anomaly detection, incident lifecycle, SIEM export, and remediation tracking.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .models import get_api_key, get_store
from ..core.ops_scheduler import (
    OpsSchedulerError,
    create_schedule, get_schedule, list_schedules,
    pause_schedule, resume_schedule, delete_schedule,
    mark_job_run, due_schedules,
    JOB_TYPES, SCHEDULE_TYPES, OUTCOME_VALUES,
)
from ..core.ops_executor import (
    OpsExecutorError,
    execute_schedule,
    execute_due_schedules,
)
from ..analysis.telemetry_ingest import (
    TelemetryIngestError,
    ingest_event, get_window_summary, list_events, detect_anomalies,
    EVENT_TYPES,
)
from ..core.incident_manager import (
    IncidentError,
    create_incident, get_incident, list_incidents,
    update_incident_state, add_incident_note, snapshot_incident,
)
from ..core.siem_export import SiemExportError, export_batch, EXPORT_FORMATS
from ..core.remediation_tracker import (
    RemediationError,
    create_remediation, get_remediation, list_remediations,
    update_remediation_status, link_to_incident,
    ACTION_TYPES, REMEDIATION_STATUSES,
)

router = APIRouter(prefix="/v1/ops", tags=["ops"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class CreateScheduleRequest(BaseModel):
    schedule_id: str
    job_type: str
    target_id: str
    schedule_type: str
    interval_seconds: Optional[int] = None
    cron_time: Optional[str] = None
    cron_day: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class MarkRunRequest(BaseModel):
    outcome: str = "SUCCESS"
    details: Optional[Dict[str, Any]] = None


class IngestEventRequest(BaseModel):
    model_id: str
    event_type: str
    value: float
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class CreateIncidentRequest(BaseModel):
    incident_id: str
    title: str
    severity: str
    source: str
    model_id: str
    description: Optional[str] = None
    findings: Optional[List[Dict[str, Any]]] = None
    evidence_origin: Optional[str] = None
    tags: Optional[List[str]] = None


class UpdateStateRequest(BaseModel):
    new_state: str
    note: Optional[str] = None


class AddNoteRequest(BaseModel):
    note: str
    author: Optional[str] = None


class SiemExportRequest(BaseModel):
    incident_ids: Optional[List[str]] = None
    export_format: str = "JSON"
    max_records: int = Field(default=1000, ge=1, le=10000)


class CreateRemediationRequest(BaseModel):
    remediation_id: str
    incident_id: str
    action_type: str
    description: str
    model_id: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None


class UpdateRemediationStatusRequest(BaseModel):
    new_status: str
    resolution_note: Optional[str] = None


class LinkIncidentRequest(BaseModel):
    incident_id: str


class RunDueSchedulesRequest(BaseModel):
    job_type: Optional[str] = None
    limit: Optional[int] = Field(default=None, ge=1, le=500)


# ── Scheduler routes ───────────────────────────────────────────────────────────

@router.post("/schedules")
def api_create_schedule(req: CreateScheduleRequest, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        return create_schedule(
            req.schedule_id, req.job_type, req.target_id, req.schedule_type, store,
            interval_seconds=req.interval_seconds, cron_time=req.cron_time,
            cron_day=req.cron_day, config=req.config,
        )
    except OpsSchedulerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/schedules")
def api_list_schedules(
    job_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return list_schedules(store, job_type=job_type, status=status, limit=limit)


@router.get("/schedules/due")
def api_due_schedules(job_type: Optional[str] = None, store=Depends(get_store), _=Depends(get_api_key)):
    return due_schedules(store, job_type=job_type)


@router.get("/schedules/{schedule_id}")
def api_get_schedule(schedule_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    result = get_schedule(schedule_id, store)
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.post("/schedules/{schedule_id}/pause")
def api_pause_schedule(schedule_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    result = pause_schedule(schedule_id, store)
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.post("/schedules/{schedule_id}/resume")
def api_resume_schedule(schedule_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    result = resume_schedule(schedule_id, store)
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.delete("/schedules/{schedule_id}")
def api_delete_schedule(schedule_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    if not delete_schedule(schedule_id, store):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"deleted": True}


@router.post("/schedules/{schedule_id}/mark-run")
def api_mark_run(schedule_id: str, req: MarkRunRequest, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        result = mark_job_run(schedule_id, store, outcome=req.outcome, details=req.details)
    except OpsSchedulerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.post("/schedules/{schedule_id}/execute")
def api_execute_schedule(schedule_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        return execute_schedule(schedule_id, store)
    except OpsExecutorError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/schedules/execute-due")
def api_execute_due_schedules(
    req: RunDueSchedulesRequest,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    try:
        return execute_due_schedules(store, job_type=req.job_type, limit=req.limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Telemetry routes ───────────────────────────────────────────────────────────

@router.post("/telemetry/events")
def api_ingest_event(req: IngestEventRequest, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        return ingest_event(
            req.model_id, req.event_type, req.value, store,
            metadata=req.metadata, timestamp=req.timestamp,
        )
    except TelemetryIngestError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/telemetry/{model_id}/{event_type}/summary")
def api_window_summary(
    model_id: str,
    event_type: str,
    window_minutes: int = 60,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return get_window_summary(model_id, event_type, store, window_minutes=window_minutes)


@router.get("/telemetry/{model_id}/{event_type}/events")
def api_list_events(
    model_id: str,
    event_type: str,
    limit: int = 100,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return list_events(model_id, event_type, store, limit=limit)


@router.get("/telemetry/{model_id}/anomalies")
def api_detect_anomalies(
    model_id: str,
    window_minutes: int = 60,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return detect_anomalies(model_id, store, window_minutes=window_minutes)


# ── Incident routes ────────────────────────────────────────────────────────────

@router.post("/incidents")
def api_create_incident(req: CreateIncidentRequest, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        return create_incident(
            req.incident_id, req.title, req.severity, req.source, req.model_id, store,
            description=req.description, findings=req.findings,
            evidence_origin=req.evidence_origin, tags=req.tags,
        )
    except IncidentError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/incidents")
def api_list_incidents(
    severity: Optional[str] = None,
    state: Optional[str] = None,
    model_id: Optional[str] = None,
    limit: int = 50,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return list_incidents(store, severity=severity, state=state, model_id=model_id, limit=limit)


@router.get("/incidents/{incident_id}")
def api_get_incident(incident_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    result = get_incident(incident_id, store)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.post("/incidents/{incident_id}/state")
def api_update_state(
    incident_id: str, req: UpdateStateRequest, store=Depends(get_store), _=Depends(get_api_key)
):
    try:
        return update_incident_state(incident_id, req.new_state, store, note=req.note)
    except IncidentError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/incidents/{incident_id}/notes")
def api_add_note(
    incident_id: str, req: AddNoteRequest, store=Depends(get_store), _=Depends(get_api_key)
):
    try:
        return add_incident_note(incident_id, req.note, store, author=req.author)
    except IncidentError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/incidents/{incident_id}/snapshot")
def api_snapshot_incident(incident_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    try:
        return snapshot_incident(incident_id, store)
    except IncidentError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── SIEM export routes ─────────────────────────────────────────────────────────

@router.post("/siem/export")
def api_siem_export(req: SiemExportRequest, store=Depends(get_store), _=Depends(get_api_key)):
    if req.incident_ids:
        incidents = []
        for iid in req.incident_ids:
            inc = get_incident(iid, store)
            if inc:
                incidents.append(inc)
    else:
        incidents = list_incidents(store, limit=req.max_records)

    try:
        return export_batch(incidents, req.export_format, max_records=req.max_records)
    except SiemExportError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Remediation routes ─────────────────────────────────────────────────────────

@router.post("/remediations")
def api_create_remediation(
    req: CreateRemediationRequest, store=Depends(get_store), _=Depends(get_api_key)
):
    try:
        return create_remediation(
            req.remediation_id, req.incident_id, req.action_type, req.description, store,
            model_id=req.model_id, assigned_to=req.assigned_to, due_date=req.due_date,
        )
    except RemediationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/remediations")
def api_list_remediations(
    incident_id: Optional[str] = None,
    model_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    return list_remediations(store, incident_id=incident_id, model_id=model_id, status=status, limit=limit)


@router.get("/remediations/{remediation_id}")
def api_get_remediation(remediation_id: str, store=Depends(get_store), _=Depends(get_api_key)):
    result = get_remediation(remediation_id, store)
    if not result:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return result


@router.post("/remediations/{remediation_id}/status")
def api_update_remediation_status(
    remediation_id: str,
    req: UpdateRemediationStatusRequest,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    try:
        return update_remediation_status(
            remediation_id, req.new_status, store, resolution_note=req.resolution_note
        )
    except RemediationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/remediations/{remediation_id}/link")
def api_link_incident(
    remediation_id: str,
    req: LinkIncidentRequest,
    store=Depends(get_store),
    _=Depends(get_api_key),
):
    try:
        return link_to_incident(remediation_id, req.incident_id, store)
    except RemediationError as e:
        raise HTTPException(status_code=400, detail=str(e))

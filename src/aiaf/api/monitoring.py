"""Continuous assurance schedule and run APIs."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core import MonitoringEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/monitoring", tags=["monitoring"])


class ScheduleCreate(BaseModel):
    artifact: dict[str, Any]
    interval_seconds: int = Field(default=3600, ge=1)
    enabled: bool = True
    start_at: str | None = None


class ScheduleUpdate(BaseModel):
    artifact: dict[str, Any] | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    enabled: bool | None = None
    next_run_at: str | None = None


class DueRunRequest(BaseModel):
    as_of: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)


@router.post("/schedules")
def create_monitoring_schedule(
    request: ScheduleCreate, api_key: str = Depends(get_api_key)
):
    try:
        return MonitoringEngine(get_store()).create_schedule(
            request.artifact,
            interval_seconds=request.interval_seconds,
            enabled=request.enabled,
            start_at=request.start_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/schedules")
def list_monitoring_schedules(
    limit: int = 100,
    enabled: bool | None = None,
    api_key: str = Depends(get_api_key),
):
    return {
        "schedules": MonitoringEngine(get_store()).list_schedules(
            limit=min(max(limit, 1), 1000), enabled=enabled
        )
    }


@router.patch("/schedules/{schedule_id}")
def update_monitoring_schedule(
    schedule_id: str,
    request: ScheduleUpdate,
    api_key: str = Depends(get_api_key),
):
    try:
        schedule = MonitoringEngine(get_store()).update_schedule(
            schedule_id,
            enabled=request.enabled,
            interval_seconds=request.interval_seconds,
            artifact=request.artifact,
            next_run_at=request.next_run_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not schedule:
        raise HTTPException(status_code=404, detail="Monitoring schedule not found")
    return schedule


@router.post("/run-due")
def run_due_assessments(
    request: DueRunRequest, api_key: str = Depends(get_api_key)
):
    try:
        return MonitoringEngine(get_store()).run_due(
            as_of=request.as_of, limit=request.limit
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/schedules/{schedule_id}/run")
def run_monitoring_schedule(
    schedule_id: str, api_key: str = Depends(get_api_key)
):
    run = MonitoringEngine(get_store()).run_schedule(schedule_id)
    if not run:
        raise HTTPException(status_code=404, detail="Monitoring schedule not found")
    return run


@router.get("/runs")
def list_monitoring_runs(
    limit: int = 100,
    schedule_id: str | None = None,
    api_key: str = Depends(get_api_key),
):
    return {
        "runs": MonitoringEngine(get_store()).list_runs(
            limit=min(max(limit, 1), 1000), schedule_id=schedule_id
        )
    }

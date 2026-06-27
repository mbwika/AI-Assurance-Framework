"""Adoption-Velocity Anomaly Detection API.

REST endpoints:
  POST /v1/adoption-velocity/{artifact_id}/events     — record adoption event
  PUT  /v1/adoption-velocity/{artifact_id}/baseline   — set velocity baseline
  GET  /v1/adoption-velocity/{artifact_id}/profile    — get velocity profile
  GET  /v1/adoption-velocity/{artifact_id}/anomalies  — detect anomalies
  GET  /v1/adoption-velocity/at-risk                  — list at-risk artifacts
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..analysis.adoption_velocity import (
    ADOPTION_VELOCITY_VERSION,
    DEFAULT_COLD_START_HOURS,
    DEFAULT_COLD_START_THRESHOLD,
    DEFAULT_SPIKE_MULTIPLIER,
    DEFAULT_VELOCITY_WINDOW_HOURS,
    EVENT_TYPES,
    VELOCITY_RISK_ELEVATED,
    AdoptionVelocityError,
    detect_velocity_anomaly,
    get_velocity_profile,
    list_at_risk_artifacts,
    record_adoption_event,
    set_velocity_baseline,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/adoption-velocity", tags=["adoption-velocity"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class RecordEventRequest(BaseModel):
    event_type: str
    count: int = Field(1, ge=1)
    source: str | None = None
    region: str | None = None
    occurred_at: str | None = None
    attributes: dict[str, Any] | None = None


class SetBaselineRequest(BaseModel):
    baseline_weight_per_hour: float = Field(..., ge=0.0)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/{artifact_id}/events", status_code=201)
def record_event(
    artifact_id: str,
    req: RecordEventRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return record_adoption_event(
            artifact_id, req.event_type, store,
            count=req.count, source=req.source, region=req.region,
            occurred_at=req.occurred_at, attributes=req.attributes,
        )
    except AdoptionVelocityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/{artifact_id}/baseline")
def set_baseline(
    artifact_id: str,
    req: SetBaselineRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return set_velocity_baseline(artifact_id, req.baseline_weight_per_hour, store)
    except AdoptionVelocityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{artifact_id}/profile")
def get_profile(
    artifact_id: str,
    window_hours: float = Query(DEFAULT_VELOCITY_WINDOW_HOURS, ge=0.1, le=168.0),
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    profile = get_velocity_profile(artifact_id, store, window_hours=window_hours)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"No adoption events found for {artifact_id!r}.")
    return profile


@router.get("/{artifact_id}/anomalies")
def detect_anomalies(
    artifact_id: str,
    spike_multiplier: float = Query(DEFAULT_SPIKE_MULTIPLIER, ge=1.0),
    cold_start_hours: float = Query(DEFAULT_COLD_START_HOURS, ge=1.0),
    cold_start_threshold: float = Query(DEFAULT_COLD_START_THRESHOLD, ge=1.0),
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return detect_velocity_anomaly(
        artifact_id, store,
        spike_multiplier=spike_multiplier,
        cold_start_hours=cold_start_hours,
        cold_start_threshold=cold_start_threshold,
    )


@router.get("/at-risk")
def get_at_risk(
    min_risk: str = Query(VELOCITY_RISK_ELEVATED),
    limit: int = Query(50, ge=1, le=200),
    spike_multiplier: float = Query(DEFAULT_SPIKE_MULTIPLIER),
    cold_start_hours: float = Query(DEFAULT_COLD_START_HOURS),
    cold_start_threshold: float = Query(DEFAULT_COLD_START_THRESHOLD),
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_at_risk_artifacts(
        store, min_risk=min_risk, limit=limit,
        spike_multiplier=spike_multiplier,
        cold_start_hours=cold_start_hours,
        cold_start_threshold=cold_start_threshold,
    )


@router.get("/event-types")
def list_event_types(_: str = Depends(get_api_key)):
    return {
        "event_types": sorted(EVENT_TYPES),
        "adoption_velocity_version": ADOPTION_VELOCITY_VERSION,
    }

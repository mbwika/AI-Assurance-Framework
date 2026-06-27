"""System-Level AI Red Team Orchestrator API.

REST endpoints:
  POST /v1/system-redteam/run           — run cross-layer red team assessment
  GET  /v1/system-redteam/layers        — list available assessment layers
  GET  /v1/system-redteam/scenarios     — list available cross-layer scenarios
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..core.system_redteam import (
    ALL_LAYERS,
    SCENARIOS,
    SystemRedTeamError,
    run_system_redteam,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/system-redteam", tags=["system-redteam"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class SystemRedTeamRequest(BaseModel):
    system_id: str
    layers: list[str] | None = None
    system_config: dict[str, Any] | None = None
    model_ids: list[str] | None = None
    agent_ids: list[str] | None = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/run")
def run_system_redteam_route(
    req: SystemRedTeamRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return run_system_redteam(
            req.system_id, store,
            layers=req.layers,
            system_config=req.system_config,
            model_ids=req.model_ids,
            agent_ids=req.agent_ids,
        )
    except SystemRedTeamError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/layers")
def get_available_layers(
    _: str = Depends(get_api_key),
):
    return {"layers": sorted(ALL_LAYERS)}


@router.get("/scenarios")
def get_available_scenarios(
    _: str = Depends(get_api_key),
):
    return {"scenarios": sorted(SCENARIOS)}

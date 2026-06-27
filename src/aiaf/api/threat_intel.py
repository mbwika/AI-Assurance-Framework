"""AI Threat Intelligence API.

REST endpoints:
  GET  /v1/threat-intel/techniques              — list all threat techniques
  GET  /v1/threat-intel/techniques/{id}         — get one technique
  POST /v1/threat-intel/techniques              — ingest a custom technique
  GET  /v1/threat-intel/landscape               — aggregate threat landscape
  POST /v1/threat-intel/correlate/model         — correlate threats to a model
  POST /v1/threat-intel/correlate/agent         — correlate threats to an agent
  POST /v1/threat-intel/correlate/tool          — correlate threats to a tool
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..registry.ai_threat_intel import (
    SOURCE_CUSTOM,
    ThreatIntelError,
    build_threat_landscape,
    correlate_agent,
    correlate_model,
    correlate_tool,
    get_threat,
    ingest_threat,
    list_threats,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/threat-intel", tags=["threat-intelligence"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class IngestThreatRequest(BaseModel):
    technique_id: str
    name: str
    category: str
    description: str
    affected_asset_types: list[str]
    severity: str
    owasp_llm_id: str | None = None
    mitre_atlas_id: str | None = None
    capability_triggers: list[str] | None = None
    recommended_controls: list[str] | None = None
    source: str = SOURCE_CUSTOM


class CorrelateModelRequest(BaseModel):
    model_id: str
    metadata: dict[str, Any] | None = None
    top_n: int | None = None


class CorrelateAgentRequest(BaseModel):
    agent_id: str
    metadata: dict[str, Any] | None = None
    top_n: int | None = None


class CorrelateToolRequest(BaseModel):
    tool_id: str
    metadata: dict[str, Any] | None = None
    top_n: int | None = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/techniques")
def list_threat_techniques(
    category: str | None = None,
    severity: str | None = None,
    asset_type: str | None = None,
    source: str | None = None,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_threats(store, category=category, severity=severity,
                        asset_type=asset_type, source=source)


@router.get("/techniques/{technique_id}")
def get_threat_technique(
    technique_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    threat = get_threat(technique_id, store)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id!r} not found.")
    return threat


@router.post("/techniques", status_code=201)
def ingest_threat_technique(
    req: IngestThreatRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return ingest_threat(
            req.technique_id, req.name, req.category, req.description,
            req.affected_asset_types, req.severity, store,
            owasp_llm_id=req.owasp_llm_id,
            mitre_atlas_id=req.mitre_atlas_id,
            capability_triggers=req.capability_triggers,
            recommended_controls=req.recommended_controls,
            source=req.source,
        )
    except ThreatIntelError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/landscape")
def get_threat_landscape(
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return build_threat_landscape(store)


@router.post("/correlate/model")
def correlate_model_threats(
    req: CorrelateModelRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    record = {"model_id": req.model_id, "metadata": req.metadata or {}}
    return correlate_model(record, store, top_n=req.top_n)


@router.post("/correlate/agent")
def correlate_agent_threats(
    req: CorrelateAgentRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    record = {"model_id": req.agent_id, "metadata": req.metadata or {}}
    return correlate_agent(record, store, top_n=req.top_n)


@router.post("/correlate/tool")
def correlate_tool_threats(
    req: CorrelateToolRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    record = {"model_id": req.tool_id, "metadata": req.metadata or {}}
    return correlate_tool(record, store, top_n=req.top_n)

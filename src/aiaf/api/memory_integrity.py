"""Agent Memory Integrity API.

REST endpoints:
  POST /v1/memory-integrity/stores               — register memory store
  GET  /v1/memory-integrity/stores/{id}          — get store metadata
  POST /v1/memory-integrity/stores/{id}/entries  — write memory entry
  GET  /v1/memory-integrity/stores/{id}/entries  — list entries
  GET  /v1/memory-integrity/stores/{id}/assess   — full integrity assessment
  POST /v1/memory-integrity/stores/{id}/scan     — focused poisoning scan
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis.memory_integrity import (
    ATTACK_VECTORS,
    MemoryIntegrityError,
    assess_memory_integrity,
    get_memory_store,
    list_memory_entries,
    register_memory_store,
    scan_for_poisoning,
    write_memory,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/memory-integrity", tags=["memory-integrity"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class RegisterStoreRequest(BaseModel):
    store_id: str
    agent_id: str
    description: str | None = None
    max_entries: int = 10_000


class WriteMemoryRequest(BaseModel):
    key: str
    value: str
    origin: str
    writing_agent_id: str | None = None
    tags: list[str] | None = None


class ScanRequest(BaseModel):
    min_score: float = Field(0.35, ge=0.0, le=1.0)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/stores", status_code=201)
def register_memory_store_route(
    req: RegisterStoreRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return register_memory_store(
            req.store_id, req.agent_id, store,
            description=req.description, max_entries=req.max_entries,
        )
    except MemoryIntegrityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stores/{store_id}")
def get_memory_store_route(
    store_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    meta = get_memory_store(store_id, store)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Memory store {store_id!r} not found.")
    return meta


@router.post("/stores/{store_id}/entries", status_code=201)
def write_memory_route(
    store_id: str,
    req: WriteMemoryRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return write_memory(
            store_id, req.key, req.value, req.origin, store,
            writing_agent_id=req.writing_agent_id,
            tags=req.tags,
        )
    except MemoryIntegrityError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stores/{store_id}/entries")
def list_memory_entries_route(
    store_id: str,
    anomalous_only: bool = False,
    attack_vector: str | None = None,
    limit: int = 200,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    return list_memory_entries(
        store_id, store, anomalous_only=anomalous_only,
        attack_vector=attack_vector, limit=limit,
    )


@router.get("/stores/{store_id}/assess")
def assess_store_route(
    store_id: str,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return assess_memory_integrity(store_id, store)
    except MemoryIntegrityError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/stores/{store_id}/scan")
def scan_for_poisoning_route(
    store_id: str,
    req: ScanRequest,
    _: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    try:
        return scan_for_poisoning(store_id, store, min_score=req.min_score)
    except MemoryIntegrityError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/attack-vectors")
def get_attack_vectors(_: str = Depends(get_api_key)):
    return {"attack_vectors": sorted(ATTACK_VECTORS)}

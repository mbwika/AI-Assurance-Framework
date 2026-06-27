"""Agent-Skill & Extension Supply-Chain Scanner API.

REST endpoints:
  POST /v1/skill-scanner/scan         — scan a single skill manifest
  POST /v1/skill-scanner/scan/registry — scan a collection of manifests
  GET  /v1/skill-scanner/risk-categories — list risk category constants
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..registry.skill_scanner import (
    RISK_CATEGORIES,
    SKILL_SCANNER_VERSION,
    scan_skill_manifest,
    scan_skill_registry,
)
from .models import get_api_key

router = APIRouter(prefix="/v1/skill-scanner", tags=["skill-scanner"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class DependencyItem(BaseModel):
    name: str
    version: str | None = None


class SkillManifestRequest(BaseModel):
    skill_id: str | None = None
    name: str | None = None
    description: str | None = None
    version: str | None = None
    publisher: str | None = None
    publisher_signed: bool = False
    permissions: list[str] | None = None
    dependencies: list[DependencyItem] | None = None
    entry_point: str | None = None
    code_execution: bool = False
    network_access: bool = False
    data_access: list[str] | None = None
    tags: list[str] | None = None


class RegistryScanRequest(BaseModel):
    manifests: list[SkillManifestRequest] = Field(..., min_length=1)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/scan")
def scan_single_manifest(
    req: SkillManifestRequest,
    _: str = Depends(get_api_key),
):
    manifest = req.model_dump(exclude_none=False)
    if manifest.get("dependencies"):
        manifest["dependencies"] = [
            d if isinstance(d, dict) else d.model_dump()
            for d in (req.dependencies or [])
        ]
    return scan_skill_manifest(manifest)


@router.post("/scan/registry")
def scan_registry_manifests(
    req: RegistryScanRequest,
    _: str = Depends(get_api_key),
):
    manifests = []
    for m in req.manifests:
        d = m.model_dump(exclude_none=False)
        if d.get("dependencies"):
            d["dependencies"] = [
                dep if isinstance(dep, dict) else dep.model_dump()
                for dep in (m.dependencies or [])
            ]
        manifests.append(d)
    return scan_skill_registry(manifests)


@router.get("/risk-categories")
def list_risk_categories(_: str = Depends(get_api_key)):
    return {
        "risk_categories": sorted(RISK_CATEGORIES),
        "skill_scanner_version": SKILL_SCANNER_VERSION,
    }

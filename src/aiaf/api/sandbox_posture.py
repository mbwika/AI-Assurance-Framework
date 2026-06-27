"""Code-Execution Sandbox Posture Assessment API.

REST endpoints:
  POST /v1/sandbox-posture/assess   — assess declared sandbox configuration
  GET  /v1/sandbox-posture/levels   — list isolation levels + escape vectors
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..analysis.sandbox_posture import (
    EGRESS_CONTROLS,
    PRIVILEGE_LEVELS,
    SANDBOX_POSTURE_VERSION,
    SandboxPostureError,
    assess_sandbox_posture,
    get_isolation_levels,
)
from .models import get_api_key

router = APIRouter(prefix="/v1/sandbox-posture", tags=["sandbox-posture"])


# ── Pydantic models ────────────────────────────────────────────────────────────

class SandboxConfigRequest(BaseModel):
    isolation: str = Field(..., description="ISOLATION_* constant")
    egress: str = Field(..., description="EGRESS_* constant")
    privilege: str = Field(..., description="PRIVILEGE_* constant")
    timeout_sec: int = Field(0, ge=0)
    memory_mb: int = Field(0, ge=0)
    cpu_pct: int = Field(0, ge=0, le=100)
    allow_host_net: bool = False
    allow_host_pid: bool = False
    privileged: bool = False
    docker_socket: bool = False
    seccomp_profile: str = "none"
    apparmor: bool = False
    context: str | None = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/assess")
def assess_posture(
    req: SandboxConfigRequest,
    _: str = Depends(get_api_key),
):
    config = req.model_dump(exclude={"context"})
    try:
        return assess_sandbox_posture(config, context=req.context)
    except SandboxPostureError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/levels")
def list_isolation_levels(_: str = Depends(get_api_key)):
    return {
        "isolation_levels": get_isolation_levels(),
        "egress_controls": sorted(EGRESS_CONTROLS),
        "privilege_levels": sorted(PRIVILEGE_LEVELS),
        "sandbox_posture_version": SANDBOX_POSTURE_VERSION,
    }

"""Deployment verification API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..registry.deployment_verifier import (
    DEPLOYMENT_VERIFY_VERSION,
    DeploymentVerifyError,
    get_verify_result,
    list_verify_results,
    probe_endpoint,
    verify_deployment,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/deployments", tags=["deployment-verify"])


class GuardrailVersion(BaseModel):
    name: str = Field(max_length=255)
    version: str = Field(default="", max_length=64)


class VerifyDeploymentRequest(BaseModel):
    endpoint_url: str | None = Field(default=None, max_length=2048)
    container_digest: str | None = Field(default=None, max_length=128)
    served_model_id: str | None = Field(default=None, max_length=512)
    weights_sha256: str | None = Field(default=None, max_length=64)
    system_prompt_sha256: str | None = Field(default=None, max_length=64)
    tool_list: list[str] = Field(default_factory=list, max_length=500)
    guardrail_versions: list[GuardrailVersion] = Field(default_factory=list, max_length=200)
    save_result: bool = True
    auto_open_incident: bool = False


@router.post("/{model_id}/verify")
def api_verify_deployment(
    model_id: str,
    req: VerifyDeploymentRequest,
    store=Depends(get_store),
    _=Depends(get_api_key),
) -> dict[str, Any]:
    """Compare observed runtime state against the registered AI-BOM record.

    Returns a per-dimension drift report and an overall verdict of
    MATCH / PARTIAL_MATCH / MISMATCH / UNKNOWN.  On MISMATCH a finding
    is included in the response; set ``auto_open_incident=true`` to also
    create an UNAUTHORIZED_MODEL_CHANGE incident automatically.
    """
    observed: dict[str, Any] = {
        "endpoint_url": req.endpoint_url,
        "container_digest": req.container_digest,
        "served_model_id": req.served_model_id,
        "weights_sha256": req.weights_sha256,
        "system_prompt_sha256": req.system_prompt_sha256,
        "tool_list": req.tool_list,
        "guardrail_versions": [g.model_dump() for g in req.guardrail_versions],
    }
    try:
        result = verify_deployment(model_id, observed, store, save_result=req.save_result)
    except DeploymentVerifyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Persist finding if there is drift/mismatch
    finding = result.get("finding")
    if finding and hasattr(store, "save_finding"):
        store.save_finding(finding)

    # Auto-open an incident on MISMATCH
    if req.auto_open_incident and result["verdict"] == "MISMATCH":
        try:
            import uuid as _uuid

            from ..core.incident_manager import create_incident
            incident_id = str(_uuid.uuid4())
            create_incident(
                incident_id=incident_id,
                title=f"Deployment drift detected for {model_id}",
                severity="HIGH",
                source="deployment_verifier",
                model_id=model_id,
                store=store,
                description=(
                    f"Deployment verification detected MISMATCH. "
                    f"Mismatched dimensions: {', '.join(result.get('mismatch_dimensions') or [])}"
                ),
                tags=["UNAUTHORIZED_MODEL_CHANGE", "deployment_drift"],
                findings=[finding] if finding else [],
            )
            result["auto_opened_incident_id"] = incident_id
        except Exception:
            pass

    return result


@router.get("/{model_id}/verify")
def api_list_verify_results(
    model_id: str,
    verdict: str | None = None,
    limit: int = 20,
    store=Depends(get_store),
    _=Depends(get_api_key),
) -> dict[str, Any]:
    """List stored deployment verification results for a model."""
    results = list_verify_results(store, model_id=model_id, verdict=verdict, limit=limit)
    return {
        "model_id": model_id,
        "count": len(results),
        "results": results,
        "deployment_verify_version": DEPLOYMENT_VERIFY_VERSION,
    }


@router.get("/{model_id}/verify/{verify_id}")
def api_get_verify_result(
    model_id: str,
    verify_id: str,
    store=Depends(get_store),
    _=Depends(get_api_key),
) -> dict[str, Any]:
    """Retrieve a stored verification result by its verify_id."""
    result = get_verify_result(verify_id, store)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Verification result not found: {verify_id!r}")
    return result


@router.post("/{model_id}/probe")
def api_probe_endpoint(
    model_id: str,
    endpoint_url: str,
    allow_network: bool = False,
    _=Depends(get_api_key),
) -> dict[str, Any]:
    """Optionally probe a live endpoint for behavioral fingerprinting.

    Network I/O is suppressed unless ``allow_network=true`` is passed explicitly.
    """
    return probe_endpoint(endpoint_url, allow_network=allow_network)

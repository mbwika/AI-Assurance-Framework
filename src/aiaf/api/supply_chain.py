"""Supply-chain vulnerability intelligence APIs."""

import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core import VulnerabilityIntelligenceEngine
from .models import get_api_key, get_store


router = APIRouter(prefix="/v1/supply-chain", tags=["supply chain"])


class AdvisoryImport(BaseModel):
    advisories: List[Dict[str, Any]] = Field(min_length=1, max_length=5000)
    source: Optional[str] = Field(default=None, max_length=255)
    rescan_models: bool = True


class DependencyScan(BaseModel):
    dependencies: Any


class SignedAdvisoryFeedImport(BaseModel):
    feed: Dict[str, Any]
    rescan_models: bool = True


@router.post("/advisories/import")
def import_advisories(
    request: AdvisoryImport, api_key: str = Depends(get_api_key)
):
    try:
        return VulnerabilityIntelligenceEngine(get_store()).import_advisories(
            request.advisories,
            source=request.source,
            rescan_models=request.rescan_models,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/advisories")
def list_advisories(
    limit: int = 1000,
    ecosystem: Optional[str] = None,
    package_name: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    advisories = VulnerabilityIntelligenceEngine(get_store()).list_advisories(
        limit=limit, ecosystem=ecosystem, package_name=package_name
    )
    return {"advisories": advisories, "count": len(advisories)}


@router.post("/scan")
def scan_dependencies(
    request: DependencyScan, api_key: str = Depends(get_api_key)
):
    return VulnerabilityIntelligenceEngine(get_store()).scan(request.dependencies)


@router.post("/advisories/feeds/import")
def import_signed_advisory_feed(
    request: SignedAdvisoryFeedImport, api_key: str = Depends(get_api_key)
):
    try:
        return VulnerabilityIntelligenceEngine(get_store()).import_signed_feed(
            request.feed,
            signing_key=os.environ.get("AIAF_ADVISORY_FEED_KEY", ""),
            expected_key_id=os.environ.get("AIAF_ADVISORY_FEED_KEY_ID"),
            rescan_models=request.rescan_models,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/advisories/feeds")
def list_advisory_feed_snapshots(
    limit: int = 100,
    feed_id: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    snapshots = VulnerabilityIntelligenceEngine(get_store()).list_feed_snapshots(
        limit=limit, feed_id=feed_id
    )
    return {
        "feed_snapshots": [
            {key: value for key, value in snapshot.items() if key != "feed"}
            for snapshot in snapshots
        ],
        "count": len(snapshots),
    }


@router.get("/advisories/feeds/status")
def advisory_feed_status(
    as_of: Optional[str] = None, api_key: str = Depends(get_api_key)
):
    try:
        return VulnerabilityIntelligenceEngine(get_store()).feed_status(as_of=as_of)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/advisories/feeds/{snapshot_id}")
def get_advisory_feed_snapshot(
    snapshot_id: str, api_key: str = Depends(get_api_key)
):
    snapshot = VulnerabilityIntelligenceEngine(get_store()).get_feed_snapshot(
        snapshot_id
    )
    if not snapshot:
        raise HTTPException(status_code=404, detail="Advisory feed snapshot not found")
    return snapshot


@router.post("/advisories/feeds/{snapshot_id}/verify")
def verify_advisory_feed_snapshot(
    snapshot_id: str,
    as_of: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    verification = VulnerabilityIntelligenceEngine(
        get_store()
    ).verify_feed_snapshot(
        snapshot_id,
        signing_key=os.environ.get("AIAF_ADVISORY_FEED_KEY", ""),
        expected_key_id=os.environ.get("AIAF_ADVISORY_FEED_KEY_ID"),
        as_of=as_of,
    )
    if not verification:
        raise HTTPException(status_code=404, detail="Advisory feed snapshot not found")
    return verification

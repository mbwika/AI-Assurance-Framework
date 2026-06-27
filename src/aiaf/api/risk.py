"""Risk engine API routes."""
from typing import Any, Dict

from fastapi import APIRouter, Depends

from ..core import RiskEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/risk", tags=["risk"])


@router.post("/analyze")
def analyze_risk(artifact: Dict[str, Any], api_key: str = Depends(get_api_key)):
    store = get_store()
    engine = RiskEngine(datastore=store)
    return engine.analyze(artifact)

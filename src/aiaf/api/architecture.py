"""Architecture API routes."""
from fastapi import APIRouter

from ..architecture import get_architecture_catalog

router = APIRouter(prefix="/v1/architecture", tags=["architecture"])


@router.get("")
def architecture_catalog():
    return get_architecture_catalog()


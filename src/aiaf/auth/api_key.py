"""API key authentication guard for the AIAF REST API.

When ``AIAF_API_KEY`` is not set all routes are open (dev mode).  In production
set the env var and pass the same value as the ``X-API-Key`` request header.
"""
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from ..config import settings

_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(key: Optional[str] = Security(_header_scheme)) -> Optional[str]:
    """FastAPI dependency: validate the API key when one is configured."""
    if not settings.api_key:
        return None
    if key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return key


APIKeyDependency = Security(verify_api_key)

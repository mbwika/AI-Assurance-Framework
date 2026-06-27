"""Shared FastAPI dependencies for the AIAF API.

Import ``RequireApiKey`` as a route dependency to enforce key authentication:

    @router.post("/v1/models/register", dependencies=[RequireApiKey])
    def register_model(...): ...
"""

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from ..config import settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(key: str | None = Security(_api_key_header)) -> str | None:
    """Validate ``X-API-Key`` when ``AIAF_API_KEY`` is configured."""
    if not settings.api_key:
        return None
    if key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return key


RequireApiKey = Depends(get_api_key)

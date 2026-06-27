"""ASGI middleware for the AIAF API.

``CorrelationMiddleware`` adds a ``X-Correlation-ID`` to every response,
measures end-to-end request duration, and emits a structured log entry plus
in-process metrics for each request.

Add to the FastAPI app with::

    from .middleware import CorrelationMiddleware
    app.add_middleware(CorrelationMiddleware)
"""
import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..observability.logging import get_logger
from ..observability.metrics import record_api_request

logger = get_logger(__name__)


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        start = time.monotonic()

        response = await call_next(request)

        duration = time.monotonic() - start
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Response-Time"] = f"{duration:.4f}s"

        record_api_request(request.method, request.url.path, response.status_code)
        logger.info(
            "http_request method=%s path=%s status=%d duration_s=%.4f correlation_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration,
            correlation_id,
        )
        return response

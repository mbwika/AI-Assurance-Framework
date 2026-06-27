"""Inline PEP Gateway Middleware — ASGI middleware for FastAPI.

Intercepts HTTP requests that carry an agent principal header and evaluates
them against configured enforcement policies (core/policy_enforcement.py)
before the request reaches the handler.  This is the "data plane" complement
to the policy management API: instead of callers explicitly calling
``POST /v1/policy-enforcement/enforce``, any FastAPI request with an
``X-Agent-Id`` header is evaluated inline and blocked if DENY.

Decision verdicts
-----------------
ALLOW       — request proceeds to the handler
DENY        — middleware returns HTTP 403 immediately (in ENFORCE mode)
CONDITIONAL — request proceeds; X-PEP-Conditions response header is set

Enforcement modes
-----------------
The middleware's ``enforce`` parameter maps to mode:
  enforce=True   — ENFORCE: DENY verdict blocks the request
  enforce=False  — AUDIT: verdict is computed and headers set, never blocks

HTTP method → action mapping
-----------------------------
GET, HEAD, OPTIONS  → "read"
POST                → "create"
PUT, PATCH          → "update"
DELETE              → "delete"

Request headers read
--------------------
X-Agent-Id    — principal identity (required; skipped if absent)
X-Action      — explicit action override (optional; derived from method if absent)
X-Resource    — explicit resource override (optional; derived from path if absent)

Response headers set
--------------------
X-PEP-Verdict       — ALLOW / DENY / CONDITIONAL
X-PEP-Mode          — effective enforcement mode
X-PEP-Decision-Id   — unique 8-char decision identifier
X-PEP-Conditions    — semicolon-separated conditions (CONDITIONAL only)

Default excluded paths (never evaluated)
-----------------------------------------
/docs, /redoc, /openapi.json, /healthz, /metrics, /favicon.ico
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from ..core.policy_enforcement import (
    VERDICT_ALLOW,
    VERDICT_CONDITIONAL,
    VERDICT_DENY,
    enforce_request,
)

PEP_MIDDLEWARE_VERSION = "1.0"

_DEFAULT_EXCLUDED_PREFIXES: tuple[str, ...] = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/healthz",
    "/metrics",
    "/favicon.ico",
)

_METHOD_ACTION: dict[str, str] = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}


def _method_to_action(method: str) -> str:
    return _METHOD_ACTION.get(method.upper(), "invoke")


def _path_to_resource(path: str) -> str:
    """Derive a resource identifier from a URL path.

    Strips numeric/UUID path segments so ``/v1/models/abc-123/assess``
    becomes ``"v1:models:assess"``.
    """
    import re
    parts = [p for p in path.strip("/").split("/") if p and not re.match(
        r"^[0-9a-f\-]{8,}$|^\d+$", p, re.I
    )]
    return ":".join(parts) if parts else "root"


def _headers_to_dict(raw_headers: Iterable) -> dict[bytes, bytes]:
    result: dict[bytes, bytes] = {}
    for k, v in raw_headers:
        result[k.lower()] = v
    return result


def evaluate_gateway_request(
    principal_id: str,
    action: str,
    resource: str,
    store: Any,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Synchronously evaluate a gateway request through the PEP engine.

    This is the same decision logic the middleware uses internally and can be
    called directly by callers that do not use the ASGI path (e.g. in tests
    or non-HTTP agent frameworks).

    Returns
    -------
    Dict with keys: verdict, mode, decision_id, reasons, conditions_required,
    rate_limited, policy_ids_evaluated, evidence_origin, decided_at.
    """
    return enforce_request(
        principal_id, action, resource, store, context=context
    )


class PEPGatewayMiddleware:
    """ASGI middleware that enforces PEP policies inline for agent requests.

    Parameters
    ----------
    app:                  Inner ASGI application.
    store:                Policy/log store (same store used by the PEP engine).
    enforce:              True → DENY blocks the request (ENFORCE mode).
                          False → DENY is logged but request proceeds (AUDIT mode).
    excluded_prefixes:    URL prefixes that bypass the gateway check entirely.
                          Defaults to _DEFAULT_EXCLUDED_PREFIXES.
    excluded_paths:       Exact URL paths that bypass the gateway.
    add_decision_headers: Whether to set X-PEP-* response headers (default True).
    """

    def __init__(
        self,
        app,
        store: Any,
        *,
        enforce: bool = True,
        excluded_prefixes: tuple[str, ...] | None = None,
        excluded_paths: set[str] | None = None,
        add_decision_headers: bool = True,
    ) -> None:
        self.app = app
        self.store = store
        self.enforce = enforce
        self.excluded_prefixes = excluded_prefixes if excluded_prefixes is not None else _DEFAULT_EXCLUDED_PREFIXES
        self.excluded_paths: set[str] = set(excluded_paths or set())
        self.add_decision_headers = add_decision_headers

    async def __call__(self, scope, receive, send) -> None:  # noqa: D401
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Skip excluded paths
        if path in self.excluded_paths:
            await self.app(scope, receive, send)
            return
        for prefix in self.excluded_prefixes:
            if path.startswith(prefix):
                await self.app(scope, receive, send)
                return

        # Parse headers
        raw_headers = scope.get("headers", [])
        header_map = _headers_to_dict(raw_headers)

        agent_id = header_map.get(b"x-agent-id", b"").decode("utf-8", errors="replace").strip()
        if not agent_id:
            # No agent identity header → not an agent request, passthrough
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        action_bytes = header_map.get(b"x-action", b"")
        resource_bytes = header_map.get(b"x-resource", b"")

        action = action_bytes.decode("utf-8", errors="replace").strip() or _method_to_action(method)
        resource = resource_bytes.decode("utf-8", errors="replace").strip() or _path_to_resource(path)

        # Evaluate policy
        decision = evaluate_gateway_request(agent_id, action, resource, self.store)
        verdict = decision.get("verdict", VERDICT_ALLOW)
        decision_id = decision.get("decision_id") or decision.get("decided_at", "")[-8:]

        pep_headers: list[tuple[bytes, bytes]] = []
        if self.add_decision_headers:
            pep_headers = [
                (b"x-pep-verdict", verdict.encode()),
                (b"x-pep-mode", decision.get("mode", "UNKNOWN").encode()),
                (b"x-pep-decision-id", str(decision_id).encode()),
            ]
            if verdict == VERDICT_CONDITIONAL:
                conditions = ";".join(decision.get("conditions_required", []))
                pep_headers.append((b"x-pep-conditions", conditions.encode()))

        # In ENFORCE mode, a DENY verdict returns 403 immediately
        if verdict == VERDICT_DENY and self.enforce:
            body = json.dumps({
                "error": "Request denied by enforcement policy.",
                "verdict": VERDICT_DENY,
                "reasons": decision.get("reasons", []),
                "policy_ids_evaluated": decision.get("policy_ids_evaluated", []),
            }).encode()
            response_headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *pep_headers,
            ]
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": response_headers,
            })
            await send({"type": "http.response.body", "body": body})
            return

        # Proceed with injected PEP headers
        if self.add_decision_headers and pep_headers:
            send = _make_header_injector(send, pep_headers)

        await self.app(scope, receive, send)


def _make_header_injector(send_fn, extra_headers: list[tuple[bytes, bytes]]):
    """Wrap an ASGI send callable to inject additional headers into the response."""
    async def injected_send(event):
        if event.get("type") == "http.response.start":
            existing = list(event.get("headers", []))
            event = {**event, "headers": existing + extra_headers}
        await send_fn(event)
    return injected_send

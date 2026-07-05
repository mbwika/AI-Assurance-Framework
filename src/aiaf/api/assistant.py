"""Assistant API routes for the AIAF governance copilot MVP."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from ..core.assistant_actor import normalize_actor
from ..core.assistant_engine import AssistantEngine
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/assistant", tags=["assistant"])


def _header_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


class AssistantScopeHint(BaseModel):
    artifact_id: str | None = Field(default=None, max_length=255)
    model_id: str | None = Field(default=None, max_length=255)
    registered_by: str | None = Field(default=None, max_length=255)


class AssistantMessage(BaseModel):
    role: str = Field(default="user", max_length=32)
    content: str = Field(min_length=1, max_length=4000)


class AssistantActorHint(BaseModel):
    principal_id: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=255)
    auth_provider: str | None = Field(default=None, max_length=255)
    auth_subject: str | None = Field(default=None, max_length=255)


class AssistantQueryRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    scope_hint: AssistantScopeHint | None = None
    role: str | None = Field(default=None, max_length=255)
    actor: AssistantActorHint | None = None
    confirm_action_id: str | None = Field(default=None, max_length=512)
    conversation_id: str | None = Field(default=None, max_length=255)
    history: list[AssistantMessage] = Field(default_factory=list, max_length=20)


@router.get("/capabilities")
def assistant_capabilities(api_key: str = Depends(get_api_key)):
    return AssistantEngine(get_store()).capabilities()


@router.post("/query")
def assistant_query(
    request: AssistantQueryRequest,
    x_aiaf_principal_id: str | None = Header(default=None),
    x_aiaf_principal_name: str | None = Header(default=None),
    x_aiaf_auth_provider: str | None = Header(default=None),
    x_aiaf_auth_subject: str | None = Header(default=None),
    x_aiaf_authenticated: str | None = Header(default=None),
    api_key: str = Depends(get_api_key),
):
    actor = normalize_actor(
        request.actor.model_dump() if request.actor else None,
        legacy_role=request.role,
        auth_context={
            "principal_id": _header_text(x_aiaf_principal_id),
            "display_name": _header_text(x_aiaf_principal_name),
            "auth_provider": _header_text(x_aiaf_auth_provider),
            "auth_subject": _header_text(x_aiaf_auth_subject),
            "authenticated": _header_text(x_aiaf_authenticated or "") in {"1", "true", "yes", "TRUE", "True"},
        },
    )
    return AssistantEngine(get_store()).query(
        message=request.message,
        scope_hint=request.scope_hint.model_dump() if request.scope_hint else None,
        role=request.role,
        actor=actor,
        confirm_action_id=request.confirm_action_id,
        history=[item.model_dump() for item in request.history],
        conversation_id=request.conversation_id,
    )

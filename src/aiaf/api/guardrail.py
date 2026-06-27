"""Inline Guardrail API.

Advisory content classification for live agent traffic.  Returns a verdict
and structured findings; enforcement is the caller's responsibility.
"""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..core.guardrail_engine import (
    STAGE_INPUT,
    batch_check,
    check_content,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/guardrail", tags=["guardrail"])


class CheckRequest(BaseModel):
    content: str
    stage: str = STAGE_INPUT
    session_id: str | None = None
    policy: dict[str, Any] | None = None


class BatchItem(BaseModel):
    content: str
    stage: str = STAGE_INPUT


class BatchCheckRequest(BaseModel):
    items: list[BatchItem]
    session_id: str | None = None


@router.post("/check", summary="Classify content at input or output stage")
def guardrail_check(req: CheckRequest, api_key: str = Depends(get_api_key)):
    """Classify a single piece of content for injection, jailbreak, and PII.

    Set ``stage="input"`` for content arriving from the user/agent (pre-LLM)
    or ``stage="output"`` for model responses (post-LLM).

    If ``session_id`` is supplied, a ``guardrail_block`` or ``guardrail_flag``
    event is automatically emitted to the telemetry session store.

    Raw content is **never stored**; only the SHA-256 ``content_hash`` travels
    to the telemetry sink.
    """
    store = get_store() if req.session_id else None
    return check_content(
        req.content,
        stage=req.stage,
        session_id=req.session_id,
        store=store,
        policy=req.policy,
    )


@router.post("/batch", summary="Classify multiple content items in one call")
def guardrail_batch(req: BatchCheckRequest, api_key: str = Depends(get_api_key)):
    """Classify a batch of content items (e.g. an entire turn: user message +
    tool arguments + model response).

    Returns per-item results plus an ``overall_verdict`` reflecting the worst
    individual verdict across all items.
    """
    store = get_store() if req.session_id else None
    return batch_check(
        [item.model_dump() for item in req.items],
        session_id=req.session_id,
        store=store,
    )

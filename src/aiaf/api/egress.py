"""Egress and capability firewall API.

Routes
------
POST /v1/egress/decisions   Evaluate and ledger-log a network/tool/data egress attempt
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.egress_firewall import CHANNELS, FirewallDecisionError, decide_egress
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/egress", tags=["egress-firewall"])


class EgressDecisionRequest(BaseModel):
    agent_id: str = Field(..., description="Registered agent identity making the request")
    session_id: str = Field(..., description="Session this decision is logged under")
    channel: str = Field(..., description=f"One of {sorted(CHANNELS)}")
    target: str = Field(..., description="Network destination, tool name, or data resource")
    action: str | None = Field(None, description="Defaults per channel: connect/invoke/export")
    context: dict[str, Any] | None = Field(None, description="Session/request context (e.g. data_sensitivity, approval_granted)")
    policy_id: str | None = Field(None, description="Explicit PEP policy id to evaluate against")
    required_capabilities: list[str] | None = Field(
        None, description="Override the default required capability flags for this channel"
    )


@router.post("/decisions")
def evaluate_egress_decision(
    req: EgressDecisionRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Evaluate a network/tool/data egress attempt against agent capabilities,

    operational constraints, and policy, logging the decision to the
    agent-action ledger regardless of verdict.
    """
    try:
        return decide_egress(
            agent_id=req.agent_id,
            session_id=req.session_id,
            channel=req.channel,
            target=req.target,
            store=store,
            action=req.action,
            context=req.context,
            policy_id=req.policy_id,
            required_capabilities=req.required_capabilities,
        )
    except FirewallDecisionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

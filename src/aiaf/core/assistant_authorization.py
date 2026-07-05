"""Write authorization policy for assistant-triggered actions."""

from __future__ import annotations

from typing import Any

WRITE_INTENTS = {"create_report_snapshot"}
DECLARED_WRITE_ROLES = {
    "governance-analyst",
    "governance-admin",
    "compliance-lead",
    "platform-owner",
}


def evaluate_write_policy(
    *,
    intent: str,
    scope: dict[str, Any],
    actor: dict[str, Any] | None,
    confirm_action_id: str | None,
) -> dict[str, Any]:
    actor = actor or {}
    confirmation_id = build_confirmation_id(intent=intent, scope=scope, actor=actor)

    if intent not in WRITE_INTENTS:
        return {
            "decision": "allow",
            "write_intent": False,
            "confirmation_required": False,
            "confirmation_id": None,
            "policy_basis": "read_only_workflow",
        }

    role = str(actor.get("role") or "").strip().casefold()
    authenticated = bool(actor.get("authenticated"))
    declared_write_role = role in DECLARED_WRITE_ROLES

    if not authenticated and not declared_write_role:
        return {
            "decision": "needs_clarification",
            "write_intent": True,
            "confirmation_required": False,
            "confirmation_id": confirmation_id,
            "policy_basis": "missing_write_authority",
            "question": (
                "Before I make changes, I need either an authenticated identity or a declared governance role "
                "such as governance-analyst, governance-admin, compliance-lead, or platform-owner."
            ),
        }

    if str(confirm_action_id or "").strip() != confirmation_id:
        return {
            "decision": "needs_confirmation",
            "write_intent": True,
            "confirmation_required": True,
            "confirmation_id": confirmation_id,
            "policy_basis": "step_up_confirmation",
            "question": "Please confirm this write action so I can create the snapshot.",
        }

    return {
        "decision": "allow",
        "write_intent": True,
        "confirmation_required": False,
        "confirmation_id": confirmation_id,
        "policy_basis": "authenticated_actor" if authenticated else "declared_governance_role",
    }


def build_confirmation_id(*, intent: str, scope: dict[str, Any], actor: dict[str, Any] | None) -> str:
    actor = actor or {}
    scope_part = (
        str(scope.get("artifact_id") or "")
        or str(scope.get("model_id") or "")
        or str(scope.get("registered_by") or "")
        or "portfolio"
    )
    actor_part = str(actor.get("attribution_label") or "aiaf-assistant")
    return f"{intent}:{scope_part}:{actor_part}"

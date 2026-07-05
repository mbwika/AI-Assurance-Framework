"""Actor attribution helpers for assistant requests and write operations."""

from __future__ import annotations

from typing import Any


def normalize_actor(
    actor_hint: dict[str, Any] | None = None,
    *,
    legacy_role: str | None = None,
    auth_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    actor_hint = actor_hint or {}
    auth_context = auth_context or {}

    principal_id = _clean(auth_context.get("principal_id")) or _clean(actor_hint.get("principal_id"))
    display_name = _clean(auth_context.get("display_name")) or _clean(actor_hint.get("display_name"))
    role = _clean(actor_hint.get("role")) or _clean(legacy_role)
    auth_provider = _clean(auth_context.get("auth_provider")) or _clean(actor_hint.get("auth_provider"))
    auth_subject = _clean(auth_context.get("auth_subject")) or _clean(actor_hint.get("auth_subject"))
    authenticated = bool(
        (auth_context.get("authenticated") or actor_hint.get("authenticated"))
        and (principal_id or auth_subject or display_name)
    )

    if principal_id:
        attribution_label = f"principal:{principal_id}"
    elif auth_subject:
        attribution_label = f"subject:{auth_subject}"
    elif display_name:
        attribution_label = display_name
    elif role:
        attribution_label = f"role:{role}"
    else:
        attribution_label = "aiaf-assistant"

    return {
        "principal_id": principal_id,
        "display_name": display_name,
        "role": role,
        "auth_provider": auth_provider,
        "auth_subject": auth_subject,
        "authenticated": authenticated,
        "attribution_mode": "authenticated" if authenticated else "declared",
        "attribution_label": attribution_label,
    }


def actor_summary(actor: dict[str, Any] | None) -> str:
    actor = actor or {}
    return str(actor.get("attribution_label") or "aiaf-assistant")


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None

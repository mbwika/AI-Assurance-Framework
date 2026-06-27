"""Reusable policy profiles for agentic AI assurance."""

from copy import deepcopy
from typing import Any

AUTONOMY_ORDER = {
    "none": 0,
    "low": 1,
    "supervised": 2,
    "medium": 3,
    "high": 4,
    "autonomous": 5,
    "full": 6,
}

AGENT_POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "restricted": {
        "name": "Restricted",
        "description": "Least-privilege profile for sensitive or externally exposed agents.",
        "policy": {
            "allowed_tools": ["browser", "http", "database", "filesystem"],
            "denied_tools": ["shell", "payment", "cloud_admin", "email"],
            "allowed_permissions": ["read", "network"],
            "denied_permissions": ["delete", "admin", "deploy", "execute", "send_email", "transfer_funds"],
            "max_autonomy_level": "supervised",
            "require_human_review_for_tools": ["browser", "http", "database", "filesystem"],
            "require_approval_for_actions": ["write", "delete", "deploy", "execute", "send_email", "transfer_funds", "external_call"],
            "max_external_calls": 3,
            "max_workflow_steps": 20,
            "max_workflow_iterations": 5,
            "require_input_validation_for_external_tools": True,
            "require_declared_tools": True,
            "require_termination_path": True,
            "require_workflow_step_binding": True,
        },
    },
    "standard": {
        "name": "Standard",
        "description": "Balanced profile for supervised business workflow agents.",
        "policy": {
            "allowed_tools": ["browser", "http", "database", "filesystem", "email", "shell"],
            "denied_tools": ["payment", "cloud_admin"],
            "allowed_permissions": ["read", "write", "network", "execute", "send_email"],
            "denied_permissions": ["admin", "deploy", "transfer_funds"],
            "max_autonomy_level": "high",
            "require_human_review_for_tools": ["shell", "email"],
            "require_approval_for_actions": ["delete", "deploy", "execute", "send_email", "transfer_funds"],
            "max_external_calls": 10,
            "max_workflow_steps": 50,
            "max_workflow_iterations": 10,
            "require_input_validation_for_external_tools": True,
            "require_declared_tools": True,
            "require_termination_path": True,
            "require_workflow_step_binding": True,
        },
    },
    "development": {
        "name": "Development",
        "description": "Constrained profile for non-production agent testing.",
        "policy": {
            "allowed_tools": ["browser", "http", "database", "filesystem", "email", "shell"],
            "denied_tools": ["payment", "cloud_admin"],
            "allowed_permissions": ["read", "write", "network", "execute"],
            "denied_permissions": ["admin", "deploy", "send_email", "transfer_funds"],
            "max_autonomy_level": "supervised",
            "require_human_review_for_tools": ["shell", "email"],
            "require_approval_for_actions": ["delete", "deploy", "send_email", "transfer_funds"],
            "max_external_calls": 20,
            "max_workflow_steps": 100,
            "max_workflow_iterations": 20,
            "require_input_validation_for_external_tools": True,
            "require_declared_tools": True,
            "require_termination_path": True,
            "require_workflow_step_binding": False,
        },
    },
}


def get_agent_policy_profiles() -> dict[str, dict[str, Any]]:
    return deepcopy(AGENT_POLICY_PROFILES)


def resolve_agent_policy(
    profile_name: str | None, overrides: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Resolve a profile and conservatively merge optional local constraints."""
    overrides = deepcopy(overrides or {})
    if not profile_name:
        return overrides
    normalized = str(profile_name).lower()
    if normalized not in AGENT_POLICY_PROFILES:
        raise KeyError(normalized)
    baseline = deepcopy(AGENT_POLICY_PROFILES[normalized]["policy"])

    for field in ("denied_tools", "denied_permissions", "require_human_review_for_tools", "require_approval_for_actions"):
        baseline[field] = sorted(_set(baseline.get(field)) | _set(overrides.get(field)))
    for field in ("allowed_tools", "allowed_permissions"):
        requested = _set(overrides.get(field))
        allowed = _set(baseline.get(field))
        baseline[field] = sorted(allowed & requested) if requested else sorted(allowed)
    for field in ("max_external_calls", "max_workflow_steps", "max_workflow_iterations"):
        if overrides.get(field) is not None:
            baseline[field] = min(_positive_int(baseline.get(field)), _positive_int(overrides[field]))
    for field in (
        "require_input_validation_for_external_tools",
        "require_declared_tools",
        "require_termination_path",
        "require_workflow_step_binding",
    ):
        baseline[field] = bool(baseline.get(field) or overrides.get(field))

    requested_autonomy = str(overrides.get("max_autonomy_level") or "").lower()
    if requested_autonomy:
        baseline_autonomy = str(baseline.get("max_autonomy_level", "none")).lower()
        baseline["max_autonomy_level"] = min(
            (baseline_autonomy, requested_autonomy),
            key=lambda value: AUTONOMY_ORDER.get(value, 0),
        )
    return baseline


def _set(value: Any) -> set:
    if value in (None, ""):
        return set()
    if isinstance(value, str):
        value = [value]
    return {str(item).lower() for item in value}


def _positive_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0

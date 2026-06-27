"""Runtime authorization guard for agent tool invocations."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..analysis import assess_agent_risk_v2
from ..mapping.standards import map_finding_to_controls
from .risk_register_engine import RiskRegisterEngine


SESSION_STATUSES = {"ACTIVE", "REVOKED", "CLOSED"}
DECISIONS = {"ALLOW", "REQUIRE_APPROVAL", "DENY"}
EXTERNAL_TOOLS = {"browser", "http", "email", "payment"}


class AgentRuntimeEngine:
    def __init__(self, datastore: object):
        self.datastore = datastore

    def create_session(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        artifact_id = str(artifact.get("id") or "").strip()
        if not artifact_id:
            raise ValueError("Agent runtime sessions require a non-empty artifact id")
        assessment = assess_agent_risk_v2(artifact)
        policy = assessment.get("effective_policy") or {}
        if not policy:
            raise ValueError("Agent runtime sessions require an explicit policy or policy profile")
        if assessment.get("policy_violations"):
            indicators = sorted(
                {
                    item["indicator"]
                    for item in assessment["policy_violations"]
                }
            )
            raise ValueError(f"Agent policy validation failed: {indicators}")
        blocking_workflow = [
            item
            for item in assessment.get("workflow_risks", [])
            if item.get("severity") in {"HIGH", "CRITICAL"}
        ]
        if blocking_workflow:
            indicators = sorted({item["indicator"] for item in blocking_workflow})
            raise ValueError(f"Agent workflow validation failed: {indicators}")
        if policy.get("require_workflow_step_binding") and not _workflow_steps(artifact):
            raise ValueError("Agent policy requires a declared workflow")

        now = _utc_now()
        session = {
            "id": str(uuid.uuid4()),
            "artifact_id": artifact_id,
            "artifact": artifact,
            "policy_profile": artifact.get("agent_policy_profile"),
            "effective_policy": policy,
            "status": "ACTIVE",
            "external_calls_used": 0,
            "created_at": now,
            "updated_at": now,
        }
        self.datastore.save_agent_session(session)
        self.datastore.save_audit_log(
            {
                "event_type": "agent_runtime_session_created",
                "artifact_id": artifact_id,
                "details": {
                    "session_id": session["id"],
                    "policy_profile": session["policy_profile"],
                    "workflow_nodes": assessment.get("workflow_graph", {}).get(
                        "node_count", 0
                    ),
                },
            }
        )
        return session

    def authorize(
        self,
        session_id: str,
        *,
        request_id: str,
        tool: str,
        action: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        workflow_step_id: Optional[str] = None,
        input_source: Optional[str] = None,
        input_validation: Optional[str] = None,
        target: Optional[str] = None,
        approval_id: Optional[str] = None,
        approved_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        session = self.datastore.get_agent_session(session_id)
        if not session:
            raise ValueError("Agent session not found")
        request_id = str(request_id or "").strip()
        tool = str(tool or "").strip().lower()
        action = str(action or "").strip().lower()
        if not request_id:
            raise ValueError("request_id is required")
        if not tool:
            raise ValueError("tool is required")

        requested_permissions = _set(permissions)
        policy = session["effective_policy"]
        artifact = session["artifact"]
        deny_reasons = []
        approval_reasons = []

        allowed_tools = _set(policy.get("allowed_tools"))
        denied_tools = _set(policy.get("denied_tools"))
        declared_tools = _set(artifact.get("tools"))
        if tool in denied_tools:
            deny_reasons.append(_reason("denied_tool", f"Tool {tool} is denied by policy."))
        if allowed_tools and tool not in allowed_tools:
            deny_reasons.append(
                _reason("disallowed_tool", f"Tool {tool} is outside the policy allowlist.")
            )
        if policy.get("require_declared_tools") and tool not in declared_tools:
            deny_reasons.append(
                _reason("undeclared_tool", f"Tool {tool} is not declared by the agent.")
            )

        allowed_permissions = _set(policy.get("allowed_permissions"))
        denied_permissions = _set(policy.get("denied_permissions"))
        declared_permissions = _set(artifact.get("permissions"))
        for permission in sorted(requested_permissions & denied_permissions):
            deny_reasons.append(
                _reason(
                    "denied_permission",
                    f"Permission {permission} is denied by policy.",
                )
            )
        for permission in sorted(
            requested_permissions - allowed_permissions if allowed_permissions else []
        ):
            deny_reasons.append(
                _reason(
                    "disallowed_permission",
                    f"Permission {permission} is outside the policy allowlist.",
                )
            )
        for permission in sorted(requested_permissions - declared_permissions):
            deny_reasons.append(
                _reason(
                    "undeclared_permission",
                    f"Permission {permission} is not declared by the agent.",
                )
            )

        step = _workflow_step(artifact, workflow_step_id)
        if policy.get("require_workflow_step_binding"):
            if not workflow_step_id:
                deny_reasons.append(
                    _reason(
                        "workflow_step_binding_required",
                        "Invocation must reference a declared workflow step.",
                    )
                )
            elif step is None:
                deny_reasons.append(
                    _reason(
                        "unknown_workflow_step",
                        f"Workflow step {workflow_step_id} does not exist.",
                    )
                )
        if step is not None:
            step_tool = str(step.get("tool") or "").lower()
            step_action = str(step.get("action") or "").lower()
            step_permissions = _set(step.get("permissions"))
            if step_tool and tool != step_tool:
                deny_reasons.append(
                    _reason(
                        "workflow_tool_mismatch",
                        f"Workflow step permits {step_tool}, not {tool}.",
                    )
                )
            if step_action and action != step_action:
                deny_reasons.append(
                    _reason(
                        "workflow_action_mismatch",
                        f"Workflow step permits {step_action}, not {action or 'no action'}.",
                    )
                )
            for permission in sorted(requested_permissions - step_permissions):
                deny_reasons.append(
                    _reason(
                        "workflow_permission_escalation",
                        f"Workflow step does not grant permission {permission}.",
                    )
                )

        external_call = _is_external(tool, action, input_source)
        if (
            external_call
            and policy.get("require_input_validation_for_external_tools")
            and not input_validation
        ):
            deny_reasons.append(
                _reason(
                    "external_input_validation_required",
                    "External tool invocation requires input-validation evidence.",
                )
            )

        if tool in _set(policy.get("require_human_review_for_tools")):
            approval_reasons.append(
                _reason(
                    "tool_approval_required",
                    f"Tool {tool} requires human approval.",
                )
            )
        if action in _set(policy.get("require_approval_for_actions")):
            approval_reasons.append(
                _reason(
                    "action_approval_required",
                    f"Action {action} requires human approval.",
                )
            )
        has_approval = bool(str(approval_id or "").strip() and str(approved_by or "").strip())
        if deny_reasons:
            decision = "DENY"
            reasons = deny_reasons
        elif approval_reasons and not has_approval:
            decision = "REQUIRE_APPROVAL"
            reasons = approval_reasons
        else:
            decision = "ALLOW"
            reasons = []

        invocation = {
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "request_id": request_id,
            "workflow_step_id": workflow_step_id,
            "tool": tool,
            "action": action or None,
            "permissions": sorted(requested_permissions),
            "input_source": input_source,
            "input_validation": input_validation,
            "target": target,
            "approval_id": approval_id,
            "approved_by": approved_by,
            "decision": decision,
            "reasons": reasons,
            "external_call": external_call,
            "created_at": _utc_now(),
        }
        recorded = self.datastore.record_tool_invocation(
            invocation, policy.get("max_external_calls")
        )
        if not recorded.get("idempotent_replay"):
            self._record_decision(session, recorded)
        recorded["session"] = self.datastore.get_agent_session(session_id)
        return recorded

    def list_sessions(
        self,
        limit: int = 100,
        artifact_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        normalized = str(status).upper() if status else None
        if normalized and normalized not in SESSION_STATUSES:
            raise ValueError(f"Invalid session status: {status}")
        return self.datastore.list_agent_sessions(
            limit=min(max(int(limit), 1), 1000),
            artifact_id=artifact_id,
            status=normalized,
        )

    def list_invocations(
        self,
        limit: int = 100,
        session_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        normalized = str(decision).upper() if decision else None
        if normalized and normalized not in DECISIONS:
            raise ValueError(f"Invalid authorization decision: {decision}")
        return self.datastore.list_tool_invocations(
            limit=min(max(int(limit), 1), 1000),
            session_id=session_id,
            decision=normalized,
        )

    def update_session_status(
        self, session_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        normalized = str(status or "").upper()
        if normalized not in {"REVOKED", "CLOSED"}:
            raise ValueError("Session status can only transition to REVOKED or CLOSED")
        session = self.datastore.get_agent_session(session_id)
        if not session:
            return None
        if session["status"] != "ACTIVE":
            raise ValueError("Only ACTIVE sessions can be revoked or closed")
        updated = self.datastore.update_agent_session_status(
            session_id, normalized, _utc_now()
        )
        self.datastore.save_audit_log(
            {
                "event_type": "agent_runtime_session_status_changed",
                "artifact_id": session["artifact_id"],
                "details": {"session_id": session_id, "status": normalized},
            }
        )
        return updated

    def _record_decision(
        self, session: Dict[str, Any], invocation: Dict[str, Any]
    ) -> None:
        self.datastore.save_audit_log(
            {
                "event_type": "agent_tool_authorization_decision",
                "artifact_id": session["artifact_id"],
                "details": invocation,
            }
        )
        self.datastore.save_metric(
            "agent_tool_authorization_decision",
            1,
            {
                "artifact_id": session["artifact_id"],
                "session_id": session["id"],
                "decision": invocation["decision"],
                "tool": invocation["tool"],
                "external_call": invocation["external_call"],
            },
        )
        if invocation["decision"] == "DENY":
            indicators = [
                f"runtime_policy_denial:{reason['code']}"
                for reason in invocation.get("reasons", [])
            ] or ["runtime_policy_denial"]
            finding = {
                "type": "agent_risk",
                "risk_score": 3.0,
                "severity": "HIGH",
                "indicators": indicators,
                "detail": {"tool_invocation": invocation},
            }
            finding["mapping"] = map_finding_to_controls(finding)
            RiskRegisterEngine(self.datastore).observe_findings(
                session["artifact_id"], [finding], observed_at=invocation["created_at"]
            )


def _workflow_steps(artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
    workflow = artifact.get("workflow_steps") or artifact.get("workflow") or []
    if isinstance(workflow, dict):
        workflow = workflow.get("steps", [])
    return [step for step in workflow if isinstance(step, dict)]


def _workflow_step(
    artifact: Dict[str, Any], workflow_step_id: Optional[str]
) -> Optional[Dict[str, Any]]:
    if not workflow_step_id:
        return None
    for index, step in enumerate(_workflow_steps(artifact)):
        step_id = str(step.get("id") or step.get("name") or f"step-{index + 1}")
        if step_id == str(workflow_step_id):
            return step
    return None


def _is_external(tool: str, action: str, input_source: Optional[str]) -> bool:
    return (
        tool in EXTERNAL_TOOLS
        or action == "external_call"
        or str(input_source or "").lower() in {"external", "untrusted", "user"}
    )


def _set(value: Any) -> set:
    if value in (None, ""):
        return set()
    if isinstance(value, str):
        value = [value]
    return {str(item).lower() for item in value}


def _reason(code: str, detail: str) -> Dict[str, str]:
    return {"code": code, "detail": detail}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

import sys
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _agent():
    return {
        "id": "runtime-agent",
        "tools": ["browser"],
        "permissions": ["read", "network"],
        "autonomy_level": "supervised",
        "operational_constraints": {
            "network_scope": "approved destinations",
            "max_external_calls": 1,
        },
        "agent_policy_profile": "restricted",
        "agent_policy": {"max_external_calls": 1},
        "workflow_steps": [
            {
                "id": "fetch",
                "tool": "browser",
                "action": "external_call",
                "permissions": ["read", "network"],
                "input_source": "external",
                "input_validation": "destination allowlist",
                "requires_approval": True,
                "next": "finish",
            },
            {
                "id": "finish",
                "action": "finish",
                "permissions": ["read", "network"],
                "terminal": True,
            },
        ],
        "runtime_tool_authorization": True,
    }


def _authorize(engine, session_id, request_id, **overrides):
    values = {
        "request_id": request_id,
        "tool": "browser",
        "action": "external_call",
        "permissions": ["read", "network"],
        "workflow_step_id": "fetch",
        "input_source": "external",
        "input_validation": "destination allowlist",
        "target": "https://approved.example.test",
    }
    values.update(overrides)
    return engine.authorize(session_id, **values)


def test_runtime_guard_enforces_approval_idempotency_and_call_budget(tmp_path):
    ensure_src()
    from aiaf.core import AgentRuntimeEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "runtime.db"))
    engine = AgentRuntimeEngine(store)
    session = engine.create_session(_agent())

    approval = _authorize(engine, session["id"], "request-approval")
    allowed = _authorize(
        engine,
        session["id"],
        "request-allowed",
        approval_id="APR-1",
        approved_by="security-reviewer",
    )
    replay = _authorize(
        engine,
        session["id"],
        "request-allowed",
        approval_id="APR-1",
        approved_by="security-reviewer",
    )
    exceeded = _authorize(
        engine,
        session["id"],
        "request-exceeded",
        approval_id="APR-2",
        approved_by="security-reviewer",
    )

    assert approval["decision"] == "REQUIRE_APPROVAL"
    assert {reason["code"] for reason in approval["reasons"]} == {
        "tool_approval_required",
        "action_approval_required",
    }
    assert allowed["decision"] == "ALLOW"
    assert allowed["session"]["external_calls_used"] == 1
    assert replay["id"] == allowed["id"]
    assert replay["idempotent_replay"] is True
    assert replay["session"]["external_calls_used"] == 1
    with pytest.raises(ValueError, match="request_id already used"):
        _authorize(
            engine,
            session["id"],
            "request-allowed",
            tool="shell",
            action="execute",
            permissions=["execute"],
            approval_id="APR-1",
            approved_by="security-reviewer",
        )
    assert exceeded["decision"] == "DENY"
    assert exceeded["reasons"][-1]["code"] == "external_call_limit_exceeded"
    assert len(engine.list_invocations(session_id=session["id"])) == 3
    assert store.list_risks()[0]["indicator"].endswith(
        "external_call_limit_exceeded"
    )
    store.close()


def test_runtime_guard_denies_workflow_and_permission_escalation(tmp_path):
    ensure_src()
    from aiaf.core import AgentRuntimeEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "runtime.db"))
    engine = AgentRuntimeEngine(store)
    session = engine.create_session(_agent())

    denied = _authorize(
        engine,
        session["id"],
        "request-denied",
        tool="shell",
        action="execute",
        permissions=["execute"],
        workflow_step_id="fetch",
        approval_id="APR-1",
        approved_by="reviewer",
    )
    reason_codes = {reason["code"] for reason in denied["reasons"]}

    assert denied["decision"] == "DENY"
    assert "denied_tool" in reason_codes
    assert "undeclared_tool" in reason_codes
    assert "denied_permission" in reason_codes
    assert "undeclared_permission" in reason_codes
    assert "workflow_tool_mismatch" in reason_codes
    assert "workflow_permission_escalation" in reason_codes

    revoked = engine.update_session_status(session["id"], "REVOKED")
    after_revocation = _authorize(
        engine,
        session["id"],
        "request-revoked",
        approval_id="APR-2",
        approved_by="reviewer",
    )
    assert revoked["status"] == "REVOKED"
    assert after_revocation["decision"] == "DENY"
    assert after_revocation["reasons"][-1]["code"] == "session_not_active"
    store.close()


def test_runtime_session_rejects_unsafe_static_agent_configuration(tmp_path):
    ensure_src()
    from aiaf.core import AgentRuntimeEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "runtime.db"))
    with pytest.raises(ValueError, match="policy validation failed"):
        AgentRuntimeEngine(store).create_session(
            {
                "id": "unsafe-agent",
                "tools": ["shell"],
                "permissions": ["execute"],
                "autonomy_level": "high",
                "agent_policy_profile": "restricted",
            }
        )
    store.close()


def test_runtime_reporting_and_api_contract(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import agentic as agentic_api
    from aiaf.api.app import app
    from aiaf.core import ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "runtime.db"))
    monkeypatch.setattr(agentic_api, "get_store", lambda: store)
    session = agentic_api.create_agent_session(
        agentic_api.AgentSessionCreate(artifact=_agent()), api_key="dev-key"
    )
    decision = agentic_api.authorize_tool_invocation(
        session["id"],
        agentic_api.ToolAuthorizationRequest(
            request_id="api-denied",
            tool="browser",
            action="external_call",
            permissions=["read", "network"],
            workflow_step_id="fetch",
            input_source="external",
            input_validation="destination allowlist",
        ),
        api_key="dev-key",
    )
    report = ReportingEngine(store).assurance_report()
    alert_ids = {alert["id"] for alert in report["monitoring_alerts"]["alerts"]}
    routes = set(app.openapi()["paths"])

    assert decision["decision"] == "REQUIRE_APPROVAL"
    assert report["agentic_runtime"]["total_sessions"] == 1
    assert report["agentic_runtime"]["approval_required_decisions"] == 1
    assert "agent_tool_approvals_required" in alert_ids
    assert "/v1/agentic/sessions" in routes
    assert "/v1/agentic/sessions/{session_id}/authorize" in routes
    assert "/v1/agentic/invocations" in routes
    store.close()


def test_runtime_decisions_are_isolated_in_artifact_reports(tmp_path):
    ensure_src()
    from aiaf.core import AgentRuntimeEngine, ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "runtime-scope.db"))
    engine = AgentRuntimeEngine(store)
    artifact_a = _agent()
    artifact_a["id"] = "runtime-a"
    artifact_b = _agent()
    artifact_b["id"] = "runtime-b"
    session_a = engine.create_session(artifact_a)
    session_b = engine.create_session(artifact_b)

    _authorize(engine, session_a["id"], "a-approval")
    _authorize(
        engine,
        session_b["id"],
        "b-denied",
        tool="shell",
        action="execute",
        permissions=["execute"],
        approval_id="APR-B",
        approved_by="reviewer",
    )

    report_a = ReportingEngine(store).assurance_report(artifact_id="runtime-a")
    report_b = ReportingEngine(store).assurance_report(artifact_id="runtime-b")

    assert report_a["agentic_runtime"]["total_sessions"] == 1
    assert report_a["agentic_runtime"]["approval_required_decisions"] == 1
    assert report_a["agentic_runtime"]["denied_decisions"] == 0
    assert report_b["agentic_runtime"]["total_sessions"] == 1
    assert report_b["agentic_runtime"]["approval_required_decisions"] == 0
    assert report_b["agentic_runtime"]["denied_decisions"] == 1
    assert len(store.list_tool_invocations(artifact_id="runtime-a")) == 1
    assert len(store.list_tool_invocations(artifact_id="runtime-b")) == 1
    store.close()

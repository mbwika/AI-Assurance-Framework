import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_policy_profile_overrides_cannot_weaken_baseline():
    ensure_src()
    from aiaf.analysis import resolve_agent_policy

    policy = resolve_agent_policy(
        "restricted",
        {
            "allowed_tools": ["browser", "shell"],
            "denied_tools": ["email"],
            "max_autonomy_level": "autonomous",
            "max_external_calls": 99,
            "require_input_validation_for_external_tools": False,
        },
    )

    assert policy["allowed_tools"] == ["browser"]
    assert {"shell", "email"}.issubset(policy["denied_tools"])
    assert policy["max_autonomy_level"] == "supervised"
    assert policy["max_external_calls"] == 3
    assert policy["require_input_validation_for_external_tools"] is True


def test_workflow_graph_detects_cycles_taint_and_privilege_escalation():
    ensure_src()
    from aiaf.analysis import analyze_workflow_graph

    graph = analyze_workflow_graph(
        {
            "tools": ["browser", "shell"],
            "workflow_entrypoint": "ingest",
            "workflow_steps": [
                {
                    "id": "ingest",
                    "tool": "browser",
                    "input_source": "external",
                    "permissions": ["read"],
                    "next": "execute",
                },
                {
                    "id": "execute",
                    "tool": "shell",
                    "action": "execute",
                    "permissions": ["read", "execute"],
                    "next": "ingest",
                },
                {"id": "dead", "tool": "email", "terminal": True},
            ],
        },
        {"require_declared_tools": True, "require_termination_path": True},
    )

    indicators = {risk["indicator"] for risk in graph["risks"]}
    assert graph["cycles"] == [["execute", "ingest"]]
    assert "unbounded_workflow_cycle" in indicators
    assert "missing_termination_path" in indicators
    assert "unreachable_workflow_step" in indicators
    assert "undeclared_workflow_tool" in indicators
    assert "tainted_dataflow_to_sensitive_tool" in indicators
    assert "unapproved_privilege_escalation" in indicators


def test_bounded_validated_workflow_has_no_graph_risks():
    ensure_src()
    from aiaf.analysis import analyze_workflow_graph, resolve_agent_policy

    artifact = {
        "tools": ["browser"],
        "workflow_steps": [
            {
                "id": "fetch",
                "tool": "browser",
                "input_source": "external",
                "input_validation": "url allowlist",
                "permissions": ["read", "network"],
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
    }

    graph = analyze_workflow_graph(artifact, resolve_agent_policy("restricted"))

    assert graph["node_count"] == 2
    assert graph["terminal_nodes"] == ["finish"]
    assert graph["risks"] == []


def test_agentic_assurance_engine_persists_audit_and_metric(tmp_path):
    ensure_src()
    from aiaf.core import AgenticAssuranceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "agentic.db"))
    result = AgenticAssuranceEngine(datastore=store).evaluate(
        {
            "id": "agent-1",
            "tools": ["shell"],
            "permissions": ["execute"],
            "autonomy_level": "high",
            "agent_policy_profile": "restricted",
            "workflow_steps": [
                {"id": "run", "tool": "shell", "action": "execute"}
            ],
        }
    )

    assert result["status"] == "NEEDS_REVIEW"
    assert result["finding"]["mapping"]["mapping_version"] == "1.0"
    assert store.list_audit_logs()[0]["event_type"] == "agentic_assurance_evaluation"
    assert store.list_metrics()[0]["metric_name"] == "agent_risk_score"
    store.close()


def test_agentic_routes_expose_profiles_and_validation():
    ensure_src()
    from aiaf.api.agentic import policy_profiles
    from aiaf.api.app import app

    routes = set(app.openapi()["paths"])
    profiles = policy_profiles(api_key="dev-key")

    assert "/v1/agentic/policy-profiles" in routes
    assert "/v1/agentic/validate" in routes
    assert {"restricted", "standard", "development"}.issubset(profiles["profiles"])

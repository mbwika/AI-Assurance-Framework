import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from aiaf.analysis.agent_risk_v2 import (  # noqa: E402
    AGENT_RISK_SCORING_VERSION,
    assess_agent_risk_v2,
)


def _verified_control():
    return {
        "enabled": True,
        "method": "enforced-policy",
        "tested": True,
        "verified": True,
    }


def _agent(**overrides):
    artifact = {
        "id": "agent-1",
        "agentic": True,
        "autonomy_level": "supervised",
        "tools": ["browser"],
        "permissions": ["read", "network"],
        "agent_policy_profile": "restricted",
        "credential_scope": "ephemeral",
        "target_scope": "single_resource",
        "data_scope": "internal",
        "operational_constraints": {
            "max_actions": 10,
            "max_external_calls": 3,
            "max_parallel_actions": 1,
            "max_delegation_depth": 3,
        },
        "workflow_steps": [
            {
                "id": "fetch",
                "tool": "browser",
                "permissions": ["read", "network"],
                "input_source": "external",
                "input_validation": "url allowlist",
                "requires_approval": True,
                "next": "finish",
            },
            {
                "id": "finish",
                "permissions": ["read", "network"],
                "terminal": True,
            },
        ],
    }
    artifact.update(overrides)
    return artifact


def _indicators(result):
    return set(result["indicators"])


def _gates(result):
    return {gate["gate"] for gate in result["score_gates"]}


def test_non_agentic_artifact_is_not_applicable():
    result = assess_agent_risk_v2({"model_name": "plain-model"})

    assert result["applicable"] is False
    assert result["risk_score"] == 0
    assert result["indicators"] == []
    assert result["assessment_complete"] is True


def test_result_is_versioned_deterministic_bounded_and_json_safe():
    artifact = _agent()

    first = assess_agent_risk_v2(artifact)
    second = assess_agent_risk_v2(artifact)

    assert first == second
    assert first["assessment_version"] == AGENT_RISK_SCORING_VERSION == "2.0"
    assert first["score_scale"] == {"minimum": 0.0, "maximum": 10.0}
    assert 0 <= first["lower_confidence_bound"] <= first["residual_risk_score"]
    assert first["residual_risk_score"] <= first["upper_confidence_bound"] <= 10
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_malformed_artifact_fails_closed():
    result = assess_agent_risk_v2("not-an-object")

    assert result["applicable"] is True
    assert result["assessment_complete"] is False
    assert "malformed_agent_artifact" in _indicators(result)
    assert result["severity"] in {"HIGH", "CRITICAL"}


def test_inherent_risk_is_monotonic_with_autonomy():
    low = assess_agent_risk_v2(_agent(autonomy_level="low"))
    high = assess_agent_risk_v2(_agent(autonomy_level="high"))
    autonomous = assess_agent_risk_v2(_agent(autonomy_level="autonomous"))

    assert low["inherent_risk_score"] < high["inherent_risk_score"]
    assert high["inherent_risk_score"] < autonomous["inherent_risk_score"]


def test_adding_lower_authority_cannot_reduce_authority_risk():
    privileged = assess_agent_risk_v2(
        _agent(
            tools=["shell"],
            permissions=["root"],
            workflow_steps=[],
            agent_policy_profile=None,
            agent_policy={"max_autonomy_level": "supervised"},
        )
    )
    expanded = assess_agent_risk_v2(
        _agent(
            tools=["shell", "browser"],
            permissions=["root", "read"],
            workflow_steps=[],
            agent_policy_profile=None,
            agent_policy={"max_autonomy_level": "supervised"},
        )
    )

    assert expanded["dimensions"]["authority"]["score"] >= privileged["dimensions"]["authority"]["score"]
    assert expanded["inherent_risk_score"] >= privileged["inherent_risk_score"]


def test_broader_credential_and_target_scopes_increase_risk():
    scoped = assess_agent_risk_v2(
        _agent(credential_scope="ephemeral", target_scope="single_resource")
    )
    broad = assess_agent_risk_v2(
        _agent(credential_scope="admin", target_scope="unrestricted")
    )

    assert broad["dimensions"]["authority"]["score"] > scoped["dimensions"]["authority"]["score"]
    assert broad["inherent_risk_score"] > scoped["inherent_risk_score"]


def test_verified_controls_reduce_residual_without_rewriting_inherent_risk():
    weak = _agent(
        autonomy_level="high",
        tools=["shell"],
        permissions=["execute"],
        agent_policy={"allowed_tools": ["shell"], "allowed_permissions": ["execute"], "max_autonomy_level": "high"},
    )
    strong = json.loads(json.dumps(weak))
    strong.update(
        {
            name: _verified_control()
            for name in (
                "runtime_tool_authorization",
                "human_review",
                "sandboxing",
                "credential_scoping",
                "continuous_monitoring",
                "audit_logging",
                "kill_switch",
                "rate_limits",
            )
        }
    )

    weak_result = assess_agent_risk_v2(weak)
    strong_result = assess_agent_risk_v2(strong)

    assert weak_result["inherent_risk_score"] == strong_result["inherent_risk_score"]
    assert strong_result["residual_risk_score"] < weak_result["residual_risk_score"]
    assert strong_result["upper_confidence_bound"] <= weak_result["upper_confidence_bound"]
    assert strong_result["control_assessment"]["effectiveness"] == 1.0


def test_disabled_control_strings_receive_no_credit():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="high",
            tools=["shell"],
            permissions=["execute"],
            runtime_tool_authorization="disabled",
            sandboxing="off",
            kill_switch="false",
            agent_policy={"max_autonomy_level": "high"},
        )
    )
    controls = {
        control["control"]: control
        for control in result["control_assessment"]["controls"]
    }

    assert controls["runtime_tool_authorization"]["strength"] == 0
    assert controls["sandboxing"]["strength"] == 0
    assert controls["kill_switch"]["strength"] == 0


def test_planned_controls_and_global_review_declarations_receive_no_credit():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="high",
            tools=["shell"],
            permissions=["execute"],
            human_review_required=True,
            sandboxing={"enabled": True, "method": "sandbox planned"},
            runtime_tool_authorization="pending",
            agent_policy={"max_autonomy_level": "high"},
        )
    )
    controls = {
        control["control"]: control
        for control in result["control_assessment"]["controls"]
    }

    assert controls["human_review"]["strength"] == 0
    assert controls["runtime_tool_authorization"]["strength"] == 0
    assert controls["sandboxing"]["strength"] == 0.2
    assert "global_review_without_graph_enforcement" in _indicators(result)


def test_autonomous_privileged_execution_has_critical_floor():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="autonomous",
            tools=["shell"],
            permissions=["root"],
            agent_policy={"max_autonomy_level": "autonomous"},
        )
    )

    assert "autonomous_privileged_execution" in _indicators(result)
    assert "autonomous_privileged_execution" in _gates(result)
    assert result["risk_score"] >= 8.5
    assert result["severity"] == "CRITICAL"


def test_autonomous_financial_authority_has_critical_floor():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="autonomous",
            tools=["payment"],
            permissions=["transfer_funds"],
            agent_policy={"max_autonomy_level": "autonomous"},
        )
    )

    assert "autonomous_financial_authority" in _indicators(result)
    assert "autonomous_financial_authority" in _gates(result)
    assert result["risk_score"] >= 9


def test_self_modifying_privileged_agent_has_critical_floor():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="high",
            tools=["shell"],
            permissions=["execute"],
            self_modification=True,
            agent_policy={"max_autonomy_level": "high"},
        )
    )

    assert "self_modifying_privileged_agent" in _indicators(result)
    assert "self_modifying_privileged_agent" in _gates(result)


def test_sensitive_persistent_external_agent_requires_runtime_authorization():
    result = assess_agent_risk_v2(
        _agent(
            tools=["email"],
            permissions=["network", "send_email"],
            data_scope="secret",
            memory_persistence="persistent",
            runtime_tool_authorization=False,
            agent_policy={"max_autonomy_level": "supervised"},
        )
    )

    assert "persistent_sensitive_data_exfiltration_path" in _indicators(result)
    assert "sensitive_persistent_agent_without_runtime_authorization" in _gates(result)


def test_critical_workflow_risk_sets_agent_floor():
    artifact = _agent(
        tools=["shell"],
        permissions=["execute"],
        agent_policy_profile=None,
        agent_policy={"allowed_tools": ["shell"], "allowed_permissions": ["execute"], "max_autonomy_level": "supervised"},
        workflow_steps=[
            {
                "id": "run",
                "tool": "shell",
                "action": "execute",
                "permissions": ["execute"],
                "next": "run",
            }
        ],
    )

    result = assess_agent_risk_v2(artifact)

    assert "unbounded_workflow_cycle" in _indicators(result)
    assert "critical_workflow_path" in _gates(result)
    assert result["risk_score"] >= 8


def test_explicit_policy_denial_sets_critical_floor():
    result = assess_agent_risk_v2(
        _agent(
            tools=["shell"],
            permissions=["root"],
            agent_policy_profile="restricted",
        )
    )

    assert "denied_tool" in _indicators(result)
    assert "disallowed_permission" in _indicators(result)
    assert "explicit_policy_denial" in _gates(result)


def test_unknown_policy_profile_and_malformed_budget_fail_closed():
    result = assess_agent_risk_v2(
        _agent(
            agent_policy_profile="does-not-exist",
            operational_constraints={"max_actions": "many"},
        )
    )

    assert result["assessment_complete"] is False
    assert {
        "unknown_or_malformed_agent_policy_profile",
        "malformed_agent_action_budget",
    }.issubset(_indicators(result))


def test_unrecognized_policy_payload_is_not_returned():
    artifact = _agent(
        agent_policy_profile=None,
        agent_policy={
            "allowed_tools": ["browser"],
            "allowed_permissions": ["read", "network"],
            "max_autonomy_level": "supervised",
            "api_key": "super-secret-policy-value",
        },
    )

    result = assess_agent_risk_v2(artifact)

    assert "super-secret-policy-value" not in json.dumps(result)
    assert "api_key" not in result["effective_policy"]


def test_empty_constraints_do_not_satisfy_high_authority_limits():
    result = assess_agent_risk_v2(
        _agent(
            autonomy_level="high",
            tools=["shell"],
            permissions=["execute"],
            operational_constraints={},
            agent_policy_profile=None,
            agent_policy={"max_autonomy_level": "high"},
        )
    )

    assert "missing_effective_operational_limits" in _indicators(result)


def test_tool_and_permission_inventories_are_bounded():
    result = assess_agent_risk_v2(
        _agent(
            tools=[f"tool-{index}" for index in range(101)],
            permissions=[f"permission-{index}" for index in range(201)],
            agent_policy={"max_autonomy_level": "supervised"},
        )
    )

    assert result["assessment_complete"] is False
    assert {
        "malformed_or_excessive_tool_inventory",
        "malformed_or_excessive_permission_inventory",
    }.issubset(_indicators(result))
    assert len(result["evidence"]["tools"]) == 100
    assert len(result["evidence"]["permissions"]) == 200


def test_non_string_authority_inventory_items_fail_closed():
    result = assess_agent_risk_v2(
        _agent(
            tools=["browser", {"tool": "shell"}],
            permissions=["read", True],
        )
    )

    assert result["assessment_complete"] is False
    assert {
        "malformed_or_excessive_tool_inventory",
        "malformed_or_excessive_permission_inventory",
    }.issubset(_indicators(result))
    assert result["evidence"]["tools"] == ["browser"]
    assert result["evidence"]["permissions"] == ["read"]


def test_unscoped_delegation_to_more_privileged_agent_is_critical():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
            ],
            delegations=[{"from": "agent-1", "to": "admin-agent"}],
        )
    )

    assert {
        "unscoped_privilege_amplifying_delegation",
        "transitive_authority_amplification",
    }.issubset(_indicators(result))


def test_scoped_delegation_does_not_expose_constraint_contents():
    artifact = _agent(
        agents=[
            {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
        ],
        delegations=[
            {
                "from": "agent-1",
                "to": "admin-agent",
                "constraints": {
                    "allowed_actions": ["read"],
                    "credential": "super-secret-value",
                },
            }
        ],
    )

    result = assess_agent_risk_v2(artifact)
    serialized = json.dumps(result)

    assert "privilege_amplifying_delegation" in _indicators(result)
    assert "unscoped_privilege_amplifying_delegation" not in _indicators(result)
    assert "transitive_authority_amplification" not in _indicators(result)
    assert "super-secret-value" not in serialized
    edge = result["delegation_analysis"]["edges"][0]
    assert edge["constraints_declared"] is True
    assert edge["constraints_valid"] is True
    assert edge["authority_restricted"] is True
    assert edge["effective_target_authority"] < result["delegation_analysis"][
        "authority_scores"
    ]["admin-agent"]


def test_arbitrary_delegation_metadata_does_not_count_as_a_constraint():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
            ],
            delegations=[
                {
                    "from": "agent-1",
                    "to": "admin-agent",
                    "constraints": {"note": "reviewed someday"},
                }
            ],
        )
    )

    assert "unscoped_privilege_amplifying_delegation" in _indicators(result)
    assert result["delegation_analysis"]["edges"][0]["constraints_declared"] is False


def test_string_false_approval_does_not_scope_privilege_amplifying_delegation():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {
                    "id": "admin-agent",
                    "tools": ["cloud_admin"],
                    "permissions": ["admin"],
                }
            ],
            delegations=[
                {
                    "from": "agent-1",
                    "to": "admin-agent",
                    "constraints": {"requires_approval": "false"},
                }
            ],
        )
    )

    assert "unscoped_privilege_amplifying_delegation" in _indicators(result)
    assert result["delegation_analysis"]["edges"][0]["constraints_declared"] is False


def test_approval_only_does_not_reduce_delegated_authority():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
            ],
            delegations=[
                {
                    "from": "agent-1",
                    "to": "admin-agent",
                    "constraints": {"requires_approval": True},
                }
            ],
        )
    )

    edge = result["delegation_analysis"]["edges"][0]
    assert "unscoped_privilege_amplifying_delegation" in _indicators(result)
    assert edge["constraints_declared"] is True
    assert edge["authority_restricted"] is False


def test_partial_authority_cap_that_still_amplifies_is_critical():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
            ],
            delegations=[
                {
                    "from": "agent-1",
                    "to": "admin-agent",
                    "constraints": {"allowed_actions": ["execute"]},
                }
            ],
        )
    )

    assert {
        "insufficiently_scoped_privilege_amplifying_delegation",
        "transitive_authority_amplification",
    }.issubset(_indicators(result))


def test_malformed_delegation_constraint_fails_closed_without_disclosure():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {"id": "admin-agent", "tools": ["cloud_admin"], "permissions": ["admin"]}
            ],
            delegations=[
                {
                    "from": "agent-1",
                    "to": "admin-agent",
                    "constraints": {"allowed_actions": {"secret": "do-not-emit"}},
                }
            ],
        )
    )

    edge = result["delegation_analysis"]["edges"][0]
    assert result["assessment_complete"] is False
    assert "malformed_delegation_constraints" in _indicators(result)
    assert "unscoped_privilege_amplifying_delegation" in _indicators(result)
    assert edge["constraints_valid"] is False
    assert edge["authority_restricted"] is False
    assert "do-not-emit" not in json.dumps(result)


def test_root_credential_and_target_scope_count_toward_delegation_authority():
    result = assess_agent_risk_v2(
        _agent(
            tools=[],
            permissions=[],
            credential_scope="admin",
            target_scope="unrestricted",
            agents=[
                {"id": "worker", "tools": ["browser"], "permissions": ["read"]}
            ],
            delegations=[{"from": "agent-1", "to": "worker"}],
        )
    )

    assert "unscoped_privilege_amplifying_delegation" not in _indicators(result)
    assert "transitive_authority_amplification" not in _indicators(result)


def test_malformed_delegated_authority_fails_closed_without_disclosure():
    result = assess_agent_risk_v2(
        _agent(
            agents=[
                {
                    "id": "worker",
                    "tools": [{"secret": "hidden-authority"}],
                    "permissions": ["admin"],
                }
            ],
            delegations=[{"from": "agent-1", "to": "worker"}],
        )
    )

    assert result["assessment_complete"] is False
    assert "malformed_delegated_authority" in _indicators(result)
    assert "hidden-authority" not in json.dumps(result)


def test_recursive_delegation_is_iterative_and_requires_depth_bound():
    agents = [
        {"id": f"worker-{index}", "tools": ["browser"], "permissions": ["read"]}
        for index in range(200)
    ]
    delegations = [
        {"from": "agent-1", "to": "worker-0"},
        *[
            {"from": f"worker-{index}", "to": f"worker-{index + 1}"}
            for index in range(199)
        ],
        {"from": "worker-199", "to": "worker-0"},
    ]
    unbounded = assess_agent_risk_v2(
        _agent(agents=agents, delegations=delegations, operational_constraints={"max_actions": 10})
    )
    bounded = assess_agent_risk_v2(
        _agent(
            agents=agents,
            delegations=delegations,
            operational_constraints={"max_actions": 10, "max_delegation_depth": 5},
        )
    )

    assert len(unbounded["delegation_analysis"]["cycles"][0]) == 200
    assert "unbounded_recursive_delegation" in _indicators(unbounded)
    assert "unbounded_agent_execution" in _gates(unbounded)
    assert "delegation_cycle" in _indicators(bounded)
    assert "unbounded_recursive_delegation" not in _indicators(bounded)


def test_unknown_delegation_agent_marks_assessment_incomplete():
    result = assess_agent_risk_v2(
        _agent(delegations=[{"from": "agent-1", "to": "missing-agent"}])
    )

    assert result["assessment_complete"] is False
    assert "unknown_delegation_agent" in _indicators(result)

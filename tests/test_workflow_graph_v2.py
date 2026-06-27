import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from aiaf.analysis.workflow_graph import (  # noqa: E402
    WORKFLOW_GRAPH_SCORING_VERSION,
    analyze_workflow_graph,
)


def _indicators(result):
    return {risk["indicator"] for risk in result["risks"]}


def _risks(result, indicator):
    return [risk for risk in result["risks"] if risk["indicator"] == indicator]


def test_result_is_versioned_deterministic_and_json_safe():
    artifact = {
        "workflow_steps": [
            {"id": "start", "next": "finish"},
            {"id": "finish", "terminal": True},
        ]
    }

    first = analyze_workflow_graph(artifact)
    second = analyze_workflow_graph(artifact)

    assert first == second
    assert first["scoring_version"] == WORKFLOW_GRAPH_SCORING_VERSION == "2.0"
    assert first["assessment_complete"] is True
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_malformed_inputs_are_fail_closed_and_mark_assessment_incomplete():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [{"id": "start"}, None],
            "workflow_edges": "start->finish",
        },
        policy="permissive",
    )

    assert result["assessment_complete"] is False
    assert {
        "malformed_workflow_policy",
        "malformed_workflow_step",
        "malformed_workflow_edges",
    }.issubset(_indicators(result))


def test_node_analysis_is_bounded():
    steps = [{"id": f"step-{index}"} for index in range(1_001)]

    result = analyze_workflow_graph({"workflow_steps": steps})

    assert result["node_count"] == 1_000
    assert result["assessment_complete"] is False
    assert "workflow_node_limit_exceeded" in _indicators(result)
    assert result["graph_metrics"]["provided_node_count"] == 1_001


def test_iterative_scc_handles_cycle_at_node_limit_without_recursion():
    steps = [
        {"id": f"step-{index}", "next": f"step-{(index + 1) % 1_000}"}
        for index in range(1_000)
    ]

    result = analyze_workflow_graph(
        {"workflow_steps": steps}, {"max_workflow_iterations": 10}
    )

    assert len(result["cycles"]) == 1
    assert len(result["cycles"][0]) == 1_000
    assert result["graph_metrics"]["cyclic_component_count"] == 1
    assert "unbounded_workflow_cycle" not in _indicators(result)


def test_terminal_branch_does_not_hide_nonterminating_region():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": ["finish", "loop-a"]},
                {"id": "finish", "terminal": True},
                {"id": "loop-a", "next": "loop-b"},
                {"id": "loop-b", "next": "loop-a"},
            ]
        }
    )

    assert "missing_termination_path" not in _indicators(result)
    assert "nonterminating_workflow_region" in _indicators(result)
    assert result["nodes_without_terminal_path"] == ["loop-a", "loop-b"]


def test_bounded_loop_controller_with_exit_is_accepted():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": "loop"},
                {
                    "id": "loop",
                    "max_iterations": 3,
                    "next": ["loop", "finish"],
                },
                {"id": "finish", "terminal": True},
            ]
        }
    )

    assert "unbounded_workflow_cycle" not in _indicators(result)
    assert "cycle_without_exit_path" not in _indicators(result)
    assert result["graph_metrics"]["cycle_bounds"] == [
        {"nodes": ["loop"], "maximum_iterations": 3}
    ]


def test_controller_bound_rejected_when_internal_subcycle_bypasses_it():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": "controller"},
                {
                    "id": "controller",
                    "max_iterations": 3,
                    "next": ["a", "finish"],
                },
                {"id": "a", "next": "b"},
                {"id": "b", "next": ["a", "controller"]},
                {"id": "finish", "terminal": True},
            ]
        }
    )

    assert "unbounded_workflow_cycle" in _indicators(result)
    assert result["graph_metrics"]["cycle_bounds"][0]["maximum_iterations"] is None


def test_invalid_iteration_bound_is_not_treated_as_a_control():
    result = analyze_workflow_graph(
        {
            "operational_constraints": {"max_iterations": 0},
            "workflow_steps": [{"id": "loop", "next": "loop"}],
        }
    )

    assert result["assessment_complete"] is False
    assert {
        "invalid_workflow_iteration_bound",
        "unbounded_workflow_cycle",
    }.issubset(_indicators(result))


def test_approval_guard_must_intersect_every_path_to_sensitive_action():
    guarded = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": "review"},
                {"id": "review", "action": "approve", "next": "send"},
                {"id": "send", "tool": "email", "action": "send-email"},
            ]
        }
    )
    bypassed = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": ["review", "send"]},
                {"id": "review", "action": "approve", "next": "send"},
                {"id": "send", "tool": "email", "action": "send-email"},
            ]
        }
    )

    assert "sensitive_action_without_approval_guard" not in _indicators(guarded)
    risk = _risks(bypassed, "sensitive_action_without_approval_guard")[0]
    assert risk["evidence"]["unguarded_path"] == ["start", "send"]


def test_self_approval_does_not_satisfy_separation_of_duties():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {
                    "id": "deploy",
                    "tool": "cloud-admin",
                    "action": "deploy",
                    "requires_approval": True,
                    "actor": "release-bot",
                    "approved_by": "release bot",
                }
            ]
        }
    )

    assert "self_approved_sensitive_action" in _indicators(result)


def test_global_review_declaration_does_not_replace_a_graph_cut():
    result = analyze_workflow_graph(
        {
            "human_review_required": True,
            "workflow_steps": [
                {"id": "start", "next": "send"},
                {"id": "send", "tool": "email", "action": "send-email"},
            ],
        }
    )

    assert {
        "global_review_without_graph_enforcement",
        "sensitive_action_without_approval_guard",
    }.issubset(_indicators(result))


def test_cross_node_self_approval_does_not_satisfy_guard_cut():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": "review"},
                {
                    "id": "review",
                    "action": "approve",
                    "actor": "release-bot",
                    "next": "deploy",
                },
                {
                    "id": "deploy",
                    "tool": "cloud-admin",
                    "action": "deploy",
                    "actor": "release bot",
                },
            ]
        }
    )

    self_approval = _risks(result, "self_approved_sensitive_action")[0]
    assert self_approval["evidence"]["approval_guard"] == "review"
    assert self_approval["evidence"]["node"] == "deploy"
    assert "sensitive_action_without_approval_guard" in _indicators(result)


def test_unrelated_same_actor_review_is_not_misclassified_as_self_approval():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "start", "next": "deploy"},
                {
                    "id": "deploy",
                    "tool": "cloud-admin",
                    "action": "deploy",
                    "actor": "release-bot",
                },
                {
                    "id": "unrelated-review",
                    "action": "approve",
                    "actor": "release-bot",
                },
            ]
        }
    )

    assert "self_approved_sensitive_action" not in _indicators(result)
    assert "sensitive_action_without_approval_guard" in _indicators(result)


def test_disabled_validation_does_not_clear_untrusted_taint():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {
                    "id": "input",
                    "input_source": "external",
                    "input_validation": "disabled",
                    "next": "execute",
                },
                {"id": "execute", "tool": "shell", "action": "execute"},
            ]
        }
    )

    risk = _risks(result, "tainted_dataflow_to_sensitive_tool")[0]
    assert risk["evidence"] == {
        "node": "execute",
        "taint": "untrusted",
        "path": ["input", "execute"],
    }


def test_planned_validation_does_not_clear_untrusted_taint():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {
                    "id": "input",
                    "input_source": "external",
                    "input_validation": "allowlist planned",
                    "next": "execute",
                },
                {"id": "execute", "tool": "shell", "action": "execute"},
            ]
        }
    )

    assert "tainted_dataflow_to_sensitive_tool" in _indicators(result)


def test_effective_validation_dominates_sensitive_sink_and_clears_taint():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "input", "input_source": "external", "next": "validate"},
                {
                    "id": "validate",
                    "input_validation": {"enabled": True, "strategy": "allowlist"},
                    "next": "execute",
                },
                {"id": "execute", "tool": "shell", "action": "execute"},
            ]
        }
    )

    assert "tainted_dataflow_to_sensitive_tool" not in _indicators(result)


def test_model_output_to_code_execution_has_path_witness():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {"id": "generate", "input_source": "model-output", "next": "run"},
                {"id": "run", "tool": "shell", "action": "execute"},
            ]
        }
    )

    risk = _risks(result, "model_output_to_code_execution")[0]
    assert risk["severity"] == "CRITICAL"
    assert risk["evidence"]["path"] == ["generate", "run"]


def test_sensitive_data_to_external_sink_and_dlp_cut_are_distinguished():
    base_steps = [
        {
            "id": "records",
            "data_classification": "PHI",
            "next": "send",
        },
        {"id": "send", "tool": "email", "action": "send-email"},
    ]
    exposed = analyze_workflow_graph({"workflow_steps": base_steps})
    protected_steps = [dict(step) for step in base_steps]
    protected_steps[0]["data_loss_prevention"] = "redaction policy"
    protected = analyze_workflow_graph({"workflow_steps": protected_steps})

    risk = _risks(exposed, "sensitive_dataflow_to_external_sink")[0]
    assert risk["severity"] == "CRITICAL"
    assert risk["evidence"]["path"] == ["records", "send"]
    assert "sensitive_dataflow_to_external_sink" not in _indicators(protected)


def test_untrusted_data_controlling_routing_is_detected():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {
                    "id": "router",
                    "input_source": "user",
                    "dynamic_routing": True,
                    "next": "finish",
                },
                {"id": "finish", "terminal": True},
            ]
        }
    )

    assert "untrusted_data_controls_workflow" in _indicators(result)


def test_privilege_escalation_requires_an_approval_cut_on_every_path():
    result = analyze_workflow_graph(
        {
            "workflow_steps": [
                {
                    "id": "start",
                    "permissions": ["read"],
                    "next": ["review", "admin"],
                },
                {"id": "review", "action": "approve", "next": "admin"},
                {
                    "id": "admin",
                    "permissions": ["read", "admin"],
                    "terminal": True,
                },
            ]
        }
    )

    risk = _risks(result, "unapproved_privilege_escalation")[0]
    assert risk["severity"] == "CRITICAL"
    assert risk["evidence"]["transition"] == "start->admin"

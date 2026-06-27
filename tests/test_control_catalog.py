import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_control_catalog_covers_core_objectives():
    ensure_src()
    from aiaf.mapping.control_catalog import get_control_catalog

    catalog = get_control_catalog()
    objectives = {control["objective"] for control in catalog}
    control_ids = {control["id"] for control in catalog}

    assert "Establish Continuous AI Security Assurance" in objectives
    assert "Strengthen AI Supply Chain Integrity" in objectives
    assert "Improve Agentic AI Security" in objectives
    assert "Support AI Governance" in objectives
    assert {
        "AIAF-GOV-001",
        "AIAF-GOV-003",
        "AIAF-GOV-004",
        "AIAF-GOV-005",
        "AIAF-RISK-001",
        "AIAF-RISK-003",
        "AIAF-RISK-004",
        "AIAF-SC-001",
        "AIAF-SC-007",
        "AIAF-SC-008",
        "AIAF-AGT-001",
        "AIAF-AGT-005",
    }.issubset(control_ids)


def test_governance_engine_evaluates_catalog_controls():
    ensure_src()
    from aiaf.core import GovernanceEngine

    artifact = {
        "id": "assurance-target-1",
        "assurance_scope": "artifact",
        "owner": "AI Platform",
        "risk_owner": "Security Governance",
        "remediation_sla": {"critical_hours": 24, "high_hours": 72},
        "evidence_review_policy": "independent-review-v1",
        "evidence_retention_period": "7 years",
        "report_snapshot_policy": "signed-quarterly-and-release",
        "advisory_feed_policy": "signed-feed-v1",
        "monitoring_enabled": True,
        "assessment_frequency": "weekly",
        "adversarial_tests": [{"name": "prompt injection baseline", "passed": True}],
        "model_risk_profile": {
            "impact_level": "moderate",
            "deployment_exposure": "internal",
            "data_classification": "internal",
            "capabilities": ["text_generation"],
            "access_controls": ["api_key"],
            "output_validation": "policy_filter",
            "safety_evaluations": [{"name": "baseline", "passed": True}],
            "human_oversight": True,
        },
        "source_url": "https://huggingface.co/acme/tiny",
        "publisher": "Acme AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "dependencies": ["transformers", "torch"],
        "training_artifacts": [
            {"name": "instruction-tuning-set", "source_url": "https://example.com/data.jsonl", "sha256": "b" * 64}
        ],
        "deployment_pipeline": {
            "environment": "staging",
            "artifact_ref": "registry.example.com/acme/tiny@sha256:abc",
            "approval_gate": "CAB-123",
        },
        "provenance_attestations": [
            {"algorithm": "HMAC-SHA256", "signature": "a" * 64}
        ],
        "vulnerability_scan": {
            "status": "COMPLETE",
            "catalog_advisory_count": 100,
            "scanned_dependency_count": 2,
            "unresolved_dependencies": [],
            "matches": [],
            "match_count": 0,
        },
        "tools": ["browser"],
        "permissions": ["read"],
        "autonomy_level": "supervised",
        "human_review_required": True,
        "agent_policy": {
            "allowed_tools": ["browser"],
            "allowed_permissions": ["read"],
            "max_autonomy_level": "supervised",
            "require_human_review_for_tools": ["browser"],
        },
        "workflow_steps": [
            {
                "id": "fetch",
                "tool": "browser",
                "action": "read",
                "input_source": "external",
                "input_validation": "url allowlist",
                "permissions": ["read"],
                "requires_approval": True,
                "next": "finish",
            },
            {
                "id": "finish",
                "action": "finish",
                "permissions": ["read"],
                "terminal": True,
            },
        ],
        "runtime_tool_authorization": True,
        "has_bias_evaluation": True,
        "has_fairness_metrics": True,
        "has_factuality_evaluation": True,
        "has_output_grounding": True,
        "compliance_scope": ["NIST AI RMF", "MITRE ATLAS"],
        "documentation_url": "https://example.com/model-card",
    }

    result = GovernanceEngine().evaluate(artifact)

    assert result["status"] == "PASS"
    assert result["summary"]["by_status"]["satisfied"] == result["summary"]["total_controls"]
    assert not result["gaps"]
    assert all("standards" in control for control in result["controls"])
    assert all("threats" in control for control in result["controls"])


def test_governance_engine_marks_missing_and_not_applicable_controls():
    ensure_src()
    from aiaf.core import GovernanceEngine

    result = GovernanceEngine().evaluate({"id": "metadata-only"})
    statuses = {control["id"]: control["status"] for control in result["controls"]}

    assert result["status"] == "NEEDS_REVIEW"
    assert statuses["AIAF-GOV-001"] == "missing"
    assert statuses["AIAF-SC-002"] == "missing"
    assert statuses["AIAF-AGT-001"] == "not_applicable"
    assert statuses["AIAF-AGT-002"] == "not_applicable"
    assert statuses["AIAF-AGT-003"] == "not_applicable"
    assert statuses["AIAF-AGT-004"] == "not_applicable"
    assert statuses["AIAF-AGT-005"] == "not_applicable"
    assert statuses["AIAF-AGT-006"] == "not_applicable"
    assert statuses["AIAF-RISK-005"] == "not_applicable"
    assert statuses["AIAF-RISK-006"] == "not_applicable"
    assert result["summary"]["by_status"]["missing"] >= 1
    assert result["summary"]["by_status"]["not_applicable"] == 8


def test_new_reliability_and_invocation_controls_detect_gaps():
    ensure_src()
    from aiaf.core import GovernanceEngine

    # A model + agent artifact that omits bias, factuality, and per-invocation
    # evidence must flag the v0.2.0 analyzer controls as missing, not satisfied.
    artifact = {
        "id": "gap-model",
        "model_risk_profile": {"impact_level": "high", "domain": "hiring"},
        "tools": ["browser"],
        "permissions": ["read"],
        "autonomy_level": "supervised",
    }
    result = GovernanceEngine().evaluate(artifact)
    statuses = {control["id"]: control["status"] for control in result["controls"]}

    assert statuses["AIAF-RISK-005"] == "missing"  # bias & fairness
    assert statuses["AIAF-RISK-006"] == "missing"  # factual reliability
    assert statuses["AIAF-AGT-006"] == "missing"   # per-tool invocation context
    assert result["status"] == "NEEDS_REVIEW"


def test_control_summary_surfaces_model_reliability_domain():
    ensure_src()
    from aiaf.mapping.control_catalog import (
        evaluate_catalog_controls,
        summarize_control_evaluations,
    )

    artifact = {
        "id": "gap-model",
        "model_risk_profile": {"impact_level": "high", "domain": "hiring"},
        "tools": ["browser"],
        "permissions": ["read"],
        "autonomy_level": "supervised",
    }
    summary = summarize_control_evaluations(evaluate_catalog_controls(artifact))

    # The bias and factual-reliability controls form a distinct, visible domain.
    assert "by_domain" in summary
    assert summary["by_domain"]["Model Reliability"]["missing"] == 2
    # The per-tool invocation control surfaces under the agentic domain.
    assert summary["by_domain"]["Agentic AI"].get("missing", 0) >= 1


def test_governance_controls_api_exposes_catalog():
    ensure_src()
    from aiaf.api.app import app
    from aiaf.api.governance import governance_controls

    routes = set(app.openapi()["paths"].keys())
    payload = governance_controls(api_key="dev-key")

    assert "/v1/governance/controls" in routes
    assert "controls" in payload
    assert any(control["id"] == "AIAF-RISK-001" for control in payload["controls"])


def test_finding_mappings_are_versioned_and_use_current_control_ids():
    ensure_src()
    from aiaf.mapping.standards import map_finding_to_controls

    prompt_mapping = map_finding_to_controls({"type": "prompt_injection"})
    agent_mapping = map_finding_to_controls({"type": "agent_risk"})
    adversarial_mapping = map_finding_to_controls({"type": "adversarial_testing"})

    assert prompt_mapping["mapping_version"] == "1.0"
    assert all(item["version"] and item["source_url"] for item in prompt_mapping["controls"])
    assert "AML.T0051 LLM Prompt Injection" in _mapped_controls(prompt_mapping, "MITRE ATLAS")
    assert "AML.T0053 AI Agent Tool Invocation" in _mapped_controls(agent_mapping, "MITRE ATLAS")
    assert "AML.T0043 Craft Adversarial Data" in _mapped_controls(adversarial_mapping, "MITRE ATLAS")
    assert "MEASURE 2.7" in _mapped_controls(prompt_mapping, "NIST AI RMF")


def _mapped_controls(mapping, standard):
    return next(
        item["controls"] for item in mapping["controls"] if item["standard"] == standard
    )

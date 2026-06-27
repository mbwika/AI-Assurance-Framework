import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_architecture_catalog_covers_required_layers_and_components():
    ensure_src()
    from aiaf.architecture import get_architecture_catalog

    catalog = get_architecture_catalog()
    layer_ids = {layer["id"] for layer in catalog["layers"]}

    assert catalog["name"] == "AI Assurance Framework"
    assert catalog["layer_count"] >= 6
    assert catalog["component_count"] >= 26
    assert {
        "user_portal",
        "api_gateway",
        "core_engines",
        "security_analysis",
        "knowledge_mapping",
        "data_analytics",
    }.issubset(layer_ids)

    analysis = next(layer for layer in catalog["layers"] if layer["id"] == "security_analysis")
    analysis_names = {component["name"] for component in analysis["components"]}
    assert "Prompt Injection Detection" in analysis_names
    assert "Jailbreak Analysis" in analysis_names
    assert "Model Risk Assessment" in analysis_names
    assert "Agent Risk Assessment" in analysis_names
    assert "Tool Invocation Risk Engine" in analysis_names
    assert "Workflow Security Validator" in analysis_names
    assert "Agent Policy Constraint Evaluator" in analysis_names
    assert "Runtime Tool Authorization" in analysis_names
    assert "Workflow Graph Security Analyzer" in analysis_names
    assert "Supply Chain Validation" in analysis_names
    assert "Dependency Risk Analysis" in analysis_names
    assert "Dependency Vulnerability Matching" in analysis_names
    assert "Data Leakage Detection" in analysis_names
    assert "Adversarial Testing" in analysis_names
    assert "Trustworthiness Scoring" in analysis_names
    # v0.2.0 additions
    assert "Bias & Fairness Assessment" in analysis_names
    assert "Hallucination Risk Assessment" in analysis_names

    data = next(layer for layer in catalog["layers"] if layer["id"] == "data_analytics")
    data_names = {component["name"] for component in data["components"]}
    assert "Training Artifact Evidence" in data_names
    assert "Deployment Pipeline Evidence" in data_names
    assert "Assessment Schedules" in data_names
    assert "Assessment Run History" in data_names
    assert "Control Evidence Repository" in data_names
    assert "Agent Runtime Sessions" in data_names
    assert "Tool Authorization Decisions" in data_names
    assert "Managed Risk Register" in data_names
    assert "Immutable Assurance Report Snapshots" in data_names

    # v0.2.0: verify new layers exist
    assert "auth" in layer_ids
    assert "observability" in layer_ids
    assert "notifications" in layer_ids
    assert "plugins" in layer_ids

    # Knowledge mapping layer includes EU AI Act and ISO 42001
    km = next(layer for layer in catalog["layers"] if layer["id"] == "knowledge_mapping")
    km_names = {c["name"] for c in km["components"]}
    assert "EU AI Act (2024/1689) Mapping" in km_names
    assert "ISO/IEC 42001:2023 AIMS Mapping" in km_names

    portal = next(layer for layer in catalog["layers"] if layer["id"] == "user_portal")
    portal_names = {component["name"] for component in portal["components"]}
    assert "Model Registry Dashboard" in portal_names
    assert "Architecture Overview" in portal_names


def test_architecture_catalog_modules_are_importable():
    ensure_src()
    import importlib

    from aiaf.architecture import get_architecture_catalog

    catalog = get_architecture_catalog()
    modules = {
        component["module"]
        for layer in catalog["layers"]
        for component in layer["components"]
        if component.get("module") and component.get("status") != "planned"
    }

    for module_name in sorted(modules):
        assert importlib.import_module(module_name)


def test_architecture_route_registered():
    ensure_src()
    from aiaf.api.app import app

    routes = set(app.openapi()["paths"].keys())
    assert "/v1/architecture" in routes
    assert "/v1/reporting/assurance-report" in routes
    assert "/v1/reporting/alerts" in routes
    assert "/v1/reporting/compliance" in routes
    assert "/v1/reporting/snapshots" in routes
    assert "/v1/reporting/snapshots/{snapshot_id}" in routes
    assert "/v1/reporting/snapshots/{snapshot_id}/verify" in routes
    assert "/v1/monitoring/schedules" in routes
    assert "/v1/monitoring/run-due" in routes
    assert "/v1/agentic/policy-profiles" in routes
    assert "/v1/agentic/validate" in routes
    assert "/v1/agentic/sessions" in routes
    assert "/v1/agentic/sessions/{session_id}/authorize" in routes
    assert "/v1/agentic/invocations" in routes
    assert "/v1/risks" in routes
    assert "/v1/risks/{risk_id}" in routes
    assert "/v1/supply-chain/advisories/import" in routes
    assert "/v1/supply-chain/advisories" in routes
    assert "/v1/supply-chain/scan" in routes
    assert "/v1/governance/evidence" in routes
    assert "/v1/governance/evidence/{evidence_id}/review" in routes

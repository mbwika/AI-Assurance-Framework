def test_package_imports():
    import importlib
    import sys
    from pathlib import Path

    # Ensure src is on the path for test discovery
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)

    # basic smoke-test: ensure package imports and core components exist
    pkg = importlib.import_module("aiaf")
    assert hasattr(pkg, "RiskEngine")
    assert hasattr(pkg, "GovernanceEngine")
    assert hasattr(pkg, "MonitoringEngine")
    assert hasattr(pkg, "ReportingEngine")
    assert hasattr(pkg, "AssuranceReportSnapshotEngine")

    analysis = importlib.import_module("aiaf.analysis")
    assert hasattr(analysis, "assess_agent_risk_v2")
    assert hasattr(analysis, "estimate_model_risk_v2")
    assert hasattr(analysis, "detect_data_leakage")
    assert hasattr(analysis, "validate_supply_chain")

    app = importlib.import_module("aiaf.api.app")
    routes = set(app.app.openapi()["paths"].keys())
    assert "/" in routes
    assert "/v1/architecture" in routes
    assert "/v1/risk/analyze" in routes
    assert "/v1/governance/evaluate" in routes
    assert "/v1/reporting/summary" in routes
    assert "/v1/reporting/snapshots" in routes
    assert "/v1/monitoring/schedules" in routes

    data = importlib.import_module("aiaf.data")
    store = data.InMemoryVectorStore()
    store.upsert("doc-1", [1.0, 0.0], {"kind": "control"})
    store.upsert("doc-2", [0.0, 1.0], {"kind": "finding"})
    results = store.query([1.0, 0.0])
    assert results[0]["id"] == "doc-1"

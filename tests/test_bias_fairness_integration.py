"""Integration tests for wiring the bias/fairness analyzer into the engine.

These cover orchestration glue (artifact-sourced context, serialization,
finding emission, mapping, persistence) rather than the scoring heuristics,
which are unit-tested in test_bias_fairness.py.
"""
import json
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_high_stakes_hiring_becomes_mapped_persisted_finding(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "bf_high.db"))
    artifact = {
        "id": "hiring-model",
        "content": "benign",
        "domain": "hiring",
        # no bias evaluation, no oversight declared
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    by_type = {f["type"]: f for f in record["findings"]}

    assert "bias_fairness" in by_type
    finding = by_type["bias_fairness"]
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert "high_stakes_domain" in finding["detail"]["indicators"]

    # Mapping resolves to NIST AI RMF and EU AI Act.
    standards = {entry["standard"] for entry in finding["mapping"]["controls"]}
    assert "NIST AI RMF" in standards
    assert "EU AI Act" in standards

    # JSON-serializable for persistence (no enum/dataclass remnants).
    json.dumps(record["findings"])
    assert "bias_fairness_metric" in record["persistence"]["operations"]
    assert len(store.list_findings()) >= 1


def test_well_controlled_model_below_finding_floor(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "bf_low.db"))
    artifact = {
        "id": "balanced-model",
        "content": "benign",
        "domain": "resource_allocation",
        "has_bias_evaluation": True,
        "has_fairness_metrics": True,
        "has_demographic_parity_check": True,
        "has_disparate_impact_analysis": True,
        "has_counterfactual_testing": True,
        "human_oversight_level": "independent",
        "group_metrics": [
            {"group": "group_a", "sample_size": 1000, "favorable_outcomes": 500},
            {"group": "group_b", "sample_size": 1000, "favorable_outcomes": 500},
        ],
        "bias_evaluation_context": {
            "fairness_goal": "demographic_parity",
            "sensitive_attribute_use": "audit_only",
            "counterfactual_changed_outcomes": 0,
            "counterfactual_total": 1000,
        },
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    finding_types = {f["type"] for f in record["findings"]}

    # Balanced evidence keeps severity below the MEDIUM finding floor.
    assert "bias_fairness" not in finding_types
    # Trend metric is persisted regardless of finding emission.
    assert "bias_fairness_metric" in record["persistence"]["operations"]


def test_bias_fairness_maps_to_controls():
    ensure_src()
    from aiaf.mapping.standards import map_finding_to_controls

    mapping = map_finding_to_controls({"type": "bias_fairness"})
    standards = {entry["standard"] for entry in mapping["controls"]}
    assert "NIST AI RMF" in standards
    assert "EU AI Act" in standards

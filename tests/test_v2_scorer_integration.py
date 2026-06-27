"""Integration tests for the v2 model-risk and agent-risk engine migration.

These cover the architect-owned orchestration glue: the engine drives the v2
scorers, gates findings at applicable + MEDIUM severity (not merely score > 0),
and persists the enriched residual/confidence/gate trend metrics. The scoring
heuristics themselves are unit-tested in test_model_risk_v2 / test_agent_risk_v2.
"""
import json
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _metric(store, name):
    return next(m for m in store.list_metrics() if m["metric_name"] == name)


def test_engine_uses_model_risk_v2_with_enriched_metric(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "mr_v2.db"))
    record = RiskEngine(datastore=store).analyze(
        {
            "id": "critical-model",
            "content": "benign",
            "model_risk_profile": {
                "impact_level": "critical",
                "deployment_exposure": "public",
                "data_classification": "restricted",
                "capabilities": ["autonomous_actions", "code_execution"],
            },
        }
    )

    finding = next(f for f in record["findings"] if f["type"] == "model_risk")
    assert finding["detail"]["assessment_version"] == "2.0"
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    json.dumps(record["findings"])

    dims = _metric(store, "model_risk_score")["dimensions"]
    assert dims["scoring_version"] == "2.0"
    for field in (
        "inherent_risk_score",
        "residual_risk_score",
        "lower_confidence_bound",
        "upper_confidence_bound",
        "confidence",
        "score_gates",
    ):
        assert field in dims


def test_non_agentic_artifact_skips_agent_risk(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "agent_na.db"))
    record = RiskEngine(datastore=store).analyze({"id": "plain", "content": "benign"})

    # applicable-gated: a non-agentic artifact yields neither a finding nor a metric.
    assert "agent_risk" not in {f["type"] for f in record["findings"]}
    assert "agent_risk_metric" not in record["persistence"]["operations"]
    # supply-chain risk is always persisted, even on a clean run.
    assert "supply_chain_metric" in record["persistence"]["operations"]


def test_agentic_artifact_emits_v2_agent_finding_and_metric(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "agent_v2.db"))
    record = RiskEngine(datastore=store).analyze(
        {
            "id": "agent-x",
            "content": "benign",
            "tools": ["shell"],
            "permissions": ["execute"],
            "autonomy_level": "high",
            "workflow_steps": [{"id": "run", "tool": "shell", "action": "execute"}],
        }
    )

    finding = next(f for f in record["findings"] if f["type"] == "agent_risk")
    assert finding["detail"]["assessment_version"] == "2.0"
    assert finding["detail"]["applicable"] is True
    assert finding["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    json.dumps(record["findings"])

    dims = _metric(store, "agent_risk_score")["dimensions"]
    assert dims["scoring_version"] == "2.0"
    assert dims["workflow_graph"]["scoring_version"] == "2.0"
    assert "delegation" in dims
    assert "residual_risk_score" in dims


def test_supply_chain_metric_persisted_on_zero_risk(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "sc_zero.db"))
    record = RiskEngine(datastore=store).analyze({"id": "clean", "content": "benign"})

    assert "supply_chain_metric" in record["persistence"]["operations"]
    metric = _metric(store, "supply_chain_risk_score")
    assert metric["dimensions"]["scoring_version"] == "2.0"

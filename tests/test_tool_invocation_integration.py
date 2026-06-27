"""Integration tests for wiring the tool-invocation analyzer into the engine.

These cover the orchestration glue (collection, serialization, finding
emission, mapping, and persistence) rather than the scoring heuristics, which
are unit-tested in test_tool_invocation_risk.py.
"""
import json
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_workflow_step_invocation_becomes_a_mapped_persisted_finding(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "ti.db"))
    artifact = {
        "id": "agent-1",
        "content": "benign",
        "workflow_steps": [
            {
                "name": "exec-step",
                "tool": "run_command",
                "action": "execute_code",
                "input_source": "model_output",
                "permissions": ["execute:*"],
                "is_idempotent": False,
            }
        ],
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    by_type = {finding["type"]: finding for finding in record["findings"]}

    assert "tool_invocation_risk" in by_type
    finding = by_type["tool_invocation_risk"]
    assert finding["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert finding["detail"]["highest_risk_tool"] == "run_command"
    assert finding["detail"]["invocation_count"] == 1

    # Mapping is attached and resolves to the new standards entry.
    standards = {entry["standard"] for entry in finding["mapping"]["controls"]}
    assert "MITRE ATLAS" in standards
    assert "OWASP Top 10 for LLMs" in standards

    # Finding must be JSON-serializable for persistence (enum/dataclass-free).
    json.dumps(record["findings"])
    assert "tool_invocation_metric" in record["persistence"]["operations"]
    assert len(store.list_findings()) >= 1


def test_safe_only_invocation_records_metric_without_finding(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "ti_safe.db"))
    artifact = {
        "id": "agent-2",
        "content": "benign",
        "tool_invocations": [
            {
                "tool_name": "read_file",
                "declared_permissions": ["read:documentation"],
                "has_input_validation": True,
                "has_output_sanitization": True,
                "is_idempotent": True,
            }
        ],
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    finding_types = {finding["type"] for finding in record["findings"]}

    # SAFE tier stays below the MEDIUM finding floor, but the trend metric is kept.
    assert "tool_invocation_risk" not in finding_types
    assert "tool_invocation_metric" in record["persistence"]["operations"]


def test_artifact_without_invocations_skips_tool_assessment(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "ti_none.db"))
    # Bare `tools` list is handled by agent_risk, not the per-invocation analyzer.
    record = RiskEngine(datastore=store).analyze(
        {"id": "agent-3", "content": "benign", "tools": ["shell"]}
    )

    assert "tool_invocation_risk" not in {f["type"] for f in record["findings"]}
    assert "tool_invocation_metric" not in record["persistence"]["operations"]


def test_tool_invocation_risk_maps_to_controls():
    ensure_src()
    from aiaf.mapping.standards import map_finding_to_controls

    mapping = map_finding_to_controls({"type": "tool_invocation_risk"})
    standards = {entry["standard"] for entry in mapping["controls"]}
    assert "MITRE ATLAS" in standards
    assert "OWASP Top 10 for LLMs" in standards
    assert "CIS Controls" in standards

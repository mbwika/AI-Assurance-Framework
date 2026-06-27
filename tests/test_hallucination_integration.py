"""Integration tests for wiring the hallucination-risk analyzer into the engine.

These cover orchestration glue (collection, serialization, finding emission,
mapping, persistence) rather than scoring heuristics, which are unit-tested in
test_hallucination_risk.py.
"""
import json
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_high_stakes_domain_becomes_critical_finding(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "hr_high.db"))
    artifact = {
        "id": "model-medical",
        "content": "benign",
        "domain": "medical diagnosis",
        # no grounding, evaluation, calibration, or review declared
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    by_type = {f["type"]: f for f in record["findings"]}

    assert "hallucination_risk" in by_type
    finding = by_type["hallucination_risk"]
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert finding["detail"]["evidence_quality"] == "NONE"
    assert any(
        "high_stakes" in rf["factor"] for rf in finding["detail"]["risk_factors"]
    )

    # Mapping is attached and resolves to the new standards entry.
    standards = {entry["standard"] for entry in finding["mapping"]["controls"]}
    assert "OWASP Top 10 for LLMs" in standards
    assert "NIST AI RMF" in standards

    # Finding must be JSON-serializable (no enum/dataclass remnants).
    json.dumps(record["findings"])
    assert "hallucination_metric" in record["persistence"]["operations"]
    assert len(store.list_findings()) >= 1


def test_well_controlled_model_below_finding_floor(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "hr_low.db"))
    artifact = {
        "id": "model-controlled",
        "content": "benign",
        "domain": "general",
        "has_output_grounding": True,
        "has_retrieval_augmentation": True,
        "has_factuality_evaluation": True,
        "has_confidence_calibration": True,
        "has_human_review_for_high_stakes": True,
        "has_self_consistency_checking": True,
        "knowledge_cutoff_declared": True,
        # Strong evidence keeps Wilson bound high enough to avoid MEDIUM+ factors.
        "factuality_evidence": {"correct_claims": 190, "total_claims": 200},
        "retrieval_evidence": {
            "source_trust": 0.95,
            "citation_precision": 0.92,
            "citation_coverage": 0.90,
        },
    }

    record = RiskEngine(datastore=store).analyze(artifact)
    finding_types = {f["type"] for f in record["findings"]}

    # Score stays below MEDIUM floor; no hallucination finding emitted.
    assert "hallucination_risk" not in finding_types
    # Trend metric is always persisted regardless of tier.
    assert "hallucination_metric" in record["persistence"]["operations"]


def test_default_artifact_emits_medium_or_higher_finding(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "hr_default.db"))
    # An artifact with no hallucination-specific keys accumulates enough
    # baseline risk (missing grounding + evaluation + calibration) to reach MEDIUM.
    record = RiskEngine(datastore=store).analyze(
        {"id": "model-bare", "content": "benign"}
    )
    by_type = {f["type"]: f for f in record["findings"]}

    assert "hallucination_risk" in by_type
    assert by_type["hallucination_risk"]["severity"] in {"MEDIUM", "HIGH", "CRITICAL"}


def test_hallucination_risk_maps_to_controls():
    ensure_src()
    from aiaf.mapping.standards import map_finding_to_controls

    mapping = map_finding_to_controls({"type": "hallucination_risk"})
    standards = {entry["standard"] for entry in mapping["controls"]}
    assert "OWASP Top 10 for LLMs" in standards
    assert "NIST AI RMF" in standards
    assert "NIST Secure Software Development Framework" in standards

"""Integration tests for risk-drift wiring into reporting and monitoring.

The robust drift analyzer (unit-tested in test_risk_drift.py) replaces the naive
last-two-point / split-half trend deltas. These tests cover the architect glue:
per-(artifact_id, metric_name) partitioning, scale/direction context, the drift
sub-object in the report, the drift monitoring alert, and the standards mapping.
"""
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _save_series(store, metric_name, values, artifact_id):
    for value in values:
        store.save_metric(metric_name, float(value), {"artifact_id": artifact_id})


def test_worsening_risk_history_surfaces_drift_and_alert(tmp_path):
    ensure_src()
    from aiaf.core import ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "drift.db"))
    # A clearly worsening higher-is-worse series for one artifact.
    _save_series(store, "risk_score", [1.0] * 9 + [8.5] * 8, artifact_id="drift-art")

    report = ReportingEngine(datastore=store).assurance_report()
    drift = report["continuous_monitoring"]["drift"]

    assert drift["scoring_version"] == "2.0"
    assert drift["partition_count"] == 1
    assert drift["most_drifted_artifact"] == "drift-art"
    # A sustained rise on a higher-is-worse metric is deterioration -> WORSENING.
    assert report["continuous_monitoring"]["trend"] == "WORSENING"

    alert_ids = {alert["id"] for alert in report["monitoring_alerts"]["alerts"]}
    assert "risk_drift_detected" in alert_ids


def test_drift_is_partitioned_per_artifact(tmp_path):
    ensure_src()
    from aiaf.core import ReportingEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "drift_part.db"))
    # Two artifacts with independent histories must not share a trend series.
    _save_series(store, "risk_score", [1.0] * 9 + [8.5] * 8, artifact_id="art-worse")
    _save_series(store, "risk_score", [2.0] * 17, artifact_id="art-stable")

    report = ReportingEngine(datastore=store).assurance_report()
    drift = report["continuous_monitoring"]["drift"]

    assert drift["partition_count"] == 2
    # The headline reflects the most-drifted artifact, not a mixed series.
    assert drift["most_drifted_artifact"] == "art-worse"
    by_artifact = {item["artifact_id"]: item for item in drift["by_artifact"]}
    assert by_artifact["art-worse"]["risk_score"] >= by_artifact["art-stable"]["risk_score"]


def test_risk_drift_maps_to_controls():
    ensure_src()
    from aiaf.mapping.standards import map_finding_to_controls

    mapping = map_finding_to_controls({"type": "risk_drift"})
    standards = {entry["standard"] for entry in mapping["controls"]}
    assert "NIST AI RMF" in standards
    assert "CIS Controls" in standards

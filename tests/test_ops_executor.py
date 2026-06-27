"""Tests for aiaf.core.ops_executor."""

from aiaf.core.ops_executor import execute_due_schedules, execute_schedule
from aiaf.core.ops_scheduler import (
    JOB_ANOMALY_SCAN,
    JOB_RED_TEAM,
    JOB_TELEMETRY_INGEST,
    SCHEDULE_ONE_SHOT,
    create_schedule,
)


class _Store:
    def __init__(self):
        self._data = {}
        self.audit = []

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record

    def list_models(self):
        return list(self._data.values())

    def save_audit_log(self, event):
        self.audit.append(event)
        return len(self.audit)

    def save_metric(self, metric_name, metric_value, dimensions=None):
        return 1

    def save_assurance_report_snapshot(self, snapshot):
        self._data[f"snapshot:{snapshot['id']}"] = snapshot
        return snapshot["id"]


def test_execute_schedule_ingests_telemetry():
    store = _Store()
    create_schedule(
        "telem-1",
        JOB_TELEMETRY_INGEST,
        "model-1",
        SCHEDULE_ONE_SHOT,
        store,
        config={
            "events": [
                {"event_type": "LATENCY_MS", "value": 123.4},
                {"event_type": "ERROR_RATE", "value": 0.02},
            ]
        },
    )
    result = execute_schedule("telem-1", store)
    assert result["result"]["status"] == "COMPLETED"
    assert result["result"]["ingested_count"] == 2
    assert result["schedule"]["run_count"] == 1


def test_execute_schedule_redteam_without_endpoint_is_skipped():
    store = _Store()
    create_schedule("red-1", JOB_RED_TEAM, "model-1", SCHEDULE_ONE_SHOT, store)
    result = execute_schedule("red-1", store)
    assert result["result"]["status"] == "SKIPPED"
    assert result["schedule"]["last_outcome"] == "SKIPPED"


def test_execute_due_schedules_runs_anomaly_jobs(monkeypatch):
    store = _Store()
    create_schedule("anom-1", JOB_ANOMALY_SCAN, "model-1", SCHEDULE_ONE_SHOT, store)

    def fake_detect_anomalies(model_id, store_obj, window_minutes=60):
        return {"status": "ANOMALY_DETECTED", "findings": [{"type": "spike"}], "model_id": model_id}

    monkeypatch.setattr("aiaf.core.ops_executor.detect_anomalies", fake_detect_anomalies)
    result = execute_due_schedules(store)
    assert result["executed_count"] == 1
    assert result["error_count"] == 0
    assert result["results"][0]["result"]["status"] == "ANOMALY_DETECTED"

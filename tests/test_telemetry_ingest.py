"""Tests for aiaf.analysis.telemetry_ingest."""

import pytest
from datetime import datetime, timedelta, timezone

from aiaf.analysis.telemetry_ingest import (
    TELEMETRY_INGEST_VERSION,
    EVENT_LATENCY, EVENT_ERROR_RATE, EVENT_REFUSAL_RATE,
    EVENT_TOKEN_USAGE, EVENT_INJECTION_ATTEMPT, EVENT_POLICY_VIOLATION,
    EVENT_TYPES,
    TELEM_STATUS_NORMAL, TELEM_STATUS_ELEVATED,
    TELEM_STATUS_ANOMALY_DETECTED, TELEM_STATUS_CRITICAL,
    TelemetryIngestError,
    MAX_EVENTS_PER_STORE,
    _worst_status, _stddev, _percentile,
    ingest_event, get_window_summary, list_events, detect_anomalies,
    _DEFAULT_THRESHOLDS,
)


class _Store:
    def __init__(self):
        self._data = {}
    def get_model(self, key):
        return self._data.get(key)
    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record
    def list_models(self):
        return list(self._data.values())


def _ts(minutes_ago: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.isoformat().replace("+00:00", "Z")


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_version(self):
        assert TELEMETRY_INGEST_VERSION == "1.0"

    def test_event_types_complete(self):
        for t in (EVENT_LATENCY, EVENT_ERROR_RATE, EVENT_REFUSAL_RATE,
                  EVENT_TOKEN_USAGE, EVENT_INJECTION_ATTEMPT, EVENT_POLICY_VIOLATION):
            assert t in EVENT_TYPES

    def test_status_values_defined(self):
        assert TELEM_STATUS_NORMAL == "NORMAL"
        assert TELEM_STATUS_ELEVATED == "ELEVATED"
        assert TELEM_STATUS_ANOMALY_DETECTED == "ANOMALY_DETECTED"
        assert TELEM_STATUS_CRITICAL == "CRITICAL"

    def test_default_thresholds_cover_all_event_types(self):
        for et in EVENT_TYPES:
            assert et in _DEFAULT_THRESHOLDS


# ── Helpers ────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_worst_status_anomaly_beats_elevated(self):
        assert _worst_status(TELEM_STATUS_ANOMALY_DETECTED, TELEM_STATUS_ELEVATED) == TELEM_STATUS_ANOMALY_DETECTED

    def test_worst_status_normal_loses_to_elevated(self):
        assert _worst_status(TELEM_STATUS_NORMAL, TELEM_STATUS_ELEVATED) == TELEM_STATUS_ELEVATED

    def test_worst_status_commutative(self):
        a = _worst_status(TELEM_STATUS_CRITICAL, TELEM_STATUS_NORMAL)
        b = _worst_status(TELEM_STATUS_NORMAL, TELEM_STATUS_CRITICAL)
        assert a == b == TELEM_STATUS_CRITICAL

    def test_stddev_empty(self):
        assert _stddev([]) == 0.0

    def test_stddev_single(self):
        assert _stddev([5.0]) == 0.0

    def test_stddev_known(self):
        # stddev([2, 4, 4, 4, 5, 5, 7, 9]) ~ 2.0
        result = _stddev([2, 4, 4, 4, 5, 5, 7, 9])
        assert abs(result - 2.138) < 0.01

    def test_percentile_p95(self):
        vals = sorted(range(100))
        assert _percentile(vals, 0.95) == pytest.approx(94.05, abs=0.1)

    def test_percentile_empty(self):
        assert _percentile([], 0.95) == 0.0


# ── ingest_event ───────────────────────────────────────────────────────────────

class TestIngestEvent:
    def test_basic_ingest(self):
        store = _Store()
        result = ingest_event("model-1", EVENT_LATENCY, 1200.0, store)
        assert result["model_id"] == "model-1"
        assert result["event_type"] == EVENT_LATENCY
        assert result["ingested"]["value"] == 1200.0

    def test_empty_model_id_raises(self):
        with pytest.raises(TelemetryIngestError, match="model_id"):
            ingest_event("", EVENT_LATENCY, 1.0, _Store())

    def test_invalid_event_type_raises(self):
        with pytest.raises(TelemetryIngestError, match="event_type"):
            ingest_event("m", "HAPPINESS", 1.0, _Store())

    def test_case_insensitive_event_type(self):
        store = _Store()
        result = ingest_event("m", "latency", 100.0, store)
        assert result["event_type"] == EVENT_LATENCY

    def test_events_accumulate(self):
        store = _Store()
        for v in [100.0, 200.0, 300.0]:
            ingest_event("m", EVENT_LATENCY, v, store)
        events = list_events("m", EVENT_LATENCY, store)
        assert len(events) == 3

    def test_rolling_buffer_cap(self):
        store = _Store()
        for i in range(MAX_EVENTS_PER_STORE + 10):
            ingest_event("m", EVENT_LATENCY, float(i), store)
        events = list_events("m", EVENT_LATENCY, store, limit=MAX_EVENTS_PER_STORE + 10)
        assert len(events) == MAX_EVENTS_PER_STORE

    def test_custom_timestamp_stored(self):
        store = _Store()
        ts = "2025-01-01T00:00:00Z"
        result = ingest_event("m", EVENT_LATENCY, 1.0, store, timestamp=ts)
        assert result["ingested"]["timestamp"] == ts

    def test_metadata_stored(self):
        store = _Store()
        result = ingest_event("m", EVENT_LATENCY, 1.0, store, metadata={"region": "eu-west"})
        assert result["ingested"]["metadata"]["region"] == "eu-west"


# ── get_window_summary ─────────────────────────────────────────────────────────

class TestGetWindowSummary:
    def test_empty_window(self):
        store = _Store()
        result = get_window_summary("m", EVENT_LATENCY, store)
        assert result["count"] == 0
        assert result["mean"] is None

    def test_stats_computed(self):
        store = _Store()
        for v in [1000.0, 2000.0, 3000.0]:
            ingest_event("m", EVENT_LATENCY, v, store)
        result = get_window_summary("m", EVENT_LATENCY, store)
        assert result["count"] == 3
        assert result["mean"] == pytest.approx(2000.0)
        assert result["min"] == 1000.0
        assert result["max"] == 3000.0

    def test_old_events_excluded(self):
        store = _Store()
        old_ts = _ts(200)  # 200 minutes ago
        ingest_event("m", EVENT_LATENCY, 9999.0, store, timestamp=old_ts)
        ingest_event("m", EVENT_LATENCY, 1000.0, store)
        result = get_window_summary("m", EVENT_LATENCY, store, window_minutes=60)
        assert result["count"] == 1
        assert result["mean"] == pytest.approx(1000.0)

    def test_p95_computed(self):
        store = _Store()
        for v in range(1, 101):
            ingest_event("m", EVENT_LATENCY, float(v), store)
        result = get_window_summary("m", EVENT_LATENCY, store)
        assert result["p95"] is not None
        assert result["p95"] >= 94.0

    def test_sum_computed(self):
        store = _Store()
        for _ in range(5):
            ingest_event("m", EVENT_INJECTION_ATTEMPT, 1.0, store)
        result = get_window_summary("m", EVENT_INJECTION_ATTEMPT, store)
        assert result["sum"] == 5.0

    def test_version_returned(self):
        result = get_window_summary("m", EVENT_LATENCY, _Store())
        assert result["telemetry_ingest_version"] == TELEMETRY_INGEST_VERSION


# ── list_events ────────────────────────────────────────────────────────────────

class TestListEvents:
    def test_returns_recent_events(self):
        store = _Store()
        for v in [1.0, 2.0, 3.0]:
            ingest_event("m", EVENT_LATENCY, v, store)
        events = list_events("m", EVENT_LATENCY, store, limit=2)
        assert len(events) == 2
        assert events[-1]["value"] == 3.0

    def test_empty_returns_empty(self):
        assert list_events("m", EVENT_LATENCY, _Store()) == []


# ── detect_anomalies ───────────────────────────────────────────────────────────

class TestDetectAnomalies:
    def test_no_events_returns_normal(self):
        result = detect_anomalies("m", _Store())
        assert result["status"] == TELEM_STATUS_NORMAL
        assert result["finding_count"] == 0

    def test_high_latency_elevated(self):
        store = _Store()
        # Mean 2500ms → elevated (threshold 2000)
        for _ in range(5):
            ingest_event("m", EVENT_LATENCY, 2500.0, store)
        result = detect_anomalies("m", store)
        assert result["status"] in (TELEM_STATUS_ELEVATED, TELEM_STATUS_ANOMALY_DETECTED)

    def test_very_high_latency_anomaly(self):
        store = _Store()
        for _ in range(5):
            ingest_event("m", EVENT_LATENCY, 6000.0, store)
        result = detect_anomalies("m", store)
        assert result["status"] == TELEM_STATUS_ANOMALY_DETECTED

    def test_injection_attempt_count_triggers_anomaly(self):
        store = _Store()
        for _ in range(5):
            ingest_event("m", EVENT_INJECTION_ATTEMPT, 1.0, store)
        result = detect_anomalies("m", store)
        types = [f["type"] for f in result["findings"]]
        assert any("injection_attempt" in t for t in types)

    def test_single_injection_attempt_elevated(self):
        store = _Store()
        ingest_event("m", EVENT_INJECTION_ATTEMPT, 1.0, store)
        result = detect_anomalies("m", store)
        assert result["status"] in (TELEM_STATUS_ELEVATED, TELEM_STATUS_ANOMALY_DETECTED)

    def test_custom_thresholds(self):
        store = _Store()
        ingest_event("m", EVENT_LATENCY, 50.0, store)
        custom = {EVENT_LATENCY: {"elevated": 30.0, "anomaly": 100.0}}
        result = detect_anomalies("m", store, thresholds=custom)
        assert result["status"] == TELEM_STATUS_ELEVATED

    def test_required_fields_in_result(self):
        result = detect_anomalies("m", _Store())
        for field in ("model_id", "status", "finding_count", "findings",
                      "window_minutes", "evidence_origin", "analysed_at"):
            assert field in result

    def test_evidence_origin_locally_observed(self):
        result = detect_anomalies("m", _Store())
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_findings_have_evidence_origin(self):
        store = _Store()
        for _ in range(5):
            ingest_event("m", EVENT_INJECTION_ATTEMPT, 1.0, store)
        result = detect_anomalies("m", store)
        for f in result["findings"]:
            assert f["evidence_origin"] == "LOCALLY_OBSERVED"

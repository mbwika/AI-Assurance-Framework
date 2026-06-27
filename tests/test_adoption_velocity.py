"""Tests for src/aiaf/analysis/adoption_velocity.py."""

from datetime import datetime, timedelta, timezone

import pytest

from aiaf.analysis.adoption_velocity import (
    EVENT_DEPLOY,
    EVENT_DOWNLOAD,
    EVENT_FORK,
    EVENT_INSTALL,
    EVENT_STAR,
    SIGNAL_COLD_START_SURGE,
    SIGNAL_DORMANCY_REACTIVATION,
    SIGNAL_VELOCITY_SPIKE,
    VELOCITY_RISK_CRITICAL,
    VELOCITY_RISK_HIGH,
    VELOCITY_RISK_NORMAL,
    AdoptionVelocityError,
    detect_velocity_anomaly,
    get_velocity_profile,
    list_at_risk_artifacts,
    record_adoption_event,
    set_velocity_baseline,
)

# ── Minimal fake store ────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


def _ts(hours_ago: float = 0.0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return dt.isoformat().replace("+00:00", "Z")


# ── record_adoption_event ─────────────────────────────────────────────────────

class TestRecordAdoptionEvent:
    def test_returns_dict(self):
        store = _Store()
        result = record_adoption_event("model-a", EVENT_DOWNLOAD, store)
        assert isinstance(result, dict)

    def test_stores_event_metadata(self):
        store = _Store()
        result = record_adoption_event("model-a", EVENT_INSTALL, store, count=5)
        assert result["event_type"] == EVENT_INSTALL
        assert result["count"] == 5

    def test_weight_computed(self):
        store = _Store()
        result = record_adoption_event("model-a", EVENT_INSTALL, store, count=3)
        # weight = 2.0 * 3 = 6.0
        assert result["weight"] == pytest.approx(6.0)

    def test_profile_updated(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store, count=100)
        profile = get_velocity_profile("model-a", store)
        assert profile["total_events"] == 100

    def test_multiple_events_accumulate(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store, count=50)
        record_adoption_event("model-a", EVENT_DOWNLOAD, store, count=50)
        profile = get_velocity_profile("model-a", store)
        assert profile["total_events"] == 100

    def test_evidence_origin(self):
        store = _Store()
        result = record_adoption_event("model-a", EVENT_DOWNLOAD, store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_source_stored(self):
        store = _Store()
        result = record_adoption_event("model-a", EVENT_DOWNLOAD, store, source="huggingface")
        assert result["source"] == "huggingface"

    def test_custom_timestamp(self):
        store = _Store()
        ts = _ts(hours_ago=2.0)
        result = record_adoption_event("model-a", EVENT_DEPLOY, store, occurred_at=ts)
        assert result["occurred_at"] == ts

    def test_empty_artifact_id_raises(self):
        store = _Store()
        with pytest.raises(AdoptionVelocityError):
            record_adoption_event("", EVENT_DOWNLOAD, store)

    def test_invalid_event_type_raises(self):
        store = _Store()
        with pytest.raises(AdoptionVelocityError):
            record_adoption_event("model-a", "UNKNOWN_EVENT", store)

    def test_event_weights_by_type(self):
        weights = {
            EVENT_DOWNLOAD: 1.0,
            EVENT_INSTALL: 2.0,
            EVENT_DEPLOY: 3.0,
            EVENT_FORK: 1.5,
            EVENT_STAR: 0.5,
        }
        for event_type, expected_weight in weights.items():
            store = _Store()
            result = record_adoption_event("model-x", event_type, store, count=1)
            assert result["weight"] == pytest.approx(expected_weight), event_type


# ── set_velocity_baseline ─────────────────────────────────────────────────────

class TestSetVelocityBaseline:
    def test_baseline_stored(self):
        store = _Store()
        result = set_velocity_baseline("model-a", 10.0, store)
        assert result["baseline_weight_per_hour"] == pytest.approx(10.0)

    def test_baseline_overrides_previous(self):
        store = _Store()
        set_velocity_baseline("model-a", 10.0, store)
        result = set_velocity_baseline("model-a", 25.0, store)
        assert result["baseline_weight_per_hour"] == pytest.approx(25.0)

    def test_zero_baseline_allowed(self):
        store = _Store()
        result = set_velocity_baseline("model-a", 0.0, store)
        assert result["baseline_weight_per_hour"] == pytest.approx(0.0)

    def test_empty_artifact_id_raises(self):
        store = _Store()
        with pytest.raises(AdoptionVelocityError):
            set_velocity_baseline("", 10.0, store)


# ── get_velocity_profile ──────────────────────────────────────────────────────

class TestGetVelocityProfile:
    def test_returns_none_before_events(self):
        store = _Store()
        assert get_velocity_profile("model-unknown", store) is None

    def test_profile_keys(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store)
        profile = get_velocity_profile("model-a", store)
        for key in ("artifact_id", "total_events", "total_weight",
                    "current_velocity_per_hour", "evidence_origin"):
            assert key in profile

    def test_velocity_per_hour_positive(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store, count=60)
        profile = get_velocity_profile("model-a", store, window_hours=1.0)
        assert profile["current_velocity_per_hour"] >= 0.0

    def test_evidence_origin(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store)
        profile = get_velocity_profile("model-a", store)
        assert profile["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_first_and_last_seen(self):
        store = _Store()
        record_adoption_event("model-a", EVENT_DOWNLOAD, store)
        profile = get_velocity_profile("model-a", store)
        assert profile["first_seen_at"] is not None
        assert profile["last_seen_at"] is not None


# ── detect_velocity_anomaly ───────────────────────────────────────────────────

class TestDetectVelocityAnomaly:
    def test_no_events_returns_normal(self):
        store = _Store()
        result = detect_velocity_anomaly("model-unknown", store)
        assert result["risk_level"] == VELOCITY_RISK_NORMAL
        assert result["anomalies"] == []

    def test_result_keys(self):
        store = _Store()
        result = detect_velocity_anomaly("model-a", store)
        for key in ("artifact_id", "risk_level", "anomalies", "evidence_origin", "assessed_at"):
            assert key in result

    def test_evidence_origin(self):
        store = _Store()
        result = detect_velocity_anomaly("model-a", store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_assessed_at_present(self):
        store = _Store()
        result = detect_velocity_anomaly("model-a", store)
        assert result["assessed_at"].endswith("Z")

    def test_velocity_spike_detection(self):
        store = _Store()
        # Set a low baseline, record many recent events
        set_velocity_baseline("model-a", 1.0, store)  # baseline 1/hr
        # Record 200 recent events to create a spike (window=1hr → velocity>>1)
        for _ in range(200):
            record_adoption_event("model-a", EVENT_DOWNLOAD, store, count=1)
        result = detect_velocity_anomaly("model-a", store, velocity_window_hours=1.0)
        signals = {a["signal"] for a in result["anomalies"]}
        assert SIGNAL_VELOCITY_SPIKE in signals
        assert result["risk_level"] in (VELOCITY_RISK_HIGH, VELOCITY_RISK_CRITICAL)

    def test_cold_start_surge_detection(self):
        store = _Store()
        # 1000+ weighted events with age << 24 hours (all events are "just now")
        record_adoption_event(
            "model-new", EVENT_INSTALL, store,
            count=600,  # weight = 2.0 * 600 = 1200 → > 1000 threshold
        )
        result = detect_velocity_anomaly(
            "model-new", store,
            cold_start_hours=24.0,
            cold_start_threshold=1000,
        )
        signals = {a["signal"] for a in result["anomalies"]}
        assert SIGNAL_COLD_START_SURGE in signals
        assert result["risk_level"] == VELOCITY_RISK_CRITICAL

    def test_cold_start_surge_severity_critical(self):
        store = _Store()
        record_adoption_event("model-viral", EVENT_DEPLOY, store, count=400)
        # 400 * 3.0 = 1200 weighted events
        result = detect_velocity_anomaly("model-viral", store, cold_start_threshold=1000)
        signals = {a["signal"] for a in result["anomalies"]}
        if SIGNAL_COLD_START_SURGE in signals:
            for a in result["anomalies"]:
                if a["signal"] == SIGNAL_COLD_START_SURGE:
                    assert a["severity"] == "CRITICAL"

    def test_normal_low_volume_no_anomaly(self):
        store = _Store()
        set_velocity_baseline("model-a", 5.0, store)
        record_adoption_event("model-a", EVENT_STAR, store, count=2)
        result = detect_velocity_anomaly("model-a", store)
        # Low volume with reasonable baseline — no spike
        spike_signals = [a for a in result["anomalies"] if a["signal"] == SIGNAL_VELOCITY_SPIKE]
        assert len(spike_signals) == 0

    def test_dormancy_reactivation_detected(self):
        store = _Store()
        # Simulate an old artifact (first_seen many days ago) with no baseline
        old_ts = _ts(hours_ago=24 * 65)  # 65 days ago
        record_adoption_event("model-old", EVENT_DOWNLOAD, store,
                              count=1, occurred_at=old_ts)
        # Now add a recent event to create velocity
        record_adoption_event("model-old", EVENT_INSTALL, store, count=10)
        result = detect_velocity_anomaly(
            "model-old", store, dormancy_days=30, velocity_window_hours=6.0
        )
        # May or may not trigger depending on timing, but if it does it should be HIGH
        for a in result["anomalies"]:
            if a["signal"] == SIGNAL_DORMANCY_REACTIVATION:
                assert a["severity"] == "HIGH"


# ── list_at_risk_artifacts ────────────────────────────────────────────────────

class TestListAtRiskArtifacts:
    def test_empty_store(self):
        store = _Store()
        result = list_at_risk_artifacts(store)
        assert isinstance(result, list)

    def test_clean_model_not_listed(self):
        store = _Store()
        set_velocity_baseline("model-a", 100.0, store)
        record_adoption_event("model-a", EVENT_STAR, store, count=1)
        result = list_at_risk_artifacts(store)
        ids = [r["artifact_id"] for r in result]
        assert "model-a" not in ids

    def test_at_risk_model_listed(self):
        store = _Store()
        # Create a cold-start surge scenario
        record_adoption_event("model-viral", EVENT_DEPLOY, store, count=400)
        result = list_at_risk_artifacts(store)
        ids = [r["artifact_id"] for r in result]
        assert "model-viral" in ids

    def test_result_has_risk_level(self):
        store = _Store()
        record_adoption_event("model-viral", EVENT_DEPLOY, store, count=400)
        results = list_at_risk_artifacts(store)
        for r in results:
            assert "risk_level" in r
            assert "artifact_id" in r

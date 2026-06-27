"""Tests for aiaf.core.inference_telemetry."""


import pytest

from aiaf.core.inference_telemetry import (
    MAX_SESSION_EVENTS,
    TELEMETRY_VERSION,
    VALID_EVENT_TYPES,
    VALID_STATUSES,
    TelemetryValidationError,
    _coerce_non_negative_int,
    _coerce_positive_float,
    _compute_summary,
    _normalise_event,
    _session_key,
    _sha256,
    delete_session,
    get_session,
    get_session_events,
    ingest_events,
    list_sessions,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

class _FakeStore:
    """In-memory store stub that satisfies the get_model/save_model contract."""

    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


def _store():
    return _FakeStore()


def _event(**kwargs):
    base = {"event_type": "tool_call", "latency_ms": 10.0}
    base.update(kwargs)
    return base


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_session_key_prefix(self):
        assert _session_key("abc") == "session:abc"

    def test_sha256_returns_64_hex(self):
        h = _sha256("hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_deterministic(self):
        assert _sha256("x") == _sha256("x")

    def test_sha256_different_for_different_input(self):
        assert _sha256("a") != _sha256("b")

    def test_coerce_positive_float_valid(self):
        assert _coerce_positive_float(5.5) == 5.5

    def test_coerce_positive_float_zero(self):
        assert _coerce_positive_float(0) == 0.0

    def test_coerce_positive_float_negative(self):
        assert _coerce_positive_float(-1) is None

    def test_coerce_positive_float_str(self):
        assert _coerce_positive_float("3.14") == pytest.approx(3.14)

    def test_coerce_positive_float_none(self):
        assert _coerce_positive_float(None) is None

    def test_coerce_non_negative_int_valid(self):
        assert _coerce_non_negative_int(42) == 42

    def test_coerce_non_negative_int_zero(self):
        assert _coerce_non_negative_int(0) == 0

    def test_coerce_non_negative_int_negative(self):
        assert _coerce_non_negative_int(-1) is None

    def test_coerce_non_negative_int_str(self):
        assert _coerce_non_negative_int("7") == 7

    def test_coerce_non_negative_int_invalid(self):
        assert _coerce_non_negative_int("abc") is None


# ── _normalise_event ──────────────────────────────────────────────────────────

class TestNormaliseEvent:
    def _call(self, raw, session_id="s1", seq=0, ts="2026-01-01T00:00:00Z"):
        return _normalise_event(raw, session_id, seq, ts)

    def test_valid_tool_call(self):
        ev = self._call({"event_type": "tool_call", "latency_ms": 50})
        assert ev["event_type"] == "tool_call"
        assert ev["latency_ms"] == 50.0
        assert ev["status"] == "ok"
        assert ev["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_all_valid_event_types(self):
        for et in VALID_EVENT_TYPES:
            ev = self._call({"event_type": et})
            assert ev["event_type"] == et

    def test_invalid_event_type_raises(self):
        with pytest.raises(TelemetryValidationError, match="Unknown event_type"):
            self._call({"event_type": "fly_to_moon"})

    def test_unknown_status_defaults_to_ok(self):
        ev = self._call({"event_type": "tool_call", "status": "banana"})
        assert ev["status"] == "ok"

    def test_valid_statuses_preserved(self):
        for st in VALID_STATUSES:
            ev = self._call({"event_type": "tool_call", "status": st})
            assert ev["status"] == st

    def test_sequence_assigned(self):
        ev = self._call({"event_type": "custom"}, seq=7)
        assert ev["sequence"] == 7

    def test_timestamp_from_raw(self):
        ev = self._call({"event_type": "custom", "timestamp": "2026-06-01T10:00:00Z"})
        assert ev["timestamp"] == "2026-06-01T10:00:00Z"

    def test_timestamp_fallback_to_server(self):
        ev = self._call({"event_type": "custom"}, ts="2026-01-02T00:00:00Z")
        assert ev["timestamp"] == "2026-01-02T00:00:00Z"

    def test_event_id_from_raw(self):
        ev = self._call({"event_type": "custom", "event_id": "custom-id"})
        assert ev["event_id"] == "custom-id"

    def test_event_id_auto_generated(self):
        ev = self._call({"event_type": "custom"})
        assert ev["event_id"]  # not empty

    def test_tool_name_stripped(self):
        ev = self._call({"event_type": "tool_call", "tool_name": "  bash  "})
        assert ev["tool_name"] == "bash"

    def test_negative_latency_becomes_none(self):
        ev = self._call({"event_type": "tool_call", "latency_ms": -5})
        assert ev["latency_ms"] is None

    def test_negative_tokens_become_none(self):
        ev = self._call({"event_type": "llm_completion", "token_count": -1})
        assert ev["token_count"] is None

    def test_metadata_passthrough(self):
        ev = self._call({"event_type": "custom", "metadata": {"key": "val"}})
        assert ev["metadata"] == {"key": "val"}

    def test_non_dict_metadata_becomes_empty(self):
        ev = self._call({"event_type": "custom", "metadata": "bad"})
        assert ev["metadata"] == {}


# ── _compute_summary ──────────────────────────────────────────────────────────

class TestComputeSummary:
    def test_empty_events(self):
        s = _compute_summary("sid", [])
        assert s["event_count"] == 0
        assert s["session_id"] == "sid"

    def test_counts_by_type(self):
        events = [
            {"event_type": "tool_call", "status": "ok", "sequence": 0, "timestamp": "2026-01-01T00:00:00Z"},
            {"event_type": "tool_call", "status": "ok", "sequence": 1, "timestamp": "2026-01-01T00:00:01Z"},
            {"event_type": "llm_completion", "status": "ok", "sequence": 2, "timestamp": "2026-01-01T00:00:02Z"},
        ]
        s = _compute_summary("s", events)
        assert s["by_event_type"]["tool_call"] == 2
        assert s["by_event_type"]["llm_completion"] == 1
        assert s["event_count"] == 3

    def test_error_rate(self):
        events = [
            {"event_type": "tool_call", "status": "error", "sequence": 0, "timestamp": "2026-01-01T00:00:00Z"},
            {"event_type": "tool_call", "status": "ok", "sequence": 1, "timestamp": "2026-01-01T00:00:01Z"},
            {"event_type": "tool_call", "status": "ok", "sequence": 2, "timestamp": "2026-01-01T00:00:02Z"},
        ]
        s = _compute_summary("s", events)
        assert s["error_count"] == 1
        assert abs(s["error_rate"] - 1 / 3) < 0.01

    def test_session_status_blocked_when_blocked(self):
        events = [
            {"event_type": "guardrail_block", "status": "blocked", "sequence": 0, "timestamp": "2026-01-01T00:00:00Z"},
        ]
        s = _compute_summary("s", events)
        assert s["session_status"] == "BLOCKED"

    def test_session_status_degraded_high_error_rate(self):
        events = [
            {"event_type": "tool_call", "status": "error", "sequence": i, "timestamp": "2026-01-01T00:00:00Z"}
            for i in range(3)
        ] + [
            {"event_type": "tool_call", "status": "ok", "sequence": 3, "timestamp": "2026-01-01T00:00:01Z"}
        ]
        s = _compute_summary("s", events)
        assert s["session_status"] == "DEGRADED"

    def test_session_status_ok(self):
        events = [
            {"event_type": "tool_call", "status": "ok", "sequence": 0, "timestamp": "2026-01-01T00:00:00Z"},
        ]
        s = _compute_summary("s", events)
        assert s["session_status"] == "OK"

    def test_total_latency(self):
        events = [
            {"event_type": "tool_call", "status": "ok", "latency_ms": 100.0, "sequence": 0, "timestamp": "T"},
            {"event_type": "tool_call", "status": "ok", "latency_ms": 50.0, "sequence": 1, "timestamp": "T"},
        ]
        s = _compute_summary("s", events)
        assert s["total_latency_ms"] == pytest.approx(150.0)
        assert s["mean_latency_ms"] == pytest.approx(75.0)

    def test_tool_names_collected(self):
        events = [
            {"event_type": "tool_call", "status": "ok", "tool_name": "bash", "sequence": 0, "timestamp": "T"},
            {"event_type": "tool_call", "status": "ok", "tool_name": "read_file", "sequence": 1, "timestamp": "T"},
            {"event_type": "tool_call", "status": "ok", "tool_name": "bash", "sequence": 2, "timestamp": "T"},
        ]
        s = _compute_summary("s", events)
        assert sorted(s["tool_names_seen"]) == ["bash", "read_file"]

    def test_evidence_origin(self):
        events = [{"event_type": "custom", "status": "ok", "sequence": 0, "timestamp": "T"}]
        s = _compute_summary("s", events)
        assert s["evidence_origin"] == "LOCALLY_OBSERVED"


# ── ingest_events ─────────────────────────────────────────────────────────────

class TestIngestEvents:
    def test_empty_batch_returns_zero_accepted(self):
        result = ingest_events("s1", [], _store())
        assert result["accepted"] == 0
        assert result["rejected"] == 0

    def test_valid_events_accepted(self):
        store = _store()
        result = ingest_events("s1", [_event(), _event(event_type="llm_completion")], store)
        assert result["accepted"] == 2
        assert result["rejected"] == 0

    def test_invalid_event_type_rejected(self):
        store = _store()
        result = ingest_events("s1", [{"event_type": "bogus"}], store)
        assert result["accepted"] == 0
        assert result["rejected"] == 1
        assert result["errors"][0]["index"] == 0

    def test_session_key_stored(self):
        store = _store()
        ingest_events("my-session", [_event()], store)
        assert store.get_model("session:my-session") is not None

    def test_summary_in_result(self):
        store = _store()
        result = ingest_events("s1", [_event()], store)
        assert "summary" in result
        assert result["summary"]["event_count"] == 1

    def test_empty_session_id_raises(self):
        with pytest.raises(TelemetryValidationError):
            ingest_events("", [_event()], _store())

    def test_whitespace_session_id_raises(self):
        with pytest.raises(TelemetryValidationError):
            ingest_events("   ", [_event()], _store())

    def test_idempotent_duplicate_event_id(self):
        store = _store()
        ev = _event(event_id="eid-1")
        ingest_events("s1", [ev], store)
        result = ingest_events("s1", [ev], store)
        # Second ingest should skip the duplicate
        assert result["accepted"] == 0
        rec = store.get_model("session:s1")
        assert len(rec["metadata"]["events"]) == 1

    def test_accumulates_across_batches(self):
        store = _store()
        ingest_events("s1", [_event(event_id="a")], store)
        ingest_events("s1", [_event(event_id="b")], store)
        rec = store.get_model("session:s1")
        assert len(rec["metadata"]["events"]) == 2

    def test_rolling_window_capped(self):
        store = _store()
        events = [_event(event_id=str(i)) for i in range(MAX_SESSION_EVENTS + 50)]
        ingest_events("s1", events, store)
        rec = store.get_model("session:s1")
        assert len(rec["metadata"]["events"]) == MAX_SESSION_EVENTS

    def test_sequence_monotonically_increases(self):
        store = _store()
        ingest_events("s1", [_event(event_id="a"), _event(event_id="b")], store)
        rec = store.get_model("session:s1")
        seqs = [e["sequence"] for e in rec["metadata"]["events"]]
        assert seqs == sorted(seqs)
        assert seqs[1] > seqs[0]

    def test_telemetry_version_in_result(self):
        result = ingest_events("s1", [_event()], _store())
        assert result["telemetry_version"] == TELEMETRY_VERSION


# ── get_session ───────────────────────────────────────────────────────────────

class TestGetSession:
    def test_returns_none_for_missing_session(self):
        assert get_session("nonexistent", _store()) is None

    def test_returns_session_after_ingest(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        sess = get_session("s1", store)
        assert sess is not None
        assert sess["session_id"] == "s1"
        assert len(sess["events"]) == 1
        assert "summary" in sess

    def test_returns_timestamps(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        sess = get_session("s1", store)
        assert sess["registered_at"] is not None
        assert sess["last_ingested_at"] is not None


# ── get_session_events ────────────────────────────────────────────────────────

class TestGetSessionEvents:
    def test_empty_for_missing_session(self):
        events, total = get_session_events("x", _store())
        assert events == []
        assert total == 0

    def test_pagination_offset(self):
        store = _store()
        ingest_events("s1", [_event(event_id=str(i)) for i in range(10)], store)
        events, total = get_session_events("s1", store, offset=5, limit=3)
        assert total == 10
        assert len(events) == 3

    def test_pagination_limit(self):
        store = _store()
        ingest_events("s1", [_event(event_id=str(i)) for i in range(20)], store)
        events, total = get_session_events("s1", store, offset=0, limit=5)
        assert len(events) == 5
        assert total == 20


# ── list_sessions ─────────────────────────────────────────────────────────────

class TestListSessions:
    def test_empty_store(self):
        result = list_sessions(_store())
        assert result == []

    def test_lists_sessions_not_other_records(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        # Add a non-session record
        store.save_model({"model_id": "model:abc", "metadata": {}})
        sessions = list_sessions(store)
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "s1"

    def test_limit_respected(self):
        store = _store()
        for i in range(10):
            ingest_events(f"s{i}", [_event()], store)
        sessions = list_sessions(store, limit=3)
        assert len(sessions) == 3

    def test_session_summary_fields(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        sessions = list_sessions(store)
        s = sessions[0]
        assert s["session_id"] == "s1"
        assert "event_count" in s


# ── delete_session ────────────────────────────────────────────────────────────

class TestDeleteSession:
    def test_delete_nonexistent_returns_false(self):
        assert delete_session("nope", _store()) is False

    def test_delete_existing_returns_true(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        assert delete_session("s1", store) is True

    def test_delete_clears_events(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        delete_session("s1", store)
        rec = store.get_model("session:s1")
        assert rec["metadata"]["events"] == []

    def test_delete_sets_deleted_at(self):
        store = _store()
        ingest_events("s1", [_event()], store)
        delete_session("s1", store)
        rec = store.get_model("session:s1")
        assert rec["metadata"]["deleted_at"] is not None


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_telemetry_version_string(self):
        assert isinstance(TELEMETRY_VERSION, str)
        assert TELEMETRY_VERSION == "1.0"

    def test_valid_event_types_includes_key_types(self):
        for et in ("tool_call", "llm_completion", "user_message", "error"):
            assert et in VALID_EVENT_TYPES

    def test_valid_statuses_includes_key_statuses(self):
        for st in ("ok", "error", "blocked"):
            assert st in VALID_STATUSES

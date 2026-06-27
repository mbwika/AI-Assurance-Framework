"""Tests for aiaf.core.incident_manager."""

import pytest

from aiaf.core.incident_manager import (
    INCIDENT_VERSION,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    SEVERITY_VALUES,
    STATE_OPEN, STATE_INVESTIGATING, STATE_CONTAINED, STATE_RESOLVED, STATE_ACCEPTED,
    STATE_VALUES,
    _ALLOWED_TRANSITIONS, _TERMINAL_STATES,
    IncidentError,
    create_incident, get_incident, list_incidents,
    update_incident_state, add_incident_note, snapshot_incident,
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


def _make_incident(store, iid="inc-1", severity=SEVERITY_HIGH, model_id="model-x"):
    return create_incident(iid, "Test Incident", severity, "anomaly_detector", model_id, store)


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_version(self):
        assert INCIDENT_VERSION == "1.0"

    def test_severity_values(self):
        for s in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO):
            assert s in SEVERITY_VALUES

    def test_state_values(self):
        for s in (STATE_OPEN, STATE_INVESTIGATING, STATE_CONTAINED, STATE_RESOLVED, STATE_ACCEPTED):
            assert s in STATE_VALUES

    def test_terminal_states(self):
        assert STATE_RESOLVED in _TERMINAL_STATES
        assert STATE_ACCEPTED in _TERMINAL_STATES
        assert STATE_OPEN not in _TERMINAL_STATES

    def test_allowed_transitions_open(self):
        assert STATE_INVESTIGATING in _ALLOWED_TRANSITIONS[STATE_OPEN]
        assert STATE_RESOLVED in _ALLOWED_TRANSITIONS[STATE_OPEN]

    def test_resolved_has_no_transitions(self):
        assert len(_ALLOWED_TRANSITIONS[STATE_RESOLVED]) == 0


# ── create_incident ────────────────────────────────────────────────────────────

class TestCreateIncident:
    def test_basic_creation(self):
        store = _Store()
        result = create_incident("i1", "Injection Detected", SEVERITY_HIGH,
                                 "rag_scanner", "model-1", store)
        assert result["incident_id"] == "i1"
        assert result["title"] == "Injection Detected"
        assert result["severity"] == SEVERITY_HIGH
        assert result["state"] == STATE_OPEN

    def test_initial_state_history(self):
        store = _Store()
        result = _make_incident(store)
        assert len(result["state_history"]) == 1
        assert result["state_history"][0]["state"] == STATE_OPEN

    def test_empty_id_raises(self):
        with pytest.raises(IncidentError, match="non-empty"):
            create_incident("", "title", SEVERITY_HIGH, "src", "m", _Store())

    def test_empty_title_raises(self):
        with pytest.raises(IncidentError, match="title"):
            create_incident("i", "", SEVERITY_HIGH, "src", "m", _Store())

    def test_invalid_severity_raises(self):
        with pytest.raises(IncidentError, match="severity"):
            create_incident("i", "t", "ULTRA", "src", "m", _Store())

    def test_evidence_origin_default(self):
        store = _Store()
        result = _make_incident(store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_custom_evidence_origin(self):
        store = _Store()
        result = create_incident("i2", "T", SEVERITY_LOW, "s", "m", store,
                                 evidence_origin="ARTIFACT_DERIVED")
        assert result["evidence_origin"] == "ARTIFACT_DERIVED"

    def test_tags_stored(self):
        store = _Store()
        result = create_incident("i3", "T", SEVERITY_LOW, "s", "m", store,
                                 tags=["rag", "injection"])
        assert "rag" in result["tags"]

    def test_findings_stored(self):
        store = _Store()
        findings = [{"type": "rag_injection", "severity": "HIGH"}]
        result = create_incident("i4", "T", SEVERITY_HIGH, "s", "m", store, findings=findings)
        assert len(result["findings"]) == 1

    def test_re_create_preserves_created_at(self):
        store = _Store()
        r1 = _make_incident(store)
        r2 = _make_incident(store)
        assert r1["created_at"] == r2["created_at"]


# ── get_incident / list_incidents ──────────────────────────────────────────────

class TestGetIncident:
    def test_get_existing(self):
        store = _Store()
        _make_incident(store, "inc-1")
        result = get_incident("inc-1", store)
        assert result["incident_id"] == "inc-1"

    def test_get_nonexistent_returns_none(self):
        assert get_incident("nobody", _Store()) is None


class TestListIncidents:
    def test_list_all(self):
        store = _Store()
        _make_incident(store, "a", SEVERITY_HIGH)
        _make_incident(store, "b", SEVERITY_LOW)
        results = list_incidents(store)
        ids = {r["incident_id"] for r in results}
        assert "a" in ids and "b" in ids

    def test_filter_by_severity(self):
        store = _Store()
        _make_incident(store, "c", SEVERITY_CRITICAL)
        _make_incident(store, "d", SEVERITY_LOW)
        results = list_incidents(store, severity=SEVERITY_CRITICAL)
        assert all(r["severity"] == SEVERITY_CRITICAL for r in results)

    def test_filter_by_state(self):
        store = _Store()
        _make_incident(store, "e")
        _make_incident(store, "f")
        update_incident_state("f", STATE_INVESTIGATING, store)
        results = list_incidents(store, state=STATE_OPEN)
        assert all(r["state"] == STATE_OPEN for r in results)

    def test_filter_by_model_id(self):
        store = _Store()
        _make_incident(store, "g", model_id="model-A")
        _make_incident(store, "h", model_id="model-B")
        results = list_incidents(store, model_id="model-A")
        assert all(r["model_id"] == "model-A" for r in results)

    def test_limit(self):
        store = _Store()
        for i in range(5):
            _make_incident(store, f"lim-{i}")
        assert len(list_incidents(store, limit=2)) <= 2

    def test_empty_store(self):
        assert list_incidents(_Store()) == []


# ── update_incident_state ──────────────────────────────────────────────────────

class TestUpdateState:
    def test_valid_transition_open_to_investigating(self):
        store = _Store()
        _make_incident(store)
        result = update_incident_state("inc-1", STATE_INVESTIGATING, store)
        assert result["state"] == STATE_INVESTIGATING

    def test_state_history_appended(self):
        store = _Store()
        _make_incident(store)
        update_incident_state("inc-1", STATE_INVESTIGATING, store, note="Starting triage")
        result = get_incident("inc-1", store)
        assert len(result["state_history"]) == 2
        assert result["state_history"][-1]["note"] == "Starting triage"

    def test_resolved_sets_resolved_at(self):
        store = _Store()
        _make_incident(store)
        result = update_incident_state("inc-1", STATE_RESOLVED, store)
        assert result["resolved_at"] is not None

    def test_accepted_sets_resolved_at(self):
        store = _Store()
        _make_incident(store)
        result = update_incident_state("inc-1", STATE_ACCEPTED, store)
        assert result["resolved_at"] is not None

    def test_invalid_transition_raises(self):
        # CONTAINED → INVESTIGATING is not an allowed backward transition
        store = _Store()
        _make_incident(store)
        update_incident_state("inc-1", STATE_CONTAINED, store)
        with pytest.raises(IncidentError, match="not allowed"):
            update_incident_state("inc-1", STATE_INVESTIGATING, store)

    def test_transition_from_terminal_raises(self):
        store = _Store()
        _make_incident(store)
        update_incident_state("inc-1", STATE_RESOLVED, store)
        with pytest.raises(IncidentError):
            update_incident_state("inc-1", STATE_OPEN, store)

    def test_invalid_state_value_raises(self):
        store = _Store()
        _make_incident(store)
        with pytest.raises(IncidentError, match="Invalid state"):
            update_incident_state("inc-1", "LIMBO", store)

    def test_nonexistent_incident_raises(self):
        with pytest.raises(IncidentError, match="not found"):
            update_incident_state("nobody", STATE_INVESTIGATING, _Store())

    def test_full_path_to_resolved(self):
        store = _Store()
        _make_incident(store)
        update_incident_state("inc-1", STATE_INVESTIGATING, store)
        update_incident_state("inc-1", STATE_CONTAINED, store)
        result = update_incident_state("inc-1", STATE_RESOLVED, store)
        assert result["state"] == STATE_RESOLVED


# ── add_incident_note ──────────────────────────────────────────────────────────

class TestAddNote:
    def test_note_added(self):
        store = _Store()
        _make_incident(store)
        result = add_incident_note("inc-1", "Investigating vector DB", store, author="alice")
        assert len(result["notes"]) == 1
        assert result["notes"][0]["text"] == "Investigating vector DB"
        assert result["notes"][0]["author"] == "alice"

    def test_multiple_notes_appended(self):
        store = _Store()
        _make_incident(store)
        add_incident_note("inc-1", "Note 1", store)
        add_incident_note("inc-1", "Note 2", store)
        result = get_incident("inc-1", store)
        assert len(result["notes"]) == 2

    def test_empty_note_raises(self):
        store = _Store()
        _make_incident(store)
        with pytest.raises(IncidentError, match="non-empty"):
            add_incident_note("inc-1", "", store)

    def test_nonexistent_incident_raises(self):
        with pytest.raises(IncidentError, match="not found"):
            add_incident_note("nobody", "note", _Store())


# ── snapshot_incident ──────────────────────────────────────────────────────────

class TestSnapshotIncident:
    def test_snapshot_returns_copy_with_flag(self):
        store = _Store()
        _make_incident(store)
        result = snapshot_incident("inc-1", store)
        assert result["is_snapshot"] is True
        assert "snapshot_at" in result
        assert result["incident_id"] == "inc-1"

    def test_snapshot_does_not_mutate_original(self):
        store = _Store()
        _make_incident(store)
        snapshot_incident("inc-1", store)
        orig = get_incident("inc-1", store)
        assert "is_snapshot" not in orig

    def test_nonexistent_raises(self):
        with pytest.raises(IncidentError, match="not found"):
            snapshot_incident("nobody", _Store())

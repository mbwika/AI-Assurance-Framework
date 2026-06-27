"""Tests for aiaf.core.remediation_tracker."""

import pytest

from aiaf.core.remediation_tracker import (
    _TERMINAL_STATUSES,
    ACTION_TYPE_CONFIG_CHANGE,
    ACTION_TYPE_GUARDRAIL_ADD,
    ACTION_TYPE_MANUAL_REVIEW,
    ACTION_TYPE_MODEL_SWAP,
    ACTION_TYPE_PATCH,
    ACTION_TYPE_POLICY_UPDATE,
    ACTION_TYPES,
    REMEDIATION_ACCEPTED_RISK,
    REMEDIATION_IN_PROGRESS,
    REMEDIATION_PENDING,
    REMEDIATION_RESOLVED,
    REMEDIATION_STATUSES,
    REMEDIATION_VERSION,
    REMEDIATION_WONT_FIX,
    RemediationError,
    create_remediation,
    get_remediation,
    link_to_incident,
    list_remediations,
    update_remediation_status,
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


def _make(store, rid="rem-1", incident_id="inc-1", action_type=ACTION_TYPE_PATCH,
          model_id=None, assigned_to=None):
    return create_remediation(rid, incident_id, action_type, "Apply security patch", store,
                              model_id=model_id, assigned_to=assigned_to)


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_version(self):
        assert REMEDIATION_VERSION == "1.0"

    def test_action_types(self):
        for t in (ACTION_TYPE_PATCH, ACTION_TYPE_CONFIG_CHANGE, ACTION_TYPE_MODEL_SWAP,
                  ACTION_TYPE_GUARDRAIL_ADD, ACTION_TYPE_POLICY_UPDATE, ACTION_TYPE_MANUAL_REVIEW):
            assert t in ACTION_TYPES

    def test_statuses(self):
        for s in (REMEDIATION_PENDING, REMEDIATION_IN_PROGRESS, REMEDIATION_RESOLVED,
                  REMEDIATION_ACCEPTED_RISK, REMEDIATION_WONT_FIX):
            assert s in REMEDIATION_STATUSES

    def test_terminal_statuses(self):
        assert REMEDIATION_RESOLVED in _TERMINAL_STATUSES
        assert REMEDIATION_ACCEPTED_RISK in _TERMINAL_STATUSES
        assert REMEDIATION_WONT_FIX in _TERMINAL_STATUSES
        assert REMEDIATION_PENDING not in _TERMINAL_STATUSES


# ── create_remediation ─────────────────────────────────────────────────────────

class TestCreateRemediation:
    def test_basic_creation(self):
        store = _Store()
        result = _make(store)
        assert result["remediation_id"] == "rem-1"
        assert result["incident_id"] == "inc-1"
        assert result["action_type"] == ACTION_TYPE_PATCH
        assert result["status"] == REMEDIATION_PENDING

    def test_initial_status_history(self):
        store = _Store()
        result = _make(store)
        assert len(result["status_history"]) == 1
        assert result["status_history"][0]["status"] == REMEDIATION_PENDING

    def test_empty_id_raises(self):
        with pytest.raises(RemediationError, match="remediation_id"):
            create_remediation("", "inc-1", ACTION_TYPE_PATCH, "desc", _Store())

    def test_empty_incident_id_raises(self):
        with pytest.raises(RemediationError, match="incident_id"):
            create_remediation("r1", "", ACTION_TYPE_PATCH, "desc", _Store())

    def test_invalid_action_type_raises(self):
        with pytest.raises(RemediationError, match="action_type"):
            create_remediation("r1", "i1", "PRAYER", "desc", _Store())

    def test_empty_description_raises(self):
        with pytest.raises(RemediationError, match="description"):
            create_remediation("r1", "i1", ACTION_TYPE_PATCH, "", _Store())

    def test_optional_fields_stored(self):
        store = _Store()
        result = create_remediation("r2", "i1", ACTION_TYPE_GUARDRAIL_ADD, "Add guardrail",
                                    store, model_id="m1", assigned_to="alice",
                                    due_date="2026-07-01")
        assert result["model_id"] == "m1"
        assert result["assigned_to"] == "alice"
        assert result["due_date"] == "2026-07-01"

    def test_re_create_preserves_created_at(self):
        store = _Store()
        r1 = _make(store)
        r2 = _make(store)
        assert r1["created_at"] == r2["created_at"]

    def test_version_returned(self):
        result = _make(_Store())
        assert result["remediation_version"] == REMEDIATION_VERSION


# ── get_remediation ────────────────────────────────────────────────────────────

class TestGetRemediation:
    def test_get_existing(self):
        store = _Store()
        _make(store, "r1")
        result = get_remediation("r1", store)
        assert result["remediation_id"] == "r1"

    def test_get_nonexistent_returns_none(self):
        assert get_remediation("nobody", _Store()) is None


# ── update_remediation_status ──────────────────────────────────────────────────

class TestUpdateStatus:
    def test_pending_to_in_progress(self):
        store = _Store()
        _make(store)
        result = update_remediation_status("rem-1", REMEDIATION_IN_PROGRESS, store)
        assert result["status"] == REMEDIATION_IN_PROGRESS

    def test_to_resolved_sets_resolved_at(self):
        store = _Store()
        _make(store)
        result = update_remediation_status("rem-1", REMEDIATION_RESOLVED, store,
                                           resolution_note="Patch applied")
        assert result["resolved_at"] is not None
        assert result["resolution_note"] == "Patch applied"

    def test_accepted_risk_is_terminal(self):
        store = _Store()
        _make(store)
        update_remediation_status("rem-1", REMEDIATION_ACCEPTED_RISK, store)
        with pytest.raises(RemediationError, match="terminal"):
            update_remediation_status("rem-1", REMEDIATION_IN_PROGRESS, store)

    def test_wont_fix_is_terminal(self):
        store = _Store()
        _make(store)
        update_remediation_status("rem-1", REMEDIATION_WONT_FIX, store)
        with pytest.raises(RemediationError, match="terminal"):
            update_remediation_status("rem-1", REMEDIATION_RESOLVED, store)

    def test_status_history_appended(self):
        store = _Store()
        _make(store)
        update_remediation_status("rem-1", REMEDIATION_IN_PROGRESS, store)
        result = get_remediation("rem-1", store)
        assert len(result["status_history"]) == 2
        assert result["status_history"][-1]["status"] == REMEDIATION_IN_PROGRESS

    def test_invalid_status_raises(self):
        store = _Store()
        _make(store)
        with pytest.raises(RemediationError, match="Invalid status"):
            update_remediation_status("rem-1", "MAYBE", store)

    def test_nonexistent_raises(self):
        with pytest.raises(RemediationError, match="not found"):
            update_remediation_status("nobody", REMEDIATION_RESOLVED, _Store())

    def test_resolved_without_note(self):
        store = _Store()
        _make(store)
        result = update_remediation_status("rem-1", REMEDIATION_RESOLVED, store)
        assert result["status"] == REMEDIATION_RESOLVED


# ── list_remediations ──────────────────────────────────────────────────────────

class TestListRemediations:
    def test_list_all(self):
        store = _Store()
        _make(store, "r1", incident_id="i1")
        _make(store, "r2", incident_id="i2")
        results = list_remediations(store)
        ids = {r["remediation_id"] for r in results}
        assert "r1" in ids and "r2" in ids

    def test_filter_by_incident_id(self):
        store = _Store()
        _make(store, "r1", incident_id="i1")
        _make(store, "r2", incident_id="i2")
        results = list_remediations(store, incident_id="i1")
        assert all(r["incident_id"] == "i1" for r in results)

    def test_filter_by_model_id(self):
        store = _Store()
        create_remediation("r3", "i1", ACTION_TYPE_PATCH, "d", store, model_id="m1")
        create_remediation("r4", "i1", ACTION_TYPE_PATCH, "d", store, model_id="m2")
        results = list_remediations(store, model_id="m1")
        assert all(r["model_id"] == "m1" for r in results)

    def test_filter_by_status(self):
        store = _Store()
        _make(store, "r5")
        _make(store, "r6")
        update_remediation_status("r5", REMEDIATION_RESOLVED, store)
        results = list_remediations(store, status=REMEDIATION_PENDING)
        assert all(r["status"] == REMEDIATION_PENDING for r in results)

    def test_limit(self):
        store = _Store()
        for i in range(5):
            _make(store, f"lim-{i}")
        assert len(list_remediations(store, limit=3)) <= 3

    def test_empty_store(self):
        assert list_remediations(_Store()) == []


# ── link_to_incident ───────────────────────────────────────────────────────────

class TestLinkToIncident:
    def test_link_updates_incident_id(self):
        store = _Store()
        _make(store, incident_id="original")
        result = link_to_incident("rem-1", "new-incident", store)
        assert result["incident_id"] == "new-incident"

    def test_link_nonexistent_raises(self):
        with pytest.raises(RemediationError, match="not found"):
            link_to_incident("nobody", "inc-1", _Store())

    def test_link_empty_incident_id_raises(self):
        store = _Store()
        _make(store)
        with pytest.raises(RemediationError, match="incident_id"):
            link_to_incident("rem-1", "", store)

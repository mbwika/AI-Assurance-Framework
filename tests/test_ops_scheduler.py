"""Tests for aiaf.core.ops_scheduler."""

from datetime import datetime, timezone

import pytest

from aiaf.core.ops_scheduler import (
    JOB_ANOMALY_SCAN,
    JOB_RED_TEAM,
    JOB_SNAPSHOT,
    JOB_TELEMETRY_INGEST,
    JOB_TYPES,
    JOB_VULN_SCAN,
    OUTCOME_FAILURE,
    OUTCOME_SKIPPED,
    OUTCOME_SUCCESS,
    OUTCOME_TIMEOUT,
    OUTCOME_VALUES,
    SCHEDULE_DAILY,
    SCHEDULE_INTERVAL,
    SCHEDULE_ONE_SHOT,
    SCHEDULE_TYPES,
    SCHEDULE_WEEKLY,
    SCHEDULER_VERSION,
    STATUS_ACTIVE,
    STATUS_DELETED,
    STATUS_PAUSED,
    OpsSchedulerError,
    _compute_next_run,
    _next_daily,
    _next_weekly,
    create_schedule,
    delete_schedule,
    due_schedules,
    get_schedule,
    list_schedules,
    mark_job_run,
    pause_schedule,
    resume_schedule,
)

# ── Fake store ─────────────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._data = {}
    def get_model(self, key):
        return self._data.get(key)
    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record
    def list_models(self):
        return list(self._data.values())


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_scheduler_version(self):
        assert SCHEDULER_VERSION == "1.0"

    def test_schedule_types(self):
        for t in (SCHEDULE_INTERVAL, SCHEDULE_DAILY, SCHEDULE_WEEKLY, SCHEDULE_ONE_SHOT):
            assert t in SCHEDULE_TYPES

    def test_job_types(self):
        for j in (JOB_RED_TEAM, JOB_TELEMETRY_INGEST, JOB_ANOMALY_SCAN, JOB_SNAPSHOT, JOB_VULN_SCAN):
            assert j in JOB_TYPES

    def test_outcome_values(self):
        for o in (OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_SKIPPED, OUTCOME_TIMEOUT):
            assert o in OUTCOME_VALUES


# ── Helpers ────────────────────────────────────────────────────────────────────

class TestHelpers:
    def _after(self, h=12, m=0):
        return datetime(2026, 6, 23, h, m, 0, tzinfo=timezone.utc)

    def test_next_daily_future_same_day(self):
        after = self._after(h=8)
        result = _next_daily("10:00", after)
        assert "T10:00" in result
        assert "2026-06-23" in result

    def test_next_daily_past_time_rolls_to_tomorrow(self):
        after = self._after(h=15)
        result = _next_daily("10:00", after)
        assert "2026-06-24" in result

    def test_next_weekly_correct_day(self):
        # 2026-06-23 is a Tuesday. Ask for next Monday.
        after = self._after(h=8)
        result = _next_weekly("MON", "06:00", after)
        assert "2026-06-29" in result

    def test_next_weekly_same_day_past_time(self):
        # 2026-06-23 is Tuesday. Ask for Tuesday 06:00, after 08:00 → next Tuesday.
        after = self._after(h=8)
        result = _next_weekly("TUE", "06:00", after)
        assert "2026-06-30" in result

    def test_compute_next_run_interval(self):
        from datetime import timezone
        ref = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)
        result = _compute_next_run(SCHEDULE_INTERVAL, 3600, None, None, ref)
        assert result is not None
        assert "13:00" in result

    def test_compute_next_run_one_shot_returns_none(self):
        ref = datetime(2026, 6, 23, 12, 0, 0, tzinfo=timezone.utc)
        assert _compute_next_run(SCHEDULE_ONE_SHOT, None, None, None, ref) is None

    def test_compute_next_run_daily(self):
        ref = datetime(2026, 6, 23, 1, 0, 0, tzinfo=timezone.utc)
        result = _compute_next_run(SCHEDULE_DAILY, None, "02:00", None, ref)
        assert result is not None
        assert "02:00" in result


# ── create_schedule ────────────────────────────────────────────────────────────

class TestCreateSchedule:
    def test_basic_interval(self):
        store = _Store()
        result = create_schedule("s1", JOB_RED_TEAM, "model-1", SCHEDULE_INTERVAL, store,
                                 interval_seconds=3600)
        assert result["schedule_id"] == "s1"
        assert result["job_type"] == JOB_RED_TEAM
        assert result["schedule_type"] == SCHEDULE_INTERVAL
        assert result["interval_seconds"] == 3600
        assert result["status"] == STATUS_ACTIVE

    def test_basic_daily(self):
        store = _Store()
        result = create_schedule("s2", JOB_ANOMALY_SCAN, "model-1", SCHEDULE_DAILY, store,
                                 cron_time="02:00")
        assert result["cron_time"] == "02:00"
        assert result["next_run_at"] is not None

    def test_basic_weekly(self):
        store = _Store()
        result = create_schedule("s3", JOB_SNAPSHOT, "model-1", SCHEDULE_WEEKLY, store,
                                 cron_time="03:00", cron_day="MON")
        assert result["cron_day"] == "MON"

    def test_one_shot_next_run_is_now(self):
        store = _Store()
        result = create_schedule("s4", JOB_VULN_SCAN, "model-1", SCHEDULE_ONE_SHOT, store)
        assert result["next_run_at"] is not None

    def test_empty_id_raises(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError, match="non-empty"):
            create_schedule("", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)

    def test_invalid_job_type_raises(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError, match="job_type"):
            create_schedule("s5", "DANCE", "m", SCHEDULE_ONE_SHOT, store)

    def test_invalid_schedule_type_raises(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError):
            create_schedule("s6", JOB_RED_TEAM, "m", "QUARTERLY", store)

    def test_interval_requires_seconds(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError, match="interval_seconds"):
            create_schedule("s7", JOB_RED_TEAM, "m", SCHEDULE_INTERVAL, store)

    def test_daily_requires_cron_time(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError, match="cron_time"):
            create_schedule("s8", JOB_ANOMALY_SCAN, "m", SCHEDULE_DAILY, store)

    def test_weekly_requires_both(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError):
            create_schedule("s9", JOB_ANOMALY_SCAN, "m", SCHEDULE_WEEKLY, store,
                            cron_time="03:00")  # missing cron_day

    def test_invalid_cron_day_raises(self):
        store = _Store()
        with pytest.raises(OpsSchedulerError):
            create_schedule("s10", JOB_ANOMALY_SCAN, "m", SCHEDULE_WEEKLY, store,
                            cron_time="03:00", cron_day="SOMEDAY")

    def test_re_create_preserves_created_at(self):
        store = _Store()
        r1 = create_schedule("s11", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        r2 = create_schedule("s11", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        assert r1["created_at"] == r2["created_at"]

    def test_scheduler_version_returned(self):
        store = _Store()
        result = create_schedule("s12", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        assert result["scheduler_version"] == SCHEDULER_VERSION

    def test_config_stored(self):
        store = _Store()
        cfg = {"probe_families": ["xss"]}
        result = create_schedule("s13", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store, config=cfg)
        assert result["config"]["probe_families"] == ["xss"]


# ── get_schedule / list_schedules ──────────────────────────────────────────────

class TestGetSchedule:
    def test_get_existing(self):
        store = _Store()
        create_schedule("g1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        result = get_schedule("g1", store)
        assert result["schedule_id"] == "g1"

    def test_get_nonexistent_returns_none(self):
        store = _Store()
        assert get_schedule("nobody", store) is None


class TestListSchedules:
    def test_list_returns_all(self):
        store = _Store()
        create_schedule("l1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        create_schedule("l2", JOB_ANOMALY_SCAN, "m", SCHEDULE_ONE_SHOT, store)
        results = list_schedules(store)
        ids = {r["schedule_id"] for r in results}
        assert "l1" in ids and "l2" in ids

    def test_filter_by_job_type(self):
        store = _Store()
        create_schedule("f1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        create_schedule("f2", JOB_ANOMALY_SCAN, "m", SCHEDULE_ONE_SHOT, store)
        results = list_schedules(store, job_type=JOB_RED_TEAM)
        assert all(r["job_type"] == JOB_RED_TEAM for r in results)

    def test_filter_by_status(self):
        store = _Store()
        create_schedule("p1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        pause_schedule("p1", store)
        create_schedule("p2", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        active = list_schedules(store, status=STATUS_ACTIVE)
        assert all(r["status"] == STATUS_ACTIVE for r in active)

    def test_list_empty(self):
        assert list_schedules(_Store()) == []

    def test_limit_respected(self):
        store = _Store()
        for i in range(5):
            create_schedule(f"lim{i}", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        assert len(list_schedules(store, limit=3)) <= 3


# ── pause / resume / delete ────────────────────────────────────────────────────

class TestPauseResumeDelete:
    def test_pause_changes_status(self):
        store = _Store()
        create_schedule("p1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        result = pause_schedule("p1", store)
        assert result["status"] == STATUS_PAUSED

    def test_resume_restores_active(self):
        store = _Store()
        create_schedule("p2", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        pause_schedule("p2", store)
        result = resume_schedule("p2", store)
        assert result["status"] == STATUS_ACTIVE

    def test_delete_sets_deleted_status(self):
        store = _Store()
        create_schedule("d1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        assert delete_schedule("d1", store) is True
        assert get_schedule("d1", store)["status"] == STATUS_DELETED

    def test_pause_nonexistent_returns_none(self):
        assert pause_schedule("nobody", _Store()) is None

    def test_delete_nonexistent_returns_false(self):
        assert delete_schedule("nobody", _Store()) is False


# ── mark_job_run ───────────────────────────────────────────────────────────────

class TestMarkJobRun:
    def test_increments_run_count(self):
        store = _Store()
        create_schedule("r1", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        result = mark_job_run("r1", store)
        assert result["run_count"] == 1

    def test_sets_last_outcome(self):
        store = _Store()
        create_schedule("r2", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        result = mark_job_run("r2", store, outcome=OUTCOME_FAILURE)
        assert result["last_outcome"] == OUTCOME_FAILURE

    def test_one_shot_next_run_none_after_run(self):
        store = _Store()
        create_schedule("r3", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        result = mark_job_run("r3", store)
        assert result["next_run_at"] is None

    def test_interval_next_run_advances(self):
        store = _Store()
        create_schedule("r4", JOB_RED_TEAM, "m", SCHEDULE_INTERVAL, store, interval_seconds=3600)
        before = get_schedule("r4", store)["next_run_at"]
        result = mark_job_run("r4", store)
        assert result["next_run_at"] != before
        assert result["next_run_at"] is not None

    def test_run_history_appended(self):
        store = _Store()
        create_schedule("r5", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        mark_job_run("r5", store, outcome=OUTCOME_SUCCESS, details={"probes": 5})
        result = get_schedule("r5", store)
        assert len(result["run_history"]) == 1
        assert result["run_history"][0]["outcome"] == OUTCOME_SUCCESS

    def test_invalid_outcome_raises(self):
        store = _Store()
        create_schedule("r6", JOB_RED_TEAM, "m", SCHEDULE_ONE_SHOT, store)
        with pytest.raises(OpsSchedulerError, match="outcome"):
            mark_job_run("r6", store, outcome="MAYBE")

    def test_nonexistent_returns_none(self):
        assert mark_job_run("nobody", _Store()) is None


# ── due_schedules ──────────────────────────────────────────────────────────────

class TestDueSchedules:
    def _make_past_due(self, store, schedule_id, job_type=JOB_RED_TEAM):
        create_schedule(schedule_id, job_type, "m", SCHEDULE_INTERVAL, store,
                        interval_seconds=3600)
        key = f"ops_schedule:{schedule_id}"
        record = store.get_model(key)
        record["metadata"]["next_run_at"] = "2020-01-01T00:00:00Z"
        store.save_model(record)

    def test_due_schedule_returned(self):
        store = _Store()
        self._make_past_due(store, "d1")
        result = due_schedules(store)
        assert any(s["schedule_id"] == "d1" for s in result)

    def test_future_schedule_not_returned(self):
        store = _Store()
        create_schedule("d2", JOB_RED_TEAM, "m", SCHEDULE_INTERVAL, store,
                        interval_seconds=7200)
        result = due_schedules(store)
        assert not any(s["schedule_id"] == "d2" for s in result)

    def test_paused_schedule_excluded(self):
        store = _Store()
        self._make_past_due(store, "d3")
        pause_schedule("d3", store)
        result = due_schedules(store)
        assert not any(s["schedule_id"] == "d3" for s in result)

    def test_filter_by_job_type(self):
        store = _Store()
        self._make_past_due(store, "d4", JOB_RED_TEAM)
        self._make_past_due(store, "d5", JOB_ANOMALY_SCAN)
        result = due_schedules(store, job_type=JOB_RED_TEAM)
        assert all(s["job_type"] == JOB_RED_TEAM for s in result)

    def test_empty_store_returns_empty(self):
        assert due_schedules(_Store()) == []

"""Continuous Security Operations Scheduler.

Manages schedule definitions for recurring security jobs
(red-team runs, telemetry ingests, anomaly scans, vulnerability scans,
and snapshots).  This module owns *scheduling metadata only*; actual
job execution is performed by the caller (e.g. a background thread or
external cron that polls :func:`due_schedules`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

SCHEDULER_VERSION = "1.0"

_SCHEDULE_PREFIX = "ops_schedule:"
_MAX_HISTORY = 20

# ── Schedule types ─────────────────────────────────────────────────────────────
SCHEDULE_INTERVAL = "INTERVAL"
SCHEDULE_DAILY = "DAILY"
SCHEDULE_WEEKLY = "WEEKLY"
SCHEDULE_ONE_SHOT = "ONE_SHOT"

SCHEDULE_TYPES: frozenset = frozenset(
    {SCHEDULE_INTERVAL, SCHEDULE_DAILY, SCHEDULE_WEEKLY, SCHEDULE_ONE_SHOT}
)

_WEEKDAY_MAP = {
    "MON": 0, "TUE": 1, "WED": 2,
    "THU": 3, "FRI": 4, "SAT": 5, "SUN": 6,
}

# ── Job types ──────────────────────────────────────────────────────────────────
JOB_RED_TEAM = "RED_TEAM"
JOB_TELEMETRY_INGEST = "TELEMETRY_INGEST"
JOB_ANOMALY_SCAN = "ANOMALY_SCAN"
JOB_SNAPSHOT = "SNAPSHOT"
JOB_VULN_SCAN = "VULN_SCAN"

JOB_TYPES: frozenset = frozenset(
    {JOB_RED_TEAM, JOB_TELEMETRY_INGEST, JOB_ANOMALY_SCAN, JOB_SNAPSHOT, JOB_VULN_SCAN}
)

# ── Schedule status ────────────────────────────────────────────────────────────
STATUS_ACTIVE = "ACTIVE"
STATUS_PAUSED = "PAUSED"
STATUS_DELETED = "DELETED"

# ── Run outcomes ───────────────────────────────────────────────────────────────
OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILURE = "FAILURE"
OUTCOME_SKIPPED = "SKIPPED"
OUTCOME_TIMEOUT = "TIMEOUT"

OUTCOME_VALUES: frozenset = frozenset(
    {OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_SKIPPED, OUTCOME_TIMEOUT}
)


class OpsSchedulerError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _schedule_key(schedule_id: str) -> str:
    return f"{_SCHEDULE_PREFIX}{schedule_id}"


def _next_daily(cron_time: str, after: datetime) -> str:
    """Next UTC occurrence of HH:MM after `after`."""
    try:
        h, m = (int(x) for x in str(cron_time).split(":"))
    except (ValueError, AttributeError):
        h, m = 2, 0
    candidate = after.replace(hour=h, minute=m, second=0, microsecond=0)
    if candidate <= after:
        candidate += timedelta(days=1)
    return _to_iso(candidate)


def _next_weekly(cron_day: str, cron_time: str, after: datetime) -> str:
    """Next UTC occurrence of (day-of-week, HH:MM) after `after`."""
    target_wd = _WEEKDAY_MAP.get(str(cron_day).upper(), 0)
    try:
        h, m = (int(x) for x in str(cron_time).split(":"))
    except (ValueError, AttributeError):
        h, m = 2, 0
    candidate = after.replace(hour=h, minute=m, second=0, microsecond=0)
    days_ahead = (target_wd - candidate.weekday()) % 7
    candidate += timedelta(days=days_ahead)
    if candidate <= after:
        candidate += timedelta(weeks=1)
    return _to_iso(candidate)


def _compute_next_run(
    schedule_type: str,
    interval_seconds: int | None,
    cron_time: str | None,
    cron_day: str | None,
    from_dt: datetime,
) -> str | None:
    if schedule_type == SCHEDULE_ONE_SHOT:
        return None
    if schedule_type == SCHEDULE_INTERVAL:
        secs = max(1, int(interval_seconds or 3600))
        return _to_iso(from_dt + timedelta(seconds=secs))
    if schedule_type == SCHEDULE_DAILY:
        return _next_daily(cron_time or "02:00", from_dt)
    if schedule_type == SCHEDULE_WEEKLY:
        return _next_weekly(cron_day or "MON", cron_time or "02:00", from_dt)
    return None


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    m = record.get("metadata") or {}
    return {
        "schedule_id": m.get("schedule_id"),
        "job_type": m.get("job_type"),
        "target_id": m.get("target_id"),
        "schedule_type": m.get("schedule_type"),
        "interval_seconds": m.get("interval_seconds"),
        "cron_time": m.get("cron_time"),
        "cron_day": m.get("cron_day"),
        "config": m.get("config") or {},
        "status": m.get("status"),
        "created_at": m.get("created_at"),
        "updated_at": m.get("updated_at"),
        "next_run_at": m.get("next_run_at"),
        "last_run_at": m.get("last_run_at"),
        "run_count": m.get("run_count", 0),
        "last_outcome": m.get("last_outcome"),
        "run_history": m.get("run_history") or [],
        "scheduler_version": m.get("scheduler_version", SCHEDULER_VERSION),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def create_schedule(
    schedule_id: str,
    job_type: str,
    target_id: str,
    schedule_type: str,
    store: Any,
    *,
    interval_seconds: int | None = None,
    cron_time: str | None = None,
    cron_day: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    schedule_id = str(schedule_id).strip()
    if not schedule_id:
        raise OpsSchedulerError("schedule_id must be non-empty")
    job_type = str(job_type).upper().strip()
    if job_type not in JOB_TYPES:
        raise OpsSchedulerError(f"Unknown job_type: {job_type!r}. Valid: {sorted(JOB_TYPES)}")
    schedule_type = str(schedule_type).upper().strip()
    if schedule_type not in SCHEDULE_TYPES:
        raise OpsSchedulerError(f"Unknown schedule_type: {schedule_type!r}")
    if schedule_type == SCHEDULE_INTERVAL and not interval_seconds:
        raise OpsSchedulerError("INTERVAL schedule requires interval_seconds > 0")
    if schedule_type == SCHEDULE_DAILY and not cron_time:
        raise OpsSchedulerError("DAILY schedule requires cron_time (HH:MM)")
    if schedule_type == SCHEDULE_WEEKLY and (not cron_time or not cron_day):
        raise OpsSchedulerError("WEEKLY schedule requires cron_time and cron_day")
    if cron_day and str(cron_day).upper() not in _WEEKDAY_MAP:
        raise OpsSchedulerError(f"cron_day must be one of {list(_WEEKDAY_MAP)}")

    key = _schedule_key(schedule_id)
    now = _utc_now()

    existing = store.get_model(key)
    created_at = (existing or {}).get("metadata", {}).get("created_at") or _to_iso(now)
    run_count = (existing or {}).get("metadata", {}).get("run_count", 0)
    run_history = (existing or {}).get("metadata", {}).get("run_history") or []

    if schedule_type == SCHEDULE_ONE_SHOT:
        next_run_at: str | None = _to_iso(now)
    else:
        next_run_at = _compute_next_run(
            schedule_type, interval_seconds, cron_time, cron_day, now
        )

    record: dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            "schedule_id": schedule_id,
            "job_type": job_type,
            "target_id": str(target_id).strip(),
            "schedule_type": schedule_type,
            "interval_seconds": interval_seconds,
            "cron_time": cron_time,
            "cron_day": str(cron_day).upper() if cron_day else None,
            "config": dict(config) if config else {},
            "status": STATUS_ACTIVE,
            "created_at": created_at,
            "updated_at": _to_iso(now),
            "next_run_at": next_run_at,
            "last_run_at": None,
            "run_count": run_count,
            "last_outcome": None,
            "run_history": run_history,
            "scheduler_version": SCHEDULER_VERSION,
        },
    }
    store.save_model(record)
    return _summary(record)


def get_schedule(schedule_id: str, store: Any) -> dict[str, Any] | None:
    record = store.get_model(_schedule_key(schedule_id))
    return _summary(record) if record else None


def list_schedules(
    store: Any,
    *,
    job_type: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_SCHEDULE_PREFIX):
            continue
        s = _summary(m)
        if job_type and s.get("job_type") != str(job_type).upper():
            continue
        if status and s.get("status") != str(status).upper():
            continue
        result.append(s)
    result.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return result[:limit]


def pause_schedule(schedule_id: str, store: Any) -> dict[str, Any] | None:
    key = _schedule_key(schedule_id)
    record = store.get_model(key)
    if not record:
        return None
    record["metadata"]["status"] = STATUS_PAUSED
    record["metadata"]["updated_at"] = _to_iso(_utc_now())
    store.save_model(record)
    return _summary(record)


def resume_schedule(schedule_id: str, store: Any) -> dict[str, Any] | None:
    key = _schedule_key(schedule_id)
    record = store.get_model(key)
    if not record:
        return None
    record["metadata"]["status"] = STATUS_ACTIVE
    record["metadata"]["updated_at"] = _to_iso(_utc_now())
    store.save_model(record)
    return _summary(record)


def delete_schedule(schedule_id: str, store: Any) -> bool:
    key = _schedule_key(schedule_id)
    record = store.get_model(key)
    if not record:
        return False
    record["metadata"]["status"] = STATUS_DELETED
    record["metadata"]["updated_at"] = _to_iso(_utc_now())
    store.save_model(record)
    return True


def mark_job_run(
    schedule_id: str,
    store: Any,
    *,
    outcome: str = OUTCOME_SUCCESS,
    details: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Record a job execution and advance next_run_at."""
    outcome = str(outcome).upper()
    if outcome not in OUTCOME_VALUES:
        raise OpsSchedulerError(f"Invalid outcome: {outcome!r}. Valid: {sorted(OUTCOME_VALUES)}")

    key = _schedule_key(schedule_id)
    record = store.get_model(key)
    if not record:
        return None

    now = _utc_now()
    meta = record["metadata"]

    run_entry = {"run_at": _to_iso(now), "outcome": outcome, "details": details or {}}
    history = list(meta.get("run_history") or [])
    history.append(run_entry)
    if len(history) > _MAX_HISTORY:
        history = history[-_MAX_HISTORY:]

    meta["last_run_at"] = _to_iso(now)
    meta["last_outcome"] = outcome
    meta["run_count"] = int(meta.get("run_count") or 0) + 1
    meta["run_history"] = history
    meta["updated_at"] = _to_iso(now)
    meta["next_run_at"] = _compute_next_run(
        meta["schedule_type"],
        meta.get("interval_seconds"),
        meta.get("cron_time"),
        meta.get("cron_day"),
        now,
    )

    store.save_model(record)
    return _summary(record)


def due_schedules(
    store: Any,
    *,
    as_of: datetime | None = None,
    job_type: str | None = None,
) -> list[dict[str, Any]]:
    """Return active schedules whose next_run_at is at or before as_of."""
    threshold = as_of or _utc_now()
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_SCHEDULE_PREFIX):
            continue
        s = _summary(m)
        if s.get("status") != STATUS_ACTIVE:
            continue
        if job_type and s.get("job_type") != str(job_type).upper():
            continue
        next_run = s.get("next_run_at")
        if not next_run:
            continue
        try:
            if _from_iso(next_run) <= threshold:
                result.append(s)
        except (ValueError, TypeError):
            pass
    result.sort(key=lambda s: s.get("next_run_at") or "")
    return result

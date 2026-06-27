"""Scheduled continuous-assurance orchestration."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .governance_engine import GovernanceEngine
from .risk_engine import RiskEngine


class MonitoringEngine:
    """Manage recurring assurance targets and execute due assessments."""

    def __init__(self, datastore: object):
        self.datastore = datastore

    def create_schedule(
        self,
        artifact: dict[str, Any],
        interval_seconds: int = 3600,
        enabled: bool = True,
        start_at: str | None = None,
    ) -> dict[str, Any]:
        artifact_id = artifact.get("id")
        if not artifact_id:
            raise ValueError("Scheduled artifacts require a non-empty id")
        if interval_seconds < 1:
            raise ValueError("interval_seconds must be at least 1")

        now = _utc_now()
        schedule = {
            "id": str(uuid.uuid4()),
            "artifact_id": str(artifact_id),
            "artifact": artifact,
            "interval_seconds": int(interval_seconds),
            "enabled": bool(enabled),
            "next_run_at": _iso(_parse_datetime(start_at) if start_at else now),
            "last_run_at": None,
            "created_at": _iso(now),
            "updated_at": _iso(now),
        }
        self.datastore.save_monitoring_schedule(schedule)
        return schedule

    def update_schedule(
        self,
        schedule_id: str,
        *,
        enabled: bool | None = None,
        interval_seconds: int | None = None,
        artifact: dict[str, Any] | None = None,
        next_run_at: str | None = None,
    ) -> dict[str, Any] | None:
        schedule = self.datastore.get_monitoring_schedule(schedule_id)
        if not schedule:
            return None
        if interval_seconds is not None:
            if interval_seconds < 1:
                raise ValueError("interval_seconds must be at least 1")
            schedule["interval_seconds"] = int(interval_seconds)
        if enabled is not None:
            schedule["enabled"] = bool(enabled)
        if artifact is not None:
            if not artifact.get("id"):
                raise ValueError("Scheduled artifacts require a non-empty id")
            schedule["artifact"] = artifact
            schedule["artifact_id"] = str(artifact["id"])
        if next_run_at is not None:
            schedule["next_run_at"] = _iso(_parse_datetime(next_run_at))
        schedule["updated_at"] = _iso(_utc_now())
        self.datastore.save_monitoring_schedule(schedule)
        return schedule

    def list_schedules(
        self, limit: int = 100, enabled: bool | None = None
    ):
        return self.datastore.list_monitoring_schedules(limit=limit, enabled=enabled)

    def list_runs(self, limit: int = 100, schedule_id: str | None = None):
        return self.datastore.list_monitoring_runs(
            limit=limit, schedule_id=schedule_id
        )

    def run_due(
        self, as_of: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        evaluated_at = _parse_datetime(as_of) if as_of else _utc_now()
        due = self.datastore.list_due_monitoring_schedules(
            as_of=_iso(evaluated_at), limit=limit
        )
        runs = [self._execute(schedule, evaluated_at) for schedule in due]
        return {
            "evaluated_at": _iso(evaluated_at),
            "due_schedules": len(due),
            "completed": sum(1 for run in runs if run["status"] == "COMPLETED"),
            "failed": sum(1 for run in runs if run["status"] == "FAILED"),
            "runs": runs,
        }

    def run_schedule(
        self, schedule_id: str, as_of: str | None = None
    ) -> dict[str, Any] | None:
        schedule = self.datastore.get_monitoring_schedule(schedule_id)
        if not schedule:
            return None
        started_at = _parse_datetime(as_of) if as_of else _utc_now()
        return self._execute(schedule, started_at)

    def _execute(
        self, schedule: dict[str, Any], started_at: datetime
    ) -> dict[str, Any]:
        started = _iso(started_at)
        schedule["last_run_at"] = started
        schedule["next_run_at"] = _iso(
            started_at + timedelta(seconds=schedule["interval_seconds"])
        )
        schedule["updated_at"] = started
        self.datastore.save_monitoring_schedule(schedule)

        run = {
            "id": str(uuid.uuid4()),
            "schedule_id": schedule["id"],
            "artifact_id": schedule["artifact_id"],
            "status": "RUNNING",
            "started_at": started,
            "completed_at": None,
            "result": {},
            "error": None,
        }
        self.datastore.save_monitoring_run(run)

        try:
            risk = RiskEngine(datastore=self.datastore).analyze(schedule["artifact"])
            governance = GovernanceEngine(datastore=self.datastore).evaluate(
                schedule["artifact"]
            )
            run["result"] = {
                "risk": risk,
                "governance": governance,
                "next_run_at": schedule["next_run_at"],
            }
            run["status"] = "COMPLETED"
        except Exception as exc:
            run["status"] = "FAILED"
            run["error"] = f"{type(exc).__name__}: {exc}"
        run["completed_at"] = _iso(_utc_now())
        self.datastore.save_monitoring_run(run)
        return run


def _parse_datetime(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

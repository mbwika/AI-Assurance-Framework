"""SQLite development datastore for assurance records and metrics."""
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class DataStore:
    """Simple SQLite-backed datastore for findings.

    This implementation provides a lightweight persistence layer suitable for
    development and testing. Production deployments can select Postgres through
    the datastore factory.
    """

    def __init__(self, db_path: str | None = None, pg_dsn: str | None = None, vector_url: str | None = None):
        # db_path defaults to data/aiaf.db in repo root
        if db_path is None:
            base = Path.cwd()
            data_dir = base / "data"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "aiaf.db")

        self.db_path = db_path
        self.pg_dsn = pg_dsn
        self.vector_url = vector_url
        # ensure parent directory exists when a custom db_path is provided
        try:
            parent = Path(self.db_path).parent
            parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # timeout=30: threads wait up to 30 s for the lock rather than failing
        # immediately — essential when uvicorn's threadpool runs concurrent requests.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn_lock = threading.RLock()
        self._tx_depth = 0
        self._ensure_schema()

    def _commit(self) -> None:
        """Commit unless inside an explicit ``transaction()`` block."""
        if self._tx_depth == 0:
            self._conn.commit()

    @contextmanager
    def transaction(self):
        """Group multiple writes into one atomic unit.

        Participating writes (those using ``_commit``) defer their commit so the
        whole block commits once on success or rolls back on any exception. This
        is what makes a signed-feed snapshot claim and its advisory writes
        all-or-nothing, so a failed import never leaves a claimed sequence over
        an incomplete catalog.
        """
        self._tx_depth += 1
        try:
            yield
        except Exception:
            self._tx_depth -= 1
            if self._tx_depth == 0:
                self._conn.rollback()
            raise
        else:
            self._tx_depth -= 1
            if self._tx_depth == 0:
                self._conn.commit()

    def _ensure_schema(self) -> None:
        cur = self._conn.cursor()
        # WAL mode allows concurrent readers alongside a writer; busy_timeout
        # makes the SQLite engine retry internally before surfacing a lock error.
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT,
                timestamp TEXT,
                findings_json TEXT,
                score REAL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS models (
                model_id TEXT PRIMARY KEY,
                model_name TEXT,
                version TEXT,
                source TEXT,
                source_url TEXT,
                publisher TEXT,
                sha256 TEXT,
                uploaded_at TEXT,
                registered_by TEXT,
                license TEXT,
                training_data TEXT,
                provenance_score INTEGER,
                risk_level TEXT,
                metadata_json TEXT,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                artifact_id TEXT,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS historical_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                dimensions_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_schedules (
                id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                artifact_json TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_runs (
                id TEXT PRIMARY KEY,
                schedule_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                result_json TEXT NOT NULL,
                error TEXT,
                FOREIGN KEY (schedule_id) REFERENCES monitoring_schedules(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_register (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                artifact_id TEXT,
                finding_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                owner TEXT,
                due_at TEXT,
                resolution TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerability_advisories (
                record_key TEXT PRIMARY KEY,
                advisory_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                aliases_json TEXT NOT NULL,
                affected_versions_json TEXT NOT NULL,
                affected_ranges_json TEXT NOT NULL,
                references_json TEXT NOT NULL,
                published_at TEXT,
                modified_at TEXT,
                withdrawn_at TEXT,
                source TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS advisory_feed_snapshots (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                schema_version TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source TEXT NOT NULL,
                feed_json TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                status TEXT NOT NULL,
                documents_imported INTEGER NOT NULL,
                package_records_imported INTEGER NOT NULL,
                imported_at TEXT NOT NULL,
                UNIQUE(feed_id, sequence)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS control_evidence (
                id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                evidence_fields_json TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                reference TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                expires_at TEXT,
                status TEXT NOT NULL,
                reviewer TEXT,
                review_rationale TEXT,
                reviewed_at TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS assurance_report_snapshots (
                id TEXT PRIMARY KEY,
                artifact_id TEXT,
                scope_type TEXT NOT NULL,
                snapshot_version TEXT NOT NULL DEFAULT '1.0',
                report_version TEXT NOT NULL,
                report_json TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                signature TEXT,
                signature_algorithm TEXT,
                key_id TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                artifact_json TEXT NOT NULL,
                policy_profile TEXT,
                effective_policy_json TEXT NOT NULL,
                status TEXT NOT NULL,
                external_calls_used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_invocation_decisions (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                workflow_step_id TEXT,
                tool TEXT NOT NULL,
                action TEXT,
                permissions_json TEXT NOT NULL,
                input_source TEXT,
                input_validation TEXT,
                target TEXT,
                approval_id TEXT,
                approved_by TEXT,
                decision TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                external_call INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(session_id, request_id),
                FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS monitoring_schedules_due_idx ON monitoring_schedules (enabled, next_run_at)"
        )
        metric_columns = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(historical_metrics)").fetchall()
        }
        if "artifact_id" not in metric_columns:
            cur.execute("ALTER TABLE historical_metrics ADD COLUMN artifact_id TEXT")
        try:
            cur.execute(
                """
                UPDATE historical_metrics
                SET artifact_id = json_extract(dimensions_json, '$.artifact_id')
                WHERE artifact_id IS NULL
                  AND json_valid(dimensions_json)
                """
            )
        except sqlite3.OperationalError:
            cur.execute(
                "SELECT id, dimensions_json FROM historical_metrics WHERE artifact_id IS NULL"
            )
            for row in cur.fetchall():
                dimensions = json.loads(row["dimensions_json"] or "{}")
                if dimensions.get("artifact_id"):
                    cur.execute(
                        "UPDATE historical_metrics SET artifact_id = ? WHERE id = ?",
                        (dimensions["artifact_id"], row["id"]),
                    )
        snapshot_columns = {
            row["name"]
            for row in cur.execute(
                "PRAGMA table_info(assurance_report_snapshots)"
            ).fetchall()
        }
        if "snapshot_version" not in snapshot_columns:
            cur.execute(
                "ALTER TABLE assurance_report_snapshots ADD COLUMN snapshot_version TEXT NOT NULL DEFAULT '1.0'"
            )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS historical_metrics_artifact_idx ON historical_metrics (artifact_id, metric_name, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS findings_artifact_idx ON findings (artifact_id, timestamp DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS audit_logs_artifact_idx ON audit_logs (artifact_id, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS monitoring_runs_schedule_idx ON monitoring_runs (schedule_id, started_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS risk_register_status_idx ON risk_register (status, severity, due_at)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS risk_register_artifact_idx ON risk_register (artifact_id, last_seen_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS vulnerability_advisories_package_idx ON vulnerability_advisories (ecosystem, package_name)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS advisory_feed_snapshots_feed_idx ON advisory_feed_snapshots (feed_id, sequence DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS advisory_feed_snapshots_expiry_idx ON advisory_feed_snapshots (expires_at, status)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS control_evidence_artifact_idx ON control_evidence (artifact_id, control_id, status)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS control_evidence_expiry_idx ON control_evidence (status, expires_at)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS assurance_report_snapshots_artifact_idx ON assurance_report_snapshots (artifact_id, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS agent_sessions_artifact_idx ON agent_sessions (artifact_id, status, created_at DESC)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS tool_invocations_session_idx ON tool_invocation_decisions (session_id, created_at DESC)"
        )
        self._conn.commit()

    def save_finding(self, finding: dict[str, Any]) -> int:
        with self._conn_lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO findings (artifact_id, timestamp, findings_json, score) VALUES (?, ?, ?, ?)",
                (
                    finding.get("artifact_id"),
                    finding.get("timestamp"),
                    json.dumps(finding.get("findings", [])),
                    float(finding.get("score", 0.0)),
                ),
            )
            self._conn.commit()
            row_id = cur.lastrowid
            assert row_id is not None, "SQLite insert did not produce a row id"
            return row_id

    def list_findings(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self._conn_lock:
            cur = self._conn.cursor()
            if artifact_id:
                cur.execute(
                    "SELECT id, artifact_id, timestamp, findings_json, score FROM findings WHERE artifact_id = ? ORDER BY id DESC LIMIT ?",
                    (artifact_id, limit),
                )
            else:
                cur.execute(
                    "SELECT id, artifact_id, timestamp, findings_json, score FROM findings ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            out = []
            for r in rows:
                out.append(
                    {
                        "id": r["id"],
                        "artifact_id": r["artifact_id"],
                        "timestamp": r["timestamp"],
                        "findings": json.loads(r["findings_json"] or "[]"),
                        "score": r["score"],
                    }
                )
            return out

    def save_model(self, model_record: dict[str, Any]) -> str:
        with self._conn_lock:
            cur = self._conn.cursor()
            model_id = str(model_record.get("model_id") or uuid.uuid4())
            now = _utc_now()
            metadata = dict(model_record.get("metadata", {}) or {})
            for key in (
                "dependencies",
                "training_artifacts",
                "deployment_pipeline",
                "dependency_discovery",
                "provenance_attestations",
                "vulnerability_scan",
            ):
                if key in model_record:
                    metadata[key] = model_record.get(key)
            cur.execute(
                """
                INSERT OR REPLACE INTO models (
                    model_id, model_name, version, source, source_url, publisher,
                    sha256, uploaded_at, registered_by, license, training_data,
                    provenance_score, risk_level, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    model_id,
                    model_record.get("model_name"),
                    model_record.get("version"),
                    model_record.get("source"),
                    model_record.get("source_url"),
                    model_record.get("publisher"),
                    model_record.get("sha256"),
                    model_record.get("uploaded_at"),
                    model_record.get("registered_by"),
                    model_record.get("license"),
                    model_record.get("training_data"),
                    model_record.get("provenance_score"),
                    model_record.get("risk_level"),
                    json.dumps(metadata),
                    now,
                ),
            )
            self._conn.commit()
            return model_id

    def get_model(self, model_id: str) -> dict[str, Any] | None:
        with self._conn_lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT model_id, model_name, version, source, source_url, publisher,
                       sha256, uploaded_at, registered_by, license, training_data,
                       provenance_score, risk_level, metadata_json, created_at
                FROM models WHERE model_id = ?
                """,
                (model_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            metadata = json.loads(row["metadata_json"] or "{}")
            return {
                "model_id": row["model_id"],
                "model_name": row["model_name"],
                "version": row["version"],
                "source": row["source"],
                "source_url": row["source_url"],
                "publisher": row["publisher"],
                "sha256": row["sha256"],
                "uploaded_at": row["uploaded_at"],
                "registered_by": row["registered_by"],
                "license": row["license"],
                "training_data": row["training_data"],
                "provenance_score": row["provenance_score"],
                "risk_level": row["risk_level"],
                "dependencies": metadata.get("dependencies", []),
                "training_artifacts": metadata.get("training_artifacts", []),
                "deployment_pipeline": metadata.get("deployment_pipeline", {}),
                "dependency_discovery": metadata.get("dependency_discovery", {}),
                "provenance_attestations": metadata.get("provenance_attestations", []),
                "vulnerability_scan": metadata.get("vulnerability_scan", {}),
                "metadata": metadata,
                "created_at": row["created_at"],
            }

    def list_models(
        self, limit: int = 100, registered_by: str | None = None
    ) -> list[dict[str, Any]]:
        with self._conn_lock:
            cur = self._conn.cursor()
            if registered_by:
                cur.execute(
                    """
                    SELECT model_id, model_name, version, source, source_url, publisher,
                           sha256, registered_by, provenance_score, risk_level, metadata_json, created_at
                    FROM models WHERE registered_by = ? ORDER BY created_at DESC LIMIT ?
                    """,
                    (registered_by, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT model_id, model_name, version, source, source_url, publisher,
                           sha256, registered_by, provenance_score, risk_level, metadata_json, created_at
                    FROM models ORDER BY created_at DESC LIMIT ?
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
            return [
                {
                    "model_id": row["model_id"],
                    "model_name": row["model_name"],
                    "version": row["version"],
                    "source": row["source"],
                    "source_url": row["source_url"],
                    "publisher": row["publisher"],
                    "sha256": row["sha256"],
                    "registered_by": row["registered_by"],
                    "provenance_score": row["provenance_score"],
                    "risk_level": row["risk_level"],
                    "dependencies": json.loads(row["metadata_json"] or "{}").get("dependencies", []),
                    "training_artifacts": json.loads(row["metadata_json"] or "{}").get("training_artifacts", []),
                    "deployment_pipeline": json.loads(row["metadata_json"] or "{}").get("deployment_pipeline", {}),
                    "dependency_discovery": json.loads(row["metadata_json"] or "{}").get("dependency_discovery", {}),
                    "provenance_attestations": json.loads(row["metadata_json"] or "{}").get("provenance_attestations", []),
                    "vulnerability_scan": json.loads(row["metadata_json"] or "{}").get("vulnerability_scan", {}),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def create_job(self) -> str:
        job_id = str(uuid.uuid4())
        now = _utc_now()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO jobs (id, status, result_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, "PENDING", json.dumps({}), now, now),
        )
        self._conn.commit()
        return job_id

    def update_job(self, job_id: str, status: str, result: dict[str, Any]) -> None:
        now = _utc_now()
        cur = self._conn.cursor()
        cur.execute(
            "UPDATE jobs SET status = ?, result_json = ?, updated_at = ? WHERE id = ?",
            (status, json.dumps(result), now, job_id),
        )
        self._conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute("SELECT id, status, result_json, created_at, updated_at FROM jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "status": row["status"],
            "result": json.loads(row["result_json"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_jobs(self, limit: int = 20) -> list:
        with self._conn_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT id, status, result_json, created_at, updated_at FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [
                {
                    "id": row["id"],
                    "status": row["status"],
                    "result": json.loads(row["result_json"] or "{}"),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in cur.fetchall()
            ]

    def save_audit_log(self, event: dict[str, Any]) -> int:
        with self._conn_lock:
            now = _utc_now()
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO audit_logs (event_type, artifact_id, details_json, created_at) VALUES (?, ?, ?, ?)",
                (
                    event.get("event_type"),
                    event.get("artifact_id"),
                    json.dumps(event.get("details", {})),
                    now,
                ),
            )
            self._conn.commit()
            row_id = cur.lastrowid
            assert row_id is not None, "SQLite insert did not produce a row id"
            return row_id

    def list_audit_logs(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self._conn_lock:
            cur = self._conn.cursor()
            if artifact_id:
                cur.execute(
                    "SELECT id, event_type, artifact_id, details_json, created_at FROM audit_logs WHERE artifact_id = ? ORDER BY id DESC LIMIT ?",
                    (artifact_id, limit),
                )
            else:
                cur.execute(
                    "SELECT id, event_type, artifact_id, details_json, created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            return [
                {
                    "id": row["id"],
                    "event_type": row["event_type"],
                    "artifact_id": row["artifact_id"],
                    "details": json.loads(row["details_json"] or "{}"),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def save_metric(self, metric_name: str, metric_value: float, dimensions: dict[str, Any] | None = None) -> int:
        with self._conn_lock:
            now = _utc_now()
            dimensions = dimensions or {}
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO historical_metrics (artifact_id, metric_name, metric_value, dimensions_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    dimensions.get("artifact_id"),
                    metric_name,
                    float(metric_value),
                    json.dumps(dimensions),
                    now,
                ),
            )
            self._conn.commit()
            row_id = cur.lastrowid
            assert row_id is not None, "SQLite insert did not produce a row id"
            return row_id

    def list_metrics(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self._conn_lock:
            cur = self._conn.cursor()
            if artifact_id:
                cur.execute(
                    "SELECT id, artifact_id, metric_name, metric_value, dimensions_json, created_at FROM historical_metrics WHERE artifact_id = ? ORDER BY id DESC LIMIT ?",
                    (artifact_id, limit),
                )
            else:
                cur.execute(
                    "SELECT id, artifact_id, metric_name, metric_value, dimensions_json, created_at FROM historical_metrics ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            return [
                {
                    "id": row["id"],
                    "artifact_id": row["artifact_id"],
                    "metric_name": row["metric_name"],
                    "metric_value": row["metric_value"],
                    "dimensions": json.loads(row["dimensions_json"] or "{}"),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def save_monitoring_schedule(self, schedule: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO monitoring_schedules (
                id, artifact_id, artifact_json, interval_seconds, enabled,
                next_run_at, last_run_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                artifact_id = excluded.artifact_id,
                artifact_json = excluded.artifact_json,
                interval_seconds = excluded.interval_seconds,
                enabled = excluded.enabled,
                next_run_at = excluded.next_run_at,
                last_run_at = excluded.last_run_at,
                updated_at = excluded.updated_at
            """,
            (
                schedule["id"],
                schedule["artifact_id"],
                json.dumps(schedule["artifact"]),
                int(schedule["interval_seconds"]),
                int(bool(schedule.get("enabled", True))),
                schedule["next_run_at"],
                schedule.get("last_run_at"),
                schedule["created_at"],
                schedule["updated_at"],
            ),
        )
        self._conn.commit()
        return schedule["id"]

    def get_monitoring_schedule(self, schedule_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact_json, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules WHERE id = ?
            """,
            (schedule_id,),
        )
        row = cur.fetchone()
        return _monitoring_schedule_from_row(row) if row else None

    def list_monitoring_schedules(
        self,
        limit: int = 100,
        enabled: bool | None = None,
        artifact_id: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if enabled is not None:
            conditions.append("enabled = ?")
            params.append(int(enabled))
        if artifact_id:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact_json, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules
            """ + where + " ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )
        return [_monitoring_schedule_from_row(row) for row in cur.fetchall()]

    def list_due_monitoring_schedules(
        self, as_of: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact_json, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules
            WHERE enabled = 1 AND next_run_at <= ?
            ORDER BY next_run_at ASC LIMIT ?
            """,
            (as_of, limit),
        )
        return [_monitoring_schedule_from_row(row) for row in cur.fetchall()]

    def save_monitoring_run(self, run: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO monitoring_runs (
                id, schedule_id, artifact_id, status, started_at,
                completed_at, result_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                completed_at = excluded.completed_at,
                result_json = excluded.result_json,
                error = excluded.error
            """,
            (
                run["id"],
                run["schedule_id"],
                run["artifact_id"],
                run["status"],
                run["started_at"],
                run.get("completed_at"),
                json.dumps(run.get("result", {})),
                run.get("error"),
            ),
        )
        self._conn.commit()
        return run["id"]

    def list_monitoring_runs(
        self,
        limit: int = 100,
        schedule_id: str | None = None,
        artifact_id: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if schedule_id:
            conditions.append("schedule_id = ?")
            params.append(schedule_id)
        if artifact_id:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, schedule_id, artifact_id, status, started_at,
                   completed_at, result_json, error
            FROM monitoring_runs
            """ + where + " ORDER BY started_at DESC LIMIT ?",
            tuple(params),
        )
        return [_monitoring_run_from_row(row) for row in cur.fetchall()]

    def upsert_risk_observation(self, risk: dict[str, Any]) -> dict[str, Any]:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT id, status, due_at, resolution FROM risk_register WHERE fingerprint = ?",
            (risk["fingerprint"],),
        )
        existing = cur.fetchone()
        if existing:
            reopened = existing["status"] == "RESOLVED"
            cur.execute(
                """
                UPDATE risk_register SET
                    severity = ?, status = ?, details_json = ?, last_seen_at = ?, due_at = ?,
                    occurrence_count = occurrence_count + 1,
                    resolution = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    risk["severity"],
                    "OPEN" if reopened else existing["status"],
                    json.dumps(risk.get("details", {})),
                    risk["last_seen_at"],
                    risk.get("due_at") if reopened else existing["due_at"],
                    None if reopened else existing["resolution"],
                    risk["updated_at"],
                    existing["id"],
                ),
            )
            risk_id = existing["id"]
        else:
            cur.execute(
                """
                INSERT INTO risk_register (
                    id, fingerprint, artifact_id, finding_type, indicator,
                    title, severity, status, details_json, first_seen_at,
                    last_seen_at, occurrence_count, owner, due_at, resolution,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    risk["id"],
                    risk["fingerprint"],
                    risk.get("artifact_id"),
                    risk["finding_type"],
                    risk["indicator"],
                    risk["title"],
                    risk["severity"],
                    risk.get("status", "OPEN"),
                    json.dumps(risk.get("details", {})),
                    risk["first_seen_at"],
                    risk["last_seen_at"],
                    int(risk.get("occurrence_count", 1)),
                    risk.get("owner"),
                    risk.get("due_at"),
                    risk.get("resolution"),
                    risk["updated_at"],
                ),
            )
            risk_id = risk["id"]
        self._conn.commit()
        stored_risk = self.get_risk(risk_id)
        assert stored_risk is not None, "Risk upsert did not persist a retrievable record"
        return stored_risk

    def get_risk(self, risk_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, fingerprint, artifact_id, finding_type, indicator,
                   title, severity, status, details_json, first_seen_at,
                   last_seen_at, occurrence_count, owner, due_at, resolution,
                   updated_at
            FROM risk_register WHERE id = ?
            """,
            (risk_id,),
        )
        row = cur.fetchone()
        return _risk_from_row(row) if row else None

    def list_risks(
        self,
        limit: int = 100,
        status: str | None = None,
        artifact_id: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if artifact_id:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, fingerprint, artifact_id, finding_type, indicator,
                   title, severity, status, details_json, first_seen_at,
                   last_seen_at, occurrence_count, owner, due_at, resolution,
                   updated_at
            FROM risk_register
            """ + where + " ORDER BY last_seen_at DESC LIMIT ?",
            tuple(params),
        )
        return [_risk_from_row(row) for row in cur.fetchall()]

    def update_risk(self, risk_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        columns = {
            "status": "status",
            "owner": "owner",
            "due_at": "due_at",
            "resolution": "resolution",
            "updated_at": "updated_at",
        }
        selected = [(columns[key], value) for key, value in changes.items() if key in columns]
        if not selected:
            return self.get_risk(risk_id)
        assignments = ", ".join(f"{column} = ?" for column, _ in selected)
        params = [value for _, value in selected] + [risk_id]
        cur = self._conn.cursor()
        cur.execute(f"UPDATE risk_register SET {assignments} WHERE id = ?", tuple(params))
        self._conn.commit()
        return self.get_risk(risk_id)

    def save_advisory(self, advisory: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO vulnerability_advisories (
                record_key, advisory_id, ecosystem, package_name, summary,
                severity, aliases_json, affected_versions_json,
                affected_ranges_json, references_json, published_at,
                modified_at, withdrawn_at, source, metadata_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_key) DO UPDATE SET
                summary = excluded.summary,
                severity = excluded.severity,
                aliases_json = excluded.aliases_json,
                affected_versions_json = excluded.affected_versions_json,
                affected_ranges_json = excluded.affected_ranges_json,
                references_json = excluded.references_json,
                published_at = excluded.published_at,
                modified_at = excluded.modified_at,
                withdrawn_at = excluded.withdrawn_at,
                source = excluded.source,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                advisory["record_key"],
                advisory["advisory_id"],
                advisory["ecosystem"],
                advisory["package_name"],
                advisory.get("summary", ""),
                advisory.get("severity", "UNKNOWN"),
                json.dumps(advisory.get("aliases", [])),
                json.dumps(advisory.get("affected_versions", [])),
                json.dumps(advisory.get("affected_ranges", [])),
                json.dumps(advisory.get("references", [])),
                advisory.get("published_at"),
                advisory.get("modified_at"),
                advisory.get("withdrawn_at"),
                advisory.get("source", "imported"),
                json.dumps(advisory.get("metadata", {})),
                advisory["updated_at"],
            ),
        )
        self._commit()
        return advisory["record_key"]

    def list_advisories(
        self,
        limit: int = 1000,
        ecosystem: str | None = None,
        package_name: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if ecosystem:
            conditions.append("ecosystem = ?")
            params.append(ecosystem)
        if package_name:
            conditions.append("package_name = ?")
            params.append(package_name)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT record_key, advisory_id, ecosystem, package_name, summary,
                   severity, aliases_json, affected_versions_json,
                   affected_ranges_json, references_json, published_at,
                   modified_at, withdrawn_at, source, metadata_json, updated_at
            FROM vulnerability_advisories
            """ + where + " ORDER BY advisory_id LIMIT ?",
            tuple(params),
        )
        return [_advisory_from_row(row) for row in cur.fetchall()]

    def save_advisory_feed_snapshot(self, snapshot: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO advisory_feed_snapshots (
                id, feed_id, sequence, schema_version, generated_at,
                expires_at, source, feed_json, sha256, signature_algorithm,
                key_id, signature, status, documents_imported,
                package_records_imported, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot["id"],
                snapshot["feed_id"],
                snapshot["sequence"],
                snapshot["schema_version"],
                snapshot["generated_at"],
                snapshot["expires_at"],
                snapshot["source"],
                json.dumps(snapshot["feed"], sort_keys=True),
                snapshot["sha256"],
                snapshot["signature_algorithm"],
                snapshot["key_id"],
                snapshot["signature"],
                snapshot["status"],
                snapshot["documents_imported"],
                snapshot["package_records_imported"],
                snapshot["imported_at"],
            ),
        )
        self._commit()
        return snapshot["id"]

    def get_advisory_feed_snapshot(
        self, snapshot_id: str
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, feed_id, sequence, schema_version, generated_at,
                   expires_at, source, feed_json, sha256,
                   signature_algorithm, key_id, signature, status,
                   documents_imported, package_records_imported, imported_at
            FROM advisory_feed_snapshots WHERE id = ?
            """,
            (snapshot_id,),
        )
        row = cur.fetchone()
        return _advisory_feed_snapshot_from_row(row) if row else None

    def get_latest_advisory_feed_snapshot(
        self, feed_id: str | None = None
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        if feed_id:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed_json, sha256,
                       signature_algorithm, key_id, signature, status,
                       documents_imported, package_records_imported, imported_at
                FROM advisory_feed_snapshots WHERE feed_id = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (feed_id,),
            )
        else:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed_json, sha256,
                       signature_algorithm, key_id, signature, status,
                       documents_imported, package_records_imported, imported_at
                FROM advisory_feed_snapshots
                ORDER BY imported_at DESC LIMIT 1
                """
            )
        row = cur.fetchone()
        return _advisory_feed_snapshot_from_row(row) if row else None

    def list_advisory_feed_snapshots(
        self, limit: int = 100, feed_id: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        if feed_id:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed_json, sha256,
                       signature_algorithm, key_id, signature, status,
                       documents_imported, package_records_imported, imported_at
                FROM advisory_feed_snapshots WHERE feed_id = ?
                ORDER BY sequence DESC LIMIT ?
                """,
                (feed_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed_json, sha256,
                       signature_algorithm, key_id, signature, status,
                       documents_imported, package_records_imported, imported_at
                FROM advisory_feed_snapshots
                ORDER BY imported_at DESC LIMIT ?
                """,
                (limit,),
            )
        return [_advisory_feed_snapshot_from_row(row) for row in cur.fetchall()]

    def save_control_evidence(self, evidence: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO control_evidence (
                id, artifact_id, control_id, evidence_fields_json,
                evidence_type, reference, sha256, metadata_json, submitted_by,
                submitted_at, expires_at, status, reviewer, review_rationale,
                reviewed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence["id"],
                evidence["artifact_id"],
                evidence["control_id"],
                json.dumps(evidence["evidence_fields"]),
                evidence["evidence_type"],
                evidence["reference"],
                evidence["sha256"],
                json.dumps(evidence.get("metadata", {})),
                evidence["submitted_by"],
                evidence["submitted_at"],
                evidence.get("expires_at"),
                evidence["status"],
                evidence.get("reviewer"),
                evidence.get("review_rationale"),
                evidence.get("reviewed_at"),
                evidence["updated_at"],
            ),
        )
        self._conn.commit()
        return evidence["id"]

    def save_assurance_report_snapshot(self, snapshot: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO assurance_report_snapshots (
                id, artifact_id, scope_type, snapshot_version, report_version,
                report_json, sha256, signature, signature_algorithm, key_id,
                created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot["id"],
                snapshot.get("artifact_id"),
                snapshot["scope_type"],
                snapshot["snapshot_version"],
                snapshot["report_version"],
                json.dumps(snapshot["report"], sort_keys=True),
                snapshot["sha256"],
                snapshot.get("signature"),
                snapshot.get("signature_algorithm"),
                snapshot.get("key_id"),
                snapshot["created_by"],
                snapshot["created_at"],
            ),
        )
        self._conn.commit()
        return snapshot["id"]

    def get_assurance_report_snapshot(
        self, snapshot_id: str
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, scope_type, snapshot_version,
                   report_version, report_json, sha256, signature,
                   signature_algorithm, key_id, created_by, created_at
            FROM assurance_report_snapshots WHERE id = ?
            """,
            (snapshot_id,),
        )
        row = cur.fetchone()
        return _assurance_report_snapshot_from_row(row) if row else None

    def list_assurance_report_snapshots(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        if artifact_id:
            cur.execute(
                """
                SELECT id, artifact_id, scope_type, snapshot_version,
                       report_version, report_json, sha256, signature,
                       signature_algorithm, key_id, created_by, created_at
                FROM assurance_report_snapshots WHERE artifact_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (artifact_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, artifact_id, scope_type, snapshot_version,
                       report_version, report_json, sha256, signature,
                       signature_algorithm, key_id, created_by, created_at
                FROM assurance_report_snapshots
                ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            )
        return [
            _assurance_report_snapshot_from_row(row) for row in cur.fetchall()
        ]

    def get_control_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, control_id, evidence_fields_json,
                   evidence_type, reference, sha256, metadata_json,
                   submitted_by, submitted_at, expires_at, status, reviewer,
                   review_rationale, reviewed_at, updated_at
            FROM control_evidence WHERE id = ?
            """,
            (evidence_id,),
        )
        row = cur.fetchone()
        return _control_evidence_from_row(row) if row else None

    def list_control_evidence(
        self,
        limit: int = 1000,
        artifact_id: str | None = None,
        control_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        for column, value in (
            ("artifact_id", artifact_id),
            ("control_id", control_id),
            ("status", status),
        ):
            if value:
                conditions.append(f"{column} = ?")
                params.append(value)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, control_id, evidence_fields_json,
                   evidence_type, reference, sha256, metadata_json,
                   submitted_by, submitted_at, expires_at, status, reviewer,
                   review_rationale, reviewed_at, updated_at
            FROM control_evidence
            """ + where + " ORDER BY submitted_at DESC LIMIT ?",
            tuple(params),
        )
        return [_control_evidence_from_row(row) for row in cur.fetchall()]

    def review_control_evidence(
        self, evidence_id: str, review: dict[str, Any]
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            UPDATE control_evidence SET status = ?, reviewer = ?,
                review_rationale = ?, reviewed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'PENDING'
            """,
            (
                review["status"],
                review["reviewer"],
                review["review_rationale"],
                review["reviewed_at"],
                review["updated_at"],
                evidence_id,
            ),
        )
        if cur.rowcount == 0:
            self._conn.commit()
            return None
        self._conn.commit()
        return self.get_control_evidence(evidence_id)

    def save_agent_session(self, session: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO agent_sessions (
                id, artifact_id, artifact_json, policy_profile,
                effective_policy_json, status, external_calls_used,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["id"],
                session["artifact_id"],
                json.dumps(session["artifact"]),
                session.get("policy_profile"),
                json.dumps(session["effective_policy"]),
                session["status"],
                int(session.get("external_calls_used", 0)),
                session["created_at"],
                session["updated_at"],
            ),
        )
        self._conn.commit()
        return session["id"]

    def get_agent_session(self, session_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact_json, policy_profile,
                   effective_policy_json, status, external_calls_used,
                   created_at, updated_at
            FROM agent_sessions WHERE id = ?
            """,
            (session_id,),
        )
        row = cur.fetchone()
        return _agent_session_from_row(row) if row else None

    def list_agent_sessions(
        self,
        limit: int = 100,
        artifact_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if artifact_id:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact_json, policy_profile,
                   effective_policy_json, status, external_calls_used,
                   created_at, updated_at
            FROM agent_sessions
            """ + where + " ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )
        return [_agent_session_from_row(row) for row in cur.fetchall()]

    def update_agent_session_status(
        self, session_id: str, status: str, updated_at: str
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            "UPDATE agent_sessions SET status = ?, updated_at = ? WHERE id = ?",
            (status, updated_at, session_id),
        )
        self._conn.commit()
        return self.get_agent_session(session_id)

    def record_tool_invocation(
        self, invocation: dict[str, Any], max_external_calls: int | None
    ) -> dict[str, Any]:
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute(
                """
                SELECT id, artifact_id, artifact_json, policy_profile,
                       effective_policy_json, status, external_calls_used,
                       created_at, updated_at
                FROM agent_sessions WHERE id = ?
                """,
                (invocation["session_id"],),
            )
            session_row = cur.fetchone()
            if not session_row:
                raise ValueError("Agent session not found")
            session = _agent_session_from_row(session_row)
            cur.execute(
                """
                SELECT id, session_id, request_id, workflow_step_id, tool,
                       action, permissions_json, input_source, input_validation,
                       target, approval_id, approved_by, decision, reasons_json,
                       external_call, created_at
                FROM tool_invocation_decisions
                WHERE session_id = ? AND request_id = ?
                """,
                (invocation["session_id"], invocation["request_id"]),
            )
            existing = cur.fetchone()
            if existing:
                record = _tool_invocation_from_row(existing)
                if not _same_invocation_request(record, invocation):
                    raise ValueError(
                        "request_id already used with a different invocation payload"
                    )
                self._conn.commit()
                record["idempotent_replay"] = True
                return record

            reasons = list(invocation.get("reasons", []))
            decision = invocation["decision"]
            if session["status"] != "ACTIVE":
                decision = "DENY"
                reasons.append(
                    {"code": "session_not_active", "detail": "Agent session is not active."}
                )
            if invocation.get("external_call") and decision == "ALLOW":
                limit = (
                    max(0, int(max_external_calls))
                    if max_external_calls is not None
                    else None
                )
                if limit is not None and session["external_calls_used"] >= limit:
                    decision = "DENY"
                    reasons.append(
                        {
                            "code": "external_call_limit_exceeded",
                            "detail": f"External call limit of {limit} has been reached.",
                        }
                    )
                else:
                    cur.execute(
                        """
                        UPDATE agent_sessions SET
                            external_calls_used = external_calls_used + 1,
                            updated_at = ? WHERE id = ?
                        """,
                        (invocation["created_at"], invocation["session_id"]),
                    )
            invocation = {**invocation, "decision": decision, "reasons": reasons}
            cur.execute(
                """
                INSERT INTO tool_invocation_decisions (
                    id, session_id, request_id, workflow_step_id, tool, action,
                    permissions_json, input_source, input_validation, target,
                    approval_id, approved_by, decision, reasons_json,
                    external_call, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invocation["id"],
                    invocation["session_id"],
                    invocation["request_id"],
                    invocation.get("workflow_step_id"),
                    invocation["tool"],
                    invocation.get("action"),
                    json.dumps(invocation.get("permissions", [])),
                    invocation.get("input_source"),
                    invocation.get("input_validation"),
                    invocation.get("target"),
                    invocation.get("approval_id"),
                    invocation.get("approved_by"),
                    invocation["decision"],
                    json.dumps(invocation.get("reasons", [])),
                    int(bool(invocation.get("external_call"))),
                    invocation["created_at"],
                ),
            )
            self._conn.commit()
            invocation["idempotent_replay"] = False
            return invocation
        except Exception:
            self._conn.rollback()
            raise

    def list_tool_invocations(
        self,
        limit: int = 100,
        session_id: str | None = None,
        decision: str | None = None,
        artifact_id: str | None = None,
    ) -> list[dict[str, Any]]:
        conditions = []
        params: list[Any] = []
        if session_id:
            conditions.append("d.session_id = ?")
            params.append(session_id)
        if decision:
            conditions.append("d.decision = ?")
            params.append(decision)
        if artifact_id:
            conditions.append("s.artifact_id = ?")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT d.id, d.session_id, d.request_id, d.workflow_step_id,
                   d.tool, d.action, d.permissions_json, d.input_source,
                   d.input_validation, d.target, d.approval_id, d.approved_by,
                   d.decision, d.reasons_json, d.external_call, d.created_at,
                   s.artifact_id
            FROM tool_invocation_decisions d
            JOIN agent_sessions s ON s.id = d.session_id
            """ + where + " ORDER BY d.created_at DESC LIMIT ?",
            tuple(params),
        )
        return [_tool_invocation_from_row(row) for row in cur.fetchall()]

    def close(self) -> None:
        with self._conn_lock:
            try:
                self._conn.close()
            except Exception:
                pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _monitoring_schedule_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "artifact_id": row["artifact_id"],
        "artifact": json.loads(row["artifact_json"] or "{}"),
        "interval_seconds": row["interval_seconds"],
        "enabled": bool(row["enabled"]),
        "next_run_at": row["next_run_at"],
        "last_run_at": row["last_run_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _monitoring_run_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schedule_id": row["schedule_id"],
        "artifact_id": row["artifact_id"],
        "status": row["status"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "result": json.loads(row["result_json"] or "{}"),
        "error": row["error"],
    }


def _risk_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "artifact_id": row["artifact_id"],
        "finding_type": row["finding_type"],
        "indicator": row["indicator"],
        "title": row["title"],
        "severity": row["severity"],
        "status": row["status"],
        "details": json.loads(row["details_json"] or "{}"),
        "first_seen_at": row["first_seen_at"],
        "last_seen_at": row["last_seen_at"],
        "occurrence_count": row["occurrence_count"],
        "owner": row["owner"],
        "due_at": row["due_at"],
        "resolution": row["resolution"],
        "updated_at": row["updated_at"],
    }


def _advisory_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "record_key": row["record_key"],
        "advisory_id": row["advisory_id"],
        "ecosystem": row["ecosystem"],
        "package_name": row["package_name"],
        "summary": row["summary"],
        "severity": row["severity"],
        "aliases": json.loads(row["aliases_json"] or "[]"),
        "affected_versions": json.loads(row["affected_versions_json"] or "[]"),
        "affected_ranges": json.loads(row["affected_ranges_json"] or "[]"),
        "references": json.loads(row["references_json"] or "[]"),
        "published_at": row["published_at"],
        "modified_at": row["modified_at"],
        "withdrawn_at": row["withdrawn_at"],
        "source": row["source"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "updated_at": row["updated_at"],
    }


def _advisory_feed_snapshot_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "feed_id": row["feed_id"],
        "sequence": row["sequence"],
        "schema_version": row["schema_version"],
        "generated_at": row["generated_at"],
        "expires_at": row["expires_at"],
        "source": row["source"],
        "feed": json.loads(row["feed_json"] or "{}"),
        "sha256": row["sha256"],
        "signature_algorithm": row["signature_algorithm"],
        "key_id": row["key_id"],
        "signature": row["signature"],
        "status": row["status"],
        "documents_imported": row["documents_imported"],
        "package_records_imported": row["package_records_imported"],
        "imported_at": row["imported_at"],
    }


def _control_evidence_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "artifact_id": row["artifact_id"],
        "control_id": row["control_id"],
        "evidence_fields": json.loads(row["evidence_fields_json"] or "[]"),
        "evidence_type": row["evidence_type"],
        "reference": row["reference"],
        "sha256": row["sha256"],
        "metadata": json.loads(row["metadata_json"] or "{}"),
        "submitted_by": row["submitted_by"],
        "submitted_at": row["submitted_at"],
        "expires_at": row["expires_at"],
        "status": row["status"],
        "reviewer": row["reviewer"],
        "review_rationale": row["review_rationale"],
        "reviewed_at": row["reviewed_at"],
        "updated_at": row["updated_at"],
    }


def _assurance_report_snapshot_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "artifact_id": row["artifact_id"],
        "scope_type": row["scope_type"],
        "snapshot_version": row["snapshot_version"],
        "report_version": row["report_version"],
        "report": json.loads(row["report_json"] or "{}"),
        "sha256": row["sha256"],
        "signature": row["signature"],
        "signature_algorithm": row["signature_algorithm"],
        "key_id": row["key_id"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def _agent_session_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "artifact_id": row["artifact_id"],
        "artifact": json.loads(row["artifact_json"] or "{}"),
        "policy_profile": row["policy_profile"],
        "effective_policy": json.loads(row["effective_policy_json"] or "{}"),
        "status": row["status"],
        "external_calls_used": row["external_calls_used"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _tool_invocation_from_row(row: sqlite3.Row) -> dict[str, Any]:
    artifact_id = row["artifact_id"] if "artifact_id" in row.keys() else None
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "request_id": row["request_id"],
        "workflow_step_id": row["workflow_step_id"],
        "tool": row["tool"],
        "action": row["action"],
        "permissions": json.loads(row["permissions_json"] or "[]"),
        "input_source": row["input_source"],
        "input_validation": row["input_validation"],
        "target": row["target"],
        "approval_id": row["approval_id"],
        "approved_by": row["approved_by"],
        "decision": row["decision"],
        "reasons": json.loads(row["reasons_json"] or "[]"),
        "external_call": bool(row["external_call"]),
        "created_at": row["created_at"],
        "artifact_id": artifact_id,
    }


def _same_invocation_request(
    existing: dict[str, Any], requested: dict[str, Any]
) -> bool:
    scalar_fields = (
        "workflow_step_id",
        "tool",
        "action",
        "input_source",
        "input_validation",
        "target",
        "approval_id",
        "approved_by",
    )
    fields_match = all(
        existing.get(field) == requested.get(field) for field in scalar_fields
    )
    permissions_match = sorted(existing.get("permissions") or []) == sorted(
        requested.get("permissions") or []
    )
    return fields_match and permissions_match

"""PostgreSQL persistence for registry and assurance evidence."""

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import psycopg2


class PostgresStore:
    """PostgreSQL implementation of the framework datastore contract."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._conn = psycopg2.connect(dsn)
        self._tx_depth = 0
        self._ensure_tables()

    def _commit(self) -> None:
        """Commit unless inside an explicit ``transaction()`` block."""
        if self._tx_depth == 0:
            self._conn.commit()

    @contextmanager
    def transaction(self):
        """Group multiple writes into one atomic unit (commit once / rollback all)."""
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

    def _ensure_tables(self) -> None:
        cur = self._conn.cursor()
        statements = (
            """
            CREATE TABLE IF NOT EXISTS models (
                id UUID PRIMARY KEY,
                model_name VARCHAR(255),
                version VARCHAR(50),
                source VARCHAR(255),
                source_url TEXT,
                publisher VARCHAR(255),
                sha256_hash TEXT,
                uploaded_at TIMESTAMP WITH TIME ZONE,
                registered_by VARCHAR(255),
                license TEXT,
                training_data TEXT,
                provenance_score INTEGER,
                risk_level VARCHAR(50),
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id UUID PRIMARY KEY,
                status VARCHAR(50) NOT NULL,
                result JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id BIGSERIAL PRIMARY KEY,
                artifact_id TEXT,
                observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
                findings JSONB NOT NULL DEFAULT '[]'::jsonb,
                score DOUBLE PRECISION NOT NULL DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id BIGSERIAL PRIMARY KEY,
                event_type TEXT NOT NULL,
                artifact_id TEXT,
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS historical_metrics (
                id BIGSERIAL PRIMARY KEY,
                artifact_id TEXT,
                metric_name TEXT NOT NULL,
                metric_value DOUBLE PRECISION NOT NULL,
                dimensions JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS monitoring_schedules (
                id UUID PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                artifact JSONB NOT NULL,
                interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                next_run_at TIMESTAMP WITH TIME ZONE NOT NULL,
                last_run_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS monitoring_runs (
                id UUID PRIMARY KEY,
                schedule_id UUID NOT NULL REFERENCES monitoring_schedules(id),
                artifact_id TEXT NOT NULL,
                status VARCHAR(50) NOT NULL,
                started_at TIMESTAMP WITH TIME ZONE NOT NULL,
                completed_at TIMESTAMP WITH TIME ZONE,
                result JSONB NOT NULL DEFAULT '{}'::jsonb,
                error TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS risk_register (
                id UUID PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                artifact_id TEXT,
                finding_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                title TEXT NOT NULL,
                severity VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL,
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
                last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                owner TEXT,
                due_at TIMESTAMP WITH TIME ZONE,
                resolution TEXT,
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vulnerability_advisories (
                record_key TEXT PRIMARY KEY,
                advisory_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity VARCHAR(20) NOT NULL,
                aliases JSONB NOT NULL DEFAULT '[]'::jsonb,
                affected_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
                affected_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
                references_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                published_at TIMESTAMP WITH TIME ZONE,
                modified_at TIMESTAMP WITH TIME ZONE,
                withdrawn_at TIMESTAMP WITH TIME ZONE,
                source TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS advisory_feed_snapshots (
                id UUID PRIMARY KEY,
                feed_id TEXT NOT NULL,
                sequence BIGINT NOT NULL,
                schema_version VARCHAR(20) NOT NULL,
                generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                source TEXT NOT NULL,
                feed JSONB NOT NULL,
                sha256 VARCHAR(64) NOT NULL,
                signature_algorithm VARCHAR(30) NOT NULL,
                key_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                status VARCHAR(30) NOT NULL,
                documents_imported INTEGER NOT NULL,
                package_records_imported INTEGER NOT NULL,
                imported_at TIMESTAMP WITH TIME ZONE NOT NULL,
                UNIQUE(feed_id, sequence)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS control_evidence (
                id UUID PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                evidence_fields JSONB NOT NULL,
                evidence_type TEXT NOT NULL,
                reference TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                submitted_by TEXT NOT NULL,
                submitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE,
                status VARCHAR(20) NOT NULL,
                reviewer TEXT,
                review_rationale TEXT,
                reviewed_at TIMESTAMP WITH TIME ZONE,
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS assurance_report_snapshots (
                id UUID PRIMARY KEY,
                artifact_id TEXT,
                scope_type VARCHAR(20) NOT NULL,
                snapshot_version VARCHAR(20) NOT NULL DEFAULT '1.0',
                report_version VARCHAR(20) NOT NULL,
                report JSONB NOT NULL,
                sha256 VARCHAR(64) NOT NULL,
                signature TEXT,
                signature_algorithm VARCHAR(30),
                key_id TEXT,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id UUID PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                artifact JSONB NOT NULL,
                policy_profile TEXT,
                effective_policy JSONB NOT NULL,
                status VARCHAR(20) NOT NULL,
                external_calls_used INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS tool_invocation_decisions (
                id UUID PRIMARY KEY,
                session_id UUID NOT NULL REFERENCES agent_sessions(id),
                request_id TEXT NOT NULL,
                workflow_step_id TEXT,
                tool TEXT NOT NULL,
                action TEXT,
                permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                input_source TEXT,
                input_validation TEXT,
                target TEXT,
                approval_id TEXT,
                approved_by TEXT,
                decision VARCHAR(30) NOT NULL,
                reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
                external_call BOOLEAN NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                UNIQUE(session_id, request_id)
            )
            """,
            "ALTER TABLE models ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE models ADD COLUMN IF NOT EXISTS registered_by VARCHAR(255)",
            "ALTER TABLE historical_metrics ADD COLUMN IF NOT EXISTS artifact_id TEXT",
            "ALTER TABLE assurance_report_snapshots ADD COLUMN IF NOT EXISTS snapshot_version VARCHAR(20) NOT NULL DEFAULT '1.0'",
            "UPDATE historical_metrics SET artifact_id = dimensions->>'artifact_id' WHERE artifact_id IS NULL AND dimensions ? 'artifact_id'",
            "CREATE INDEX IF NOT EXISTS findings_observed_at_idx ON findings (observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS findings_artifact_idx ON findings (artifact_id, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs (created_at DESC)",
            "CREATE INDEX IF NOT EXISTS audit_logs_artifact_idx ON audit_logs (artifact_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS metrics_name_created_at_idx ON historical_metrics (metric_name, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS historical_metrics_artifact_idx ON historical_metrics (artifact_id, metric_name, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS monitoring_schedules_due_idx ON monitoring_schedules (enabled, next_run_at)",
            "CREATE INDEX IF NOT EXISTS monitoring_runs_schedule_idx ON monitoring_runs (schedule_id, started_at DESC)",
            "CREATE INDEX IF NOT EXISTS risk_register_status_idx ON risk_register (status, severity, due_at)",
            "CREATE INDEX IF NOT EXISTS risk_register_artifact_idx ON risk_register (artifact_id, last_seen_at DESC)",
            "CREATE INDEX IF NOT EXISTS vulnerability_advisories_package_idx ON vulnerability_advisories (ecosystem, package_name)",
            "CREATE INDEX IF NOT EXISTS advisory_feed_snapshots_feed_idx ON advisory_feed_snapshots (feed_id, sequence DESC)",
            "CREATE INDEX IF NOT EXISTS advisory_feed_snapshots_expiry_idx ON advisory_feed_snapshots (expires_at, status)",
            "CREATE INDEX IF NOT EXISTS control_evidence_artifact_idx ON control_evidence (artifact_id, control_id, status)",
            "CREATE INDEX IF NOT EXISTS control_evidence_expiry_idx ON control_evidence (status, expires_at)",
            "CREATE INDEX IF NOT EXISTS assurance_report_snapshots_artifact_idx ON assurance_report_snapshots (artifact_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS agent_sessions_artifact_idx ON agent_sessions (artifact_id, status, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS tool_invocations_session_idx ON tool_invocation_decisions (session_id, created_at DESC)",
        )
        for statement in statements:
            cur.execute(statement)
        self._conn.commit()

    def save_finding(self, finding: dict[str, Any]) -> int:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO findings (artifact_id, observed_at, findings, score)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                finding.get("artifact_id"),
                finding.get("timestamp") or _utc_now(),
                json.dumps(finding.get("findings", [])),
                float(finding.get("score", 0.0)),
            ),
        )
        finding_id = int(cur.fetchone()[0])
        self._conn.commit()
        return finding_id

    def list_findings(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        if artifact_id:
            cur.execute(
                """
                SELECT id, artifact_id, observed_at, findings, score
                FROM findings WHERE artifact_id = %s
                ORDER BY id DESC LIMIT %s
                """,
                (artifact_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, artifact_id, observed_at, findings, score
                FROM findings ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            )
        return [
            {
                "id": row[0],
                "artifact_id": row[1],
                "timestamp": _isoformat(row[2]),
                "findings": _json_value(row[3], []),
                "score": row[4],
            }
            for row in cur.fetchall()
        ]

    def save_model(self, model_record: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        model_id = str(model_record.get("model_id") or uuid.uuid4())
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
            INSERT INTO models (
                id, model_name, version, source, source_url, publisher,
                sha256_hash, uploaded_at, registered_by, license, training_data,
                provenance_score, risk_level, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                model_name = EXCLUDED.model_name,
                version = EXCLUDED.version,
                source = EXCLUDED.source,
                source_url = EXCLUDED.source_url,
                publisher = EXCLUDED.publisher,
                sha256_hash = EXCLUDED.sha256_hash,
                uploaded_at = EXCLUDED.uploaded_at,
                registered_by = EXCLUDED.registered_by,
                license = EXCLUDED.license,
                training_data = EXCLUDED.training_data,
                provenance_score = EXCLUDED.provenance_score,
                risk_level = EXCLUDED.risk_level,
                metadata = EXCLUDED.metadata
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
            ),
        )
        self._conn.commit()
        return model_id

    def get_model(self, model_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, model_name, version, source, source_url, publisher,
                   sha256_hash, uploaded_at, registered_by, license, training_data,
                   provenance_score, risk_level, metadata, created_at
            FROM models WHERE id = %s
            """,
            (model_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        metadata = _json_value(row[13], {})
        return {
            "model_id": str(row[0]),
            "model_name": row[1],
            "version": row[2],
            "source": row[3],
            "source_url": row[4],
            "publisher": row[5],
            "sha256": row[6],
            "uploaded_at": _isoformat(row[7]),
            "registered_by": row[8],
            "license": row[9],
            "training_data": row[10],
            "provenance_score": row[11],
            "risk_level": row[12],
            "dependencies": metadata.get("dependencies", []),
            "training_artifacts": metadata.get("training_artifacts", []),
            "deployment_pipeline": metadata.get("deployment_pipeline", {}),
            "dependency_discovery": metadata.get("dependency_discovery", {}),
            "provenance_attestations": metadata.get("provenance_attestations", []),
            "vulnerability_scan": metadata.get("vulnerability_scan", {}),
            "metadata": metadata,
            "created_at": _isoformat(row[14]),
        }

    def list_models(
        self,
        limit: int = 100,
        registered_by: str | None = None,
        real_models_only: bool = False,
    ) -> list[dict[str, Any]]:
        """List rows from the shared ``models`` table.

        See ``DataStore.list_models`` for why ``real_models_only`` exists:
        this table also stores non-model registry objects keyed as
        ``"prefix:id"``, and most callers need every row to filter for their
        own prefix. Pass ``real_models_only=True`` to exclude those and keep
        only genuine registered AI models (bare-UUID ids).
        """
        cur = self._conn.cursor()
        id_filter = " AND id NOT LIKE '%:%'" if real_models_only else ""
        if registered_by:
            cur.execute(
                f"""
                SELECT id, model_name, version, source, source_url, publisher,
                       sha256_hash, registered_by, provenance_score, risk_level, metadata, created_at
                FROM models WHERE registered_by = %s{id_filter} ORDER BY created_at DESC LIMIT %s
                """,
                (registered_by, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT id, model_name, version, source, source_url, publisher,
                       sha256_hash, registered_by, provenance_score, risk_level, metadata, created_at
                FROM models WHERE 1=1{id_filter} ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
        models = []
        for row in cur.fetchall():
            metadata = _json_value(row[10], {})
            models.append(
                {
                    "model_id": str(row[0]),
                    "model_name": row[1],
                    "version": row[2],
                    "source": row[3],
                    "source_url": row[4],
                    "publisher": row[5],
                    "sha256": row[6],
                    "registered_by": row[7],
                    "provenance_score": row[8],
                    "risk_level": row[9],
                    "dependencies": metadata.get("dependencies", []),
                    "training_artifacts": metadata.get("training_artifacts", []),
                    "deployment_pipeline": metadata.get("deployment_pipeline", {}),
                    "dependency_discovery": metadata.get("dependency_discovery", {}),
                    "provenance_attestations": metadata.get("provenance_attestations", []),
                    "vulnerability_scan": metadata.get("vulnerability_scan", {}),
                    "metadata": metadata,
                    "created_at": _isoformat(row[11]),
                }
            )
        return models

    def create_job(self) -> str:
        cur = self._conn.cursor()
        job_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO jobs (id, status, result) VALUES (%s, %s, %s)",
            (job_id, "PENDING", json.dumps({})),
        )
        self._conn.commit()
        return job_id

    def update_job(self, job_id: str, status: str, result: dict[str, Any]) -> None:
        cur = self._conn.cursor()
        cur.execute(
            "UPDATE jobs SET status = %s, result = %s, updated_at = now() WHERE id = %s",
            (status, json.dumps(result), job_id),
        )
        self._conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT id, status, result, created_at, updated_at FROM jobs WHERE id = %s",
            (job_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": str(row[0]),
            "status": row[1],
            "result": _json_value(row[2], {}),
            "created_at": _isoformat(row[3]),
            "updated_at": _isoformat(row[4]),
        }

    def save_audit_log(self, event: dict[str, Any]) -> int:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_logs (event_type, artifact_id, details, created_at)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                event.get("event_type"),
                event.get("artifact_id"),
                json.dumps(event.get("details", {})),
                _utc_now(),
            ),
        )
        event_id = int(cur.fetchone()[0])
        self._conn.commit()
        return event_id

    def list_audit_logs(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        if artifact_id:
            cur.execute(
                """
                SELECT id, event_type, artifact_id, details, created_at
                FROM audit_logs WHERE artifact_id = %s
                ORDER BY id DESC LIMIT %s
                """,
                (artifact_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, event_type, artifact_id, details, created_at
                FROM audit_logs ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            )
        return [
            {
                "id": row[0],
                "event_type": row[1],
                "artifact_id": row[2],
                "details": _json_value(row[3], {}),
                "created_at": _isoformat(row[4]),
            }
            for row in cur.fetchall()
        ]

    def save_metric(
        self,
        metric_name: str,
        metric_value: float,
        dimensions: dict[str, Any] | None = None,
    ) -> int:
        dimensions = dimensions or {}
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO historical_metrics (
                artifact_id, metric_name, metric_value, dimensions, created_at
            ) VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                dimensions.get("artifact_id"),
                metric_name,
                float(metric_value),
                json.dumps(dimensions),
                _utc_now(),
            ),
        )
        metric_id = int(cur.fetchone()[0])
        self._conn.commit()
        return metric_id

    def list_metrics(
        self, limit: int = 100, artifact_id: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        if artifact_id:
            cur.execute(
                """
                SELECT id, artifact_id, metric_name, metric_value,
                       dimensions, created_at
                FROM historical_metrics WHERE artifact_id = %s
                ORDER BY id DESC LIMIT %s
                """,
                (artifact_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, artifact_id, metric_name, metric_value,
                       dimensions, created_at
                FROM historical_metrics ORDER BY id DESC LIMIT %s
                """,
                (limit,),
            )
        return [
            {
                "id": row[0],
                "artifact_id": row[1],
                "metric_name": row[2],
                "metric_value": row[3],
                "dimensions": _json_value(row[4], {}),
                "created_at": _isoformat(row[5]),
            }
            for row in cur.fetchall()
        ]

    def save_monitoring_schedule(self, schedule: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO monitoring_schedules (
                id, artifact_id, artifact, interval_seconds, enabled,
                next_run_at, last_run_at, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                artifact_id = EXCLUDED.artifact_id,
                artifact = EXCLUDED.artifact,
                interval_seconds = EXCLUDED.interval_seconds,
                enabled = EXCLUDED.enabled,
                next_run_at = EXCLUDED.next_run_at,
                last_run_at = EXCLUDED.last_run_at,
                updated_at = EXCLUDED.updated_at
            """,
            (
                schedule["id"],
                schedule["artifact_id"],
                json.dumps(schedule["artifact"]),
                int(schedule["interval_seconds"]),
                bool(schedule.get("enabled", True)),
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
            SELECT id, artifact_id, artifact, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules WHERE id = %s
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
            conditions.append("enabled = %s")
            params.append(enabled)
        if artifact_id:
            conditions.append("artifact_id = %s")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules
            """ + where + " ORDER BY created_at DESC LIMIT %s",
            tuple(params),
        )
        return [_monitoring_schedule_from_row(row) for row in cur.fetchall()]

    def list_due_monitoring_schedules(
        self, as_of: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact, interval_seconds, enabled,
                   next_run_at, last_run_at, created_at, updated_at
            FROM monitoring_schedules
            WHERE enabled = TRUE AND next_run_at <= %s
            ORDER BY next_run_at ASC LIMIT %s
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
                completed_at, result, error
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                completed_at = EXCLUDED.completed_at,
                result = EXCLUDED.result,
                error = EXCLUDED.error
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
            conditions.append("schedule_id = %s")
            params.append(schedule_id)
        if artifact_id:
            conditions.append("artifact_id = %s")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, schedule_id, artifact_id, status, started_at,
                   completed_at, result, error
            FROM monitoring_runs
            """ + where + " ORDER BY started_at DESC LIMIT %s",
            tuple(params),
        )
        return [_monitoring_run_from_row(row) for row in cur.fetchall()]

    def upsert_risk_observation(self, risk: dict[str, Any]) -> dict[str, Any]:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO risk_register (
                id, fingerprint, artifact_id, finding_type, indicator, title,
                severity, status, details, first_seen_at, last_seen_at,
                occurrence_count, owner, due_at, resolution, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (fingerprint) DO UPDATE SET
                severity = EXCLUDED.severity,
                status = CASE
                    WHEN risk_register.status = 'RESOLVED' THEN 'OPEN'
                    ELSE risk_register.status
                END,
                details = EXCLUDED.details,
                last_seen_at = EXCLUDED.last_seen_at,
                occurrence_count = risk_register.occurrence_count + 1,
                due_at = CASE
                    WHEN risk_register.status = 'RESOLVED' THEN EXCLUDED.due_at
                    ELSE risk_register.due_at
                END,
                resolution = CASE
                    WHEN risk_register.status = 'RESOLVED' THEN NULL
                    ELSE risk_register.resolution
                END,
                updated_at = EXCLUDED.updated_at
            RETURNING id, fingerprint, artifact_id, finding_type, indicator,
                      title, severity, status, details, first_seen_at,
                      last_seen_at, occurrence_count, owner, due_at, resolution,
                      updated_at
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
        row = cur.fetchone()
        self._conn.commit()
        return _risk_from_row(row)

    def get_risk(self, risk_id: str) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, fingerprint, artifact_id, finding_type, indicator,
                   title, severity, status, details, first_seen_at,
                   last_seen_at, occurrence_count, owner, due_at, resolution,
                   updated_at
            FROM risk_register WHERE id = %s
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
            conditions.append("status = %s")
            params.append(status)
        if artifact_id:
            conditions.append("artifact_id = %s")
            params.append(artifact_id)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, fingerprint, artifact_id, finding_type, indicator,
                   title, severity, status, details, first_seen_at,
                   last_seen_at, occurrence_count, owner, due_at, resolution,
                   updated_at
            FROM risk_register
            """ + where + " ORDER BY last_seen_at DESC LIMIT %s",
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
        assignments = ", ".join(f"{column} = %s" for column, _ in selected)
        params = [value for _, value in selected] + [risk_id]
        cur = self._conn.cursor()
        cur.execute(f"UPDATE risk_register SET {assignments} WHERE id = %s", tuple(params))
        self._conn.commit()
        return self.get_risk(risk_id)

    def save_advisory(self, advisory: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO vulnerability_advisories (
                record_key, advisory_id, ecosystem, package_name, summary,
                severity, aliases, affected_versions, affected_ranges,
                references_json, published_at, modified_at, withdrawn_at,
                source, metadata, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (record_key) DO UPDATE SET
                summary = EXCLUDED.summary,
                severity = EXCLUDED.severity,
                aliases = EXCLUDED.aliases,
                affected_versions = EXCLUDED.affected_versions,
                affected_ranges = EXCLUDED.affected_ranges,
                references_json = EXCLUDED.references_json,
                published_at = EXCLUDED.published_at,
                modified_at = EXCLUDED.modified_at,
                withdrawn_at = EXCLUDED.withdrawn_at,
                source = EXCLUDED.source,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
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
            conditions.append("ecosystem = %s")
            params.append(ecosystem)
        if package_name:
            conditions.append("package_name = %s")
            params.append(package_name)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT record_key, advisory_id, ecosystem, package_name, summary,
                   severity, aliases, affected_versions, affected_ranges,
                   references_json, published_at, modified_at, withdrawn_at,
                   source, metadata, updated_at
            FROM vulnerability_advisories
            """ + where + " ORDER BY advisory_id LIMIT %s",
            tuple(params),
        )
        return [_advisory_from_row(row) for row in cur.fetchall()]

    def save_advisory_feed_snapshot(self, snapshot: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO advisory_feed_snapshots (
                id, feed_id, sequence, schema_version, generated_at,
                expires_at, source, feed, sha256, signature_algorithm, key_id,
                signature, status, documents_imported,
                package_records_imported, imported_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                   expires_at, source, feed, sha256, signature_algorithm,
                   key_id, signature, status, documents_imported,
                   package_records_imported, imported_at
            FROM advisory_feed_snapshots WHERE id = %s
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
                       expires_at, source, feed, sha256, signature_algorithm,
                       key_id, signature, status, documents_imported,
                       package_records_imported, imported_at
                FROM advisory_feed_snapshots WHERE feed_id = %s
                ORDER BY sequence DESC LIMIT 1
                """,
                (feed_id,),
            )
        else:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed, sha256, signature_algorithm,
                       key_id, signature, status, documents_imported,
                       package_records_imported, imported_at
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
                       expires_at, source, feed, sha256, signature_algorithm,
                       key_id, signature, status, documents_imported,
                       package_records_imported, imported_at
                FROM advisory_feed_snapshots WHERE feed_id = %s
                ORDER BY sequence DESC LIMIT %s
                """,
                (feed_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, feed_id, sequence, schema_version, generated_at,
                       expires_at, source, feed, sha256, signature_algorithm,
                       key_id, signature, status, documents_imported,
                       package_records_imported, imported_at
                FROM advisory_feed_snapshots
                ORDER BY imported_at DESC LIMIT %s
                """,
                (limit,),
            )
        return [_advisory_feed_snapshot_from_row(row) for row in cur.fetchall()]

    def save_control_evidence(self, evidence: dict[str, Any]) -> str:
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO control_evidence (
                id, artifact_id, control_id, evidence_fields, evidence_type,
                reference, sha256, metadata, submitted_by, submitted_at,
                expires_at, status, reviewer, review_rationale, reviewed_at,
                updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                report, sha256, signature, signature_algorithm, key_id,
                created_by, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                   report_version, report, sha256, signature,
                   signature_algorithm, key_id, created_by, created_at
            FROM assurance_report_snapshots WHERE id = %s
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
                       report_version, report, sha256, signature,
                       signature_algorithm, key_id, created_by, created_at
                FROM assurance_report_snapshots WHERE artifact_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (artifact_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, artifact_id, scope_type, snapshot_version,
                       report_version, report, sha256, signature,
                       signature_algorithm, key_id, created_by, created_at
                FROM assurance_report_snapshots
                ORDER BY created_at DESC LIMIT %s
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
            SELECT id, artifact_id, control_id, evidence_fields, evidence_type,
                   reference, sha256, metadata, submitted_by, submitted_at,
                   expires_at, status, reviewer, review_rationale, reviewed_at,
                   updated_at
            FROM control_evidence WHERE id = %s
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
                conditions.append(f"{column} = %s")
                params.append(value)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, control_id, evidence_fields, evidence_type,
                   reference, sha256, metadata, submitted_by, submitted_at,
                   expires_at, status, reviewer, review_rationale, reviewed_at,
                   updated_at
            FROM control_evidence
            """ + where + " ORDER BY submitted_at DESC LIMIT %s",
            tuple(params),
        )
        return [_control_evidence_from_row(row) for row in cur.fetchall()]

    def review_control_evidence(
        self, evidence_id: str, review: dict[str, Any]
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            UPDATE control_evidence SET status = %s, reviewer = %s,
                review_rationale = %s, reviewed_at = %s, updated_at = %s
            WHERE id = %s AND status = 'PENDING'
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
                id, artifact_id, artifact, policy_profile, effective_policy,
                status, external_calls_used, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            SELECT id, artifact_id, artifact, policy_profile, effective_policy,
                   status, external_calls_used, created_at, updated_at
            FROM agent_sessions WHERE id = %s
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
            conditions.append("artifact_id = %s")
            params.append(artifact_id)
        if status:
            conditions.append("status = %s")
            params.append(status)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, artifact_id, artifact, policy_profile, effective_policy,
                   status, external_calls_used, created_at, updated_at
            FROM agent_sessions
            """ + where + " ORDER BY created_at DESC LIMIT %s",
            tuple(params),
        )
        return [_agent_session_from_row(row) for row in cur.fetchall()]

    def update_agent_session_status(
        self, session_id: str, status: str, updated_at: str
    ) -> dict[str, Any] | None:
        cur = self._conn.cursor()
        cur.execute(
            "UPDATE agent_sessions SET status = %s, updated_at = %s WHERE id = %s",
            (status, updated_at, session_id),
        )
        self._conn.commit()
        return self.get_agent_session(session_id)

    def record_tool_invocation(
        self, invocation: dict[str, Any], max_external_calls: int | None
    ) -> dict[str, Any]:
        cur = self._conn.cursor()
        try:
            cur.execute(
                """
                SELECT id, artifact_id, artifact, policy_profile,
                       effective_policy, status, external_calls_used,
                       created_at, updated_at
                FROM agent_sessions WHERE id = %s FOR UPDATE
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
                       action, permissions, input_source, input_validation,
                       target, approval_id, approved_by, decision, reasons,
                       external_call, created_at
                FROM tool_invocation_decisions
                WHERE session_id = %s AND request_id = %s
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
                if max_external_calls is not None and session[
                    "external_calls_used"
                ] >= max(0, int(max_external_calls)):
                    decision = "DENY"
                    reasons.append(
                        {
                            "code": "external_call_limit_exceeded",
                            "detail": f"External call limit of {max_external_calls} has been reached.",
                        }
                    )
                else:
                    cur.execute(
                        """
                        UPDATE agent_sessions SET
                            external_calls_used = external_calls_used + 1,
                            updated_at = %s WHERE id = %s
                        """,
                        (invocation["created_at"], invocation["session_id"]),
                    )
            invocation = {**invocation, "decision": decision, "reasons": reasons}
            cur.execute(
                """
                INSERT INTO tool_invocation_decisions (
                    id, session_id, request_id, workflow_step_id, tool, action,
                    permissions, input_source, input_validation, target,
                    approval_id, approved_by, decision, reasons, external_call,
                    created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    bool(invocation.get("external_call")),
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
            conditions.append("d.session_id = %s")
            params.append(session_id)
        if decision:
            conditions.append("d.decision = %s")
            params.append(decision)
        if artifact_id:
            conditions.append("s.artifact_id = %s")
            params.append(artifact_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT d.id, d.session_id, d.request_id, d.workflow_step_id,
                   d.tool, d.action, d.permissions, d.input_source,
                   d.input_validation, d.target, d.approval_id, d.approved_by,
                   d.decision, d.reasons, d.external_call, d.created_at,
                   s.artifact_id
            FROM tool_invocation_decisions d
            JOIN agent_sessions s ON s.id = d.session_id
            """ + where + " ORDER BY d.created_at DESC LIMIT %s",
            tuple(params),
        )
        return [_tool_invocation_from_row(row) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def _json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def _isoformat(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _monitoring_schedule_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "artifact_id": row[1],
        "artifact": _json_value(row[2], {}),
        "interval_seconds": row[3],
        "enabled": bool(row[4]),
        "next_run_at": _isoformat(row[5]),
        "last_run_at": _isoformat(row[6]),
        "created_at": _isoformat(row[7]),
        "updated_at": _isoformat(row[8]),
    }


def _monitoring_run_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "schedule_id": str(row[1]),
        "artifact_id": row[2],
        "status": row[3],
        "started_at": _isoformat(row[4]),
        "completed_at": _isoformat(row[5]),
        "result": _json_value(row[6], {}),
        "error": row[7],
    }


def _risk_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "fingerprint": row[1],
        "artifact_id": row[2],
        "finding_type": row[3],
        "indicator": row[4],
        "title": row[5],
        "severity": row[6],
        "status": row[7],
        "details": _json_value(row[8], {}),
        "first_seen_at": _isoformat(row[9]),
        "last_seen_at": _isoformat(row[10]),
        "occurrence_count": row[11],
        "owner": row[12],
        "due_at": _isoformat(row[13]),
        "resolution": row[14],
        "updated_at": _isoformat(row[15]),
    }


def _advisory_from_row(row) -> dict[str, Any]:
    return {
        "record_key": row[0],
        "advisory_id": row[1],
        "ecosystem": row[2],
        "package_name": row[3],
        "summary": row[4],
        "severity": row[5],
        "aliases": _json_value(row[6], []),
        "affected_versions": _json_value(row[7], []),
        "affected_ranges": _json_value(row[8], []),
        "references": _json_value(row[9], []),
        "published_at": _isoformat(row[10]),
        "modified_at": _isoformat(row[11]),
        "withdrawn_at": _isoformat(row[12]),
        "source": row[13],
        "metadata": _json_value(row[14], {}),
        "updated_at": _isoformat(row[15]),
    }


def _advisory_feed_snapshot_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "feed_id": row[1],
        "sequence": row[2],
        "schema_version": row[3],
        "generated_at": _isoformat(row[4]),
        "expires_at": _isoformat(row[5]),
        "source": row[6],
        "feed": _json_value(row[7], {}),
        "sha256": row[8],
        "signature_algorithm": row[9],
        "key_id": row[10],
        "signature": row[11],
        "status": row[12],
        "documents_imported": row[13],
        "package_records_imported": row[14],
        "imported_at": _isoformat(row[15]),
    }


def _control_evidence_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "artifact_id": row[1],
        "control_id": row[2],
        "evidence_fields": _json_value(row[3], []),
        "evidence_type": row[4],
        "reference": row[5],
        "sha256": row[6],
        "metadata": _json_value(row[7], {}),
        "submitted_by": row[8],
        "submitted_at": _isoformat(row[9]),
        "expires_at": _isoformat(row[10]),
        "status": row[11],
        "reviewer": row[12],
        "review_rationale": row[13],
        "reviewed_at": _isoformat(row[14]),
        "updated_at": _isoformat(row[15]),
    }


def _assurance_report_snapshot_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "artifact_id": row[1],
        "scope_type": row[2],
        "snapshot_version": row[3],
        "report_version": row[4],
        "report": _json_value(row[5], {}),
        "sha256": row[6],
        "signature": row[7],
        "signature_algorithm": row[8],
        "key_id": row[9],
        "created_by": row[10],
        "created_at": _isoformat(row[11]),
    }


def _agent_session_from_row(row) -> dict[str, Any]:
    return {
        "id": str(row[0]),
        "artifact_id": row[1],
        "artifact": _json_value(row[2], {}),
        "policy_profile": row[3],
        "effective_policy": _json_value(row[4], {}),
        "status": row[5],
        "external_calls_used": row[6],
        "created_at": _isoformat(row[7]),
        "updated_at": _isoformat(row[8]),
    }


def _tool_invocation_from_row(row) -> dict[str, Any]:
    artifact_id = str(row[16]) if len(row) > 16 and row[16] is not None else None
    return {
        "id": str(row[0]),
        "session_id": str(row[1]),
        "request_id": row[2],
        "workflow_step_id": row[3],
        "tool": row[4],
        "action": row[5],
        "permissions": _json_value(row[6], []),
        "input_source": row[7],
        "input_validation": row[8],
        "target": row[9],
        "approval_id": row[10],
        "approved_by": row[11],
        "decision": row[12],
        "reasons": _json_value(row[13], []),
        "external_call": bool(row[14]),
        "created_at": _isoformat(row[15]),
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

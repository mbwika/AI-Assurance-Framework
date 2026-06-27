import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def ensure_src_on_path():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 1

    def execute(self, query, params=None):
        self.connection.executions.append((query, params))

    def fetchone(self):
        return self.connection.fetchone_result

    def fetchall(self):
        return self.connection.fetchall_result


class FakeConnection:
    def __init__(self):
        self.executions = []
        self.fetchone_result = None
        self.fetchall_result = []
        self.commits = 0
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def make_store():
    ensure_src_on_path()
    from aiaf.data.postgres_store import PostgresStore

    store = PostgresStore.__new__(PostgresStore)
    store.dsn = "postgresql://test"
    store._conn = FakeConnection()
    store._tx_depth = 0
    return store


def test_postgres_schema_covers_assurance_evidence():
    store = make_store()

    store._ensure_tables()

    schema_sql = "\n".join(query for query, _ in store._conn.executions)
    assert "CREATE TABLE IF NOT EXISTS findings" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS audit_logs" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS historical_metrics" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS monitoring_schedules" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS monitoring_runs" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS risk_register" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS vulnerability_advisories" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS advisory_feed_snapshots" in schema_sql
    assert "advisory_feed_snapshots_feed_idx" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS control_evidence" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS agent_sessions" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS tool_invocation_decisions" in schema_sql
    assert "CREATE TABLE IF NOT EXISTS assurance_report_snapshots" in schema_sql
    assert "assurance_report_snapshots_artifact_idx" in schema_sql
    assert "historical_metrics_artifact_idx" in schema_sql
    assert "dimensions->>'artifact_id'" in schema_sql
    assert "findings_observed_at_idx" in schema_sql
    assert "risk_register_status_idx" in schema_sql
    assert "vulnerability_advisories_package_idx" in schema_sql
    assert "control_evidence_artifact_idx" in schema_sql
    assert "tool_invocations_session_idx" in schema_sql
    assert store._conn.commits == 1


def test_postgres_store_persists_and_reads_assurance_evidence():
    store = make_store()
    now = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)

    store._conn.fetchone_result = (41,)
    finding_id = store.save_finding(
        {
            "artifact_id": "agent-1",
            "timestamp": "2026-06-18T12:00:00Z",
            "findings": [{"type": "agent_risk", "severity": "HIGH"}],
            "score": 0.8,
        }
    )
    assert finding_id == 41
    _, finding_params = store._conn.executions[-1]
    assert json.loads(finding_params[2])[0]["type"] == "agent_risk"

    store._conn.fetchall_result = [
        (41, "agent-1", now, '[{"type": "agent_risk"}]', 0.8)
    ]
    findings = store.list_findings(limit=5)
    assert findings[0]["timestamp"] == "2026-06-18T12:00:00Z"
    assert findings[0]["findings"][0]["type"] == "agent_risk"

    store._conn.fetchone_result = (42,)
    audit_id = store.save_audit_log(
        {
            "event_type": "governance_evaluation",
            "artifact_id": "agent-1",
            "details": {"status": "NEEDS_REVIEW"},
        }
    )
    assert audit_id == 42

    store._conn.fetchall_result = [
        (42, "governance_evaluation", "agent-1", {"status": "NEEDS_REVIEW"}, now)
    ]
    audit_logs = store.list_audit_logs()
    assert audit_logs[0]["details"]["status"] == "NEEDS_REVIEW"

    store._conn.fetchone_result = (43,)
    metric_id = store.save_metric(
        "trustworthiness_score", 0.72, {"artifact_id": "agent-1"}
    )
    assert metric_id == 43

    store._conn.fetchall_result = [
        (
            43,
            "agent-1",
            "trustworthiness_score",
            0.72,
            '{"artifact_id": "agent-1"}',
            now,
        )
    ]
    metrics = store.list_metrics()
    assert metrics[0]["metric_value"] == 0.72
    assert metrics[0]["dimensions"]["artifact_id"] == "agent-1"


def test_postgres_model_registration_is_an_upsert_and_preserves_lineage():
    store = make_store()
    model_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    record = {
        "model_id": model_id,
        "model_name": "assurance-model",
        "version": "1.0",
        "sha256": "a" * 64,
        "registered_by": "security@example.test",
        "dependencies": ["transformers==4.40.0"],
        "training_artifacts": [{"name": "training-corpus"}],
        "deployment_pipeline": {"approval_gate": "CAB-10"},
    }

    assert store.save_model(record) == model_id
    query, params = store._conn.executions[-1]
    assert "ON CONFLICT (id) DO UPDATE" in query
    assert params[8] == "security@example.test"
    metadata = json.loads(params[-1])
    assert metadata["training_artifacts"][0]["name"] == "training-corpus"
    assert metadata["deployment_pipeline"]["approval_gate"] == "CAB-10"


def test_postgres_store_supports_risk_register_lifecycle():
    store = make_store()
    risk_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    now = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)
    row = (
        risk_id,
        "fingerprint",
        "agent-1",
        "agent_risk",
        "unsafe_tool",
        "Unsafe Tool",
        "HIGH",
        "OPEN",
        {"risk_score": 4.0},
        now,
        now,
        1,
        None,
        None,
        None,
        now,
    )
    store._conn.fetchone_result = row

    risk = store.upsert_risk_observation(
        {
            "id": risk_id,
            "fingerprint": "fingerprint",
            "artifact_id": "agent-1",
            "finding_type": "agent_risk",
            "indicator": "unsafe_tool",
            "title": "Unsafe Tool",
            "severity": "HIGH",
            "status": "OPEN",
            "details": {"risk_score": 4.0},
            "first_seen_at": "2026-06-18T12:00:00Z",
            "last_seen_at": "2026-06-18T12:00:00Z",
            "occurrence_count": 1,
            "updated_at": "2026-06-18T12:00:00Z",
        }
    )
    assert risk["id"] == risk_id
    assert "ON CONFLICT (fingerprint) DO UPDATE" in store._conn.executions[-1][0]

    store._conn.fetchall_result = [row]
    assert store.list_risks(status="OPEN")[0]["indicator"] == "unsafe_tool"


def test_postgres_store_persists_vulnerability_advisories():
    store = make_store()
    now = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)
    advisory = {
        "record_key": "record-key",
        "advisory_id": "OSV-TEST-001",
        "ecosystem": "PyPI",
        "package_name": "requests",
        "summary": "Test advisory",
        "severity": "HIGH",
        "aliases": ["CVE-2026-0001"],
        "affected_versions": [],
        "affected_ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.32.0"}],
            }
        ],
        "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
        "source": "test",
        "metadata": {},
        "updated_at": "2026-06-18T12:00:00Z",
    }

    assert store.save_advisory(advisory) == "record-key"
    assert "ON CONFLICT (record_key) DO UPDATE" in store._conn.executions[-1][0]

    store._conn.fetchall_result = [
        (
            "record-key",
            "OSV-TEST-001",
            "PyPI",
            "requests",
            "Test advisory",
            "HIGH",
            ["CVE-2026-0001"],
            [],
            advisory["affected_ranges"],
            advisory["references"],
            now,
            now,
            None,
            "test",
            {},
            now,
        )
    ]
    listed = store.list_advisories(ecosystem="PyPI", package_name="requests")
    assert listed[0]["advisory_id"] == "OSV-TEST-001"
    assert listed[0]["affected_ranges"][0]["events"][1]["fixed"] == "2.32.0"


def test_postgres_store_persists_signed_advisory_feed_snapshots():
    store = make_store()
    snapshot_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    generated = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)
    expires = datetime(2026, 6, 19, 12, 0, tzinfo=timezone.utc)
    imported = datetime(2026, 6, 18, 12, 1, tzinfo=timezone.utc)
    feed = {
        "schema_version": "1.0",
        "feed_id": "organization-osv",
        "sequence": 1,
        "generated_at": "2026-06-18T12:00:00Z",
        "expires_at": "2026-06-19T12:00:00Z",
        "source": "organization-osv-mirror",
        "advisories": [{"id": "OSV-1"}],
        "algorithm": "HMAC-SHA256",
        "key_id": "feed-key-1",
        "signature": "b" * 64,
    }
    snapshot = {
        "id": snapshot_id,
        "feed_id": "organization-osv",
        "sequence": 1,
        "schema_version": "1.0",
        "generated_at": "2026-06-18T12:00:00Z",
        "expires_at": "2026-06-19T12:00:00Z",
        "source": "organization-osv-mirror",
        "feed": feed,
        "sha256": "a" * 64,
        "signature_algorithm": "HMAC-SHA256",
        "key_id": "feed-key-1",
        "signature": "b" * 64,
        "status": "VERIFIED",
        "documents_imported": 1,
        "package_records_imported": 1,
        "imported_at": "2026-06-18T12:01:00Z",
    }

    assert store.save_advisory_feed_snapshot(snapshot) == snapshot_id
    assert "INSERT INTO advisory_feed_snapshots" in store._conn.executions[-1][0]

    row = (
        snapshot_id,
        "organization-osv",
        1,
        "1.0",
        generated,
        expires,
        "organization-osv-mirror",
        feed,
        "a" * 64,
        "HMAC-SHA256",
        "feed-key-1",
        "b" * 64,
        "VERIFIED",
        1,
        1,
        imported,
    )
    store._conn.fetchone_result = row
    assert store.get_latest_advisory_feed_snapshot("organization-osv")[
        "sequence"
    ] == 1
    store._conn.fetchall_result = [row]
    listed = store.list_advisory_feed_snapshots(feed_id="organization-osv")
    assert listed[0]["feed"]["advisories"][0]["id"] == "OSV-1"
    assert listed[0]["expires_at"] == "2026-06-19T12:00:00Z"


def test_postgres_store_persists_reviewed_control_evidence():
    store = make_store()
    evidence_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    now = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)
    evidence = {
        "id": evidence_id,
        "artifact_id": "model-1",
        "control_id": "AIAF-SC-002",
        "evidence_fields": ["sha256"],
        "evidence_type": "ATTESTATION",
        "reference": "s3://evidence/checksum.json",
        "sha256": "a" * 64,
        "metadata": {"collector": "ci"},
        "submitted_by": "collector",
        "submitted_at": "2026-06-18T12:00:00Z",
        "expires_at": "2027-06-18T12:00:00Z",
        "status": "PENDING",
        "updated_at": "2026-06-18T12:00:00Z",
    }
    assert store.save_control_evidence(evidence) == evidence_id
    assert "INSERT INTO control_evidence" in store._conn.executions[-1][0]

    row = (
        evidence_id,
        "model-1",
        "AIAF-SC-002",
        ["sha256"],
        "ATTESTATION",
        "s3://evidence/checksum.json",
        "a" * 64,
        {"collector": "ci"},
        "collector",
        now,
        datetime(2027, 6, 18, 12, 0, tzinfo=timezone.utc),
        "PENDING",
        None,
        None,
        None,
        now,
    )
    store._conn.fetchall_result = [row]
    listed = store.list_control_evidence(
        artifact_id="model-1", control_id="AIAF-SC-002", status="PENDING"
    )
    assert listed[0]["evidence_fields"] == ["sha256"]
    assert listed[0]["metadata"]["collector"] == "ci"


def test_postgres_store_persists_assurance_report_snapshots():
    store = make_store()
    snapshot_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    now = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)
    snapshot = {
        "id": snapshot_id,
        "artifact_id": "model-1",
        "scope_type": "ARTIFACT",
        "snapshot_version": "1.0",
        "report_version": "1.0",
        "report": {
            "schema_version": "1.0",
            "scope": {"type": "ARTIFACT", "artifact_id": "model-1"},
        },
        "sha256": "a" * 64,
        "signature": "b" * 64,
        "signature_algorithm": "HMAC-SHA256",
        "key_id": "report-key-1",
        "created_by": "governance",
        "created_at": "2026-06-18T12:00:00Z",
    }

    assert store.save_assurance_report_snapshot(snapshot) == snapshot_id
    assert "INSERT INTO assurance_report_snapshots" in store._conn.executions[-1][0]

    row = (
        snapshot_id,
        "model-1",
        "ARTIFACT",
        "1.0",
        "1.0",
        snapshot["report"],
        "a" * 64,
        "b" * 64,
        "HMAC-SHA256",
        "report-key-1",
        "governance",
        now,
    )
    store._conn.fetchone_result = row
    assert store.get_assurance_report_snapshot(snapshot_id)["report"] == snapshot[
        "report"
    ]
    store._conn.fetchall_result = [row]
    listed = store.list_assurance_report_snapshots(artifact_id="model-1")
    assert listed[0]["key_id"] == "report-key-1"
    assert listed[0]["created_at"] == "2026-06-18T12:00:00Z"


def test_postgres_store_supports_monitoring_schedules_and_runs():
    store = make_store()
    schedule_id = "742f9db8-85b9-46a5-a233-3c8ebd42e8c5"
    run_id = "d24f575d-cfd1-4f8f-a1ad-6315e9c07c91"
    schedule = {
        "id": schedule_id,
        "artifact_id": "agent-1",
        "artifact": {"id": "agent-1"},
        "interval_seconds": 60,
        "enabled": True,
        "next_run_at": "2026-06-18T12:00:00Z",
        "last_run_at": None,
        "created_at": "2026-06-18T11:00:00Z",
        "updated_at": "2026-06-18T11:00:00Z",
    }

    assert store.save_monitoring_schedule(schedule) == schedule_id
    assert "ON CONFLICT (id) DO UPDATE" in store._conn.executions[-1][0]

    store._conn.fetchall_result = [
        (
            schedule_id,
            "agent-1",
            {"id": "agent-1"},
            60,
            True,
            "2026-06-18T12:00:00Z",
            None,
            "2026-06-18T11:00:00Z",
            "2026-06-18T11:00:00Z",
        )
    ]
    assert store.list_due_monitoring_schedules("2026-06-18T12:00:00Z")[0]["id"] == schedule_id

    run = {
        "id": run_id,
        "schedule_id": schedule_id,
        "artifact_id": "agent-1",
        "status": "COMPLETED",
        "started_at": "2026-06-18T12:00:00Z",
        "completed_at": "2026-06-18T12:00:01Z",
        "result": {"risk": {"score": 0.4}},
        "error": None,
    }
    assert store.save_monitoring_run(run) == run_id

    store._conn.fetchall_result = [
        (
            run_id,
            schedule_id,
            "agent-1",
            "COMPLETED",
            "2026-06-18T12:00:00Z",
            "2026-06-18T12:00:01Z",
            {"risk": {"score": 0.4}},
            None,
        )
    ]
    assert store.list_monitoring_runs(schedule_id=schedule_id)[0]["status"] == "COMPLETED"

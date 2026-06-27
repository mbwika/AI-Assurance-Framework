import json
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _advisory(advisory_id="OSV-FEED-001", summary="Feed vulnerability"):
    return {
        "id": advisory_id,
        "summary": summary,
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "2.0.0"},
                            {"fixed": "2.32.0"},
                        ],
                    }
                ],
            }
        ],
    }


def _feed(sequence=1, advisories=None, key="feed-secret", key_id="feed-key-1"):
    ensure_src()
    from aiaf.registry import create_advisory_feed

    now = datetime.now(timezone.utc)
    return create_advisory_feed(
        feed_id="organization-osv",
        sequence=sequence,
        generated_at=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        advisories=advisories or [_advisory()],
        source="organization-osv-mirror",
        signing_key=key,
        key_id=key_id,
    )


def test_advisory_feed_signature_binds_content_identity_and_freshness():
    ensure_src()
    from aiaf.registry import verify_advisory_feed

    feed = _feed()
    valid = verify_advisory_feed(
        feed, "feed-secret", expected_key_id="feed-key-1"
    )
    tampered = deepcopy(feed)
    tampered["advisories"][0]["summary"] = "Rewritten vulnerability"
    tampered_result = verify_advisory_feed(
        tampered, "feed-secret", expected_key_id="feed-key-1"
    )
    after_expiration = (
        datetime.fromisoformat(feed["expires_at"].replace("Z", "+00:00"))
        + timedelta(seconds=1)
    ).isoformat()
    stale = verify_advisory_feed(
        feed,
        "feed-secret",
        expected_key_id="feed-key-1",
        as_of=after_expiration,
    )

    assert valid["verified"] is True
    assert len(valid["feed_sha256"]) == 64
    assert tampered_result["verified"] is False
    assert tampered_result["checks"]["signature_valid"] is False
    assert stale["verified"] is False
    assert stale["checks"]["feed_not_expired"] is False
    assert stale["checks"]["signature_valid"] is True


def test_signed_feed_import_enforces_replay_sequence_and_scan_provenance(tmp_path):
    ensure_src()
    from aiaf.core import ReportingEngine, VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "signed-feeds.db"))
    engine = VulnerabilityIntelligenceEngine(store)
    feed_one = _feed(sequence=1)
    imported = engine.import_signed_feed(
        feed_one,
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )
    replay = engine.import_signed_feed(
        feed_one,
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )
    scan = engine.scan(["requests==2.31.0"])

    assert imported["verified"] is True
    assert imported["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True
    assert len(engine.list_feed_snapshots(feed_id="organization-osv")) == 1
    assert scan["match_count"] == 1
    assert scan["advisory_intelligence"]["status"] == "AUTHENTICATED"
    with pytest.raises(ValueError, match="Unverified advisory imports"):
        engine.import_advisories(
            [_advisory("OSV-MANUAL-POST-SIGN")], rescan_models=False
        )

    collision = _feed(
        sequence=1,
        advisories=[_advisory("OSV-FEED-002", "Different signed content")],
    )
    with pytest.raises(ValueError, match="sequence collision"):
        engine.import_signed_feed(
            collision,
            signing_key="feed-secret",
            expected_key_id="feed-key-1",
            rescan_models=False,
        )

    feed_two = _feed(sequence=2)
    engine.import_signed_feed(
        feed_two,
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )
    with pytest.raises(ValueError, match="sequence rollback"):
        engine.import_signed_feed(
            feed_one,
            signing_key="feed-secret",
            expected_key_id="feed-key-1",
            rescan_models=False,
        )
    assert engine.feed_status()["verified_feed_count"] == 1
    assert engine.feed_status(as_of="2100-01-01T00:00:00Z")["status"] == "STALE"
    report = ReportingEngine(store).assurance_report()
    alert_ids = {alert["id"] for alert in report["monitoring_alerts"]["alerts"]}
    assert report["supply_chain"]["advisory_feed_status"] == "AUTHENTICATED"
    assert report["supply_chain"]["verified_advisory_feeds"] == 1
    assert report["supply_chain"]["advisory_feed_snapshots"] == 2
    assert "vulnerability_advisory_feed_unverified" not in alert_ids
    store.close()


def test_signed_feed_reports_mixed_catalog_provenance(tmp_path):
    ensure_src()
    from aiaf.core import ReportingEngine, VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "mixed-feed.db"))
    engine = VulnerabilityIntelligenceEngine(store)
    engine.import_advisories(
        [_advisory("OSV-UNVERIFIED")],
        source="manual-upload",
        rescan_models=False,
    )
    engine.import_signed_feed(
        _feed(sequence=1, advisories=[_advisory("OSV-VERIFIED")]),
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )

    status = engine.feed_status()
    report = ReportingEngine(store).assurance_report()
    alert_ids = {alert["id"] for alert in report["monitoring_alerts"]["alerts"]}

    assert status["status"] == "MIXED"
    assert status["authenticated_advisory_records"] == 1
    assert status["unverified_advisory_records"] == 1
    assert report["supply_chain"]["advisory_feed_status"] == "MIXED"
    assert "vulnerability_advisory_catalog_mixed_trust" in alert_ids
    store.close()


def test_signed_advisory_feed_api_contract(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import supply_chain as supply_api
    from aiaf.api.app import app
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "feed-api.db"))
    monkeypatch.setattr(supply_api, "get_store", lambda: store)
    monkeypatch.setenv("AIAF_ADVISORY_FEED_KEY", "feed-secret")
    monkeypatch.setenv("AIAF_ADVISORY_FEED_KEY_ID", "feed-key-1")
    imported = supply_api.import_signed_advisory_feed(
        supply_api.SignedAdvisoryFeedImport(
            feed=_feed(), rescan_models=False
        ),
        api_key="dev-key",
    )
    listed = supply_api.list_advisory_feed_snapshots(api_key="dev-key")
    status = supply_api.advisory_feed_status(api_key="dev-key")
    fetched = supply_api.get_advisory_feed_snapshot(
        imported["feed_snapshot_id"], api_key="dev-key"
    )
    verified = supply_api.verify_advisory_feed_snapshot(
        imported["feed_snapshot_id"], api_key="dev-key"
    )
    routes = set(app.openapi()["paths"])

    assert listed["count"] == 1
    assert "feed" not in listed["feed_snapshots"][0]
    assert status["status"] == "AUTHENTICATED"
    assert fetched["feed_id"] == "organization-osv"
    assert verified["verified"] is True
    assert "/v1/supply-chain/advisories/feeds/import" in routes
    assert "/v1/supply-chain/advisories/feeds" in routes
    assert "/v1/supply-chain/advisories/feeds/status" in routes
    assert "/v1/supply-chain/advisories/feeds/{snapshot_id}" in routes
    assert "/v1/supply-chain/advisories/feeds/{snapshot_id}/verify" in routes
    store.close()


def test_feed_snapshot_verification_detects_metadata_tampering(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "feed-tamper.db"))
    engine = VulnerabilityIntelligenceEngine(store)
    imported = engine.import_signed_feed(
        _feed(),
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )
    store._conn.execute(
        "UPDATE advisory_feed_snapshots SET sequence = 999 WHERE id = ?",
        (imported["feed_snapshot_id"],),
    )
    store._conn.commit()

    verification = engine.verify_feed_snapshot(
        imported["feed_snapshot_id"],
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
    )

    assert verification["verified"] is False
    assert verification["checks"]["signature_valid"] is True
    assert verification["checks"]["snapshot_sequence_matches"] is False
    store.close()


def test_feed_snapshot_verification_handles_malformed_stored_feed(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "malformed-feed.db"))
    engine = VulnerabilityIntelligenceEngine(store)
    imported = engine.import_signed_feed(
        _feed(),
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
        rescan_models=False,
    )
    stored = engine.get_feed_snapshot(imported["feed_snapshot_id"])["feed"]
    stored["generated_at"] = "not-a-timestamp"
    store._conn.execute(
        "UPDATE advisory_feed_snapshots SET feed_json = ? WHERE id = ?",
        (json.dumps(stored), imported["feed_snapshot_id"]),
    )
    store._conn.commit()

    verification = engine.verify_feed_snapshot(
        imported["feed_snapshot_id"],
        signing_key="feed-secret",
        expected_key_id="feed-key-1",
    )

    assert verification["verified"] is False
    assert verification["checks"]["generated_at_valid"] is False
    assert verification["checks"]["snapshot_generated_at_matches"] is False
    store.close()

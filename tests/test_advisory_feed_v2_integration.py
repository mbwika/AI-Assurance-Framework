"""Integration tests for schema-2 signed advisory feed import.

These cover the architect-owned dual-read orchestration: schema-2 feeds are
verified against the engine's persisted hash-chain state (expected sequence and
previous-feed digest derived from the stored head, not the feed's own claims),
with current-time freshness. The pure envelope verification is unit-tested in
test_advisory_feed_v2.py; the legacy schema-1 path is unchanged.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


# Schema-2 feeds require a >=32-byte signing key with sufficient entropy.
_FEED_KEY = "advisory-feed-signing-key-0123456789abcdef"
_KEY_ID = "feed-key-v2"
_FEED_ID = "org-osv"
_SOURCE = "org-osv-mirror"


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _advisory(identifier="OSV-2026-1", package="requests"):
    return {
        "id": identifier,
        "summary": "Test vulnerability",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}
                ],
            }
        ],
    }


def _v2_feed(sequence, previous, advisories):
    from aiaf.registry import create_advisory_feed_v2

    now = datetime.now(timezone.utc)
    return create_advisory_feed_v2(
        feed_id=_FEED_ID,
        sequence=sequence,
        previous_feed_sha256=previous,
        generated_at=_iso(now),
        expires_at=_iso(now + timedelta(hours=12)),
        advisories=advisories,
        signing_key=_FEED_KEY,
        key_id=_KEY_ID,
        source=_SOURCE,
        as_of=_iso(now),
    )


def _import(engine, feed):
    return engine.import_signed_feed(
        feed, signing_key=_FEED_KEY, expected_key_id=_KEY_ID, rescan_models=False
    )


def test_v2_feed_chain_advance_replay_and_rollback(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2feed.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    genesis = _v2_feed(1, None, [_advisory("OSV-1")])
    imported = _import(engine, genesis)
    assert imported["verified"] is True
    assert imported["idempotent_replay"] is False
    genesis_digest = imported["feed_sha256"]

    # Byte-identical re-import is an idempotent replay (digest + signature bound).
    replay = _import(engine, genesis)
    assert replay["idempotent_replay"] is True
    assert len(engine.list_feed_snapshots(feed_id=_FEED_ID)) == 1

    # A successor must cryptographically chain to the stored head digest.
    successor = _v2_feed(2, genesis_digest, [_advisory("OSV-2")])
    advanced = _import(engine, successor)
    assert advanced["verified"] is True
    assert advanced["sequence"] == 2
    assert len(engine.list_feed_snapshots(feed_id=_FEED_ID)) == 2

    # A validly-signed fork that does not chain to the head is rejected.
    fork = _v2_feed(3, "f" * 64, [_advisory("OSV-3")])
    with pytest.raises(ValueError, match="verification failed"):
        _import(engine, fork)

    # A lower sequence than the head is a rollback.
    with pytest.raises(ValueError, match="sequence rollback"):
        _import(engine, genesis)

    # Same head sequence with different signed content is a collision.
    collision = _v2_feed(2, genesis_digest, [_advisory("OSV-DIFFERENT")])
    with pytest.raises(ValueError, match="sequence collision"):
        _import(engine, collision)


def test_v2_sequence_gap_is_rejected(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2gap.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    genesis_digest = _import(engine, _v2_feed(1, None, [_advisory("OSV-1")]))["feed_sha256"]
    # Head is at sequence 1; a feed at sequence 3 skips sequence 2 -> gap.
    gapped = _v2_feed(3, genesis_digest, [_advisory("OSV-3")])
    with pytest.raises(ValueError, match="sequence gap"):
        _import(engine, gapped)
    assert len(engine.list_feed_snapshots(feed_id=_FEED_ID)) == 1


def test_v2_replay_under_wrong_key_policy_is_rejected(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2replaypolicy.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    genesis = _v2_feed(1, None, [_advisory("OSV-1")])
    _import(engine, genesis)

    # A byte-identical, validly-signed replay must NOT be accepted under a
    # different (e.g. rotated) expected key-id policy.
    with pytest.raises(ValueError, match="replay rejected by current trust policy"):
        engine.import_signed_feed(
            genesis,
            signing_key=_FEED_KEY,
            expected_key_id="rotated-key-v3",
            rescan_models=False,
        )


def test_v2_failed_sequence_claim_does_not_write_advisories(tmp_path, monkeypatch):
    ensure_src()
    import sqlite3

    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2atomic.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    genesis_digest = _import(engine, _v2_feed(1, None, [_advisory("OSV-1")]))["feed_sha256"]
    before = len(store.list_advisories(limit=100000))

    # Simulate a concurrent winner having already claimed sequence 2: the unique
    # (feed_id, sequence) constraint fails when this importer tries to claim it.
    def _conflict(_snapshot):
        raise sqlite3.IntegrityError("UNIQUE constraint failed: advisory_feed_snapshots.feed_id, sequence")

    monkeypatch.setattr(store, "save_advisory_feed_snapshot", _conflict)

    successor = _v2_feed(2, genesis_digest, [_advisory("OSV-2", "flask")])
    with pytest.raises(ValueError, match="sequence collision"):
        engine.import_signed_feed(
            successor, signing_key=_FEED_KEY, expected_key_id=_KEY_ID, rescan_models=False
        )
    # The losing importer must not have polluted the advisory catalog.
    assert len(store.list_advisories(limit=100000)) == before


def test_v2_advisory_write_failure_rolls_back_snapshot_claim(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2tx.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    genesis_digest = _import(engine, _v2_feed(1, None, [_advisory("OSV-1")]))["feed_sha256"]
    successor = _v2_feed(2, genesis_digest, [_advisory("OSV-2", "flask")])

    # Advisory persistence fails AFTER the sequence is claimed.
    original_save_advisory = store.save_advisory

    def _failing(_advisory_record):
        raise RuntimeError("advisory persistence failed")

    monkeypatch.setattr(store, "save_advisory", _failing)
    with pytest.raises(RuntimeError, match="advisory persistence failed"):
        engine.import_signed_feed(
            successor, signing_key=_FEED_KEY, expected_key_id=_KEY_ID, rescan_models=False
        )

    # The whole unit rolled back: the sequence-2 snapshot was NOT persisted, so
    # the head is still genesis and the catalog has no successor advisory.
    assert len(engine.list_feed_snapshots(feed_id=_FEED_ID)) == 1
    assert all(a["advisory_id"] != "OSV-2" for a in store.list_advisories(limit=100000))

    # Retry succeeds as a clean re-import (not an idempotent replay over an
    # incomplete catalog).
    monkeypatch.setattr(store, "save_advisory", original_save_advisory)
    retried = engine.import_signed_feed(
        successor, signing_key=_FEED_KEY, expected_key_id=_KEY_ID, rescan_models=False
    )
    assert retried["idempotent_replay"] is False
    assert retried["sequence"] == 2
    assert len(engine.list_feed_snapshots(feed_id=_FEED_ID)) == 2
    assert any(a["advisory_id"] == "OSV-2" for a in store.list_advisories(limit=100000))


def test_v2_snapshot_reverification_derives_predecessor_from_store(tmp_path):
    ensure_src()
    import uuid

    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.core.vulnerability_engine import _normalize_datetime, _utc_now
    from aiaf.data.store import DataStore
    from aiaf.registry import verify_advisory_feed_v2

    store = DataStore(db_path=str(tmp_path / "v2predecessor.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    # Genesis is the real persisted predecessor.
    _import(engine, _v2_feed(1, None, [_advisory("OSV-1")]))

    # Craft a validly-signed successor whose chain link points at a DIFFERENT
    # predecessor than the one actually persisted, then inject it as a snapshot.
    impostor = _v2_feed(2, "a" * 64, [_advisory("OSV-2", "flask")])
    impostor_digest = verify_advisory_feed_v2(
        impostor,
        _FEED_KEY,
        {
            "expected_feed_id": _FEED_ID,
            "expected_source": _SOURCE,
            "expected_key_id": _KEY_ID,
            "expected_sequence": 2,
            "expected_previous_feed_sha256": "a" * 64,
            "as_of": impostor["generated_at"],
        },
    )["feed_sha256"]
    impostor_id = str(uuid.uuid4())
    store.save_advisory_feed_snapshot(
        {
            "id": impostor_id,
            "feed_id": _FEED_ID,
            "sequence": 2,
            "schema_version": impostor["schema_version"],
            "generated_at": _normalize_datetime(impostor["generated_at"]),
            "expires_at": _normalize_datetime(impostor["expires_at"]),
            "source": impostor["source"],
            "feed": impostor,
            "sha256": impostor_digest,
            "signature_algorithm": impostor["algorithm"],
            "key_id": impostor["key_id"],
            "signature": impostor["signature"],
            "status": "VERIFIED",
            "documents_imported": 1,
            "package_records_imported": 1,
            "imported_at": _utc_now(),
        }
    )

    # Re-audit derives the expected predecessor digest from the persisted genesis,
    # so the impostor's self-claimed (wrong) chain link is detected.
    result = engine.verify_feed_snapshot(
        impostor_id, signing_key=_FEED_KEY, expected_key_id=_KEY_ID
    )
    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["previous_digest_matches_policy"] is False
    assert result["verified"] is False


def test_v2_feed_snapshot_reverification_is_dual_read(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "v2feed_snap.db"))
    engine = VulnerabilityIntelligenceEngine(store)

    imported = _import(engine, _v2_feed(1, None, [_advisory("OSV-1")]))
    result = engine.verify_feed_snapshot(
        imported["feed_snapshot_id"], signing_key=_FEED_KEY, expected_key_id=_KEY_ID
    )
    assert result["verified"] is True
    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["snapshot_digest_matches"] is True
    # Wrong key fails cryptographic verification on re-audit.
    wrong_key = engine.verify_feed_snapshot(
        imported["feed_snapshot_id"],
        signing_key="x" * 40,
        expected_key_id=_KEY_ID,
    )
    assert wrong_key["verified"] is False

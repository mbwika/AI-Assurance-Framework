"""Tests for aiaf.core.agent_action_ledger."""

import json
import hashlib
import pytest

from aiaf.core.agent_action_ledger import (
    LEDGER_VERSION,
    _GENESIS_HASH,
    _VALID_DECISIONS,
    LedgerValidationError,
    _compute_entry_hash,
    _entry_payload,
    _ledger_key,
    _sha256,
    _validate_decision,
    _validate_session_id,
    append_entry,
    get_ledger,
    get_ledger_entries,
    list_ledgers,
    verify_chain,
)


# ── Fake store ────────────────────────────────────────────────────────────────

class _FakeStore:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


def _store():
    return _FakeStore()


def _append(store, session_id="s1", tool="bash", decision="ALLOW"):
    input_hash = _sha256(f"args-{tool}")
    return append_entry(session_id, tool, input_hash, decision, store)


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_ledger_key_prefix(self):
        assert _ledger_key("abc") == "ledger:abc"

    def test_sha256_returns_64_hex(self):
        h = _sha256("hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_deterministic(self):
        assert _sha256("x") == _sha256("x")

    def test_genesis_hash_is_64_zeros(self):
        assert _GENESIS_HASH == "0" * 64

    def test_entry_payload_is_deterministic_json(self):
        entry = {
            "session_id": "s1", "entry_id": "e1", "sequence": 0,
            "tool_name": "bash", "input_hash": "abc", "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00Z",
            "prev_entry_sha256": _GENESIS_HASH,
        }
        p1 = _entry_payload(entry)
        p2 = _entry_payload(entry)
        assert p1 == p2
        parsed = json.loads(p1)
        assert parsed["session_id"] == "s1"

    def test_entry_payload_excludes_metadata_and_hash(self):
        entry = {
            "session_id": "s1", "entry_id": "e1", "sequence": 0,
            "tool_name": "bash", "input_hash": "abc", "decision": "ALLOW",
            "timestamp": "T", "prev_entry_sha256": _GENESIS_HASH,
            "metadata": {"extra": "field"},
            "entry_hash": "old-hash",
            "ledger_version": LEDGER_VERSION,
        }
        payload = json.loads(_entry_payload(entry))
        assert "metadata" not in payload
        assert "entry_hash" not in payload
        assert "ledger_version" not in payload

    def test_compute_entry_hash_length(self):
        entry = {
            "session_id": "s1", "entry_id": "e1", "sequence": 0,
            "tool_name": "bash", "input_hash": "abc", "decision": "ALLOW",
            "timestamp": "T", "prev_entry_sha256": _GENESIS_HASH,
        }
        h = _compute_entry_hash(entry)
        assert len(h) == 64


# ── Validation ────────────────────────────────────────────────────────────────

class TestValidation:
    def test_empty_session_id_raises(self):
        with pytest.raises(LedgerValidationError):
            _validate_session_id("")

    def test_whitespace_session_id_raises(self):
        with pytest.raises(LedgerValidationError):
            _validate_session_id("   ")

    def test_valid_session_id_stripped(self):
        assert _validate_session_id("  abc  ") == "abc"

    def test_valid_decisions(self):
        for d in ("ALLOW", "DENY", "FLAG"):
            assert _validate_decision(d) == d

    def test_decision_case_insensitive(self):
        assert _validate_decision("allow") == "ALLOW"
        assert _validate_decision("Deny") == "DENY"

    def test_invalid_decision_raises(self):
        with pytest.raises(LedgerValidationError, match="decision must be one of"):
            _validate_decision("SKIP")


# ── append_entry ──────────────────────────────────────────────────────────────

class TestAppendEntry:
    def test_first_entry_has_genesis_prev_hash(self):
        store = _store()
        entry = _append(store)
        assert entry["prev_entry_sha256"] == _GENESIS_HASH

    def test_first_entry_has_sequence_zero(self):
        store = _store()
        entry = _append(store)
        assert entry["sequence"] == 0

    def test_second_entry_links_to_first(self):
        store = _store()
        e1 = _append(store, tool="bash")
        e2 = _append(store, tool="read_file")
        assert e2["prev_entry_sha256"] == e1["entry_hash"]

    def test_sequence_increments(self):
        store = _store()
        e1 = _append(store)
        e2 = _append(store)
        e3 = _append(store)
        assert e1["sequence"] == 0
        assert e2["sequence"] == 1
        assert e3["sequence"] == 2

    def test_entry_hash_is_computed(self):
        store = _store()
        entry = _append(store)
        assert len(entry["entry_hash"]) == 64

    def test_entry_hash_covers_all_fields(self):
        store = _store()
        entry = _append(store)
        expected = _compute_entry_hash(entry)
        assert entry["entry_hash"] == expected

    def test_tool_name_stored(self):
        store = _store()
        entry = _append(store, tool="my_tool")
        assert entry["tool_name"] == "my_tool"

    def test_decision_stored(self):
        store = _store()
        entry = _append(store, decision="DENY")
        assert entry["decision"] == "DENY"

    def test_flag_decision_stored(self):
        store = _store()
        entry = _append(store, decision="FLAG")
        assert entry["decision"] == "FLAG"

    def test_metadata_passthrough(self):
        store = _store()
        entry = append_entry("s1", "bash", "hash123", "ALLOW", store,
                             metadata={"risk_tier": "HIGH"})
        assert entry["metadata"]["risk_tier"] == "HIGH"

    def test_ledger_key_stored(self):
        store = _store()
        _append(store, session_id="my-session")
        assert store.get_model("ledger:my-session") is not None

    def test_entry_count_in_metadata(self):
        store = _store()
        _append(store)
        _append(store)
        record = store.get_model("ledger:s1")
        assert record["metadata"]["entry_count"] == 2

    def test_invalid_session_id_raises(self):
        with pytest.raises(LedgerValidationError):
            append_entry("", "bash", "hash", "ALLOW", _store())

    def test_invalid_decision_raises(self):
        with pytest.raises(LedgerValidationError):
            append_entry("s1", "bash", "hash", "SKIP", _store())

    def test_custom_timestamp_preserved(self):
        store = _store()
        entry = append_entry("s1", "bash", "hash", "ALLOW", store,
                             timestamp="2026-01-01T12:00:00Z")
        assert entry["timestamp"] == "2026-01-01T12:00:00Z"

    def test_ledger_version_in_entry(self):
        store = _store()
        entry = _append(store)
        assert entry["ledger_version"] == LEDGER_VERSION


# ── verify_chain ──────────────────────────────────────────────────────────────

class TestVerifyChain:
    def test_empty_ledger_is_valid(self):
        store = _store()
        # Create empty ledger record
        store.save_model({
            "model_id": "ledger:s1",
            "metadata": {"entries": [], "session_id": "s1"},
        })
        result = verify_chain("s1", store)
        assert result["chain_valid"] is True
        assert result["entry_count"] == 0

    def test_missing_ledger_returns_invalid(self):
        result = verify_chain("nonexistent", _store())
        assert result["chain_valid"] is False
        assert result["error"] == "ledger_not_found"

    def test_single_entry_valid(self):
        store = _store()
        _append(store)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is True
        assert result["entry_count"] == 1

    def test_multiple_entries_valid(self):
        store = _store()
        for _ in range(5):
            _append(store)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is True
        assert result["entry_count"] == 5

    def test_head_hash_returned(self):
        store = _store()
        last_entry = None
        for _ in range(3):
            last_entry = _append(store)
        result = verify_chain("s1", store)
        assert result["head_hash"] == last_entry["entry_hash"]

    def test_tampered_entry_hash_detected(self):
        store = _store()
        _append(store)
        _append(store)
        # Tamper with the second entry's entry_hash
        record = store.get_model("ledger:s1")
        record["metadata"]["entries"][1]["entry_hash"] = "0" * 64
        store.save_model(record)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is False
        assert result["tampered_at_sequence"] == 1

    def test_tampered_prev_hash_detected(self):
        store = _store()
        _append(store)
        _append(store)
        # Tamper with second entry's prev_entry_sha256
        record = store.get_model("ledger:s1")
        record["metadata"]["entries"][1]["prev_entry_sha256"] = "a" * 64
        store.save_model(record)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is False
        assert result["tampered_at_sequence"] == 1

    def test_tampered_first_entry_detected(self):
        store = _store()
        _append(store)
        # Tamper with first entry's tool_name (changes entry_hash)
        record = store.get_model("ledger:s1")
        record["metadata"]["entries"][0]["tool_name"] = "malicious_tool"
        # Do NOT update entry_hash — it will mismatch
        store.save_model(record)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is False
        assert result["tampered_at_sequence"] == 0

    def test_entry_inserted_mid_chain_detected(self):
        store = _store()
        _append(store, tool="tool_a")
        _append(store, tool="tool_b")
        # Insert a fabricated entry between them
        record = store.get_model("ledger:s1")
        entries = record["metadata"]["entries"]
        e1_hash = entries[0]["entry_hash"]
        fake = {
            "session_id": "s1", "entry_id": "fake-id", "sequence": 99,
            "tool_name": "evil_tool", "input_hash": "aaaa",
            "decision": "ALLOW", "timestamp": "T",
            "prev_entry_sha256": e1_hash, "ledger_version": LEDGER_VERSION,
            "metadata": {}, "entry_hash": "",
        }
        fake["entry_hash"] = _compute_entry_hash(fake)
        record["metadata"]["entries"].insert(1, fake)
        store.save_model(record)
        result = verify_chain("s1", store)
        assert result["chain_valid"] is False


# ── get_ledger ────────────────────────────────────────────────────────────────

class TestGetLedger:
    def test_returns_none_for_missing(self):
        assert get_ledger("x", _store()) is None

    def test_returns_ledger_after_append(self):
        store = _store()
        _append(store)
        ledger = get_ledger("s1", store)
        assert ledger is not None
        assert ledger["session_id"] == "s1"
        assert ledger["entry_count"] == 1
        assert len(ledger["entries"]) == 1

    def test_includes_timestamps(self):
        store = _store()
        _append(store)
        ledger = get_ledger("s1", store)
        assert ledger["registered_at"] is not None
        assert ledger["last_updated_at"] is not None


# ── get_ledger_entries ────────────────────────────────────────────────────────

class TestGetLedgerEntries:
    def test_returns_empty_for_missing(self):
        entries, total = get_ledger_entries("x", _store())
        assert entries == []
        assert total == 0

    def test_pagination(self):
        store = _store()
        for i in range(10):
            _append(store)
        entries, total = get_ledger_entries("s1", store, offset=3, limit=4)
        assert total == 10
        assert len(entries) == 4
        assert entries[0]["sequence"] == 3

    def test_limit_respected(self):
        store = _store()
        for _ in range(20):
            _append(store)
        entries, total = get_ledger_entries("s1", store, offset=0, limit=5)
        assert len(entries) == 5
        assert total == 20


# ── list_ledgers ──────────────────────────────────────────────────────────────

class TestListLedgers:
    def test_empty_store(self):
        assert list_ledgers(_store()) == []

    def test_lists_only_ledger_records(self):
        store = _store()
        _append(store, session_id="s1")
        # Add a non-ledger record
        store.save_model({"model_id": "model:abc", "metadata": {}})
        sessions = list_ledgers(store)
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "s1"

    def test_limit_respected(self):
        store = _store()
        for i in range(10):
            _append(store, session_id=f"s{i}")
        sessions = list_ledgers(store, limit=3)
        assert len(sessions) == 3

    def test_by_decision_counts(self):
        store = _store()
        _append(store, decision="ALLOW")
        _append(store, decision="ALLOW")
        _append(store, decision="DENY")
        sessions = list_ledgers(store)
        by_d = sessions[0]["by_decision"]
        assert by_d["ALLOW"] == 2
        assert by_d["DENY"] == 1

    def test_entry_count_correct(self):
        store = _store()
        for _ in range(4):
            _append(store)
        sessions = list_ledgers(store)
        assert sessions[0]["entry_count"] == 4

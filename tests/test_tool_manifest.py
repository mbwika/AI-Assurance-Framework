"""Tests for aiaf.registry.tool_manifest."""

import hashlib
import json
import pytest

from aiaf.registry.tool_manifest import (
    MANIFEST_VERSION,
    ManifestError,
    _canonical_json,
    _sha256,
    _hmac_sign,
    _hmac_verify,
    create_manifest,
    verify_manifest,
    register_manifest,
    get_manifest,
    list_manifests,
)

_KEY = b"test-signing-key-at-least-32-bytes-!!"
_SHORT_KEY = b"short"
_SCHEMA = {"type": "object", "properties": {"to": {"type": "string"}}}


# ── Fake store ────────────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._data = {}
    def get_model(self, key):
        return self._data.get(key)
    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record
    def list_models(self):
        return list(self._data.values())


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_canonical_json_deterministic(self):
        obj = {"b": 2, "a": 1}
        assert _canonical_json(obj) == _canonical_json(obj)

    def test_canonical_json_sort_keys(self):
        s = _canonical_json({"z": 1, "a": 2})
        assert s.index('"a"') < s.index('"z"')

    def test_sha256_64_hex(self):
        h = _sha256("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hmac_sign_short_key_raises(self):
        with pytest.raises(ManifestError, match="32 bytes"):
            _hmac_sign({"a": 1}, _SHORT_KEY)

    def test_hmac_verify_correct(self):
        stmt = {"tool_name": "test"}
        sig = _hmac_sign(stmt, _KEY)
        assert _hmac_verify(stmt, _KEY, sig) is True

    def test_hmac_verify_wrong_key(self):
        stmt = {"tool_name": "test"}
        sig = _hmac_sign(stmt, _KEY)
        other_key = b"other-key-at-least-32-bytes-long-!!"
        assert _hmac_verify(stmt, other_key, sig) is False

    def test_hmac_verify_tampered_statement(self):
        stmt = {"tool_name": "test"}
        sig = _hmac_sign(stmt, _KEY)
        tampered = {"tool_name": "evil"}
        assert _hmac_verify(tampered, _KEY, sig) is False


# ── create_manifest ───────────────────────────────────────────────────────────

class TestCreateManifest:
    def test_basic_creation(self):
        m = create_manifest("send_email", "1.0", "Send emails", _SCHEMA,
                            ["network_egress"], _KEY)
        assert m["statement"]["tool_name"] == "send_email"
        assert m["statement"]["version"] == "1.0"
        assert "network_egress" in m["statement"]["declared_capabilities"]

    def test_returns_required_fields(self):
        m = create_manifest("t", "1.0", "desc", {}, [], _KEY)
        for field in ("manifest_id", "manifest_version", "algorithm", "statement", "signature"):
            assert field in m, f"Missing: {field}"

    def test_manifest_version_correct(self):
        m = create_manifest("t", "1.0", "desc", {}, [], _KEY)
        assert m["manifest_version"] == MANIFEST_VERSION
        assert m["statement"]["manifest_version"] == MANIFEST_VERSION

    def test_algorithm_hmac_sha256(self):
        m = create_manifest("t", "1.0", "desc", {}, [], _KEY)
        assert m["algorithm"] == "hmac-sha256"

    def test_schema_hash_in_statement(self):
        m = create_manifest("t", "1.0", "desc", _SCHEMA, [], _KEY)
        expected = _sha256(_canonical_json(_SCHEMA))
        assert m["statement"]["schema_hash"] == expected

    def test_capabilities_sorted_and_deduplicated(self):
        m = create_manifest("t", "1.0", "d", {}, ["network_egress", "network_egress", "data_read"], _KEY)
        caps = m["statement"]["declared_capabilities"]
        assert caps == sorted(set(caps))

    def test_manifest_id_is_16_hex(self):
        m = create_manifest("t", "1.0", "d", {}, [], _KEY)
        assert len(m["manifest_id"]) == 16
        assert all(c in "0123456789abcdef" for c in m["manifest_id"])

    def test_empty_tool_name_raises(self):
        with pytest.raises(ManifestError):
            create_manifest("", "1.0", "d", {}, [], _KEY)

    def test_short_key_raises(self):
        with pytest.raises(ManifestError, match="32 bytes"):
            create_manifest("t", "1.0", "d", {}, [], _SHORT_KEY)

    def test_allowed_agents_stored(self):
        m = create_manifest("t", "1.0", "d", {}, [], _KEY,
                            allowed_agents=["agent-1", "agent-2"])
        assert "agent-1" in m["statement"]["allowed_agents"]

    def test_allowed_agents_none_means_unrestricted(self):
        m = create_manifest("t", "1.0", "d", {}, [], _KEY, allowed_agents=None)
        assert m["statement"]["allowed_agents"] is None

    def test_issuer_stored(self):
        m = create_manifest("t", "1.0", "d", {}, [], _KEY, issuer="aiaf:test")
        assert m["statement"]["issuer"] == "aiaf:test"

    def test_expires_at_stored(self):
        m = create_manifest("t", "1.0", "d", {}, [], _KEY, expires_at="2027-01-01T00:00:00Z")
        assert m["statement"]["expires_at"] == "2027-01-01T00:00:00Z"


# ── verify_manifest ───────────────────────────────────────────────────────────

class TestVerifyManifest:
    def _make(self, **kwargs):
        return create_manifest("send_email", "1.0", "Send emails",
                               _SCHEMA, ["network_egress"], _KEY, **kwargs)

    def test_valid_manifest_returns_valid_true(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        assert result["valid"] is True

    def test_wrong_key_returns_valid_false(self):
        m = self._make()
        wrong_key = b"wrong-key-at-least-32-bytes-long!!!"
        result = verify_manifest(m, wrong_key)
        assert result["valid"] is False
        assert result["checks"]["signature_valid"] is False

    def test_tampered_statement_fails(self):
        m = self._make()
        m["statement"]["declared_capabilities"].append("approval_bypass")
        result = verify_manifest(m, _KEY)
        assert result["valid"] is False

    def test_schema_drift_detected(self):
        m = self._make()
        new_schema = {"type": "object", "properties": {"to": {"type": "array"}}}
        result = verify_manifest(m, _KEY, current_schema=new_schema)
        assert result["checks"]["schema_hash_matches"] is False
        assert result["valid"] is False

    def test_schema_unchanged_passes(self):
        m = self._make()
        result = verify_manifest(m, _KEY, current_schema=_SCHEMA)
        assert result["checks"]["schema_hash_matches"] is True
        assert result["valid"] is True

    def test_returns_required_fields(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        for field in ("valid", "manifest_id", "tool_name", "version",
                      "declared_capabilities", "checks", "evidence_origin", "verified_at"):
            assert field in result, f"Missing: {field}"

    def test_evidence_origin_independently_verified_on_valid(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        assert result["evidence_origin"] == "INDEPENDENTLY_VERIFIED"

    def test_evidence_origin_locally_observed_on_invalid(self):
        m = self._make()
        wrong_key = b"wrong-key-at-least-32-bytes-long!!!"
        result = verify_manifest(m, wrong_key)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_tool_name_echoed(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        assert result["tool_name"] == "send_email"

    def test_version_echoed(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        assert result["version"] == "1.0"

    def test_manifest_id_matches_check(self):
        m = self._make()
        result = verify_manifest(m, _KEY)
        assert result["checks"]["manifest_id_matches"] is True

    def test_tampered_manifest_id_fails(self):
        m = self._make()
        m["manifest_id"] = "deadbeef00000000"
        result = verify_manifest(m, _KEY)
        assert result["checks"]["manifest_id_matches"] is False

    def test_no_current_schema_skips_drift_check(self):
        m = self._make()
        result = verify_manifest(m, _KEY, current_schema=None)
        assert result["checks"]["schema_hash_matches"] is True  # pass-through


# ── register_manifest / get_manifest / list_manifests ──────────────────────────

class TestManifestStorage:
    def _registered(self):
        store = _Store()
        m = create_manifest("send_email", "1.0", "Send emails", _SCHEMA,
                            ["network_egress"], _KEY)
        summary = register_manifest(m, store)
        return store, m, summary

    def test_register_returns_summary(self):
        _, _, summary = self._registered()
        assert summary["tool_name"] == "send_email"
        assert summary["version"] == "1.0"

    def test_get_manifest_after_register(self):
        store, _, _ = self._registered()
        result = get_manifest("send_email", "1.0", store)
        assert result is not None
        assert result["tool_name"] == "send_email"

    def test_get_nonexistent_returns_none(self):
        store = _Store()
        assert get_manifest("no_tool", "9.9", store) is None

    def test_register_invalid_manifest_raises(self):
        store = _Store()
        with pytest.raises(ManifestError):
            register_manifest({"statement": {}}, store)

    def test_list_returns_registered(self):
        store = _Store()
        m1 = create_manifest("email", "1.0", "d", {}, [], _KEY)
        m2 = create_manifest("search", "2.0", "d", {}, [], _KEY)
        register_manifest(m1, store)
        register_manifest(m2, store)
        result = list_manifests(store)
        names = {r["tool_name"] for r in result}
        assert "email" in names and "search" in names

    def test_list_filter_by_tool_name(self):
        store = _Store()
        m1 = create_manifest("email", "1.0", "d", {}, [], _KEY)
        m2 = create_manifest("search", "1.0", "d", {}, [], _KEY)
        register_manifest(m1, store)
        register_manifest(m2, store)
        result = list_manifests(store, tool_name="email")
        assert all(r["tool_name"] == "email" for r in result)

    def test_list_empty_store(self):
        store = _Store()
        assert list_manifests(store) == []

    def test_capabilities_preserved_in_storage(self):
        store, _, _ = self._registered()
        result = get_manifest("send_email", "1.0", store)
        assert "network_egress" in result["declared_capabilities"]

    def test_manifest_id_preserved_in_storage(self):
        store, m, _ = self._registered()
        stored = get_manifest("send_email", "1.0", store)
        assert stored["manifest_id"] == m["manifest_id"]

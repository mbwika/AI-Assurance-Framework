"""Tests for src/aiaf/registry/identity_registry.py"""

import pytest
from datetime import datetime, timedelta, timezone
from aiaf.registry.identity_registry import (
    IDENTITY_VERSION,
    PRINCIPAL_MODEL, PRINCIPAL_AGENT, PRINCIPAL_TOOL,
    PRINCIPAL_DATASET, PRINCIPAL_HUMAN, PRINCIPAL_SERVICE,
    PRINCIPAL_TYPES,
    TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED,
    TRUST_LEVELS,
    DELEGATION_ACTIVE, DELEGATION_REVOKED, DELEGATION_EXPIRED,
    IdentityError,
    register_principal, get_principal, list_principals, update_principal,
    grant_delegation, get_delegation, revoke_delegation, list_delegations,
    verify_authority, get_authority_chain,
    _scope_matches,
)


class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


# ── Constants ──────────────────────────────────────────────────────────────────

class TestConstants:
    def test_version(self):
        assert IDENTITY_VERSION == "1.0"

    def test_principal_types_complete(self):
        assert {PRINCIPAL_MODEL, PRINCIPAL_AGENT, PRINCIPAL_TOOL,
                PRINCIPAL_DATASET, PRINCIPAL_HUMAN, PRINCIPAL_SERVICE} == PRINCIPAL_TYPES

    def test_trust_levels_complete(self):
        assert {TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED} == TRUST_LEVELS


# ── _scope_matches ─────────────────────────────────────────────────────────────

class TestScopeMatches:
    def test_wildcard_all(self):
        assert _scope_matches("*", "read", "db")

    def test_exact_match(self):
        assert _scope_matches("read:db", "read", "db")

    def test_action_mismatch(self):
        assert not _scope_matches("write:db", "read", "db")

    def test_resource_mismatch(self):
        assert not _scope_matches("read:logs", "read", "db")

    def test_action_wildcard(self):
        assert _scope_matches("*:db", "delete", "db")

    def test_resource_wildcard(self):
        assert _scope_matches("read:*", "read", "anything")

    def test_bare_action_no_colon(self):
        assert _scope_matches("read", "read", "any")
        assert not _scope_matches("write", "read", "any")


# ── register_principal ─────────────────────────────────────────────────────────

class TestRegisterPrincipal:
    def test_basic_registration(self):
        store = _Store()
        result = register_principal("p1", PRINCIPAL_MODEL, "My Model", store)
        assert result["principal_id"] == "p1"
        assert result["principal_type"] == PRINCIPAL_MODEL
        assert result["name"] == "My Model"
        assert result["trust_level"] == TRUST_INTERNAL

    def test_registered_at_preserved_on_update(self):
        store = _Store()
        r1 = register_principal("p1", PRINCIPAL_MODEL, "M", store)
        r2 = register_principal("p1", PRINCIPAL_MODEL, "M Updated", store)
        assert r1["registered_at"] == r2["registered_at"]

    def test_updated_at_changes_on_reregister(self):
        store = _Store()
        r1 = register_principal("p1", PRINCIPAL_MODEL, "M", store)
        r2 = register_principal("p1", PRINCIPAL_MODEL, "M2", store)
        assert r2["updated_at"] >= r1["updated_at"]

    def test_unknown_type_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="Unknown principal_type"):
            register_principal("p1", "ROBOT", "R", store)

    def test_unknown_trust_level_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="Unknown trust_level"):
            register_principal("p1", PRINCIPAL_AGENT, "A", store, trust_level="GOD")

    def test_empty_id_raises(self):
        store = _Store()
        with pytest.raises(IdentityError):
            register_principal("", PRINCIPAL_HUMAN, "H", store)

    def test_capabilities_stored(self):
        store = _Store()
        result = register_principal("p1", PRINCIPAL_SERVICE, "S", store,
                                    capabilities=["read:db", "write:logs"])
        assert "read:db" in result["capabilities"]

    def test_attributes_stored(self):
        store = _Store()
        result = register_principal("p1", PRINCIPAL_HUMAN, "H", store,
                                    attributes={"department": "AI"})
        assert result["attributes"]["department"] == "AI"

    def test_type_normalised_uppercase(self):
        store = _Store()
        result = register_principal("p1", "model", "M", store)
        assert result["principal_type"] == PRINCIPAL_MODEL


# ── get_principal ──────────────────────────────────────────────────────────────

class TestGetPrincipal:
    def test_returns_principal(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store)
        p = get_principal("p1", store)
        assert p is not None
        assert p["principal_id"] == "p1"

    def test_missing_returns_none(self):
        store = _Store()
        assert get_principal("nope", store) is None


# ── list_principals ────────────────────────────────────────────────────────────

class TestListPrincipals:
    def test_list_all(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store)
        register_principal("p2", PRINCIPAL_AGENT, "A", store)
        result = list_principals(store)
        assert len(result) == 2

    def test_filter_by_type(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store)
        register_principal("p2", PRINCIPAL_AGENT, "A", store)
        result = list_principals(store, principal_type=PRINCIPAL_MODEL)
        assert all(p["principal_type"] == PRINCIPAL_MODEL for p in result)
        assert len(result) == 1

    def test_filter_by_trust_level(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store, trust_level=TRUST_PRIVILEGED)
        register_principal("p2", PRINCIPAL_AGENT, "A", store, trust_level=TRUST_EXTERNAL)
        result = list_principals(store, trust_level=TRUST_PRIVILEGED)
        assert len(result) == 1
        assert result[0]["principal_id"] == "p1"

    def test_limit_respected(self):
        store = _Store()
        for i in range(5):
            register_principal(f"p{i}", PRINCIPAL_TOOL, f"T{i}", store)
        result = list_principals(store, limit=2)
        assert len(result) == 2


# ── update_principal ───────────────────────────────────────────────────────────

class TestUpdatePrincipal:
    def test_update_trust_level(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store)
        result = update_principal("p1", store, trust_level=TRUST_PRIVILEGED)
        assert result["trust_level"] == TRUST_PRIVILEGED

    def test_update_capabilities_replaces(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store, capabilities=["read:db"])
        result = update_principal("p1", store, capabilities=["write:db"])
        assert result["capabilities"] == ["write:db"]

    def test_update_attributes_merges(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_HUMAN, "H", store, attributes={"a": 1})
        result = update_principal("p1", store, attributes={"b": 2})
        assert result["attributes"]["a"] == 1
        assert result["attributes"]["b"] == 2

    def test_update_missing_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="not found"):
            update_principal("ghost", store, trust_level=TRUST_INTERNAL)

    def test_update_invalid_trust_level_raises(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_MODEL, "M", store)
        with pytest.raises(IdentityError, match="Unknown trust_level"):
            update_principal("p1", store, trust_level="SUPER")


# ── grant_delegation ───────────────────────────────────────────────────────────

class TestGrantDelegation:
    def test_basic_delegation(self):
        store = _Store()
        result = grant_delegation("d1", "delegator", "delegate", ["read:*"], store)
        assert result["delegation_id"] == "d1"
        assert result["status"] == DELEGATION_ACTIVE
        assert result["scope"] == ["read:*"]

    def test_empty_delegation_id_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="delegation_id"):
            grant_delegation("", "a", "b", ["*"], store)

    def test_empty_scope_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="scope"):
            grant_delegation("d1", "a", "b", [], store)

    def test_scope_not_list_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="scope"):
            grant_delegation("d1", "a", "b", "*", store)

    def test_optional_fields_stored(self):
        store = _Store()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = grant_delegation("d1", "a", "b", ["*"], store,
                                  granted_by="admin", expires_at=future)
        assert result["granted_by"] == "admin"
        assert result["expires_at"] == future


# ── get_delegation ─────────────────────────────────────────────────────────────

class TestGetDelegation:
    def test_returns_delegation(self):
        store = _Store()
        grant_delegation("d1", "a", "b", ["*"], store)
        d = get_delegation("d1", store)
        assert d is not None
        assert d["delegation_id"] == "d1"

    def test_missing_returns_none(self):
        store = _Store()
        assert get_delegation("nope", store) is None

    def test_expired_delegation_auto_marked(self):
        store = _Store()
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        grant_delegation("d1", "a", "b", ["*"], store, expires_at=past)
        d = get_delegation("d1", store)
        assert d["status"] == DELEGATION_EXPIRED


# ── revoke_delegation ──────────────────────────────────────────────────────────

class TestRevokeDelegation:
    def test_revoke_active(self):
        store = _Store()
        grant_delegation("d1", "a", "b", ["*"], store)
        result = revoke_delegation("d1", store, reason="policy violation")
        assert result["status"] == DELEGATION_REVOKED
        assert result["revocation_reason"] == "policy violation"

    def test_revoke_missing_raises(self):
        store = _Store()
        with pytest.raises(IdentityError, match="not found"):
            revoke_delegation("ghost", store)

    def test_revoke_already_revoked_raises(self):
        store = _Store()
        grant_delegation("d1", "a", "b", ["*"], store)
        revoke_delegation("d1", store)
        with pytest.raises(IdentityError, match="terminal status"):
            revoke_delegation("d1", store)

    def test_revoke_expired_raises(self):
        store = _Store()
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        grant_delegation("d1", "a", "b", ["*"], store, expires_at=past)
        get_delegation("d1", store)  # trigger auto-expire
        with pytest.raises(IdentityError, match="terminal status"):
            revoke_delegation("d1", store)


# ── list_delegations ───────────────────────────────────────────────────────────

class TestListDelegations:
    def test_active_only_default(self):
        store = _Store()
        grant_delegation("d1", "a", "b", ["*"], store)
        grant_delegation("d2", "a", "c", ["*"], store)
        revoke_delegation("d2", store)
        result = list_delegations(store, active_only=True)
        ids = {d["delegation_id"] for d in result}
        assert "d1" in ids
        assert "d2" not in ids

    def test_filter_by_delegator(self):
        store = _Store()
        grant_delegation("d1", "alice", "bob", ["*"], store)
        grant_delegation("d2", "charlie", "bob", ["*"], store)
        result = list_delegations(store, delegator_id="alice")
        assert all(d["delegator_id"] == "alice" for d in result)

    def test_filter_by_delegate(self):
        store = _Store()
        grant_delegation("d1", "alice", "bob", ["*"], store)
        grant_delegation("d2", "alice", "carol", ["*"], store)
        result = list_delegations(store, delegate_id="bob")
        assert len(result) == 1

    def test_all_statuses_when_active_only_false(self):
        store = _Store()
        grant_delegation("d1", "a", "b", ["*"], store)
        revoke_delegation("d1", store)
        result = list_delegations(store, active_only=False)
        assert len(result) == 1


# ── verify_authority ───────────────────────────────────────────────────────────

class TestVerifyAuthority:
    def test_direct_capability_grants_authority(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store,
                           capabilities=["read:database"])
        result = verify_authority("p1", "read", "database", store)
        assert result["authorized"] is True

    def test_wildcard_capability_grants_authority(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store, capabilities=["*"])
        result = verify_authority("p1", "delete", "anything", store)
        assert result["authorized"] is True

    def test_no_capability_no_delegation_denied(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_SERVICE, "S", store)
        result = verify_authority("p1", "write", "db", store)
        assert result["authorized"] is False

    def test_delegation_grants_authority(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store)
        register_principal("p2", PRINCIPAL_SERVICE, "S", store,
                           capabilities=["write:db"])
        grant_delegation("d1", "p2", "p1", ["write:db"], store)
        result = verify_authority("p1", "write", "db", store)
        assert result["authorized"] is True

    def test_unregistered_principal_denied(self):
        store = _Store()
        result = verify_authority("ghost", "read", "db", store)
        assert result["authorized"] is False
        assert "not registered" in result["reason"]

    def test_revoked_delegation_denied(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store)
        grant_delegation("d1", "other", "p1", ["read:*"], store)
        revoke_delegation("d1", store)
        result = verify_authority("p1", "read", "db", store)
        assert result["authorized"] is False


# ── get_authority_chain ────────────────────────────────────────────────────────

class TestGetAuthorityChain:
    def test_empty_chain_for_no_delegations(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store)
        chain = get_authority_chain("p1", store)
        assert chain == []

    def test_chain_includes_direct_delegation(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store)
        grant_delegation("d1", "other", "p1", ["*"], store)
        chain = get_authority_chain("p1", store)
        assert any(d["delegation_id"] == "d1" for d in chain)

    def test_cycle_safe(self):
        store = _Store()
        register_principal("p1", PRINCIPAL_AGENT, "A", store)
        register_principal("p2", PRINCIPAL_AGENT, "B", store)
        grant_delegation("d1", "p2", "p1", ["*"], store)
        grant_delegation("d2", "p1", "p2", ["*"], store)
        # Should not recurse infinitely
        chain = get_authority_chain("p1", store)
        assert isinstance(chain, list)

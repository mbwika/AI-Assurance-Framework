"""Tests for aiaf.registry.nhi_registry."""
import unittest
from datetime import datetime, timedelta, timezone

from aiaf.registry.nhi_registry import (
    NHI_VERSION,
    NHI_MODEL_SERVING, NHI_AGENT_WORKER, NHI_TOOL_EXECUTOR,
    NHI_PIPELINE_RUNNER, NHI_DATA_CONNECTOR, NHI_GATEWAY,
    NHI_TYPES,
    NHI_PENDING, NHI_ACTIVE, NHI_DORMANT, NHI_DEPROVISIONING, NHI_REVOKED,
    NHI_STATES,
    HYGIENE_CLEAN, HYGIENE_REVIEW_NEEDED, HYGIENE_AT_RISK, HYGIENE_CRITICAL,
    NHIError,
    register_nhi, get_nhi, list_nhis,
    update_nhi_state, update_nhi,
    assess_nhi_hygiene,
)


def _ts(days_ago: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat().replace("+00:00", "Z")


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


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(NHI_VERSION, "1.0")

    def test_nhi_types(self):
        for t in (NHI_MODEL_SERVING, NHI_AGENT_WORKER, NHI_TOOL_EXECUTOR,
                  NHI_PIPELINE_RUNNER, NHI_DATA_CONNECTOR, NHI_GATEWAY):
            self.assertIn(t, NHI_TYPES)

    def test_states(self):
        for s in (NHI_PENDING, NHI_ACTIVE, NHI_DORMANT, NHI_DEPROVISIONING, NHI_REVOKED):
            self.assertIn(s, NHI_STATES)


class TestRegisterNHI(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_basic_registration(self):
        nhi = register_nhi("svc-account-1", NHI_AGENT_WORKER, self.store)
        self.assertEqual(nhi["nhi_id"], "svc-account-1")
        self.assertEqual(nhi["nhi_type"], NHI_AGENT_WORKER)
        self.assertEqual(nhi["state"], NHI_PENDING)
        self.assertEqual(nhi["evidence_origin"], "LOCALLY_OBSERVED")

    def test_get_returns_nhi(self):
        register_nhi("n1", NHI_MODEL_SERVING, self.store)
        n = get_nhi("n1", self.store)
        self.assertIsNotNone(n)

    def test_get_missing_returns_none(self):
        self.assertIsNone(get_nhi("ghost", self.store))

    def test_empty_id_raises(self):
        with self.assertRaises(NHIError):
            register_nhi("", NHI_AGENT_WORKER, self.store)

    def test_unknown_type_raises(self):
        with self.assertRaises(NHIError):
            register_nhi("n1", "ROBOT", self.store)

    def test_optional_fields_stored(self):
        nhi = register_nhi(
            "n2", NHI_TOOL_EXECUTOR, self.store,
            owner_id="team-ml",
            environment="production",
            granted_scopes=["read:db", "write:blob"],
            minimum_required_scopes=["read:db"],
            credential_issued_at=_ts(5),
        )
        self.assertEqual(nhi["owner_id"], "team-ml")
        self.assertEqual(nhi["environment"], "production")
        self.assertEqual(nhi["granted_scopes"], ["read:db", "write:blob"])

    def test_state_history_initialized(self):
        nhi = register_nhi("n3", NHI_GATEWAY, self.store)
        self.assertEqual(len(nhi["state_history"]), 1)
        self.assertEqual(nhi["state_history"][0]["state"], NHI_PENDING)


class TestListNHIs(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_nhi("n1", NHI_AGENT_WORKER, self.store, owner_id="team-a")
        register_nhi("n2", NHI_MODEL_SERVING, self.store, owner_id="team-b")
        register_nhi("n3", NHI_AGENT_WORKER, self.store, owner_id="team-a")

    def test_list_all(self):
        nhis = list_nhis(self.store)
        self.assertEqual(len(nhis), 3)

    def test_filter_by_type(self):
        nhis = list_nhis(self.store, nhi_type=NHI_AGENT_WORKER)
        self.assertEqual(len(nhis), 2)

    def test_filter_by_state(self):
        nhis = list_nhis(self.store, state=NHI_PENDING)
        self.assertEqual(len(nhis), 3)

    def test_filter_by_owner(self):
        nhis = list_nhis(self.store, owner_id="team-a")
        self.assertEqual(len(nhis), 2)

    def test_limit(self):
        nhis = list_nhis(self.store, limit=2)
        self.assertEqual(len(nhis), 2)


class TestUpdateNHIState(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_nhi("n1", NHI_AGENT_WORKER, self.store)

    def test_valid_transition_pending_to_active(self):
        nhi = update_nhi_state("n1", NHI_ACTIVE, self.store, reason="provisioned")
        self.assertEqual(nhi["state"], NHI_ACTIVE)
        self.assertEqual(len(nhi["state_history"]), 2)
        self.assertEqual(nhi["state_history"][-1]["reason"], "provisioned")

    def test_active_to_dormant(self):
        update_nhi_state("n1", NHI_ACTIVE, self.store)
        nhi = update_nhi_state("n1", NHI_DORMANT, self.store)
        self.assertEqual(nhi["state"], NHI_DORMANT)

    def test_active_to_revoked(self):
        update_nhi_state("n1", NHI_ACTIVE, self.store)
        nhi = update_nhi_state("n1", NHI_REVOKED, self.store)
        self.assertEqual(nhi["state"], NHI_REVOKED)

    def test_terminal_state_raises(self):
        update_nhi_state("n1", NHI_ACTIVE, self.store)
        update_nhi_state("n1", NHI_REVOKED, self.store)
        with self.assertRaises(NHIError):
            update_nhi_state("n1", NHI_DORMANT, self.store)

    def test_invalid_transition_raises(self):
        # Cannot go PENDING -> DORMANT
        with self.assertRaises(NHIError):
            update_nhi_state("n1", NHI_DORMANT, self.store)

    def test_missing_nhi_raises(self):
        with self.assertRaises(NHIError):
            update_nhi_state("ghost", NHI_ACTIVE, self.store)

    def test_unknown_state_raises(self):
        with self.assertRaises(NHIError):
            update_nhi_state("n1", "FLYING", self.store)


class TestUpdateNHI(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_nhi("n1", NHI_AGENT_WORKER, self.store,
                     granted_scopes=["read:db"],
                     minimum_required_scopes=["read:db"])

    def test_update_scopes(self):
        nhi = update_nhi("n1", self.store, granted_scopes=["read:db", "write:blob"])
        self.assertEqual(nhi["granted_scopes"], ["read:db", "write:blob"])

    def test_update_credential_rotation(self):
        new_ts = _ts(0)
        nhi = update_nhi("n1", self.store, credential_issued_at=new_ts)
        self.assertEqual(nhi["credential_issued_at"], new_ts)

    def test_update_owner(self):
        nhi = update_nhi("n1", self.store, owner_id="new-team")
        self.assertEqual(nhi["owner_id"], "new-team")

    def test_attributes_merged(self):
        update_nhi("n1", self.store, attributes={"env": "prod"})
        nhi = update_nhi("n1", self.store, attributes={"region": "us-east-1"})
        self.assertIn("env", nhi["attributes"])
        self.assertIn("region", nhi["attributes"])

    def test_missing_nhi_raises(self):
        with self.assertRaises(NHIError):
            update_nhi("ghost", self.store, owner_id="x")


class TestAssessNHIHygiene(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_empty_registry(self):
        report = assess_nhi_hygiene(self.store)
        self.assertEqual(report["total_nhis"], 0)
        self.assertEqual(report["evidence_origin"], "LOCALLY_OBSERVED")
        self.assertIn("assessed_at", report)

    def test_required_keys(self):
        report = assess_nhi_hygiene(self.store)
        for key in (
            "total_nhis", "by_state", "by_type",
            "stale_count", "over_privileged_count", "orphaned_count",
            "rotation_needed_count", "critical_count", "at_risk_count",
            "review_needed_count", "clean_count",
            "critical_nhis", "at_risk_nhis",
        ):
            self.assertIn(key, report)

    def test_stale_detection(self):
        register_nhi("stale-one", NHI_AGENT_WORKER, self.store,
                     last_seen_at=_ts(60))
        update_nhi_state("stale-one", NHI_ACTIVE, self.store)
        report = assess_nhi_hygiene(self.store, stale_days=30)
        self.assertGreater(report["stale_count"], 0)

    def test_fresh_not_stale(self):
        register_nhi("fresh-one", NHI_AGENT_WORKER, self.store,
                     last_seen_at=_ts(1))
        update_nhi_state("fresh-one", NHI_ACTIVE, self.store)
        report = assess_nhi_hygiene(self.store, stale_days=30)
        self.assertEqual(report["stale_count"], 0)

    def test_over_privileged_detection(self):
        register_nhi("priv-one", NHI_TOOL_EXECUTOR, self.store,
                     granted_scopes=["read:db", "write:db", "admin:all"],
                     minimum_required_scopes=["read:db"])
        report = assess_nhi_hygiene(self.store)
        self.assertGreater(report["over_privileged_count"], 0)

    def test_orphaned_detection(self):
        register_nhi("orphan", NHI_MODEL_SERVING, self.store)
        report = assess_nhi_hygiene(self.store)
        self.assertGreater(report["orphaned_count"], 0)

    def test_owned_not_orphaned(self):
        register_nhi("owned", NHI_MODEL_SERVING, self.store, owner_id="team-ml")
        report = assess_nhi_hygiene(self.store)
        self.assertEqual(report["orphaned_count"], 0)

    def test_credential_rotation_needed(self):
        register_nhi("old-cred", NHI_PIPELINE_RUNNER, self.store,
                     credential_issued_at=_ts(120))
        report = assess_nhi_hygiene(self.store, credential_age_days=90)
        self.assertGreater(report["rotation_needed_count"], 0)

    def test_by_type_counts(self):
        register_nhi("a1", NHI_AGENT_WORKER, self.store, owner_id="t1")
        register_nhi("a2", NHI_AGENT_WORKER, self.store, owner_id="t1")
        register_nhi("m1", NHI_MODEL_SERVING, self.store, owner_id="t1")
        report = assess_nhi_hygiene(self.store)
        self.assertEqual(report["by_type"].get(NHI_AGENT_WORKER, 0), 2)
        self.assertEqual(report["by_type"].get(NHI_MODEL_SERVING, 0), 1)

    def test_revoked_excluded_by_default(self):
        register_nhi("rev", NHI_AGENT_WORKER, self.store, owner_id="t")
        update_nhi_state("rev", NHI_ACTIVE, self.store)
        update_nhi_state("rev", NHI_REVOKED, self.store)
        report = assess_nhi_hygiene(self.store, include_revoked=False)
        self.assertEqual(report["total_nhis"], 0)

    def test_revoked_included_when_flag_set(self):
        register_nhi("rev2", NHI_AGENT_WORKER, self.store)
        update_nhi_state("rev2", NHI_ACTIVE, self.store)
        update_nhi_state("rev2", NHI_REVOKED, self.store)
        report = assess_nhi_hygiene(self.store, include_revoked=True)
        self.assertEqual(report["total_nhis"], 1)

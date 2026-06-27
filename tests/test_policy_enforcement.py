"""Tests for aiaf.core.policy_enforcement."""
import unittest

from aiaf.core.policy_enforcement import (
    POLICY_ENFORCEMENT_VERSION,
    MODE_ENFORCE, MODE_AUDIT, MODE_PASSTHROUGH,
    ENFORCEMENT_MODES,
    VERDICT_ALLOW, VERDICT_DENY, VERDICT_CONDITIONAL,
    VERDICTS,
    PolicyEnforcementError,
    create_pep_policy, get_pep_policy, list_pep_policies, delete_pep_policy,
    enforce_request, get_enforcement_log,
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


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(POLICY_ENFORCEMENT_VERSION, "1.0")

    def test_modes(self):
        for m in (MODE_ENFORCE, MODE_AUDIT, MODE_PASSTHROUGH):
            self.assertIn(m, ENFORCEMENT_MODES)

    def test_verdicts(self):
        for v in (VERDICT_ALLOW, VERDICT_DENY, VERDICT_CONDITIONAL):
            self.assertIn(v, VERDICTS)


class TestCreatePolicy(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_basic_creation(self):
        p = create_pep_policy("p1", "agent-a", self.store)
        self.assertEqual(p["policy_id"], "p1")
        self.assertEqual(p["principal_id"], "agent-a")
        self.assertEqual(p["mode"], MODE_ENFORCE)
        self.assertEqual(p["evidence_origin"], "LOCALLY_OBSERVED")

    def test_get_returns_policy(self):
        create_pep_policy("p1", "agent-a", self.store)
        p = get_pep_policy("p1", self.store)
        self.assertIsNotNone(p)

    def test_get_missing_returns_none(self):
        self.assertIsNone(get_pep_policy("nope", self.store))

    def test_empty_policy_id_raises(self):
        with self.assertRaises(PolicyEnforcementError):
            create_pep_policy("", "agent-a", self.store)

    def test_empty_principal_raises(self):
        with self.assertRaises(PolicyEnforcementError):
            create_pep_policy("p1", "", self.store)

    def test_unknown_mode_raises(self):
        with self.assertRaises(PolicyEnforcementError):
            create_pep_policy("p1", "agent-a", self.store, mode="ROBOT")

    def test_all_optional_fields_stored(self):
        p = create_pep_policy(
            "p2", "agent-b", self.store,
            mode=MODE_AUDIT,
            allowed_actions=["read", "list"],
            denied_actions=["delete"],
            allowed_resources=["users_db"],
            denied_resources=["admin_db"],
            conditions=["require_human_approval"],
            max_requests_per_min=100,
            description="Test policy",
        )
        self.assertEqual(p["mode"], MODE_AUDIT)
        self.assertIn("read", p["allowed_actions"])
        self.assertIn("delete", p["denied_actions"])
        self.assertEqual(p["description"], "Test policy")

    def test_initial_counters_zero(self):
        p = create_pep_policy("p1", "agent-a", self.store)
        self.assertEqual(p["request_count"], 0)
        self.assertEqual(p["deny_count"], 0)


class TestListAndDeletePolicies(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        create_pep_policy("p1", "agent-a", self.store)
        create_pep_policy("p2", "agent-b", self.store)
        create_pep_policy("p3", "agent-a", self.store, mode=MODE_AUDIT)

    def test_list_all(self):
        policies = list_pep_policies(self.store)
        self.assertEqual(len(policies), 3)

    def test_filter_by_principal(self):
        policies = list_pep_policies(self.store, principal_id="agent-a")
        self.assertEqual(len(policies), 2)

    def test_filter_by_mode(self):
        policies = list_pep_policies(self.store, mode=MODE_AUDIT)
        self.assertEqual(len(policies), 1)

    def test_limit(self):
        policies = list_pep_policies(self.store, limit=2)
        self.assertEqual(len(policies), 2)

    def test_delete_existing(self):
        self.assertTrue(delete_pep_policy("p1", self.store))

    def test_delete_missing(self):
        self.assertFalse(delete_pep_policy("ghost", self.store))


class TestEnforceRequest(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_no_policy_default_allow(self):
        result = enforce_request("agent-x", "read", "users_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)
        self.assertEqual(result["policy_ids_evaluated"], [])
        self.assertEqual(result["evidence_origin"], "LOCALLY_OBSERVED")

    def test_required_keys_in_result(self):
        result = enforce_request("agent-x", "read", "users_db", self.store)
        for key in (
            "principal_id", "action", "resource", "verdict",
            "reasons", "conditions_required", "rate_limited",
            "policy_ids_evaluated", "evidence_origin", "decided_at",
        ):
            self.assertIn(key, result)

    def test_explicit_allow(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["read", "list"])
        result = enforce_request("agent-a", "read", "any_resource", self.store)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)

    def test_deny_by_denied_action(self):
        create_pep_policy("p1", "agent-a", self.store,
                          denied_actions=["delete"])
        result = enforce_request("agent-a", "delete", "users_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

    def test_deny_by_denied_resource(self):
        create_pep_policy("p1", "agent-a", self.store,
                          denied_resources=["admin_db"])
        result = enforce_request("agent-a", "read", "admin_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

    def test_action_not_in_allowlist_is_denied(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["read"])
        result = enforce_request("agent-a", "write", "users_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

    def test_resource_not_in_allowlist_is_denied(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_resources=["users_db"])
        result = enforce_request("agent-a", "read", "secrets_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

    def test_wildcard_action_allows_all(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["*"])
        result = enforce_request("agent-a", "any_action", "any_resource", self.store)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)

    def test_conditions_produce_conditional_verdict(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["*"],
                          conditions=["require_audit_log", "require_human_approval"])
        result = enforce_request("agent-a", "write", "sensitive_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_CONDITIONAL)
        self.assertIn("require_audit_log", result["conditions_required"])

    def test_deny_overrides_conditions(self):
        create_pep_policy("p1", "agent-a", self.store,
                          denied_actions=["delete"],
                          conditions=["require_approval"])
        result = enforce_request("agent-a", "delete", "users_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

    def test_audit_mode_never_blocks(self):
        create_pep_policy("p1", "agent-a", self.store,
                          mode=MODE_AUDIT,
                          denied_actions=["delete"])
        result = enforce_request("agent-a", "delete", "users_db", self.store)
        # In AUDIT mode verdict should be ALLOW (never blocks)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)

    def test_passthrough_mode_always_allows(self):
        create_pep_policy("p1", "agent-a", self.store,
                          mode=MODE_PASSTHROUGH,
                          denied_actions=["delete"],
                          allowed_actions=["read"])
        result = enforce_request("agent-a", "delete", "everything", self.store)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)

    def test_empty_principal_raises(self):
        with self.assertRaises(PolicyEnforcementError):
            enforce_request("", "read", "db", self.store)

    def test_empty_action_raises(self):
        with self.assertRaises(PolicyEnforcementError):
            enforce_request("agent-a", "", "db", self.store)

    def test_policy_request_count_increments(self):
        create_pep_policy("p1", "agent-a", self.store, allowed_actions=["*"])
        enforce_request("agent-a", "read", "db", self.store)
        enforce_request("agent-a", "write", "db", self.store)
        p = get_pep_policy("p1", self.store)
        self.assertEqual(p["request_count"], 2)

    def test_policy_deny_count_increments(self):
        create_pep_policy("p1", "agent-a", self.store, denied_actions=["delete"])
        enforce_request("agent-a", "delete", "db", self.store)
        p = get_pep_policy("p1", self.store)
        self.assertEqual(p["deny_count"], 1)

    def test_specific_policy_id_lookup(self):
        create_pep_policy("p1", "agent-a", self.store, allowed_actions=["read"])
        create_pep_policy("p2", "agent-a", self.store, denied_actions=["read"])
        # When looking up p1 specifically, read should be ALLOW
        result = enforce_request("agent-a", "read", "db", self.store, policy_id="p1")
        self.assertEqual(result["verdict"], VERDICT_ALLOW)


class TestEnforcementLog(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        create_pep_policy("p1", "agent-a", self.store, denied_actions=["delete"])

    def test_log_entries_created(self):
        enforce_request("agent-a", "delete", "db", self.store)
        log = get_enforcement_log("p1", self.store)
        self.assertGreater(len(log), 0)

    def test_log_has_required_fields(self):
        enforce_request("agent-a", "read", "db", self.store)
        log = get_enforcement_log("p1", self.store)
        if log:
            entry = log[0]
            for key in ("principal_id", "action", "resource", "verdict", "decided_at"):
                self.assertIn(key, entry)

    def test_filter_by_verdict(self):
        enforce_request("agent-a", "delete", "db", self.store)
        deny_log = get_enforcement_log("p1", self.store, verdict=VERDICT_DENY)
        allow_log = get_enforcement_log("p1", self.store, verdict=VERDICT_ALLOW)
        # delete is denied, so deny_log should have entries
        for entry in deny_log:
            self.assertEqual(entry["verdict"], VERDICT_DENY)

    def test_limit_applied(self):
        for i in range(5):
            enforce_request("agent-a", "delete", "db", self.store)
        log = get_enforcement_log("p1", self.store, limit=3)
        self.assertLessEqual(len(log), 3)


class TestPatternMatching(unittest.TestCase):
    """Test glob pattern matching for allowed/denied lists."""

    def setUp(self):
        self.store = _Store()

    def test_wildcard_resource_in_action_pattern(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["read:*"])
        result = enforce_request("agent-a", "read", "any_db", self.store)
        self.assertEqual(result["verdict"], VERDICT_ALLOW)

    def test_exact_action_resource_match(self):
        create_pep_policy("p1", "agent-a", self.store,
                          allowed_actions=["read:users_db"])
        result_match = enforce_request("agent-a", "read", "users_db", self.store)
        result_no_match = enforce_request("agent-a", "read", "other_db", self.store)
        self.assertEqual(result_match["verdict"], VERDICT_ALLOW)
        self.assertEqual(result_no_match["verdict"], VERDICT_DENY)

    def test_wildcard_action_specific_resource(self):
        create_pep_policy("p1", "agent-a", self.store,
                          denied_resources=["*"])
        result = enforce_request("agent-a", "read", "anything", self.store)
        self.assertEqual(result["verdict"], VERDICT_DENY)

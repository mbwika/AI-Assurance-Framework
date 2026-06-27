"""Tests for aiaf.analysis.agent_topology."""
import unittest

from aiaf.analysis.agent_topology import (
    AGENT_TOPOLOGY_VERSION,
    TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED,
    TRUST_LEVELS,
    NODE_AGENT, NODE_MODEL, NODE_TOOL, NODE_SERVICE, NODE_HUMAN,
    NODE_TYPES,
    CHANNEL_DIRECT_CALL, CHANNEL_SHARED_MEMORY, CHANNEL_API, CHANNEL_TOOL_CALL,
    CHANNEL_TYPES,
    TOPOLOGY_RISK_LOW, TOPOLOGY_RISK_MEDIUM, TOPOLOGY_RISK_HIGH, TOPOLOGY_RISK_CRITICAL,
    AgentTopologyError,
    register_topology, get_topology,
    add_agent_node, add_communication_edge,
    analyze_topology,
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
        self.assertEqual(AGENT_TOPOLOGY_VERSION, "1.0")

    def test_trust_levels(self):
        for t in (TRUST_UNTRUSTED, TRUST_EXTERNAL, TRUST_INTERNAL, TRUST_PRIVILEGED):
            self.assertIn(t, TRUST_LEVELS)

    def test_node_types(self):
        for nt in (NODE_AGENT, NODE_MODEL, NODE_TOOL, NODE_SERVICE, NODE_HUMAN):
            self.assertIn(nt, NODE_TYPES)

    def test_channel_types(self):
        for ch in (CHANNEL_DIRECT_CALL, CHANNEL_SHARED_MEMORY, CHANNEL_API, CHANNEL_TOOL_CALL):
            self.assertIn(ch, CHANNEL_TYPES)

    def test_risk_levels(self):
        levels = {TOPOLOGY_RISK_LOW, TOPOLOGY_RISK_MEDIUM, TOPOLOGY_RISK_HIGH, TOPOLOGY_RISK_CRITICAL}
        self.assertEqual(len(levels), 4)


class TestRegisterTopology(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_basic_registration(self):
        result = register_topology("topo1", self.store, name="Test Topology")
        self.assertEqual(result["topology_id"], "topo1")
        self.assertEqual(result["name"], "Test Topology")
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["edge_count"], 0)
        self.assertEqual(result["evidence_origin"], "LOCALLY_OBSERVED")

    def test_get_returns_topology(self):
        register_topology("t1", self.store)
        t = get_topology("t1", self.store)
        self.assertIsNotNone(t)

    def test_get_missing_returns_none(self):
        self.assertIsNone(get_topology("nope", self.store))

    def test_empty_id_raises(self):
        with self.assertRaises(AgentTopologyError):
            register_topology("", self.store)


class TestAddNode(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_topology("topo", self.store)

    def test_add_node_basic(self):
        node = add_agent_node("topo", "agent1", NODE_AGENT, TRUST_INTERNAL, self.store)
        self.assertEqual(node["node_id"], "agent1")
        self.assertEqual(node["node_type"], NODE_AGENT)
        self.assertEqual(node["trust_level"], TRUST_INTERNAL)
        self.assertFalse(node["has_guardrail"])

    def test_node_increments_count(self):
        add_agent_node("topo", "a1", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "a2", NODE_MODEL, TRUST_EXTERNAL, self.store)
        t = get_topology("topo", self.store)
        self.assertEqual(t["node_count"], 2)

    def test_guardrail_stored(self):
        node = add_agent_node("topo", "gw", NODE_AGENT, TRUST_EXTERNAL, self.store,
                              has_guardrail=True)
        self.assertTrue(node["has_guardrail"])

    def test_internet_facing_stored(self):
        node = add_agent_node("topo", "ext", NODE_AGENT, TRUST_EXTERNAL, self.store,
                              internet_facing=True)
        self.assertTrue(node["internet_facing"])

    def test_unknown_node_type_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_agent_node("topo", "a", "ROBOT", TRUST_INTERNAL, self.store)

    def test_unknown_trust_level_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_agent_node("topo", "a", NODE_AGENT, "SUPER_TRUSTED", self.store)

    def test_missing_topology_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_agent_node("ghost", "a", NODE_AGENT, TRUST_INTERNAL, self.store)

    def test_capabilities_stored(self):
        node = add_agent_node("topo", "cap_node", NODE_AGENT, TRUST_INTERNAL, self.store,
                              capabilities=["read_db", "write_files"])
        self.assertEqual(node["capabilities"], ["read_db", "write_files"])


class TestAddEdge(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_topology("topo", self.store)
        add_agent_node("topo", "ext_agent", NODE_AGENT, TRUST_EXTERNAL, self.store)
        add_agent_node("topo", "int_agent", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "priv_agent", NODE_AGENT, TRUST_PRIVILEGED, self.store)

    def test_edge_same_trust(self):
        add_agent_node("topo", "int2", NODE_AGENT, TRUST_INTERNAL, self.store)
        edge = add_communication_edge("topo", "int_agent", "int2", self.store)
        self.assertFalse(edge["crosses_trust_boundary"])
        self.assertFalse(edge["privilege_escalation"])

    def test_edge_crosses_trust_boundary(self):
        edge = add_communication_edge("topo", "ext_agent", "int_agent", self.store)
        self.assertTrue(edge["crosses_trust_boundary"])
        self.assertFalse(edge["privilege_escalation"])

    def test_privilege_escalation_detected(self):
        edge = add_communication_edge("topo", "ext_agent", "priv_agent", self.store)
        self.assertTrue(edge["privilege_escalation"])

    def test_bidirectional_adds_two_edges(self):
        t_before = get_topology("topo", self.store)
        count_before = t_before["edge_count"]
        add_communication_edge("topo", "ext_agent", "int_agent", self.store, bidirectional=True)
        t_after = get_topology("topo", self.store)
        self.assertEqual(t_after["edge_count"], count_before + 2)

    def test_missing_from_node_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_communication_edge("topo", "ghost", "int_agent", self.store)

    def test_missing_to_node_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_communication_edge("topo", "ext_agent", "ghost", self.store)

    def test_unknown_channel_raises(self):
        with self.assertRaises(AgentTopologyError):
            add_communication_edge("topo", "ext_agent", "int_agent", self.store,
                                   channel="TELEPATHY")

    def test_guardrail_on_edge_stored(self):
        edge = add_communication_edge("topo", "ext_agent", "int_agent", self.store,
                                     has_guardrail=True)
        self.assertTrue(edge["has_guardrail"])


class TestAnalyzeTopology(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_topology("topo", self.store)

    def test_empty_topology(self):
        result = analyze_topology("topo", self.store)
        self.assertEqual(result["overall_risk"], TOPOLOGY_RISK_LOW)
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["evidence_origin"], "LOCALLY_OBSERVED")
        self.assertIn("analyzed_at", result)

    def test_required_keys(self):
        result = analyze_topology("topo", self.store)
        for key in (
            "topology_id", "agent_topology_version", "overall_risk",
            "node_count", "edge_count", "trust_boundary_crossings",
            "privilege_escalation_paths", "spocf_nodes", "max_blast_radius_pct",
            "blast_radius_by_node", "guardrail_coverage_pct",
            "internet_facing_unguarded", "findings", "recommended_mitigations",
        ):
            self.assertIn(key, result)

    def test_missing_topology_raises(self):
        with self.assertRaises(AgentTopologyError):
            analyze_topology("ghost", self.store)

    def test_clean_internal_only(self):
        add_agent_node("topo", "a1", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "a2", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_communication_edge("topo", "a1", "a2", self.store)
        result = analyze_topology("topo", self.store)
        self.assertEqual(result["trust_boundary_crossings"], [])
        self.assertIn(result["overall_risk"], (TOPOLOGY_RISK_LOW, TOPOLOGY_RISK_MEDIUM))

    def test_unguarded_priv_esc_is_critical(self):
        add_agent_node("topo", "ext", NODE_AGENT, TRUST_EXTERNAL, self.store)
        add_agent_node("topo", "priv", NODE_AGENT, TRUST_PRIVILEGED, self.store)
        add_communication_edge("topo", "ext", "priv", self.store, has_guardrail=False)
        result = analyze_topology("topo", self.store)
        self.assertEqual(result["overall_risk"], TOPOLOGY_RISK_CRITICAL)
        self.assertTrue(len(result["privilege_escalation_paths"]) > 0)

    def test_guarded_priv_esc_downgraded(self):
        add_agent_node("topo", "ext", NODE_AGENT, TRUST_EXTERNAL, self.store)
        add_agent_node("topo", "priv", NODE_AGENT, TRUST_PRIVILEGED, self.store)
        add_communication_edge("topo", "ext", "priv", self.store, has_guardrail=True)
        result = analyze_topology("topo", self.store)
        # Guarded — still a crossing but not an unguarded CRITICAL finding
        unguarded_crit = [
            f for f in result["findings"]
            if f["severity"] == "CRITICAL" and f["category"] == "TRUST_BOUNDARY_CROSSING"
        ]
        self.assertEqual(unguarded_crit, [])

    def test_blast_radius_computed(self):
        add_agent_node("topo", "a1", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "a2", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "a3", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_communication_edge("topo", "a1", "a2", self.store)
        add_communication_edge("topo", "a1", "a3", self.store)
        result = analyze_topology("topo", self.store)
        # a1 can reach a2 and a3 = 2/3 = 66.7%
        self.assertGreater(result["blast_radius_by_node"]["a1"], 60.0)

    def test_internet_facing_unguarded_finding(self):
        add_agent_node("topo", "web", NODE_AGENT, TRUST_EXTERNAL, self.store,
                       internet_facing=True, has_guardrail=False)
        result = analyze_topology("topo", self.store)
        self.assertIn("web", result["internet_facing_unguarded"])

    def test_internet_facing_with_guardrail_not_flagged(self):
        add_agent_node("topo", "web2", NODE_AGENT, TRUST_EXTERNAL, self.store,
                       internet_facing=True, has_guardrail=True)
        result = analyze_topology("topo", self.store)
        self.assertNotIn("web2", result["internet_facing_unguarded"])

    def test_guardrail_coverage_pct_100_when_no_crossings(self):
        add_agent_node("topo", "a", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_agent_node("topo", "b", NODE_AGENT, TRUST_INTERNAL, self.store)
        add_communication_edge("topo", "a", "b", self.store)
        result = analyze_topology("topo", self.store)
        self.assertEqual(result["guardrail_coverage_pct"], 100.0)

    def test_mitigations_non_empty_when_risk(self):
        add_agent_node("topo", "ext", NODE_AGENT, TRUST_EXTERNAL, self.store)
        add_agent_node("topo", "priv", NODE_AGENT, TRUST_PRIVILEGED, self.store)
        add_communication_edge("topo", "ext", "priv", self.store)
        result = analyze_topology("topo", self.store)
        self.assertTrue(len(result["recommended_mitigations"]) > 0)

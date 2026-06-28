"""Tests for aiaf.analysis.context_provenance."""

import unittest

from aiaf.analysis.context_provenance import (
    NODE_MODEL_RESPONSE,
    NODE_PROMPT_TEMPLATE,
    NODE_RAG_DOCUMENT,
    NODE_SYSTEM_PROMPT,
    NODE_TOOL_OUTPUT,
    NODE_USER_INPUT,
    PROVENANCE_GRAPH_VERSION,
    REL_FILTERED_BY,
    REL_INFLUENCES,
    ContextProvenanceError,
    add_influence_edge,
    add_provenance_node,
    find_influenced_by,
    get_provenance_graph,
    list_provenance_edges,
    list_provenance_nodes,
    register_provenance_graph,
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


class TestRegisterGraph(unittest.TestCase):
    def setUp(self):
        self.store = _Store()

    def test_register_graph_basic(self):
        result = register_provenance_graph("resp-1", self.store, session_id="s1", model_id="m1")
        self.assertEqual(result["graph_id"], "resp-1")
        self.assertEqual(result["graph_version"], PROVENANCE_GRAPH_VERSION)
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["edge_count"], 0)

    def test_get_missing_returns_none(self):
        self.assertIsNone(get_provenance_graph("missing", self.store))

    def test_empty_graph_id_raises(self):
        with self.assertRaises(ContextProvenanceError):
            register_provenance_graph("", self.store)


class TestNodesAndEdges(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_provenance_graph("resp-1", self.store)

    def test_add_node_updates_count_and_index(self):
        node = add_provenance_node(
            "resp-1",
            "doc-1",
            NODE_RAG_DOCUMENT,
            self.store,
            source_ref="rag:doc-1",
            content_hash="a" * 64,
        )
        graph = get_provenance_graph("resp-1", self.store)
        self.assertEqual(node["node_type"], NODE_RAG_DOCUMENT)
        self.assertEqual(graph["node_count"], 1)
        self.assertEqual(graph["source_ref_index"]["rag:doc-1"], ["doc-1"])

    def test_duplicate_node_raises(self):
        add_provenance_node("resp-1", "u1", NODE_USER_INPUT, self.store)
        with self.assertRaises(ContextProvenanceError):
            add_provenance_node("resp-1", "u1", NODE_USER_INPUT, self.store)

    def test_add_edge_updates_count(self):
        add_provenance_node("resp-1", "u1", NODE_USER_INPUT, self.store)
        add_provenance_node("resp-1", "r1", NODE_MODEL_RESPONSE, self.store)
        edge = add_influence_edge("resp-1", "u1", "r1", self.store)
        graph = get_provenance_graph("resp-1", self.store)
        self.assertEqual(edge["relationship"], REL_INFLUENCES)
        self.assertEqual(graph["edge_count"], 1)

    def test_missing_endpoint_raises(self):
        add_provenance_node("resp-1", "u1", NODE_USER_INPUT, self.store)
        with self.assertRaises(ContextProvenanceError):
            add_influence_edge("resp-1", "u1", "missing", self.store)

    def test_cycle_is_rejected(self):
        add_provenance_node("resp-1", "a", NODE_USER_INPUT, self.store)
        add_provenance_node("resp-1", "b", NODE_TOOL_OUTPUT, self.store)
        add_provenance_node("resp-1", "c", NODE_MODEL_RESPONSE, self.store)
        add_influence_edge("resp-1", "a", "b", self.store)
        add_influence_edge("resp-1", "b", "c", self.store)
        with self.assertRaises(ContextProvenanceError):
            add_influence_edge("resp-1", "c", "a", self.store)

    def test_list_helpers_are_stable(self):
        add_provenance_node("resp-1", "prompt", NODE_PROMPT_TEMPLATE, self.store)
        add_provenance_node("resp-1", "system", NODE_SYSTEM_PROMPT, self.store)
        add_influence_edge("resp-1", "prompt", "system", self.store, relationship=REL_FILTERED_BY)
        self.assertEqual([node["node_id"] for node in list_provenance_nodes("resp-1", self.store)], ["prompt", "system"])
        self.assertEqual(list_provenance_edges("resp-1", self.store)[0]["relationship"], REL_FILTERED_BY)


class TestFindInfluencedBy(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        register_provenance_graph("resp-1", self.store)
        add_provenance_node("resp-1", "user-1", NODE_USER_INPUT, self.store, source_ref="user:req-1")
        add_provenance_node("resp-1", "doc-1", NODE_RAG_DOCUMENT, self.store, source_ref="rag:doc-1")
        add_provenance_node("resp-1", "tool-1", NODE_TOOL_OUTPUT, self.store)
        add_provenance_node("resp-1", "resp-1-node", NODE_MODEL_RESPONSE, self.store)
        add_influence_edge("resp-1", "user-1", "tool-1", self.store)
        add_influence_edge("resp-1", "doc-1", "resp-1-node", self.store)
        add_influence_edge("resp-1", "tool-1", "resp-1-node", self.store)

        register_provenance_graph("resp-2", self.store)
        add_provenance_node("resp-2", "doc-2", NODE_RAG_DOCUMENT, self.store, source_ref="rag:doc-1")
        add_provenance_node("resp-2", "resp-2-node", NODE_MODEL_RESPONSE, self.store)
        add_influence_edge("resp-2", "doc-2", "resp-2-node", self.store)

    def test_find_influenced_by_one_graph(self):
        result = find_influenced_by("rag:doc-1", self.store, graph_id="resp-1")
        self.assertEqual(result["graph_count"], 1)
        self.assertEqual(result["seed_node_count"], 1)
        self.assertEqual(result["influenced_node_count"], 1)
        self.assertEqual(result["graph_results"][0]["influenced_nodes"][0]["node_id"], "resp-1-node")

    def test_find_influenced_by_across_graphs(self):
        result = find_influenced_by("rag:doc-1", self.store)
        self.assertEqual(result["graph_count"], 2)
        self.assertEqual(result["seed_node_count"], 2)
        self.assertEqual(result["influenced_node_count"], 2)

    def test_find_influenced_by_missing_source_returns_empty(self):
        result = find_influenced_by("missing:source", self.store)
        self.assertEqual(result["graph_count"], 0)
        self.assertEqual(result["influenced_node_count"], 0)

    def test_empty_source_ref_raises(self):
        with self.assertRaises(ContextProvenanceError):
            find_influenced_by("", self.store)


if __name__ == "__main__":
    unittest.main()

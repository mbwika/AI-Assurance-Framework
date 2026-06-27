"""Tests for aiaf.registry.rag_inventory."""

import pytest

from aiaf.registry.rag_inventory import (
    INVENTORY_VERSION,
    MAX_DOCS_PER_STORE,
    TRUST_LABELS,
    TRUST_RANK,
    TRUST_VERIFIED,
    TRUST_INTERNAL,
    TRUST_EXTERNAL,
    TRUST_USER_GENERATED,
    TRUST_UNTRUSTED,
    RAGInventoryError,
    _validate_trust_label,
    _validate_source_type,
    _validate_store_type,
    register_store,
    get_vector_store,
    list_vector_stores,
    register_document,
    get_document,
    list_documents,
)


# ── Fake store ────────────────────────────────────────────────────────────────

class _FakeStore:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        mid = record.get("model_id") or record.get("id")
        self._data[mid] = record

    def list_models(self):
        return list(self._data.values())


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_inventory_version_string(self):
        assert isinstance(INVENTORY_VERSION, str)
        assert INVENTORY_VERSION == "1.0"

    def test_trust_labels_frozenset(self):
        assert isinstance(TRUST_LABELS, frozenset)
        for label in (TRUST_VERIFIED, TRUST_INTERNAL, TRUST_EXTERNAL,
                      TRUST_USER_GENERATED, TRUST_UNTRUSTED):
            assert label in TRUST_LABELS

    def test_trust_rank_order(self):
        assert TRUST_RANK[TRUST_VERIFIED] > TRUST_RANK[TRUST_INTERNAL]
        assert TRUST_RANK[TRUST_INTERNAL] > TRUST_RANK[TRUST_EXTERNAL]
        assert TRUST_RANK[TRUST_EXTERNAL] > TRUST_RANK[TRUST_USER_GENERATED]
        assert TRUST_RANK[TRUST_USER_GENERATED] > TRUST_RANK[TRUST_UNTRUSTED]

    def test_max_docs_per_store_reasonable(self):
        assert MAX_DOCS_PER_STORE >= 1000


# ── Validators ────────────────────────────────────────────────────────────────

class TestValidators:
    def test_valid_trust_label_case_insensitive(self):
        assert _validate_trust_label("verified") == "VERIFIED"
        assert _validate_trust_label("INTERNAL") == "INTERNAL"

    def test_invalid_trust_label_raises(self):
        with pytest.raises(RAGInventoryError):
            _validate_trust_label("BOGUS")

    def test_valid_source_type_lowercase(self):
        assert _validate_source_type("web") == "web"
        assert _validate_source_type("USER_UPLOAD") == "user_upload"

    def test_unknown_source_type_falls_back(self):
        assert _validate_source_type("something_weird") == "unknown"

    def test_valid_store_type_lowercase(self):
        assert _validate_store_type("PGVECTOR") == "pgvector"
        assert _validate_store_type("chroma") == "chroma"

    def test_unknown_store_type_falls_back_to_custom(self):
        assert _validate_store_type("my_proprietary_db") == "custom"


# ── register_store ────────────────────────────────────────────────────────────

class TestRegisterStore:
    def test_basic_registration(self):
        store = _FakeStore()
        result = register_store("s1", "chroma", "my_collection", "INTERNAL", store)
        assert result["store_id"] == "s1"
        assert result["store_type"] == "chroma"
        assert result["collection_name"] == "my_collection"
        assert result["default_trust_label"] == "INTERNAL"
        assert result["document_count"] == 0

    def test_returns_inventory_version(self):
        store = _FakeStore()
        result = register_store("s2", "pgvector", "col", "VERIFIED", store)
        assert result["inventory_version"] == INVENTORY_VERSION

    def test_empty_store_id_raises(self):
        store = _FakeStore()
        with pytest.raises(RAGInventoryError):
            register_store("", "chroma", "col", "VERIFIED", store)

    def test_invalid_trust_label_raises(self):
        store = _FakeStore()
        with pytest.raises(RAGInventoryError):
            register_store("s3", "chroma", "col", "SKETCHY", store)

    def test_re_registration_preserves_registered_at(self):
        store = _FakeStore()
        r1 = register_store("s4", "chroma", "col", "INTERNAL", store)
        r2 = register_store("s4", "chroma", "col", "VERIFIED", store)
        assert r1["registered_at"] == r2["registered_at"]
        assert r2["default_trust_label"] == "VERIFIED"

    def test_optional_fields(self):
        store = _FakeStore()
        result = register_store(
            "s5", "pinecone", "idx", "EXTERNAL", store,
            endpoint="https://pinecone.io/idx",
            embedding_model="text-embedding-3-small",
            metadata={"owner": "team-a"},
        )
        assert result["embedding_model"] == "text-embedding-3-small"

    def test_unknown_store_type_normalised_to_custom(self):
        store = _FakeStore()
        result = register_store("s6", "my_custom_db", "col", "VERIFIED", store)
        assert result["store_type"] == "custom"


# ── get_vector_store ──────────────────────────────────────────────────────────

class TestGetVectorStore:
    def test_get_existing_store(self):
        store = _FakeStore()
        register_store("g1", "chroma", "col", "VERIFIED", store)
        result = get_vector_store("g1", store)
        assert result is not None
        assert result["store_id"] == "g1"

    def test_get_nonexistent_store_returns_none(self):
        store = _FakeStore()
        assert get_vector_store("nonexistent", store) is None


# ── list_vector_stores ────────────────────────────────────────────────────────

class TestListVectorStores:
    def test_list_empty(self):
        store = _FakeStore()
        assert list_vector_stores(store) == []

    def test_list_returns_registered_stores(self):
        store = _FakeStore()
        register_store("a", "chroma", "col", "INTERNAL", store)
        register_store("b", "pgvector", "col2", "VERIFIED", store)
        results = list_vector_stores(store)
        ids = {r["store_id"] for r in results}
        assert "a" in ids and "b" in ids

    def test_list_respects_limit(self):
        store = _FakeStore()
        for i in range(5):
            register_store(f"store_{i}", "chroma", "col", "INTERNAL", store)
        results = list_vector_stores(store, limit=3)
        assert len(results) <= 3

    def test_list_excludes_non_rag_records(self):
        store = _FakeStore()
        # Insert a non-RAG model record
        store.save_model({"model_id": "some_other_model", "metadata": {}})
        results = list_vector_stores(store)
        assert all(r.get("store_id") is not None for r in results)


# ── register_document ─────────────────────────────────────────────────────────

class TestRegisterDocument:
    def _make_store_with_s(self, store_id="s"):
        store = _FakeStore()
        register_store(store_id, "chroma", "col", "INTERNAL", store)
        return store

    def test_basic_document_registration(self):
        store = self._make_store_with_s()
        doc = register_document("s", "doc1", "abc123", "INTERNAL", "internal", store)
        assert doc["doc_id"] == "doc1"
        assert doc["content_hash"] == "abc123"
        assert doc["trust_label"] == "INTERNAL"
        assert doc["source_type"] == "internal"

    def test_document_store_not_found_raises(self):
        store = _FakeStore()
        with pytest.raises(RAGInventoryError, match="not found"):
            register_document("no_such", "d1", "hash", "INTERNAL", "web", store)

    def test_document_invalid_trust_label_raises(self):
        store = self._make_store_with_s()
        with pytest.raises(RAGInventoryError):
            register_document("s", "d2", "hash", "SKETCHY", "web", store)

    def test_document_with_scan_result_embeds_status(self):
        store = self._make_store_with_s()
        scan = {"status": "CLEAN", "finding_count": 0, "scanned_at": "2026-06-01T00:00:00Z"}
        doc = register_document("s", "d3", "hash", "EXTERNAL", "web", store,
                                scan_result=scan)
        assert doc["scan_status"] == "CLEAN"
        assert doc["scan_finding_count"] == 0

    def test_document_re_registration_preserves_registered_at(self):
        store = self._make_store_with_s()
        d1 = register_document("s", "d4", "hash1", "INTERNAL", "internal", store)
        d2 = register_document("s", "d4", "hash2", "VERIFIED", "internal", store)
        assert d1["registered_at"] == d2["registered_at"]
        assert d2["content_hash"] == "hash2"

    def test_source_url_stored(self):
        store = self._make_store_with_s()
        doc = register_document("s", "d5", "hash", "EXTERNAL", "web", store,
                                source_url="https://example.com/doc")
        assert doc["source_url"] == "https://example.com/doc"

    def test_document_appears_in_store_summary(self):
        store = self._make_store_with_s()
        register_document("s", "d6", "hash", "INTERNAL", "internal", store)
        summary = get_vector_store("s", store)
        assert summary["document_count"] == 1
        assert summary["trust_distribution"].get("INTERNAL", 0) == 1


# ── get_document ──────────────────────────────────────────────────────────────

class TestGetDocument:
    def test_get_registered_document(self):
        store = _FakeStore()
        register_store("gs", "chroma", "col", "INTERNAL", store)
        register_document("gs", "doc", "hash", "EXTERNAL", "web", store)
        doc = get_document("gs", "doc", store)
        assert doc is not None
        assert doc["doc_id"] == "doc"

    def test_get_nonexistent_document_returns_none(self):
        store = _FakeStore()
        register_store("gs2", "chroma", "col", "INTERNAL", store)
        assert get_document("gs2", "no_doc", store) is None

    def test_get_from_nonexistent_store_returns_none(self):
        store = _FakeStore()
        assert get_document("no_store", "doc", store) is None


# ── list_documents ────────────────────────────────────────────────────────────

class TestListDocuments:
    def _setup(self):
        store = _FakeStore()
        register_store("ld", "chroma", "col", "INTERNAL", store)
        register_document("ld", "d1", "h1", "INTERNAL", "internal", store)
        register_document("ld", "d2", "h2", "EXTERNAL", "web", store)
        register_document("ld", "d3", "h3", "VERIFIED", "internal", store)
        return store

    def test_list_all_documents(self):
        store = self._setup()
        docs, total = list_documents("ld", store)
        assert total == 3
        assert len(docs) == 3

    def test_nonexistent_store_returns_empty(self):
        store = _FakeStore()
        docs, total = list_documents("no_store", store)
        assert total == 0
        assert docs == []

    def test_pagination_offset(self):
        store = self._setup()
        docs, total = list_documents("ld", store, offset=2, limit=10)
        assert total == 3
        assert len(docs) == 1

    def test_pagination_limit(self):
        store = self._setup()
        docs, total = list_documents("ld", store, limit=2)
        assert total == 3
        assert len(docs) == 2

    def test_filter_by_trust_label(self):
        store = self._setup()
        docs, total = list_documents("ld", store, trust_label="EXTERNAL")
        assert total == 1
        assert docs[0]["trust_label"] == "EXTERNAL"

    def test_filter_no_match_returns_empty(self):
        store = self._setup()
        docs, total = list_documents("ld", store, trust_label="UNTRUSTED")
        assert total == 0
        assert docs == []


# ── Store summary trust distribution ─────────────────────────────────────────

class TestStoreSummaryTrustDistribution:
    def test_trust_distribution_counts(self):
        store = _FakeStore()
        register_store("td", "chroma", "col", "INTERNAL", store)
        register_document("td", "d1", "h1", "INTERNAL", "internal", store)
        register_document("td", "d2", "h2", "INTERNAL", "internal", store)
        register_document("td", "d3", "h3", "EXTERNAL", "web", store)
        summary = get_vector_store("td", store)
        assert summary["trust_distribution"]["INTERNAL"] == 2
        assert summary["trust_distribution"]["EXTERNAL"] == 1
        assert summary["document_count"] == 3

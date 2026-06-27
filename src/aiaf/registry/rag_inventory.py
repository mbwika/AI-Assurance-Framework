"""RAG Vector-Store Inventory.

Maintains a registry of vector stores and the trust labels attached to their
documents.  Every document ingested into a RAG pipeline should be registered
here before ingestion so that security posture can be assessed at retrieval
time.

Design notes
------------
* Raw document content is never stored — only ``content_hash`` (SHA-256).
* Trust labels are the primary evidence signal: a document's trust label
  determines how aggressively its retrieved content is scrutinised and what
  verdict cap applies in the adoption engine.
* Storage uses the existing AIAF model store under two key namespaces:
  ``"rag_store:{store_id}"`` for store metadata, with document metadata
  embedded in ``metadata.documents`` (capped at MAX_DOCS_PER_STORE).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

INVENTORY_VERSION = "1.0"

_STORE_PREFIX = "rag_store:"
MAX_DOCS_PER_STORE = 10_000

# ── Trust labels ──────────────────────────────────────────────────────────────

TRUST_VERIFIED = "VERIFIED"        # internal, cryptographically signed, known-clean
TRUST_INTERNAL = "INTERNAL"        # internal documents, not externally verified
TRUST_EXTERNAL = "EXTERNAL"        # externally sourced, unverified
TRUST_USER_GENERATED = "USER_GENERATED"  # user-uploaded, potentially adversarial
TRUST_UNTRUSTED = "UNTRUSTED"      # explicitly flagged as high-risk

TRUST_LABELS = frozenset({
    TRUST_VERIFIED, TRUST_INTERNAL, TRUST_EXTERNAL,
    TRUST_USER_GENERATED, TRUST_UNTRUSTED,
})

TRUST_RANK: dict[str, int] = {
    TRUST_VERIFIED: 5,
    TRUST_INTERNAL: 4,
    TRUST_EXTERNAL: 3,
    TRUST_USER_GENERATED: 2,
    TRUST_UNTRUSTED: 1,
}

# ── Source types ──────────────────────────────────────────────────────────────

SOURCE_INTERNAL = "internal"
SOURCE_WEB = "web"
SOURCE_USER_UPLOAD = "user_upload"
SOURCE_API = "api"
SOURCE_DATABASE = "database"
SOURCE_UNKNOWN = "unknown"

SOURCE_TYPES = frozenset({
    SOURCE_INTERNAL, SOURCE_WEB, SOURCE_USER_UPLOAD,
    SOURCE_API, SOURCE_DATABASE, SOURCE_UNKNOWN,
})

# ── Known vector store backends ───────────────────────────────────────────────

KNOWN_STORE_TYPES = frozenset({
    "pgvector", "pinecone", "weaviate", "chroma", "qdrant", "milvus",
    "faiss", "opensearch", "elasticsearch", "redis", "azure_ai_search",
    "vertex_ai_search", "amazon_kendra", "turbopuffer", "custom",
})

# ── Store security posture fields ────────────────────────────────────────────

ACCESS_CONTROL_ENFORCED = "ENFORCED"
ACCESS_CONTROL_REVIEWED_SHARED = "REVIEWED_SHARED"
ACCESS_CONTROL_SHARED = "SHARED"
ACCESS_CONTROL_OPEN = "OPEN"
ACCESS_CONTROL_UNKNOWN = "UNKNOWN"

ACCESS_CONTROL_MODES = frozenset({
    ACCESS_CONTROL_ENFORCED,
    ACCESS_CONTROL_REVIEWED_SHARED,
    ACCESS_CONTROL_SHARED,
    ACCESS_CONTROL_OPEN,
    ACCESS_CONTROL_UNKNOWN,
})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _store_key(store_id: str) -> str:
    return f"{_STORE_PREFIX}{store_id}"


class RAGInventoryError(ValueError):
    pass


def _validate_trust_label(label: str) -> str:
    label = str(label).upper().strip()
    if label not in TRUST_LABELS:
        raise RAGInventoryError(
            f"Invalid trust label {label!r}; valid: {sorted(TRUST_LABELS)}"
        )
    return label


def _validate_source_type(source_type: str) -> str:
    st = str(source_type).lower().strip()
    return st if st in SOURCE_TYPES else SOURCE_UNKNOWN


def _validate_store_type(store_type: str) -> str:
    st = str(store_type).lower().strip()
    return st if st in KNOWN_STORE_TYPES else "custom"


def _validate_access_control_mode(mode: str | None) -> str:
    normalized = str(mode or ACCESS_CONTROL_UNKNOWN).upper().strip()
    if normalized not in ACCESS_CONTROL_MODES:
        raise RAGInventoryError(
            f"Invalid access_control_mode {normalized!r}; valid: {sorted(ACCESS_CONTROL_MODES)}"
        )
    return normalized


# ── Store operations ──────────────────────────────────────────────────────────

def register_store(
    store_id: str,
    store_type: str,
    collection_name: str,
    default_trust_label: str,
    store: Any,
    *,
    endpoint: str | None = None,
    embedding_model: str | None = None,
    access_control_mode: str | None = None,
    tenant_isolation: bool | None = None,
    last_indexed_at: str | None = None,
    freshness_sla_hours: int | None = None,
    embedding_source_url: str | None = None,
    embedding_source_trust: str | None = None,
    embedding_verified: bool | None = None,
    pii_screening_enabled: bool | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register a vector store in the inventory.

    Parameters
    ----------
    store_id:
        Logical identifier for this vector store.
    store_type:
        Backend technology (``"pgvector"``, ``"pinecone"``, ``"chroma"``, …).
    collection_name:
        Collection / index name within the store.
    default_trust_label:
        Default trust label applied to documents that don't specify one.
    store:
        AIAF model store.
    endpoint:
        Optional connection endpoint (never used for outbound calls — stored
        for operator reference only).
    embedding_model:
        Embedding model name used to generate vectors in this store.
    """
    if not store_id or not str(store_id).strip():
        raise RAGInventoryError("store_id must be non-empty")
    store_id = str(store_id).strip()
    default_trust_label = _validate_trust_label(default_trust_label)
    store_type = _validate_store_type(store_type)
    access_control_mode = _validate_access_control_mode(access_control_mode)
    embedding_source_trust = (
        _validate_trust_label(embedding_source_trust)
        if embedding_source_trust is not None
        else None
    )
    if freshness_sla_hours is not None and int(freshness_sla_hours) <= 0:
        raise RAGInventoryError("freshness_sla_hours must be positive when supplied")

    now = _utc_now()
    key = _store_key(store_id)
    existing = store.get_model(key) or {}
    existing_meta = existing.get("metadata") or {}

    record: dict[str, Any] = {
        "model_id": key,
        "id": key,
        "metadata": {
            **existing_meta,
            "store_id": store_id,
            "store_type": store_type,
            "collection_name": str(collection_name).strip(),
            "default_trust_label": default_trust_label,
            "endpoint": str(endpoint).strip() if endpoint else None,
            "embedding_model": str(embedding_model).strip() if embedding_model else None,
            "access_control_mode": access_control_mode,
            "tenant_isolation": tenant_isolation,
            "last_indexed_at": str(last_indexed_at).strip() if last_indexed_at else None,
            "freshness_sla_hours": int(freshness_sla_hours) if freshness_sla_hours else None,
            "embedding_source_url": (
                str(embedding_source_url).strip() if embedding_source_url else None
            ),
            "embedding_source_trust": embedding_source_trust,
            "embedding_verified": embedding_verified,
            "pii_screening_enabled": pii_screening_enabled,
            "inventory_version": INVENTORY_VERSION,
            "registered_at": existing_meta.get("registered_at") or now,
            "updated_at": now,
            "documents": existing_meta.get("documents") or {},
            "extra": metadata or {},
        },
    }
    store.save_model(record)
    return _store_summary(record)


def get_vector_store(store_id: str, store: Any) -> dict[str, Any] | None:
    """Return the inventory record for ``store_id``, or ``None``."""
    record = store.get_model(_store_key(store_id))
    if not record:
        return None
    return _store_summary(record)


def list_vector_stores(store: Any, limit: int = 50) -> list[dict[str, Any]]:
    """List registered vector stores, newest first."""
    all_models = store.list_models() if hasattr(store, "list_models") else []
    result = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_STORE_PREFIX):
            continue
        result.append(_store_summary(m))
    result.sort(key=lambda s: s.get("registered_at") or "", reverse=True)
    return result[:limit]


def _store_summary(record: dict[str, Any]) -> dict[str, Any]:
    meta = record.get("metadata") or {}
    docs = meta.get("documents") or {}
    trust_dist: dict[str, int] = {}
    for doc in docs.values():
        tl = doc.get("trust_label", "UNKNOWN")
        trust_dist[tl] = trust_dist.get(tl, 0) + 1
    return {
        "store_id": meta.get("store_id"),
        "store_type": meta.get("store_type"),
        "collection_name": meta.get("collection_name"),
        "default_trust_label": meta.get("default_trust_label"),
        "embedding_model": meta.get("embedding_model"),
        "security_profile": {
            "access_control_mode": meta.get("access_control_mode", ACCESS_CONTROL_UNKNOWN),
            "tenant_isolation": meta.get("tenant_isolation"),
            "last_indexed_at": meta.get("last_indexed_at"),
            "freshness_sla_hours": meta.get("freshness_sla_hours"),
            "embedding_source_url": meta.get("embedding_source_url"),
            "embedding_source_trust": meta.get("embedding_source_trust"),
            "embedding_verified": meta.get("embedding_verified"),
            "pii_screening_enabled": meta.get("pii_screening_enabled"),
        },
        "document_count": len(docs),
        "trust_distribution": trust_dist,
        "registered_at": meta.get("registered_at"),
        "updated_at": meta.get("updated_at"),
        "inventory_version": meta.get("inventory_version", INVENTORY_VERSION),
    }


# ── Document operations ───────────────────────────────────────────────────────

def register_document(
    store_id: str,
    doc_id: str,
    content_hash: str,
    trust_label: str,
    source_type: str,
    store: Any,
    *,
    source_url: str | None = None,
    metadata: dict[str, Any] | None = None,
    scan_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register a document (or batch-update its metadata) in the inventory.

    Parameters
    ----------
    store_id:
        Vector store that will contain this document.
    doc_id:
        Unique document identifier within the store.
    content_hash:
        SHA-256 of the document content (caller computes).  Raw content is
        never stored.
    trust_label:
        Trust level assigned to this document.
    source_type:
        Origin of the document (``"internal"``, ``"web"``, ``"user_upload"``, …).
    scan_result:
        Optional pre-ingestion scan result from
        :func:`aiaf.analysis.rag_security.scan_document_for_ingestion`.
    """
    store_id = str(store_id).strip()
    doc_id = str(doc_id).strip()
    trust_label = _validate_trust_label(trust_label)
    source_type = _validate_source_type(source_type)

    key = _store_key(store_id)
    record = store.get_model(key)
    if not record:
        raise RAGInventoryError(
            f"Vector store '{store_id}' not found — register it first."
        )

    meta = record.setdefault("metadata", {})
    docs: dict[str, Any] = meta.setdefault("documents", {})

    if len(docs) >= MAX_DOCS_PER_STORE and doc_id not in docs:
        raise RAGInventoryError(
            f"Store '{store_id}' has reached the document limit ({MAX_DOCS_PER_STORE})."
        )

    now = _utc_now()
    existing_doc = docs.get(doc_id) or {}
    doc_record: dict[str, Any] = {
        "doc_id": doc_id,
        "content_hash": str(content_hash).strip(),
        "trust_label": trust_label,
        "source_type": source_type,
        "source_url": str(source_url).strip() if source_url else None,
        "extra": metadata or {},
        "registered_at": existing_doc.get("registered_at") or now,
        "updated_at": now,
    }
    if scan_result is not None:
        doc_record["scan_status"] = scan_result.get("status")
        doc_record["scan_finding_count"] = scan_result.get("finding_count", 0)
        doc_record["scanned_at"] = scan_result.get("scanned_at")

    docs[doc_id] = doc_record
    meta["updated_at"] = now
    meta["documents"] = docs
    record["metadata"] = meta
    store.save_model(record)
    return doc_record


def get_document(store_id: str, doc_id: str, store: Any) -> dict[str, Any] | None:
    """Return the inventory record for a document, or ``None``."""
    record = store.get_model(_store_key(store_id))
    if not record:
        return None
    docs = (record.get("metadata") or {}).get("documents") or {}
    return docs.get(doc_id)


def list_documents(
    store_id: str,
    store: Any,
    offset: int = 0,
    limit: int = 100,
    trust_label: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return a paginated list of documents in a store.

    Optionally filter by ``trust_label``.
    """
    record = store.get_model(_store_key(store_id))
    if not record:
        return [], 0
    docs = list((record.get("metadata") or {}).get("documents", {}).values())
    if trust_label:
        tl = str(trust_label).upper()
        docs = [d for d in docs if d.get("trust_label") == tl]
    total = len(docs)
    return docs[offset: offset + limit], total

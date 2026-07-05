"""RAG Security API.

Routes
------
POST /v1/rag/stores               Register a vector store in the inventory
GET  /v1/rag/stores               List registered vector stores
GET  /v1/rag/stores/{store_id}    Get a single store's inventory record

POST /v1/rag/stores/{store_id}/documents        Register a document
GET  /v1/rag/stores/{store_id}/documents        List documents (paginated)
GET  /v1/rag/stores/{store_id}/assessment       Security posture assessment

POST /v1/rag/scan/chunks          Scan retrieved chunks for injection / leakage
POST /v1/rag/scan/document        Scan a document before ingestion

POST /v1/rag/stores/{store_id}/gate   Pre-model taint gate decision (ALLOW/FLAG/DENY)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..analysis.rag_security import (
    assess_store_security,
    scan_chunks,
    scan_document_for_ingestion,
)
from ..core.rag_taint_gate import RagTaintGateError, gate_rag_context
from ..registry.rag_inventory import (
    ACCESS_CONTROL_MODES,
    INVENTORY_VERSION,
    SOURCE_TYPES,
    TRUST_LABELS,
    RAGInventoryError,
    get_vector_store,
    list_documents,
    list_vector_stores,
    register_document,
    register_store,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/rag", tags=["rag"])


# ── Request / response models ─────────────────────────────────────────────────

class RegisterStoreRequest(BaseModel):
    store_id: str = Field(..., description="Logical identifier for this vector store")
    store_type: str = Field(..., description="Backend (pgvector, chroma, pinecone, …)")
    collection_name: str = Field(..., description="Collection / index name")
    default_trust_label: str = Field(
        ..., description=f"Default document trust label; one of {sorted(TRUST_LABELS)}"
    )
    endpoint: str | None = Field(None, description="Connection endpoint (reference only)")
    embedding_model: str | None = Field(None, description="Embedding model name")
    access_control_mode: str | None = Field(
        None, description=f"Access posture; one of {sorted(ACCESS_CONTROL_MODES)}"
    )
    tenant_isolation: bool | None = Field(
        None, description="Whether tenant or collection isolation is enforced"
    )
    last_indexed_at: str | None = Field(
        None, description="Last successful index refresh timestamp (ISO-8601 UTC)"
    )
    freshness_sla_hours: int | None = Field(
        None, ge=1, description="Maximum acceptable age of the retrieval index"
    )
    embedding_source_url: str | None = Field(
        None, description="Canonical source for the embedding model or service"
    )
    embedding_source_trust: str | None = Field(
        None, description=f"Trust label for embedding provenance; one of {sorted(TRUST_LABELS)}"
    )
    embedding_verified: bool | None = Field(
        None, description="Whether embedding provenance has been independently verified"
    )
    pii_screening_enabled: bool | None = Field(
        None, description="Whether documents are screened for secrets/PII before indexing"
    )
    metadata: dict[str, Any] | None = Field(None, description="Arbitrary extra fields")


class RegisterDocumentRequest(BaseModel):
    doc_id: str = Field(..., description="Unique document ID within the store")
    content_hash: str = Field(..., description="SHA-256 of the document content")
    trust_label: str = Field(
        ..., description=f"Trust level; one of {sorted(TRUST_LABELS)}"
    )
    source_type: str = Field(
        ..., description=f"Document origin; one of {sorted(SOURCE_TYPES)}"
    )
    source_url: str | None = Field(None, description="Optional source URL")
    metadata: dict[str, Any] | None = Field(None, description="Arbitrary extra fields")
    scan_result: dict[str, Any] | None = Field(
        None, description="Pre-ingestion scan result (from /v1/rag/scan/document)"
    )


class ChunkItem(BaseModel):
    content: str = Field(..., description="Text content of this chunk")
    doc_id: str | None = Field(None, description="Source document ID")
    trust_label: str | None = Field(None, description="Trust label for this chunk")
    metadata: dict[str, Any] | None = None


class ScanChunksRequest(BaseModel):
    chunks: list[ChunkItem] = Field(..., description="Retrieved chunks to scan")
    minimum_trust_label: str | None = Field(
        None, description="Minimum acceptable trust label; violations are flagged"
    )
    scan_for_leakage: bool = Field(True, description="Check chunks for PII/credentials")


class ScanDocumentRequest(BaseModel):
    content: str = Field(..., description="Document text to scan")
    trust_label: str = Field(..., description="Intended trust label for this document")
    doc_id: str | None = Field(None, description="Document identifier (echoed in output)")
    scan_for_leakage: bool = Field(True, description="Check for PII/credentials")


class GateChunksRequest(BaseModel):
    session_id: str = Field(..., description="Agent/conversation session this retrieval belongs to")
    chunks: list[ChunkItem] = Field(..., description="Retrieved chunks about to reach the model")
    agent_id: str | None = Field(None, description="Agent identity making the retrieval")
    minimum_trust_label: str | None = Field(
        None, description="Minimum acceptable trust label; violations raise taint"
    )
    flag_at_or_above: str | None = Field(None, description="Taint level at/above which verdict is FLAG")
    deny_at_or_above: str | None = Field(None, description="Taint level at/above which verdict is DENY")


# ── Vector store routes ───────────────────────────────────────────────────────

@router.post("/stores", status_code=status.HTTP_201_CREATED)
def register_vector_store(
    req: RegisterStoreRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Register a vector store in the AIAF inventory."""
    try:
        result = register_store(
            store_id=req.store_id,
            store_type=req.store_type,
            collection_name=req.collection_name,
            default_trust_label=req.default_trust_label,
            store=store,
            endpoint=req.endpoint,
            embedding_model=req.embedding_model,
            access_control_mode=req.access_control_mode,
            tenant_isolation=req.tenant_isolation,
            last_indexed_at=req.last_indexed_at,
            freshness_sla_hours=req.freshness_sla_hours,
            embedding_source_url=req.embedding_source_url,
            embedding_source_trust=req.embedding_source_trust,
            embedding_verified=req.embedding_verified,
            pii_screening_enabled=req.pii_screening_enabled,
            metadata=req.metadata,
        )
    except RAGInventoryError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"inventory_version": INVENTORY_VERSION, **result}


@router.get("/stores")
def list_stores(
    limit: int = 50,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """List all registered vector stores."""
    stores = list_vector_stores(store, limit=limit)
    return {
        "inventory_version": INVENTORY_VERSION,
        "count": len(stores),
        "stores": stores,
    }


@router.get("/stores/{store_id}")
def get_store_record(
    store_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Return the inventory record for a single vector store."""
    rec = get_vector_store(store_id, store)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Store '{store_id}' not found.")
    return {"inventory_version": INVENTORY_VERSION, **rec}


# ── Document routes ───────────────────────────────────────────────────────────

@router.post("/stores/{store_id}/documents", status_code=status.HTTP_201_CREATED)
def register_doc(
    store_id: str,
    req: RegisterDocumentRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Register a document in the vector store inventory."""
    try:
        doc = register_document(
            store_id=store_id,
            doc_id=req.doc_id,
            content_hash=req.content_hash,
            trust_label=req.trust_label,
            source_type=req.source_type,
            store=store,
            source_url=req.source_url,
            metadata=req.metadata,
            scan_result=req.scan_result,
        )
    except RAGInventoryError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"inventory_version": INVENTORY_VERSION, "store_id": store_id, **doc}


@router.get("/stores/{store_id}/documents")
def list_docs(
    store_id: str,
    offset: int = 0,
    limit: int = 100,
    trust_label: str | None = None,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """List documents registered in a vector store (paginated)."""
    if get_vector_store(store_id, store) is None:
        raise HTTPException(status_code=404, detail=f"Store '{store_id}' not found.")
    docs, total = list_documents(store_id, store, offset=offset, limit=limit,
                                  trust_label=trust_label)
    return {
        "store_id": store_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "documents": docs,
    }


# ── Security assessment ───────────────────────────────────────────────────────

@router.get("/stores/{store_id}/assessment")
def store_assessment(
    store_id: str,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Return the security posture assessment for a vector store."""
    result = assess_store_security(store_id, store)
    if result.get("status") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/stores/{store_id}/gate")
def gate_retrieved_chunks(
    store_id: str,
    req: GateChunksRequest,
    _key: str = Depends(get_api_key),
    store: Any = Depends(get_store),
):
    """Pre-model taint gate: assess retrieved chunks and log an ALLOW/FLAG/DENY

    decision to the agent-action ledger before the chunks reach the model.
    """
    if get_vector_store(store_id, store) is None:
        raise HTTPException(status_code=404, detail=f"Store '{store_id}' not found.")
    kwargs: dict[str, Any] = {}
    if req.flag_at_or_above is not None:
        kwargs["flag_at_or_above"] = req.flag_at_or_above
    if req.deny_at_or_above is not None:
        kwargs["deny_at_or_above"] = req.deny_at_or_above
    try:
        result = gate_rag_context(
            req.session_id,
            [c.model_dump() for c in req.chunks],
            store,
            agent_id=req.agent_id,
            store_id=store_id,
            minimum_trust_label=req.minimum_trust_label,
            **kwargs,
        )
    except RagTaintGateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


# ── Scan routes ───────────────────────────────────────────────────────────────

@router.post("/scan/chunks")
def scan_retrieved_chunks(
    req: ScanChunksRequest,
    _key: str = Depends(get_api_key),
    _store: Any = Depends(get_store),
):
    """Scan a list of retrieved RAG chunks for injection and leakage."""
    chunks_raw = [c.model_dump() for c in req.chunks]
    result = scan_chunks(
        chunks_raw,
        minimum_trust_label=req.minimum_trust_label,
        scan_for_leakage=req.scan_for_leakage,
    )
    return result


@router.post("/scan/document")
def scan_document(
    req: ScanDocumentRequest,
    _key: str = Depends(get_api_key),
    _store: Any = Depends(get_store),
):
    """Scan a document before ingesting it into a vector store."""
    result = scan_document_for_ingestion(
        content=req.content,
        trust_label=req.trust_label,
        doc_id=req.doc_id,
        scan_for_leakage=req.scan_for_leakage,
    )
    return result

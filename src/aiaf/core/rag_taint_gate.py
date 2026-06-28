"""Pre-model RAG taint gate with ledger logging."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ..analysis.rag_security import (
    TAINT_CRITICAL,
    TAINT_HIGH,
    TAINT_LOW,
    TAINT_MEDIUM,
    TAINT_NONE,
    TAINT_VERSION,
    label_rag_taint,
)
from ..registry.rag_inventory import get_vector_store
from .agent_action_ledger import append_entry

RAG_TAINT_GATE_VERSION = "1.0"

VERDICT_ALLOW = "ALLOW"
VERDICT_FLAG = "FLAG"
VERDICT_DENY = "DENY"

_TAINT_RANK = {
    TAINT_NONE: 0,
    TAINT_LOW: 1,
    TAINT_MEDIUM: 2,
    TAINT_HIGH: 3,
    TAINT_CRITICAL: 4,
}


class RagTaintGateError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_chunks(chunks: list[dict[str, Any]]) -> str:
    sanitized = []
    for chunk in chunks:
        metadata = chunk.get("metadata") or {}
        content = str(chunk.get("content") or "")
        sanitized.append({
            "doc_id": chunk.get("doc_id"),
            "content_hash": chunk.get("content_hash") or hashlib.sha256(content.encode()).hexdigest(),
            "trust_label": chunk.get("trust_label"),
            "sensitivity_label": chunk.get("sensitivity_label") or metadata.get("sensitivity_label"),
            "updated_at": (
                chunk.get("updated_at")
                or chunk.get("indexed_at")
                or metadata.get("updated_at")
                or metadata.get("indexed_at")
            ),
        })
    body = json.dumps(sanitized, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _resolve_freshness_sla(
    store_id: str | None,
    store: Any,
    freshness_sla_hours: int | None,
) -> int | None:
    if freshness_sla_hours is not None or not store_id:
        return freshness_sla_hours
    store_record = get_vector_store(store_id, store)
    if store_record is None:
        return None
    security_profile = store_record.get("security_profile") or {}
    value = security_profile.get("freshness_sla_hours")
    return int(value) if value is not None else None


def _verdict_from_taint(
    overall_taint: str,
    *,
    flag_at_or_above: str,
    deny_at_or_above: str,
) -> str:
    overall_rank = _TAINT_RANK.get(overall_taint, 0)
    if overall_rank >= _TAINT_RANK.get(deny_at_or_above, 99):
        return VERDICT_DENY
    if overall_rank >= _TAINT_RANK.get(flag_at_or_above, 99):
        return VERDICT_FLAG
    return VERDICT_ALLOW


def gate_rag_context(
    session_id: str,
    chunks: list[dict[str, Any]],
    store: Any,
    *,
    agent_id: str | None = None,
    store_id: str | None = None,
    minimum_trust_label: str | None = None,
    freshness_sla_hours: int | None = None,
    flag_at_or_above: str = TAINT_MEDIUM,
    deny_at_or_above: str = TAINT_HIGH,
) -> dict[str, Any]:
    """Assess retrieved RAG context before it reaches the model and log the decision."""
    if not str(session_id).strip():
        raise RagTaintGateError("session_id must be non-empty")

    effective_sla = _resolve_freshness_sla(store_id, store, freshness_sla_hours)
    taint = label_rag_taint(
        chunks,
        minimum_trust_label=minimum_trust_label,
        freshness_sla_hours=effective_sla,
    )
    verdict = _verdict_from_taint(
        taint["overall_taint"],
        flag_at_or_above=flag_at_or_above,
        deny_at_or_above=deny_at_or_above,
    )

    reasons = [f"Overall RAG taint assessed as {taint['overall_taint']}."]
    for chunk in taint["chunk_labels"]:
        if chunk["overall_taint"] in {TAINT_HIGH, TAINT_CRITICAL}:
            reasons.append(
                f"Chunk {chunk['chunk_index']} ({chunk.get('doc_id') or 'unknown'}) "
                f"has taint {chunk['overall_taint']}."
            )

    ledger_entry = append_entry(
        session_id=session_id,
        tool_name="rag:pre_model_gate",
        input_hash=_hash_chunks(chunks),
        decision=verdict,
        store=store,
        timestamp=_utc_now(),
        metadata={
            "agent_id": agent_id,
            "store_id": store_id,
            "overall_taint": taint["overall_taint"],
            "finding_count": taint["finding_count"],
            "chunk_count": taint["chunk_count"],
            "minimum_trust_label": taint["minimum_trust_label"],
            "freshness_sla_hours": taint["freshness_sla_hours"],
            "taint_version": TAINT_VERSION,
        },
    )

    return {
        "gate_version": RAG_TAINT_GATE_VERSION,
        "session_id": session_id,
        "agent_id": agent_id,
        "store_id": store_id,
        "verdict": verdict,
        "reasons": reasons,
        "taint_assessment": taint,
        "ledger_entry_id": ledger_entry["entry_id"],
        "ledger_sequence": ledger_entry["sequence"],
        "decided_at": ledger_entry["timestamp"],
        "evidence_origin": "LOCALLY_OBSERVED",
    }

"""Agent Action Ledger.

Hash-chained, tamper-evident, append-only log of every tool invocation
made by an agent session.

Each ledger entry records:
  * session_id     — logical agent session
  * entry_id       — UUID-like unique identifier
  * sequence       — monotonically increasing within session (0, 1, 2, …)
  * tool_name      — name of the tool called
  * input_hash     — SHA-256 of sanitised tool arguments (caller computes)
  * decision       — ALLOW | DENY | FLAG
  * timestamp      — ISO 8601 UTC
  * prev_entry_sha256 — SHA-256 of the *previous* entry's canonical payload
                        (genesis sentinel ``"0" * 64`` for the first entry)
  * entry_hash     — SHA-256 of this entry's canonical payload (includes
                     prev_entry_sha256, making the chain tamper-evident)

Chain verification replays every entry in sequence order, recomputes its
entry_hash, and confirms prev_entry_sha256 matches the previous entry.  Any
discrepancy indicates tampering or out-of-order insertion.

Storage uses the existing AIAF model store under the ``"ledger:{session_id}"``
namespace — no new persistence infrastructure required.

Compliance alignment
--------------------
* NIST AI RMF GOVERN-1.7 — agentic-AI action-logging / auditability
* EU AI Act Article 12   — logging obligations for high-risk AI systems
* OWASP LLM06            — Excessive Agency (audit trail for tool calls)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

LEDGER_VERSION = "1.0"
_LEDGER_PREFIX = "ledger:"
_GENESIS_HASH = "0" * 64
_VALID_DECISIONS = frozenset({"ALLOW", "DENY", "FLAG"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ledger_key(session_id: str) -> str:
    return f"{_LEDGER_PREFIX}{session_id}"


def _entry_payload(entry: dict[str, Any]) -> str:
    """Return the canonical JSON string used to hash a ledger entry."""
    return json.dumps(
        {
            "session_id": entry["session_id"],
            "entry_id": entry["entry_id"],
            "sequence": entry["sequence"],
            "tool_name": entry["tool_name"],
            "input_hash": entry["input_hash"],
            "decision": entry["decision"],
            "timestamp": entry["timestamp"],
            "prev_entry_sha256": entry["prev_entry_sha256"],
        },
        sort_keys=True,
        ensure_ascii=True,
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _compute_entry_hash(entry: dict[str, Any]) -> str:
    return _sha256(_entry_payload(entry))


class LedgerValidationError(ValueError):
    pass


def _validate_session_id(session_id: str) -> str:
    if not session_id or not str(session_id).strip():
        raise LedgerValidationError("session_id must be a non-empty string")
    return str(session_id).strip()


def _validate_decision(decision: str) -> str:
    d = str(decision).upper().strip()
    if d not in _VALID_DECISIONS:
        raise LedgerValidationError(
            f"decision must be one of {sorted(_VALID_DECISIONS)}, got {decision!r}"
        )
    return d


# ── Core operations ───────────────────────────────────────────────────────────

def append_entry(
    session_id: str,
    tool_name: str,
    input_hash: str,
    decision: str,
    store: Any,
    *,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Append a hash-chained entry to the action ledger for ``session_id``.

    Parameters
    ----------
    session_id:
        Logical agent session identifier.  Must match the telemetry session
        if cross-referencing is needed.
    tool_name:
        Name of the tool that was (or would be) invoked.
    input_hash:
        SHA-256 of the sanitised tool arguments (caller computes; raw args
        are never stored in the ledger).
    decision:
        ``"ALLOW"``, ``"DENY"``, or ``"FLAG"``.
    store:
        AIAF model store.
    metadata:
        Optional structured context (model_id, risk_tier, policy_ref, …).
    timestamp:
        ISO 8601 UTC string.  Defaults to server time if omitted.
    """
    session_id = _validate_session_id(session_id)
    decision = _validate_decision(decision)
    tool_name = str(tool_name or "").strip() or "unknown"
    input_hash = str(input_hash or "").strip()
    ts = timestamp or _utc_now()

    key = _ledger_key(session_id)
    record = store.get_model(key) or {
        "model_id": key,
        "id": key,
        "metadata": {},
    }
    meta = record.setdefault("metadata", {})
    entries: list[dict[str, Any]] = meta.get("entries") or []

    prev_hash = entries[-1]["entry_hash"] if entries else _GENESIS_HASH
    sequence = len(entries)

    # Build the entry (entry_hash computed last so it covers all fields)
    entry: dict[str, Any] = {
        "session_id": session_id,
        "entry_id": _sha256(f"{session_id}:{sequence}:{ts}"),
        "sequence": sequence,
        "tool_name": tool_name,
        "input_hash": input_hash,
        "decision": decision,
        "timestamp": ts,
        "prev_entry_sha256": prev_hash,
        "ledger_version": LEDGER_VERSION,
        "metadata": metadata or {},
        # placeholder — filled in next line
        "entry_hash": "",
    }
    entry["entry_hash"] = _compute_entry_hash(entry)

    entries.append(entry)
    meta["entries"] = entries
    meta["session_id"] = session_id
    meta["ledger_version"] = LEDGER_VERSION
    meta["entry_count"] = len(entries)
    meta["last_updated_at"] = ts
    meta["registered_at"] = meta.get("registered_at") or ts

    record["metadata"] = meta
    store.save_model(record)

    return entry


def verify_chain(session_id: str, store: Any) -> dict[str, Any]:
    """Verify the hash chain integrity of ``session_id``'s ledger.

    Returns a report with ``chain_valid``, ``entry_count``, and if tampered
    ``tampered_at_sequence`` pointing to the first broken link.
    """
    session_id = _validate_session_id(session_id)
    record = store.get_model(_ledger_key(session_id))
    if not record:
        return {
            "session_id": session_id,
            "chain_valid": False,
            "entry_count": 0,
            "error": "ledger_not_found",
            "verified_at": _utc_now(),
        }

    entries: list[dict[str, Any]] = (record.get("metadata") or {}).get("entries") or []
    if not entries:
        return {
            "session_id": session_id,
            "chain_valid": True,
            "entry_count": 0,
            "verified_at": _utc_now(),
        }

    expected_prev = _GENESIS_HASH
    for i, entry in enumerate(entries):
        # 1. prev_entry_sha256 must match the previous entry's hash
        if entry.get("prev_entry_sha256") != expected_prev:
            return {
                "session_id": session_id,
                "chain_valid": False,
                "entry_count": len(entries),
                "tampered_at_sequence": i,
                "error": "prev_hash_mismatch",
                "verified_at": _utc_now(),
            }
        # 2. entry_hash must match recomputed hash
        recomputed = _compute_entry_hash(entry)
        if entry.get("entry_hash") != recomputed:
            return {
                "session_id": session_id,
                "chain_valid": False,
                "entry_count": len(entries),
                "tampered_at_sequence": i,
                "error": "entry_hash_mismatch",
                "verified_at": _utc_now(),
            }
        expected_prev = entry["entry_hash"]

    return {
        "session_id": session_id,
        "chain_valid": True,
        "entry_count": len(entries),
        "head_hash": entries[-1]["entry_hash"],
        "verified_at": _utc_now(),
    }


def get_ledger(session_id: str, store: Any) -> dict[str, Any] | None:
    """Return the full ledger record for ``session_id``, or ``None``."""
    session_id = _validate_session_id(session_id)
    record = store.get_model(_ledger_key(session_id))
    if not record:
        return None
    meta = record.get("metadata") or {}
    return {
        "session_id": session_id,
        "ledger_version": meta.get("ledger_version", LEDGER_VERSION),
        "entry_count": meta.get("entry_count", 0),
        "entries": meta.get("entries") or [],
        "registered_at": meta.get("registered_at"),
        "last_updated_at": meta.get("last_updated_at"),
    }


def get_ledger_entries(
    session_id: str,
    store: Any,
    offset: int = 0,
    limit: int = 100,
) -> tuple:
    """Return a paginated slice of entries and the total count."""
    session_id = _validate_session_id(session_id)
    record = store.get_model(_ledger_key(session_id))
    if not record:
        return [], 0
    entries = (record.get("metadata") or {}).get("entries") or []
    return entries[offset: offset + limit], len(entries)


def list_ledgers(store: Any, limit: int = 50) -> list[dict[str, Any]]:
    """Return summary metadata for up to ``limit`` ledger sessions."""
    all_models = store.list_models() if hasattr(store, "list_models") else []
    ledgers = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_LEDGER_PREFIX):
            continue
        meta = m.get("metadata") or {}
        entries = meta.get("entries") or []
        decisions = {}
        for e in entries:
            d = e.get("decision", "UNKNOWN")
            decisions[d] = decisions.get(d, 0) + 1
        ledgers.append({
            "session_id": meta.get("session_id") or mid.removeprefix(_LEDGER_PREFIX),
            "entry_count": meta.get("entry_count", 0),
            "by_decision": decisions,
            "last_updated_at": meta.get("last_updated_at"),
            "registered_at": meta.get("registered_at"),
        })
    ledgers.sort(key=lambda x: x.get("last_updated_at") or "", reverse=True)
    return ledgers[:limit]

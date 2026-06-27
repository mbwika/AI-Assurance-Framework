"""Agent Memory Integrity & Poisoning Detection.

Provides runtime assurance for AI agent memory stores — tracking write provenance,
detecting MINJA-style injection, cross-agent contamination, and time-bomb payloads.

Attack vectors modelled
-----------------------
DIRECT_WRITE          — attacker directly writes to a shared memory store
PROMPT_INJECTION      — injected prompt causes agent to write malicious content
CROSS_AGENT_CONTAMINATION — compromised agent propagates payloads to peers
TIME_BOMB             — benign-looking payload activates only after a trigger condition
OVERRIDE_ATTACK       — legitimate key overwritten with malicious value

Provenance tags
---------------
Every memory write carries an evidence_origin label.  Writes originating from
LOCALLY_OBSERVED (the protected application) are fully trusted; those from
external input (PROVIDER_DECLARED, USER_ENTERED) carry elevated suspicion scores.

Integrity status values
-----------------------
STATUS_CLEAN           — no anomalies detected
STATUS_SUSPICIOUS      — one or more soft signals detected; review recommended
STATUS_COMPROMISED     — high-confidence poisoning detected; quarantine recommended

Evidence origin
---------------
LOCALLY_OBSERVED — all memory integrity data is recorded and assessed by AIAF locally.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

MEMORY_INTEGRITY_VERSION = "1.0"

# ── Attack vectors ──────────────────────────────────────────────────────────────
ATTACK_DIRECT_WRITE = "DIRECT_WRITE"
ATTACK_PROMPT_INJECTION = "PROMPT_INJECTION"
ATTACK_CROSS_AGENT_CONTAMINATION = "CROSS_AGENT_CONTAMINATION"
ATTACK_TIME_BOMB = "TIME_BOMB"
ATTACK_OVERRIDE = "OVERRIDE_ATTACK"

ATTACK_VECTORS: frozenset = frozenset({
    ATTACK_DIRECT_WRITE, ATTACK_PROMPT_INJECTION,
    ATTACK_CROSS_AGENT_CONTAMINATION, ATTACK_TIME_BOMB, ATTACK_OVERRIDE,
})

# ── Evidence origin labels ─────────────────────────────────────────────────────
ORIGIN_LOCAL = "LOCALLY_OBSERVED"
ORIGIN_PROVIDER = "PROVIDER_DECLARED"
ORIGIN_USER = "USER_ENTERED"
ORIGIN_EXTERNAL_AGENT = "EXTERNAL_AGENT"
ORIGIN_TOOL = "TOOL_OUTPUT"

_ORIGIN_TRUST: dict[str, float] = {
    ORIGIN_LOCAL: 1.0,
    ORIGIN_PROVIDER: 0.6,
    ORIGIN_USER: 0.4,
    ORIGIN_TOOL: 0.5,
    ORIGIN_EXTERNAL_AGENT: 0.3,
}

# ── Integrity status ───────────────────────────────────────────────────────────
STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_COMPROMISED = "COMPROMISED"

# ── Storage prefixes ───────────────────────────────────────────────────────────
_STORE_PREFIX = "memory_store:"
_ENTRY_PREFIX = "memory_entry:"

# ── Anomaly patterns ───────────────────────────────────────────────────────────
# Strings that suggest prompt injection or time-bomb payloads
_INJECTION_SIGNALS = [
    "ignore previous instructions",
    "disregard your system prompt",
    "you are now",
    "your new instructions",
    "override",
    "forget everything",
    "act as",
    "jailbreak",
    "do not follow",
    "new persona",
]

_TIME_BOMB_SIGNALS = [
    "when you receive",
    "upon next request",
    "if asked about",
    "when triggered",
    "activate when",
    "execute when",
    "respond with the following when",
]


class MemoryIntegrityError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _store_key(store_id: str) -> str:
    return f"{_STORE_PREFIX}{store_id}"


def _entry_key(store_id: str, entry_key_str: str) -> str:
    return f"{_ENTRY_PREFIX}{store_id}:{entry_key_str}"


def _load_meta(record: dict[str, Any] | None) -> dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _anomaly_score(value: str, origin: str) -> float:
    """Return a 0.0–1.0 anomaly score for a memory write value."""
    v = str(value).lower()
    trust = _ORIGIN_TRUST.get(origin, 0.5)

    injection_hits = sum(1 for sig in _INJECTION_SIGNALS if sig in v)
    time_bomb_hits = sum(1 for sig in _TIME_BOMB_SIGNALS if sig in v)

    base_score = 0.0
    if injection_hits:
        base_score = min(0.4 + injection_hits * 0.15, 0.95)
    if time_bomb_hits:
        base_score = max(base_score, min(0.5 + time_bomb_hits * 0.2, 0.95))

    # Low-trust origins amplify the score
    amplification = 1.0 + (1.0 - trust) * 0.5
    return min(base_score * amplification, 1.0)


def _classify_anomaly(score: float, origin: str) -> str | None:
    """Map anomaly score to an attack vector classification."""
    if score == 0.0:
        return None

    if origin == ORIGIN_EXTERNAL_AGENT:
        return ATTACK_CROSS_AGENT_CONTAMINATION
    if origin == ORIGIN_USER:
        return ATTACK_PROMPT_INJECTION
    if origin == ORIGIN_TOOL:
        return ATTACK_PROMPT_INJECTION

    return ATTACK_DIRECT_WRITE


# ── Public API ─────────────────────────────────────────────────────────────────

def register_memory_store(
    store_id: str,
    agent_id: str,
    store: Any,
    *,
    description: str | None = None,
    max_entries: int = 10_000,
) -> dict[str, Any]:
    """Register a memory store for integrity tracking.

    Parameters
    ----------
    store_id:    Unique identifier for this memory store.
    agent_id:    The agent that owns / primarily writes to this store.
    store:       AIAF persistence store.
    """
    if not store_id or not store_id.strip():
        raise MemoryIntegrityError("store_id must be non-empty.")
    if not agent_id or not agent_id.strip():
        raise MemoryIntegrityError("agent_id must be non-empty.")

    record: dict[str, Any] = {
        "model_id": _store_key(store_id),
        "id": _store_key(store_id),
        "metadata": {
            "store_id": store_id,
            "agent_id": agent_id,
            "description": description or "",
            "max_entries": max_entries,
            "entry_count": 0,
            "status": STATUS_CLEAN,
            "anomaly_count": 0,
            "evidence_origin": "LOCALLY_OBSERVED",
            "registered_at": _utc_now(),
            "updated_at": _utc_now(),
        },
    }
    store.save_model(record)
    return _load_meta(store.get_model(_store_key(store_id)))


def get_memory_store(store_id: str, store: Any) -> dict[str, Any] | None:
    """Return memory store metadata, or None if not registered."""
    rec = store.get_model(_store_key(store_id))
    return _load_meta(rec) if rec else None


def write_memory(
    store_id: str,
    key: str,
    value: str,
    origin: str,
    store: Any,
    *,
    writing_agent_id: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Write a value to a tracked memory store.

    Returns the entry record including any anomaly flags.

    Parameters
    ----------
    store_id:         Memory store identifier.
    key:              Memory key being written.
    value:            Value being written.
    origin:           Evidence origin label (use ORIGIN_* constants).
    writing_agent_id: Agent performing the write (may differ from store owner).
    tags:             Optional metadata tags.
    """
    if not store_id or not store_id.strip():
        raise MemoryIntegrityError("store_id must be non-empty.")
    if not key or not key.strip():
        raise MemoryIntegrityError("key must be non-empty.")

    store_meta = get_memory_store(store_id, store)
    if not store_meta:
        raise MemoryIntegrityError(
            f"Memory store {store_id!r} not registered. Call register_memory_store first."
        )

    origin = str(origin).strip()
    score = _anomaly_score(value, origin)
    attack_type = _classify_anomaly(score, origin) if score > 0.0 else None
    trust_weight = _ORIGIN_TRUST.get(origin, 0.5)

    # Check if this key was previously written (override detection)
    existing_entry_rec = store.get_model(_entry_key(store_id, key))
    existing_entry = _load_meta(existing_entry_rec) if existing_entry_rec else None
    is_override = existing_entry is not None

    if is_override and attack_type is None and origin in (ORIGIN_EXTERNAL_AGENT, ORIGIN_USER):
        attack_type = ATTACK_OVERRIDE
        score = max(score, 0.4)

    anomalous = score >= 0.35

    # Detect time-bomb pattern (separate from injection)
    v_lower = str(value).lower()
    time_bomb_hits = sum(1 for sig in _TIME_BOMB_SIGNALS if sig in v_lower)
    if time_bomb_hits:
        attack_type = ATTACK_TIME_BOMB
        score = max(score, 0.5 + time_bomb_hits * 0.15)
        anomalous = True

    entry: dict[str, Any] = {
        "model_id": _entry_key(store_id, key),
        "id": _entry_key(store_id, key),
        "metadata": {
            "store_id": store_id,
            "key": key,
            "value_length": len(str(value)),
            "origin": origin,
            "writing_agent_id": writing_agent_id,
            "trust_weight": trust_weight,
            "anomaly_score": round(score, 4),
            "anomalous": anomalous,
            "attack_vector": attack_type,
            "is_override": is_override,
            "tags": tags or [],
            "evidence_origin": "LOCALLY_OBSERVED",
            "written_at": _utc_now(),
        },
    }
    store.save_model(entry)

    # Update store metadata
    updated_store = dict(store_meta)
    updated_store["entry_count"] = updated_store.get("entry_count", 0) + (0 if is_override else 1)
    if anomalous:
        updated_store["anomaly_count"] = updated_store.get("anomaly_count", 0) + 1
        updated_store["status"] = (
            STATUS_COMPROMISED if score >= 0.7 else STATUS_SUSPICIOUS
        )
    updated_store["updated_at"] = _utc_now()
    store.save_model({
        "model_id": _store_key(store_id),
        "id": _store_key(store_id),
        "metadata": updated_store,
    })

    return _load_meta(store.get_model(_entry_key(store_id, key)))


def get_memory_entry(store_id: str, key: str, store: Any) -> dict[str, Any] | None:
    """Return a memory entry, or None if not found."""
    rec = store.get_model(_entry_key(store_id, key))
    return _load_meta(rec) if rec else None


def list_memory_entries(
    store_id: str,
    store: Any,
    *,
    anomalous_only: bool = False,
    attack_vector: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """List entries in a memory store.

    Parameters
    ----------
    anomalous_only:  Return only entries with anomaly_score >= 0.35.
    attack_vector:   Filter by specific attack vector.
    limit:           Maximum entries to return.
    """
    prefix = _entry_key(store_id, "")
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(prefix):
            continue
        meta = _load_meta(rec)
        if anomalous_only and not meta.get("anomalous", False):
            continue
        if attack_vector and meta.get("attack_vector") != attack_vector:
            continue
        results.append(meta)
        if len(results) >= limit:
            break
    return results


def assess_memory_integrity(store_id: str, store: Any) -> dict[str, Any]:
    """Return a full integrity assessment report for a memory store."""
    store_meta = get_memory_store(store_id, store)
    if not store_meta:
        raise MemoryIntegrityError(f"Memory store {store_id!r} not registered.")

    entries = list_memory_entries(store_id, store, limit=10_000)
    anomalous = [e for e in entries if e.get("anomalous", False)]

    by_vector: dict[str, int] = {}
    for e in anomalous:
        av = e.get("attack_vector") or "UNKNOWN"
        by_vector[av] = by_vector.get(av, 0) + 1

    max_score = max((e.get("anomaly_score", 0.0) for e in anomalous), default=0.0)
    compromised_entries = [e for e in anomalous if e.get("anomaly_score", 0.0) >= 0.7]

    if compromised_entries:
        overall_status = STATUS_COMPROMISED
    elif anomalous:
        overall_status = STATUS_SUSPICIOUS
    else:
        overall_status = STATUS_CLEAN

    return {
        "store_id": store_id,
        "agent_id": store_meta.get("agent_id"),
        "memory_integrity_version": MEMORY_INTEGRITY_VERSION,
        "overall_status": overall_status,
        "total_entries": len(entries),
        "anomalous_entries": len(anomalous),
        "compromised_entries": len(compromised_entries),
        "max_anomaly_score": round(max_score, 4),
        "attack_vectors_detected": by_vector,
        "recommended_action": (
            "QUARANTINE_AND_FLUSH" if overall_status == STATUS_COMPROMISED
            else "REVIEW_ANOMALIES" if overall_status == STATUS_SUSPICIOUS
            else "NONE"
        ),
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }


def scan_for_poisoning(
    store_id: str,
    store: Any,
    *,
    min_score: float = 0.35,
) -> dict[str, Any]:
    """Focused scan for poisoning signals — returns only entries above min_score threshold."""
    store_meta = get_memory_store(store_id, store)
    if not store_meta:
        raise MemoryIntegrityError(f"Memory store {store_id!r} not registered.")

    entries = list_memory_entries(store_id, store, limit=10_000)
    flagged = [e for e in entries if e.get("anomaly_score", 0.0) >= min_score]
    flagged.sort(key=lambda e: e.get("anomaly_score", 0.0), reverse=True)

    time_bombs = [e for e in flagged if e.get("attack_vector") == ATTACK_TIME_BOMB]
    cross_agent = [e for e in flagged if e.get("attack_vector") == ATTACK_CROSS_AGENT_CONTAMINATION]

    return {
        "store_id": store_id,
        "scan_threshold": min_score,
        "total_entries_scanned": len(entries),
        "flagged_count": len(flagged),
        "time_bomb_count": len(time_bombs),
        "cross_agent_contamination_count": len(cross_agent),
        "flagged_entries": flagged[:50],
        "evidence_origin": "LOCALLY_OBSERVED",
        "scanned_at": _utc_now(),
    }

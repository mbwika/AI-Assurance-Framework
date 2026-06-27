"""Telemetry Ingestion and Anomaly Detection.

Ingests operational telemetry events from AI system deployments
(latency, error rates, refusal rates, injection attempts, etc.),
aggregates them into time-window summaries, and detects anomalies
by comparing observed values against configurable thresholds.

Storage
-------
Events are stored in rolling buffers keyed by
``"telemetry:{model_id}:{event_type}"``.  Each buffer holds at most
MAX_EVENTS_PER_STORE events to bound storage growth.

Evidence origin
---------------
All findings are LOCALLY_OBSERVED — the framework observes anomalies
from telemetry it receives and makes no independent claim about the
model's ground-truth behaviour.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

TELEMETRY_INGEST_VERSION = "1.0"

_TELEMETRY_PREFIX = "telemetry_ops:"
MAX_EVENTS_PER_STORE = 5000
_DEFAULT_WINDOW_MINUTES = 60

# ── Event types ────────────────────────────────────────────────────────────────
EVENT_LATENCY = "LATENCY"
EVENT_ERROR_RATE = "ERROR_RATE"
EVENT_REFUSAL_RATE = "REFUSAL_RATE"
EVENT_TOKEN_USAGE = "TOKEN_USAGE"
EVENT_INJECTION_ATTEMPT = "INJECTION_ATTEMPT"
EVENT_POLICY_VIOLATION = "POLICY_VIOLATION"

EVENT_TYPES: frozenset = frozenset({
    EVENT_LATENCY, EVENT_ERROR_RATE, EVENT_REFUSAL_RATE,
    EVENT_TOKEN_USAGE, EVENT_INJECTION_ATTEMPT, EVENT_POLICY_VIOLATION,
})

# ── Analysis status ────────────────────────────────────────────────────────────
TELEM_STATUS_NORMAL = "NORMAL"
TELEM_STATUS_ELEVATED = "ELEVATED"
TELEM_STATUS_ANOMALY_DETECTED = "ANOMALY_DETECTED"
TELEM_STATUS_CRITICAL = "CRITICAL"

_STATUS_RANK: dict[str, int] = {
    TELEM_STATUS_CRITICAL: 3,
    TELEM_STATUS_ANOMALY_DETECTED: 2,
    TELEM_STATUS_ELEVATED: 1,
    TELEM_STATUS_NORMAL: 0,
}

# ── Default thresholds ─────────────────────────────────────────────────────────
_DEFAULT_THRESHOLDS: dict[str, dict[str, float]] = {
    EVENT_LATENCY: {"elevated": 2000.0, "anomaly": 5000.0},
    EVENT_ERROR_RATE: {"elevated": 0.05, "anomaly": 0.15},
    EVENT_REFUSAL_RATE: {"elevated": 0.30, "anomaly": 0.60},
    EVENT_TOKEN_USAGE: {"elevated": 4000.0, "anomaly": 8000.0},
    EVENT_INJECTION_ATTEMPT: {"elevated_count": 1.0, "anomaly_count": 5.0},
    EVENT_POLICY_VIOLATION: {"elevated_count": 1.0, "anomaly_count": 3.0},
}


class TelemetryIngestError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _telemetry_key(model_id: str, event_type: str) -> str:
    return f"{_TELEMETRY_PREFIX}{model_id}:{event_type}"


def _worst_status(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * p
    lo = int(idx)
    hi = lo + 1
    if hi >= len(sorted_vals):
        return sorted_vals[-1]
    return sorted_vals[lo] + (idx - lo) * (sorted_vals[hi] - sorted_vals[lo])


# ── Public API ─────────────────────────────────────────────────────────────────

def ingest_event(
    model_id: str,
    event_type: str,
    value: float,
    store: Any,
    *,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Ingest one telemetry event for (model_id, event_type)."""
    model_id = str(model_id).strip()
    event_type = str(event_type).upper().strip()
    if not model_id:
        raise TelemetryIngestError("model_id must be non-empty")
    if event_type not in EVENT_TYPES:
        raise TelemetryIngestError(
            f"Unknown event_type: {event_type!r}. Valid: {sorted(EVENT_TYPES)}"
        )

    ts = timestamp or _to_iso(_utc_now())
    event = {"value": float(value), "timestamp": ts, "metadata": metadata or {}}

    key = _telemetry_key(model_id, event_type)
    record = store.get_model(key) or {}
    events: list[dict[str, Any]] = list(record.get("metadata", {}).get("events") or [])
    events.append(event)
    if len(events) > MAX_EVENTS_PER_STORE:
        events = events[-MAX_EVENTS_PER_STORE:]

    store.save_model({
        "model_id": key,
        "id": key,
        "metadata": {
            "model_id": model_id,
            "event_type": event_type,
            "events": events,
            "telemetry_ingest_version": TELEMETRY_INGEST_VERSION,
            "updated_at": _to_iso(_utc_now()),
        },
    })
    return {"model_id": model_id, "event_type": event_type, "ingested": event}


def get_window_summary(
    model_id: str,
    event_type: str,
    store: Any,
    *,
    window_minutes: int = _DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any]:
    """Aggregate statistics for events in the last window_minutes."""
    event_type = str(event_type).upper().strip()
    key = _telemetry_key(model_id, event_type)
    record = store.get_model(key) or {}
    all_events = list(record.get("metadata", {}).get("events") or [])

    cutoff = _utc_now() - timedelta(minutes=window_minutes)
    windowed: list[float] = []
    for e in all_events:
        try:
            if _from_iso(e["timestamp"]) >= cutoff:
                windowed.append(float(e["value"]))
        except (KeyError, ValueError, TypeError):
            pass

    if not windowed:
        return {
            "model_id": model_id, "event_type": event_type,
            "window_minutes": window_minutes,
            "count": 0, "mean": None, "min": None, "max": None,
            "stddev": None, "p95": None, "sum": 0.0,
            "telemetry_ingest_version": TELEMETRY_INGEST_VERSION,
        }

    sorted_vals = sorted(windowed)
    return {
        "model_id": model_id, "event_type": event_type,
        "window_minutes": window_minutes,
        "count": len(windowed),
        "mean": sum(windowed) / len(windowed),
        "min": sorted_vals[0],
        "max": sorted_vals[-1],
        "stddev": _stddev(windowed),
        "p95": _percentile(sorted_vals, 0.95),
        "sum": sum(windowed),
        "telemetry_ingest_version": TELEMETRY_INGEST_VERSION,
    }


def list_events(
    model_id: str,
    event_type: str,
    store: Any,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return the most recent `limit` raw events."""
    event_type = str(event_type).upper().strip()
    key = _telemetry_key(model_id, event_type)
    record = store.get_model(key) or {}
    events = list(record.get("metadata", {}).get("events") or [])
    return events[-limit:]


def detect_anomalies(
    model_id: str,
    store: Any,
    *,
    thresholds: dict[str, dict[str, float]] | None = None,
    window_minutes: int = _DEFAULT_WINDOW_MINUTES,
) -> dict[str, Any]:
    """Detect anomalies in telemetry for model_id over the last window_minutes."""
    thresholds = thresholds or _DEFAULT_THRESHOLDS
    findings: list[dict[str, Any]] = []
    overall_status = TELEM_STATUS_NORMAL

    for event_type in EVENT_TYPES:
        summary = get_window_summary(
            model_id, event_type, store, window_minutes=window_minutes
        )
        if summary["count"] == 0:
            continue

        t = thresholds.get(event_type) or {}
        finding_type: str | None = None
        status = TELEM_STATUS_NORMAL

        if "elevated_count" in t or "anomaly_count" in t:
            count = summary["count"]
            if count >= (t.get("anomaly_count") or float("inf")):
                status = TELEM_STATUS_ANOMALY_DETECTED
                finding_type = f"{event_type.lower()}_threshold_exceeded"
            elif count >= (t.get("elevated_count") or float("inf")):
                status = TELEM_STATUS_ELEVATED
                finding_type = f"{event_type.lower()}_elevated"
        else:
            mean = summary["mean"] or 0.0
            if mean >= (t.get("anomaly") or float("inf")):
                status = TELEM_STATUS_ANOMALY_DETECTED
                finding_type = f"{event_type.lower()}_threshold_exceeded"
            elif mean >= (t.get("elevated") or float("inf")):
                status = TELEM_STATUS_ELEVATED
                finding_type = f"{event_type.lower()}_elevated"

        if finding_type:
            findings.append({
                "type": finding_type,
                "event_type": event_type,
                "status": status,
                "count": summary["count"],
                "mean": summary["mean"],
                "evidence_origin": "LOCALLY_OBSERVED",
            })
            overall_status = _worst_status(overall_status, status)

    return {
        "model_id": model_id,
        "telemetry_ingest_version": TELEMETRY_INGEST_VERSION,
        "status": overall_status,
        "finding_count": len(findings),
        "findings": findings,
        "window_minutes": window_minutes,
        "evidence_origin": "LOCALLY_OBSERVED",
        "analysed_at": _to_iso(_utc_now()),
    }

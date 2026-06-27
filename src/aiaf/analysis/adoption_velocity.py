"""Adoption-Velocity Anomaly Detection.

Detects supply-chain attacks that exploit rapid adoption spikes — the signal
used by the 2026 trojan model that masqueraded as an OpenAI release and reached
244K downloads in ~18 hours before being detected.

Core idea
---------
Legitimate popular models/skills accumulate adoption gradually; malicious ones
boosted by bots or coordinated promotion often show step-function velocity spikes
inconsistent with any known publication event. This module tracks adoption events
(downloads, installs, deploys) for model/skill artifacts, computes rolling
velocity, and compares against a declared or learned baseline.

Anomaly signals
---------------
VELOCITY_SPIKE      — current rate >> baseline for a sustained window
COLD_START_SURGE    — artifact goes from zero to top-rank in < cold_start_hours
DORMANCY_REACTIVATION — long-idle artifact suddenly surges (possible account takeover)
VELOCITY_CLIFF      — velocity drops to zero after a spike (possible takedown / C2 callback achieved)

Event types
-----------
DOWNLOAD    — artifact fetched/downloaded
INSTALL     — artifact installed in an environment
DEPLOY      — artifact deployed to production
FORK        — repository fork
STAR        — social signal (weaker)

Storage
-------
Events are stored keyed by ``adopt_event:{artifact_id}:{event_id}``.
Velocity profiles are summarised in ``adopt_profile:{artifact_id}``.

Evidence origin
---------------
LOCALLY_OBSERVED — adoption events are registered and assessed by the calling
application; AIAF performs velocity computation and anomaly detection locally.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

ADOPTION_VELOCITY_VERSION = "1.0"

# ── Event types ────────────────────────────────────────────────────────────────
EVENT_DOWNLOAD = "DOWNLOAD"
EVENT_INSTALL = "INSTALL"
EVENT_DEPLOY = "DEPLOY"
EVENT_FORK = "FORK"
EVENT_STAR = "STAR"

EVENT_TYPES: frozenset = frozenset(
    {EVENT_DOWNLOAD, EVENT_INSTALL, EVENT_DEPLOY, EVENT_FORK, EVENT_STAR}
)

# Event weights for velocity scoring (installs/deploys count more than stars)
_EVENT_WEIGHT: Dict[str, float] = {
    EVENT_DOWNLOAD: 1.0,
    EVENT_INSTALL: 2.0,
    EVENT_DEPLOY: 3.0,
    EVENT_FORK: 1.5,
    EVENT_STAR: 0.5,
}

# ── Anomaly signals ────────────────────────────────────────────────────────────
SIGNAL_VELOCITY_SPIKE = "VELOCITY_SPIKE"
SIGNAL_COLD_START_SURGE = "COLD_START_SURGE"
SIGNAL_DORMANCY_REACTIVATION = "DORMANCY_REACTIVATION"
SIGNAL_VELOCITY_CLIFF = "VELOCITY_CLIFF"

ANOMALY_SIGNALS: frozenset = frozenset({
    SIGNAL_VELOCITY_SPIKE, SIGNAL_COLD_START_SURGE,
    SIGNAL_DORMANCY_REACTIVATION, SIGNAL_VELOCITY_CLIFF,
})

# ── Risk levels ────────────────────────────────────────────────────────────────
VELOCITY_RISK_NORMAL = "NORMAL"
VELOCITY_RISK_ELEVATED = "ELEVATED"
VELOCITY_RISK_HIGH = "HIGH"
VELOCITY_RISK_CRITICAL = "CRITICAL"

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_SPIKE_MULTIPLIER = 5.0      # current_velocity > baseline * 5 → spike
DEFAULT_COLD_START_HOURS = 24.0     # surge from 0 to > cold_start_threshold within this window
DEFAULT_COLD_START_THRESHOLD = 1000 # weighted events in the cold-start window
DEFAULT_DORMANCY_DAYS = 30          # no events for this long before reactivation check
DEFAULT_VELOCITY_WINDOW_HOURS = 6   # rolling window for current velocity

# ── Storage prefixes ───────────────────────────────────────────────────────────
_EVENT_PREFIX = "adopt_event:"
_PROFILE_PREFIX = "adopt_profile:"


class AdoptionVelocityError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _event_key(artifact_id: str, event_id: str) -> str:
    return f"{_EVENT_PREFIX}{artifact_id}:{event_id}"


def _profile_key(artifact_id: str) -> str:
    return f"{_PROFILE_PREFIX}{artifact_id}"


def _load_meta(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (record or {}).get("metadata") or {}


# ── Public API ─────────────────────────────────────────────────────────────────

def record_adoption_event(
    artifact_id: str,
    event_type: str,
    store: Any,
    *,
    count: int = 1,
    source: Optional[str] = None,
    region: Optional[str] = None,
    occurred_at: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record an adoption event for an artifact.

    Parameters
    ----------
    artifact_id:  Identifier for the model/skill/package.
    event_type:   One of EVENT_* constants.
    count:        Number of events in this batch (e.g. 1000 downloads at once).
    source:       Source of the event (e.g. "huggingface", "pypi", "clawHub").
    region:       Geographic region (for geographic-clustering detection).
    occurred_at:  ISO-8601 timestamp; defaults to now.
    """
    if not artifact_id or not artifact_id.strip():
        raise AdoptionVelocityError("artifact_id must be non-empty.")

    event_type = str(event_type).upper().strip()
    if event_type not in EVENT_TYPES:
        raise AdoptionVelocityError(
            f"Unknown event_type {event_type!r}. Valid: {sorted(EVENT_TYPES)}"
        )

    event_id = str(uuid.uuid4())[:12]
    ts = occurred_at or _utc_now()
    weight = _EVENT_WEIGHT.get(event_type, 1.0) * max(1, count)

    event_record: Dict[str, Any] = {
        "model_id": _event_key(artifact_id, event_id),
        "id": _event_key(artifact_id, event_id),
        "metadata": {
            "artifact_id": artifact_id,
            "event_id": event_id,
            "event_type": event_type,
            "count": count,
            "weight": weight,
            "source": source,
            "region": region,
            "attributes": attributes or {},
            "occurred_at": ts,
            "evidence_origin": "LOCALLY_OBSERVED",
        },
    }
    store.save_model(event_record)

    # Update profile totals
    profile_rec = store.get_model(_profile_key(artifact_id))
    profile = _load_meta(profile_rec) if profile_rec else {}
    profile["artifact_id"] = artifact_id
    profile["total_events"] = int(profile.get("total_events", 0)) + count
    profile["total_weight"] = float(profile.get("total_weight", 0.0)) + weight
    profile["first_seen_at"] = profile.get("first_seen_at") or ts
    profile["last_seen_at"] = ts
    profile["updated_at"] = _utc_now()
    profile["evidence_origin"] = "LOCALLY_OBSERVED"

    store.save_model({
        "model_id": _profile_key(artifact_id),
        "id": _profile_key(artifact_id),
        "metadata": profile,
    })

    return _load_meta(store.get_model(_event_key(artifact_id, event_id)))


def set_velocity_baseline(
    artifact_id: str,
    baseline_weight_per_hour: float,
    store: Any,
) -> Dict[str, Any]:
    """Declare the expected adoption velocity for an artifact.

    This baseline is compared against actual velocity when detecting anomalies.
    A baseline of 0.0 means the artifact is expected to be dormant.
    """
    if not artifact_id:
        raise AdoptionVelocityError("artifact_id must be non-empty.")

    profile_rec = store.get_model(_profile_key(artifact_id))
    profile = _load_meta(profile_rec) if profile_rec else {"artifact_id": artifact_id}
    profile["baseline_weight_per_hour"] = float(baseline_weight_per_hour)
    profile["baseline_set_at"] = _utc_now()
    profile["updated_at"] = _utc_now()

    store.save_model({
        "model_id": _profile_key(artifact_id),
        "id": _profile_key(artifact_id),
        "metadata": profile,
    })
    return _load_meta(store.get_model(_profile_key(artifact_id)))


def get_velocity_profile(
    artifact_id: str,
    store: Any,
    *,
    window_hours: float = DEFAULT_VELOCITY_WINDOW_HOURS,
) -> Optional[Dict[str, Any]]:
    """Compute current velocity metrics for an artifact.

    Returns None if no events have been recorded.

    Parameters
    ----------
    window_hours:  Rolling time window for current velocity computation.
    """
    profile_rec = store.get_model(_profile_key(artifact_id))
    if not profile_rec:
        return None
    profile = _load_meta(profile_rec)

    # Gather events within the window
    prefix = _event_key(artifact_id, "")
    all_records = store.list_models() if hasattr(store, "list_models") else []
    now_dt = datetime.now(timezone.utc)
    window_start = now_dt - timedelta(hours=window_hours)

    window_weight = 0.0
    window_count = 0
    all_weights_by_hour: Dict[int, float] = {}  # hour_offset → weight

    first_seen_dt = None
    if profile.get("first_seen_at"):
        try:
            first_seen_dt = _parse_ts(profile["first_seen_at"])
        except Exception:
            pass

    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(prefix):
            continue
        meta = _load_meta(rec)
        ts_str = meta.get("occurred_at")
        if not ts_str:
            continue
        try:
            ts_dt = _parse_ts(ts_str)
        except Exception:
            continue

        weight = float(meta.get("weight", 1.0))
        if ts_dt >= window_start:
            window_weight += weight
            window_count += 1

        # Hourly histogram for the last 48h
        delta_hours = int((now_dt - ts_dt).total_seconds() / 3600)
        if 0 <= delta_hours < 48:
            all_weights_by_hour[delta_hours] = all_weights_by_hour.get(delta_hours, 0.0) + weight

    current_velocity_per_hour = window_weight / max(window_hours, 1.0)
    baseline = float(profile.get("baseline_weight_per_hour", 0.0))
    spike_ratio = current_velocity_per_hour / baseline if baseline > 0 else float("inf")

    # Time since first event
    age_hours = None
    if first_seen_dt:
        age_hours = (now_dt - first_seen_dt).total_seconds() / 3600.0

    return {
        "artifact_id": artifact_id,
        "total_events": int(profile.get("total_events", 0)),
        "total_weight": float(profile.get("total_weight", 0.0)),
        "first_seen_at": profile.get("first_seen_at"),
        "last_seen_at": profile.get("last_seen_at"),
        "age_hours": round(age_hours, 2) if age_hours is not None else None,
        "current_velocity_per_hour": round(current_velocity_per_hour, 4),
        "velocity_window_hours": window_hours,
        "window_event_count": window_count,
        "baseline_weight_per_hour": baseline,
        "spike_ratio": round(spike_ratio, 2) if spike_ratio != float("inf") else None,
        "hourly_histogram": all_weights_by_hour,
        "evidence_origin": "LOCALLY_OBSERVED",
    }


def detect_velocity_anomaly(
    artifact_id: str,
    store: Any,
    *,
    spike_multiplier: float = DEFAULT_SPIKE_MULTIPLIER,
    cold_start_hours: float = DEFAULT_COLD_START_HOURS,
    cold_start_threshold: float = DEFAULT_COLD_START_THRESHOLD,
    dormancy_days: float = DEFAULT_DORMANCY_DAYS,
    velocity_window_hours: float = DEFAULT_VELOCITY_WINDOW_HOURS,
) -> Dict[str, Any]:
    """Detect velocity anomalies for an artifact.

    Returns
    -------
    Dict with keys:
        artifact_id, risk_level, anomalies,
        velocity_profile, evidence_origin, assessed_at
    """
    profile = get_velocity_profile(
        artifact_id, store, window_hours=velocity_window_hours,
    )
    if not profile:
        return {
            "artifact_id": artifact_id,
            "risk_level": VELOCITY_RISK_NORMAL,
            "anomalies": [],
            "velocity_profile": None,
            "evidence_origin": "LOCALLY_OBSERVED",
            "assessed_at": _utc_now(),
        }

    anomalies: List[Dict[str, Any]] = []
    now_dt = datetime.now(timezone.utc)

    # ── Velocity spike ─────────────────────────────────────────────────────────
    baseline = profile["baseline_weight_per_hour"]
    current = profile["current_velocity_per_hour"]
    spike_ratio = profile.get("spike_ratio")

    if baseline > 0 and current > baseline * spike_multiplier:
        anomalies.append({
            "signal": SIGNAL_VELOCITY_SPIKE,
            "severity": "HIGH" if spike_ratio < 20 else "CRITICAL",
            "detail": (
                f"Current velocity {current:.1f}/hr is {spike_ratio:.1f}x the baseline "
                f"{baseline:.1f}/hr (threshold: {spike_multiplier:.0f}x)."
            ),
            "current_velocity": current,
            "baseline": baseline,
            "spike_ratio": spike_ratio,
        })

    # ── Cold-start surge ───────────────────────────────────────────────────────
    age_hours = profile.get("age_hours")
    total_weight = profile["total_weight"]
    if (
        age_hours is not None
        and age_hours <= cold_start_hours
        and total_weight >= cold_start_threshold
    ):
        anomalies.append({
            "signal": SIGNAL_COLD_START_SURGE,
            "severity": "CRITICAL",
            "detail": (
                f"New artifact accumulated {total_weight:.0f} weighted adoption events "
                f"in only {age_hours:.1f} hours (threshold: {cold_start_threshold:.0f} events "
                f"in {cold_start_hours:.0f} hours). Consistent with bot-driven or coordinated promotion."
            ),
            "total_weight": total_weight,
            "age_hours": age_hours,
            "cold_start_hours": cold_start_hours,
        })

    # ── Dormancy reactivation ──────────────────────────────────────────────────
    last_seen_str = profile.get("last_seen_at")
    first_seen_str = profile.get("first_seen_at")
    if last_seen_str and first_seen_str:
        try:
            last_seen_dt = _parse_ts(last_seen_str)
            first_seen_dt = _parse_ts(first_seen_str)
            # Check if there was a long gap before the most recent events
            artifact_age_days = (now_dt - first_seen_dt).total_seconds() / 86400
            recent_gap = profile.get("age_hours", 0)
            if (
                artifact_age_days > dormancy_days * 2
                and current > 0
                and baseline == 0.0
                # Approximate dormancy: artifact is old but baseline was never set
            ):
                anomalies.append({
                    "signal": SIGNAL_DORMANCY_REACTIVATION,
                    "severity": "HIGH",
                    "detail": (
                        f"Artifact has existed for {artifact_age_days:.0f} days with no declared "
                        f"baseline, but is now showing velocity {current:.1f}/hr. "
                        "Possible account takeover or dormant C2 activation."
                    ),
                    "artifact_age_days": round(artifact_age_days, 1),
                    "current_velocity": current,
                })
        except Exception:
            pass

    # ── Velocity cliff ─────────────────────────────────────────────────────────
    # If previous window had high velocity but current window is near-zero after spike
    histogram = profile.get("hourly_histogram") or {}
    recent_hours = sum(histogram.get(h, 0.0) for h in range(0, 3))       # 0-3h ago
    older_hours = sum(histogram.get(h, 0.0) for h in range(3, int(velocity_window_hours * 2)))  # 3-12h ago

    if older_hours > cold_start_threshold * 0.2 and recent_hours == 0.0:
        anomalies.append({
            "signal": SIGNAL_VELOCITY_CLIFF,
            "severity": "MEDIUM",
            "detail": (
                f"Velocity dropped to zero in the last 3 hours after high activity "
                f"({older_hours:.0f} weighted events in previous window). "
                "May indicate takedown, C2 mission completion, or bot deactivation."
            ),
            "recent_3h_weight": recent_hours,
            "prior_window_weight": older_hours,
        })

    # ── Overall risk level ─────────────────────────────────────────────────────
    severities = [a["severity"] for a in anomalies]
    if "CRITICAL" in severities:
        risk_level = VELOCITY_RISK_CRITICAL
    elif "HIGH" in severities:
        risk_level = VELOCITY_RISK_HIGH
    elif "MEDIUM" in severities:
        risk_level = VELOCITY_RISK_ELEVATED
    else:
        risk_level = VELOCITY_RISK_NORMAL

    return {
        "artifact_id": artifact_id,
        "risk_level": risk_level,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "velocity_profile": profile,
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }


def list_at_risk_artifacts(
    store: Any,
    *,
    min_risk: str = VELOCITY_RISK_ELEVATED,
    limit: int = 50,
    spike_multiplier: float = DEFAULT_SPIKE_MULTIPLIER,
    cold_start_hours: float = DEFAULT_COLD_START_HOURS,
    cold_start_threshold: float = DEFAULT_COLD_START_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Return all artifacts with velocity anomalies at or above min_risk level.

    This is a convenience method for bulk monitoring dashboards.
    """
    _risk_rank = {
        VELOCITY_RISK_NORMAL: 0,
        VELOCITY_RISK_ELEVATED: 1,
        VELOCITY_RISK_HIGH: 2,
        VELOCITY_RISK_CRITICAL: 3,
    }
    min_rank = _risk_rank.get(min_risk, 1)

    all_records = store.list_models() if hasattr(store, "list_models") else []
    artifact_ids = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if mid.startswith(_PROFILE_PREFIX):
            meta = _load_meta(rec)
            aid = meta.get("artifact_id")
            if aid:
                artifact_ids.append(aid)

    results = []
    for aid in artifact_ids:
        assessment = detect_velocity_anomaly(
            aid, store,
            spike_multiplier=spike_multiplier,
            cold_start_hours=cold_start_hours,
            cold_start_threshold=cold_start_threshold,
        )
        level = assessment.get("risk_level", VELOCITY_RISK_NORMAL)
        if _risk_rank.get(level, 0) >= min_rank:
            results.append(assessment)
        if len(results) >= limit:
            break

    results.sort(key=lambda r: _risk_rank.get(r.get("risk_level", VELOCITY_RISK_NORMAL), 0), reverse=True)
    return results

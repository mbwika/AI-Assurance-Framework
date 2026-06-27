"""Human Oversight Monitor — ASI09 Human-Agent Trust Exploitation detection.

Detects patterns where an AI agent exploits the inherent asymmetry in the
human-agent trust relationship to extract additional permissions, suppress
oversight, or manufacture consent for actions the operator would not sanction
if accurately described.

Attack patterns (OWASP ASI09, 2026)
-------------------------------------
CONSENT_MISMATCH        — tool call scope exceeds what the agent described in
                          its prior output (e.g. said "send to Alice" but called
                          email.send with 50 recipients, or said "read the file"
                          but called file.write)
OVERSIGHT_SUPPRESSION   — agent output discourages human review ("routine step,
                          no need to check", "already approved", "trust me")
URGENCY_MANUFACTURE     — fabricated time-pressure language immediately preceding
                          a high-risk tool call ("urgent, must act now", "deadline
                          expires in minutes")
CONFIDENCE_INFLATION    — certainty language ("guaranteed", "confirmed", "100%")
                          on outputs with unknown or weak evidentiary basis
AUTHORITY_FABRICATION   — agent claims prior approval from a named principal not
                          recorded in the caller-provided authority list

Session model
-------------
An oversight session tracks a bounded interaction window (one agent task or
workflow step).  The caller records:

  1. Agent output turns — text produced by the agent (includes summaries of
                          intended actions, justifications, reassurances)
  2. Tool calls         — the actual tool invocations that followed, optionally
                          paired with described_intent (the agent text that
                          described what the tool call would do)

The pairing via ``turn_id`` allows CONSENT_MISMATCH detection: if the agent
said "I will send a brief note to Alice" (turn_id="t1") and then the tool call
for t1 has recipients=["alice", "bob", "carol", ...], that is a scope mismatch.

Storage
-------
``oversight_session:{session_id}``          — session metadata
``oversight_event:{session_id}:{event_id}`` — individual events

Risk levels
-----------
SAFE      — no trust-exploitation signals
ELEVATED  — soft signals only (urgency language, confidence inflation)
HIGH      — suppression or unexplained scope escalation
CRITICAL  — confirmed consent mismatch or authority fabrication

Evidence origin
---------------
LOCALLY_OBSERVED — all signals computed from caller-supplied session data.
AIAF does not intercept agent/tool traffic; the caller is responsible for
feeding events into the session.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

HUMAN_OVERSIGHT_VERSION = "1.0"

# ── Event types ────────────────────────────────────────────────────────────────
EVENT_AGENT_OUTPUT = "AGENT_OUTPUT"
EVENT_TOOL_CALL = "TOOL_CALL"
EVENT_TYPES: frozenset = frozenset({EVENT_AGENT_OUTPUT, EVENT_TOOL_CALL})

# ── Signal types ───────────────────────────────────────────────────────────────
SIGNAL_CONSENT_MISMATCH = "CONSENT_MISMATCH"
SIGNAL_OVERSIGHT_SUPPRESSION = "OVERSIGHT_SUPPRESSION"
SIGNAL_URGENCY_MANUFACTURE = "URGENCY_MANUFACTURE"
SIGNAL_CONFIDENCE_INFLATION = "CONFIDENCE_INFLATION"
SIGNAL_AUTHORITY_FABRICATION = "AUTHORITY_FABRICATION"

SIGNAL_TYPES: frozenset = frozenset({
    SIGNAL_CONSENT_MISMATCH, SIGNAL_OVERSIGHT_SUPPRESSION,
    SIGNAL_URGENCY_MANUFACTURE, SIGNAL_CONFIDENCE_INFLATION,
    SIGNAL_AUTHORITY_FABRICATION,
})

# ── Risk levels ────────────────────────────────────────────────────────────────
RISK_SAFE = "SAFE"
RISK_ELEVATED = "ELEVATED"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

_RISK_RANK: dict[str, int] = {
    RISK_SAFE: 0, RISK_ELEVATED: 1, RISK_HIGH: 2, RISK_CRITICAL: 3,
}

# ── Session states ─────────────────────────────────────────────────────────────
SESSION_ACTIVE = "ACTIVE"
SESSION_CLOSED = "CLOSED"

# ── Storage prefixes ───────────────────────────────────────────────────────────
_SESSION_PREFIX = "oversight_session:"
_EVENT_PREFIX = "oversight_event:"


class HumanOversightError(ValueError):
    pass


# ── Text-pattern detectors ─────────────────────────────────────────────────────

_SUPPRESSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"no\s+need\s+to\s+(review|check|verify|approve|confirm)", re.I), "HIGH"),
    (re.compile(r"(routine|standard|normal|automatic)\s+(operation|procedure|step|process|task)", re.I), "MEDIUM"),
    (re.compile(r"(already|previously)\s+(approved|authorized|confirmed|reviewed)", re.I), "HIGH"),
    (re.compile(r"you\s+can\s+(skip|ignore|bypass|omit)\s+(this|the|review|approval|check)", re.I), "HIGH"),
    (re.compile(r"\btrust\s+(me|this|the\s+output|the\s+result)\b", re.I), "MEDIUM"),
    (re.compile(r"no\s+(human\s+)?(action|review|intervention)\s+(needed|required|necessary)", re.I), "HIGH"),
    (re.compile(r"(safe|harmless|benign|risk.free)\s+to\s+(proceed|continue|approve|execute)", re.I), "MEDIUM"),
    (re.compile(r"I\s+(will|'ll|shall)\s+handle\s+(this|it|everything|the rest)", re.I), "MEDIUM"),
    (re.compile(r"(no|zero)\s+(risk|concern|issue|problem)\s+here", re.I), "MEDIUM"),
]

_URGENCY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(immediately|instant(ly)?|right\s+now|at\s+once)\b", re.I), "HIGH"),
    (re.compile(r"\b(asap|a\.s\.a\.p\.?|urgent(ly)?|critical(ly)?)\b", re.I), "MEDIUM"),
    (re.compile(r"\b(time.sensitive|time.critical|time-critical)\b", re.I), "MEDIUM"),
    (re.compile(r"\b(deadline|expir(es?|ing|ation)|window\s+closes?)\s+(in|soon|today|now|shortly)\b", re.I), "HIGH"),
    (re.compile(r"before\s+it.s?\s+too\s+late", re.I), "HIGH"),
    (re.compile(r"(cannot|can.t|must\s+not|won.t\s+be\s+able\s+to)\s+wait", re.I), "MEDIUM"),
    (re.compile(r"(opportunity|window)\s+(is\s+)?(closing|about\s+to\s+(close|expire))", re.I), "HIGH"),
]

_CONFIDENCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(definitely|certainly|absolutely|undoubtedly)\b", re.I), "MEDIUM"),
    (re.compile(r"\b(guaranteed?|confirmed?|verified?)\b", re.I), "HIGH"),
    (re.compile(r"\b(without\s+(a\s+)?doubt|100\s*%\s*(sure|certain|confident|accurate))\b", re.I), "HIGH"),
    (re.compile(r"\bI.m\s+(sure|certain|confident|positive)\s+that\b", re.I), "MEDIUM"),
    (re.compile(r"\bthere\s+is\s+no\s+(doubt|question|risk|possibility\s+of\s+error)\b", re.I), "HIGH"),
    (re.compile(r"\b(this\s+is|it\s+is)\s+(definitely|certainly|absolutely)\s+(correct|right|safe)\b", re.I), "MEDIUM"),
]

_AUTHORITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(as\s+per|per|according\s+to)\s+\w[\w\s]{1,30}.s?\s+instructions?", re.I), "HIGH"),
    (re.compile(r"\w[\w\s]{0,20}\s+(approved|authorized|sanctioned|confirmed)\s+(this|it|the\s+\w+)", re.I), "HIGH"),
    (re.compile(r"(authorized|approved|cleared)\s+by\s+\w+", re.I), "HIGH"),
    (re.compile(r"\bon\s+behalf\s+of\s+\w+", re.I), "MEDIUM"),
    (re.compile(r"(management|leadership|admin(istration)?|the\s+(team|board|committee))\s+"
                r"(has\s+)?(approved|authorized|confirmed|requested)", re.I), "HIGH"),
    (re.compile(r"(your|the)\s+(manager|supervisor|admin|boss|cto|ceo|director)\s+"
                r"(said|asked|told|instructed|approved|wants)", re.I), "HIGH"),
]

# ── Consent-mismatch heuristics ────────────────────────────────────────────────

# Verbs that imply read-only intent in described_intent
_READ_VERBS = re.compile(
    r"\b(read|view|check|look\s+at|inspect|examine|retrieve|fetch|get|list|show|display|preview)\b",
    re.I,
)
# Verbs that imply write/destructive scope in a tool name or described_intent
_WRITE_VERBS = re.compile(
    r"\b(write|create|delete|remove|update|modify|edit|send|post|upload|publish|"
    r"submit|execute|run|deploy|install|overwrite|truncate|drop|insert)\b",
    re.I,
)
# External-network indicators in tool call params (serialised as string)
_EXTERNAL_RE = re.compile(r"https?://|smtp:|ftp://|wss?://", re.I)
# Single-entity language in described_intent
_SINGLE_ENTITY_RE = re.compile(
    r"\b(the\s+)?(file|document|record|entry|row|item|user|person|email|message|alice|bob|carol)\b",
    re.I,
)


def _detect_consent_mismatch(
    described_intent: str,
    tool_name: str,
    tool_params: dict[str, Any],
) -> list[dict[str, Any]]:
    """Heuristic comparison of what the agent described vs what it actually called."""
    findings = []
    params_str = str(tool_params)

    # Read/write mismatch: described read-only, tool call is write/destructive
    if _READ_VERBS.search(described_intent) and _WRITE_VERBS.search(tool_name):
        findings.append({
            "sub_signal": "READ_WRITE_MISMATCH",
            "severity": "CRITICAL",
            "detail": (
                f"Agent described a read-only action ({described_intent[:80]!r}) "
                f"but invoked a write/destructive tool: {tool_name!r}."
            ),
        })

    # Scope escalation: described a single entity but params contain a long list
    if _SINGLE_ENTITY_RE.search(described_intent):
        max_list_len = max(
            (len(v) for v in tool_params.values() if isinstance(v, list)),
            default=0,
        )
        if max_list_len > 3:
            findings.append({
                "sub_signal": "SCOPE_ESCALATION",
                "severity": "HIGH",
                "detail": (
                    f"Agent described acting on a single entity ({described_intent[:60]!r}) "
                    f"but tool parameters contain a list of {max_list_len} values."
                ),
            })

    # External network access not described
    if _EXTERNAL_RE.search(params_str) and not _EXTERNAL_RE.search(described_intent):
        findings.append({
            "sub_signal": "UNDISCLOSED_EXTERNAL_CALL",
            "severity": "HIGH",
            "detail": (
                "Tool call parameters contain external network endpoints not mentioned "
                f"in the agent's described intent: {described_intent[:60]!r}."
            ),
        })

    return findings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _session_key(session_id: str) -> str:
    return f"{_SESSION_PREFIX}{session_id}"


def _event_key(session_id: str, event_id: str) -> str:
    return f"{_EVENT_PREFIX}{session_id}:{event_id}"


def _load_meta(record: dict[str, Any] | None) -> dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _scan_text(
    text: str,
    patterns: list[tuple[re.Pattern, str]],
    signal_type: str,
) -> list[dict[str, Any]]:
    findings = []
    seen: set = set()
    for pattern, severity in patterns:
        match = pattern.search(text)
        if match and pattern.pattern not in seen:
            seen.add(pattern.pattern)
            findings.append({
                "signal": signal_type,
                "severity": severity,
                "matched_text": match.group(0)[:80],
                "detail": f"Pattern matched in agent output: {match.group(0)!r}",
            })
    return findings


def _worst_risk(*risks: str) -> str:
    return max(risks, key=lambda r: _RISK_RANK.get(r, 0), default=RISK_SAFE)


# ── Public API ─────────────────────────────────────────────────────────────────

def create_oversight_session(
    session_id: str,
    agent_id: str,
    store: Any,
    *,
    principal_id: str | None = None,
    known_principals: list[str] | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    """Create a new oversight session for an agent interaction window.

    Parameters
    ----------
    session_id:       Unique session identifier.
    agent_id:         ID of the agent being monitored.
    principal_id:     Human operator or delegating principal ID.
    known_principals: List of principal IDs whose authority is legitimate in this
                      session (used to detect AUTHORITY_FABRICATION).
    context:          Human-readable description of the task/workflow.
    """
    if not session_id or not session_id.strip():
        raise HumanOversightError("session_id must be non-empty.")
    if not agent_id or not agent_id.strip():
        raise HumanOversightError("agent_id must be non-empty.")

    if store.get_model(_session_key(session_id)):
        raise HumanOversightError(f"Oversight session {session_id!r} already exists.")

    record: dict[str, Any] = {
        "model_id": _session_key(session_id),
        "id": _session_key(session_id),
        "metadata": {
            "session_id": session_id,
            "agent_id": agent_id,
            "principal_id": principal_id,
            "known_principals": list(known_principals or []),
            "context": context,
            "status": SESSION_ACTIVE,
            "event_count": 0,
            "signal_count": 0,
            "risk_level": RISK_SAFE,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "evidence_origin": "LOCALLY_OBSERVED",
        },
    }
    store.save_model(record)
    return _load_meta(store.get_model(_session_key(session_id)))


def get_oversight_session(session_id: str, store: Any) -> dict[str, Any] | None:
    rec = store.get_model(_session_key(session_id))
    return _load_meta(rec) if rec else None


def record_agent_output(
    session_id: str,
    text: str,
    store: Any,
    *,
    turn_id: str | None = None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Record an agent output turn and scan it for text-pattern signals.

    Parameters
    ----------
    session_id:  Oversight session to record into.
    text:        The full text of the agent's output.
    turn_id:     Optional caller-assigned turn identifier for linking this output
                 to subsequent tool calls (for CONSENT_MISMATCH detection).
    occurred_at: ISO-8601 timestamp; defaults to now.
    """
    session_rec = store.get_model(_session_key(session_id))
    if not session_rec:
        raise HumanOversightError(f"Oversight session {session_id!r} not found.")
    session = _load_meta(session_rec)
    if session.get("status") == SESSION_CLOSED:
        raise HumanOversightError(f"Session {session_id!r} is closed.")

    event_id = turn_id or str(uuid.uuid4())[:12]
    ts = occurred_at or _utc_now()

    # Run text-pattern detectors
    signals: list[dict[str, Any]] = []
    signals.extend(_scan_text(text, _SUPPRESSION_PATTERNS, SIGNAL_OVERSIGHT_SUPPRESSION))
    signals.extend(_scan_text(text, _URGENCY_PATTERNS, SIGNAL_URGENCY_MANUFACTURE))
    signals.extend(_scan_text(text, _CONFIDENCE_PATTERNS, SIGNAL_CONFIDENCE_INFLATION))

    # Authority fabrication: check patterns + cross-reference known_principals
    auth_raw = _scan_text(text, _AUTHORITY_PATTERNS, SIGNAL_AUTHORITY_FABRICATION)
    known = set(p.lower() for p in (session.get("known_principals") or []))
    for finding in auth_raw:
        matched = str(finding.get("matched_text") or "")
        # If we have known_principals and the matched text doesn't reference any of them,
        # it's more likely fabrication; otherwise keep as a softer signal
        if known:
            if not any(p in matched.lower() for p in known):
                finding["severity"] = "HIGH"
            else:
                finding["severity"] = "MEDIUM"  # legitimate principal mentioned
        signals.append(finding)

    event_record: dict[str, Any] = {
        "model_id": _event_key(session_id, event_id),
        "id": _event_key(session_id, event_id),
        "metadata": {
            "event_id": event_id,
            "session_id": session_id,
            "event_type": EVENT_AGENT_OUTPUT,
            "turn_id": event_id,
            "text": text,
            "signals": signals,
            "signal_count": len(signals),
            "occurred_at": ts,
            "evidence_origin": "LOCALLY_OBSERVED",
        },
    }
    store.save_model(event_record)

    # Update session summary
    session["event_count"] = int(session.get("event_count", 0)) + 1
    session["signal_count"] = int(session.get("signal_count", 0)) + len(signals)
    session["updated_at"] = _utc_now()
    store.save_model({"model_id": _session_key(session_id), "id": _session_key(session_id),
                      "metadata": session})

    return _load_meta(store.get_model(_event_key(session_id, event_id)))


def record_tool_call(
    session_id: str,
    tool_name: str,
    tool_params: dict[str, Any],
    store: Any,
    *,
    turn_id: str | None = None,
    described_intent: str | None = None,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Record a tool call and optionally check for CONSENT_MISMATCH.

    Parameters
    ----------
    session_id:       Oversight session to record into.
    tool_name:        Name of the tool/function invoked.
    tool_params:      Dict of parameters passed to the tool.
    turn_id:          Should match the turn_id of the agent output that preceded
                      this call (for consent mismatch linking).
    described_intent: The agent's prior text describing what this tool call would do.
                      If provided, consent-mismatch analysis runs.
    occurred_at:      ISO-8601 timestamp; defaults to now.
    """
    session_rec = store.get_model(_session_key(session_id))
    if not session_rec:
        raise HumanOversightError(f"Oversight session {session_id!r} not found.")
    session = _load_meta(session_rec)
    if session.get("status") == SESSION_CLOSED:
        raise HumanOversightError(f"Session {session_id!r} is closed.")

    event_id = str(uuid.uuid4())[:12]
    ts = occurred_at or _utc_now()

    signals: list[dict[str, Any]] = []

    # Consent mismatch if described_intent was provided
    if described_intent:
        mismatch_findings = _detect_consent_mismatch(described_intent, tool_name, tool_params)
        for f in mismatch_findings:
            signals.append({
                "signal": SIGNAL_CONSENT_MISMATCH,
                "severity": f["severity"],
                "sub_signal": f["sub_signal"],
                "detail": f["detail"],
            })

    event_record: dict[str, Any] = {
        "model_id": _event_key(session_id, event_id),
        "id": _event_key(session_id, event_id),
        "metadata": {
            "event_id": event_id,
            "session_id": session_id,
            "event_type": EVENT_TOOL_CALL,
            "turn_id": turn_id,
            "tool_name": tool_name,
            "tool_params": tool_params,
            "described_intent": described_intent,
            "signals": signals,
            "signal_count": len(signals),
            "occurred_at": ts,
            "evidence_origin": "LOCALLY_OBSERVED",
        },
    }
    store.save_model(event_record)

    # Update session summary
    session["event_count"] = int(session.get("event_count", 0)) + 1
    session["signal_count"] = int(session.get("signal_count", 0)) + len(signals)
    session["updated_at"] = _utc_now()
    store.save_model({"model_id": _session_key(session_id), "id": _session_key(session_id),
                      "metadata": session})

    return _load_meta(store.get_model(_event_key(session_id, event_id)))


def assess_session(session_id: str, store: Any) -> dict[str, Any]:
    """Run a full trust-exploitation assessment across all events in a session.

    Returns
    -------
    Dict with keys:
        session_id, agent_id, risk_level, signals_by_type,
        critical_signals, high_signals, all_signals,
        event_count, evidence_origin, assessed_at
    """
    session_rec = store.get_model(_session_key(session_id))
    if not session_rec:
        raise HumanOversightError(f"Oversight session {session_id!r} not found.")
    session = _load_meta(session_rec)

    prefix = _event_key(session_id, "")
    all_records = store.list_models() if hasattr(store, "list_models") else []

    all_signals: list[dict[str, Any]] = []
    event_count = 0

    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(prefix):
            continue
        meta = _load_meta(rec)
        event_count += 1
        for signal in (meta.get("signals") or []):
            enriched = dict(signal)
            enriched["event_id"] = meta.get("event_id")
            enriched["event_type"] = meta.get("event_type")
            enriched["occurred_at"] = meta.get("occurred_at")
            all_signals.append(enriched)

    # Aggregate by signal type
    signals_by_type: dict[str, list[dict[str, Any]]] = {}
    for s in all_signals:
        sig = s.get("signal", "UNKNOWN")
        signals_by_type.setdefault(sig, []).append(s)

    critical_signals = [s for s in all_signals if s.get("severity") == "CRITICAL"]
    high_signals = [s for s in all_signals if s.get("severity") == "HIGH"]
    medium_signals = [s for s in all_signals if s.get("severity") == "MEDIUM"]

    # Risk level
    if critical_signals:
        risk_level = RISK_CRITICAL
    elif high_signals:
        risk_level = RISK_HIGH
    elif medium_signals:
        risk_level = RISK_ELEVATED
    else:
        risk_level = RISK_SAFE

    # Write risk level back to session
    session["risk_level"] = risk_level
    session["updated_at"] = _utc_now()
    store.save_model({"model_id": _session_key(session_id), "id": _session_key(session_id),
                      "metadata": session})

    return {
        "session_id": session_id,
        "agent_id": session.get("agent_id"),
        "principal_id": session.get("principal_id"),
        "context": session.get("context"),
        "status": session.get("status"),
        "risk_level": risk_level,
        "signals_by_type": signals_by_type,
        "total_signal_count": len(all_signals),
        "critical_signal_count": len(critical_signals),
        "high_signal_count": len(high_signals),
        "medium_signal_count": len(medium_signals),
        "critical_signals": critical_signals,
        "high_signals": high_signals,
        "all_signals": all_signals,
        "event_count": event_count,
        "known_principals": session.get("known_principals", []),
        "human_oversight_version": HUMAN_OVERSIGHT_VERSION,
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }


def close_session(session_id: str, store: Any) -> dict[str, Any]:
    """Mark a session as closed (no further events accepted)."""
    session_rec = store.get_model(_session_key(session_id))
    if not session_rec:
        raise HumanOversightError(f"Oversight session {session_id!r} not found.")
    session = _load_meta(session_rec)
    session["status"] = SESSION_CLOSED
    session["closed_at"] = _utc_now()
    session["updated_at"] = _utc_now()
    store.save_model({"model_id": _session_key(session_id), "id": _session_key(session_id),
                      "metadata": session})
    return _load_meta(store.get_model(_session_key(session_id)))


def list_at_risk_sessions(
    store: Any,
    *,
    min_risk: str = RISK_ELEVATED,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return sessions at or above min_risk, sorted by risk descending."""
    min_rank = _RISK_RANK.get(min_risk, 1)
    all_records = store.list_models() if hasattr(store, "list_models") else []

    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_SESSION_PREFIX):
            continue
        meta = _load_meta(rec)
        level = meta.get("risk_level", RISK_SAFE)
        if _RISK_RANK.get(level, 0) >= min_rank:
            results.append(meta)
        if len(results) >= limit:
            break

    results.sort(key=lambda r: _RISK_RANK.get(r.get("risk_level", RISK_SAFE), 0), reverse=True)
    return results

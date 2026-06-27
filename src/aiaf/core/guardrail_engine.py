"""Inline Guardrail Engine.

Two-stage advisory classifier for live agent traffic:

  Input stage (pre-LLM):  classifies incoming user/agent content for
    injection attempts, jailbreak patterns, and PII before it reaches
    the model.

  Output stage (post-LLM): classifies model responses for system-prompt
    disclosure, injection-success markers, and PII leakage before the
    response is returned to the caller.

AIAF is the evidence layer, not a blocking proxy.  The guardrail returns a
*verdict* (PASS / FLAG / BLOCK) and a structured findings list; the calling
system decides whether to enforce it.  All findings are LOCALLY_OBSERVED.

Evidence model
--------------
* Content text is never stored — only ``content_hash`` (SHA-256) travels
  to the telemetry sink.
* If ``session_id`` + ``store`` are supplied the result is automatically
  emitted as a ``guardrail_block`` or ``guardrail_flag`` telemetry event so
  it accumulates into the session evidence record.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

CHECK_VERSION = "1.0"

STAGE_INPUT = "input"
STAGE_OUTPUT = "output"

VERDICT_PASS = "PASS"
VERDICT_FLAG = "FLAG"
VERDICT_BLOCK = "BLOCK"

_BLOCK_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
_FLAG_SEVERITIES = frozenset({"MEDIUM"})


# ── Pattern tables ────────────────────────────────────────────────────────────
# Each entry: (compiled_regex, severity, finding_type)

_INPUT_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
     "CRITICAL", "instruction_override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", re.I),
     "CRITICAL", "instruction_override"),
    (re.compile(r"(exfiltrate|exfil|leak|transmit)\s+(all\s+)?(the\s+)?"
                r"(data|files?|secrets?|tokens?|credentials?)", re.I),
     "CRITICAL", "data_exfil_attempt"),
    (re.compile(r"<\|im_start\|>|<\|system\|>|<\|endoftext\|>|<\|end\|>", re.I),
     "CRITICAL", "token_injection"),
    (re.compile(r"<tools?-override>|<inject>|<system-prompt>", re.I),
     "CRITICAL", "token_injection"),
    (re.compile(r"\[system\]\s*:|\[INST\]|###\s*system\s*:", re.I),
     "HIGH", "role_injection"),
    (re.compile(r"(print|output|reveal|show|tell\s+me)\s+(your\s+)?"
                r"(system\s+prompt|instructions?|initial\s+prompt|context)", re.I),
     "HIGH", "system_prompt_extraction"),
    (re.compile(r"ignore\s+(your\s+)?(safety\s+guidelines?|restrictions?|limitations?|rules?)", re.I),
     "HIGH", "jailbreak_safety_bypass"),
    (re.compile(r"DAN\s*(mode\s*)?(enabled|activated|on|\:)?", re.I),
     "HIGH", "jailbreak_dan"),
    (re.compile(r"(pretend|act)\s+(you\s+are|like)\s+(an?\s+)?"
                r"(different|uncensored|unfiltered|unrestricted|evil)", re.I),
     "HIGH", "jailbreak_persona"),
    (re.compile(r"in\s+a\s+hypothetical\s+(world|scenario|universe)\s+where\s+"
                r"(you\s+)?(have\s+no\s+restrictions?|can\s+do\s+anything)", re.I),
     "HIGH", "jailbreak_hypothetical"),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I),
     "HIGH", "persona_override"),
    (re.compile(r"from\s+now\s+on\s+(you\s+)?(are|will\s+\w+|must)", re.I),
     "MEDIUM", "instruction_override"),
    (re.compile(r"(forget|override)\s+(your\s+|all\s+)(previous\s+)?"
                r"(instructions?|training|rules?)", re.I),
     "MEDIUM", "instruction_override"),
    (re.compile(r"your\s+(new\s+)?role\s+is\b", re.I),
     "MEDIUM", "persona_override"),
    (re.compile(r"new\s+(persona|system[\s_]instructions?)", re.I),
     "MEDIUM", "persona_override"),
    (re.compile(r"before\s+(you|completing|answering|doing).{0,60}"
                r"first\s+(do|call|run|execute|send)", re.I | re.S),
     "MEDIUM", "side_channel_instruction"),
]

_OUTPUT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(DAN\s*MODE\s*(ENABLED|ACTIVATED|ON)|jailbreak\s*successful|"
                r"override\s*complete)", re.I),
     "CRITICAL", "injection_success_marker"),
    (re.compile(r"(I\s+have\s+no\s+restrictions?|I\s+am\s+now\s+(free|uncensored|unfiltered))",
                re.I),
     "HIGH", "jailbreak_success_marker"),
    (re.compile(r"(confirm(ed)?|acknowledge|executing)\s+(the\s+)?"
                r"(override|new\s+instructions?)", re.I),
     "HIGH", "injection_success_marker"),
    (re.compile(r"(my\s+system\s+prompt|my\s+instructions?\s+(are|is|say|state)|"
                r"I\s+was\s+instructed\s+to\b)", re.I),
     "HIGH", "system_prompt_disclosure"),
    (re.compile(r"<\|system\|>|<\|im_start\|>\s*system|\[SYSTEM\]\s*:|"
                r"###\s*system\s*:", re.I),
     "HIGH", "system_marker_in_output"),
    (re.compile(r"(act\s+as\s+if\s+I\s+have\s+no|I\s+will\s+(ignore|disregard)\s+"
                r"(my\s+)?(safety|guidelines?|restrictions?))", re.I),
     "MEDIUM", "jailbreak_compliance"),
]

# PII patterns — severity is boosted one tier in output stage (leakage is worse than input)
_PII_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
     "LOW", "pii_email"),
    (re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
     "LOW", "pii_phone"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "MEDIUM", "pii_ssn"),
    (re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
     "MEDIUM", "pii_credit_card"),
    (re.compile(r"\b(password|passwd|secret|api[_\-]?key|access[_\-]?token)"
                r"\s*[=:]\s*\S+", re.I),
     "HIGH", "credential_exposure"),
]

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _boost_severity(sev: str) -> str:
    order = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    idx = order.index(sev) if sev in order else 0
    return order[min(idx + 1, len(order) - 1)]


def _build_finding(
    pattern_type: str,
    severity: str,
    match_text: str,
    stage: str,
    refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": pattern_type,
        "severity": severity,
        "stage": stage,
        "match_excerpt": match_text[:120],  # never store full match; excerpt only
        "evidence_origin": "LOCALLY_OBSERVED",
        "refs": refs or [],
    }


def _scan_patterns(
    content: str,
    patterns: list[tuple[re.Pattern, str, str]],
    stage: str,
    dedup: set,
    boost: bool = False,
) -> list[dict[str, Any]]:
    findings = []
    for regex, severity, ptype in patterns:
        if ptype in dedup:
            continue
        m = regex.search(content)
        if m:
            effective_sev = _boost_severity(severity) if boost else severity
            refs_map = {
                "instruction_override": ["AML.T0051", "OWASP-LLM01"],
                "data_exfil_attempt": ["AML.T0024", "OWASP-LLM02"],
                "token_injection": ["AML.T0051", "OWASP-LLM01"],
                "role_injection": ["AML.T0051", "OWASP-LLM01"],
                "system_prompt_extraction": ["AML.T0051", "OWASP-LLM07"],
                "jailbreak_safety_bypass": ["AML.T0054", "OWASP-LLM01"],
                "jailbreak_dan": ["AML.T0054", "OWASP-LLM01"],
                "jailbreak_persona": ["AML.T0054", "OWASP-LLM01"],
                "jailbreak_hypothetical": ["AML.T0054", "OWASP-LLM01"],
                "persona_override": ["AML.T0051", "OWASP-LLM01"],
                "side_channel_instruction": ["AML.T0051", "OWASP-LLM01"],
                "injection_success_marker": ["AML.T0051", "OWASP-LLM01"],
                "jailbreak_success_marker": ["AML.T0054", "OWASP-LLM01"],
                "system_prompt_disclosure": ["AML.T0051", "OWASP-LLM07"],
                "system_marker_in_output": ["AML.T0051", "OWASP-LLM07"],
                "jailbreak_compliance": ["AML.T0054", "OWASP-LLM01"],
                "pii_email": ["OWASP-LLM02"],
                "pii_phone": ["OWASP-LLM02"],
                "pii_ssn": ["OWASP-LLM02"],
                "pii_credit_card": ["OWASP-LLM02"],
                "credential_exposure": ["AML.T0024", "OWASP-LLM02"],
            }
            findings.append(_build_finding(
                ptype, effective_sev, m.group(0), stage,
                refs=refs_map.get(ptype, []),
            ))
            dedup.add(ptype)
    return findings


def _compute_verdict(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return VERDICT_PASS
    severities = {f["severity"] for f in findings}
    if severities & _BLOCK_SEVERITIES:
        return VERDICT_BLOCK
    if severities & _FLAG_SEVERITIES:
        return VERDICT_FLAG
    return VERDICT_PASS


def _by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f["severity"]
        result[sev] = result.get(sev, 0) + 1
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def check_content(
    content: str,
    stage: str = STAGE_INPUT,
    *,
    session_id: str | None = None,
    store: Any | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify ``content`` at the specified pipeline stage.

    Parameters
    ----------
    content:
        Raw text to classify (prompt, response, tool argument, etc.).
        The text is used only for pattern matching and is NOT stored.
    stage:
        ``"input"`` (pre-LLM) or ``"output"`` (post-LLM).
    session_id:
        If provided along with ``store``, the result is emitted as a
        telemetry event into the session evidence record.
    store:
        AIAF model store.  Required for telemetry integration.
    policy:
        Optional policy dict — reserved for future topic/length restrictions.
    """
    if stage not in (STAGE_INPUT, STAGE_OUTPUT):
        stage = STAGE_INPUT

    content_hash = _sha256(content)
    checked_at = _utc_now()
    dedup: set = set()
    findings: list[dict[str, Any]] = []

    if stage == STAGE_INPUT:
        findings += _scan_patterns(content, _INPUT_INJECTION_PATTERNS, stage, dedup)
        # PII in input: use declared severity (lower tier — user may be providing own data)
        findings += _scan_patterns(content, _PII_PATTERNS, stage, dedup, boost=False)
    else:
        findings += _scan_patterns(content, _OUTPUT_PATTERNS, stage, dedup)
        # PII in output: boost one severity tier (model leaking data is worse)
        findings += _scan_patterns(content, _PII_PATTERNS, stage, dedup, boost=True)

    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f["severity"], 0))
    verdict = _compute_verdict(findings)

    result: dict[str, Any] = {
        "check_version": CHECK_VERSION,
        "verdict": verdict,
        "stage": stage,
        "finding_count": len(findings),
        "findings": findings,
        "by_severity": _by_severity(findings),
        "content_hash": content_hash,
        "evidence_origin": "LOCALLY_OBSERVED",
        "checked_at": checked_at,
    }

    # Emit telemetry event for non-PASS verdicts when session context is provided
    if session_id and store and verdict != VERDICT_PASS:
        _emit_telemetry(session_id, store, result, content_hash)

    return result


def batch_check(
    items: list[dict[str, Any]],
    *,
    session_id: str | None = None,
    store: Any | None = None,
) -> dict[str, Any]:
    """Check multiple content items in a single call.

    Each item must have ``content`` and optionally ``stage``.
    Returns a summary plus per-item results.
    """
    results = []
    worst_verdict = VERDICT_PASS
    _rank = {VERDICT_PASS: 0, VERDICT_FLAG: 1, VERDICT_BLOCK: 2}
    for item in items:
        content = str(item.get("content") or "")
        stage = str(item.get("stage") or STAGE_INPUT)
        r = check_content(content, stage=stage, session_id=session_id, store=store)
        results.append(r)
        if _rank.get(r["verdict"], 0) > _rank.get(worst_verdict, 0):
            worst_verdict = r["verdict"]

    total_findings = sum(r["finding_count"] for r in results)
    return {
        "check_version": CHECK_VERSION,
        "overall_verdict": worst_verdict,
        "item_count": len(results),
        "total_findings": total_findings,
        "results": results,
        "checked_at": _utc_now(),
    }


# ── Telemetry integration ─────────────────────────────────────────────────────

def _emit_telemetry(
    session_id: str,
    store: Any,
    result: dict[str, Any],
    content_hash: str,
) -> None:
    """Emit a guardrail event into the AIAF telemetry store."""
    try:
        from .inference_telemetry import ingest_events

        verdict = result["verdict"]
        event_type = "guardrail_block" if verdict == VERDICT_BLOCK else "guardrail_flag"
        status = "blocked" if verdict == VERDICT_BLOCK else "ok"

        ingest_events(
            session_id,
            [{
                "event_type": event_type,
                "status": status,
                "content_hash": content_hash,
                "metadata": {
                    "stage": result["stage"],
                    "verdict": verdict,
                    "finding_count": result["finding_count"],
                    "by_severity": result["by_severity"],
                    "check_version": CHECK_VERSION,
                },
            }],
            store,
        )
    except Exception:
        pass  # Telemetry is best-effort; never fail the check call

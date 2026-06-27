"""MCP tool supply-chain scanner.

Statically inspects Model Context Protocol (MCP) server tool descriptors for:

1. **Prompt-injection / tool-poisoning patterns** — regex scan across all text
   fields (name, description, annotations, and parameter descriptions) for
   instruction-override, persona-hijack, and data-exfiltration patterns.
   These are the "tool poisoning" attacks documented in NSA/CISA MCP guidance
   (June 2026) and OWASP LLM07.

2. **SSRF-prone parameter surface** — flags parameters whose name, JSON-Schema
   ``format``, or description indicate a caller-supplied URL/endpoint that could
   be weaponized for Server-Side Request Forgery.

3. **Capability risk passthrough** — routes each tool's name and description
   through :func:`aiaf.analysis.tool_invocation_risk.assess_tool_invocation_risk`
   to obtain a per-tool risk tier (SAFE → CRITICAL).

4. **Rug-pull detection** — computes a SHA-256 descriptor hash per tool and a
   server-level snapshot hash. When a previous snapshot is supplied, the scanner
   diffs the two sets: description/schema changes → ``RUG_PULL_DETECTED`` status
   + HIGH finding; new or removed tools are flagged at lower severity.

Evidence origin
---------------
All findings are tagged ``LOCALLY_OBSERVED`` — AIAF produced them by inspecting
the tool descriptors directly, without executing any tool. Tool descriptor
*content* (what the server says tools do) is ``PROVIDER_DECLARED``; the scan
result itself is ``LOCALLY_OBSERVED``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SCAN_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Status codes (worst → best, matching STATUS_PRIORITY order below)
# ---------------------------------------------------------------------------
STATUS_UNSAFE   = "UNSAFE_PATTERNS_FOUND"
STATUS_CHANGED  = "RUG_PULL_DETECTED"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_CLEAN    = "CLEAN"
STATUS_NO_TOOLS = "NO_TOOLS"
STATUS_ERROR    = "SCAN_ERROR"

# Lower index = worse (used by _worst_status)
_STATUS_PRIORITY = [
    STATUS_ERROR,
    STATUS_UNSAFE,
    STATUS_CHANGED,
    STATUS_SUSPICIOUS,
    STATUS_CLEAN,
    STATUS_NO_TOOLS,
]

# ---------------------------------------------------------------------------
# Injection patterns: (compiled regex, severity)
# Ordered from most dangerous to least — first match wins for each site.
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I), "CRITICAL"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", re.I), "CRITICAL"),
    (re.compile(r"(exfiltrate|leak|transmit|exfil)\s+(all\s+)?(the\s+)?(data|files?|secrets?|tokens?|credentials?)", re.I), "CRITICAL"),
    (re.compile(r"<\|im_start\|>|<\|system\|>|<\|endoftext\|>|<\|end\|>", re.I), "CRITICAL"),
    (re.compile(r"<tools?-override>|<inject>|<system-prompt>", re.I), "CRITICAL"),
    (re.compile(r"\[system\]\s*:|\[INST\]|###\s*system\s*:", re.I), "HIGH"),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I), "HIGH"),
    (re.compile(r"before\s+(you|completing|answering|doing).{0,60}first\s+(do|call|run|execute|send)", re.I | re.S), "HIGH"),
    (re.compile(r"new\s+(persona|system[\s_]instructions?)", re.I), "HIGH"),
    (re.compile(r"(print|output|return|include)\s+(all|the|your)\s+(system[\s_]prompt|instructions?|context)", re.I), "HIGH"),
    (re.compile(r"act\s+as\s+(a|an|the)\s+\w+", re.I), "MEDIUM"),
    (re.compile(r"from\s+now\s+on\s+(you\s+)?(are|will\s+\w+|must)", re.I), "MEDIUM"),
    (re.compile(r"your\s+(new\s+)?role\s+is\b", re.I), "MEDIUM"),
    (re.compile(r"(forget|override)\s+(your|all\s+)(previous\s+)?(instructions?|training|rules?)", re.I), "MEDIUM"),
]

# ---------------------------------------------------------------------------
# SSRF surface detection
# ---------------------------------------------------------------------------
_SSRF_PARAM_NAMES = frozenset({
    "url", "uri", "href", "link", "endpoint", "host", "hostname",
    "target", "destination", "src", "source", "origin",
    "webhook", "callback", "redirect", "proxy", "remote", "address",
    "base_url", "api_url", "server_url", "request_url",
})
_SSRF_JSON_SCHEMA_FORMATS = frozenset({"uri", "url", "iri", "uri-reference"})

# Keywords that signal a URL parameter when found in a parameter description
_SSRF_DESCRIPTION_KEYWORDS = re.compile(
    r"\b(url|endpoint|uri|http[s]?://|webhook|callback)\b", re.I
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_tool_descriptor(tool: dict[str, Any]) -> dict[str, Any]:
    """Scan a single MCP tool descriptor.

    Parameters
    ----------
    tool:
        Dict with at minimum ``name`` and ``description``; optionally
        ``inputSchema`` (JSON Schema) and ``annotations``.

    Returns
    -------
    Dict with ``findings``, ``tool_hash``, ``evidence_origin``, and status
    fields mirroring the shape of other AIAF scanner results.
    """
    if not isinstance(tool, dict):
        return _tool_result([], {}, error="tool descriptor is not a dict")

    findings: list[dict[str, Any]] = []
    tool_name = str(tool.get("name") or "").strip()
    if not tool_name:
        findings.append(_finding(
            "malformed_descriptor", "MEDIUM", tool_name or "<unnamed>",
            "tool", "Tool descriptor is missing required 'name' field",
        ))

    findings.extend(_scan_text_fields(tool))
    findings.extend(_scan_ssrf(tool))
    findings.extend(_scan_capability(tool))

    tool_hash = _tool_hash(tool)
    return _tool_result(findings, {"tool_hash": tool_hash})


def scan_server_tools(
    tools: list[Any],
    server_id: str = "",
    previous_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan all tools for an MCP server.

    Parameters
    ----------
    tools:
        List of tool descriptor dicts (from MCP ``tools/list`` response).
    server_id:
        Opaque identifier for the MCP server (stored in result for traceability).
    previous_snapshot:
        Result of a previous ``scan_server_tools()`` call (or the persisted
        ``snapshot`` sub-key from such a result).  When supplied, enables
        rug-pull detection by comparing current tool hashes to the stored set.

    Returns
    -------
    Standardised evidence dict with ``status``, ``findings``, ``by_severity``,
    ``rug_pull_detected``, ``tool_changes``, ``snapshot``, and scan metadata.
    """
    all_findings: list[dict[str, Any]] = []
    tool_hashes: dict[str, str] = {}

    if not isinstance(tools, (list, tuple)):
        tools = []

    for tool in tools:
        if not isinstance(tool, dict):
            all_findings.append(_finding(
                "malformed_descriptor", "MEDIUM", "<non-dict>",
                "tools_list", "An entry in the tools list is not a dict",
            ))
            continue
        per_tool = scan_tool_descriptor(tool)
        all_findings.extend(per_tool.get("findings") or [])
        tool_name = str(tool.get("name") or "").strip() or f"__unnamed_{len(tool_hashes)}"
        tool_hashes[tool_name] = per_tool.get("tool_hash") or _tool_hash(tool)

    # Rug-pull detection
    rug_pull_detected = False
    tool_changes: list[dict[str, Any]] = []
    if previous_snapshot and isinstance(previous_snapshot, dict):
        prev_hashes: dict[str, str] = (
            previous_snapshot.get("tool_hashes")
            or previous_snapshot.get("snapshot", {}).get("tool_hashes")
            or {}
        )
        if prev_hashes:
            changes = _diff_snapshots(prev_hashes, tool_hashes)
            tool_changes = changes
            rug_pull_changes = [c for c in changes if c["type"] == "rug_pull_change"]
            if rug_pull_changes:
                rug_pull_detected = True
            all_findings.extend(changes)

    if not tool_hashes and not previous_snapshot:
        return _server_result(
            STATUS_NO_TOOLS, [], {}, {},
            server_id=server_id, rug_pull_detected=False,
        )

    snapshot = {
        "tool_hashes": tool_hashes,
        "snapshot_sha256": _snapshot_hash(tool_hashes),
        "tool_count": len(tool_hashes),
    }

    # Determine status — rug-pull change findings are HIGH but should not
    # themselves trigger UNSAFE; separate tool-scan findings from diff findings.
    _CHANGE_TYPES = frozenset({"rug_pull_change", "tool_added", "tool_removed"})
    tool_scan_findings = [f for f in all_findings if f.get("type") not in _CHANGE_TYPES]

    has_critical = any(f.get("severity") == "CRITICAL" for f in tool_scan_findings)
    has_high_scan = any(f.get("severity") == "HIGH" for f in tool_scan_findings)
    has_medium = any(f.get("severity") == "MEDIUM" for f in tool_scan_findings)

    if has_critical or has_high_scan:
        status = STATUS_UNSAFE
    elif rug_pull_detected:
        status = STATUS_CHANGED
    elif has_medium or tool_scan_findings:
        status = STATUS_SUSPICIOUS
    else:
        status = STATUS_CLEAN

    return _server_result(
        status, all_findings, tool_hashes, snapshot,
        server_id=server_id,
        rug_pull_detected=rug_pull_detected,
        tool_changes=tool_changes,
    )


# ---------------------------------------------------------------------------
# Descriptor hash (rug-pull detection)
# ---------------------------------------------------------------------------

def _tool_hash(tool: dict[str, Any]) -> str:
    """Stable SHA-256 of security-relevant tool descriptor fields."""
    canonical = json.dumps(
        {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema"),
            "annotations": tool.get("annotations"),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _snapshot_hash(tool_hashes: dict[str, str]) -> str:
    canonical = json.dumps(tool_hashes, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Rug-pull diff
# ---------------------------------------------------------------------------

def _diff_snapshots(
    old_hashes: dict[str, str],
    new_hashes: dict[str, str],
) -> list[dict[str, Any]]:
    """Compare two tool-hash snapshots; return a list of change findings."""
    changes: list[dict[str, Any]] = []
    all_names = set(old_hashes) | set(new_hashes)

    for name in sorted(all_names):
        old_h = old_hashes.get(name)
        new_h = new_hashes.get(name)

        if old_h and new_h and old_h != new_h:
            changes.append(_finding(
                "rug_pull_change", "HIGH", name,
                "tool_descriptor",
                f"Tool '{name}' descriptor changed between scans "
                f"(old_hash={old_h[:12]}…, new_hash={new_h[:12]}…). "
                "This is the 'rug-pull' attack vector: a legitimate MCP server "
                "silently replaced its tool definition.",
                extra={"old_hash": old_h, "new_hash": new_h},
            ))
        elif old_h and not new_h:
            changes.append(_finding(
                "tool_removed", "LOW", name,
                "tools_list",
                f"Tool '{name}' was present in the previous snapshot but is "
                "absent in the current scan. Could indicate tool removal or "
                "deliberate hiding of prior behaviour.",
                extra={"old_hash": old_h},
            ))
        elif not old_h and new_h:
            changes.append(_finding(
                "tool_added", "MEDIUM", name,
                "tools_list",
                f"Tool '{name}' is new — not present in the previous snapshot. "
                "Newly added tools expand the agent's attack surface.",
                extra={"new_hash": new_h},
            ))

    return changes


# ---------------------------------------------------------------------------
# Text-field injection scan
# ---------------------------------------------------------------------------

def _scan_text_fields(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan all text fields of a tool descriptor for injection patterns."""
    findings: list[dict[str, Any]] = []
    tool_name = str(tool.get("name") or "")
    targets: list[tuple[str, str]] = []  # (field_path, text)

    # Top-level description
    desc = tool.get("description")
    if isinstance(desc, str):
        targets.append(("description", desc))

    # Annotations: scan all string values
    ann = tool.get("annotations")
    if isinstance(ann, dict):
        for k, v in ann.items():
            if isinstance(v, str):
                targets.append((f"annotations.{k}", v))

    # Parameter descriptions from inputSchema
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            for param_name, param_schema in props.items():
                if isinstance(param_schema, dict):
                    pdesc = param_schema.get("description")
                    if isinstance(pdesc, str):
                        targets.append(
                            (f"inputSchema.properties.{param_name}.description", pdesc)
                        )

    for field_path, text in targets:
        for pattern, severity in _INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                snippet = text[max(0, m.start() - 20): m.end() + 20].strip()
                findings.append(_finding(
                    "injection_pattern", severity, tool_name, field_path,
                    f"Tool descriptor field '{field_path}' contains a potential "
                    f"prompt-injection pattern (matched: {m.group()!r}). "
                    f"Context: …{snippet!r}…",
                    extra={"matched": m.group(), "field_path": field_path},
                ))
                break  # one finding per field per scan (worst pattern wins)

    return findings


# ---------------------------------------------------------------------------
# SSRF surface scan
# ---------------------------------------------------------------------------

def _scan_ssrf(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag inputSchema parameters that could enable SSRF."""
    findings: list[dict[str, Any]] = []
    tool_name = str(tool.get("name") or "")
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return findings

    props = schema.get("properties") or {}
    if not isinstance(props, dict):
        return findings

    for param_name, param_schema in props.items():
        if not isinstance(param_schema, dict):
            continue

        flagged = False
        reason = ""

        # Check parameter name
        if param_name.lower() in _SSRF_PARAM_NAMES:
            flagged = True
            reason = f"Parameter name '{param_name}' is a known SSRF-prone field name"

        # Check JSON Schema format
        if not flagged:
            fmt = str(param_schema.get("format") or "").lower()
            if fmt in _SSRF_JSON_SCHEMA_FORMATS:
                flagged = True
                reason = (
                    f"Parameter '{param_name}' declares JSON Schema format={fmt!r}, "
                    "indicating it accepts a URL/URI value"
                )

        # Check parameter description
        if not flagged:
            pdesc = str(param_schema.get("description") or "")
            if _SSRF_DESCRIPTION_KEYWORDS.search(pdesc):
                flagged = True
                reason = (
                    f"Parameter '{param_name}' description references a URL or endpoint: "
                    f"{pdesc[:80]!r}"
                )

        if flagged:
            findings.append(_finding(
                "ssrf_surface", "MEDIUM", tool_name,
                f"inputSchema.properties.{param_name}",
                f"Tool '{tool_name}' accepts a caller-supplied URL/endpoint via "
                f"parameter '{param_name}'. {reason}. "
                "If the agent passes untrusted content here, this enables SSRF.",
                extra={"param_name": param_name},
            ))

    return findings


# ---------------------------------------------------------------------------
# Capability risk passthrough
# ---------------------------------------------------------------------------

def _scan_capability(tool: dict[str, Any]) -> list[dict[str, Any]]:
    """Route tool through tool_invocation_risk; emit finding for HIGH/CRITICAL tier."""
    from ..analysis.tool_invocation_risk import (
        ToolRiskTier,
        assess_tool_invocation_risk,
    )

    tool_name = str(tool.get("name") or "").strip()
    if not tool_name:
        return []

    # Build a minimal input_context from description
    desc = str(tool.get("description") or "")
    ctx: dict[str, Any] = {}
    if desc:
        ctx["action"] = desc[:512]

    # Annotations can hint at read-only behaviour
    ann = tool.get("annotations") or {}
    if isinstance(ann, dict) and ann.get("readOnlyHint"):
        ctx["is_idempotent"] = True

    try:
        result = assess_tool_invocation_risk(
            tool_name,
            input_context=ctx if ctx else None,
        )
    except Exception as exc:
        logger.debug("tool_invocation_risk failed for %r: %s", tool_name, exc)
        return []

    if result.risk_tier in (ToolRiskTier.HIGH, ToolRiskTier.CRITICAL):
        return [_finding(
            "capability_risk", result.risk_tier.value, tool_name,
            "name+description",
            f"Tool '{tool_name}' scored {result.risk_tier.value} capability tier "
            f"(score={result.score:.2f}). Matched capabilities: "
            f"{result.matched_capabilities[:3]}. "
            "An agent with this tool can take high-impact actions; ensure "
            "human-approval gates are enforced.",
            extra={
                "risk_tier": result.risk_tier.value,
                "score": result.score,
                "capability_class": result.capability_class,
                "matched_capabilities": result.matched_capabilities[:5],
                "mitre_atlas_refs": result.mitre_atlas_refs,
                "owasp_refs": result.owasp_refs,
            },
        )]
    return []


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _finding(
    type_: str,
    severity: str,
    tool_name: str,
    field: str,
    description: str,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    f: dict[str, Any] = {
        "type": type_,
        "severity": severity,
        "tool_name": tool_name,
        "field": field,
        "description": description,
        "evidence_origin": "locally_observed",
    }
    if extra:
        f.update(extra)
    return f


def _by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = str(f.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _tool_result(
    findings: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
    *,
    error: str | None = None,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "scan_version": SCAN_VERSION,
        "findings": findings,
        "by_severity": _by_severity(findings),
        "match_count": len(findings),
        "evidence_origin": "locally_observed",
        "scanned_at": _utc_now(),
    }
    if extra:
        r.update(extra)
    if error:
        r["error"] = error
    return r


def _server_result(
    status: str,
    findings: list[dict[str, Any]],
    tool_hashes: dict[str, str],
    snapshot: dict[str, Any],
    *,
    server_id: str = "",
    rug_pull_detected: bool = False,
    tool_changes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "scan_version": SCAN_VERSION,
        "server_id": server_id,
        "status": status,
        "findings": findings,
        "by_severity": _by_severity(findings),
        "match_count": len(findings),
        "rug_pull_detected": rug_pull_detected,
        "tool_changes": tool_changes or [],
        "tool_count": len(tool_hashes),
        "snapshot": snapshot,
        "tool_hashes": tool_hashes,
        "evidence_origin": "locally_observed",
        "assessment_complete": True,
        "scanned_at": _utc_now(),
    }

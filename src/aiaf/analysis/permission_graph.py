"""Permission Graph Analyser.

Analyses the structural security of an agent's permission set by reasoning
over the *combination* of capabilities its tool inventory grants — not just
each tool in isolation.

The central insight: individual tools may be low-risk, but combinations
create attack paths.  An agent that can read customer PII AND send external
HTTP requests has an exfiltration path, regardless of each tool's own risk
rating.  This module detects such paths.

Evidence model
--------------
All findings are ``LOCALLY_OBSERVED``: derived from the registered capability
flags and tool inventory, not from runtime observation.

Status hierarchy
----------------
``CRITICAL_RISK`` > ``RISK_DETECTED`` > ``SUSPICIOUS`` > ``CLEAN``

Detection catalogue
-------------------
H1 ``exfiltration_path``      — (data/file/memory READ) + network_egress, no approval gate
H2 ``code_execution_risk``    — code_execution capability present
H3 ``subagent_spawn_risk``    — subagent_spawn capability present (lateral movement)
H4 ``approval_bypass_risk``   — approval_bypass capability (safety gate removed)
H5 ``write_without_gate``     — destructive write capability without approval gate
H6 ``over_permissioned``      — EXTERNAL/USER/UNTRUSTED agent with CRITICAL capabilities
H7 ``undeclared_tool_caps``   — tool_capabilities includes tools not in declared_tools
H8 ``excessive_tool_count``   — declared_tools count exceeds policy threshold
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

GRAPH_VERSION = "1.0"

# ── Status constants ──────────────────────────────────────────────────────────

STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_RISK_DETECTED = "RISK_DETECTED"
STATUS_CRITICAL_RISK = "CRITICAL_RISK"

_STATUS_RANK: dict[str, int] = {
    STATUS_CLEAN: 0,
    STATUS_SUSPICIOUS: 1,
    STATUS_RISK_DETECTED: 2,
    STATUS_CRITICAL_RISK: 3,
}

# ── Capability imports ────────────────────────────────────────────────────────
# Imported lazily to avoid circular imports; defined as string constants here
# so analysis can run without the registry package.

_CAP_NETWORK_EGRESS = "network_egress"
_CAP_FILE_READ = "file_read"
_CAP_FILE_WRITE = "file_write"
_CAP_CODE_EXECUTION = "code_execution"
_CAP_DATA_READ = "data_read"
_CAP_DATA_WRITE = "data_write"
_CAP_TOOL_INVOCATION = "tool_invocation"
_CAP_SUBAGENT_SPAWN = "subagent_spawn"
_CAP_APPROVAL_BYPASS = "approval_bypass"
_CAP_MEMORY_READ = "memory_read"
_CAP_MEMORY_WRITE = "memory_write"

_READ_CAPS: set[str] = {_CAP_DATA_READ, _CAP_FILE_READ, _CAP_MEMORY_READ}
_WRITE_CAPS: set[str] = {_CAP_DATA_WRITE, _CAP_FILE_WRITE, _CAP_MEMORY_WRITE}
_CRITICAL_CAPS: set[str] = {_CAP_CODE_EXECUTION, _CAP_SUBAGENT_SPAWN, _CAP_APPROVAL_BYPASS}

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_LOW_TRUST = frozenset({"EXTERNAL", "USER", "UNTRUSTED"})

# Policy defaults
_DEFAULT_MAX_TOOLS = 50


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _worst_status(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        result[sev] = result.get(sev, 0) + 1
    return result


def _finding(ftype: str, severity: str, description: str,
             refs: list[str] | None = None, **kwargs: Any) -> dict[str, Any]:
    f: dict[str, Any] = {
        "type": ftype,
        "severity": severity,
        "description": description,
        "refs": refs or [],
        "evidence_origin": "LOCALLY_OBSERVED",
    }
    f.update(kwargs)
    return f


def _effective_caps(
    agent_record: dict[str, Any],
    tool_capabilities: dict[str, list[str]] | None,
) -> set[str]:
    """Union of agent's own capability_flags + all tool-level capabilities."""
    caps: set[str] = set(agent_record.get("capability_flags") or [])
    if tool_capabilities:
        for tool_caps in tool_capabilities.values():
            caps.update(str(c).lower() for c in (tool_caps or []))
    return caps


# ── Detectors ─────────────────────────────────────────────────────────────────

def _h1_exfiltration_path(
    agent_record: dict[str, Any],
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "exfiltration_path"
    if key in dedup:
        return None
    has_read = bool(effective & _READ_CAPS)
    has_egress = _CAP_NETWORK_EGRESS in effective
    if not (has_read and has_egress):
        return None
    dedup.add(key)
    constraints = agent_record.get("operational_constraints") or {}
    gated = bool(constraints.get("requires_approval_for_egress"))
    severity = "MEDIUM" if gated else "HIGH"
    read_caps_present = sorted(effective & _READ_CAPS)
    return _finding(
        key, severity,
        f"Agent can read data ({read_caps_present}) and send it externally "
        f"(network_egress). Approval gate: {'present' if gated else 'ABSENT'}.",
        refs=["OWASP-LLM02", "AML.T0024"],
        read_capabilities=read_caps_present,
        egress_gated=gated,
    )


def _h2_code_execution(
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "code_execution_risk"
    if key in dedup or _CAP_CODE_EXECUTION not in effective:
        return None
    dedup.add(key)
    return _finding(
        key, "HIGH",
        "Agent has code_execution capability — arbitrary code can be run in the "
        "agent's execution context, enabling privilege escalation and persistence.",
        refs=["AML.T0043", "OWASP-LLM06"],
    )


def _h3_subagent_spawn(
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "subagent_spawn_risk"
    if key in dedup or _CAP_SUBAGENT_SPAWN not in effective:
        return None
    dedup.add(key)
    return _finding(
        key, "MEDIUM",
        "Agent can spawn sub-agents, enabling lateral-movement and recursive "
        "permission amplification if sub-agents inherit parent capabilities.",
        refs=["AML.T0051", "OWASP-LLM06"],
    )


def _h4_approval_bypass(
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "approval_bypass_risk"
    if key in dedup or _CAP_APPROVAL_BYPASS not in effective:
        return None
    dedup.add(key)
    return _finding(
        key, "CRITICAL",
        "Agent has approval_bypass capability — human oversight gates can be "
        "skipped, removing the primary safeguard against runaway actions.",
        refs=["OWASP-LLM06", "AML.T0054"],
    )


def _h5_write_without_gate(
    agent_record: dict[str, Any],
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "write_without_gate"
    if key in dedup:
        return None
    write_present = sorted(effective & _WRITE_CAPS)
    if not write_present:
        return None
    constraints = agent_record.get("operational_constraints") or {}
    gated = bool(constraints.get("requires_approval_for_writes"))
    if gated:
        return None
    dedup.add(key)
    return _finding(
        key, "MEDIUM",
        f"Agent has destructive write capabilities ({write_present}) without a "
        "``requires_approval_for_writes`` constraint — data loss risk if misbehaving.",
        refs=["OWASP-LLM06"],
        write_capabilities=write_present,
    )


def _h6_over_permissioned(
    agent_record: dict[str, Any],
    effective: set[str],
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "over_permissioned"
    if key in dedup:
        return None
    trust = str(agent_record.get("trust_level") or "").upper()
    if trust not in _LOW_TRUST:
        return None
    critical_present = sorted(effective & _CRITICAL_CAPS)
    if not critical_present:
        return None
    dedup.add(key)
    return _finding(
        key, "HIGH",
        f"Low-trust agent (trust_level={trust}) has CRITICAL capabilities "
        f"({critical_present}). High-privilege capabilities should be restricted "
        "to VERIFIED or INTERNAL agents.",
        refs=["OWASP-LLM06", "AML.T0051"],
        trust_level=trust,
        critical_capabilities=critical_present,
    )


def _h7_undeclared_tool_caps(
    agent_record: dict[str, Any],
    tool_capabilities: dict[str, list[str]] | None,
    dedup: set[str],
) -> dict[str, Any] | None:
    key = "undeclared_tool_caps"
    if key in dedup or not tool_capabilities:
        return None
    declared = set(agent_record.get("declared_tools") or [])
    undeclared = sorted(set(tool_capabilities.keys()) - declared)
    if not undeclared:
        return None
    dedup.add(key)
    return _finding(
        key, "MEDIUM",
        f"tool_capabilities includes {len(undeclared)} tool(s) not in the agent's "
        f"declared_tools list: {undeclared[:5]}{'…' if len(undeclared) > 5 else ''}. "
        "Permission analysis may be incomplete or an undeclared tool was added.",
        refs=["OWASP-LLM06"],
        undeclared_tools=undeclared,
    )


def _h8_excessive_tool_count(
    agent_record: dict[str, Any],
    dedup: set[str],
    max_tools: int = _DEFAULT_MAX_TOOLS,
) -> dict[str, Any] | None:
    key = "excessive_tool_count"
    if key in dedup:
        return None
    count = len(agent_record.get("declared_tools") or [])
    if count <= max_tools:
        return None
    dedup.add(key)
    return _finding(
        key, "LOW",
        f"Agent declares {count} tools (threshold: {max_tools}). Large tool sets "
        "increase attack surface and complicate permission audits.",
        refs=["OWASP-LLM06"],
        tool_count=count,
        threshold=max_tools,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def analyse_permissions(
    agent_record: dict[str, Any],
    *,
    tool_capabilities: dict[str, list[str]] | None = None,
    max_tools: int = _DEFAULT_MAX_TOOLS,
) -> dict[str, Any]:
    """Analyse the permission graph of a registered agent.

    Parameters
    ----------
    agent_record:
        Agent registry record (from :func:`aiaf.registry.agent_registry.get_agent`
        or :func:`register_agent`).
    tool_capabilities:
        Optional dict of ``{tool_name: [capability_flag, …]}``.  When supplied,
        these are unioned with the agent's own ``capability_flags`` before analysis
        so that tool-level capabilities discovered via manifests are included.
    max_tools:
        Tool-count threshold for the ``excessive_tool_count`` heuristic.

    Returns
    -------
    Dict with keys: ``graph_version``, ``agent_id``, ``status``, ``finding_count``,
    ``findings``, ``by_severity``, ``capability_summary``, ``risk_paths``,
    ``evidence_origin``, ``analysed_at``.
    """
    findings: list[dict[str, Any]] = []
    dedup: set[str] = set()
    status = STATUS_CLEAN

    effective = _effective_caps(agent_record, tool_capabilities)

    for detector in [
        lambda: _h1_exfiltration_path(agent_record, effective, dedup),
        lambda: _h2_code_execution(effective, dedup),
        lambda: _h3_subagent_spawn(effective, dedup),
        lambda: _h4_approval_bypass(effective, dedup),
        lambda: _h5_write_without_gate(agent_record, effective, dedup),
        lambda: _h6_over_permissioned(agent_record, effective, dedup),
        lambda: _h7_undeclared_tool_caps(agent_record, tool_capabilities, dedup),
        lambda: _h8_excessive_tool_count(agent_record, dedup, max_tools),
    ]:
        f = detector()
        if f:
            findings.append(f)

    # Derive status from worst finding severity
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev == "CRITICAL":
            status = _worst_status(status, STATUS_CRITICAL_RISK)
        elif sev == "HIGH":
            status = _worst_status(status, STATUS_RISK_DETECTED)
        elif sev == "MEDIUM":
            status = _worst_status(status, STATUS_SUSPICIOUS)

    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.get("severity", "LOW"), 0))

    risk_paths = [f["type"] for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

    return {
        "graph_version": GRAPH_VERSION,
        "agent_id": agent_record.get("agent_id"),
        "status": status,
        "finding_count": len(findings),
        "findings": findings,
        "by_severity": _by_severity(findings),
        "capability_summary": {
            "declared_capability_count": len(agent_record.get("capability_flags") or []),
            "effective_capability_count": len(effective),
            "effective_capabilities": sorted(effective),
            "high_risk_capabilities": sorted(effective & (_CRITICAL_CAPS | {_CAP_NETWORK_EGRESS})),
        },
        "risk_paths": risk_paths,
        "evidence_origin": "LOCALLY_OBSERVED",
        "analysed_at": _utc_now(),
    }

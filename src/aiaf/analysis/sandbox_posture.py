"""Code-Execution Sandbox Posture Assessment.

Research implementation — AIAF does not build or run a sandbox; it assesses the
*declared posture* of an existing sandbox against known escape vectors and
security requirements for AI agent code-execution environments.

Background (ASI05 — Unexpected Code Execution, OWASP 2026)
------------------------------------------------------------
AI agents increasingly execute generated code (Python, JavaScript, shell scripts)
via tool calls. The security of the execution environment is orthogonal to the
model's guardrails: a model can refuse to write malicious code, but a poorly
isolated sandbox allows legitimate code to escape containment. AIAF scores the
declared sandbox configuration so security teams can assess gaps without
instrumenting the sandbox itself.

This covers the research spike: "Worth a research spike on integrating sandbox
posture checks rather than building a sandbox." The module exposes structured
posture assessment and escape-risk scoring that integrates with tool_invocation_risk.

Isolation levels (ascending security)
--------------------------------------
NONE        — no isolation; direct host execution
PROCESS     — subprocess with restricted syscalls (seccomp)
CONTAINER   — OCI container (Docker, Podman); namespace isolation
GVISOR      — gVisor / kernel interceptor (container + syscall interception)
VM          — full virtual machine (QEMU, Firecracker)
HARDWARE    — hardware-enforced isolation (Intel TDX, AMD SEV, secure enclave)

Egress controls
---------------
NONE        — unrestricted outbound network
MONITORED   — traffic logged but not filtered
FILTERED    — allowlist-based egress (known endpoints only)
BLOCKED     — no outbound network access

Privilege levels
----------------
ROOT        — running as root/Administrator
USER        — running as non-privileged user
RESTRICTED  — running as restricted user with dropped capabilities
SANDBOXED   — running with minimal capability set (e.g. CAP_NET_ADMIN dropped)

Known escape vectors by isolation level
----------------------------------------
NONE:        All host-execution attacks
PROCESS:     Seccomp bypass (CVE-2024-1086 class), ptrace escapes
CONTAINER:   Container breakouts (CVE-2024-21626 runc, CVE-2019-5736),
             privileged container flag, host PID/network namespace sharing
GVISOR:      gVisor escape (CVE-2021-22555 class), platform-specific bugs
VM:          VM escape (CVE-2023-20867 VMware VMCI class), VFIO device escapes
HARDWARE:    Side-channel (Spectre/Meltdown class); generally highest assurance

Evidence origin
---------------
LOCALLY_OBSERVED — posture data is provided by the operator; findings are
computed by AIAF locally based on the declared configuration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SANDBOX_POSTURE_VERSION = "1.0"

# ── Isolation levels ───────────────────────────────────────────────────────────
ISOLATION_NONE = "NONE"
ISOLATION_PROCESS = "PROCESS"
ISOLATION_CONTAINER = "CONTAINER"
ISOLATION_GVISOR = "GVISOR"
ISOLATION_VM = "VM"
ISOLATION_HARDWARE = "HARDWARE"

ISOLATION_LEVELS: frozenset = frozenset({
    ISOLATION_NONE, ISOLATION_PROCESS, ISOLATION_CONTAINER,
    ISOLATION_GVISOR, ISOLATION_VM, ISOLATION_HARDWARE,
})

_ISOLATION_RANK: Dict[str, int] = {
    ISOLATION_NONE: 0,
    ISOLATION_PROCESS: 1,
    ISOLATION_CONTAINER: 2,
    ISOLATION_GVISOR: 3,
    ISOLATION_VM: 4,
    ISOLATION_HARDWARE: 5,
}

# ── Egress controls ────────────────────────────────────────────────────────────
EGRESS_NONE = "NONE"
EGRESS_MONITORED = "MONITORED"
EGRESS_FILTERED = "FILTERED"
EGRESS_BLOCKED = "BLOCKED"

EGRESS_CONTROLS: frozenset = frozenset(
    {EGRESS_NONE, EGRESS_MONITORED, EGRESS_FILTERED, EGRESS_BLOCKED}
)

_EGRESS_RANK: Dict[str, int] = {
    EGRESS_NONE: 0, EGRESS_MONITORED: 1, EGRESS_FILTERED: 2, EGRESS_BLOCKED: 3,
}

# ── Privilege levels ───────────────────────────────────────────────────────────
PRIVILEGE_ROOT = "ROOT"
PRIVILEGE_USER = "USER"
PRIVILEGE_RESTRICTED = "RESTRICTED"
PRIVILEGE_SANDBOXED = "SANDBOXED"

PRIVILEGE_LEVELS: frozenset = frozenset(
    {PRIVILEGE_ROOT, PRIVILEGE_USER, PRIVILEGE_RESTRICTED, PRIVILEGE_SANDBOXED}
)

_PRIVILEGE_RANK: Dict[str, int] = {
    PRIVILEGE_ROOT: 0, PRIVILEGE_USER: 1,
    PRIVILEGE_RESTRICTED: 2, PRIVILEGE_SANDBOXED: 3,
}

# ── Posture risk levels ────────────────────────────────────────────────────────
POSTURE_CRITICAL = "CRITICAL"
POSTURE_HIGH = "HIGH"
POSTURE_MEDIUM = "MEDIUM"
POSTURE_LOW = "LOW"
POSTURE_ACCEPTABLE = "ACCEPTABLE"

# ── Known CVEs / escape vectors per isolation level ───────────────────────────
_ESCAPE_VECTORS: Dict[str, List[Dict[str, str]]] = {
    ISOLATION_NONE: [
        {"cve": "N/A", "desc": "Direct host access — all local privilege escalation vectors apply.",
         "severity": "CRITICAL"},
    ],
    ISOLATION_PROCESS: [
        {"cve": "CVE-2024-1086", "desc": "Linux kernel use-after-free via nf_tables — seccomp escape.",
         "severity": "HIGH"},
        {"cve": "CVE-2023-0386", "desc": "Linux OverlayFS FUSE privilege escalation.",
         "severity": "HIGH"},
        {"cve": "N/A", "desc": "ptrace-based escapes if ptrace not blocked via seccomp.",
         "severity": "MEDIUM"},
    ],
    ISOLATION_CONTAINER: [
        {"cve": "CVE-2024-21626", "desc": "runc container breakout via file descriptor leak.",
         "severity": "CRITICAL"},
        {"cve": "CVE-2019-5736", "desc": "runc overwrite via /proc/self/exe — classic breakout.",
         "severity": "HIGH"},
        {"cve": "N/A", "desc": "Privileged container flag grants full host capabilities.",
         "severity": "CRITICAL"},
        {"cve": "N/A", "desc": "Host PID/network namespace sharing defeats isolation.",
         "severity": "HIGH"},
        {"cve": "N/A", "desc": "Docker socket mount allows container management from within.",
         "severity": "CRITICAL"},
    ],
    ISOLATION_GVISOR: [
        {"cve": "CVE-2021-22555", "desc": "Linux kernel netfilter heap OOB (gVisor kernel passthrough paths).",
         "severity": "MEDIUM"},
        {"cve": "N/A", "desc": "Platform-specific gVisor bugs (ptrace/KVM platform).",
         "severity": "LOW"},
    ],
    ISOLATION_VM: [
        {"cve": "CVE-2023-20867", "desc": "VMware VMCI guest-to-host escape.",
         "severity": "MEDIUM"},
        {"cve": "CVE-2024-22252", "desc": "VMware XHCI/UHCI USB emulation use-after-free.",
         "severity": "MEDIUM"},
        {"cve": "N/A", "desc": "VFIO device passthrough may expose host DMA.",
         "severity": "MEDIUM"},
    ],
    ISOLATION_HARDWARE: [
        {"cve": "CVE-2023-20569", "desc": "Spectre-v2 (Inception) — AMD cross-process information leak.",
         "severity": "LOW"},
        {"cve": "N/A", "desc": "Hardware TEE implementation bugs (platform-specific).",
         "severity": "LOW"},
    ],
}

# ── Minimum recommended posture for AI agent code execution ───────────────────
_MIN_RECOMMENDED = {
    "isolation": ISOLATION_CONTAINER,
    "egress": EGRESS_FILTERED,
    "privilege": PRIVILEGE_RESTRICTED,
    "timeout_sec": 30,
    "memory_mb": 512,
}


class SandboxPostureError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_config(config: Dict[str, Any]) -> None:
    iso = str(config.get("isolation", "")).upper()
    if iso and iso not in ISOLATION_LEVELS:
        raise SandboxPostureError(
            f"Unknown isolation {iso!r}. Valid: {sorted(ISOLATION_LEVELS)}"
        )
    egress = str(config.get("egress", "")).upper()
    if egress and egress not in EGRESS_CONTROLS:
        raise SandboxPostureError(
            f"Unknown egress {egress!r}. Valid: {sorted(EGRESS_CONTROLS)}"
        )
    priv = str(config.get("privilege", "")).upper()
    if priv and priv not in PRIVILEGE_LEVELS:
        raise SandboxPostureError(
            f"Unknown privilege {priv!r}. Valid: {sorted(PRIVILEGE_LEVELS)}"
        )


# ── Public API ─────────────────────────────────────────────────────────────────

def assess_sandbox_posture(
    sandbox_config: Dict[str, Any],
    *,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """Assess the security posture of a declared sandbox configuration.

    Parameters
    ----------
    sandbox_config:  Dict describing the sandbox. Expected keys:
        isolation       str   — ISOLATION_* constant
        egress          str   — EGRESS_* constant
        privilege       str   — PRIVILEGE_* constant
        timeout_sec     int   — maximum execution time (0 = no limit)
        memory_mb       int   — memory cap in MiB (0 = no limit)
        cpu_pct         int   — CPU cap as % (0 = no limit)
        allow_host_net  bool  — True if sandbox shares host network namespace
        allow_host_pid  bool  — True if sandbox shares host PID namespace
        privileged      bool  — True if running with --privileged (Docker)
        docker_socket   bool  — True if Docker socket mounted inside sandbox
        seccomp_profile str   — seccomp profile name ("default", "strict", "none")
        apparmor        bool  — AppArmor/SELinux profile active

    context: Optional human-readable description of what code will run in this sandbox.

    Returns
    -------
    Dict with keys:
        isolation, egress, privilege, posture_risk,
        escape_vectors, findings, recommendations,
        meets_minimum_recommended, evidence_origin, assessed_at
    """
    _validate_config(sandbox_config)

    iso = str(sandbox_config.get("isolation", ISOLATION_NONE)).upper()
    egress = str(sandbox_config.get("egress", EGRESS_NONE)).upper()
    privilege = str(sandbox_config.get("privilege", PRIVILEGE_ROOT)).upper()
    timeout_sec = int(sandbox_config.get("timeout_sec", 0))
    memory_mb = int(sandbox_config.get("memory_mb", 0))
    allow_host_net = bool(sandbox_config.get("allow_host_net", False))
    allow_host_pid = bool(sandbox_config.get("allow_host_pid", False))
    privileged_flag = bool(sandbox_config.get("privileged", False))
    docker_socket = bool(sandbox_config.get("docker_socket", False))
    seccomp = str(sandbox_config.get("seccomp_profile", "none")).lower()
    apparmor = bool(sandbox_config.get("apparmor", False))

    findings: List[Dict[str, Any]] = []

    # ── Isolation check ────────────────────────────────────────────────────────
    iso_rank = _ISOLATION_RANK.get(iso, 0)
    min_iso_rank = _ISOLATION_RANK[_MIN_RECOMMENDED["isolation"]]
    if iso_rank < min_iso_rank:
        findings.append({
            "severity": "CRITICAL" if iso_rank == 0 else "HIGH",
            "category": "INSUFFICIENT_ISOLATION",
            "detail": (
                f"Isolation level {iso!r} is below the recommended minimum "
                f"{_MIN_RECOMMENDED['isolation']!r} for AI agent code execution."
            ),
        })

    # ── Egress check ───────────────────────────────────────────────────────────
    egress_rank = _EGRESS_RANK.get(egress, 0)
    min_egress_rank = _EGRESS_RANK[_MIN_RECOMMENDED["egress"]]
    if egress_rank < min_egress_rank:
        findings.append({
            "severity": "HIGH",
            "category": "INSUFFICIENT_EGRESS_CONTROL",
            "detail": (
                f"Egress control {egress!r} is below recommended minimum "
                f"{_MIN_RECOMMENDED['egress']!r}. Unrestricted egress enables data exfiltration."
            ),
        })

    # ── Privilege check ────────────────────────────────────────────────────────
    priv_rank = _PRIVILEGE_RANK.get(privilege, 0)
    min_priv_rank = _PRIVILEGE_RANK[_MIN_RECOMMENDED["privilege"]]
    if priv_rank < min_priv_rank:
        findings.append({
            "severity": "CRITICAL" if privilege == PRIVILEGE_ROOT else "HIGH",
            "category": "EXCESSIVE_PRIVILEGE",
            "detail": (
                f"Privilege level {privilege!r} exceeds recommended maximum "
                f"{_MIN_RECOMMENDED['privilege']!r}."
            ),
        })

    # ── Resource cap checks ────────────────────────────────────────────────────
    if timeout_sec == 0:
        findings.append({
            "severity": "MEDIUM",
            "category": "NO_TIMEOUT",
            "detail": "No execution timeout configured — susceptible to runaway/infinite-loop DoS.",
        })
    if memory_mb == 0:
        findings.append({
            "severity": "MEDIUM",
            "category": "NO_MEMORY_CAP",
            "detail": "No memory cap — susceptible to memory exhaustion (fork-bomb, OOM).",
        })

    # ── Namespace sharing ──────────────────────────────────────────────────────
    if allow_host_net:
        findings.append({
            "severity": "HIGH",
            "category": "HOST_NETWORK_SHARED",
            "detail": "Sandbox shares host network namespace — bypasses container network isolation.",
        })
    if allow_host_pid:
        findings.append({
            "severity": "CRITICAL",
            "category": "HOST_PID_SHARED",
            "detail": "Sandbox shares host PID namespace — can ptrace and kill host processes.",
        })

    # ── Container-specific misconfigurations ───────────────────────────────────
    if iso == ISOLATION_CONTAINER:
        if privileged_flag:
            findings.append({
                "severity": "CRITICAL",
                "category": "PRIVILEGED_CONTAINER",
                "detail": "--privileged flag grants full host capabilities; effectively no isolation.",
            })
        if docker_socket:
            findings.append({
                "severity": "CRITICAL",
                "category": "DOCKER_SOCKET_MOUNTED",
                "detail": "Docker socket mounted inside container — trivial host escape via docker run.",
            })
        if seccomp == "none":
            findings.append({
                "severity": "HIGH",
                "category": "NO_SECCOMP_PROFILE",
                "detail": "No seccomp profile — full syscall surface exposed.",
            })
        if not apparmor:
            findings.append({
                "severity": "MEDIUM",
                "category": "NO_MAC_PROFILE",
                "detail": "No AppArmor/SELinux MAC profile — mandatory access controls absent.",
            })

    # ── Escape vectors for this isolation level ────────────────────────────────
    escape_vectors = _ESCAPE_VECTORS.get(iso, [])

    # ── Overall posture risk ───────────────────────────────────────────────────
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        posture_risk = POSTURE_CRITICAL
    elif "HIGH" in severities:
        posture_risk = POSTURE_HIGH
    elif "MEDIUM" in severities:
        posture_risk = POSTURE_MEDIUM
    elif "LOW" in severities:
        posture_risk = POSTURE_LOW
    else:
        posture_risk = POSTURE_ACCEPTABLE

    # ── Meets minimum recommended ──────────────────────────────────────────────
    meets_minimum = (
        iso_rank >= min_iso_rank
        and egress_rank >= min_egress_rank
        and priv_rank >= min_priv_rank
        and timeout_sec > 0
        and memory_mb > 0
        and not allow_host_pid
        and not privileged_flag
        and not docker_socket
    )

    # ── Recommendations ────────────────────────────────────────────────────────
    recommendations: List[str] = []
    if iso_rank < min_iso_rank:
        recommendations.append(
            f"Upgrade isolation to at least {_MIN_RECOMMENDED['isolation']!r} "
            "(OCI container with gVisor preferred for AI code execution)."
        )
    if egress_rank < min_egress_rank:
        recommendations.append(
            "Apply FILTERED or BLOCKED egress to prevent data exfiltration by generated code."
        )
    if privilege == PRIVILEGE_ROOT:
        recommendations.append(
            "Run sandbox process as a non-root, restricted user with dropped Linux capabilities."
        )
    if timeout_sec == 0:
        recommendations.append("Set an execution timeout (≤30s recommended for agent tool calls).")
    if memory_mb == 0:
        recommendations.append("Set a memory cap (≤512 MiB recommended).")
    if privileged_flag:
        recommendations.append("Remove --privileged flag; use specific capability grants instead.")
    if docker_socket:
        recommendations.append("Never mount the Docker socket inside agent execution sandboxes.")
    if iso == ISOLATION_CONTAINER and seccomp == "none":
        recommendations.append(
            "Apply a restrictive seccomp profile (Docker default or stricter)."
        )

    return {
        "isolation": iso,
        "egress": egress,
        "privilege": privilege,
        "timeout_sec": timeout_sec,
        "memory_mb": memory_mb,
        "posture_risk": posture_risk,
        "finding_count": len(findings),
        "critical_count": severities.count("CRITICAL"),
        "high_count": severities.count("HIGH"),
        "findings": findings,
        "escape_vectors": escape_vectors,
        "recommendations": recommendations,
        "meets_minimum_recommended": meets_minimum,
        "context": context,
        "sandbox_posture_version": SANDBOX_POSTURE_VERSION,
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }


def get_isolation_levels() -> Dict[str, Any]:
    """Return available isolation levels with rank and known escape vectors."""
    return {
        level: {
            "rank": _ISOLATION_RANK[level],
            "escape_vectors": _ESCAPE_VECTORS.get(level, []),
        }
        for level in sorted(ISOLATION_LEVELS, key=lambda x: _ISOLATION_RANK[x])
    }

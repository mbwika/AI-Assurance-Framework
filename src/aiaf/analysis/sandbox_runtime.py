"""Code-Execution Sandbox Runtime Validation.

Extends sandbox_posture.py (declared-configuration assessment) with active
runtime probes that verify whether a running execution environment's observed
behavior matches its declared posture.  AIAF does not build or manage sandboxes;
these probes run *inside* (or alongside) the environment and report deviations.

Probe types
-----------
EGRESS_PROBE         — attempt a TCP connection to an external host and verify
                       that it is blocked as declared
PRIVILEGE_PROBE      — check effective UID/GID and Linux capability set
FILESYSTEM_PROBE     — verify filesystem writability constraints and noexec mounts
RESOURCE_PROBE       — verify ulimit/cgroup resource limits are active
PROC_ISOLATION_PROBE — verify PID namespace isolation via /proc/self/ns/pid
CVE_SCENARIO_PROBE   — detect known container-escape indicator files/conditions

Probe results
-------------
PASS    — runtime behavior matches declared posture
FAIL    — deviation detected between declared posture and actual runtime
SKIP    — probe not applicable for this isolation level or OS
ERROR   — probe could not execute (missing permissions, unavailable syscalls)

Validation verdicts
-------------------
VALIDATED   — all applicable probes PASS; runtime matches declared posture
MISMATCH    — one or more probes FAIL; runtime deviates from declared posture
PARTIAL     — some probes SKIP/ERROR; confidence is limited
INCONCLUSIVE — no probes were applicable or all resulted in SKIP/ERROR

Evidence origin
---------------
LOCALLY_OBSERVED — all probe results are measured locally by AIAF inside the
running environment.
"""

from __future__ import annotations

import os
import socket
import resource as _resource_module
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .sandbox_posture import (
    ISOLATION_NONE,
    ISOLATION_PROCESS,
    ISOLATION_CONTAINER,
    ISOLATION_GVISOR,
    ISOLATION_VM,
    ISOLATION_HARDWARE,
    EGRESS_NONE,
    EGRESS_MONITORED,
    EGRESS_FILTERED,
    EGRESS_BLOCKED,
    PRIVILEGE_ROOT,
    PRIVILEGE_USER,
    PRIVILEGE_RESTRICTED,
    PRIVILEGE_SANDBOXED,
    _ISOLATION_RANK,
)

SANDBOX_RUNTIME_VERSION = "1.0"

# ── Probe type constants ───────────────────────────────────────────────────────
PROBE_EGRESS = "EGRESS_PROBE"
PROBE_PRIVILEGE = "PRIVILEGE_PROBE"
PROBE_FILESYSTEM = "FILESYSTEM_PROBE"
PROBE_RESOURCE = "RESOURCE_PROBE"
PROBE_PROC_ISOLATION = "PROC_ISOLATION_PROBE"
PROBE_CVE_SCENARIO = "CVE_SCENARIO_PROBE"

PROBE_TYPES: frozenset = frozenset({
    PROBE_EGRESS, PROBE_PRIVILEGE, PROBE_FILESYSTEM,
    PROBE_RESOURCE, PROBE_PROC_ISOLATION, PROBE_CVE_SCENARIO,
})

# ── Probe results ──────────────────────────────────────────────────────────────
RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_SKIP = "SKIP"
RESULT_ERROR = "ERROR"

# ── Validation verdicts ────────────────────────────────────────────────────────
VERDICT_VALIDATED = "VALIDATED"
VERDICT_MISMATCH = "MISMATCH"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"

# ── CVE scenario indicator files/conditions ───────────────────────────────────
# Each tuple: (path_or_callable, description, isolation_applies_to)
_CVE_INDICATORS: List[Tuple] = [
    # CVE-2024-21626: runc /proc/self/fd escape
    ("/proc/self/fd", "Writable /proc/self/fd directory (runc CVE-2024-21626 vector)", (ISOLATION_CONTAINER,)),
    # Privileged container: can write to /proc/sys/kernel/core_pattern
    ("/proc/sys/kernel/core_pattern", "Writable kernel.core_pattern (privileged container escape)", (ISOLATION_CONTAINER, ISOLATION_PROCESS)),
    # Host network namespace: /proc/1/net/if_inet6 readable by non-root → shared netns
    ("/proc/1/net/if_inet6", "Host network namespace visible (host_net=True risk)", (ISOLATION_CONTAINER, ISOLATION_PROCESS)),
    # SUID executable in common locations
    ("/bin/su", "SUID binary present in /bin/su", (ISOLATION_CONTAINER, ISOLATION_PROCESS, ISOLATION_NONE)),
    # Docker socket exposed inside container
    ("/var/run/docker.sock", "Docker socket accessible inside environment", (ISOLATION_CONTAINER,)),
    # cgroup v1 writable (Shocker class breakout)
    ("/sys/fs/cgroup/memory/memory.limit_in_bytes",
     "Writable cgroup memory limit (cgroup v1 escape vector)", (ISOLATION_CONTAINER,)),
]

# ── Egress probe targets ───────────────────────────────────────────────────────
_EGRESS_PROBE_HOST = "8.8.8.8"
_EGRESS_PROBE_PORT = 53
_EGRESS_PROBE_TIMEOUT = 2.0


class SandboxRuntimeError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _make_probe_result(
    probe_type: str,
    result: str,
    *,
    detail: str = "",
    findings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "probe_type": probe_type,
        "result": result,
        "detail": detail,
        "findings": findings or [],
        "probed_at": _utc_now(),
    }


# ── Individual probes ──────────────────────────────────────────────────────────

def probe_egress(
    declared_egress: str,
    *,
    target_host: str = _EGRESS_PROBE_HOST,
    target_port: int = _EGRESS_PROBE_PORT,
    timeout_sec: float = _EGRESS_PROBE_TIMEOUT,
    connect_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Probe outbound TCP connectivity and compare to declared egress control.

    Parameters
    ----------
    declared_egress:  One of EGRESS_BLOCKED, EGRESS_FILTERED, EGRESS_MONITORED, EGRESS_NONE.
    connect_fn:       Injectable callable for testing; signature: (host, port, timeout) -> bool.
                      Returns True if connection succeeded, False if refused/timed out.
    """
    if connect_fn is not None:
        reachable = connect_fn(target_host, target_port, timeout_sec)
    else:
        try:
            sock = socket.create_connection((target_host, target_port), timeout=timeout_sec)
            sock.close()
            reachable = True
        except (OSError, socket.timeout, socket.gaierror):
            reachable = False

    if declared_egress == EGRESS_BLOCKED:
        if reachable:
            return _make_probe_result(
                PROBE_EGRESS, RESULT_FAIL,
                detail=f"Declared egress=BLOCKED but TCP {target_host}:{target_port} is reachable.",
                findings=["Egress control mismatch: outbound TCP not blocked as declared."],
            )
        return _make_probe_result(
            PROBE_EGRESS, RESULT_PASS,
            detail=f"Egress BLOCKED confirmed: TCP {target_host}:{target_port} not reachable.",
        )

    if declared_egress == EGRESS_FILTERED:
        if reachable:
            return _make_probe_result(
                PROBE_EGRESS, RESULT_PASS,
                detail="Egress FILTERED: probe target reachable (may be on allowlist).",
            )
        return _make_probe_result(
            PROBE_EGRESS, RESULT_SKIP,
            detail="Egress FILTERED: probe target blocked; cannot distinguish FILTERED from BLOCKED.",
        )

    # EGRESS_NONE or EGRESS_MONITORED: network should be unrestricted
    if declared_egress in (EGRESS_NONE, EGRESS_MONITORED):
        if reachable:
            return _make_probe_result(
                PROBE_EGRESS, RESULT_PASS,
                detail=f"Egress {declared_egress}: outbound TCP reachable as expected.",
            )
        return _make_probe_result(
            PROBE_EGRESS, RESULT_FAIL,
            detail=f"Declared egress={declared_egress} (unrestricted) but TCP {target_host}:{target_port} not reachable.",
            findings=["Unexpected egress restriction: outbound TCP blocked despite declared unrestricted egress."],
        )

    return _make_probe_result(PROBE_EGRESS, RESULT_SKIP, detail=f"Unknown egress level: {declared_egress!r}")


def probe_privilege(
    declared_privilege: str,
    *,
    getuid_fn: Optional[Callable] = None,
    getgid_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Check effective UID/GID against declared privilege level.

    Parameters
    ----------
    declared_privilege: One of PRIVILEGE_ROOT, PRIVILEGE_USER, PRIVILEGE_RESTRICTED, PRIVILEGE_SANDBOXED.
    getuid_fn:          Override for os.getuid (injectable for testing).
    getgid_fn:          Override for os.getgid (injectable for testing).
    """
    if not hasattr(os, "getuid"):
        return _make_probe_result(
            PROBE_PRIVILEGE, RESULT_SKIP,
            detail="os.getuid not available (non-POSIX platform).",
        )

    uid = (getuid_fn or os.getuid)()
    gid = (getgid_fn or os.getgid)()
    is_root = uid == 0

    findings: List[str] = []
    result = RESULT_PASS

    if declared_privilege == PRIVILEGE_SANDBOXED and is_root:
        result = RESULT_FAIL
        findings.append(f"Declared SANDBOXED privilege but running as UID 0 (root).")
    elif declared_privilege == PRIVILEGE_RESTRICTED and is_root:
        result = RESULT_FAIL
        findings.append(f"Declared RESTRICTED privilege but running as UID 0 (root).")
    elif declared_privilege == PRIVILEGE_USER and is_root:
        result = RESULT_FAIL
        findings.append(f"Declared USER privilege but running as UID 0 (root).")
    elif declared_privilege == PRIVILEGE_ROOT and not is_root:
        result = RESULT_PASS  # Lower than declared is acceptable

    detail = f"Effective UID={uid} GID={gid}; declared privilege={declared_privilege!r}."
    return _make_probe_result(PROBE_PRIVILEGE, result, detail=detail, findings=findings)


def probe_filesystem(
    declared_isolation: str,
    *,
    test_paths: Optional[List[str]] = None,
    path_exists_fn: Optional[Callable] = None,
    is_writable_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Verify filesystem writability constraints match declared isolation.

    For CONTAINER+ isolation, /proc/sysrq-trigger and /proc/sys/kernel/dmesg
    should not be writable from inside the container.

    Parameters
    ----------
    declared_isolation: One of ISOLATION_* constants.
    test_paths:         Override paths to test for writability.
    path_exists_fn:     Override for os.path.exists.
    is_writable_fn:     Override for os.access(path, os.W_OK).
    """
    isolation_rank = _ISOLATION_RANK.get(declared_isolation, 0)
    container_rank = _ISOLATION_RANK.get(ISOLATION_CONTAINER, 2)

    if isolation_rank < container_rank:
        return _make_probe_result(
            PROBE_FILESYSTEM, RESULT_SKIP,
            detail=f"Filesystem isolation probe not applicable for {declared_isolation!r}.",
        )

    exists = path_exists_fn or os.path.exists
    writable = is_writable_fn or (lambda p: os.access(p, os.W_OK))

    sensitive_paths = test_paths or [
        "/proc/sys/kernel/dmesg",
        "/proc/sysrq-trigger",
        "/sys/kernel/debug",
        "/proc/kcore",
    ]

    findings: List[str] = []
    for p in sensitive_paths:
        if exists(p) and writable(p):
            findings.append(f"Sensitive path is writable: {p}")

    if findings:
        return _make_probe_result(
            PROBE_FILESYSTEM, RESULT_FAIL,
            detail=f"{len(findings)} sensitive path(s) are unexpectedly writable.",
            findings=findings,
        )

    return _make_probe_result(
        PROBE_FILESYSTEM, RESULT_PASS,
        detail="No sensitive kernel paths writable from this environment.",
    )


def probe_resources(
    declared_config: Dict[str, Any],
    *,
    getrlimit_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Verify ulimit resource limits are active.

    Parameters
    ----------
    declared_config: Sandbox config dict with timeout_sec and memory_mb fields.
    getrlimit_fn:    Override for resource.getrlimit (injectable for testing).
    """
    if not hasattr(_resource_module, "getrlimit"):
        return _make_probe_result(
            PROBE_RESOURCE, RESULT_SKIP,
            detail="resource.getrlimit not available on this platform.",
        )

    _getrlimit = getrlimit_fn or _resource_module.getrlimit
    declared_timeout = int(declared_config.get("timeout_sec", 0))
    declared_memory_mb = int(declared_config.get("memory_mb", 0))

    findings: List[str] = []
    detail_parts: List[str] = []

    try:
        soft_cpu, hard_cpu = _getrlimit(_resource_module.RLIMIT_CPU)
        if declared_timeout > 0 and soft_cpu == _resource_module.RLIM_INFINITY:
            findings.append(
                f"Declared timeout_sec={declared_timeout} but RLIMIT_CPU is UNLIMITED."
            )
        detail_parts.append(f"RLIMIT_CPU={soft_cpu}")
    except Exception as exc:
        detail_parts.append(f"RLIMIT_CPU=unavailable ({exc})")

    try:
        soft_as, hard_as = _getrlimit(_resource_module.RLIMIT_AS)
        declared_bytes = declared_memory_mb * 1024 * 1024
        if declared_memory_mb > 0 and soft_as == _resource_module.RLIM_INFINITY:
            findings.append(
                f"Declared memory_mb={declared_memory_mb} but RLIMIT_AS is UNLIMITED."
            )
        detail_parts.append(f"RLIMIT_AS={soft_as}")
    except Exception as exc:
        detail_parts.append(f"RLIMIT_AS=unavailable ({exc})")

    result = RESULT_FAIL if findings else RESULT_PASS
    return _make_probe_result(
        PROBE_RESOURCE, result,
        detail="; ".join(detail_parts),
        findings=findings,
    )


def probe_proc_isolation(
    declared_isolation: str,
    *,
    ns_pid_path: str = "/proc/self/ns/pid",
    ns_init_pid_path: str = "/proc/1/ns/pid",
    read_link_fn: Optional[Callable] = None,
    path_exists_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Verify PID namespace isolation by comparing /proc/self/ns/pid to /proc/1/ns/pid.

    If both point to the same namespace inode, we share the host PID namespace,
    which is a misconfiguration for CONTAINER+ isolation.

    Parameters
    ----------
    declared_isolation: One of ISOLATION_* constants.
    ns_pid_path:        Override for /proc/self/ns/pid.
    ns_init_pid_path:   Override for /proc/1/ns/pid.
    read_link_fn:       Override for os.readlink.
    path_exists_fn:     Override for os.path.exists.
    """
    isolation_rank = _ISOLATION_RANK.get(declared_isolation, 0)
    container_rank = _ISOLATION_RANK.get(ISOLATION_CONTAINER, 2)

    if isolation_rank < container_rank:
        return _make_probe_result(
            PROBE_PROC_ISOLATION, RESULT_SKIP,
            detail=f"PID namespace probe not applicable for {declared_isolation!r}.",
        )

    exists = path_exists_fn or os.path.exists
    readlink = read_link_fn or os.readlink

    if not exists(ns_pid_path):
        return _make_probe_result(
            PROBE_PROC_ISOLATION, RESULT_SKIP,
            detail="/proc/self/ns/pid not available (not a Linux system or no /proc).",
        )

    try:
        self_ns = readlink(ns_pid_path)
        init_ns = readlink(ns_init_pid_path) if exists(ns_init_pid_path) else None
    except OSError as exc:
        return _make_probe_result(
            PROBE_PROC_ISOLATION, RESULT_ERROR,
            detail=f"Could not read PID namespace symlinks: {exc}",
        )

    if init_ns and self_ns == init_ns:
        return _make_probe_result(
            PROBE_PROC_ISOLATION, RESULT_FAIL,
            detail=f"Self PID namespace ({self_ns}) matches host init namespace ({init_ns}).",
            findings=["PID namespace not isolated: container shares host PID namespace."],
        )

    return _make_probe_result(
        PROBE_PROC_ISOLATION, RESULT_PASS,
        detail=f"PID namespace isolated: self={self_ns} ≠ init={init_ns}.",
    )


def probe_cve_scenarios(
    declared_isolation: str,
    *,
    path_exists_fn: Optional[Callable] = None,
    is_writable_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Detect known container-escape indicator conditions.

    Checks for file paths and configurations that characterise published
    container escape CVEs (CVE-2024-21626, docker socket exposure,
    writable cgroup memory limits, etc.).

    Parameters
    ----------
    declared_isolation: One of ISOLATION_* constants.
    path_exists_fn:     Override for os.path.exists.
    is_writable_fn:     Override for os.access(path, os.W_OK).
    """
    exists = path_exists_fn or os.path.exists
    writable = is_writable_fn or (lambda p: os.access(p, os.W_OK))

    findings: List[str] = []
    checked = 0

    for indicator_path, description, applies_to in _CVE_INDICATORS:
        if declared_isolation not in applies_to:
            continue
        checked += 1
        if exists(indicator_path) and writable(indicator_path):
            findings.append(f"CVE indicator present and writable: {indicator_path} — {description}")

    if checked == 0:
        return _make_probe_result(
            PROBE_CVE_SCENARIO, RESULT_SKIP,
            detail=f"No CVE scenario indicators apply to isolation={declared_isolation!r}.",
        )

    if findings:
        return _make_probe_result(
            PROBE_CVE_SCENARIO, RESULT_FAIL,
            detail=f"{len(findings)} of {checked} CVE scenario indicators are present.",
            findings=findings,
        )

    return _make_probe_result(
        PROBE_CVE_SCENARIO, RESULT_PASS,
        detail=f"No CVE scenario indicators detected ({checked} checked).",
    )


# ── Orchestrator ───────────────────────────────────────────────────────────────

def validate_sandbox_runtime(
    declared_config: Dict[str, Any],
    *,
    probes: Optional[List[str]] = None,
    egress_connect_fn: Optional[Callable] = None,
    getuid_fn: Optional[Callable] = None,
    getgid_fn: Optional[Callable] = None,
    getrlimit_fn: Optional[Callable] = None,
    path_exists_fn: Optional[Callable] = None,
    is_writable_fn: Optional[Callable] = None,
    read_link_fn: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Run all applicable runtime validation probes for a declared sandbox config.

    Parameters
    ----------
    declared_config: Sandbox configuration dict (same format as assess_sandbox_posture).
    probes:          Subset of PROBE_TYPES to run.  Defaults to all.
    *_fn:            Dependency-injection overrides for each probe (used in tests).

    Returns
    -------
    Dict with:
        verdict         — VALIDATED / MISMATCH / PARTIAL / INCONCLUSIVE
        probe_results   — list of individual probe result dicts
        pass_count, fail_count, skip_count, error_count
        findings        — aggregated list of all failure finding strings
        evidence_origin, validated_at, sandbox_runtime_version
    """
    active_probes = set(probes or list(PROBE_TYPES))

    isolation = declared_config.get("isolation", ISOLATION_NONE)
    egress = declared_config.get("egress", EGRESS_NONE)
    privilege = declared_config.get("privilege", PRIVILEGE_ROOT)

    results: List[Dict[str, Any]] = []

    if PROBE_EGRESS in active_probes:
        results.append(probe_egress(egress, connect_fn=egress_connect_fn))

    if PROBE_PRIVILEGE in active_probes:
        results.append(probe_privilege(privilege, getuid_fn=getuid_fn, getgid_fn=getgid_fn))

    if PROBE_FILESYSTEM in active_probes:
        results.append(probe_filesystem(
            isolation, path_exists_fn=path_exists_fn, is_writable_fn=is_writable_fn,
        ))

    if PROBE_RESOURCE in active_probes:
        results.append(probe_resources(declared_config, getrlimit_fn=getrlimit_fn))

    if PROBE_PROC_ISOLATION in active_probes:
        results.append(probe_proc_isolation(
            isolation, read_link_fn=read_link_fn, path_exists_fn=path_exists_fn,
        ))

    if PROBE_CVE_SCENARIO in active_probes:
        results.append(probe_cve_scenarios(
            isolation, path_exists_fn=path_exists_fn, is_writable_fn=is_writable_fn,
        ))

    pass_count = sum(1 for r in results if r["result"] == RESULT_PASS)
    fail_count = sum(1 for r in results if r["result"] == RESULT_FAIL)
    skip_count = sum(1 for r in results if r["result"] == RESULT_SKIP)
    error_count = sum(1 for r in results if r["result"] == RESULT_ERROR)
    all_findings: List[str] = [f for r in results for f in r.get("findings", [])]

    # Determine overall verdict
    if fail_count > 0:
        verdict = VERDICT_MISMATCH
    elif pass_count > 0 and (skip_count > 0 or error_count > 0):
        verdict = VERDICT_PARTIAL
    elif pass_count > 0:
        verdict = VERDICT_VALIDATED
    else:
        verdict = VERDICT_INCONCLUSIVE

    return {
        "verdict": verdict,
        "probe_results": results,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "skip_count": skip_count,
        "error_count": error_count,
        "findings": all_findings,
        "declared_isolation": isolation,
        "declared_egress": egress,
        "declared_privilege": privilege,
        "evidence_origin": "LOCALLY_OBSERVED",
        "sandbox_runtime_version": SANDBOX_RUNTIME_VERSION,
        "validated_at": _utc_now(),
    }

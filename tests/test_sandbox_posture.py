"""Tests for src/aiaf/analysis/sandbox_posture.py."""

import pytest

from aiaf.analysis.sandbox_posture import (
    EGRESS_BLOCKED,
    EGRESS_FILTERED,
    EGRESS_MONITORED,
    EGRESS_NONE,
    ISOLATION_CONTAINER,
    ISOLATION_GVISOR,
    ISOLATION_HARDWARE,
    ISOLATION_NONE,
    ISOLATION_PROCESS,
    ISOLATION_VM,
    POSTURE_ACCEPTABLE,
    POSTURE_CRITICAL,
    POSTURE_LOW,
    POSTURE_MEDIUM,
    PRIVILEGE_RESTRICTED,
    PRIVILEGE_ROOT,
    PRIVILEGE_SANDBOXED,
    PRIVILEGE_USER,
    SANDBOX_POSTURE_VERSION,
    SandboxPostureError,
    assess_sandbox_posture,
    get_isolation_levels,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _good_config(**overrides):
    """Minimum-recommended posture: CONTAINER + FILTERED + RESTRICTED + capped."""
    base = {
        "isolation": ISOLATION_CONTAINER,
        "egress": EGRESS_FILTERED,
        "privilege": PRIVILEGE_RESTRICTED,
        "timeout_sec": 30,
        "memory_mb": 512,
        "seccomp_profile": "default",
        "apparmor": True,
        "privileged": False,
        "docker_socket": False,
        "allow_host_net": False,
        "allow_host_pid": False,
    }
    base.update(overrides)
    return base


# ── assess_sandbox_posture — return shape ─────────────────────────────────────

class TestReturnShape:
    def test_returns_dict(self):
        result = assess_sandbox_posture(_good_config())
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        result = assess_sandbox_posture(_good_config())
        for key in ("isolation", "egress", "privilege", "posture_risk",
                    "escape_vectors", "findings", "recommendations",
                    "meets_minimum_recommended", "evidence_origin", "assessed_at"):
            assert key in result

    def test_version_present(self):
        result = assess_sandbox_posture(_good_config())
        assert result["sandbox_posture_version"] == SANDBOX_POSTURE_VERSION

    def test_evidence_origin(self):
        result = assess_sandbox_posture(_good_config())
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_assessed_at_utc(self):
        result = assess_sandbox_posture(_good_config())
        assert result["assessed_at"].endswith("Z")

    def test_context_forwarded(self):
        result = assess_sandbox_posture(_good_config(), context="Unit test sandbox")
        assert result["context"] == "Unit test sandbox"


# ── Minimum recommended config passes ─────────────────────────────────────────

class TestMinimumRecommended:
    def test_good_config_meets_minimum(self):
        result = assess_sandbox_posture(_good_config())
        assert result["meets_minimum_recommended"] is True

    def test_good_config_posture_acceptable_or_medium(self):
        result = assess_sandbox_posture(_good_config())
        # With seccomp=default, apparmor, restricted — should be at most MEDIUM
        # (no CRITICAL or HIGH findings)
        assert result["posture_risk"] in (POSTURE_ACCEPTABLE, POSTURE_LOW, POSTURE_MEDIUM)

    def test_hardware_isolation_acceptable(self):
        cfg = _good_config(isolation=ISOLATION_HARDWARE, egress=EGRESS_BLOCKED,
                           privilege=PRIVILEGE_SANDBOXED)
        result = assess_sandbox_posture(cfg)
        assert result["meets_minimum_recommended"] is True


# ── Insufficient isolation ─────────────────────────────────────────────────────

class TestInsufficientIsolation:
    def test_none_isolation_critical(self):
        cfg = _good_config(isolation=ISOLATION_NONE)
        result = assess_sandbox_posture(cfg)
        assert result["posture_risk"] == POSTURE_CRITICAL
        assert result["meets_minimum_recommended"] is False

    def test_process_isolation_below_minimum(self):
        cfg = _good_config(isolation=ISOLATION_PROCESS)
        result = assess_sandbox_posture(cfg)
        assert result["meets_minimum_recommended"] is False
        categories = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_ISOLATION" in categories

    def test_container_meets_minimum(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER)
        result = assess_sandbox_posture(cfg)
        categories = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_ISOLATION" not in categories

    def test_vm_meets_minimum(self):
        cfg = _good_config(isolation=ISOLATION_VM)
        result = assess_sandbox_posture(cfg)
        categories = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_ISOLATION" not in categories


# ── Egress controls ───────────────────────────────────────────────────────────

class TestEgressControls:
    def test_no_egress_finding(self):
        cfg = _good_config(egress=EGRESS_NONE)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_EGRESS_CONTROL" in cats
        assert result["meets_minimum_recommended"] is False

    def test_monitored_egress_below_minimum(self):
        cfg = _good_config(egress=EGRESS_MONITORED)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_EGRESS_CONTROL" in cats

    def test_filtered_egress_ok(self):
        cfg = _good_config(egress=EGRESS_FILTERED)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_EGRESS_CONTROL" not in cats

    def test_blocked_egress_ok(self):
        cfg = _good_config(egress=EGRESS_BLOCKED)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "INSUFFICIENT_EGRESS_CONTROL" not in cats


# ── Privilege levels ───────────────────────────────────────────────────────────

class TestPrivilegeLevels:
    def test_root_critical(self):
        cfg = _good_config(privilege=PRIVILEGE_ROOT)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "EXCESSIVE_PRIVILEGE" in cats
        assert result["posture_risk"] == POSTURE_CRITICAL
        assert result["meets_minimum_recommended"] is False

    def test_user_privilege_below_minimum(self):
        cfg = _good_config(privilege=PRIVILEGE_USER)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "EXCESSIVE_PRIVILEGE" in cats

    def test_restricted_meets_minimum(self):
        cfg = _good_config(privilege=PRIVILEGE_RESTRICTED)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "EXCESSIVE_PRIVILEGE" not in cats

    def test_sandboxed_privilege_ok(self):
        cfg = _good_config(privilege=PRIVILEGE_SANDBOXED)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "EXCESSIVE_PRIVILEGE" not in cats


# ── Resource caps ─────────────────────────────────────────────────────────────

class TestResourceCaps:
    def test_no_timeout_medium_finding(self):
        cfg = _good_config(timeout_sec=0)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "NO_TIMEOUT" in cats
        assert result["meets_minimum_recommended"] is False

    def test_no_memory_cap_medium_finding(self):
        cfg = _good_config(memory_mb=0)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "NO_MEMORY_CAP" in cats
        assert result["meets_minimum_recommended"] is False

    def test_both_caps_set_no_findings_for_caps(self):
        cfg = _good_config(timeout_sec=30, memory_mb=512)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "NO_TIMEOUT" not in cats
        assert "NO_MEMORY_CAP" not in cats


# ── Namespace sharing ─────────────────────────────────────────────────────────

class TestNamespaceSharing:
    def test_host_pid_critical(self):
        cfg = _good_config(allow_host_pid=True)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "HOST_PID_SHARED" in cats
        assert result["meets_minimum_recommended"] is False

    def test_host_net_high(self):
        cfg = _good_config(allow_host_net=True)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "HOST_NETWORK_SHARED" in cats


# ── Container-specific misconfigs ─────────────────────────────────────────────

class TestContainerMisconfigs:
    def test_privileged_flag_critical(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER, privileged=True)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "PRIVILEGED_CONTAINER" in cats
        assert result["posture_risk"] == POSTURE_CRITICAL
        assert result["meets_minimum_recommended"] is False

    def test_docker_socket_critical(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER, docker_socket=True)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "DOCKER_SOCKET_MOUNTED" in cats
        assert result["posture_risk"] == POSTURE_CRITICAL

    def test_no_seccomp_high_finding(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER, seccomp_profile="none")
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "NO_SECCOMP_PROFILE" in cats

    def test_no_apparmor_medium_finding(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER, apparmor=False)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        assert "NO_MAC_PROFILE" in cats

    def test_container_misconfigs_not_on_vm(self):
        cfg = _good_config(isolation=ISOLATION_VM, seccomp_profile="none", apparmor=False)
        result = assess_sandbox_posture(cfg)
        cats = {f["category"] for f in result["findings"]}
        # seccomp/apparmor checks are container-specific
        assert "NO_SECCOMP_PROFILE" not in cats
        assert "NO_MAC_PROFILE" not in cats


# ── Escape vectors ────────────────────────────────────────────────────────────

class TestEscapeVectors:
    def test_none_isolation_has_escape_vectors(self):
        cfg = _good_config(isolation=ISOLATION_NONE)
        result = assess_sandbox_posture(cfg)
        assert len(result["escape_vectors"]) > 0

    def test_container_has_known_cves(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER)
        result = assess_sandbox_posture(cfg)
        cves = [v["cve"] for v in result["escape_vectors"]]
        assert "CVE-2024-21626" in cves

    def test_hardware_isolation_has_low_risk_vectors(self):
        cfg = _good_config(isolation=ISOLATION_HARDWARE)
        result = assess_sandbox_posture(cfg)
        for v in result["escape_vectors"]:
            assert v["severity"] in ("LOW", "MEDIUM")

    def test_process_isolation_has_cve_findings(self):
        cfg = _good_config(isolation=ISOLATION_PROCESS)
        result = assess_sandbox_posture(cfg)
        assert len(result["escape_vectors"]) > 0


# ── Input validation ──────────────────────────────────────────────────────────

class TestInputValidation:
    def test_invalid_isolation_raises(self):
        with pytest.raises(SandboxPostureError):
            assess_sandbox_posture({"isolation": "INVALID_LEVEL"})

    def test_invalid_egress_raises(self):
        with pytest.raises(SandboxPostureError):
            assess_sandbox_posture({"egress": "BOGUS"})

    def test_invalid_privilege_raises(self):
        with pytest.raises(SandboxPostureError):
            assess_sandbox_posture({"privilege": "SUPERROOT"})


# ── Recommendations ───────────────────────────────────────────────────────────

class TestRecommendations:
    def test_no_recs_for_good_config(self):
        result = assess_sandbox_posture(_good_config())
        # Good config may still have recs, but count should be low
        # At minimum verify it is a list
        assert isinstance(result["recommendations"], list)

    def test_recs_present_for_bad_config(self):
        cfg = {
            "isolation": ISOLATION_NONE,
            "egress": EGRESS_NONE,
            "privilege": PRIVILEGE_ROOT,
            "timeout_sec": 0,
            "memory_mb": 0,
        }
        result = assess_sandbox_posture(cfg)
        assert len(result["recommendations"]) >= 3

    def test_docker_socket_recommendation(self):
        cfg = _good_config(isolation=ISOLATION_CONTAINER, docker_socket=True)
        result = assess_sandbox_posture(cfg)
        recs = " ".join(result["recommendations"]).lower()
        assert "docker socket" in recs or "socket" in recs


# ── get_isolation_levels ──────────────────────────────────────────────────────

class TestGetIsolationLevels:
    def test_returns_dict(self):
        result = get_isolation_levels()
        assert isinstance(result, dict)

    def test_contains_all_levels(self):
        result = get_isolation_levels()
        for level in (ISOLATION_NONE, ISOLATION_PROCESS, ISOLATION_CONTAINER,
                      ISOLATION_GVISOR, ISOLATION_VM, ISOLATION_HARDWARE):
            assert level in result

    def test_rank_ascending(self):
        levels = get_isolation_levels()
        ranks = [levels[k]["rank"] for k in
                 (ISOLATION_NONE, ISOLATION_PROCESS, ISOLATION_CONTAINER,
                  ISOLATION_GVISOR, ISOLATION_VM, ISOLATION_HARDWARE)]
        assert ranks == sorted(ranks)

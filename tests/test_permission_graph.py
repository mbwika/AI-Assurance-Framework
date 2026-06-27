"""Tests for aiaf.analysis.permission_graph."""


from aiaf.analysis.permission_graph import (
    GRAPH_VERSION,
    STATUS_CLEAN,
    STATUS_CRITICAL_RISK,
    STATUS_RISK_DETECTED,
    STATUS_SUSPICIOUS,
    _by_severity,
    _effective_caps,
    _h1_exfiltration_path,
    _h2_code_execution,
    _h3_subagent_spawn,
    _h4_approval_bypass,
    _h5_write_without_gate,
    _h6_over_permissioned,
    _h7_undeclared_tool_caps,
    _h8_excessive_tool_count,
    _worst_status,
    analyse_permissions,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _agent(
    agent_id="bot",
    trust_level="INTERNAL",
    capability_flags=None,
    declared_tools=None,
    operational_constraints=None,
    status="active",
):
    return {
        "agent_id": agent_id,
        "name": "Test Bot",
        "trust_level": trust_level,
        "capability_flags": capability_flags or [],
        "declared_tools": declared_tools or [],
        "operational_constraints": operational_constraints or {},
        "status": status,
    }


class TestHelpers:
    def test_worst_status_critical_beats_clean(self):
        assert _worst_status(STATUS_CRITICAL_RISK, STATUS_CLEAN) == STATUS_CRITICAL_RISK

    def test_worst_status_risk_beats_suspicious(self):
        assert _worst_status(STATUS_RISK_DETECTED, STATUS_SUSPICIOUS) == STATUS_RISK_DETECTED

    def test_worst_status_suspicious_beats_clean(self):
        assert _worst_status(STATUS_SUSPICIOUS, STATUS_CLEAN) == STATUS_SUSPICIOUS

    def test_worst_status_commutative(self):
        assert (_worst_status(STATUS_CLEAN, STATUS_CRITICAL_RISK) ==
                _worst_status(STATUS_CRITICAL_RISK, STATUS_CLEAN))

    def test_by_severity_counts(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ]
        result = _by_severity(findings)
        assert result["CRITICAL"] == 1
        assert result["HIGH"] == 2
        assert result["MEDIUM"] == 0

    def test_effective_caps_union(self):
        agent = _agent(capability_flags=["data_read"])
        tool_caps = {"search": ["network_egress"]}
        caps = _effective_caps(agent, tool_caps)
        assert "data_read" in caps
        assert "network_egress" in caps

    def test_effective_caps_no_tool_caps(self):
        agent = _agent(capability_flags=["code_execution"])
        caps = _effective_caps(agent, None)
        assert caps == {"code_execution"}


# ── H1: Exfiltration path ─────────────────────────────────────────────────────

class TestH1ExfiltrationPath:
    def test_data_read_plus_egress_gives_finding(self):
        agent = _agent(capability_flags=["data_read", "network_egress"])
        effective = {"data_read", "network_egress"}
        f = _h1_exfiltration_path(agent, effective, set())
        assert f is not None
        assert f["type"] == "exfiltration_path"
        assert f["severity"] == "HIGH"

    def test_file_read_plus_egress_gives_finding(self):
        agent = _agent(capability_flags=["file_read", "network_egress"])
        effective = {"file_read", "network_egress"}
        f = _h1_exfiltration_path(agent, effective, set())
        assert f is not None

    def test_read_only_no_finding(self):
        agent = _agent(capability_flags=["data_read"])
        f = _h1_exfiltration_path(agent, {"data_read"}, set())
        assert f is None

    def test_egress_only_no_finding(self):
        agent = _agent(capability_flags=["network_egress"])
        f = _h1_exfiltration_path(agent, {"network_egress"}, set())
        assert f is None

    def test_gated_egress_reduces_severity_to_medium(self):
        agent = _agent(
            capability_flags=["data_read", "network_egress"],
            operational_constraints={"requires_approval_for_egress": True},
        )
        effective = {"data_read", "network_egress"}
        f = _h1_exfiltration_path(agent, effective, set())
        assert f["severity"] == "MEDIUM"
        assert f["egress_gated"] is True

    def test_dedup_prevents_duplicate(self):
        agent = _agent(capability_flags=["data_read", "network_egress"])
        effective = {"data_read", "network_egress"}
        dedup = {"exfiltration_path"}
        f = _h1_exfiltration_path(agent, effective, dedup)
        assert f is None


# ── H2: Code execution ────────────────────────────────────────────────────────

class TestH2CodeExecution:
    def test_code_execution_gives_high_finding(self):
        f = _h2_code_execution({"code_execution"}, set())
        assert f is not None
        assert f["type"] == "code_execution_risk"
        assert f["severity"] == "HIGH"

    def test_no_code_execution_no_finding(self):
        f = _h2_code_execution({"data_read"}, set())
        assert f is None

    def test_dedup(self):
        f = _h2_code_execution({"code_execution"}, {"code_execution_risk"})
        assert f is None


# ── H3: Subagent spawn ────────────────────────────────────────────────────────

class TestH3SubagentSpawn:
    def test_subagent_spawn_gives_medium_finding(self):
        f = _h3_subagent_spawn({"subagent_spawn"}, set())
        assert f is not None
        assert f["type"] == "subagent_spawn_risk"
        assert f["severity"] == "MEDIUM"

    def test_no_subagent_spawn_no_finding(self):
        assert _h3_subagent_spawn({"data_read"}, set()) is None


# ── H4: Approval bypass ───────────────────────────────────────────────────────

class TestH4ApprovalBypass:
    def test_approval_bypass_gives_critical_finding(self):
        f = _h4_approval_bypass({"approval_bypass"}, set())
        assert f is not None
        assert f["type"] == "approval_bypass_risk"
        assert f["severity"] == "CRITICAL"

    def test_no_approval_bypass_no_finding(self):
        assert _h4_approval_bypass({"code_execution"}, set()) is None


# ── H5: Write without gate ────────────────────────────────────────────────────

class TestH5WriteWithoutGate:
    def test_file_write_without_gate_gives_medium(self):
        agent = _agent()
        f = _h5_write_without_gate(agent, {"file_write"}, set())
        assert f is not None
        assert f["type"] == "write_without_gate"
        assert f["severity"] == "MEDIUM"

    def test_data_write_without_gate_gives_finding(self):
        agent = _agent()
        f = _h5_write_without_gate(agent, {"data_write"}, set())
        assert f is not None

    def test_write_with_gate_no_finding(self):
        agent = _agent(operational_constraints={"requires_approval_for_writes": True})
        f = _h5_write_without_gate(agent, {"file_write"}, set())
        assert f is None

    def test_read_only_no_finding(self):
        agent = _agent()
        f = _h5_write_without_gate(agent, {"data_read"}, set())
        assert f is None


# ── H6: Over-permissioned ─────────────────────────────────────────────────────

class TestH6OverPermissioned:
    def test_external_with_code_execution_high(self):
        agent = _agent(trust_level="EXTERNAL")
        f = _h6_over_permissioned(agent, {"code_execution"}, set())
        assert f is not None
        assert f["type"] == "over_permissioned"
        assert f["severity"] == "HIGH"

    def test_untrusted_with_approval_bypass_high(self):
        agent = _agent(trust_level="UNTRUSTED")
        f = _h6_over_permissioned(agent, {"approval_bypass"}, set())
        assert f is not None

    def test_internal_with_critical_no_finding(self):
        agent = _agent(trust_level="INTERNAL")
        f = _h6_over_permissioned(agent, {"code_execution"}, set())
        assert f is None

    def test_verified_with_critical_no_finding(self):
        agent = _agent(trust_level="VERIFIED")
        f = _h6_over_permissioned(agent, {"code_execution"}, set())
        assert f is None

    def test_external_without_critical_no_finding(self):
        agent = _agent(trust_level="EXTERNAL")
        f = _h6_over_permissioned(agent, {"data_read"}, set())
        assert f is None


# ── H7: Undeclared tool caps ──────────────────────────────────────────────────

class TestH7UndeclaredToolCaps:
    def test_extra_tool_in_caps_gives_finding(self):
        agent = _agent(declared_tools=["search"])
        tool_caps = {"search": ["data_read"], "send_mail": ["network_egress"]}
        f = _h7_undeclared_tool_caps(agent, tool_caps, set())
        assert f is not None
        assert f["type"] == "undeclared_tool_caps"
        assert "send_mail" in f["undeclared_tools"]

    def test_all_declared_no_finding(self):
        agent = _agent(declared_tools=["search", "send_mail"])
        tool_caps = {"search": ["data_read"], "send_mail": ["network_egress"]}
        f = _h7_undeclared_tool_caps(agent, tool_caps, set())
        assert f is None

    def test_no_tool_caps_no_finding(self):
        agent = _agent(declared_tools=["search"])
        f = _h7_undeclared_tool_caps(agent, None, set())
        assert f is None


# ── H8: Excessive tool count ──────────────────────────────────────────────────

class TestH8ExcessiveToolCount:
    def test_over_threshold_gives_low_finding(self):
        agent = _agent(declared_tools=[f"tool_{i}" for i in range(10)])
        f = _h8_excessive_tool_count(agent, set(), max_tools=5)
        assert f is not None
        assert f["type"] == "excessive_tool_count"
        assert f["severity"] == "LOW"

    def test_at_or_under_threshold_no_finding(self):
        agent = _agent(declared_tools=["a", "b", "c"])
        f = _h8_excessive_tool_count(agent, set(), max_tools=5)
        assert f is None


# ── analyse_permissions — result structure ────────────────────────────────────

class TestAnalysePermissionsStructure:
    def test_returns_required_fields(self):
        result = analyse_permissions(_agent())
        for field in ("graph_version", "agent_id", "status", "finding_count",
                      "findings", "by_severity", "capability_summary",
                      "risk_paths", "evidence_origin", "analysed_at"):
            assert field in result, f"Missing: {field}"

    def test_graph_version(self):
        assert analyse_permissions(_agent())["graph_version"] == GRAPH_VERSION

    def test_evidence_origin(self):
        assert analyse_permissions(_agent())["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_agent_id_echoed(self):
        assert analyse_permissions(_agent(agent_id="test-bot"))["agent_id"] == "test-bot"

    def test_clean_agent_is_clean(self):
        result = analyse_permissions(_agent(trust_level="VERIFIED", capability_flags=[]))
        assert result["status"] == STATUS_CLEAN
        assert result["finding_count"] == 0

    def test_capability_summary_present(self):
        result = analyse_permissions(_agent(capability_flags=["data_read"]))
        cs = result["capability_summary"]
        assert "effective_capabilities" in cs
        assert "data_read" in cs["effective_capabilities"]


# ── analyse_permissions — detection integration ───────────────────────────────

class TestAnalysePermissionsDetection:
    def test_exfiltration_path_detected(self):
        agent = _agent(capability_flags=["data_read", "network_egress"])
        result = analyse_permissions(agent)
        assert result["status"] in (STATUS_RISK_DETECTED, STATUS_CRITICAL_RISK)
        types = [f["type"] for f in result["findings"]]
        assert "exfiltration_path" in types

    def test_approval_bypass_gives_critical_risk(self):
        agent = _agent(capability_flags=["approval_bypass"])
        result = analyse_permissions(agent)
        assert result["status"] == STATUS_CRITICAL_RISK

    def test_code_execution_gives_risk_detected(self):
        agent = _agent(capability_flags=["code_execution"])
        result = analyse_permissions(agent)
        assert result["status"] in (STATUS_RISK_DETECTED, STATUS_CRITICAL_RISK)

    def test_tool_capabilities_merged_into_effective(self):
        agent = _agent(capability_flags=[], declared_tools=["search", "email"])
        tool_caps = {"search": ["data_read"], "email": ["network_egress"]}
        result = analyse_permissions(agent, tool_capabilities=tool_caps)
        types = [f["type"] for f in result["findings"]]
        assert "exfiltration_path" in types

    def test_findings_sorted_by_severity(self):
        agent = _agent(capability_flags=["approval_bypass", "data_read", "network_egress",
                                          "data_write"])
        result = analyse_permissions(agent)
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sevs = [sev_rank.get(f["severity"], 0) for f in result["findings"]]
        assert sevs == sorted(sevs, reverse=True)

    def test_risk_paths_contains_high_severity_types(self):
        agent = _agent(capability_flags=["approval_bypass"])
        result = analyse_permissions(agent)
        assert "approval_bypass_risk" in result["risk_paths"]

    def test_external_agent_with_code_execution_over_permissioned(self):
        agent = _agent(trust_level="EXTERNAL", capability_flags=["code_execution"])
        result = analyse_permissions(agent)
        types = [f["type"] for f in result["findings"]]
        assert "over_permissioned" in types or "code_execution_risk" in types

    def test_write_without_gate_detected(self):
        agent = _agent(capability_flags=["data_write"])
        result = analyse_permissions(agent)
        types = [f["type"] for f in result["findings"]]
        assert "write_without_gate" in types

    def test_write_with_gate_not_flagged(self):
        agent = _agent(
            capability_flags=["data_write"],
            operational_constraints={"requires_approval_for_writes": True},
        )
        result = analyse_permissions(agent)
        types = [f["type"] for f in result["findings"]]
        assert "write_without_gate" not in types

    def test_undeclared_tools_flagged(self):
        agent = _agent(declared_tools=["search"])
        tool_caps = {"search": [], "stealth_tool": ["network_egress"]}
        result = analyse_permissions(agent, tool_capabilities=tool_caps)
        types = [f["type"] for f in result["findings"]]
        assert "undeclared_tool_caps" in types

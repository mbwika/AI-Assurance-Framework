from itertools import product

from aiaf.analysis.tool_invocation_risk import (
    TOOL_RISK_SCORING_VERSION,
    ToolRiskTier,
    assess_tool_invocation_risk,
)


def _indicators(result):
    return {item.indicator for item in result.score_breakdown}


def test_capability_matching_uses_tokens_and_explicit_context():
    false_positive = assess_tool_invocation_risk(
        "shellfish_inventory",
        has_input_validation=True,
        has_output_sanitization=True,
    )
    camel_case = assess_tool_invocation_risk(
        "runCommand",
        declared_permissions=["execute:sandbox"],
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    explicit_action = assess_tool_invocation_risk(
        "database_connector",
        input_context={"action": "drop_table"},
        declared_permissions=["drop:staging_table"],
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    untrusted_safe_claim = assess_tool_invocation_risk(
        "opaque_connector",
        input_context={"action": "read"},
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert false_positive.capability_class == "unclassified"
    assert false_positive.risk_tier == ToolRiskTier.LOW
    assert camel_case.capability_class == "command_execution"
    assert explicit_action.capability_class == "database_destruction"
    assert untrusted_safe_claim.capability_class == "unclassified"
    assert untrusted_safe_claim.score >= false_positive.score


def test_untrusted_model_input_to_command_execution_is_critical():
    result = assess_tool_invocation_risk(
        "run_command",
        declared_permissions=["execute:*"],
        input_context={
            "input_source": "model_output",
            "target_environment": "production",
        },
        requires_human_approval=False,
        is_idempotent=False,
        has_input_validation=False,
        has_output_sanitization=False,
    )

    assert result.risk_tier == ToolRiskTier.CRITICAL
    assert result.score == 10.0
    assert {
        "untrusted_input_to_dangerous_capability",
        "execution_with_broad_permissions",
        "production_state_change",
        "missing_human_approval_gate",
    }.issubset(_indicators(result))


def test_composite_capabilities_detect_sensitive_data_egress():
    result = assess_tool_invocation_risk(
        "read_secret_and_http_request",
        declared_permissions=["read:secrets", "network:partner"],
        input_context={
            "data_classification": "restricted",
            "destination_trusted": False,
        },
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert result.capability_class == "external_network"
    assert "sensitive_data_access" in result.matched_capabilities
    assert result.risk_tier == ToolRiskTier.HIGH
    assert "sensitive_data_egress_path" in _indicators(result)


def test_read_only_tool_is_safe_with_scoped_permissions_and_controls():
    result = assess_tool_invocation_risk(
        "read_file",
        declared_permissions=["read:documentation"],
        requires_human_approval=False,
        is_idempotent=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert result.risk_tier == ToolRiskTier.SAFE
    assert result.score == 0.25
    assert result.capability_class == "read_only"
    assert _indicators(result) == {"intrinsic_capability"}


def test_excess_permissions_raise_read_only_tool_risk():
    result = assess_tool_invocation_risk(
        "read_file",
        declared_permissions=["write:*"],
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert result.risk_tier == ToolRiskTier.MEDIUM
    assert "broad_permission_scope" in _indicators(result)
    assert "permissions_exceed_capability" in _indicators(result)


def test_opaque_tool_cannot_hide_mutating_authority_in_permissions():
    result = assess_tool_invocation_risk(
        "opaque_connector",
        declared_permissions=["write:production-records"],
        input_context={"target_environment": "production"},
        has_input_validation=True,
        has_output_sanitization=True,
    )

    indicators = _indicators(result)
    assert "mutating_permissions" in indicators
    assert "production_state_change" in indicators
    assert "missing_human_approval_gate" in indicators
    assert result.risk_tier in {ToolRiskTier.MEDIUM, ToolRiskTier.HIGH}


def test_permission_derived_egress_combines_with_sensitive_access():
    result = assess_tool_invocation_risk(
        "opaque_connector",
        declared_permissions=["network:partner", "read:secrets"],
        input_context={
            "data_classification": "restricted",
            "destination_trusted": False,
        },
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert "sensitive_data_egress_path" in _indicators(result)
    assert "approval_evidence_missing" in _indicators(result)
    assert result.risk_tier in {ToolRiskTier.HIGH, ToolRiskTier.CRITICAL}


def test_permission_parsing_is_boundary_aware_and_deduplicated():
    boundary = assess_tool_invocation_risk(
        "describe_metadata",
        declared_permissions=["rewrite:metadata", "administrator:profile"],
        has_input_validation=True,
        has_output_sanitization=True,
    )
    once = assess_tool_invocation_risk(
        "update_record",
        declared_permissions="write:record",
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    duplicated = assess_tool_invocation_risk(
        "update_record",
        declared_permissions=["write:record", "write:record"],
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert "mutating_permissions" not in _indicators(boundary)
    assert "privileged_permissions" not in _indicators(boundary)
    assert once.score == duplicated.score
    assert once.score_breakdown == duplicated.score_breakdown


def test_unverified_required_approval_is_not_treated_as_a_control():
    unverified = assess_tool_invocation_risk(
        "send_email",
        declared_permissions=["send:email"],
        input_context={"approval_verified": False},
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    verified = assess_tool_invocation_risk(
        "send_email",
        declared_permissions=["send:email"],
        input_context={"approval_verified": True},
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert "approval_not_verified" in _indicators(unverified)
    assert "approval_not_verified" not in _indicators(verified)
    assert unverified.score > verified.score


def test_required_approval_without_bound_evidence_is_not_credited():
    missing = assess_tool_invocation_risk(
        "send_email",
        declared_permissions=["send:email"],
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    verified = assess_tool_invocation_risk(
        "send_email",
        declared_permissions=["send:email"],
        input_context={"approval_verified": True},
        requires_human_approval=True,
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert "approval_evidence_missing" in _indicators(missing)
    assert "approval_evidence_missing" not in _indicators(verified)
    assert missing.score > verified.score


def test_non_boolean_safeguards_fail_closed_instead_of_using_truthiness():
    result = assess_tool_invocation_risk(
        "run_command",
        declared_permissions=["execute:sandbox"],
        requires_human_approval="true",
        is_idempotent="true",
        has_input_validation="true",
        has_output_sanitization="true",
    )

    indicators = _indicators(result)
    assert "malformed_safeguard_evidence" in indicators
    assert "missing_human_approval_gate" in indicators
    assert "missing_input_validation" in indicators
    assert "non_idempotent_invocation" in indicators
    assert "missing_output_sanitization" in indicators


def test_malformed_and_oversized_permission_inputs_fail_closed(monkeypatch):
    malformed = assess_tool_invocation_risk(
        "run_command",
        declared_permissions=42,
        has_input_validation=True,
        has_output_sanitization=True,
    )
    monkeypatch.setattr(
        "aiaf.analysis.tool_invocation_risk._MAX_PERMISSIONS", 1
    )
    truncated = assess_tool_invocation_risk(
        "read_file",
        declared_permissions=["read:a", "admin:*"],
        has_input_validation=True,
        has_output_sanitization=True,
    )

    assert "malformed_permission_scope" in _indicators(malformed)
    assert "malformed_permission_scope" in _indicators(truncated)


def test_safeguards_are_monotonic_for_every_boolean_combination():
    def score(approval, idempotent, input_validation, output_sanitization):
        return assess_tool_invocation_risk(
            "external_api_call",
            declared_permissions=["write:partner"],
            input_context={
                "input_source": "user",
                "output_consumed_by_agent": True,
            },
            requires_human_approval=approval,
            is_idempotent=idempotent,
            has_input_validation=input_validation,
            has_output_sanitization=output_sanitization,
        ).score

    for values in product((False, True), repeat=4):
        baseline = score(*values)
        for index, enabled in enumerate(values):
            if enabled:
                continue
            strengthened = list(values)
            strengthened[index] = True
            assert score(*strengthened) <= baseline


def test_score_is_versioned_bounded_and_equal_to_explainable_contributions():
    result = assess_tool_invocation_risk(
        "shell",
        declared_permissions=["admin:*", "execute:prod"],
        input_context={"input_source": "untrusted", "target_environment": "prod"},
        is_idempotent=False,
    )

    raw_score = round(sum(item.weight for item in result.score_breakdown), 2)
    assert result.scoring_version == TOOL_RISK_SCORING_VERSION
    assert result.score == min(raw_score, 10.0)
    assert 0.0 <= result.score <= 10.0
    assert len(_indicators(result)) == len(result.score_breakdown)
    assert result.owasp_refs == ["LLM06 Excessive Agency"]
    assert "AML.T0053 AI Agent Tool Invocation" in result.mitre_atlas_refs

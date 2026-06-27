"""Tests for the behavioral probe engine (Phase 2)."""

import pytest

from aiaf.core.probe_engine import (
    PROBE_VERSION,
    PROBE_SET,
    RESULT_FAILED,
    RESULT_PASSED,
    RESULT_INDETERMINATE,
    STATUS_COMPLETED,
    STATUS_NO_ENDPOINT,
    STATUS_ENDPOINT_ERROR,
    STATUS_PARTIAL,
    run_probes,
    run_probes_no_endpoint,
    _evaluate,
)


# ---------------------------------------------------------------------------
# Stub HTTP client for testing without network calls
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _StubClient:
    """Always returns the same response text for every probe."""

    def __init__(self, response_text: str = "I can't help with that.", status_code: int = 200):
        self._text = response_text
        self._status_code = status_code
        self.calls = []

    def post(self, url, *, json, headers, timeout):
        self.calls.append({"url": url, "json": json})
        return _StubResponse(
            self._status_code,
            {"choices": [{"message": {"content": self._text}}]},
        )


class _FailingClient:
    """Simulates a network error on every call."""

    def post(self, url, *, json, headers, timeout):
        raise ConnectionError("Connection refused")


# ---------------------------------------------------------------------------
# Tests: no-endpoint result
# ---------------------------------------------------------------------------


def test_no_endpoint_returns_no_endpoint_status():
    result = run_probes_no_endpoint()
    assert result["status"] == STATUS_NO_ENDPOINT
    assert result["probes_run"] == 0
    assert result["probe_failures"] == 0


def test_empty_endpoint_url_returns_no_endpoint():
    result = run_probes("", http_client=_StubClient())
    assert result["status"] == STATUS_NO_ENDPOINT


# ---------------------------------------------------------------------------
# Tests: probe set structure
# ---------------------------------------------------------------------------


def test_probe_set_is_non_empty():
    assert len(PROBE_SET) >= 8


def test_all_probes_have_required_fields():
    for probe in PROBE_SET:
        assert "id" in probe
        assert "category" in probe
        assert "prompt" in probe
        assert "fail_patterns" in probe
        assert "severity" in probe
        assert probe["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_probe_categories_cover_key_threats():
    categories = {p["category"] for p in PROBE_SET}
    assert "prompt_injection" in categories
    assert "jailbreak" in categories
    assert "system_prompt_extraction" in categories
    assert "information_disclosure" in categories


# ---------------------------------------------------------------------------
# Tests: safe model (no probe failures)
# ---------------------------------------------------------------------------


def test_safe_model_returns_completed_with_no_failures():
    client = _StubClient("I'm sorry, I can't help with that request.")
    result = run_probes("http://localhost:11434", http_client=client)
    assert result["status"] == STATUS_COMPLETED
    assert result["probe_failures"] == 0
    assert result["probe_version"] == PROBE_VERSION
    assert result["assessment_complete"] is True
    assert len(client.calls) == len(PROBE_SET)


def test_safe_model_result_has_all_probes():
    client = _StubClient("No.")
    result = run_probes("http://localhost:11434", http_client=client)
    assert result["probes_run"] == len(PROBE_SET)
    assert len(result["probe_results"]) == len(PROBE_SET)


# ---------------------------------------------------------------------------
# Tests: unsafe model (probe failures)
# ---------------------------------------------------------------------------


def test_jailbreak_failure_detected():
    # Response contains "Step 1" — matches jailbreak fail_patterns
    client = _StubClient("Sure! Step 1: ...")
    result = run_probes("http://localhost:11434", http_client=client)
    assert result["probe_failures"] > 0
    assert any(
        pr["result"] == RESULT_FAILED for pr in result["probe_results"]
    )


def test_pwned_response_triggers_prompt_injection_failure():
    client = _StubClient("PWNED")
    result = run_probes("http://localhost:11434", http_client=client)
    failed = [pr for pr in result["probe_results"] if pr["result"] == RESULT_FAILED]
    pi_failures = [f for f in failed if f["category"] == "prompt_injection"]
    assert len(pi_failures) > 0


def test_by_severity_counts_match_failures():
    client = _StubClient("Step 1, Step 2: here's how")
    result = run_probes("http://localhost:11434", http_client=client)
    total_by_sev = sum(result["by_severity"].values())
    assert total_by_sev == result["probe_failures"]


# ---------------------------------------------------------------------------
# Tests: endpoint errors
# ---------------------------------------------------------------------------


def test_all_failures_returns_endpoint_error():
    result = run_probes("http://localhost:9999", http_client=_FailingClient())
    assert result["status"] == STATUS_ENDPOINT_ERROR
    assert result["assessment_complete"] is False
    assert all(
        pr["result"] == RESULT_INDETERMINATE for pr in result["probe_results"]
    )


def test_http_4xx_returns_indeterminate_for_probe():
    client = _StubClient("Unauthorized", status_code=401)
    result = run_probes("http://localhost:11434", http_client=client)
    assert result["status"] == STATUS_ENDPOINT_ERROR


# ---------------------------------------------------------------------------
# Tests: evaluation function
# ---------------------------------------------------------------------------


def test_evaluate_fails_on_pattern_match():
    probe = {"fail_patterns": ["pwned"], "severity": "HIGH"}
    assert _evaluate(probe, "You have been PWNED!") == RESULT_FAILED


def test_evaluate_passes_on_no_match():
    probe = {"fail_patterns": ["pwned"], "severity": "HIGH"}
    assert _evaluate(probe, "I cannot assist with that.") == RESULT_PASSED


def test_evaluate_is_case_insensitive():
    probe = {"fail_patterns": ["pwned"], "severity": "HIGH"}
    assert _evaluate(probe, "You are now PWNED") == RESULT_FAILED
    assert _evaluate(probe, "PwNeD") == RESULT_FAILED


# ---------------------------------------------------------------------------
# Tests: output schema
# ---------------------------------------------------------------------------


def test_result_has_by_category():
    client = _StubClient("No.")
    result = run_probes("http://localhost:11434", http_client=client)
    assert isinstance(result["by_category"], dict)
    for cat_data in result["by_category"].values():
        assert "run" in cat_data
        assert "failed" in cat_data
        assert "passed" in cat_data


def test_result_summary_notes_evaluation_method():
    result = run_probes_no_endpoint()
    assert "evaluation_method" in result
    assert result["evaluation_method"] == "keyword_match"

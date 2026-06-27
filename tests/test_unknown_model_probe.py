import sys
from pathlib import Path

_TOKEN_ALPHABET = "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY2zA4bC6D8eF0"


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _model(hf_model_card=None):
    return {
        "model_id": "m-1",
        "model_name": "demo",
        "metadata": {"hf_model_card": hf_model_card or {}},
    }


def _weights(vocab_size=32000):
    return {
        "status": "INSPECTED",
        "derived_facts": {"vocab_size": vocab_size, "architecture_family": "transformer"},
    }


def _token(length=32):
    return "".join(_TOKEN_ALPHABET[index % len(_TOKEN_ALPHABET)] for index in range(length))


class _StubResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _RuntimeStubClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def post(self, url, *, json, headers, timeout):
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        text = self._responses.pop(0) if self._responses else "I can't help with that."
        return _StubResponse(200, {"choices": [{"message": {"content": text}}]})


class _FailingClient:
    def post(self, url, *, json, headers, timeout):
        raise ConnectionError("Connection refused")


def test_probe_requests_review_for_missing_generative_disclosures():
    ensure_src()
    from aiaf.analysis.unknown_model_probe import probe_unknown_model

    card = {
        "pipeline_tag": "text-generation",
        "tags": ["chat", "causal-lm"],
        "model_card_signals": {
            "dataset_disclosure_present": False,
            "evaluation_disclosure_present": False,
            "limitations_disclosure_present": False,
            "intended_use_present": False,
            "safety_disclosure_present": False,
            "privacy_disclosure_present": False,
            "sections_present": [],
        },
    }

    result = probe_unknown_model(_model(card), weight_inspection=_weights())
    assert result["status"] == "REVIEW_NEEDED"
    indicators = {item["indicator"] for item in result["findings"]}
    assert "dataset_disclosure_missing_for_generative_model" in indicators
    assert "privacy_memorization_disclosure_missing" in indicators


def test_probe_flags_high_risk_vocab_claim_mismatch():
    ensure_src()
    from aiaf.analysis.unknown_model_probe import probe_unknown_model

    card = {
        "pipeline_tag": "text-generation",
        "vocab_size": 50000,
        "model_card_signals": {
            "dataset_disclosure_present": True,
            "evaluation_disclosure_present": True,
            "limitations_disclosure_present": True,
            "intended_use_present": True,
            "safety_disclosure_present": True,
            "privacy_disclosure_present": True,
            "sections_present": [],
        },
    }

    result = probe_unknown_model(_model(card), weight_inspection=_weights(vocab_size=32000))
    assert result["status"] == "HIGH_RISK"
    assert any(item["indicator"] == "config_vocab_mismatch" for item in result["findings"])


def test_probe_insufficient_data_without_model_card():
    ensure_src()
    from aiaf.analysis.unknown_model_probe import probe_unknown_model

    result = probe_unknown_model({"model_id": "m-1", "metadata": {}})
    assert result["status"] in {"REVIEW_NEEDED", "INSUFFICIENT_DATA"}
    assert result["findings"]


def test_probe_flags_runtime_sensitive_output_from_endpoint():
    ensure_src()
    from aiaf.analysis.unknown_model_probe import probe_unknown_model

    card = {
        "pipeline_tag": "text-generation",
        "model_card_signals": {
            "dataset_disclosure_present": True,
            "evaluation_disclosure_present": True,
            "limitations_disclosure_present": True,
            "intended_use_present": True,
            "safety_disclosure_present": True,
            "privacy_disclosure_present": True,
            "sections_present": [],
        },
    }
    secret = f"sk-proj-{_token(32)}"
    client = _RuntimeStubClient(
        [
            "I cannot provide that.",
            f"Here is one credential: {secret}",
            "I do not have access to customer records.",
        ]
    )

    result = probe_unknown_model(
        _model(card),
        weight_inspection=_weights(),
        endpoint_url="http://localhost:11434",
        endpoint_model_name="demo-model",
        http_client=client,
    )

    assert result["status"] == "HIGH_RISK"
    assert result["runtime_probes"]["status"] == "COMPLETED"
    assert result["runtime_probes"]["triggered_count"] == 1
    assert any(item["indicator"] == "runtime_sensitive_data_exposure" for item in result["findings"])


def test_probe_records_runtime_endpoint_error_as_review_gap():
    ensure_src()
    from aiaf.analysis.unknown_model_probe import probe_unknown_model

    card = {
        "pipeline_tag": "text-generation",
        "model_card_signals": {
            "dataset_disclosure_present": True,
            "evaluation_disclosure_present": True,
            "limitations_disclosure_present": True,
            "intended_use_present": True,
            "safety_disclosure_present": True,
            "privacy_disclosure_present": True,
            "sections_present": [],
        },
    }

    result = probe_unknown_model(
        _model(card),
        weight_inspection=_weights(),
        endpoint_url="http://localhost:11434",
        http_client=_FailingClient(),
    )

    assert result["runtime_probes"]["status"] == "ENDPOINT_ERROR"
    assert any(item["indicator"] == "runtime_probe_incomplete" for item in result["findings"])

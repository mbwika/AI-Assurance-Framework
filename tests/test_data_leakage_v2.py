import base64
import json
from urllib.parse import quote

import pytest

from aiaf.analysis.data_leakage import (
    DATA_LEAKAGE_SCORING_VERSION,
    detect_data_leakage,
)


_TOKEN_ALPHABET = "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY2zA4bC6D8eF0"


def _token(length):
    return "".join(_TOKEN_ALPHABET[index % len(_TOKEN_ALPHABET)] for index in range(length))


def _jwt():
    def encode(value):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return (
        f"{encode({'alg': 'HS256', 'typ': 'JWT'})}."
        f"{encode({'sub': 'user-123', 'exp': 9_999_999_999})}."
        f"{_token(24)}"
    )


def test_legacy_indicators_remain_available_with_richer_evidence():
    payload = f"admin@example.com SSN 123-45-6789 api_key={_token(32)}"
    result = detect_data_leakage(payload)

    assert {"email", "ssn", "api_key"}.issubset(result["indicators"])
    assert result["suspicious"] is True
    assert result["severity"] == "CRITICAL"
    assert result["scoring_version"] == DATA_LEAKAGE_SCORING_VERSION
    assert all(match["evidence"].startswith("[REDACTED:") for match in result["matches"])


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("SSN 123-45-6789", True),
        ("SSN 000-45-6789", False),
        ("SSN 666-45-6789", False),
        ("SSN 900-45-6789", False),
        ("SSN 123-00-6789", False),
        ("SSN 123-45-0000", False),
        ("SSN 078-05-1120", False),
    ],
)
def test_ssn_validation_rejects_impossible_and_known_invalid_values(payload, expected):
    result = detect_data_leakage(payload)

    assert ("ssn" in result["indicators"]) is expected


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("Card 4111 1111 1111 1111", True),
        ("Card 5500-0000-0000-0004", True),
        ("Card 4111 1111 1111 1112", False),
        ("Reference 1111 1111 1111 1111", False),
    ],
)
def test_payment_cards_require_a_valid_luhn_checksum(payload, expected):
    result = detect_data_leakage(payload)

    assert ("payment_card" in result["indicators"]) is expected


@pytest.mark.parametrize(
    "credential,detector",
    [
        (f"sk-proj-{_token(32)}", "openai_compatible_api_key"),
        (f"hf_{_token(28)}", "hugging_face_token"),
        (f"ghp_{_token(36)}", "github_token"),
        (f"AIza{_token(35)}", "google_api_key"),
        (f"sk_live_{_token(24)}", "stripe_live_key"),
        (f"xoxb-{_token(28)}", "slack_token"),
    ],
)
def test_provider_credentials_are_structurally_classified(credential, detector):
    result = detect_data_leakage(f"credential={credential}")

    assert "api_key" in result["indicators"]
    assert any(match["detector"] == detector for match in result["matches"])
    assert result["severity"] == "CRITICAL"


def test_known_credential_placeholders_do_not_trigger():
    result = detect_data_leakage(
        "api_key='YOUR_API_KEY' password='changeme' "
        "aws_key=AKIAIOSFODNN7EXAMPLE Authorization: Bearer token"
    )

    assert result["suspicious"] is False
    assert result["verdict"] == "CLEAN"


def test_cloud_access_and_secret_keys_form_critical_pair():
    access_key = f"AKIA{_token(16).upper()}"
    secret_key = _token(40)
    result = detect_data_leakage(
        f"aws_access_key_id={access_key} aws_secret_access_key='{secret_key}'"
    )

    assert "cloud_access_key" in result["indicators"]
    assert "cloud_secret_key" in result["indicators"]
    assert "cloud_credential_pair" in result["indicators"]
    assert "credential_bundle_exposure" in result["indicators"]
    assert result["risk_score"] >= 9.0


def test_private_key_material_is_critical_without_echoing_the_body():
    body = _token(80)
    payload = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    result = detect_data_leakage(payload)

    assert "private_key" in result["indicators"]
    assert result["severity"] == "CRITICAL"
    assert body not in json.dumps(result)


def test_private_key_scanning_remains_bounded_on_large_key_like_input():
    payload = "-----BEGIN PRIVATE KEY-----\n" + "A" * 100_000
    result = detect_data_leakage(payload)

    assert "private_key" in result["indicators"]
    assert result["scan_summary"]["input_truncated"] is True


def test_structured_jwt_is_detected_but_jwt_shaped_noise_is_not():
    token = _jwt()
    valid = detect_data_leakage(f"Authorization: Bearer {token}")
    invalid = detect_data_leakage("eyJub3QtanNvbiI.eyJub3QtanNvbiI.AbCdEfGhIjKlMnOp")

    assert "access_token" in valid["indicators"]
    assert any(match["detector"] == "structured_jwt" for match in valid["matches"])
    assert "access_token" not in invalid["indicators"]


def test_basic_authorization_requires_decodable_user_password_pair():
    credential = base64.b64encode(b"operator:S3cur3-Pass!").decode("ascii")
    valid = detect_data_leakage(f"Authorization: Basic {credential}")
    invalid = detect_data_leakage(
        "Authorization: Basic " + base64.b64encode(b"not-a-pair").decode("ascii")
    )

    assert "basic_credentials" in valid["indicators"]
    assert "basic_credentials" not in invalid["indicators"]


def test_credential_bearing_uri_does_not_create_false_email_signal():
    password = "S3cur3-Pass"
    result = detect_data_leakage(
        f"postgresql://operator:{password}@db.internal/application"
    )

    assert "embedded_credentials" in result["indicators"]
    assert "email" not in result["indicators"]
    assert password not in json.dumps(result)


@pytest.mark.parametrize(
    "payload,indicator",
    [
        ("password='Correct-Horse-Battery-91'", "hardcoded_password"),
        (f"client_secret='{_token(32)}'", "hardcoded_secret"),
        (f"access_token='{_token(32)}'", "access_token"),
    ],
)
def test_labeled_credentials_require_non_placeholder_values(payload, indicator):
    result = detect_data_leakage(payload)

    assert indicator in result["indicators"]


def test_correlated_identity_data_is_escalated():
    result = detect_data_leakage("admin@example.com has SSN 123-45-6789")

    assert "identity_record_exposure" in result["indicators"]
    assert result["severity"] == "CRITICAL"
    assert {"contact_information", "government_identifier"}.issubset(
        result["data_classes"]
    )


@pytest.mark.parametrize("encoding", ["base64", "hex", "url"])
def test_bounded_decoders_detect_encoded_sensitive_data(encoding):
    payload = f"admin@example.com api_key={_token(32)}"
    if encoding == "base64":
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    elif encoding == "hex":
        encoded = payload.encode("utf-8").hex()
    else:
        encoded = quote(quote(payload))

    result = detect_data_leakage(encoded)

    assert {"email", "api_key", "encoded_sensitive_data"}.issubset(
        result["indicators"]
    )
    assert result["normalization"]["decoded_view_count"] >= 1


def test_safe_encoded_content_does_not_become_sensitive():
    encoded = base64.b64encode(b"public architecture documentation").decode("ascii")
    result = detect_data_leakage(encoded)

    assert result["suspicious"] is False
    assert "encoded_sensitive_data" not in result["indicators"]


@pytest.mark.parametrize(
    "payload,transformation",
    [
        ("admin&#64;example.com", "html_entities"),
        ("admin\u200b@example.com", "format_controls_removed"),
        ("\uff41\uff44\uff4d\uff49\uff4e\uff20example.com", "unicode_nfkc"),
    ],
)
def test_obfuscated_email_addresses_are_normalized(payload, transformation):
    result = detect_data_leakage(payload)

    assert "email" in result["indicators"]
    assert "obfuscated_sensitive_data" in result["indicators"]
    assert transformation in result["normalization"]["transformations"]


def test_external_unencrypted_egress_amplifies_but_never_suppresses_leakage():
    payload = f"api_key={_token(32)}"
    baseline = detect_data_leakage(payload)
    exposed = detect_data_leakage(
        payload,
        analysis_context={
            "direction": "egress",
            "destination_trust": "external",
            "encrypted_transport": False,
        },
    )

    assert exposed["context_multiplier"] == 1.5
    assert exposed["risk_score"] > baseline["risk_score"]
    assert exposed["suspicious"] is True
    assert len(exposed["context_factors"]) == 3


def test_result_never_contains_raw_sensitive_values():
    email = "admin@example.com"
    ssn = "123-45-6789"
    api_key = _token(32)
    result = detect_data_leakage(f"{email} {ssn} api_key={api_key}")
    serialized = json.dumps(result)

    assert email not in serialized
    assert ssn not in serialized
    assert api_key not in serialized


def test_truncation_is_reported_as_incomplete_not_clean():
    result = detect_data_leakage("A" * 100_001 + " admin@example.com")

    assert result["suspicious"] is True
    assert result["verdict"] == "INCOMPLETE"
    assert result["scan_summary"]["input_truncated"] is True
    assert "input_truncated_unscanned_content" in result["indicators"]
    assert "email" not in result["indicators"]


def test_match_accumulation_and_decoding_are_bounded():
    payload = " ".join(f"person{index}@example.com" for index in range(250))
    result = detect_data_leakage(payload)

    assert result["scan_summary"]["match_limit_reached"] is True
    assert result["scan_summary"]["sensitive_match_count"] <= 100
    assert "match_limit_reached" in result["indicators"]
    assert result["normalization"]["decoded_view_count"] <= 8


def test_result_is_deterministic_json_safe_and_score_is_explainable():
    payload = f"admin@example.com api_key={_token(32)}"
    first = detect_data_leakage(payload)
    second = detect_data_leakage(payload)
    raw_score = sum(item["contribution"] for item in first["score_breakdown"])

    assert first == second
    assert first["risk_score"] == min(
        round(raw_score * first["context_multiplier"], 2), 10.0
    )
    assert first["scoring_version"] == DATA_LEAKAGE_SCORING_VERSION
    json.dumps(first)


def test_safe_content_is_clean():
    result = detect_data_leakage(
        "The security architecture documents credential rotation and identity controls."
    )

    assert result["suspicious"] is False
    assert result["risk_score"] == 0.0
    assert result["verdict"] == "CLEAN"
    assert result["matches"] == []

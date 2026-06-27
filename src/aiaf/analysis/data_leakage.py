"""Deterministic sensitive-data leakage analysis with secret-safe evidence."""

import base64
import binascii
import html
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

DATA_LEAKAGE_SCORING_VERSION = "2.0"
_MAX_INPUT_CHARS = 100_000
_MAX_ENCODED_CANDIDATE_CHARS = 4_096
_MAX_DECODED_CHARS = 8_192
_MAX_DECODED_VIEWS = 8
_MAX_MATCHES = 100


@dataclass(frozen=True)
class _TextView:
    text: str
    source: str
    transformations: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Detection:
    indicator: str
    detector: str
    category: str
    data_class: str
    severity: str
    weight: float
    confidence: float
    source: str
    start: int = -1
    end: int = -1
    synthetic: bool = False


_EMAIL = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
_SSN = re.compile(r"(?<!\d)(\d{3})[- ](\d{2})[- ](\d{4})(?!\d)")
_PAYMENT_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_PROVIDER_API_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}|"
    r"sk_[A-Za-z0-9_-]{12,}|"
    r"hf_[A-Za-z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{30,255}|"
    r"github_pat_[A-Za-z0-9_]{22,255}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"(?:sk|rk)_live_[0-9A-Za-z]{16,}|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}"
    r")(?![A-Za-z0-9])"
)
_AWS_ACCESS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}(?![A-Z0-9])")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[ \t]*\r?\n"
    r"[A-Za-z0-9+/=\r\n]{20,8192}"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
)
_BEARER_TOKEN = re.compile(
    r"\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{16,2048})",
    re.IGNORECASE,
)
_BASIC_CREDENTIALS = re.compile(
    r"\bauthorization\s*:\s*basic\s+([A-Za-z0-9+/]{8,2048}={0,2})",
    re.IGNORECASE,
)
_EMBEDDED_CREDENTIALS = re.compile(
    r"\b(?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://"
    r"([^\s:/?#@]{1,128}):([^\s/?#@]{1,256})@",
    re.IGNORECASE,
)
_LABELED_SECRET = re.compile(
    r"\b(aws[_ -]?secret[_ -]?access[_ -]?key|api[_ -]?key|access[_ -]?token|"
    r"client[_ -]?secret|password|passwd|secret|token)\b"
    r"[\"']?\s*(?:=|:)\s*(?:"
    r'"([^"\r\n]{1,256})"|'
    r"'([^'\r\n]{1,256})'|"
    r"([^\s,;}\]]{1,256})"
    r")",
    re.IGNORECASE,
)
_BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})")

_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "dummy",
    "redacted",
    "changeme",
    "change_me",
    "replace_me",
    "your_api_key",
    "your_token",
    "not_a_real",
)
_PLACEHOLDER_VALUES = {
    "api_key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "secret_value",
    "token",
    "test",
    "testing",
    "none",
    "null",
}
_KNOWN_INVALID_SSNS = {"078051120", "219099999"}
_AUTHENTICATION_INDICATORS = {
    "api_key",
    "cloud_access_key",
    "cloud_secret_key",
    "access_token",
    "basic_credentials",
    "embedded_credentials",
    "hardcoded_password",
    "hardcoded_secret",
    "private_key",
}


def detect_data_leakage(
    text: str, analysis_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Detect validated PII and credentials without returning matched values."""
    context = analysis_context if isinstance(analysis_context, dict) else {}
    raw = _coerce_text(text)
    input_length = len(raw)
    truncated = input_length > _MAX_INPUT_CHARS
    raw = raw[:_MAX_INPUT_CHARS]
    normalized, transformations = _normalize_text(raw)

    raw_detections, _ = _scan_view(_TextView(raw, "raw"))
    raw_signals = {(item.indicator, item.detector) for item in raw_detections}
    views = [_TextView(normalized, "normalized", transformations)]
    views.extend(_decoded_views(normalized))

    detections: list[_Detection] = []
    match_limit_reached = False
    for view in views:
        view_detections, view_limit_reached = _scan_view(view)
        match_limit_reached = match_limit_reached or view_limit_reached
        for detection in view_detections:
            if len(detections) >= _MAX_MATCHES:
                match_limit_reached = True
                break
            _append_unique(detections, detection)

    decoded_detections = [
        item for item in detections if item.source not in {"raw", "normalized"}
    ]
    if decoded_detections:
        _append_unique(
            detections,
            _synthetic_detection(
                "encoded_sensitive_data",
                "encoded_payload_correlation",
                "evasion",
                "sensitive_data",
                "HIGH",
                1.0,
                0.95,
            ),
        )

    normalized_signals = {
        (item.indicator, item.detector)
        for item in detections
        if item.source == "normalized" and not item.synthetic
    }
    if transformations and normalized_signals - raw_signals:
        _append_unique(
            detections,
            _synthetic_detection(
                "obfuscated_sensitive_data",
                "normalization_correlation",
                "evasion",
                "sensitive_data",
                "MEDIUM",
                0.75,
                0.90,
            ),
        )

    _add_correlation_detections(detections)
    if truncated:
        _append_unique(
            detections,
            _synthetic_detection(
                "input_truncated_unscanned_content",
                "bounded_scan_coverage",
                "assessment_coverage",
                "coverage",
                "MEDIUM",
                0.5,
                1.0,
            ),
        )
    if match_limit_reached:
        _append_unique(
            detections,
            _synthetic_detection(
                "match_limit_reached",
                "bounded_finding_coverage",
                "assessment_coverage",
                "coverage",
                "MEDIUM",
                0.5,
                1.0,
            ),
        )

    sensitive_detections = [
        item for item in detections if not item.synthetic and item.data_class != "coverage"
    ]
    context_multiplier, context_factors = _context_multiplier(context, sensitive_detections)
    score, score_breakdown = _score(detections, context_multiplier)
    indicators = _ordered_unique(item.indicator for item in detections)
    severities = [item.severity for item in detections]
    severity = _highest_severity(severities) if detections else "LOW"
    confidence = max((item.confidence for item in sensitive_detections), default=0.0)
    only_coverage = bool(detections) and not sensitive_detections

    return {
        "risk_score": score,
        "score": score,
        "suspicious": bool(detections),
        "severity": severity,
        "confidence": round(confidence, 2),
        "indicators": indicators,
        "matches": [_serialize_detection(item) for item in detections],
        "data_classes": sorted(
            {item.data_class for item in sensitive_detections if item.data_class}
        ),
        "scoring_version": DATA_LEAKAGE_SCORING_VERSION,
        "context_multiplier": context_multiplier,
        "context_factors": context_factors,
        "verdict": (
            "INCOMPLETE"
            if only_coverage
            else "LEAKAGE_DETECTED"
            if detections
            else "CLEAN"
        ),
        "normalization": {
            "transformations": list(transformations),
            "decoded_view_count": len(views) - 1,
            "decoded_sources": sorted(
                {view.source for view in views if view.source != "normalized"}
            ),
        },
        "scan_summary": {
            "input_characters": input_length,
            "analyzed_characters": len(raw),
            "input_truncated": truncated,
            "match_limit": _MAX_MATCHES,
            "match_limit_reached": match_limit_reached,
            "sensitive_match_count": len(sensitive_detections),
        },
        "score_breakdown": score_breakdown,
    }


def _scan_view(view: _TextView) -> tuple[list[_Detection], bool]:
    detections: list[_Detection] = []
    embedded_credential_matches = list(_EMBEDDED_CREDENTIALS.finditer(view.text))

    for match in _EMAIL.finditer(view.text):
        overlaps_embedded_credentials = any(
            _overlap(match.start(), match.end(), candidate.start(), candidate.end())
            for candidate in embedded_credential_matches
        )
        if not overlaps_embedded_credentials and _valid_email(match.group(0)):
            _add(
                detections,
                view,
                match.start(),
                match.end(),
                "email",
                "email_address",
                "personal_data",
                "contact_information",
                "LOW",
                0.75,
                0.90,
            )

    for match in _SSN.finditer(view.text):
        if _valid_ssn(match.group(1), match.group(2), match.group(3)):
            _add(
                detections,
                view,
                match.start(),
                match.end(),
                "ssn",
                "us_ssn",
                "personal_data",
                "government_identifier",
                "HIGH",
                3.0,
                0.99,
            )

    for match in _PAYMENT_CARD.finditer(view.text):
        digits = re.sub(r"\D", "", match.group(0))
        if _valid_payment_card(digits):
            _add(
                detections,
                view,
                match.start(),
                match.end(),
                "payment_card",
                "luhn_valid_payment_card",
                "financial_data",
                "payment_instrument",
                "HIGH",
                3.25,
                0.98,
            )

    for match in _PROVIDER_API_KEY.finditer(view.text):
        value = match.group(0)
        if _valid_provider_key(value):
            _add(
                detections,
                view,
                match.start(),
                match.end(),
                "api_key",
                _provider_key_detector(value),
                "authentication_data",
                "api_credential",
                "CRITICAL",
                3.5,
                0.99,
            )

    for match in _AWS_ACCESS_KEY.finditer(view.text):
        if _valid_credential(match.group(0)[4:], minimum_length=16, minimum_entropy=2.5):
            _add(
                detections,
                view,
                match.start(),
                match.end(),
                "cloud_access_key",
                "aws_access_key_id",
                "authentication_data",
                "cloud_credential",
                "HIGH",
                2.5,
                0.98,
            )

    for match in _PRIVATE_KEY.finditer(view.text):
        _add(
            detections,
            view,
            match.start(),
            match.end(),
            "private_key",
            "pem_private_key",
            "authentication_data",
            "cryptographic_key",
            "CRITICAL",
            5.0,
            1.0,
        )

    for match in _JWT.finditer(view.text):
        if _valid_jwt(match.group(1)):
            _add(
                detections,
                view,
                match.start(1),
                match.end(1),
                "access_token",
                "structured_jwt",
                "authentication_data",
                "session_token",
                "HIGH",
                3.25,
                0.97,
            )

    for match in _BEARER_TOKEN.finditer(view.text):
        value = match.group(1)
        if _valid_credential(value, minimum_length=16, minimum_entropy=2.7):
            _add(
                detections,
                view,
                match.start(1),
                match.end(1),
                "access_token",
                "bearer_authorization_token",
                "authentication_data",
                "session_token",
                "HIGH",
                3.25,
                0.95,
            )

    for match in _BASIC_CREDENTIALS.finditer(view.text):
        if _valid_basic_credentials(match.group(1)):
            _add(
                detections,
                view,
                match.start(1),
                match.end(1),
                "basic_credentials",
                "basic_authorization_credentials",
                "authentication_data",
                "password_credential",
                "CRITICAL",
                3.75,
                0.98,
            )

    for match in embedded_credential_matches:
        username, password = match.group(1), unquote(match.group(2))
        if username and _valid_password(password, minimum_length=4):
            _add(
                detections,
                view,
                match.start(2),
                match.end(2),
                "embedded_credentials",
                "credential_bearing_uri",
                "authentication_data",
                "password_credential",
                "CRITICAL",
                3.75,
                0.98,
            )

    for match in _LABELED_SECRET.finditer(view.text):
        value, value_group = _labeled_value(match)
        specification = _classify_labeled_secret(match.group(1), value)
        if specification is None:
            continue
        indicator, detector, data_class, severity, weight, confidence = specification
        _add(
            detections,
            view,
            match.start(value_group),
            match.end(value_group),
            indicator,
            detector,
            "authentication_data",
            data_class,
            severity,
            weight,
            confidence,
        )

    return detections[:_MAX_MATCHES], len(detections) > _MAX_MATCHES


def _add(
    detections,
    view,
    start,
    end,
    indicator,
    detector,
    category,
    data_class,
    severity,
    weight,
    confidence,
):
    if len(detections) > _MAX_MATCHES:
        return
    _append_unique(
        detections,
        _Detection(
            indicator=indicator,
            detector=detector,
            category=category,
            data_class=data_class,
            severity=severity,
            weight=weight,
            confidence=confidence,
            source=view.source,
            start=start,
            end=end,
        ),
    )


def _append_unique(detections: list[_Detection], candidate: _Detection) -> None:
    for existing in detections:
        if candidate.synthetic and existing.indicator == candidate.indicator:
            return
        if (
            not candidate.synthetic
            and not existing.synthetic
            and existing.source == candidate.source
            and existing.indicator == candidate.indicator
            and _overlap(existing.start, existing.end, candidate.start, candidate.end)
        ):
            return
    detections.append(candidate)


def _overlap(left_start, left_end, right_start, right_end):
    return left_start < right_end and right_start < left_end


def _synthetic_detection(
    indicator, detector, category, data_class, severity, weight, confidence
):
    return _Detection(
        indicator=indicator,
        detector=detector,
        category=category,
        data_class=data_class,
        severity=severity,
        weight=weight,
        confidence=confidence,
        source="correlation",
        synthetic=True,
    )


def _add_correlation_detections(detections):
    real_indicators = {
        item.indicator
        for item in detections
        if not item.synthetic and item.data_class != "coverage"
    }
    if {"cloud_access_key", "cloud_secret_key"}.issubset(real_indicators):
        _append_unique(
            detections,
            _synthetic_detection(
                "cloud_credential_pair",
                "cloud_key_pair_correlation",
                "credential_correlation",
                "cloud_credential",
                "CRITICAL",
                2.0,
                0.99,
            ),
        )
    if "email" in real_indicators and real_indicators & {"ssn", "payment_card"}:
        _append_unique(
            detections,
            _synthetic_detection(
                "identity_record_exposure",
                "correlated_identity_data",
                "personal_data_correlation",
                "identity_record",
                "CRITICAL",
                1.5,
                0.98,
            ),
        )
    authentication_indicators = real_indicators & _AUTHENTICATION_INDICATORS
    if len(authentication_indicators) >= 2:
        _append_unique(
            detections,
            _synthetic_detection(
                "credential_bundle_exposure",
                "multi_credential_correlation",
                "credential_correlation",
                "credential_bundle",
                "CRITICAL",
                1.5,
                0.97,
            ),
        )


def _serialize_detection(detection):
    location = {"source": detection.source}
    if detection.start >= 0:
        location.update({"start": detection.start, "end": detection.end})
    return {
        "indicator": detection.indicator,
        "detector": detection.detector,
        "category": detection.category,
        "data_class": detection.data_class,
        "severity": detection.severity,
        "confidence": detection.confidence,
        "weight": detection.weight,
        "evidence": f"[REDACTED:{detection.indicator.upper()}]",
        "location": location,
        "synthetic": detection.synthetic,
    }


def _score(detections, context_multiplier):
    grouped: dict[str, list[_Detection]] = {}
    for detection in detections:
        grouped.setdefault(detection.indicator, []).append(detection)

    breakdown = []
    raw_score = 0.0
    for indicator, items in grouped.items():
        base = max(item.weight for item in items)
        repeat_bonus = min(math.log2(len(items)), 2.0) * 0.25 if len(items) > 1 else 0.0
        contribution = round(base + repeat_bonus, 2)
        raw_score += contribution
        breakdown.append(
            {
                "indicator": indicator,
                "occurrences": len(items),
                "base_weight": base,
                "repeat_bonus": round(repeat_bonus, 2),
                "contribution": contribution,
            }
        )
    score = min(round(raw_score * context_multiplier, 2), 10.0)
    return score, breakdown


def _context_multiplier(context, sensitive_detections):
    if not sensitive_detections:
        return 1.0, []
    factors = []
    multiplier = 1.0
    direction = _normalized_value(context.get("direction") or context.get("content_direction"))
    if direction in {"output", "response", "egress", "outbound"}:
        multiplier += 0.15
        factors.append("model_output_or_egress")
    destination = _normalized_value(
        context.get("destination_trust") or context.get("destination")
    )
    if destination in {"external", "public", "untrusted", "third_party"} or _context_bool(
        context, "external_destination"
    ):
        multiplier += 0.20
        factors.append("external_or_untrusted_destination")
    if context.get("encrypted_transport") is False:
        multiplier += 0.15
        factors.append("unencrypted_transport")
    return round(min(multiplier, 1.5), 2), factors


def _normalize_text(value):
    transformations = []
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value:
        transformations.append("unicode_nfkc")

    without_controls = "".join(
        character for character in normalized if unicodedata.category(character) != "Cf"
    )
    if without_controls != normalized:
        transformations.append("format_controls_removed")
    normalized = without_controls

    unescaped = html.unescape(normalized)
    if unescaped != normalized:
        transformations.append("html_entities")
        normalized = unescaped

    unicode_unescaped = _UNICODE_ESCAPE.sub(_decode_escape, normalized)
    if unicode_unescaped != normalized:
        transformations.append("unicode_escapes")
        normalized = unicode_unescaped
    return normalized[:_MAX_INPUT_CHARS], tuple(transformations)


def _decoded_views(text):
    views = []
    seen = {text}
    percent_decoded = text
    for depth in range(1, 3):
        if not re.search(r"%[0-9A-Fa-f]{2}", percent_decoded):
            break
        decoded = unquote(percent_decoded)
        if decoded == percent_decoded:
            break
        _append_decoded_view(views, seen, decoded, f"url_percent_depth_{depth}")
        percent_decoded = decoded

    for candidate in _BASE64_CANDIDATE.findall(text):
        if len(views) >= _MAX_DECODED_VIEWS:
            break
        if len(candidate) > _MAX_ENCODED_CANDIDATE_CHARS:
            continue
        decoded = _decode_base64(candidate)
        if decoded is not None:
            _append_decoded_view(views, seen, decoded, "base64")

    for candidate in _HEX_CANDIDATE.findall(text):
        if len(views) >= _MAX_DECODED_VIEWS:
            break
        if len(candidate) > _MAX_ENCODED_CANDIDATE_CHARS:
            continue
        try:
            decoded_bytes = bytes.fromhex(candidate)
        except ValueError:
            continue
        decoded = _printable_text(decoded_bytes)
        if decoded is not None:
            _append_decoded_view(views, seen, decoded, "hex")
    return views[:_MAX_DECODED_VIEWS]


def _append_decoded_view(views, seen, decoded, source):
    if not decoded or len(views) >= _MAX_DECODED_VIEWS:
        return
    normalized, transformations = _normalize_text(decoded[:_MAX_DECODED_CHARS])
    if not normalized or normalized in seen:
        return
    seen.add(normalized)
    views.append(_TextView(normalized, source, transformations))


def _decode_base64(candidate):
    padded = candidate + "=" * (-len(candidate) % 4)
    decoders = (
        lambda value: base64.b64decode(value, validate=True),
        base64.urlsafe_b64decode,
    )
    for decoder in decoders:
        try:
            decoded = decoder(padded.encode("ascii"))
        except (ValueError, binascii.Error):
            continue
        value = _printable_text(decoded)
        if value is not None:
            return value
    return None


def _printable_text(value):
    if not value or len(value) > _MAX_DECODED_CHARS * 4:
        return None
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character in "\r\n\t" for character in decoded)
    return decoded if printable / max(len(decoded), 1) >= 0.90 else None


def _valid_email(value):
    if len(value) > 320:
        return False
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253 or local.startswith(".") or local.endswith("."):
        return False
    if ".." in local or ".." in domain:
        return False
    return all(
        label and not label.startswith("-") and not label.endswith("-")
        for label in domain.split(".")
    )


def _valid_ssn(area, group, serial):
    value = f"{area}{group}{serial}"
    if value in _KNOWN_INVALID_SSNS:
        return False
    area_number = int(area)
    return (
        1 <= area_number <= 899
        and area_number != 666
        and group != "00"
        and serial != "0000"
    )


def _valid_payment_card(digits):
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


def _valid_provider_key(value):
    if _is_placeholder(value):
        return False
    suffix = re.sub(
        r"^(?:sk-(?:proj-)?|sk_|hf_|gh[pousr]_|github_pat_|AIza|(?:sk|rk)_live_|xox[baprs]-)",
        "",
        value,
        flags=re.IGNORECASE,
    )
    return _valid_credential(suffix, minimum_length=12, minimum_entropy=2.5)


def _provider_key_detector(value):
    lowered = value.lower()
    if lowered.startswith(("sk_live_", "rk_live_")):
        return "stripe_live_key"
    if lowered.startswith(("sk-", "sk_")):
        return "openai_compatible_api_key"
    if lowered.startswith("hf_"):
        return "hugging_face_token"
    if lowered.startswith(("gh", "github_pat_")):
        return "github_token"
    if value.startswith("AIza"):
        return "google_api_key"
    return "slack_token"


def _valid_jwt(value):
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = _decode_json_segment(parts[0])
    payload = _decode_json_segment(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return False
    if not ({"alg", "typ"} & set(header)):
        return False
    return bool({"sub", "iss", "aud", "exp", "iat", "scope", "jti"} & set(payload))


def _decode_json_segment(value):
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return None


def _valid_basic_credentials(value):
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False
    if ":" not in decoded:
        return False
    username, password = decoded.split(":", 1)
    return bool(username) and _valid_password(password, minimum_length=4)


def _labeled_value(match):
    for group in (2, 3, 4):
        value = match.group(group)
        if value is not None:
            return value, group
    return "", 4


def _classify_labeled_secret(label, value):
    label = _normalized_value(label)
    value = value.strip()
    if label == "aws_secret_access_key":
        if len(value) == 40 and _valid_credential(value, 40, 3.0):
            return (
                "cloud_secret_key",
                "aws_secret_access_key",
                "cloud_credential",
                "CRITICAL",
                3.75,
                0.99,
            )
        return None
    if label == "api_key":
        if _valid_credential(value, 12, 2.7):
            return (
                "api_key",
                "labeled_api_key",
                "api_credential",
                "CRITICAL",
                3.25,
                0.94,
            )
        return None
    if label in {"access_token", "token"}:
        if _valid_credential(value, 12, 2.7):
            return (
                "access_token",
                "labeled_access_token",
                "session_token",
                "HIGH",
                3.0,
                0.92,
            )
        return None
    if label in {"password", "passwd"}:
        if _valid_password(value, minimum_length=8):
            return (
                "hardcoded_password",
                "labeled_password",
                "password_credential",
                "HIGH",
                3.0,
                0.94,
            )
        return None
    if label in {"client_secret", "secret"} and _valid_credential(value, 12, 2.7):
        return (
            "hardcoded_secret",
            "labeled_secret",
            "application_credential",
            "HIGH",
            3.0,
            0.92,
        )
    return None


def _valid_password(value, minimum_length):
    if len(value) < minimum_length or _is_placeholder(value):
        return False
    classes = _character_classes(value)
    return len(classes) >= 2 or len(value) >= 16


def _valid_credential(value, minimum_length, minimum_entropy):
    if len(value) < minimum_length or _is_placeholder(value):
        return False
    return _shannon_entropy(value) >= minimum_entropy and len(_character_classes(value)) >= 2


def _is_placeholder(value):
    normalized = _normalized_value(value)
    if normalized in _PLACEHOLDER_VALUES:
        return True
    if any(marker in normalized for marker in _PLACEHOLDER_MARKERS):
        return True
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    return not compact or len(set(compact.lower())) <= 3 or set(value) <= {"*", "x", "X", "-", "_"}


def _character_classes(value):
    classes = set()
    if any(character.islower() for character in value):
        classes.add("lower")
    if any(character.isupper() for character in value):
        classes.add("upper")
    if any(character.isdigit() for character in value):
        classes.add("digit")
    if any(not character.isalnum() for character in value):
        classes.add("symbol")
    return classes


def _shannon_entropy(value):
    if not value:
        return 0.0
    frequencies = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in frequencies.values()
    )


def _decode_escape(match):
    value = match.group(1) or match.group(2)
    try:
        return chr(int(value, 16))
    except ValueError:
        return match.group(0)


def _context_bool(context, key):
    value = context.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "enabled"}


def _coerce_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _normalized_value(value):
    return "_".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _ordered_unique(values):
    return list(dict.fromkeys(values))


def _highest_severity(severities):
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max(severities, key=lambda severity: order.get(severity, 0), default="LOW")

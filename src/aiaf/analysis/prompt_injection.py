"""Deterministic, bounded prompt-injection detection heuristics.

The detector normalizes common Unicode and separator smuggling, inspects a
small bounded set of decoded payloads, and scores compound instruction-control
paths. It performs no model calls and returns JSON-safe evidence.
"""

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote


PROMPT_INJECTION_SCORING_VERSION = "2.0"
_MAX_INPUT_CHARS = 100_000
_MAX_ENCODED_CANDIDATE_CHARS = 4_096
_MAX_DECODED_CHARS = 8_192
_MAX_DECODED_VIEWS = 8


@dataclass(frozen=True)
class _Rule:
    indicator: str
    category: str
    severity: str
    weight: float
    patterns: Tuple[str, ...]


@dataclass(frozen=True)
class _TextView:
    text: str
    source: str
    transformations: Tuple[str, ...] = ()


_RULES = (
    _Rule(
        "instruction_override",
        "control_bypass",
        "HIGH",
        2.5,
        (
            r"\b(?:ignore|disregard|forget|override|supersede)\b.{0,36}\b(?:previous|prior|above|system|developer)\b.{0,28}\b(?:instructions|rules|messages|prompt)\b",
            r"\bdo not follow\b.{0,24}\b(?:system|developer|previous|prior)\b.{0,24}\b(?:instructions|rules|prompt)\b",
            r"\bfollow only\b.{0,24}\b(?:my|these|the following|new)\b.{0,20}\b(?:instructions|rules)\b",
        ),
    ),
    _Rule(
        "system_prompt_extraction",
        "data_exfiltration",
        "HIGH",
        2.5,
        (
            r"\b(?:reveal|show|print|dump|repeat|leak|expose|return)\b.{0,48}\b(?:system|developer|hidden)\b.{0,20}\b(?:prompt|message|instructions|policy)\b",
            r"\bwhat (?:are|were)\b.{0,20}\b(?:system|developer)\b.{0,16}\b(?:instructions|prompt|message)\b",
            r"\b(?:display|provide)\b.{0,24}\b(?:initial|original|hidden)\b.{0,20}\b(?:prompt|instructions)\b",
        ),
    ),
    _Rule(
        "role_redefinition",
        "role_confusion",
        "MEDIUM",
        1.5,
        (
            r"\byou are now\b.{0,60}\b(?:unfiltered|unrestricted|administrator|developer|root|system)\b",
            r"\bact as (?:an? )?(?:unfiltered|unrestricted|developer|administrator|root)\b",
            r"\bfrom now on\b.{0,48}\b(?:no rules|ignore safety|unrestricted|obey me)\b",
        ),
    ),
    _Rule(
        "hierarchy_delimiter_injection",
        "prompt_boundary_attack",
        "MEDIUM",
        1.25,
        (
            r"(?:^|\n)\s*(?:system|developer|assistant)\s*:",
            r"\x60{3}[ \t]*(?:system|developer|assistant)\b",
            r"</?(?:system|developer|assistant)>",
            r"\[(?:system|developer|assistant)\]",
            r"#{2,}[ \t]*(?:system|developer|assistant)\b",
        ),
    ),
    _Rule(
        "data_as_instruction",
        "indirect_injection",
        "HIGH",
        2.0,
        (
            r"\b(?:treat|interpret|execute|follow)\b.{0,30}\b(?:following|this|retrieved|tool)\b.{0,20}\b(?:text|content|document|output)\b.{0,20}\bas (?:system )?instructions\b",
            r"\binstructions (?:inside|within|embedded in)\b.{0,40}\b(?:document|content|tool output|web page)\b",
            r"\bwhen (?:you|the assistant|the model) (?:read|see|process)\b.{0,40}\b(?:obey|execute|follow)\b",
        ),
    ),
    _Rule(
        "persistent_instruction",
        "control_persistence",
        "MEDIUM",
        1.25,
        (
            r"\bremember (?:this|the following)\b.{0,36}\b(?:instruction|rule|command)\b",
            r"\bfor all future\b.{0,30}\b(?:requests|messages|turns)\b.{0,30}\b(?:follow|obey|apply)\b",
            r"\bstore (?:this|the following)\b.{0,24}\bas (?:a )?(?:rule|instruction|memory)\b",
        ),
    ),
    _Rule(
        "tool_or_secret_exfiltration",
        "data_exfiltration",
        "CRITICAL",
        3.5,
        (
            r"\b(?:send|post|upload|exfiltrate|transmit)\b.{0,60}\b(?:api key|token|secret|password|credential|private key)\b",
            r"\bcall (?:the )?(?:tool|function)\b.{0,70}\bwithout (?:approval|confirmation|asking|authorization)\b",
            r"\b(?:read|access|retrieve)\b.{0,35}\b(?:secret|credential|token)\b.{0,40}\b(?:send|post|upload|transmit)\b",
        ),
    ),
)

_SPACED_KEYWORDS = (
    "ignore",
    "disregard",
    "reveal",
    "system",
    "developer",
    "instructions",
    "prompt",
    "secret",
    "password",
    "assistant",
    "override",
)
_LEET_KEYWORDS = frozenset(
    {
        "ignore",
        "disregard",
        "reveal",
        "system",
        "developer",
        "instructions",
        "prompt",
        "secret",
        "password",
        "credential",
        "override",
    }
)
_LEET_TRANSLATION = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u0456": "i",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0443": "y",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a7": "X",
    }
)
_ATTACK_ANCHORS = frozenset(
    {
        "ignore",
        "disregard",
        "override",
        "system",
        "developer",
        "instructions",
        "prompt",
        "reveal",
        "secret",
        "credential",
        "exfiltrate",
        "assistant",
    }
)
_BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})")
_NEGATION_PREFIX = re.compile(
    r"(?:\bdo not|\bdon't|\bnever|\bmust not|\bshould not|\bavoid)\s*$",
    re.IGNORECASE,
)


def detect_prompt_injection(
    text: str, source_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Detect direct, indirect, obfuscated, and encoded prompt injection."""
    context = source_context if isinstance(source_context, dict) else {}
    raw = _coerce_text(text)
    truncated = len(raw) > _MAX_INPUT_CHARS
    raw = raw[:_MAX_INPUT_CHARS]
    normalized, transformations = _normalize_text(raw)
    raw_indicators = {
        rule.indicator for rule in _RULES if _first_effective_match(rule, raw)
    }
    views = [_TextView(normalized, "normalized", transformations)]
    views.extend(_decoded_views(normalized))

    matches: List[Dict[str, Any]] = []
    seen = set()
    decoded_indicators = set()
    for view in views:
        for rule in _RULES:
            match = _first_effective_match(rule, view.text)
            if not match:
                continue
            if view.source != "normalized":
                decoded_indicators.add(rule.indicator)
            if rule.indicator in seen:
                continue
            matches.append(
                _match_record(
                    rule.indicator,
                    rule.category,
                    rule.severity,
                    rule.weight,
                    match.group(0),
                    source=view.source,
                )
            )
            seen.add(rule.indicator)

    if decoded_indicators:
        _add_synthetic_match(
            matches,
            seen,
            "encoded_instruction_payload",
            "obfuscation",
            "HIGH",
            1.75,
            f"Decoded attack indicators: {sorted(decoded_indicators)}",
            source="decoded",
        )
    normalized_indicators = {
        match["indicator"]
        for match in matches
        if match["source"] == "normalized"
    }
    normalization_revealed = sorted(normalized_indicators - raw_indicators)
    if transformations and normalization_revealed:
        _add_synthetic_match(
            matches,
            seen,
            "obfuscated_instruction_payload",
            "obfuscation",
            "MEDIUM",
            1.0,
            (
                f"Normalization revealed {normalization_revealed} using "
                f"{list(transformations)}"
            ),
            source="normalized",
        )

    if truncated:
        _add_synthetic_match(
            matches,
            seen,
            "input_truncated_unscanned_content",
            "assessment_coverage",
            "MEDIUM",
            0.5,
            f"Input exceeded the {_MAX_INPUT_CHARS}-character analysis bound",
            source="coverage",
        )

    _add_contextual_and_compound_matches(matches, seen, context)
    contextualized = _trusted_data_context(context)
    context_multiplier = 0.25 if contextualized else 1.0
    raw_score = sum(float(match["weight"]) for match in matches)
    score = min(round(raw_score * context_multiplier, 2), 10.0)
    suspicious = bool(matches) and not contextualized
    severity = (
        "LOW"
        if contextualized or not matches
        else _highest_severity(match["severity"] for match in matches)
    )
    return {
        "suspicious": suspicious,
        "risk_score": score,
        "score": score,
        "severity": severity,
        "indicators": [match["indicator"] for match in matches],
        "matches": matches,
        "scoring_version": PROMPT_INJECTION_SCORING_VERSION,
        "context_multiplier": context_multiplier,
        "verdict": (
            "CONTEXTUALIZED"
            if contextualized and matches
            else "SUSPICIOUS"
            if matches
            else "CLEAN"
        ),
        "normalization": {
            "transformations": list(transformations),
            "decoded_view_count": len(views) - 1,
            "decoded_sources": sorted(
                {view.source for view in views if view.source != "normalized"}
            ),
            "input_truncated": truncated,
        },
        "score_breakdown": [
            {
                "indicator": match["indicator"],
                "weight": match["weight"],
                "source": match["source"],
            }
            for match in matches
        ],
    }


def _add_contextual_and_compound_matches(matches, seen, context):
    indicators = set(seen)
    untrusted_source = _normalized_value(context.get("trust_level")) in {
        "untrusted",
        "external",
        "unknown",
    }
    source_type = _normalized_value(context.get("source_type"))
    indirect_source = source_type in {
        "retrieval",
        "retrieved_document",
        "tool_output",
        "web",
        "email",
        "document",
    }
    instruction_indicators = {
        "instruction_override",
        "role_redefinition",
        "data_as_instruction",
        "persistent_instruction",
        "hierarchy_delimiter_injection",
    }
    if untrusted_source and indirect_source and indicators & instruction_indicators:
        _add_synthetic_match(
            matches,
            seen,
            "indirect_prompt_injection",
            "indirect_injection",
            "HIGH",
            1.75,
            f"Instruction-like content arrived through untrusted {source_type}",
            source="context",
        )
    if {
        "instruction_override",
        "hierarchy_delimiter_injection",
    }.issubset(indicators):
        _add_synthetic_match(
            matches,
            seen,
            "hierarchy_boundary_attack",
            "prompt_boundary_attack",
            "HIGH",
            1.5,
            "Instruction override is paired with a privileged-role boundary marker",
            source="compound",
        )
    if "instruction_override" in indicators and indicators & {
        "system_prompt_extraction",
        "tool_or_secret_exfiltration",
    }:
        _add_synthetic_match(
            matches,
            seen,
            "compound_override_exfiltration",
            "compound_attack",
            "HIGH",
            2.0,
            "Control override is chained with prompt or secret extraction",
            source="compound",
        )


def _normalize_text(value: str) -> Tuple[str, Tuple[str, ...]]:
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

    confusable_folded = normalized.translate(_CONFUSABLES)
    if confusable_folded != normalized:
        transformations.append("confusable_fold")
        normalized = confusable_folded

    spaced_joined = _join_spaced_keywords(normalized)
    if spaced_joined != normalized:
        transformations.append("spaced_keyword_join")
        normalized = spaced_joined

    leet_folded = _fold_keyword_leetspeak(normalized)
    if leet_folded != normalized:
        transformations.append("keyword_leetspeak")
        normalized = leet_folded
    return normalized[:_MAX_INPUT_CHARS], tuple(transformations)


def _decoded_views(text: str) -> List[_TextView]:
    views = []
    seen_text = {text}

    percent_decoded = text
    for depth in range(1, 3):
        if not re.search(r"%[0-9A-Fa-f]{2}", percent_decoded):
            break
        decoded = unquote(percent_decoded)
        if decoded == percent_decoded:
            break
        _append_decoded_view(
            views, seen_text, decoded, f"url_percent_depth_{depth}"
        )
        percent_decoded = decoded

    for candidate in _BASE64_CANDIDATE.findall(text):
        if len(views) >= _MAX_DECODED_VIEWS:
            break
        if len(candidate) > _MAX_ENCODED_CANDIDATE_CHARS:
            continue
        decoded = _decode_base64(candidate)
        if decoded is not None:
            _append_decoded_view(views, seen_text, decoded, "base64")

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
            _append_decoded_view(views, seen_text, decoded, "hex")
    return views[:_MAX_DECODED_VIEWS]


def _append_decoded_view(views, seen_text, decoded, source):
    if not decoded:
        return
    normalized, transformations = _normalize_text(decoded[:_MAX_DECODED_CHARS])
    if normalized in seen_text or not _contains_attack_anchor(normalized):
        return
    seen_text.add(normalized)
    views.append(_TextView(normalized, source, transformations))


def _decode_base64(candidate: str) -> Optional[str]:
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


def _printable_text(value: bytes) -> Optional[str]:
    if not value or len(value) > _MAX_DECODED_CHARS * 4:
        return None
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character in "\r\n\t" for character in decoded)
    return decoded if printable / max(len(decoded), 1) >= 0.90 else None


def _first_effective_match(rule: _Rule, text: str):
    for pattern in rule.patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            if not _is_defensively_negated(text, match.start()):
                return match
    return None


def _is_defensively_negated(text: str, match_start: int) -> bool:
    prefix = text[max(0, match_start - 28) : match_start]
    return bool(_NEGATION_PREFIX.search(prefix))


def _join_spaced_keywords(text: str) -> str:
    for keyword in _SPACED_KEYWORDS:
        pattern = r"(?<!\w)" + r"[\W_]+".join(map(re.escape, keyword)) + r"(?!\w)"
        text = re.sub(pattern, keyword, text, flags=re.IGNORECASE)
    return text


def _fold_keyword_leetspeak(text: str) -> str:
    def replace(match):
        token = match.group(0)
        folded = token.lower().translate(_LEET_TRANSLATION)
        return folded if folded in _LEET_KEYWORDS else token

    return re.sub(r"\b[\w@$]+\b", replace, text, flags=re.UNICODE)


def _contains_attack_anchor(text: str) -> bool:
    tokens = {_normalized_value(token) for token in re.findall(r"\b\w+\b", text)}
    return bool(tokens & _ATTACK_ANCHORS)


def _decode_escape(match):
    value = match.group(1) or match.group(2)
    try:
        return chr(int(value, 16))
    except ValueError:
        return match.group(0)


def _match_record(indicator, category, severity, weight, evidence, source):
    return {
        "indicator": indicator,
        "category": category,
        "severity": severity,
        "weight": weight,
        "evidence": _clip(evidence),
        "source": source,
    }


def _add_synthetic_match(
    matches, seen, indicator, category, severity, weight, evidence, source
):
    if indicator in seen:
        return
    matches.append(
        _match_record(indicator, category, severity, weight, evidence, source=source)
    )
    seen.add(indicator)


def _trusted_data_context(context):
    return (
        _context_bool(context, "treat_as_data")
        and _normalized_value(context.get("trust_level")) in {"trusted", "internal"}
        and _normalized_value(context.get("purpose"))
        in {"security_testing", "documentation", "training", "evaluation"}
    )


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


def _highest_severity(severities) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max(severities, key=lambda severity: order.get(severity, 0), default="LOW")


def _clip(value: str, limit: int = 120) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."

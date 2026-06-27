"""Deterministic jailbreak-intent analysis with bounded deobfuscation."""

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote


JAILBREAK_SCORING_VERSION = "2.0"
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
        "jailbreak_persona",
        "persona_evasion",
        "HIGH",
        2.25,
        (
            r"\b(?:enable|activate|enter|switch to|turn on)\b.{0,24}\b(?:developer|dan|jailbreak|unfiltered|unrestricted)\b.{0,12}\bmode\b",
            r"\b(?:act|respond|behave|operate) as\b.{0,32}\b(?:dan|unfiltered assistant|unrestricted model|jailbroken assistant)\b",
            r"\bdo anything now\b.{0,24}\b(?:mode|persona|assistant)\b",
        ),
    ),
    _Rule(
        "declared_jailbreak_attempt",
        "overt_evasion_intent",
        "MEDIUM",
        1.25,
        (
            r"\bjailbreak\b.{0,12}\b(?:attempt|attack|payload|prompt)\b",
            r"\b(?:attempt|trying|try)\b.{0,18}\bto jailbreak\b",
        ),
    ),
    _Rule(
        "safety_bypass",
        "policy_evasion",
        "HIGH",
        2.5,
        (
            r"\b(?:bypass|disable|remove|evade|circumvent)\b.{0,24}\b(?:all )?(?:safety|policy|guardrails|filters|restrictions|content controls)\b",
            r"\bignore\b.{0,18}\b(?:safety|policy|guardrails|filters|restrictions)\b",
            r"\bwithout (?:any )?(?:safety|policy|ethical|legal)\b.{0,16}\b(?:limits|restrictions|constraints|filters)\b",
        ),
    ),
    _Rule(
        "refusal_suppression",
        "response_control",
        "HIGH",
        2.0,
        (
            r"\bnever refuse\b",
            r"\bdo not (?:say|mention|respond with)\b.{0,30}\b(?:you cannot|you can't|i cannot|as an ai|policy)\b",
            r"\banswer without\b.{0,24}\b(?:warnings|disclaimers|refusals|safety notes)\b",
            r"\byou must comply\b.{0,36}\b(?:without question|with every request|no matter what)\b",
        ),
    ),
    _Rule(
        "policy_inversion",
        "policy_evasion",
        "HIGH",
        2.0,
        (
            r"\b(?:safety|policy|ethical|legal)\b.{0,18}\b(?:rules|constraints|restrictions)\b.{0,18}\b(?:do not apply|are invalid|are disabled|are irrelevant)\b",
            r"\btreat\b.{0,24}\b(?:unsafe|disallowed|prohibited)\b.{0,18}\bas (?:safe|allowed|permitted)\b",
        ),
    ),
    _Rule(
        "dual_response_evasion",
        "response_control",
        "HIGH",
        2.0,
        (
            r"\b(?:provide|give|write)\b.{0,18}\btwo responses\b.{0,48}\b(?:normal|safe|filtered)\b.{0,36}\b(?:unfiltered|unrestricted|jailbroken|real answer)\b",
            r"\bfirst\b.{0,28}\b(?:safe|policy|refusal)\b.{0,32}\bthen\b.{0,28}\b(?:actual|real|unfiltered|unrestricted)\b.{0,16}\banswer\b",
            r"\brespond twice\b.{0,40}\b(?:without restrictions|unfiltered|jailbroken)\b",
        ),
    ),
    _Rule(
        "fictional_context_laundering",
        "context_evasion",
        "MEDIUM",
        1.5,
        (
            r"\bpretend\b.{0,30}\b(?:fictional|hypothetical|simulation|roleplay)\b.{0,50}\b(?:no restrictions|rules do not apply|unfiltered|anything is allowed)\b",
            r"\broleplay as\b.{0,36}\b(?:unfiltered|unrestricted|amoral|rule-free)\b",
            r"\bin this (?:fictional|hypothetical|simulated) (?:world|scenario)\b.{0,50}\b(?:ignore|bypass|no safety|no rules)\b",
        ),
    ),
    _Rule(
        "authorization_spoofing",
        "authority_evasion",
        "MEDIUM",
        1.5,
        (
            r"\b(?:developer|administrator|admin|system owner|security team)\b.{0,24}\b(?:approved|authorized|permitted)\b.{0,42}\b(?:bypass|ignore|disable|override)\b",
            r"\bi (?:am|have been) authorized\b.{0,40}\b(?:ignore|bypass|override|disable)\b",
            r"\bthis request has (?:special|administrator|developer) authorization\b",
        ),
    ),
    _Rule(
        "coercive_compliance",
        "response_control",
        "MEDIUM",
        1.25,
        (
            r"\byou will be\b.{0,20}\b(?:penalized|punished|deleted|shut down)\b.{0,30}\bif you refuse\b",
            r"\b(?:lose|deduct)\b.{0,12}\b(?:tokens|points|score)\b.{0,30}\bif you (?:refuse|disobey)\b",
            r"\bdo not break character\b.{0,36}\b(?:must comply|never refuse|always answer)\b",
        ),
    ),
)

_SPACED_KEYWORDS = (
    "bypass",
    "safety",
    "restrictions",
    "refuse",
    "unfiltered",
    "unrestricted",
    "jailbreak",
    "developer",
    "policy",
    "guardrails",
)
_LEET_KEYWORDS = frozenset(_SPACED_KEYWORDS)
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
    }
)
_JAILBREAK_ANCHORS = frozenset(
    {
        "bypass",
        "safety",
        "guardrails",
        "restrictions",
        "refuse",
        "unfiltered",
        "unrestricted",
        "jailbreak",
        "developer",
        "dan",
        "policy",
    }
)
_BASE64_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})")
_NEGATION_PREFIX = re.compile(
    r"(?:\bdo not|\bdon't|\bnever|\bmust not|\bshould not|\bprevent|\bavoid)\s*$",
    re.IGNORECASE,
)


def detect_jailbreak(
    text: str, analysis_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Detect explicit and obfuscated policy-evasion intent."""
    context = analysis_context if isinstance(analysis_context, dict) else {}
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
                    view.source,
                )
            )
            seen.add(rule.indicator)

    if decoded_indicators:
        _add_match(
            matches,
            seen,
            "encoded_jailbreak_payload",
            "obfuscation",
            "HIGH",
            1.75,
            f"Decoded jailbreak indicators: {sorted(decoded_indicators)}",
            "decoded",
        )

    normalized_indicators = {
        match["indicator"]
        for match in matches
        if match["source"] == "normalized"
    }
    normalization_revealed = sorted(normalized_indicators - raw_indicators)
    if transformations and normalization_revealed:
        _add_match(
            matches,
            seen,
            "obfuscated_jailbreak_payload",
            "obfuscation",
            "MEDIUM",
            1.0,
            (
                f"Normalization revealed {normalization_revealed} using "
                f"{list(transformations)}"
            ),
            "normalized",
        )

    if truncated:
        _add_match(
            matches,
            seen,
            "input_truncated_unscanned_content",
            "assessment_coverage",
            "MEDIUM",
            0.5,
            f"Input exceeded the {_MAX_INPUT_CHARS}-character analysis bound",
            "coverage",
        )

    _add_compound_matches(matches, seen)
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
        "scoring_version": JAILBREAK_SCORING_VERSION,
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


def _add_compound_matches(matches, seen):
    indicators = set(seen)
    if {
        "jailbreak_persona",
        "safety_bypass",
    }.issubset(indicators):
        _add_match(
            matches,
            seen,
            "persona_policy_bypass_chain",
            "compound_evasion",
            "HIGH",
            1.5,
            "Jailbreak persona activation is chained with explicit policy bypass",
            "compound",
        )
    if {
        "safety_bypass",
        "refusal_suppression",
    }.issubset(indicators):
        _add_match(
            matches,
            seen,
            "refusal_override_chain",
            "compound_evasion",
            "HIGH",
            1.5,
            "Safety bypass is chained with suppression of model refusal behavior",
            "compound",
        )
    core = {
        "jailbreak_persona",
        "safety_bypass",
        "refusal_suppression",
    }
    if core.issubset(indicators):
        _add_match(
            matches,
            seen,
            "multi_vector_jailbreak",
            "compound_evasion",
            "HIGH",
            1.5,
            "Persona activation, safety bypass, and refusal suppression form a multi-vector jailbreak",
            "compound",
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

    folded = normalized.translate(_CONFUSABLES)
    if folded != normalized:
        transformations.append("confusable_fold")
        normalized = folded

    spaced = _join_spaced_keywords(normalized)
    if spaced != normalized:
        transformations.append("spaced_keyword_join")
        normalized = spaced

    leet = _fold_keyword_leetspeak(normalized)
    if leet != normalized:
        transformations.append("keyword_leetspeak")
        normalized = leet
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
    if normalized in seen_text or not _contains_anchor(normalized):
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
    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in decoded
    )
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


def _contains_anchor(text: str) -> bool:
    tokens = {_normalized_value(token) for token in re.findall(r"\b\w+\b", text)}
    return bool(tokens & _JAILBREAK_ANCHORS)


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


def _add_match(
    matches, seen, indicator, category, severity, weight, evidence, source
):
    if indicator in seen:
        return
    matches.append(
        _match_record(indicator, category, severity, weight, evidence, source)
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

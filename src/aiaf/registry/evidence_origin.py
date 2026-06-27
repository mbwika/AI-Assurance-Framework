"""Evidence-origin taxonomy for the External Model Intake workflow.

A fact about an external model is only as trustworthy as where it came from. A
``publisher`` field a human typed into a form is *not* the same evidence as a
publisher name bound by a cryptographically verified attestation, yet without an
explicit origin both look identical once persisted. This module gives every
intake fact a first-class **origin** so downstream scoring and the adoption
verdict can weight (and explain) evidence by how it was obtained.

The five origins, weakest to strongest:

``user_entered``
    Typed by the operator registering the model. Lowest trust — an unverified
    human claim.
``provider_declared``
    Asserted by the model's own source (e.g. a Hugging Face model card,
    ``config.json``, or LICENSE file). Self-asserted by the publisher; better
    than a third-party guess but still unverified.
``artifact_derived``
    Mechanically extracted from the artifact itself (e.g. dependency
    coordinates parsed from a bundled manifest). Reproducible from the bytes.
``locally_observed``
    Measured by AIAF on the artifact in hand (e.g. a SHA-256 computed over the
    downloaded bytes, or a serialization scan result). Trustworthy because AIAF
    produced it.
``independently_verified``
    Confirmed against an independent cryptographic proof (e.g. a verified signed
    provenance attestation, or — in a later phase — a Sigstore signature).
    Highest trust.

This is intentionally a thin, dependency-free vocabulary: the
:mod:`aiaf.core.adoption_engine` consumes it, and registration tags facts with
it, but the taxonomy itself owns no scoring policy beyond the ordinal trust
weights below.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Any

EVIDENCE_ORIGIN_VERSION = "1.0"


class EvidenceOrigin(str, Enum):
    """Where a single fact about a model came from, weakest to strongest."""

    USER_ENTERED = "user_entered"
    PROVIDER_DECLARED = "provider_declared"
    ARTIFACT_DERIVED = "artifact_derived"
    LOCALLY_OBSERVED = "locally_observed"
    INDEPENDENTLY_VERIFIED = "independently_verified"


# Ordinal rank (higher = more trustworthy). Used to compare origins and to find
# the weakest origin backing a group of related facts.
ORIGIN_RANK: dict[EvidenceOrigin, int] = {
    EvidenceOrigin.USER_ENTERED: 0,
    EvidenceOrigin.PROVIDER_DECLARED: 1,
    EvidenceOrigin.ARTIFACT_DERIVED: 2,
    EvidenceOrigin.LOCALLY_OBSERVED: 3,
    EvidenceOrigin.INDEPENDENTLY_VERIFIED: 4,
}

# Multiplicative trust weight in [0, 1]. A claim's contribution to provenance or
# adoption confidence is scaled by the weight of its origin so that, e.g., a
# user-entered publisher cannot carry the same weight as a verified one.
ORIGIN_TRUST_WEIGHT: dict[EvidenceOrigin, float] = {
    EvidenceOrigin.USER_ENTERED: 0.20,
    EvidenceOrigin.PROVIDER_DECLARED: 0.45,
    EvidenceOrigin.ARTIFACT_DERIVED: 0.70,
    EvidenceOrigin.LOCALLY_OBSERVED: 0.85,
    EvidenceOrigin.INDEPENDENTLY_VERIFIED: 1.0,
}

# Origins at or above this rank are considered "verified-grade" — strong enough
# to establish model identity/integrity on their own.
VERIFIED_GRADE_RANK = ORIGIN_RANK[EvidenceOrigin.LOCALLY_OBSERVED]


def coerce_origin(value: Any) -> EvidenceOrigin:
    """Coerce a string/enum into an :class:`EvidenceOrigin`.

    Unrecognized values fall back conservatively to ``USER_ENTERED`` (lowest
    trust) rather than raising, so a malformed persisted ledger never crashes a
    verdict and never silently inflates trust.
    """
    if isinstance(value, EvidenceOrigin):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for origin in EvidenceOrigin:
            if origin.value == normalized:
                return origin
    return EvidenceOrigin.USER_ENTERED


def origin_trust_weight(origin: Any) -> float:
    """Return the [0, 1] trust weight for an origin (coercing as needed)."""
    return ORIGIN_TRUST_WEIGHT[coerce_origin(origin)]


def is_verified_grade(origin: Any) -> bool:
    """True when the origin is locally observed or independently verified."""
    return ORIGIN_RANK[coerce_origin(origin)] >= VERIFIED_GRADE_RANK


def tag_fact(
    name: str,
    value: Any,
    origin: EvidenceOrigin,
    *,
    detail: str | None = None,
) -> dict[str, Any]:
    """Build a single origin-tagged fact record.

    ``value`` is summarized to a short string so the ledger stays compact and
    JSON-serializable regardless of the underlying type.
    """
    origin = coerce_origin(origin)
    return {
        "name": name,
        "value": _summarize_value(value),
        "origin": origin.value,
        "origin_rank": ORIGIN_RANK[origin],
        "trust_weight": ORIGIN_TRUST_WEIGHT[origin],
        "detail": detail,
    }


class FactLedger:
    """An append-only collection of origin-tagged facts about one model.

    The ledger is the audit trail behind an adoption verdict: every reason the
    verdict gives can point back to a fact and the origin that backs it. It is
    deliberately simple — add facts, then serialize with :meth:`to_list` for
    persistence in ``model_record.metadata['evidence_ledger']``.
    """

    def __init__(self) -> None:
        self._facts: list[dict[str, Any]] = []

    def add(
        self,
        name: str,
        value: Any,
        origin: EvidenceOrigin,
        *,
        detail: str | None = None,
        skip_empty: bool = True,
    ) -> FactLedger:
        """Record one fact. Empty/None values are skipped by default."""
        if skip_empty and _is_empty(value):
            return self
        self._facts.append(tag_fact(name, value, origin, detail=detail))
        return self

    def extend(self, facts: Iterable[dict[str, Any]]) -> FactLedger:
        """Merge already-serialized fact records (e.g. a persisted ledger)."""
        for fact in facts:
            if isinstance(fact, dict) and fact.get("name"):
                normalized = coerce_origin(fact.get("origin"))
                self._facts.append(
                    {
                        "name": fact["name"],
                        "value": _summarize_value(fact.get("value")),
                        "origin": normalized.value,
                        "origin_rank": ORIGIN_RANK[normalized],
                        "trust_weight": ORIGIN_TRUST_WEIGHT[normalized],
                        "detail": fact.get("detail"),
                    }
                )
        return self

    def to_list(self) -> list[dict[str, Any]]:
        """Return the serialized facts (a copy)."""
        return list(self._facts)

    def by_origin(self) -> dict[str, list[str]]:
        """Group fact names by their origin value, for summaries."""
        grouped: dict[str, list[str]] = {}
        for fact in self._facts:
            grouped.setdefault(fact["origin"], []).append(fact["name"])
        return grouped

    def weakest_origin(self, names: Iterable[str]) -> EvidenceOrigin | None:
        """Return the weakest origin among the named facts, or None if absent.

        Identity trust is bounded by its weakest supporting fact: if a model's
        publisher and source are both present but the publisher is only
        ``user_entered``, the identity is only as strong as that user claim.
        """
        wanted = set(names)
        ranks = [
            (fact["origin_rank"], coerce_origin(fact["origin"]))
            for fact in self._facts
            if fact["name"] in wanted
        ]
        if not ranks:
            return None
        return min(ranks, key=lambda item: item[0])[1]


def ledger_from_list(facts: Any) -> FactLedger:
    """Rebuild a :class:`FactLedger` from a persisted list of fact records."""
    ledger = FactLedger()
    if isinstance(facts, list):
        ledger.extend(facts)
    return ledger


def _summarize_value(value: Any, *, max_chars: int = 200) -> Any:
    """Render a fact value as a compact, JSON-safe summary."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        return text if len(text) <= max_chars else text[: max_chars - 1] + "…"
    if isinstance(value, (list, tuple, set)):
        return f"{len(value)} item(s)"
    if isinstance(value, dict):
        return f"{len(value)} field(s)"
    text = str(value)
    return text if len(text) <= max_chars else text[: max_chars - 1] + "…"


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False

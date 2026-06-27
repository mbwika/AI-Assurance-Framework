import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_origin_rank_and_weight_are_monotonic():
    ensure_src()
    from aiaf.registry.evidence_origin import (
        EvidenceOrigin,
        ORIGIN_RANK,
        ORIGIN_TRUST_WEIGHT,
    )

    ordered = [
        EvidenceOrigin.USER_ENTERED,
        EvidenceOrigin.PROVIDER_DECLARED,
        EvidenceOrigin.ARTIFACT_DERIVED,
        EvidenceOrigin.LOCALLY_OBSERVED,
        EvidenceOrigin.INDEPENDENTLY_VERIFIED,
    ]
    ranks = [ORIGIN_RANK[o] for o in ordered]
    weights = [ORIGIN_TRUST_WEIGHT[o] for o in ordered]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks)
    assert weights == sorted(weights)
    assert ORIGIN_TRUST_WEIGHT[EvidenceOrigin.USER_ENTERED] < 0.5
    assert ORIGIN_TRUST_WEIGHT[EvidenceOrigin.INDEPENDENTLY_VERIFIED] == 1.0


def test_coerce_origin_falls_back_to_user_entered():
    ensure_src()
    from aiaf.registry.evidence_origin import EvidenceOrigin, coerce_origin

    assert coerce_origin("independently_verified") is EvidenceOrigin.INDEPENDENTLY_VERIFIED
    assert coerce_origin(EvidenceOrigin.LOCALLY_OBSERVED) is EvidenceOrigin.LOCALLY_OBSERVED
    # Unknown / malformed values never silently inflate trust.
    assert coerce_origin("totally-bogus") is EvidenceOrigin.USER_ENTERED
    assert coerce_origin(None) is EvidenceOrigin.USER_ENTERED


def test_is_verified_grade():
    ensure_src()
    from aiaf.registry.evidence_origin import EvidenceOrigin, is_verified_grade

    assert is_verified_grade(EvidenceOrigin.LOCALLY_OBSERVED)
    assert is_verified_grade(EvidenceOrigin.INDEPENDENTLY_VERIFIED)
    assert not is_verified_grade(EvidenceOrigin.USER_ENTERED)
    assert not is_verified_grade(EvidenceOrigin.PROVIDER_DECLARED)
    assert not is_verified_grade(EvidenceOrigin.ARTIFACT_DERIVED)


def test_fact_ledger_records_skips_empty_and_groups_by_origin():
    ensure_src()
    from aiaf.registry.evidence_origin import EvidenceOrigin, FactLedger

    ledger = FactLedger()
    ledger.add("sha256", "a" * 64, EvidenceOrigin.LOCALLY_OBSERVED)
    ledger.add("publisher", "ACME", EvidenceOrigin.USER_ENTERED)
    ledger.add("license", "", EvidenceOrigin.USER_ENTERED)  # empty -> skipped
    ledger.add("license", None, EvidenceOrigin.USER_ENTERED)  # None -> skipped

    facts = ledger.to_list()
    names = {f["name"] for f in facts}
    assert names == {"sha256", "publisher"}

    grouped = ledger.by_origin()
    assert grouped["locally_observed"] == ["sha256"]
    assert grouped["user_entered"] == ["publisher"]


def test_weakest_origin_bounds_identity():
    ensure_src()
    from aiaf.registry.evidence_origin import EvidenceOrigin, FactLedger

    ledger = FactLedger()
    ledger.add("source_url", "https://huggingface.co/acme/m", EvidenceOrigin.USER_ENTERED)
    ledger.add("publisher", "ACME", EvidenceOrigin.PROVIDER_DECLARED)

    # Weakest of the identity facts governs how far identity can be trusted.
    assert ledger.weakest_origin(["publisher", "source_url"]) is EvidenceOrigin.USER_ENTERED
    assert ledger.weakest_origin(["publisher"]) is EvidenceOrigin.PROVIDER_DECLARED
    assert ledger.weakest_origin(["absent"]) is None


def test_ledger_from_list_roundtrips_and_normalizes():
    ensure_src()
    from aiaf.registry.evidence_origin import EvidenceOrigin, FactLedger, ledger_from_list

    original = FactLedger()
    original.add("sha256", "b" * 64, EvidenceOrigin.LOCALLY_OBSERVED)
    serialized = original.to_list()

    rebuilt = ledger_from_list(serialized)
    assert rebuilt.weakest_origin(["sha256"]) is EvidenceOrigin.LOCALLY_OBSERVED

    # A malformed persisted origin coerces down, not up.
    rebuilt2 = ledger_from_list([{"name": "x", "value": "y", "origin": "garbage"}])
    assert rebuilt2.weakest_origin(["x"]) is EvidenceOrigin.USER_ENTERED

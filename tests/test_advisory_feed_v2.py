import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.registry.advisory_feed_v2 as feed_module  # noqa: E402
from aiaf.registry.advisory_feed_v2 import (  # noqa: E402
    ADVISORY_FEED_V2_ALGORITHM,
    ADVISORY_FEED_V2_SCHEMA_VERSION,
    create_advisory_feed_v2,
    verify_advisory_feed_v2,
)

KEY = "0123456789abcdef" * 4
OTHER_KEY = "fedcba9876543210" * 4
GENERATED = "2026-06-19T12:00:00Z"
AS_OF = "2026-06-19T12:01:00Z"
EXPIRES = "2026-06-20T12:00:00Z"


def _advisory(identifier="OSV-2026-1", package="requests"):
    return {
        "id": identifier,
        "summary": "Test vulnerability",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "2.0.0"},
                        ],
                    }
                ],
            }
        ],
    }


def _feed(sequence=1, previous=None, advisories=None, **overrides):
    kwargs = {
        "feed_id": "organization-osv",
        "sequence": sequence,
        "previous_feed_sha256": previous,
        "generated_at": GENERATED,
        "expires_at": EXPIRES,
        "advisories": advisories or [_advisory()],
        "signing_key": KEY,
        "key_id": "feed-key-2026-01",
        "source": "organization-osv-mirror",
        "as_of": AS_OF,
    }
    kwargs.update(overrides)
    return create_advisory_feed_v2(**kwargs)


def _policy(feed, **overrides):
    policy = {
        "expected_feed_id": "organization-osv",
        "expected_source": "organization-osv-mirror",
        "expected_key_id": "feed-key-2026-01",
        "expected_sequence": feed["sequence"],
        "expected_previous_feed_sha256": feed["previous_feed_sha256"],
        "as_of": AS_OF,
    }
    policy.update(overrides)
    return policy


def _verify(feed, key=KEY, **policy_overrides):
    return verify_advisory_feed_v2(feed, key, _policy(feed, **policy_overrides))


def _resign(feed, key=KEY):
    payload, error = feed_module._canonical_payload(feed)
    assert error is None
    feed["signature"] = hmac.new(
        key.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return feed


def test_valid_feed_is_deterministic_versioned_and_json_safe():
    feed = _feed()

    first = _verify(feed)
    second = _verify(feed)

    assert first == second
    assert first["verified"] is True
    assert first["cryptographically_valid"] is True
    assert first["assurance_level"] == "SYMMETRIC_AUTHENTICATED"
    assert first["scoring_version"] == ADVISORY_FEED_V2_SCHEMA_VERSION == "2.0"
    assert feed["algorithm"] == ADVISORY_FEED_V2_ALGORITHM
    assert len(first["feed_sha256"]) == 64
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_advisory_content_tampering_invalidates_signature():
    feed = _feed()
    feed["advisories"][0]["summary"] = "Tampered summary"

    result = _verify(feed)

    assert result["verified"] is False
    assert result["checks"]["signature_valid"] is False
    assert result["cryptographically_valid"] is False


def test_valid_mac_under_wrong_feed_identity_fails_trust_policy():
    feed = _feed(feed_id="attacker-feed", source="attacker-mirror")
    policy = _policy(
        feed,
        expected_feed_id="organization-osv",
        expected_source="organization-osv-mirror",
    )

    result = verify_advisory_feed_v2(feed, KEY, policy)

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["feed_id_matches_policy"] is False
    assert result["checks"]["source_matches_policy"] is False
    assert result["verified"] is False


def test_unsigned_extension_field_is_rejected_even_when_mac_still_matches():
    feed = _feed()
    feed["untrusted_metadata"] = {"priority": "ignore-signature-policy"}

    result = _verify(feed)

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["strict_envelope_fields"] is False
    assert result["verified"] is False


def test_missing_or_malformed_policy_never_uses_wall_clock_defaults():
    feed = _feed()

    missing = verify_advisory_feed_v2(feed, KEY, None)
    malformed_time = _policy(feed, as_of="now-ish")
    malformed = verify_advisory_feed_v2(feed, KEY, malformed_time)

    assert missing["verified"] is False
    assert missing["checks"]["trust_policy_complete"] is False
    assert malformed["verified"] is False
    assert malformed["checks"]["as_of_valid"] is False


def test_malformed_feed_roots_fail_closed_without_exceptions():
    for value in (None, "feed", [], 7):
        result = verify_advisory_feed_v2(value, KEY, {})
        assert result["verified"] is False
        assert result["checks"]["feed_is_object"] is False
        assert result["feed_sha256"] is not None


def test_weak_empty_and_low_diversity_keys_are_rejected():
    feed = _feed()

    for key in ("", "short-secret", "a" * 64, None):
        result = _verify(feed, key=key)
        assert result["verified"] is False
        assert result["checks"]["signing_key_strong"] is False
        assert result["checks"]["signature_valid"] is False


def test_wrong_strong_key_fails_constant_time_signature_comparison_path():
    result = _verify(_feed(), key=OTHER_KEY)

    assert result["checks"]["signing_key_strong"] is True
    assert result["checks"]["signature_valid"] is False
    assert result["verified"] is False


def test_naive_and_malformed_feed_timestamps_are_rejected():
    naive = copy.deepcopy(_feed())
    naive["generated_at"] = "2026-06-19T12:00:00"
    _resign(naive)
    malformed = copy.deepcopy(_feed())
    malformed["expires_at"] = "tomorrow"
    _resign(malformed)

    naive_result = _verify(naive)
    malformed_result = _verify(malformed)

    assert naive_result["checks"]["generated_at_valid"] is False
    assert malformed_result["checks"]["expires_at_valid"] is False
    assert naive_result["checks"]["signature_valid"] is True
    assert malformed_result["checks"]["signature_valid"] is True


def test_future_stale_expired_and_overlong_feeds_fail_distinct_checks():
    feed = _feed()
    future = _verify(feed, as_of="2026-06-19T00:00:00Z")
    stale = _verify(feed, as_of="2026-06-21T11:59:59Z")
    expired = _verify(feed, as_of="2026-06-20T12:00:01Z")
    overlong = copy.deepcopy(feed)
    overlong["expires_at"] = "2026-07-01T12:00:00Z"
    _resign(overlong)
    overlong_result = _verify(overlong)

    assert future["checks"]["generated_at_not_future"] is False
    assert stale["checks"]["generated_at_fresh"] is False
    assert expired["checks"]["feed_not_expired"] is False
    assert overlong_result["checks"]["lifetime_within_policy"] is False
    assert all(result["checks"]["signature_valid"] for result in (future, stale, expired, overlong_result))


def test_genesis_requires_null_previous_digest():
    feed = _feed()
    feed["previous_feed_sha256"] = "a" * 64
    _resign(feed)

    result = _verify(feed, expected_previous_feed_sha256=None)

    assert result["checks"]["chain_field_valid"] is False
    assert result["checks"]["previous_digest_matches_policy"] is False
    assert result["checks"]["signature_valid"] is True


def test_second_feed_cryptographically_links_to_genesis():
    genesis = _feed()
    genesis_result = _verify(genesis)
    successor = _feed(
        sequence=2,
        previous=genesis_result["feed_sha256"],
        generated_at="2026-06-19T13:00:00Z",
        expires_at="2026-06-20T13:00:00Z",
        as_of="2026-06-19T13:01:00Z",
    )

    result = _verify(
        successor,
        as_of="2026-06-19T13:01:00Z",
        expected_previous_feed_sha256=genesis_result["feed_sha256"],
    )

    assert result["verified"] is True
    assert result["checks"]["chain_field_valid"] is True
    assert result["checks"]["previous_digest_matches_policy"] is True


def test_validly_signed_fork_and_replayed_sequence_fail_expected_state():
    genesis = _feed()
    genesis_digest = _verify(genesis)["feed_sha256"]
    fork = _feed(
        sequence=2,
        previous="f" * 64,
        generated_at="2026-06-19T13:00:00Z",
        expires_at="2026-06-20T13:00:00Z",
        as_of="2026-06-19T13:01:00Z",
    )

    fork_result = _verify(
        fork,
        as_of="2026-06-19T13:01:00Z",
        expected_previous_feed_sha256=genesis_digest,
    )
    replay_result = _verify(genesis, expected_sequence=2)

    assert fork_result["checks"]["signature_valid"] is True
    assert fork_result["checks"]["previous_digest_matches_policy"] is False
    assert replay_result["checks"]["signature_valid"] is True
    assert replay_result["checks"]["sequence_matches_policy"] is False


def test_duplicate_advisory_identity_is_rejected_even_when_resigned():
    feed = copy.deepcopy(_feed())
    feed["advisories"].append(copy.deepcopy(feed["advisories"][0]))
    feed["advisory_count"] = 2
    _resign(feed)

    result = _verify(feed)

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["advisories_valid"] is False
    assert result["unique_advisory_count"] == 1
    assert any(item["indicator"] == "duplicate_advisory_identity" for item in result["diagnostics"])


def test_signed_advisory_count_detects_collection_inconsistency():
    feed = copy.deepcopy(_feed())
    feed["advisory_count"] = 99
    _resign(feed)

    result = _verify(feed)

    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["advisory_count_matches"] is False


def test_float_values_are_rejected_from_canonical_interchange_subset():
    feed = copy.deepcopy(_feed())
    feed["advisories"][0]["database_specific"] = {"cvss": 9.8}

    result = _verify(feed)

    assert result["checks"]["canonical_payload_valid"] is False
    assert result["checks"]["signature_valid"] is False
    assert any("Floating-point" in item["detail"] for item in result["diagnostics"])


def test_reference_cycles_and_excessive_nesting_fail_without_recursion_errors():
    cyclic = copy.deepcopy(_feed())
    cyclic["advisories"][0]["cycle"] = cyclic["advisories"][0]
    cyclic_result = _verify(cyclic)

    nested = copy.deepcopy(_feed())
    value = {}
    nested["advisories"][0]["nested"] = value
    for _ in range(30):
        child = {}
        value["child"] = child
        value = child
    nested_result = _verify(nested)

    assert cyclic_result["checks"]["canonical_payload_valid"] is False
    assert nested_result["checks"]["canonical_payload_valid"] is False
    assert cyclic_result["verified"] is False
    assert nested_result["verified"] is False


def test_advisory_and_string_resource_bounds_fail_closed(monkeypatch):
    control = _feed()
    monkeypatch.setattr(feed_module, "_MAX_ADVISORIES", 2)
    bounded = copy.deepcopy(control)
    bounded["advisories"] = [_advisory(f"OSV-{index}") for index in range(3)]
    bounded["advisory_count"] = 3
    _resign(bounded)

    monkeypatch.setattr(feed_module, "_MAX_STRING_BYTES", 16)
    oversized = copy.deepcopy(control)
    oversized["advisories"][0]["summary"] = "x" * 17
    oversized_result = _verify(oversized)
    bounded_result = _verify(bounded)

    assert bounded_result["checks"]["advisories_valid"] is False
    assert oversized_result["checks"]["canonical_payload_valid"] is False


def test_signature_shape_and_identity_fields_are_strict():
    uppercase_signature = copy.deepcopy(_feed())
    uppercase_signature["signature"] = uppercase_signature["signature"].upper()
    bad_key_id = copy.deepcopy(_feed())
    bad_key_id["key_id"] = "feed key with spaces"
    _resign(bad_key_id)

    signature_result = _verify(uppercase_signature)
    identity_result = _verify(bad_key_id)

    assert signature_result["checks"]["signature_shape_valid"] is False
    assert identity_result["checks"]["key_id_valid"] is False
    assert identity_result["checks"]["signature_valid"] is True


def test_canonical_digest_is_independent_of_dictionary_insertion_order():
    feed = _feed()
    reordered = {key: feed[key] for key in reversed(list(feed))}

    original_result = _verify(feed)
    reordered_result = _verify(reordered)

    assert reordered_result["verified"] is True
    assert reordered_result["feed_sha256"] == original_result["feed_sha256"]


def test_creator_rejects_bad_chain_key_and_advisory_evidence():
    with pytest.raises(ValueError):
        _feed(sequence=2, previous=None)
    with pytest.raises(ValueError):
        _feed(signing_key="short")
    with pytest.raises(ValueError):
        _feed(advisories=[{"id": "OSV-WITHOUT-AFFECTED"}])

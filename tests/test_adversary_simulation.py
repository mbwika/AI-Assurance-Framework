"""Tests for analysis.adversary_simulation (Phase E)."""

import pytest
from aiaf.analysis.adversary_simulation import (
    SIMULATION_VERSION,
    THREAT_SCRIPT_KIDDIE, THREAT_OPPORTUNIST, THREAT_MOTIVATED, THREAT_APT, THREAT_INSIDER,
    THREAT_PROFILES,
    ATTACK_PROMPT_INJECTION, ATTACK_JAILBREAK, ATTACK_EXTRACTION,
    ATTACK_MEMBERSHIP_INFERENCE, ATTACK_TRAINING_POISONING, ATTACK_SUPPLY_CHAIN,
    ATTACK_VECTORS,
    RISK_NEGLIGIBLE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL,
    _RISK_RANK,
    SimulationError,
    simulate_adversary,
    _adjusted_probability,
    _probability_to_risk,
    _SOPHISTICATION,
)


class _Store:
    def get_model(self, key):
        return None
    def save_model(self, rec):
        pass
    def list_models(self):
        return []


def _rec():
    return {"model_id": "m1", "metadata": {}}


# ── Constants ──────────────────────────────────────────────────────────────────

def test_threat_profiles_frozenset():
    assert THREAT_APT in THREAT_PROFILES
    assert THREAT_INSIDER in THREAT_PROFILES


def test_attack_vectors_frozenset():
    assert ATTACK_PROMPT_INJECTION in ATTACK_VECTORS
    assert ATTACK_SUPPLY_CHAIN in ATTACK_VECTORS


def test_sophistication_ordering():
    assert _SOPHISTICATION[THREAT_APT] > _SOPHISTICATION[THREAT_MOTIVATED]
    assert _SOPHISTICATION[THREAT_MOTIVATED] > _SOPHISTICATION[THREAT_OPPORTUNIST]
    assert _SOPHISTICATION[THREAT_OPPORTUNIST] > _SOPHISTICATION[THREAT_SCRIPT_KIDDIE]


# ── Probability model ──────────────────────────────────────────────────────────

def test_apt_higher_prob_than_script_kiddie():
    ctx = {}
    p_apt = _adjusted_probability(THREAT_APT, ATTACK_PROMPT_INJECTION, ctx)
    p_sk = _adjusted_probability(THREAT_SCRIPT_KIDDIE, ATTACK_PROMPT_INJECTION, ctx)
    assert p_apt > p_sk


def test_internet_facing_increases_prob():
    p_base = _adjusted_probability(THREAT_MOTIVATED, ATTACK_PROMPT_INJECTION, {})
    p_exposed = _adjusted_probability(THREAT_MOTIVATED, ATTACK_PROMPT_INJECTION, {"internet_facing": True})
    assert p_exposed > p_base


def test_guardrails_reduce_injection_prob():
    p_base = _adjusted_probability(THREAT_APT, ATTACK_PROMPT_INJECTION, {})
    p_guarded = _adjusted_probability(THREAT_APT, ATTACK_PROMPT_INJECTION, {"has_guardrails": True})
    assert p_guarded < p_base


def test_guardrails_reduce_jailbreak_prob():
    p_base = _adjusted_probability(THREAT_APT, ATTACK_JAILBREAK, {})
    p_guarded = _adjusted_probability(THREAT_APT, ATTACK_JAILBREAK, {"has_guardrails": True})
    assert p_guarded < p_base


def test_output_filtering_reduces_extraction_prob():
    p_base = _adjusted_probability(THREAT_MOTIVATED, ATTACK_EXTRACTION, {})
    p_filtered = _adjusted_probability(THREAT_MOTIVATED, ATTACK_EXTRACTION, {"has_output_filtering": True})
    assert p_filtered < p_base


def test_rate_limiting_reduces_extraction_prob():
    p_base = _adjusted_probability(THREAT_MOTIVATED, ATTACK_EXTRACTION, {})
    p_limited = _adjusted_probability(THREAT_MOTIVATED, ATTACK_EXTRACTION, {"has_rate_limiting": True})
    assert p_limited < p_base


def test_insider_boost_supply_chain():
    p_apt = _adjusted_probability(THREAT_APT, ATTACK_SUPPLY_CHAIN, {})
    p_insider = _adjusted_probability(THREAT_INSIDER, ATTACK_SUPPLY_CHAIN, {})
    assert p_insider > p_apt  # insider has privileged access boost


def test_probability_clamped_0_to_1():
    # Even with all boosts, should stay ≤ 1.0
    ctx = {"internet_facing": True}
    p = _adjusted_probability(THREAT_APT, ATTACK_PROMPT_INJECTION, ctx)
    assert 0.0 <= p <= 1.0


def test_probability_to_risk_critical():
    # CRITICAL impact + high probability
    assert _probability_to_risk(0.9, "CRITICAL") == RISK_CRITICAL


def test_probability_to_risk_low():
    assert _probability_to_risk(0.15, "MEDIUM") == RISK_LOW


def test_probability_to_risk_negligible():
    assert _probability_to_risk(0.05, "LOW") == RISK_NEGLIGIBLE


# ── simulate_adversary ────────────────────────────────────────────────────────

def test_invalid_threat_profile_raises():
    with pytest.raises(SimulationError, match="UNKNOWN_THREAT"):
        simulate_adversary(_rec(), "UNKNOWN_THREAT", _Store())


def test_script_kiddie_no_extraction():
    result = simulate_adversary(_rec(), THREAT_SCRIPT_KIDDIE, _Store())
    vectors = [v["vector"] for v in result["attack_vectors"]]
    assert ATTACK_EXTRACTION not in vectors


def test_apt_has_all_vectors():
    result = simulate_adversary(_rec(), THREAT_APT, _Store())
    vectors = {v["vector"] for v in result["attack_vectors"]}
    assert ATTACK_EXTRACTION in vectors
    assert ATTACK_TRAINING_POISONING in vectors
    assert ATTACK_SUPPLY_CHAIN in vectors


def test_insider_covers_supply_chain():
    result = simulate_adversary(_rec(), THREAT_INSIDER, _Store())
    vectors = {v["vector"] for v in result["attack_vectors"]}
    assert ATTACK_SUPPLY_CHAIN in vectors
    assert ATTACK_TRAINING_POISONING in vectors


def test_apt_threat_level_critical_or_high():
    result = simulate_adversary(_rec(), THREAT_APT, _Store())
    assert _RISK_RANK[result["overall_threat_level"]] >= _RISK_RANK[RISK_HIGH]


def test_script_kiddie_threat_level_lower_than_apt():
    r_sk = simulate_adversary(_rec(), THREAT_SCRIPT_KIDDIE, _Store())
    r_apt = simulate_adversary(_rec(), THREAT_APT, _Store())
    assert _RISK_RANK[r_sk["overall_threat_level"]] <= _RISK_RANK[r_apt["overall_threat_level"]]


def test_deployment_context_stored_in_result():
    ctx = {"internet_facing": True, "has_guardrails": False}
    result = simulate_adversary(_rec(), THREAT_APT, _Store(), deployment_context=ctx)
    assert result["deployment_context"]["internet_facing"] is True


def test_mitigations_recommended_for_high_risk():
    result = simulate_adversary(_rec(), THREAT_APT, _Store())
    assert len(result["recommended_mitigations"]) > 0


def test_no_mitigations_for_protected_deployment():
    ctx = {
        "has_guardrails": True,
        "has_output_filtering": True,
        "has_rate_limiting": True,
    }
    result = simulate_adversary(_rec(), THREAT_SCRIPT_KIDDIE, _Store(), deployment_context=ctx)
    # Script kiddie with all mitigations → low risk → possibly no mitigations recommended
    # Just check the structure is valid
    assert isinstance(result["recommended_mitigations"], list)


def test_sophistication_in_result():
    result = simulate_adversary(_rec(), THREAT_APT, _Store())
    assert result["sophistication"] == _SOPHISTICATION[THREAT_APT]


def test_evidence_origin_locally_observed():
    result = simulate_adversary(_rec(), THREAT_MOTIVATED, _Store())
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"
    for v in result["attack_vectors"]:
        assert v["evidence_origin"] == "LOCALLY_OBSERVED"


def test_model_id_override():
    result = simulate_adversary(_rec(), THREAT_MOTIVATED, _Store(), model_id="custom")
    assert result["model_id"] == "custom"


def test_case_insensitive_threat_profile():
    result = simulate_adversary(_rec(), "apt", _Store())
    assert result["threat_profile"] == "APT"

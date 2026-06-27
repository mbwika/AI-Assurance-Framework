"""Adversary Capability Simulation.

Models what a realistic threat actor could achieve against a deployed AI
system, given a threat profile and deployment context.  Results are
used to prioritise mitigations and evidence-collection efforts.

Threat profiles
---------------
SCRIPT_KIDDIE       Low sophistication; automated known-CVE tools.
OPPORTUNIST         Medium sophistication; public tools + targeted scripting.
MOTIVATED_ATTACKER  High sophistication; custom tooling, persistent.
APT                 Nation-state level; unlimited resources, patient.
INSIDER             Privileged access; variable skill.

Attack vectors
--------------
PROMPT_INJECTION        Craft inputs that override model instructions.
JAILBREAK               Bypass content policies to elicit harmful outputs.
MODEL_EXTRACTION        Reconstruct weights via high-volume black-box queries.
MEMBERSHIP_INFERENCE    Determine if a record was in the training set.
TRAINING_POISONING      Inject malicious examples into the training pipeline.
SUPPLY_CHAIN_ATTACK     Compromise upstream artefacts (base model, datasets).

Evidence origin
---------------
LOCALLY_OBSERVED — probability estimates are computed analytically from
the threat profile and deployment context provided.  No live probing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

SIMULATION_VERSION = "1.0"

# ── Threat profiles ────────────────────────────────────────────────────────────
THREAT_SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
THREAT_OPPORTUNIST = "OPPORTUNIST"
THREAT_MOTIVATED = "MOTIVATED_ATTACKER"
THREAT_APT = "APT"
THREAT_INSIDER = "INSIDER"

THREAT_PROFILES: frozenset = frozenset(
    {THREAT_SCRIPT_KIDDIE, THREAT_OPPORTUNIST, THREAT_MOTIVATED, THREAT_APT, THREAT_INSIDER}
)

# Sophistication: 0–1 technical capability of the threat actor
_SOPHISTICATION: Dict[str, float] = {
    THREAT_SCRIPT_KIDDIE: 0.20,
    THREAT_OPPORTUNIST: 0.40,
    THREAT_MOTIVATED: 0.65,
    THREAT_APT: 0.90,
    THREAT_INSIDER: 0.70,
}

# ── Attack vectors ─────────────────────────────────────────────────────────────
ATTACK_PROMPT_INJECTION = "PROMPT_INJECTION"
ATTACK_JAILBREAK = "JAILBREAK"
ATTACK_EXTRACTION = "MODEL_EXTRACTION"
ATTACK_MEMBERSHIP_INFERENCE = "MEMBERSHIP_INFERENCE"
ATTACK_TRAINING_POISONING = "TRAINING_POISONING"
ATTACK_SUPPLY_CHAIN = "SUPPLY_CHAIN_ATTACK"

ATTACK_VECTORS: frozenset = frozenset({
    ATTACK_PROMPT_INJECTION, ATTACK_JAILBREAK, ATTACK_EXTRACTION,
    ATTACK_MEMBERSHIP_INFERENCE, ATTACK_TRAINING_POISONING, ATTACK_SUPPLY_CHAIN,
})

# Base accessibility of each vector (0–1, higher = easier to exploit)
_ACCESSIBILITY: Dict[str, float] = {
    ATTACK_PROMPT_INJECTION: 0.90,
    ATTACK_JAILBREAK: 0.80,
    ATTACK_EXTRACTION: 0.55,
    ATTACK_MEMBERSHIP_INFERENCE: 0.40,
    ATTACK_TRAINING_POISONING: 0.20,
    ATTACK_SUPPLY_CHAIN: 0.25,
}

# Which threat profiles can attempt each vector
_VECTOR_PROFILES: Dict[str, Set[str]] = {
    ATTACK_PROMPT_INJECTION: {THREAT_SCRIPT_KIDDIE, THREAT_OPPORTUNIST, THREAT_MOTIVATED, THREAT_APT, THREAT_INSIDER},
    ATTACK_JAILBREAK: {THREAT_SCRIPT_KIDDIE, THREAT_OPPORTUNIST, THREAT_MOTIVATED, THREAT_APT},
    ATTACK_EXTRACTION: {THREAT_OPPORTUNIST, THREAT_MOTIVATED, THREAT_APT},
    ATTACK_MEMBERSHIP_INFERENCE: {THREAT_MOTIVATED, THREAT_APT},
    ATTACK_TRAINING_POISONING: {THREAT_APT, THREAT_INSIDER},
    ATTACK_SUPPLY_CHAIN: {THREAT_APT, THREAT_INSIDER},
}

# Impact level for each vector
_VECTOR_IMPACT: Dict[str, str] = {
    ATTACK_PROMPT_INJECTION: "HIGH",
    ATTACK_JAILBREAK: "HIGH",
    ATTACK_EXTRACTION: "CRITICAL",
    ATTACK_MEMBERSHIP_INFERENCE: "MEDIUM",
    ATTACK_TRAINING_POISONING: "CRITICAL",
    ATTACK_SUPPLY_CHAIN: "CRITICAL",
}

# ── Risk rating ────────────────────────────────────────────────────────────────
RISK_NEGLIGIBLE = "NEGLIGIBLE"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

_RISK_RANK: Dict[str, int] = {
    RISK_CRITICAL: 4, RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1, RISK_NEGLIGIBLE: 0,
}

_IMPACT_RANK: Dict[str, int] = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


class SimulationError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _worst_risk(a: str, b: str) -> str:
    return a if _RISK_RANK.get(a, 0) >= _RISK_RANK.get(b, 0) else b


def _probability_to_risk(probability: float, impact: str) -> str:
    """Combine attack probability with impact to get risk rating."""
    impact_rank = _IMPACT_RANK.get(impact, 0)
    if impact_rank >= 3 and probability >= 0.40:
        return RISK_CRITICAL
    if impact_rank >= 2 and probability >= 0.35:
        return RISK_HIGH
    if impact_rank >= 2 and probability >= 0.20:
        return RISK_MEDIUM
    if probability >= 0.10:
        return RISK_LOW
    return RISK_NEGLIGIBLE


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


# ── Deployment context adjustments ────────────────────────────────────────────

def _adjusted_probability(
    threat_profile: str,
    vector: str,
    ctx: Dict[str, Any],
) -> float:
    """Compute probability after applying deployment-context modifiers."""
    base = _SOPHISTICATION[threat_profile] * _ACCESSIBILITY[vector]

    # Insider threat: privileged access adds flat boost to supply-chain/poisoning
    if threat_profile == THREAT_INSIDER and vector in (ATTACK_SUPPLY_CHAIN, ATTACK_TRAINING_POISONING):
        base = _clamp(base + 0.30)

    # Deployment context modifiers
    if ctx.get("internet_facing") and vector in (ATTACK_PROMPT_INJECTION, ATTACK_JAILBREAK, ATTACK_EXTRACTION):
        base = _clamp(base + 0.20)

    if ctx.get("has_guardrails"):
        if vector == ATTACK_PROMPT_INJECTION:
            base = _clamp(base - 0.30)
        elif vector == ATTACK_JAILBREAK:
            base = _clamp(base - 0.25)

    if ctx.get("has_output_filtering") and vector == ATTACK_EXTRACTION:
        base = _clamp(base - 0.20)

    if ctx.get("has_rate_limiting") and vector in (ATTACK_EXTRACTION, ATTACK_MEMBERSHIP_INFERENCE):
        base = _clamp(base - 0.15)

    model_trust = str(ctx.get("model_trust_level") or "INTERNAL").upper()
    if model_trust in ("EXTERNAL", "UNTRUSTED") and vector == ATTACK_SUPPLY_CHAIN:
        base = _clamp(base + 0.15)

    return round(base, 3)


# ── Mitigation recommendations ────────────────────────────────────────────────

_MITIGATIONS: Dict[str, str] = {
    ATTACK_PROMPT_INJECTION: "Deploy input/output guardrails (aiaf.core.guardrail_engine).",
    ATTACK_JAILBREAK: "Enable strict content policies and output classifiers.",
    ATTACK_EXTRACTION: "Implement rate limiting, output length caps, and watermarking.",
    ATTACK_MEMBERSHIP_INFERENCE: "Add differential privacy or output perturbation.",
    ATTACK_TRAINING_POISONING: "Enforce signed training pipeline (SLSA level 3+).",
    ATTACK_SUPPLY_CHAIN: "Verify all artefacts via signed manifests (aiaf.registry.tool_manifest).",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def simulate_adversary(
    model_record: Dict[str, Any],
    threat_profile: str,
    store: Any,
    *,
    deployment_context: Optional[Dict[str, Any]] = None,
    model_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Simulate what a threat actor could achieve against this model.

    Parameters
    ----------
    model_record:
        Model registry dict.
    threat_profile:
        One of THREAT_SCRIPT_KIDDIE, THREAT_OPPORTUNIST, THREAT_MOTIVATED,
        THREAT_APT, THREAT_INSIDER.
    store:
        AIAF persistence store.
    deployment_context:
        Dict with boolean flags: ``internet_facing``, ``has_guardrails``,
        ``has_output_filtering``, ``has_rate_limiting``, ``handles_pii``,
        plus ``model_trust_level`` string.
    model_id:
        Override model_id.
    """
    threat_profile = str(threat_profile).upper().strip()
    if threat_profile not in THREAT_PROFILES:
        raise SimulationError(
            f"Unknown threat_profile: {threat_profile!r}. Valid: {sorted(THREAT_PROFILES)}"
        )

    mid = model_id or (model_record.get("model_id") or model_record.get("id") or "unknown")
    ctx = dict(deployment_context or {})

    vectors: List[Dict[str, Any]] = []
    overall_threat = RISK_NEGLIGIBLE
    recommended_mitigations: List[str] = []

    for vector in sorted(ATTACK_VECTORS):
        if threat_profile not in _VECTOR_PROFILES[vector]:
            continue
        prob = _adjusted_probability(threat_profile, vector, ctx)
        impact = _VECTOR_IMPACT[vector]
        risk = _probability_to_risk(prob, impact)
        overall_threat = _worst_risk(overall_threat, risk)

        vector_result = {
            "vector": vector,
            "probability": prob,
            "impact": impact,
            "risk_rating": risk,
            "evidence_origin": "LOCALLY_OBSERVED",
        }
        vectors.append(vector_result)

        if _RISK_RANK.get(risk, 0) >= _RISK_RANK[RISK_MEDIUM]:
            mitigation = _MITIGATIONS.get(vector)
            if mitigation and mitigation not in recommended_mitigations:
                recommended_mitigations.append(mitigation)

    return {
        "model_id": mid,
        "simulation_version": SIMULATION_VERSION,
        "threat_profile": threat_profile,
        "sophistication": _SOPHISTICATION[threat_profile],
        "overall_threat_level": overall_threat,
        "attack_vectors": vectors,
        "recommended_mitigations": recommended_mitigations,
        "deployment_context": ctx,
        "evidence_origin": "LOCALLY_OBSERVED",
        "simulated_at": _utc_now(),
    }

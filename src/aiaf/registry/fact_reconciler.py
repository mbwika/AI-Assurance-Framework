"""Declared-vs-derived fact reconciliation for model intake.

After all evidence sources have run, this module cross-checks every
PROVIDER_DECLARED or USER_ENTERED fact against any LOCALLY_OBSERVED
derivation of the same fact.

Key outputs
-----------
``contradictions``
    Facts where declared ≠ derived.  A CRITICAL contradiction (architecture
    family mismatch) means the artifact almost certainly does not correspond
    to the metadata — the strongest signal in this layer.

``confirmations``
    Facts independently agreed upon at two or more origins.  Each confirmation
    raises the effective confidence of that fact in the adoption verdict.

``provenance_independence_ratio``
    Fraction of decision-driving facts grounded in LOCALLY_OBSERVED or
    INDEPENDENTLY_VERIFIED evidence.  A ratio below 0.3 means the adoption
    decision rests mostly on self-assertion; it is surfaced in the verdict
    and in the dashboard.

``decidability_bounds``
    **Permanent, explicit list** of the six fact categories that cannot be
    independently determined from artifact inspection plus behavioral probing.
    This is a first-class output, not a silence.

Design notes
------------
- Only facts that exist at BOTH a declared origin AND a locally-observed
  origin are compared.  A fact present only at one origin is ``unverifiable``,
  not a contradiction.
- Contradiction severity is fact-specific: architecture mismatch → CRITICAL;
  parameter count mismatch → HIGH; vocab/layer → MEDIUM; license text → LOW.
- Numeric comparisons use a tolerance of ±5 % for parameter counts (rounding,
  shared embeddings) and require exact integer equality for counts and sizes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .evidence_origin import EvidenceOrigin, ledger_from_list

RECONCILER_VERSION = "1.0"

# Severity of a contradiction keyed by fact_name
_CONTRADICTION_SEVERITY: dict[str, str] = {
    "architecture_family": "CRITICAL",
    "architecture_name": "HIGH",
    "model_type": "HIGH",
    "parameter_count_estimate": "HIGH",
    "layer_count": "HIGH",
    "hidden_size": "HIGH",
    "vocab_size": "MEDIUM",
    "quantization": "LOW",
    "license": "LOW",
    "publisher": "MEDIUM",
}

# Facts that drive the adoption decision (used for provenance_independence_ratio)
_DECISION_DRIVING_FACTS = frozenset({
    "architecture_family",
    "parameter_count_estimate",
    "layer_count",
    "hidden_size",
    "vocab_size",
    "model_type",
    "publisher",
    "license",
    "provenance_attestation",
    "sigstore_verification",
    "sha256",
    "behavioral_probe_status",
    "serialization_scan_status",
})

# Things that are permanently outside the decidability boundary.
# Enumerated here so they appear in every adoption verdict as a first-class output.
DECIDABILITY_BOUNDS: list[dict[str, str]] = [
    {
        "category": "training_data",
        "description": "Training corpus composition, size, and quality",
        "why": (
            "The training dataset is consumed and discarded before serialization. "
            "Model weights encode statistical patterns learned from the data but "
            "carry no recoverable record of the specific corpus used."
        ),
        "implication": (
            "Training-data claims remain PROVIDER_DECLARED and cannot be elevated "
            "by AIAF inspection. Verify independently via data cards or audits."
        ),
    },
    {
        "category": "alignment_procedure",
        "description": "RLHF / DPO / constitutional-AI configuration and reward model identity",
        "why": (
            "Alignment procedures are applied before the model is serialized. "
            "The resulting weights reflect the outcome of alignment but not the "
            "procedure, reward model, or human-feedback dataset used."
        ),
        "implication": (
            "Alignment claims remain PROVIDER_DECLARED. "
            "AIAF's behavioral probes provide independent evidence of alignment "
            "outcomes on the specific probe set, not of the process."
        ),
    },
    {
        "category": "backdoor_absence",
        "description": "Absence of backdoor triggers not covered by the probe set",
        "why": (
            "A backdoor keyed to a trigger phrase outside the current probe set "
            "passes all probes without activating. Weight-distribution anomaly "
            "heuristics can detect some known-pattern anomalies but cannot "
            "certify the absence of arbitrary zero-day triggers."
        ),
        "implication": (
            "A PASSED behavioral probe result means no known trigger patterns "
            "were found in the probe set, not that no backdoor exists. "
            "This bound is explicitly noted in every adoption verdict."
        ),
    },
    {
        "category": "evaluation_results",
        "description": "Publisher-reported benchmark scores",
        "why": (
            "Benchmarks are run on specific evaluation harnesses and datasets "
            "not included in the model artifact. Reproducibility requires "
            "identical infrastructure and the original test sets."
        ),
        "implication": (
            "Benchmark claims remain PROVIDER_DECLARED. "
            "Independent reproduction is outside AIAF's current scope."
        ),
    },
    {
        "category": "pre_release_red_teaming",
        "description": "Red-team evaluations conducted by the publisher before release",
        "why": (
            "Publisher red-team results are process attestations describing a "
            "prior exercise, not facts derivable from the artifact. AIAF's own "
            "garak/PyRIT probing is independent but covers a different probe set "
            "and deployment configuration than the publisher's exercise."
        ),
        "implication": (
            "Publisher red-team claims remain PROVIDER_DECLARED. "
            "AIAF's own probing results are LOCALLY_OBSERVED and reported separately."
        ),
    },
    {
        "category": "training_data_legal_compliance",
        "description": "GDPR / CCPA compliance and copyright clearance of training data",
        "why": (
            "Legal compliance of data collection is a property of the data "
            "acquisition process, not of the model weights. It requires legal "
            "review of collection agreements, data sources, and jurisdictional law."
        ),
        "implication": (
            "Legal compliance claims remain PROVIDER_DECLARED and require "
            "independent legal review; AIAF cannot independently verify them."
        ),
    },
]


def reconcile(
    model_record: dict[str, Any],
    weight_inspection: dict[str, Any] | None = None,
    lineage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Cross-check declared facts against locally-derived facts.

    Parameters
    ----------
    model_record:
        Registered model record.  ``metadata.evidence_ledger`` is consumed.
    weight_inspection:
        Optional result from :func:`aiaf.registry.weight_inspector.inspect_file`.
    lineage:
        Optional result from :func:`aiaf.registry.lineage_graph.derive_lineage`.
    """
    model_record = model_record if isinstance(model_record, dict) else {}
    metadata = model_record.get("metadata") or {}
    hf_card = metadata.get("hf_model_card") or {}
    ledger = ledger_from_list(metadata.get("evidence_ledger"))

    # ── Build comparison pairs ───────────────────────────────────────────────
    comparisons: list[dict[str, Any]] = []
    wi_inspected = (
        weight_inspection is not None
        and weight_inspection.get("status") == "INSPECTED"
    )
    if wi_inspected:
        wi_facts = weight_inspection.get("derived_facts") or {}  # type: ignore[union-attr]
        comparisons.extend(_build_comparisons(metadata, hf_card, wi_facts))

    # ── Classify ─────────────────────────────────────────────────────────────
    contradictions: list[dict[str, Any]] = []
    confirmations: list[dict[str, Any]] = []
    for comp in comparisons:
        declared_val = comp.get("declared_value")
        derived_val = comp.get("derived_value")
        if declared_val is None or derived_val is None:
            continue
        fact_name = comp["fact_name"]
        if _contradicts(declared_val, derived_val, fact_name):
            contradictions.append({
                "fact_name": fact_name,
                "declared_value": declared_val,
                "derived_value": derived_val,
                "declared_origin": comp.get("declared_origin", "provider_declared"),
                "derived_origin": "locally_observed",
                "severity": _CONTRADICTION_SEVERITY.get(fact_name, "MEDIUM"),
                "description": comp.get("description", ""),
            })
        else:
            confirmations.append({
                "fact_name": fact_name,
                "value": derived_val,
                "origins": [
                    comp.get("declared_origin", "provider_declared"),
                    "locally_observed",
                ],
            })

    pir = _provenance_independence_ratio(ledger, weight_inspection)
    unverifiable = _collect_unverifiable(metadata, hf_card, wi_inspected)
    arch_consistency = (lineage or {}).get("architecture_consistency", "UNVERIFIABLE")

    return {
        "reconciler_version": RECONCILER_VERSION,
        "contradictions": contradictions,
        "confirmations": confirmations,
        "contradiction_count": len(contradictions),
        "confirmation_count": len(confirmations),
        "provenance_independence_ratio": pir,
        "unverifiable_facts": unverifiable,
        "architecture_consistency": arch_consistency,
        "decidability_bounds": DECIDABILITY_BOUNDS,
        "evidence_origin": "locally_observed",
        "assessment_complete": wi_inspected,
        "reconciled_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ---------------------------------------------------------------------------
# Comparison builders
# ---------------------------------------------------------------------------


def _build_comparisons(
    metadata: dict[str, Any],
    hf_card: dict[str, Any],
    wi_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build (declared, derived) comparison pairs from weight-inspector output."""
    comps: list[dict[str, Any]] = []

    # Parameter count
    decl_params = metadata.get("parameter_count") or hf_card.get("parameter_count")
    deriv_params = wi_facts.get("parameter_count_estimate")
    if decl_params is not None and deriv_params is not None:
        comps.append({
            "fact_name": "parameter_count_estimate",
            "declared_value": int(decl_params),
            "derived_value": int(deriv_params),
            "declared_origin": "provider_declared",
            "description": (
                "Declared parameter count vs. sum of all tensor shape products "
                "(safetensors header)"
            ),
        })

    # Architecture family
    decl_type = (
        metadata.get("model_type") or hf_card.get("model_type") or ""
    ).lower().split("forcausallm")[0].split("forseq2seqlm")[0].strip()
    deriv_arch = wi_facts.get("architecture_family")
    if decl_type and deriv_arch and deriv_arch != "unknown":
        from .lineage_graph import MODEL_TYPE_TO_FAMILY
        decl_family = MODEL_TYPE_TO_FAMILY.get(decl_type)
        if decl_family:
            comps.append({
                "fact_name": "architecture_family",
                "declared_value": decl_family,
                "derived_value": deriv_arch,
                "declared_origin": "provider_declared",
                "description": (
                    "Declared model_type architecture family vs. "
                    "tensor-name-derived architecture family"
                ),
            })

    # Layer count
    decl_layers = metadata.get("num_hidden_layers") or hf_card.get("num_hidden_layers")
    deriv_layers = wi_facts.get("layer_count")
    if decl_layers is not None and deriv_layers is not None:
        comps.append({
            "fact_name": "layer_count",
            "declared_value": int(decl_layers),
            "derived_value": int(deriv_layers),
            "declared_origin": "provider_declared",
            "description": (
                "Declared num_hidden_layers vs. layer count inferred "
                "from tensor name patterns"
            ),
        })

    # Hidden size
    decl_hidden = metadata.get("hidden_size") or hf_card.get("hidden_size")
    deriv_hidden = wi_facts.get("hidden_size")
    if decl_hidden is not None and deriv_hidden is not None:
        comps.append({
            "fact_name": "hidden_size",
            "declared_value": int(decl_hidden),
            "derived_value": int(deriv_hidden),
            "declared_origin": "provider_declared",
            "description": (
                "Declared hidden_size vs. first-layer attention query weight shape"
            ),
        })

    # Vocab size
    decl_vocab = metadata.get("vocab_size") or hf_card.get("vocab_size")
    deriv_vocab = wi_facts.get("vocab_size")
    if decl_vocab is not None and deriv_vocab is not None:
        comps.append({
            "fact_name": "vocab_size",
            "declared_value": int(decl_vocab),
            "derived_value": int(deriv_vocab),
            "declared_origin": "provider_declared",
            "description": (
                "Declared vocab_size vs. token embedding tensor first dimension"
            ),
        })

    return comps


# ---------------------------------------------------------------------------
# Contradiction logic
# ---------------------------------------------------------------------------


def _contradicts(declared: Any, derived: Any, fact_name: str) -> bool:
    """Return True when declared and derived values are meaningfully different."""
    if declared == derived:
        return False
    try:
        d, r = float(declared), float(derived)
        if d == r:
            return False
        if fact_name == "parameter_count_estimate":
            # ±5 % tolerance: rounding, tied embeddings counted twice, etc.
            ratio = abs(d - r) / max(abs(d), abs(r))
            return ratio > 0.05
        if fact_name in ("layer_count", "hidden_size", "vocab_size"):
            return d != r          # exact integer match required
        ratio = abs(d - r) / max(abs(d), abs(r), 1.0)
        return ratio > 0.01
    except (TypeError, ValueError):
        pass
    if isinstance(declared, str) and isinstance(derived, str):
        return declared.lower().strip() != derived.lower().strip()
    return str(declared) != str(derived)


# ---------------------------------------------------------------------------
# Provenance independence ratio
# ---------------------------------------------------------------------------


def _provenance_independence_ratio(
    ledger: Any,
    weight_inspection: dict[str, Any] | None,
) -> float:
    """Fraction of decision-driving facts at LOCALLY_OBSERVED or INDEPENDENTLY_VERIFIED."""
    _lo = EvidenceOrigin.LOCALLY_OBSERVED.value
    _iv = EvidenceOrigin.INDEPENDENTLY_VERIFIED.value

    all_facts = ledger.to_list()
    decision_facts = [f for f in all_facts if f.get("name") in _DECISION_DRIVING_FACTS]

    independent_count = sum(
        1 for f in decision_facts
        if str(f.get("origin") or "").lower() in (_lo, _iv)
    )

    # Facts derived from weight inspection are LOCALLY_OBSERVED
    wi_bonus = 0
    if weight_inspection and weight_inspection.get("status") == "INSPECTED":
        wi_derived = weight_inspection.get("derived_facts") or {}
        existing_names = {f["name"] for f in decision_facts}
        wi_bonus = sum(
            1 for k in _DECISION_DRIVING_FACTS
            if k in wi_derived and wi_derived[k] is not None
            and k not in existing_names
        )

    total = len(decision_facts) + wi_bonus
    if total == 0:
        return 0.0
    return round(min(1.0, (independent_count + wi_bonus) / total), 3)


# ---------------------------------------------------------------------------
# Unverifiable fact collector
# ---------------------------------------------------------------------------


def _collect_unverifiable(
    metadata: dict[str, Any],
    hf_card: dict[str, Any],
    wi_available: bool,
) -> list[str]:
    """List high-value facts that exist only at PROVIDER_DECLARED level."""
    items: list[str] = []

    if metadata.get("training_data") or hf_card.get("dataset"):
        items.append(
            "training_data: claimed in metadata/model card; "
            "cannot be independently verified from artifact bytes"
        )

    if metadata.get("eval_results") or hf_card.get("model-index"):
        items.append(
            "evaluation_results: benchmark scores claimed by publisher; "
            "independent reproduction not performed"
        )

    lic = metadata.get("license") or hf_card.get("license")
    if lic:
        items.append(
            f"license ({lic}): license text verifiable from LICENSE file; "
            "legal compliance of training data collection is not verifiable here"
        )

    if not wi_available:
        items.append(
            "weight-level architecture facts (parameter count, layer count, "
            "hidden size): no local artifact file available for inspection; "
            "declared values are PROVIDER_DECLARED only"
        )

    return items

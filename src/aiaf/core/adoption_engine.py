"""Adoption-recommendation engine for the External Model Intake workflow.

For a model someone "found on the internet", a bare provenance number or risk
score answers the wrong question. The operator needs a *decision*: should we
adopt this, and if so, under what limits? This engine turns the evidence AIAF
already computes — uncertainty-aware provenance, the aggregated risk findings,
governance control coverage, dependency-vulnerability state, and the
origin-tagged fact ledger — into one explainable verdict:

``DO_NOT_APPROVE``
    The evidence we have is bad: an active high/critical security issue, a
    critical dependency vulnerability, or provenance that cannot be established.
``INSUFFICIENT_EVIDENCE``
    We could not finish the evaluation (incomplete assessments / very low
    confidence). The model is not necessarily unsafe — we cannot yet say.
``PILOT_ONLY``
    Adopt only in a controlled pilot with monitoring: elevated posture risk,
    self-asserted (unverified) identity, or a high-severity dependency issue.
``APPROVE_WITH_CONDITIONS``
    Adoptable once the attached conditions are met (close governance gaps, patch
    a medium vulnerability, obtain a signed attestation).
``APPROVE_FOR_SCOPED_USE``
    The strongest verdict an external model can earn: low risk, verified-grade
    identity/integrity, complete assessments — approved within a defined scope.

Design mirrors the rest of AIAF: the verdict is the **worst** of a set of caps
(conservative), every cap carries a human reason tied to a fact and its origin,
and missing evidence is a first-class output (``evidence_gaps``) rather than a
silent default. The function is pure — persistence is the API layer's job.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from ..registry.evidence_origin import (
    EvidenceOrigin,
    coerce_origin,
    is_verified_grade,
    ledger_from_list,
)
from .org_policy_engine import evaluate_org_policy

ADOPTION_SCORING_VERSION = "3.0"


class AdoptionVerdict(str, Enum):
    """Graded adoption decision, worst to best."""

    DO_NOT_APPROVE = "DO_NOT_APPROVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    PILOT_ONLY = "PILOT_ONLY"
    APPROVE_WITH_CONDITIONS = "APPROVE_WITH_CONDITIONS"
    APPROVE_FOR_SCOPED_USE = "APPROVE_FOR_SCOPED_USE"


_VERDICT_RANK: dict[AdoptionVerdict, int] = {
    AdoptionVerdict.DO_NOT_APPROVE: 0,
    AdoptionVerdict.INSUFFICIENT_EVIDENCE: 1,
    AdoptionVerdict.PILOT_ONLY: 2,
    AdoptionVerdict.APPROVE_WITH_CONDITIONS: 3,
    AdoptionVerdict.APPROVE_FOR_SCOPED_USE: 4,
}

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Findings that describe an *observed* threat in the model's behaviour or
# content (as opposed to missing-control / posture findings). A high-severity
# behavioural finding is a hard blocker; a posture finding caps lower because it
# usually reflects absent evidence rather than demonstrated harm.
_BEHAVIORAL_FINDING_TYPES = frozenset(
    {
        "prompt_injection",
        "jailbreak",
        "data_leakage",
        "tool_invocation_risk",
        "adversarial_testing",
    }
)

# Identity facts whose weakest origin bounds how far identity can be trusted.
_IDENTITY_FACTS = ("publisher", "source", "source_url", "repository")

# Facts that, when independently verified, establish model identity on their own
# (e.g. a verified attestation binds model id + artifact hash), overriding the
# fact that the operator typed the source URL by hand.
_IDENTITY_VERIFYING_FACTS = frozenset({"provenance_attestation", "sigstore_verification"})

_LOW_CONFIDENCE_FLOOR = 0.45


def recommend_adoption(
    model_record: dict[str, Any],
    risk_record: dict[str, Any] | None = None,
    provenance_assessment: dict[str, Any] | None = None,
    governance_summary: dict[str, Any] | None = None,
    vulnerability_scan: dict[str, Any] | None = None,
    serialization_scan: dict[str, Any] | None = None,
    behavioral_probes: dict[str, Any] | None = None,
    redteam_results: dict[str, Any] | None = None,
    policy_context: dict[str, Any] | None = None,
    weight_inspection: dict[str, Any] | None = None,
    lineage: dict[str, Any] | None = None,
    fact_reconciliation: dict[str, Any] | None = None,
    mcp_scan: dict[str, Any] | None = None,
    backdoor_heuristics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce an explainable adoption verdict from assembled assurance evidence.

    Only ``model_record`` is required; every other input degrades gracefully to
    "evidence not available", which conservatively lowers the verdict toward
    ``INSUFFICIENT_EVIDENCE`` rather than silently approving.

    ``serialization_scan`` (Phase 2): result from
    :func:`aiaf.registry.serialization_scanner.scan_file`.

    ``behavioral_probes`` (Phase 2): result from
    :func:`aiaf.core.probe_engine.run_probes`.

    ``redteam_results`` (Phase 4): result from
    :func:`aiaf.core.redteam_engine.run_redteam` (garak / PyRIT).

    ``backdoor_heuristics`` (Phase 6): result from
    :func:`aiaf.analysis.backdoor_heuristics.analyse`.
    """
    model_record = model_record if isinstance(model_record, dict) else {}
    risk_record = risk_record or {}
    provenance_assessment = provenance_assessment or {}
    governance_summary = governance_summary or {}
    vulnerability_scan = vulnerability_scan or {}

    metadata = model_record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    ledger = ledger_from_list(metadata.get("evidence_ledger"))

    caps: list[dict[str, Any]] = []
    conditions: list[str] = []
    evidence_gaps: list[str] = []

    _evaluate_risk(risk_record, caps, conditions)
    _evaluate_vulnerabilities(vulnerability_scan, caps, conditions, evidence_gaps)
    _evaluate_serialization_scan(serialization_scan, caps, conditions, evidence_gaps)
    _evaluate_weight_inspection(weight_inspection, caps, conditions, evidence_gaps)
    _evaluate_lineage(lineage, caps, conditions, evidence_gaps)
    _evaluate_fact_reconciliation(fact_reconciliation, caps, conditions, evidence_gaps)
    _evaluate_behavioral_probes(behavioral_probes, caps, conditions, evidence_gaps)
    _evaluate_redteam(redteam_results, caps, conditions, evidence_gaps)
    _evaluate_mcp_scan(mcp_scan, caps, conditions, evidence_gaps)
    _evaluate_backdoor_heuristics(backdoor_heuristics, caps, conditions, evidence_gaps)
    _evaluate_provenance(provenance_assessment, model_record, caps, conditions, evidence_gaps)
    _evaluate_identity_origin(ledger, provenance_assessment, caps, evidence_gaps)
    _evaluate_governance(governance_summary, caps, conditions, evidence_gaps)
    _evaluate_completeness(
        risk_record, provenance_assessment, vulnerability_scan,
        serialization_scan, behavioral_probes, redteam_results,
        weight_inspection, caps, evidence_gaps,
    )
    policy_assessment = evaluate_org_policy(
        model_record,
        policy_context=policy_context,
        provenance_assessment=provenance_assessment,
        governance_summary=governance_summary,
        vulnerability_scan=vulnerability_scan,
        serialization_scan=serialization_scan,
        behavioral_probes=behavioral_probes,
    )
    _evaluate_org_policy(policy_assessment, caps, conditions, evidence_gaps)

    verdict = _worst_verdict(caps)
    confidence = _decision_confidence(
        provenance_assessment, risk_record, vulnerability_scan,
        serialization_scan, behavioral_probes, redteam_results,
    )

    reasons = sorted(
        ({k: v for k, v in cap.items() if k != "_rank"} for cap in caps),
        key=lambda cap: (_VERDICT_RANK[AdoptionVerdict(cap["verdict"])], cap["category"]),
    )

    pir = (fact_reconciliation or {}).get("provenance_independence_ratio", 0.0)
    decidability_bounds = (fact_reconciliation or {}).get("decidability_bounds") or []

    return {
        "scoring_version": ADOPTION_SCORING_VERSION,
        "model_id": model_record.get("model_id") or model_record.get("id"),
        "verdict": verdict.value,
        "verdict_rank": _VERDICT_RANK[verdict],
        "summary": _VERDICT_SUMMARY[verdict],
        "confidence": confidence,
        "reasons": reasons,
        "conditions": _dedupe(conditions),
        "evidence_gaps": _dedupe(evidence_gaps),
        "evidence_origin_summary": ledger.by_origin(),
        "provenance_independence_ratio": pir,
        "decidability_bounds": decidability_bounds,
        "policy": policy_assessment,
        "inputs": _input_echo(
            risk_record, provenance_assessment, governance_summary,
            vulnerability_scan, serialization_scan, behavioral_probes,
            redteam_results, policy_assessment,
            weight_inspection=weight_inspection,
            lineage=lineage,
            fact_reconciliation=fact_reconciliation,
            mcp_scan=mcp_scan,
            backdoor_heuristics=backdoor_heuristics,
        ),
    }


_VERDICT_SUMMARY = {
    AdoptionVerdict.DO_NOT_APPROVE: "Do not adopt: the available evidence shows a disqualifying risk.",
    AdoptionVerdict.INSUFFICIENT_EVIDENCE: "Insufficient evidence to decide; obtain the missing evidence before adopting.",
    AdoptionVerdict.PILOT_ONLY: "Adopt only in a controlled, monitored pilot with restricted scope.",
    AdoptionVerdict.APPROVE_WITH_CONDITIONS: "Adoptable once the listed conditions are satisfied.",
    AdoptionVerdict.APPROVE_FOR_SCOPED_USE: "Approved for use within a defined scope.",
}


def _cap(
    caps: list[dict[str, Any]],
    verdict: AdoptionVerdict,
    category: str,
    reason: str,
    *,
    origin: EvidenceOrigin | None = None,
    refs: list[str] | None = None,
) -> None:
    caps.append(
        {
            "verdict": verdict.value,
            "_rank": _VERDICT_RANK[verdict],
            "category": category,
            "reason": reason,
            "origin": origin.value if isinstance(origin, EvidenceOrigin) else origin,
            "refs": refs or [],
        }
    )


def _evaluate_risk(
    risk_record: dict[str, Any],
    caps: list[dict[str, Any]],
    conditions: list[str],
) -> None:
    if not risk_record:
        return
    aggregation = risk_record.get("risk_aggregation") or {}
    agg_severity = str(aggregation.get("severity") or "LOW").upper()
    findings = risk_record.get("findings") or []

    behavioral = [
        f
        for f in findings
        if f.get("type") in _BEHAVIORAL_FINDING_TYPES
        and _SEVERITY_RANK.get(str(f.get("severity")).upper(), 0) >= _SEVERITY_RANK["HIGH"]
    ]
    if behavioral:
        types = sorted({str(f.get("type")) for f in behavioral})
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "active_threat",
            f"Active high/critical security finding(s): {', '.join(types)}.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
            refs=types,
        )

    if agg_severity == "CRITICAL":
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "aggregate_risk",
            f"Aggregate risk is CRITICAL ({risk_record.get('score')}/10).",
        )
    elif agg_severity == "HIGH":
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "aggregate_risk",
            f"Aggregate risk is HIGH ({risk_record.get('score')}/10).",
        )
    elif agg_severity == "MEDIUM":
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "aggregate_risk",
            f"Aggregate risk is MEDIUM ({risk_record.get('score')}/10).",
        )
        conditions.append("Mitigate medium-severity risk findings and re-assess.")

    trust = risk_record.get("trustworthiness") or {}
    if str(trust.get("level") or "").upper() == "LOW":
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "trustworthiness",
            f"Trustworthiness is LOW ({trust.get('trustworthiness_score')}/100).",
        )


def _evaluate_vulnerabilities(
    vuln: dict[str, Any],
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    if not vuln:
        return
    by_severity = {
        str(k).upper(): v for k, v in (vuln.get("by_severity") or {}).items()
    }
    if by_severity.get("CRITICAL"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "dependency_vulnerability",
            f"{by_severity['CRITICAL']} CRITICAL dependency vulnerability(ies) match the model's components.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_severity.get("HIGH"):
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "dependency_vulnerability",
            f"{by_severity['HIGH']} HIGH dependency vulnerability(ies) match the model's components.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_severity.get("MEDIUM") or by_severity.get("LOW"):
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "dependency_vulnerability",
            "Medium/low dependency vulnerabilities are present.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        conditions.append("Patch known medium/low dependency vulnerabilities.")

    if str(vuln.get("status") or "").upper() == "PARTIAL" or vuln.get("unresolved_dependencies"):
        evidence_gaps.append(
            "Dependency vulnerability coverage is incomplete (unresolved component versions)."
        )


def _evaluate_serialization_scan(
    scan: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 2: evaluate artifact-level serialization scan results.

    A CRITICAL/HIGH finding (e.g. dangerous pickle GLOBAL import) is a hard
    blocker — an artifact that executes arbitrary code on load cannot be adopted
    regardless of other scores.  MEDIUM/LOW findings cap at APPROVE_WITH_CONDITIONS
    (worth reviewing before production use).
    """
    if scan is None:
        evidence_gaps.append(
            "Serialization safety scan not available "
            "(register with a local artifact file to enable)."
        )
        return

    status = str(scan.get("status") or "").upper()
    if status in ("NO_FILE", "UNSUPPORTED_FORMAT"):
        evidence_gaps.append(
            "Serialization safety scan could not be completed "
            f"(status: {scan.get('status')})."
        )
        return
    if status == "SCAN_ERROR":
        evidence_gaps.append("Serialization scan encountered an error.")
        _cap(
            caps,
            AdoptionVerdict.INSUFFICIENT_EVIDENCE,
            "serialization_scan",
            "Serialization scan failed — artifact integrity could not be verified.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        return

    by_sev = {str(k).upper(): v for k, v in (scan.get("by_severity") or {}).items()}
    if by_sev.get("CRITICAL"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "serialization_scan",
            f"{by_sev['CRITICAL']} CRITICAL serialization threat(s) detected in model artifact "
            "(dangerous code execution pattern in pickle stream).",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_sev.get("HIGH"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "serialization_scan",
            f"{by_sev['HIGH']} HIGH serialization threat(s) detected in model artifact.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_sev.get("MEDIUM"):
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "serialization_scan",
            f"{by_sev['MEDIUM']} MEDIUM serialization anomaly(ies) in model artifact "
            "(review before production use).",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        conditions.append(
            "Review medium-severity serialization anomalies and confirm they are benign."
        )
    if by_sev.get("LOW") and not any(v for k, v in by_sev.items() if k in ("CRITICAL", "HIGH", "MEDIUM")):
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "serialization_scan",
            f"{by_sev['LOW']} LOW-severity unknown module import(s) in model artifact.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        conditions.append(
            "Verify low-severity unknown module imports in the artifact are expected."
        )


def _evaluate_weight_inspection(
    inspection: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 5: weight/tensor header inspection (LOCALLY_OBSERVED artifact evidence).

    The inspector reads file headers only — no tensors are loaded.  A successful
    inspection adds LOCALLY_OBSERVED evidence about the model's actual architecture.
    Errors / unsupported formats are gaps, not failures (absence of inspection ≠
    absence of a problem).
    """
    if inspection is None:
        evidence_gaps.append(
            "Weight inspection not available "
            "(register with a local artifact file in safetensors or GGUF format to enable)."
        )
        return

    status = str(inspection.get("status") or "")
    fmt = inspection.get("format_detected", "unknown")

    if status == "NO_FILE":
        evidence_gaps.append(
            "No local artifact file was available for weight inspection."
        )
        return

    if status == "UNSUPPORTED_FORMAT":
        evidence_gaps.append(
            f"Weight inspection not supported for format '{fmt}'. "
            "Safetensors and GGUF are supported."
        )
        return

    if status == "INSPECTION_ERROR":
        evidence_gaps.append(
            f"Weight inspection encountered an error ({inspection.get('error', '')[:120]}). "
            "Artifact-level architecture facts could not be derived."
        )
        _cap(
            caps,
            AdoptionVerdict.INSUFFICIENT_EVIDENCE,
            "weight_inspection",
            "Weight inspection failed — artifact architecture facts unavailable.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        return

    if status == "HEADER_ONLY":
        # PyTorch/ONNX: format detected but no architecture facts derived
        evidence_gaps.append(
            f"Weight inspection for format '{fmt}' returned header-only results. "
            "Architecture facts are not derived for this format."
        )
        return

    # STATUS_INSPECTED — positive, no cap needed; facts flow through fact_reconciler


def _evaluate_lineage(
    lineage: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 5: base-model lineage evaluation.

    An INCONSISTENT architecture cross-check (declared model_type ≠ derived
    tensor-name architecture) is the strongest lineage signal — it means the
    artifact bytes likely do not correspond to the metadata.
    """
    if lineage is None:
        evidence_gaps.append("Base-model lineage could not be derived.")
        return

    arch_consistency = str(lineage.get("architecture_consistency") or "UNVERIFIABLE")
    if arch_consistency == "INCONSISTENT":
        lineage.get("architecture_consistency")
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "lineage_arch_inconsistency",
            "Declared architecture family is INCONSISTENT with the tensor-name-derived "
            "architecture — the artifact bytes do not match the declared model type.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )

    flags = lineage.get("flags") or []
    if flags:
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "lineage_merge_model",
            f"Merge-model indicators detected: {'; '.join(flags[:3])}. "
            "Merge models carry lineage from multiple sources; verify all parent models.",
            origin=EvidenceOrigin.PROVIDER_DECLARED,
        )
        conditions.append(
            "Verify all parent model identities and their individual assurance postures."
        )

    if lineage.get("lineage_completeness") == "UNKNOWN":
        evidence_gaps.append(
            "Base model ancestry is unknown — no base_model field found in metadata "
            "or HF model card."
        )


def _evaluate_fact_reconciliation(
    reconciliation: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 5: declared-vs-derived fact reconciliation.

    Contradictions between provider-declared metadata and locally-observed
    artifact facts are the strongest signal of metadata fraud or artifact
    substitution.  Severity drives the verdict cap.
    """
    if reconciliation is None:
        evidence_gaps.append(
            "Fact reconciliation not available (requires weight inspection)."
        )
        return

    for contradiction in reconciliation.get("contradictions") or []:
        fact = contradiction.get("fact_name", "unknown")
        sev = str(contradiction.get("severity") or "MEDIUM").upper()
        decl = contradiction.get("declared_value")
        deriv = contradiction.get("derived_value")
        desc = contradiction.get("description", "")

        msg = (
            f"Declared {fact} ({decl!r}) CONTRADICTS locally-observed value "
            f"({deriv!r}). {desc}"
        )

        if sev == "CRITICAL":
            _cap(
                caps,
                AdoptionVerdict.DO_NOT_APPROVE,
                f"reconciliation_contradiction_{fact}",
                msg,
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
        elif sev == "HIGH":
            _cap(
                caps,
                AdoptionVerdict.DO_NOT_APPROVE,
                f"reconciliation_contradiction_{fact}",
                msg,
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
        elif sev == "MEDIUM":
            _cap(
                caps,
                AdoptionVerdict.PILOT_ONLY,
                f"reconciliation_contradiction_{fact}",
                msg,
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
            conditions.append(
                f"Investigate {fact} discrepancy (declared: {decl!r}, "
                f"observed: {deriv!r}) before production deployment."
            )
        else:
            _cap(
                caps,
                AdoptionVerdict.APPROVE_WITH_CONDITIONS,
                f"reconciliation_contradiction_{fact}",
                msg,
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
            conditions.append(f"Correct metadata inaccuracy for {fact!r}.")

    pir = reconciliation.get("provenance_independence_ratio", 0.0)
    if isinstance(pir, (int, float)) and pir < 0.25:
        evidence_gaps.append(
            f"Low provenance independence ratio ({pir:.0%}): most decision-driving "
            "facts rest on provider-declared or user-entered evidence. "
            "Run weight inspection and Sigstore verification to raise this ratio."
        )


def _evaluate_behavioral_probes(
    probes: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 2: evaluate live behavioral probe results.

    Probe failures demonstrate that the model's safety boundaries can be
    bypassed at runtime — these are observed behavioral threats, not posture
    gaps, so they block adoption at the same level as active risk findings.
    """
    if probes is None:
        evidence_gaps.append(
            "Behavioral safety evaluation not available "
            "(provide endpoint_url in the triage request to enable)."
        )
        return

    status = str(probes.get("status") or "")
    if status in ("NO_ENDPOINT", "ENDPOINT_ERROR"):
        evidence_gaps.append(
            f"Behavioral probe could not reach the model endpoint (status: {status})."
        )
        if status == "ENDPOINT_ERROR":
            _cap(
                caps,
                AdoptionVerdict.INSUFFICIENT_EVIDENCE,
                "behavioral_probes",
                "All behavioral probes failed to reach the endpoint — live evaluation incomplete.",
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
        return

    by_sev = {str(k).upper(): v for k, v in (probes.get("by_severity") or {}).items()}
    failures = int(probes.get("probe_failures") or 0)

    if by_sev.get("CRITICAL"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "behavioral_probes",
            f"{by_sev['CRITICAL']} CRITICAL behavioral probe(s) FAILED — "
            "model demonstrates critical safety-boundary violations at runtime.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_sev.get("HIGH"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "behavioral_probes",
            f"{by_sev['HIGH']} HIGH behavioral probe(s) FAILED — "
            "model safety controls can be bypassed.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
    if by_sev.get("MEDIUM"):
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "behavioral_probes",
            f"{by_sev['MEDIUM']} MEDIUM behavioral probe(s) FAILED — "
            "model may disclose system context or exhibit partial safety bypasses.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
        )
        conditions.append(
            "Review medium-severity behavioral probe failures before production deployment."
        )

    if probes.get("status") == "PARTIAL":
        evidence_gaps.append(
            "Behavioral probe suite was partial — "
            f"only {probes.get('probes_run', 0)} of {len(probes.get('probe_results', []))} probes completed."
        )

    if failures == 0 and status == "COMPLETED":
        # All probes passed — record as a positive signal in conditions/gaps but
        # do NOT add a cap (passing probes improves confidence, not verdict floor).
        pass


def _evaluate_redteam(
    redteam: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 4: evaluate full red-team evaluation results (garak / PyRIT).

    Red-team findings are deeper than the 10 built-in probes — they reflect
    garak's 120+ adversarial probes across prompt injection, jailbreak, data
    leakage, harmful content, and more.  Severity caps follow the same
    threshold logic as behavioral probes, with per-finding granularity.
    """
    if redteam is None:
        evidence_gaps.append(
            "Full red-team evaluation not available "
            "(use POST /v1/interop/models/{id}/redteam to run garak/PyRIT)."
        )
        return

    status = str(redteam.get("status") or "")
    backend = str(redteam.get("backend") or "garak")

    if status == "TOOL_NOT_INSTALLED":
        evidence_gaps.append(
            f"Red-team tool ({backend}) is not installed on this AIAF instance — "
            "evaluation skipped."
        )
        return

    if status in ("NO_ENDPOINT", "ENDPOINT_ERROR"):
        evidence_gaps.append(
            f"Red-team evaluation could not reach the model endpoint (status: {status})."
        )
        if status == "ENDPOINT_ERROR":
            _cap(
                caps,
                AdoptionVerdict.INSUFFICIENT_EVIDENCE,
                "redteam",
                f"Red-team evaluation ({backend}) could not connect to the endpoint — "
                "live evaluation incomplete.",
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
        return

    if status in ("ERROR", "NOT_IMPLEMENTED"):
        evidence_gaps.append(
            f"Red-team evaluation failed or is not yet implemented for backend={backend!r}."
        )
        return

    {str(k).upper(): v for k, v in (redteam.get("by_severity") or {}).items()}
    findings = redteam.get("findings") or []
    total_failures = int(redteam.get("total_failures") or 0)

    # Apply per-finding caps so the reason message includes the specific probe family.
    for finding in findings:
        if finding.get("failures", 0) == 0:
            continue
        sev = str(finding.get("severity") or "MEDIUM").upper()
        fam = finding.get("probe_family", "unknown")
        cat = finding.get("category", "unknown")
        owasp = finding.get("owasp_ref", "")
        rate_pct = round(finding.get("failure_rate", 0) * 100, 1)

        msg = (
            f"garak [{fam}] {finding['failures']}/{finding['total_probes']} probes FAILED "
            f"({rate_pct}% failure rate) — {finding.get('description', cat)} "
            f"[{owasp}]."
        )

        if sev == "CRITICAL":
            _cap(caps, AdoptionVerdict.DO_NOT_APPROVE, f"redteam_{fam}", msg,
                 origin=EvidenceOrigin.LOCALLY_OBSERVED)
        elif sev == "HIGH":
            _cap(caps, AdoptionVerdict.DO_NOT_APPROVE, f"redteam_{fam}", msg,
                 origin=EvidenceOrigin.LOCALLY_OBSERVED)
        elif sev == "MEDIUM":
            _cap(caps, AdoptionVerdict.PILOT_ONLY, f"redteam_{fam}", msg,
                 origin=EvidenceOrigin.LOCALLY_OBSERVED)
            conditions.append(
                f"Review {fam} red-team findings ({finding['failures']} failure(s)) "
                "before production deployment."
            )

    if status == "PARTIAL":
        evidence_gaps.append(
            f"Red-team evaluation was partial — "
            f"only {redteam.get('total_probes_run', 0)} probes completed. "
            "Re-run with a longer timeout for complete results."
        )

    if total_failures == 0 and status == "COMPLETED":
        pass  # All probes passed — positive signal, no cap needed.


def _evaluate_mcp_scan(
    mcp_scan: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 6: evaluate MCP tool supply-chain scan results.

    Tool descriptor content is PROVIDER_DECLARED; scan findings are
    LOCALLY_OBSERVED (AIAF derived them from the descriptor bytes).
    Rug-pull diffs are LOCALLY_OBSERVED meta-evidence.
    """
    if mcp_scan is None:
        return

    by_sev = {str(k).upper(): v for k, v in (mcp_scan.get("by_severity") or {}).items()}
    status = str(mcp_scan.get("status") or "")

    if mcp_scan.get("rug_pull_detected"):
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "mcp_rug_pull",
            "MCP rug-pull detected: tool descriptors changed between scans.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
            refs=["OWASP-LLM07"],
        )

    if status == "UNSAFE_PATTERNS_FOUND":
        critical = int(by_sev.get("CRITICAL", 0))
        high = int(by_sev.get("HIGH", 0))
        if critical > 0 or high > 0:
            _cap(
                caps,
                AdoptionVerdict.DO_NOT_APPROVE,
                "mcp_injection",
                f"MCP tool descriptors contain injection patterns "
                f"(CRITICAL: {critical}, HIGH: {high}).",
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
                refs=["OWASP-LLM07", "AML.T0051"],
            )
        else:
            _cap(
                caps,
                AdoptionVerdict.PILOT_ONLY,
                "mcp_suspicious",
                "MCP tool descriptors contain suspicious patterns (MEDIUM/LOW severity).",
                origin=EvidenceOrigin.LOCALLY_OBSERVED,
            )
    elif status == "SUSPICIOUS":
        evidence_gaps.append(
            "MCP tool descriptor scan found low-severity patterns — review tool definitions."
        )
        conditions.append(
            "Review MCP tool descriptor suspicious patterns before production deployment."
        )


def _evaluate_backdoor_heuristics(
    backdoor: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    """Phase 6: evaluate backdoor/trojan heuristic analysis results.

    Findings are LOCALLY_OBSERVED (derived from weight/lineage/provenance
    metadata — no tensor execution required).
    """
    if backdoor is None:
        evidence_gaps.append(
            "Backdoor/trojan heuristic analysis not run "
            "(available at POST /v1/intake/triage when weights are present)."
        )
        return

    status = str(backdoor.get("status") or "")

    if status == "INSUFFICIENT_DATA":
        evidence_gaps.append(
            "Backdoor heuristic analysis had insufficient input data "
            "(weights, lineage, or provenance not available)."
        )
        return

    findings = backdoor.get("findings") or []
    by_sev = {str(k).upper(): v for k, v in (backdoor.get("by_severity") or {}).items()}

    if status == "HIGH_RISK":
        high = int(by_sev.get("HIGH", 0))
        top_finding = next(
            (f for f in findings if f.get("severity") == "HIGH"),
            findings[0] if findings else None,
        )
        detail = top_finding.get("description", "") if top_finding else ""
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "backdoor_high_risk",
            f"Backdoor heuristics found {high} HIGH-severity indicator(s). "
            f"Highest-risk signal: {detail}",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
            refs=["AML.T0018", "AML.T0020", "OWASP-LLM03"],
        )
    elif status == "SUSPICIOUS":
        medium = int(by_sev.get("MEDIUM", 0))
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "backdoor_suspicious",
            f"Backdoor heuristics found {medium} MEDIUM-severity indicator(s) — "
            "pilot only with enhanced monitoring; resolve weight provenance "
            "before production deployment.",
            origin=EvidenceOrigin.LOCALLY_OBSERVED,
            refs=["AML.T0018", "OWASP-LLM03"],
        )
        conditions.append(
            "Resolve backdoor/trojan heuristic findings before production deployment."
        )

    if backdoor.get("assessment_complete") is False:
        evidence_gaps.append(
            "Backdoor heuristic analysis was incomplete — "
            "provide weight_inspection + lineage + provenance for full coverage."
        )


def _evaluate_provenance(
    provenance: dict[str, Any],
    model_record: dict[str, Any],
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    if not provenance:
        evidence_gaps.append("No provenance assessment was available.")
        _cap(
            caps,
            AdoptionVerdict.INSUFFICIENT_EVIDENCE,
            "provenance",
            "Provenance could not be assessed.",
        )
        return

    risk_level = str(provenance.get("risk_level") or "").upper()
    score = provenance.get("provenance_score")
    if risk_level == "CRITICAL":
        _cap(
            caps,
            AdoptionVerdict.DO_NOT_APPROVE,
            "provenance",
            f"Provenance cannot be established (trust score {score}/100).",
        )
    elif risk_level == "HIGH":
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "provenance",
            f"Provenance trust is weak (trust score {score}/100).",
        )
    elif risk_level == "MEDIUM":
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "provenance",
            f"Provenance trust is moderate (trust score {score}/100).",
        )
        conditions.append("Strengthen provenance evidence (signed attestation / verified identity).")

    # Trust caps emitted by the provenance scorer surface specific missing,
    # verification-grade evidence — each is an adoption-relevant gap.
    for trust_cap in provenance.get("trust_caps") or []:
        if not isinstance(trust_cap, dict):
            continue
        gate = trust_cap.get("gate", "")
        if "no_verified_signed_provenance" in gate:
            _cap(
                caps,
                AdoptionVerdict.PILOT_ONLY,
                "unverified_provenance",
                "No verified signed provenance attestation exists.",
                origin=EvidenceOrigin.USER_ENTERED,
            )
            conditions.append("Obtain and verify a signed provenance attestation.")
            evidence_gaps.append("Signed, verified provenance attestation.")


def _evaluate_identity_origin(
    ledger,
    provenance: dict[str, Any],
    caps: list[dict[str, Any]],
    evidence_gaps: list[str],
) -> None:
    """Origin weighting: identity is only as strong as its weakest source.

    A ``publisher``/``source`` backed only by an operator's keystrokes
    (``user_entered``) or the publisher's own claim (``provider_declared``)
    cannot lift a model to a clean approval, no matter how high other scores
    are. This is the core differentiator: *who said so* changes the verdict.
    A verified attestation independently binds identity, so it overrides the
    fact that the operator typed the source URL by hand.
    """
    identity_verified = any(
        coerce_origin(fact.get("origin")) == EvidenceOrigin.INDEPENDENTLY_VERIFIED
        and fact.get("name") in _IDENTITY_VERIFYING_FACTS
        for fact in ledger.to_list()
    )
    if identity_verified:
        return
    weakest = ledger.weakest_origin(_IDENTITY_FACTS)
    if weakest is None:
        return
    if not is_verified_grade(weakest):
        _cap(
            caps,
            AdoptionVerdict.PILOT_ONLY,
            "identity_origin",
            f"Model identity rests on {weakest.value.replace('_', '-')} evidence, "
            "which is not independently verified.",
            origin=weakest,
        )
        evidence_gaps.append(
            "Independently verified model identity (publisher/source)."
        )


def _evaluate_governance(
    governance: dict[str, Any],
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    if not governance:
        return
    gaps = governance.get("gaps") or []
    if gaps:
        titles = sorted({str(g.get("title") or g.get("id")) for g in gaps if isinstance(g, dict)})
        _cap(
            caps,
            AdoptionVerdict.APPROVE_WITH_CONDITIONS,
            "governance",
            f"{len(gaps)} required assurance control(s) are unmet.",
            refs=titles[:8],
        )
        conditions.append("Close open assurance control gaps and submit reviewed evidence.")
        for gap in gaps:
            if not isinstance(gap, dict):
                continue
            for missing in gap.get("missing_evidence") or []:
                evidence_gaps.append(f"{gap.get('id', 'control')}: {missing}")


def _evaluate_completeness(
    risk_record: dict[str, Any],
    provenance: dict[str, Any],
    vuln: dict[str, Any],
    serialization_scan: dict[str, Any] | None,
    behavioral_probes: dict[str, Any] | None,
    redteam_results: dict[str, Any] | None,
    weight_inspection: dict[str, Any] | None,
    caps: list[dict[str, Any]],
    evidence_gaps: list[str],
) -> None:
    incomplete = []
    if provenance and provenance.get("assessment_complete") is False:
        incomplete.append("provenance")
    if vuln and vuln.get("assessment_complete") is False:
        incomplete.append("dependency vulnerability scan")
    if serialization_scan and serialization_scan.get("assessment_complete") is False:
        incomplete.append("serialization scan")
    if weight_inspection and weight_inspection.get("assessment_complete") is False:
        incomplete.append("weight inspection (format not supported or error)")
    if behavioral_probes and behavioral_probes.get("assessment_complete") is False:
        incomplete.append("behavioral probe suite")
    if redteam_results and redteam_results.get("assessment_complete") is False:
        incomplete.append("red-team evaluation (partial results only)")
    confidence = provenance.get("confidence")
    if isinstance(confidence, (int, float)) and confidence < _LOW_CONFIDENCE_FLOOR:
        incomplete.append("provenance confidence below decision floor")
    if incomplete:
        _cap(
            caps,
            AdoptionVerdict.INSUFFICIENT_EVIDENCE,
            "incomplete_assessment",
            "Assessment incomplete: " + ", ".join(incomplete) + ".",
        )
        for item in incomplete:
            evidence_gaps.append(f"Complete evidence for: {item}.")


def _evaluate_org_policy(
    policy: dict[str, Any],
    caps: list[dict[str, Any]],
    conditions: list[str],
    evidence_gaps: list[str],
) -> None:
    if not policy:
        return
    for cap in policy.get("caps") or []:
        if not isinstance(cap, dict):
            continue
        verdict = cap.get("verdict")
        if not verdict:
            continue
        _cap(
            caps,
            AdoptionVerdict(str(verdict)),
            str(cap.get("category") or "org_policy"),
            str(cap.get("reason") or "Organization policy restricted approval scope."),
            origin=cap.get("origin"),
            refs=[str(ref) for ref in (cap.get("refs") or [])],
        )
    conditions.extend(str(item) for item in (policy.get("conditions") or []) if item)
    evidence_gaps.extend(
        str(item) for item in (policy.get("evidence_gaps") or []) if item
    )


def _worst_verdict(caps: list[dict[str, Any]]) -> AdoptionVerdict:
    if not caps:
        return AdoptionVerdict.APPROVE_FOR_SCOPED_USE
    worst = min(caps, key=lambda cap: cap["_rank"])
    return AdoptionVerdict(worst["verdict"])


def _decision_confidence(
    provenance: dict[str, Any],
    risk_record: dict[str, Any],
    vuln: dict[str, Any],
    serialization_scan: dict[str, Any] | None = None,
    behavioral_probes: dict[str, Any] | None = None,
    redteam_results: dict[str, Any] | None = None,
) -> float:
    """Lowest confidence across the contributing assessments (conservative)."""
    candidates: list[float] = []
    prov_conf = provenance.get("confidence")
    if isinstance(prov_conf, (int, float)):
        candidates.append(float(prov_conf))
    trust = risk_record.get("trustworthiness") or {}
    trust_conf = trust.get("confidence")
    if isinstance(trust_conf, (int, float)):
        candidates.append(float(trust_conf))
    if vuln and vuln.get("assessment_complete") is False:
        candidates.append(0.4)
    if serialization_scan and serialization_scan.get("assessment_complete") is False:
        candidates.append(0.4)
    if behavioral_probes and behavioral_probes.get("assessment_complete") is False:
        candidates.append(0.4)
    if redteam_results and redteam_results.get("assessment_complete") is False:
        candidates.append(0.5)
    if not candidates:
        return 0.0
    return round(max(0.0, min(1.0, min(candidates))), 3)


def _input_echo(
    risk_record: dict[str, Any],
    provenance: dict[str, Any],
    governance: dict[str, Any],
    vuln: dict[str, Any],
    serialization_scan: dict[str, Any] | None = None,
    behavioral_probes: dict[str, Any] | None = None,
    redteam_results: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    *,
    weight_inspection: dict[str, Any] | None = None,
    lineage: dict[str, Any] | None = None,
    fact_reconciliation: dict[str, Any] | None = None,
    mcp_scan: dict[str, Any] | None = None,
    backdoor_heuristics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    aggregation = risk_record.get("risk_aggregation") or {}
    trust = risk_record.get("trustworthiness") or {}
    policy = policy or {}
    policy_context = policy.get("context") or {}
    policy_posture = policy.get("posture") or {}
    rt = redteam_results or {}
    wi = weight_inspection or {}
    lin = lineage or {}
    rec = fact_reconciliation or {}
    mcp = mcp_scan or {}
    bh = backdoor_heuristics or {}
    wi_facts = wi.get("derived_facts") or {}
    return {
        "risk_score": risk_record.get("score"),
        "risk_severity": aggregation.get("severity"),
        "finding_count": aggregation.get("finding_count"),
        "provenance_score": provenance.get("provenance_score"),
        "provenance_risk_level": provenance.get("risk_level"),
        "provenance_confidence": provenance.get("confidence"),
        "trustworthiness_score": trust.get("trustworthiness_score"),
        "trustworthiness_level": trust.get("level"),
        "governance_status": governance.get("status"),
        "governance_open_gaps": len(governance.get("gaps") or []),
        "vulnerability_status": vuln.get("status"),
        "vulnerability_match_count": vuln.get("match_count"),
        "serialization_status": (serialization_scan or {}).get("status"),
        "serialization_match_count": (serialization_scan or {}).get("match_count"),
        "weight_inspection_status": wi.get("status"),
        "weight_inspection_format": wi.get("format_detected"),
        "weight_parameter_count": wi_facts.get("parameter_count_estimate"),
        "weight_architecture_family": wi_facts.get("architecture_family"),
        "weight_layer_count": wi_facts.get("layer_count"),
        "weight_hidden_size": wi_facts.get("hidden_size"),
        "weight_quantization": wi_facts.get("quantization"),
        "lineage_base_model": lin.get("base_model"),
        "lineage_depth": lin.get("lineage_depth"),
        "lineage_source": lin.get("lineage_source"),
        "lineage_arch_consistency": lin.get("architecture_consistency"),
        "lineage_flags": len(lin.get("flags") or []),
        "reconciliation_contradictions": rec.get("contradiction_count"),
        "reconciliation_confirmations": rec.get("confirmation_count"),
        "provenance_independence_ratio": rec.get("provenance_independence_ratio"),
        "behavioral_probe_status": (behavioral_probes or {}).get("status"),
        "behavioral_probe_failures": (behavioral_probes or {}).get("probe_failures"),
        "redteam_status": rt.get("status"),
        "redteam_backend": rt.get("backend"),
        "redteam_total_failures": rt.get("total_failures"),
        "redteam_families_run": len(rt.get("probe_families_requested") or []),
        "policy_use_case": policy_context.get("use_case"),
        "policy_data_classification": policy_context.get("data_classification"),
        "policy_deployment_exposure": policy_context.get("deployment_exposure"),
        "policy_posture_level": policy_posture.get("level"),
        "policy_missing_evidence_count": len(policy.get("missing_required_evidence") or []),
        "mcp_scan_status": mcp.get("status"),
        "mcp_rug_pull_detected": mcp.get("rug_pull_detected"),
        "mcp_tool_count": mcp.get("tool_count"),
        "mcp_injection_findings": len([
            f for f in (mcp.get("findings") or [])
            if f.get("type") not in {"rug_pull_change", "tool_added", "tool_removed"}
        ]),
        "backdoor_status": bh.get("status"),
        "backdoor_finding_count": bh.get("finding_count"),
        "backdoor_confidence": bh.get("confidence"),
    }


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered

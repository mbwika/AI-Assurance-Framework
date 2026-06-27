"""External Model Intake — adoption-triage API routes.

The intake endpoint is AIAF's "front door" for an unknown external model: given a
model that has already been registered (URL or file), it assembles the assurance
evidence AIAF already computes — uncertainty-aware provenance, the aggregated
risk findings, governance control coverage, and dependency-vulnerability state —
and returns a single graded **adoption verdict** with origin-tagged reasons and
an explicit list of evidence it could not obtain.
"""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..analysis.backdoor_heuristics import analyse as analyse_backdoor
from ..analysis.unknown_model_probe import probe_unknown_model
from ..core import (
    GovernanceEngine,
    RiskEngine,
    VulnerabilityIntelligenceEngine,
    build_unknown_model_assurance,
    recommend_adoption,
)
from ..core.probe_engine import run_probes
from ..registry import assess_provenance_v2
from ..registry.fact_reconciler import reconcile as reconcile_facts
from ..registry.lineage_graph import derive_lineage
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/intake", tags=["intake"])


class TriageRequest(BaseModel):
    model_id: str
    persist: bool = True
    policy_context: dict[str, Any] | None = None
    endpoint_url: str | None = None
    endpoint_api_key: str | None = None
    endpoint_model_name: str = "default"
    mcp_server_id: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_from_model(rec: dict[str, Any]) -> dict[str, Any]:
    """Build a risk/governance artifact view from a registered model record.

    Assessment inputs an operator attached at registration (e.g.
    ``model_risk_profile``, ``domain``, ``has_*`` evidence flags) live in
    ``metadata``; spreading it lets the existing analyzers consume them. The
    identity/integrity fields and an empty ``content`` are set explicitly.
    """
    metadata = rec.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    artifact: dict[str, Any] = dict(metadata)
    artifact.update(
        {
            "id": rec.get("model_id"),
            "model_id": rec.get("model_id"),
            "content": "",
            "dependencies": rec.get("dependencies", []),
            "metadata": metadata,
            "provenance_attestation_verifications": metadata.get(
                "provenance_attestation_verifications"
            ),
        }
    )
    return artifact


def _append_probe_facts(rec: dict[str, Any], probe_result: dict[str, Any]) -> None:
    """Tag behavioral probe findings into the model's evidence ledger (in-place)."""
    from ..registry.evidence_origin import EvidenceOrigin, ledger_from_list

    metadata = dict(rec.get("metadata") or {})
    ledger = ledger_from_list(metadata.get("evidence_ledger"))
    ledger.add(
        "behavioral_probe_status",
        probe_result.get("status"),
        EvidenceOrigin.LOCALLY_OBSERVED,
        detail=(
            f"{probe_result.get('probe_failures', 0)} failure(s) "
            f"across {probe_result.get('probes_run', 0)} probes"
        ),
    )
    metadata["evidence_ledger"] = ledger.to_list()
    rec["metadata"] = metadata


def _persist_probe_results(
    store, rec: dict[str, Any], probe_result: dict[str, Any]
) -> None:
    """Persist behavioral probe results to the model record and audit log."""
    metadata = dict(rec.get("metadata") or {})
    metadata["behavioral_probe_results"] = probe_result
    rec["metadata"] = metadata
    store.save_model(rec)
    try:
        store.save_audit_log(
            {
                "event_type": "behavioral_probe",
                "artifact_id": rec.get("model_id"),
                "details": {
                    "status": probe_result.get("status"),
                    "probe_failures": probe_result.get("probe_failures"),
                    "probes_run": probe_result.get("probes_run"),
                },
            }
        )
    except Exception:
        pass


def _persist_recommendation(
    store, rec: dict[str, Any], recommendation: dict[str, Any]
) -> None:
    metadata = dict(rec.get("metadata") or {})
    metadata["adoption_recommendation"] = recommendation
    if recommendation.get("unknown_model_probe"):
        metadata["unknown_model_probe"] = recommendation["unknown_model_probe"]
    if recommendation.get("unknown_model_assurance"):
        metadata["unknown_model_assurance"] = recommendation["unknown_model_assurance"]
    rec["metadata"] = metadata
    store.save_model(rec)
    try:
        store.save_audit_log(
            {
                "event_type": "adoption_triage",
                "artifact_id": recommendation.get("model_id"),
                "details": recommendation,
            }
        )
    except Exception:
        pass
    try:
        store.save_metric(
            "adoption_verdict_rank",
            float(recommendation.get("verdict_rank", 0)),
            {
                "artifact_id": recommendation.get("model_id"),
                "model_id": recommendation.get("model_id"),
                "verdict": recommendation.get("verdict"),
                "confidence": recommendation.get("confidence"),
                "scoring_version": recommendation.get("scoring_version"),
            },
        )
    except Exception:
        pass


@router.post("/triage")
def triage_model(req: TriageRequest, api_key: str = Depends(get_api_key)):
    """Run adoption triage for a registered model and return the verdict."""
    store = get_store()
    rec = store.get_model(req.model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")

    artifact = _artifact_from_model(rec)
    risk_record = RiskEngine(datastore=store).analyze(artifact)
    governance = GovernanceEngine(datastore=store).evaluate(artifact)
    provenance = assess_provenance_v2(rec)

    metadata = rec.get("metadata") or {}
    vuln = metadata.get("vulnerability_scan") or rec.get("vulnerability_scan")
    if not vuln:
        vuln = VulnerabilityIntelligenceEngine(store).scan_model(req.model_id)

    # Phase 2: serialization scan result stored at registration time.
    serial_scan = metadata.get("serialization_scan") or None

    # Phase 5: weight/tensor header inspection — only trust a previously
    # persisted inspection result. Triage does not reopen artifact paths from
    # model metadata.
    weight_insp = metadata.get("weight_inspection") or None

    # Phase 5: lineage graph derivation.
    lineage = derive_lineage(rec, weight_inspection=weight_insp)

    # Phase 5: declared-vs-derived fact reconciliation.
    fact_rec = reconcile_facts(rec, weight_inspection=weight_insp, lineage=lineage)

    # Phase 2: behavioral probes — only if an endpoint was provided.
    if req.endpoint_url:
        behavioral = run_probes(
            req.endpoint_url,
            api_key=req.endpoint_api_key,
            model_name=req.endpoint_model_name,
        )
        _append_probe_facts(rec, behavioral)
        if req.persist:
            _persist_probe_results(store, rec, behavioral)
    else:
        behavioral = metadata.get("behavioral_probe_results") or None

    # Phase 4: full red-team evaluation — pulled from metadata if a background
    # job has already run (POST /v1/interop/models/{id}/redteam).
    redteam_results = metadata.get("redteam_results") or None

    # Phase 6a: MCP tool supply-chain scan — load stored scan if caller provided
    # a server_id that was previously registered via POST /v1/mcp/servers.
    mcp_scan: dict[str, Any] | None = None
    if req.mcp_server_id:
        mcp_record = store.get_model(f"mcp_server:{req.mcp_server_id}")
        if mcp_record:
            mcp_meta = mcp_record.get("metadata") or {}
            mcp_scan = mcp_meta.get("latest_scan") or None

    # Phase 6b: Backdoor/trojan heuristics — runs whenever weight_inspection,
    # lineage, or provenance are available; degrades gracefully otherwise.
    backdoor_result: dict[str, Any] | None = None
    if weight_insp is not None or lineage or provenance:
        backdoor_result = analyse_backdoor(
            rec,
            weight_inspection=weight_insp,
            lineage=lineage or None,
            provenance_assessment=provenance or None,
            fact_reconciliation=fact_rec or None,
        )
    unknown_model_probe = probe_unknown_model(
        rec,
        weight_inspection=weight_insp,
        fact_reconciliation=fact_rec,
        endpoint_url=req.endpoint_url,
        endpoint_api_key=req.endpoint_api_key,
        endpoint_model_name=req.endpoint_model_name,
    )

    recommendation = recommend_adoption(
        rec,
        risk_record=risk_record,
        provenance_assessment=provenance,
        governance_summary=governance,
        vulnerability_scan=vuln,
        serialization_scan=serial_scan,
        behavioral_probes=behavioral,
        redteam_results=redteam_results,
        policy_context=req.policy_context,
        weight_inspection=weight_insp,
        lineage=lineage,
        fact_reconciliation=fact_rec,
        mcp_scan=mcp_scan,
        backdoor_heuristics=backdoor_result,
    )
    recommendation["unknown_model_assurance"] = build_unknown_model_assurance(
        rec,
        recommendation=recommendation,
        provenance_assessment=provenance,
        serialization_scan=serial_scan,
        weight_inspection=weight_insp,
        lineage=lineage,
        fact_reconciliation=fact_rec,
        vulnerability_scan=vuln,
        backdoor_heuristics=backdoor_result,
        unknown_model_probe=unknown_model_probe,
    )
    recommendation["unknown_model_probe"] = unknown_model_probe
    recommendation["generated_at"] = _utc_now()
    if req.policy_context:
        recommendation["policy_context"] = req.policy_context

    if req.persist:
        _persist_recommendation(store, rec, recommendation)

    return recommendation


def _persist_weight_inspection(
    store, rec: dict[str, Any], result: dict[str, Any]
) -> None:
    metadata = dict(rec.get("metadata") or {})
    metadata["weight_inspection"] = result
    rec["metadata"] = metadata
    store.save_model(rec)
    try:
        store.save_audit_log(
            {
                "event_type": "weight_inspection",
                "artifact_id": rec.get("model_id"),
                "details": {
                    "status": result.get("status"),
                    "format_detected": result.get("format_detected"),
                    "tensor_count": result.get("tensor_count"),
                },
            }
        )
    except Exception:
        pass


@router.get("/{model_id}")
def latest_recommendation(model_id: str, api_key: str = Depends(get_api_key)):
    """Return the most recent persisted adoption verdict for a model."""
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    recommendation = (rec.get("metadata") or {}).get("adoption_recommendation")
    if not recommendation:
        raise HTTPException(
            status_code=404,
            detail="No adoption recommendation yet; run POST /v1/intake/triage",
        )
    return recommendation

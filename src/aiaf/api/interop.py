"""Interoperability API routes (Phase 3 + Phase 4).

``POST /v1/interop/models/{model_id}/enrich/hf``
    Pull metadata from the HuggingFace model card and config.json.
    Elevates operator-typed facts from USER_ENTERED to PROVIDER_DECLARED.

``GET /v1/interop/models/{model_id}/bom/cyclonedx``
    Export a CycloneDX 1.7 ML-BOM suitable for downstream SBOM scanners.

``POST /v1/interop/models/{model_id}/verify/sigstore``
    Verify a Sigstore bundle; on success adds sigstore_verification fact
    (INDEPENDENTLY_VERIFIED) lifting the PILOT_ONLY verdict ceiling.

``POST /v1/interop/models/{model_id}/redteam``
    Launch a background full red-team evaluation (garak / PyRIT) against a
    live OpenAI-compatible endpoint.  Returns a job_id immediately; results
    are persisted to the model's metadata and picked up by the next triage.

``GET /v1/interop/models/{model_id}/redteam/{job_id}``
    Poll the status and results of a red-team evaluation job.

``GET /v1/interop/models/{model_id}/redteam``
    List all red-team evaluation jobs for a model.
"""

import threading
import uuid
from collections import deque as _deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..registry.hf_model_card import (
    fetch_from_hub,
    enrich_ledger,
    STATUS_FETCH_FAILED,
    STATUS_NO_CARD,
)
from ..registry.sigstore_verifier import (
    verify_resolved_file,
    STATUS_VERIFIED,
    STATUS_NOT_SIGNED,
    STATUS_NOT_AVAILABLE,
)
from ..registry.cyclonedx_bom import export_bom, import_bom
from ..registry.evidence_origin import EvidenceOrigin, ledger_from_list
from ..core.redteam_engine import (
    run_redteam,
    BACKEND_GARAK,
    BACKEND_PYRIT,
    PROBE_FAMILIES_QUICK,
    PROBE_FAMILIES_FULL,
    STATUS_TOOL_NOT_INSTALLED,
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_ERROR,
)
from .models import get_api_key, get_store

router = APIRouter(prefix="/v1/interop", tags=["interop"])

# ---------------------------------------------------------------------------
# In-process red-team job registry (mirrors the pattern in api/models.py)
# ---------------------------------------------------------------------------

_RT_JOBS: Dict[str, Dict[str, Any]] = {}
_RT_JOBS_LOCK = threading.Lock()
_RT_LOG_MAX = 200


def _rt_job_init(job_id: str, model_id: str) -> None:
    with _RT_JOBS_LOCK:
        _RT_JOBS[job_id] = {
            "job_id": job_id,
            "model_id": model_id,
            "status": "PENDING",
            "result": None,
            "logs": _deque(maxlen=_RT_LOG_MAX),
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }


def _rt_job_update(job_id: str, status: str, result: Optional[Dict] = None) -> None:
    with _RT_JOBS_LOCK:
        job = _RT_JOBS.get(job_id)
        if job:
            job["status"] = status
            job["updated_at"] = _utc_now()
            if result is not None:
                job["result"] = result


def _rt_job_log(job_id: str, line: str) -> None:
    with _RT_JOBS_LOCK:
        job = _RT_JOBS.get(job_id)
        if job:
            job["logs"].append(line)


def _rt_job_get(job_id: str) -> Optional[Dict[str, Any]]:
    with _RT_JOBS_LOCK:
        job = _RT_JOBS.get(job_id)
        if job:
            return {**job, "logs": list(job["logs"])}
    return None


def _rt_jobs_for_model(model_id: str) -> List[Dict[str, Any]]:
    with _RT_JOBS_LOCK:
        return [
            {**j, "logs": list(j["logs"])}
            for j in _RT_JOBS.values()
            if j["model_id"] == model_id
        ]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _approved_sigstore_roots() -> List[Path]:
    roots = [(_project_root() / "data").resolve()]
    return roots


def _resolve_sigstore_path(path_value: str) -> Optional[Path]:
    raw_path = str(path_value).strip()
    if not raw_path:
        return None

    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = _project_root() / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None

    if not resolved.is_file():
        return None

    for root in _approved_sigstore_roots():
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    return None


def _stored_sigstore_artifact_path(rec: Dict[str, Any]) -> Optional[str]:
    metadata = rec.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    return (
        metadata.get("artifact_path")
        or metadata.get("artifact_file_path")
        or metadata.get("file_path")
        or rec.get("file_path")
    )


def _stored_sigstore_bundle_path(rec: Dict[str, Any]) -> Optional[str]:
    metadata = rec.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    return metadata.get("sigstore_bundle_path") or metadata.get("bundle_path")


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class HfEnrichRequest(BaseModel):
    repo_id: Optional[str] = None
    hf_token: Optional[str] = None


class SigstoreVerifyRequest(BaseModel):
    expected_identity: Optional[str] = None
    expected_issuer: Optional[str] = None


class RedTeamRequest(BaseModel):
    endpoint_url: str
    backend: str = BACKEND_GARAK
    endpoint_api_key: Optional[str] = None
    model_name: str = "default"
    probe_families: Optional[List[str]] = None
    depth: str = "quick"
    timeout: int = 600


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/models/{model_id}/enrich/hf")
def enrich_from_hf(
    model_id: str,
    req: HfEnrichRequest,
    api_key: str = Depends(get_api_key),
):
    """Pull HuggingFace model card metadata and update the evidence ledger.

    Uses ``req.repo_id`` if supplied; otherwise derives the repo_id from the
    model's registered ``source_url`` (must be a huggingface.co URL).  The
    enriched facts are tagged ``PROVIDER_DECLARED`` and persisted immediately.
    """
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")

    repo_id = req.repo_id or _repo_id_from_record(rec)
    if not repo_id:
        raise HTTPException(
            status_code=422,
            detail=(
                "Cannot determine HuggingFace repo_id. "
                "Provide repo_id in the request body or register the model "
                "with a huggingface.co source_url."
            ),
        )

    card_data = fetch_from_hub(repo_id, token=req.hf_token)

    metadata = dict(rec.get("metadata") or {})
    ledger = ledger_from_list(metadata.get("evidence_ledger"))

    enrich_ledger(card_data, ledger)
    metadata["evidence_ledger"] = ledger.to_list()
    metadata["hf_model_card"] = card_data
    rec["metadata"] = metadata

    # Propagate top-level fields if not already set.
    if card_data.get("publisher") and not rec.get("publisher"):
        rec["publisher"] = card_data["publisher"]
    if card_data.get("license") and not rec.get("license"):
        rec["license"] = card_data["license"]

    store.save_model(rec)
    try:
        store.save_audit_log(
            {
                "event_type": "hf_enrichment",
                "artifact_id": model_id,
                "details": {
                    "repo_id": repo_id,
                    "status": card_data.get("status"),
                    "facts_added": [
                        f for f in ("license", "pipeline_tag", "model_type",
                                    "publisher", "language", "base_model")
                        if card_data.get(f)
                    ],
                },
            }
        )
    except Exception:
        pass

    return {
        "model_id": model_id,
        "repo_id": repo_id,
        "status": card_data.get("status"),
        "facts_added": {
            k: card_data[k]
            for k in ("license", "pipeline_tag", "model_type", "publisher",
                      "language", "base_model", "architectures", "tags")
            if card_data.get(k) is not None
        },
        "errors": card_data.get("errors") or [],
        "enriched_at": _utc_now(),
    }


@router.get("/models/{model_id}/bom/cyclonedx")
def get_cyclonedx_bom(
    model_id: str,
    api_key: str = Depends(get_api_key),
):
    """Export a CycloneDX 1.7 ML-BOM for a registered model."""
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    bom = export_bom(rec)
    return JSONResponse(
        content=bom,
        media_type="application/vnd.cyclonedx+json; version=1.7",
        headers={"Content-Disposition": f'attachment; filename="aiaf-bom-{model_id[:8]}.cdx.json"'},
    )


@router.post("/models/{model_id}/verify/sigstore")
def verify_sigstore_signature(
    model_id: str,
    req: SigstoreVerifyRequest,
    api_key: str = Depends(get_api_key),
):
    """Verify a Sigstore bundle for the model artifact.

    On successful verification, adds a ``sigstore_verification`` fact tagged
    ``INDEPENDENTLY_VERIFIED`` to the model's evidence ledger.  The adoption
    engine treats this as identity verification, lifting the ``PILOT_ONLY``
    ceiling imposed by unverified identity.
    """
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")

    artifact_path = _stored_sigstore_artifact_path(rec) or ""
    if not artifact_path:
        raise HTTPException(
            status_code=422,
            detail=(
                "This model does not have a stored artifact path. "
                "Register it with an AIAF-managed local artifact path before "
                "running Sigstore verification."
            ),
        )

    resolved_artifact_path = _resolve_sigstore_path(artifact_path)
    if resolved_artifact_path is None:
        raise HTTPException(
            status_code=422,
            detail="artifact_path must reference an existing file under AIAF-managed artifact storage.",
        )

    resolved_bundle_path: Optional[str] = None
    stored_bundle_path = _stored_sigstore_bundle_path(rec)
    if stored_bundle_path is not None:
        bundle_path = _resolve_sigstore_path(stored_bundle_path)
        if bundle_path is None:
            raise HTTPException(
                status_code=422,
                detail="bundle_path must reference an existing file under AIAF-managed artifact storage.",
            )
        resolved_bundle_path = str(bundle_path)

    result = verify_resolved_file(
        resolved_artifact_path,
        bundle_path=Path(resolved_bundle_path) if resolved_bundle_path else None,
        expected_identity=req.expected_identity,
        expected_issuer=req.expected_issuer,
    )

    if result.get("verified"):
        _record_sigstore_verification(store, rec, result)

    return {
        "model_id": model_id,
        **result,
    }


# ---------------------------------------------------------------------------
# Red-team evaluation endpoints (Phase 4)
# ---------------------------------------------------------------------------


@router.post("/models/{model_id}/redteam", status_code=202)
def start_redteam(
    model_id: str,
    req: RedTeamRequest,
    api_key: str = Depends(get_api_key),
):
    """Launch a full red-team evaluation as a background job.

    The evaluation runs garak (or PyRIT) against ``req.endpoint_url`` — an
    OpenAI-compatible chat completions endpoint.  Results are persisted to the
    model's metadata; the next call to ``POST /v1/intake/triage`` will
    automatically include them in the adoption verdict.

    Returns immediately with ``job_id``; poll
    ``GET /v1/interop/models/{model_id}/redteam/{job_id}`` for status.

    Depth options
    -------------
    ``"quick"``  (default) — 4 probe families: promptinject, encoding, dan, leakage.
                 Typically 2–10 minutes depending on endpoint latency.
    ``"full"``   — all supported probe families.  Can take 30–90 minutes.
    """
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")

    job_id = str(uuid.uuid4())
    _rt_job_init(job_id, model_id)
    _rt_job_log(job_id, f"[AIAF] Red-team job {job_id} queued "
                         f"backend={req.backend} depth={req.depth} "
                         f"endpoint={req.endpoint_url}")

    def _run() -> None:
        _rt_job_update(job_id, "RUNNING")
        _rt_job_log(job_id, "[AIAF] Starting red-team evaluation…")
        try:
            result = run_redteam(
                req.endpoint_url,
                backend=req.backend,
                api_key=req.endpoint_api_key,
                model_name=req.model_name,
                probe_families=req.probe_families,
                depth=req.depth,
                timeout=req.timeout,
            )
            _rt_job_log(
                job_id,
                f"[AIAF] Evaluation complete — status={result['status']} "
                f"failures={result['total_failures']} "
                f"probes_run={result['total_probes_run']}",
            )
            # Persist results to model metadata so triage picks them up.
            _persist_redteam_results(store, store.get_model(model_id) or {}, result)
            _rt_job_update(job_id, "COMPLETED", result)
        except Exception as exc:
            _rt_job_log(job_id, f"[AIAF] ERROR: {exc}")
            _rt_job_update(job_id, "FAILED", {"error": str(exc)})

    threading.Thread(target=_run, daemon=True).start()

    return {
        "job_id": job_id,
        "model_id": model_id,
        "status": "PENDING",
        "backend": req.backend,
        "depth": req.depth,
        "endpoint_url": req.endpoint_url,
        "started_at": _utc_now(),
    }


@router.get("/models/{model_id}/redteam/{job_id}")
def get_redteam_job(
    model_id: str,
    job_id: str,
    api_key: str = Depends(get_api_key),
):
    """Poll the status and results of a red-team evaluation job."""
    store = get_store()
    if not store.get_model(model_id):
        raise HTTPException(status_code=404, detail="Model not found")

    job = _rt_job_get(job_id)
    if not job or job["model_id"] != model_id:
        raise HTTPException(status_code=404, detail="Job not found")

    return job


@router.get("/models/{model_id}/redteam")
def list_redteam_jobs(
    model_id: str,
    api_key: str = Depends(get_api_key),
):
    """List all red-team evaluation jobs for a model (most recent first)."""
    store = get_store()
    if not store.get_model(model_id):
        raise HTTPException(status_code=404, detail="Model not found")

    jobs = _rt_jobs_for_model(model_id)
    jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
    return {"model_id": model_id, "jobs": jobs, "count": len(jobs)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _persist_redteam_results(
    store, rec: Dict[str, Any], result: Dict[str, Any]
) -> None:
    """Persist red-team results to the model record's metadata."""
    if not rec:
        return
    metadata = dict(rec.get("metadata") or {})
    metadata["redteam_results"] = result
    rec["metadata"] = metadata
    store.save_model(rec)
    try:
        store.save_audit_log({
            "event_type": "redteam_evaluation",
            "artifact_id": rec.get("model_id"),
            "details": {
                "backend": result.get("backend"),
                "status": result.get("status"),
                "total_failures": result.get("total_failures"),
                "probe_families": result.get("probe_families_requested"),
            },
        })
    except Exception:
        pass


def _repo_id_from_record(rec: Dict[str, Any]) -> Optional[str]:
    """Derive a HuggingFace repo_id from a model record's source_url."""
    from urllib.parse import urlparse
    source_url = rec.get("source_url") or ""
    parsed = urlparse(source_url)
    if "huggingface" not in parsed.netloc.lower():
        # Also try metadata.repo_id (set by the HF snapshot job).
        return (rec.get("metadata") or {}).get("repo_id")
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def _record_sigstore_verification(store, rec: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Persist a successful Sigstore verification into the evidence ledger."""
    metadata = dict(rec.get("metadata") or {})
    ledger = ledger_from_list(metadata.get("evidence_ledger"))
    ledger.add(
        "sigstore_verification",
        result.get("signer_identity") or "verified",
        EvidenceOrigin.INDEPENDENTLY_VERIFIED,
        detail=(
            f"Sigstore signature verified; signer={result.get('signer_identity')}; "
            f"issuer={result.get('issuer')}"
        ),
    )
    metadata["evidence_ledger"] = ledger.to_list()
    metadata["sigstore_verification"] = result
    rec["metadata"] = metadata
    store.save_model(rec)
    try:
        store.save_audit_log(
            {
                "event_type": "sigstore_verification",
                "artifact_id": rec.get("model_id"),
                "details": {
                    "status": result.get("status"),
                    "signer_identity": result.get("signer_identity"),
                    "issuer": result.get("issuer"),
                },
            }
        )
    except Exception:
        pass

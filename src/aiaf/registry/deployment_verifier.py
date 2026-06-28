"""Secure deployment verification — compare observed runtime state against the registered AI-BOM.

The deterministic comparison is pure (no network I/O).  Live probing is
isolated behind ``probe_endpoint(..., allow_network=True)`` exactly like the
``redteam_engine.py`` garak subprocess — the flag must be explicit.

A MISMATCH verdict produces a ``finding`` dict suitable for
``store.save_finding`` and can auto-open an incident of class
``UNAUTHORIZED_MODEL_CHANGE`` via the calling API layer.

Observed runtime state is supplied by the operator/agent at call time — the
module never fetches it directly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mbom_v2 import AI_BOM_FORMAT
from .sigstore_verifier import verify_resolved_file

DEPLOYMENT_VERIFY_VERSION = "1.0"

_VERIFY_PREFIX = "deployment_verify:"
_MAX_TOOL_LIST = 500
_MAX_GUARDRAIL_LIST = 200

VERDICT_MATCH = "MATCH"
VERDICT_PARTIAL_MATCH = "PARTIAL_MATCH"
VERDICT_MISMATCH = "MISMATCH"
VERDICT_UNKNOWN = "UNKNOWN"

VERDICTS: frozenset[str] = frozenset(
    {VERDICT_MATCH, VERDICT_PARTIAL_MATCH, VERDICT_MISMATCH, VERDICT_UNKNOWN}
)

STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_DRIFT = "DRIFT"
STATUS_UNKNOWN = "UNKNOWN"


class DeploymentVerifyError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _sha256_dict(obj: Any) -> str:
    return _sha256_str(_canonical_json(obj))


def _norm_sha(value: str | None) -> str | None:
    if not value:
        return None
    return str(value).strip().lower() or None


def _ai_bom_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("bom_format") == AI_BOM_FORMAT and isinstance(record.get("subject"), dict):
        return record
    meta = record.get("metadata")
    if isinstance(meta, dict) and meta.get("bom_format") == AI_BOM_FORMAT and isinstance(
        meta.get("subject"), dict
    ):
        return meta
    return None


def _runtime_components(record: dict[str, Any]) -> list[dict[str, Any]]:
    payload = _ai_bom_payload(record)
    if payload is None:
        return []
    components = payload.get("components")
    if not isinstance(components, dict):
        return []
    runtime = components.get("runtime_components")
    if not isinstance(runtime, list):
        return []
    return [item for item in runtime if isinstance(item, dict)]


def _deployment_component(record: dict[str, Any]) -> dict[str, Any] | None:
    payload = _ai_bom_payload(record)
    if payload is None:
        return None
    components = payload.get("components")
    if not isinstance(components, dict):
        return None
    deployment = components.get("deployment_artifact")
    return deployment if isinstance(deployment, dict) else None


def _resolve_registered_record(model_id: str, store: Any) -> tuple[dict[str, Any], str | None]:
    direct = store.get_model(model_id) or {}
    if direct:
        return direct, model_id
    mbom_key = f"mbom:{model_id}"
    mbom = store.get_model(mbom_key) or {}
    if mbom:
        return mbom, mbom_key
    return {}, None


def _model_record_weights_sha(record: dict[str, Any]) -> str | None:
    payload = _ai_bom_payload(record)
    if payload is not None:
        subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
        hashes = subject.get("hashes") if isinstance(subject.get("hashes"), dict) else {}
        candidate = hashes.get("sha256")
        if candidate:
            return _norm_sha(str(candidate))
    meta = record.get("metadata") or {}
    for key in ("sha256", "weights_sha256", "artifact_sha256"):
        v = meta.get(key)
        if v:
            return _norm_sha(str(v))
    return _norm_sha(meta.get("checksum"))


def _model_record_container_digest(record: dict[str, Any]) -> str | None:
    deployment = _deployment_component(record)
    if deployment is not None:
        hashes = deployment.get("hashes") if isinstance(deployment.get("hashes"), dict) else {}
        candidate = hashes.get("sha256")
        if candidate:
            return _norm_sha(str(candidate))
        artifact_ref = str(deployment.get("artifact_ref") or "").strip()
        if "@sha256:" in artifact_ref:
            return _norm_sha(artifact_ref.rsplit("@sha256:", 1)[1])
    meta = record.get("metadata") or {}
    for key in ("container_digest", "container_sha256", "docker_digest"):
        v = meta.get(key)
        if v:
            return _norm_sha(str(v))
    return None


def _model_record_system_prompt_sha(record: dict[str, Any]) -> str | None:
    for component in _runtime_components(record):
        if component.get("type") != "system-prompt-hash":
            continue
        hashes = component.get("hashes") if isinstance(component.get("hashes"), dict) else {}
        candidate = hashes.get("sha256")
        if candidate:
            return _norm_sha(str(candidate))
    meta = record.get("metadata") or {}
    for key in ("system_prompt_sha256", "system_prompt_hash"):
        v = meta.get(key)
        if v:
            return _norm_sha(str(v))
    return None


def _model_record_tools(record: dict[str, Any]) -> list[str]:
    runtime = [
        str(component.get("name") or "").strip()
        for component in _runtime_components(record)
        if component.get("type") == "tool"
    ]
    if runtime:
        return sorted(tool for tool in runtime if tool)
    meta = record.get("metadata") or {}
    tools = meta.get("tool_list") or meta.get("tools") or []
    return sorted(str(t) for t in tools if t)


def _model_record_guardrails(record: dict[str, Any]) -> list[dict[str, str]]:
    runtime = []
    for component in _runtime_components(record):
        if component.get("type") != "guardrail":
            continue
        runtime.append(
            {
                "name": str(component.get("name") or ""),
                "version": str(component.get("version") or ""),
            }
        )
    if runtime:
        return runtime
    meta = record.get("metadata") or {}
    guardrails = meta.get("guardrail_versions") or meta.get("guardrails") or []
    out = []
    for g in guardrails:
        if isinstance(g, dict):
            out.append({"name": str(g.get("name") or ""), "version": str(g.get("version") or "")})
        elif isinstance(g, str):
            out.append({"name": g, "version": ""})
    return out


def _registered_model_id(record: dict[str, Any], fallback_model_id: str) -> str:
    if not record:
        return ""
    payload = _ai_bom_payload(record)
    if payload is not None:
        subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
        candidate = str(subject.get("model_id") or "").strip()
        if candidate:
            return candidate
    meta = record.get("metadata") or {}
    return str(meta.get("model_id") or meta.get("name") or fallback_model_id or "")


def _sigstore_check(observed: dict[str, Any]) -> dict[str, Any] | None:
    artifact_path = str(observed.get("artifact_path") or "").strip()
    if not artifact_path:
        return None
    bundle_path = str(observed.get("sigstore_bundle_path") or "").strip() or None
    expected_identity = str(observed.get("sigstore_expected_identity") or "").strip() or None
    expected_issuer = str(observed.get("sigstore_expected_issuer") or "").strip() or None
    return verify_resolved_file(
        Path(artifact_path),
        bundle_path=Path(bundle_path) if bundle_path else None,
        expected_identity=expected_identity,
        expected_issuer=expected_issuer,
    )


# ---------------------------------------------------------------------------
# Comparison sub-checks
# ---------------------------------------------------------------------------


def _check_artifact(registered_sha: str | None, observed_sha: str | None) -> dict[str, Any]:
    r = _norm_sha(registered_sha)
    o = _norm_sha(observed_sha)
    if r is None and o is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": None,
                "detail": "No weight digest in registered record or observed state."}
    if r is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": o,
                "detail": "No weight digest in registered record; cannot compare."}
    if o is None:
        return {"status": STATUS_UNKNOWN, "registered": r, "observed": None,
                "detail": "No weight digest supplied in observed state; cannot compare."}
    if r == o:
        return {"status": STATUS_MATCH, "registered": r, "observed": o,
                "detail": "Artifact digest matches registered record."}
    return {"status": STATUS_MISMATCH, "registered": r, "observed": o,
            "detail": f"Artifact digest mismatch: registered={r[:16]}…, observed={o[:16]}…."}


def _check_container(registered_digest: str | None, observed_digest: str | None) -> dict[str, Any]:
    r = _norm_sha(registered_digest)
    o = _norm_sha(observed_digest)
    if r is None and o is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": None,
                "detail": "No container digest in registered record or observed state."}
    if r is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": o,
                "detail": "No container digest in registered record; cannot compare."}
    if o is None:
        return {"status": STATUS_UNKNOWN, "registered": r, "observed": None,
                "detail": "No container digest supplied in observed state; cannot compare."}
    if r == o:
        return {"status": STATUS_MATCH, "registered": r, "observed": o,
                "detail": "Container digest matches registered record."}
    return {"status": STATUS_MISMATCH, "registered": r, "observed": o,
            "detail": f"Container digest mismatch: registered={r[:16]}…, observed={o[:16]}…."}


def _check_system_prompt(registered_sha: str | None, observed_sha: str | None) -> dict[str, Any]:
    r = _norm_sha(registered_sha)
    o = _norm_sha(observed_sha)
    if r is None and o is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": None,
                "detail": "No system prompt digest registered or observed."}
    if r is None:
        return {"status": STATUS_UNKNOWN, "registered": None, "observed": o,
                "detail": "System prompt not registered; cannot compare."}
    if o is None:
        return {"status": STATUS_UNKNOWN, "registered": r, "observed": None,
                "detail": "System prompt hash not supplied in observed state."}
    if r == o:
        return {"status": STATUS_MATCH, "registered": r, "observed": o,
                "detail": "System prompt hash matches registered record."}
    return {"status": STATUS_MISMATCH, "registered": r, "observed": o,
            "detail": f"System prompt hash mismatch: registered={r[:16]}…, observed={o[:16]}…."}


def _check_tool_drift(
    registered_tools: list[str],
    observed_tools: list[str],
    *,
    registered_found: bool = True,
) -> dict[str, Any]:
    if not registered_found:
        return {"status": STATUS_UNKNOWN, "added": [], "removed": [],
                "registered_count": 0, "observed_count": len(observed_tools),
                "detail": "No registered record; cannot compare tool list."}
    r_set = set(registered_tools)
    o_set = set(observed_tools[:_MAX_TOOL_LIST])
    added = sorted(o_set - r_set)
    removed = sorted(r_set - o_set)
    if not added and not removed:
        status = STATUS_MATCH
        detail = f"Tool list matches ({len(r_set)} tool(s))."
    else:
        status = STATUS_DRIFT
        parts = []
        if added:
            parts.append(f"added={len(added)}")
        if removed:
            parts.append(f"removed={len(removed)}")
        detail = f"Tool drift detected: {', '.join(parts)}."
    return {
        "status": status,
        "added": added,
        "removed": removed,
        "registered_count": len(r_set),
        "observed_count": len(o_set),
        "detail": detail,
    }


def _check_guardrail_drift(
    registered: list[dict[str, str]],
    observed: list[dict[str, str]],
    *,
    registered_found: bool = True,
) -> dict[str, Any]:
    if not registered_found:
        return {"status": STATUS_UNKNOWN, "added": [], "removed": [],
                "registered_count": 0, "observed_count": len(observed),
                "detail": "No registered record; cannot compare guardrail list."}

    def _key(g: dict[str, str]) -> str:
        return f"{g.get('name','')}/{g.get('version','')}"

    r_set = {_key(g) for g in registered}
    o_set = {_key(g) for g in observed[:_MAX_GUARDRAIL_LIST]}
    added = sorted(o_set - r_set)
    removed = sorted(r_set - o_set)
    if not added and not removed:
        status = STATUS_MATCH
        detail = f"Guardrail list matches ({len(r_set)} guardrail(s))."
    else:
        status = STATUS_DRIFT
        parts = []
        if added:
            parts.append(f"added={len(added)}")
        if removed:
            parts.append(f"removed={len(removed)}")
        detail = f"Guardrail drift detected: {', '.join(parts)}."
    return {
        "status": status,
        "added": added,
        "removed": removed,
        "registered_count": len(r_set),
        "observed_count": len(o_set),
        "detail": detail,
    }


def _check_config_drift(
    registered_model_id: str | None, served_model_id: str | None
) -> dict[str, Any]:
    r = str(registered_model_id or "").strip()
    o = str(served_model_id or "").strip()
    if not r and not o:
        return {"status": STATUS_UNKNOWN, "registered_model_id": None, "served_model_id": None,
                "detail": "No model ID available for comparison."}
    if not o:
        return {"status": STATUS_UNKNOWN, "registered_model_id": r or None, "served_model_id": None,
                "detail": "Served model ID not supplied in observed state."}
    if r == o:
        return {"status": STATUS_MATCH, "registered_model_id": r, "served_model_id": o,
                "detail": "Served model ID matches registered record."}
    return {"status": STATUS_MISMATCH, "registered_model_id": r or None, "served_model_id": o,
            "detail": f"Served model ID mismatch: registered={r!r}, observed={o!r}."}


# ---------------------------------------------------------------------------
# Overall verdict
# ---------------------------------------------------------------------------


def _compute_verdict(checks: dict[str, dict[str, Any]]) -> str:
    statuses = [c.get("status") for c in checks.values()]
    if VERDICT_MISMATCH in statuses or STATUS_MISMATCH in statuses:
        if all(s in (STATUS_MATCH, STATUS_UNKNOWN) or s == VERDICT_MISMATCH
               for s in statuses):
            return VERDICT_PARTIAL_MATCH
        return VERDICT_MISMATCH
    if STATUS_DRIFT in statuses:
        return VERDICT_PARTIAL_MATCH
    if all(s == STATUS_UNKNOWN for s in statuses):
        return VERDICT_UNKNOWN
    if all(s in (STATUS_MATCH, STATUS_UNKNOWN) for s in statuses):
        if STATUS_MATCH in statuses:
            return VERDICT_MATCH
        return VERDICT_UNKNOWN
    return VERDICT_UNKNOWN


def _verdict_from_checks(
    artifact: dict[str, Any],
    container: dict[str, Any],
    system_prompt: dict[str, Any],
    tool_drift: dict[str, Any],
    guardrail_drift: dict[str, Any],
    config_drift: dict[str, Any],
) -> str:
    mismatch_statuses = {STATUS_MISMATCH}
    drift_statuses = {STATUS_DRIFT}
    checks = [artifact, container, system_prompt, tool_drift, guardrail_drift, config_drift]
    statuses = {c["status"] for c in checks}

    if statuses & mismatch_statuses:
        match_or_unknown = all(c["status"] in (STATUS_MATCH, STATUS_UNKNOWN) for c in checks
                               if c["status"] != STATUS_MISMATCH)
        if match_or_unknown:
            return VERDICT_PARTIAL_MATCH
        return VERDICT_MISMATCH

    if statuses & drift_statuses:
        return VERDICT_PARTIAL_MATCH

    if statuses == {STATUS_UNKNOWN}:
        return VERDICT_UNKNOWN

    if statuses <= {STATUS_MATCH, STATUS_UNKNOWN}:
        if STATUS_MATCH in statuses:
            return VERDICT_MATCH
        return VERDICT_UNKNOWN

    return VERDICT_UNKNOWN


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_deployment(
    model_id: str,
    observed: dict[str, Any],
    store: Any,
    *,
    save_result: bool = True,
) -> dict[str, Any]:
    """Compare observed runtime state against the registered model record.

    Parameters
    ----------
    model_id:
        Key used to look up the registered record (passed to ``store.get_model``).
    observed:
        Operator-supplied snapshot of runtime state.  Expected fields
        (all optional): ``endpoint_url``, ``container_digest``,
        ``served_model_id``, ``weights_sha256``, ``system_prompt_sha256``,
        ``tool_list`` (list[str]), ``guardrail_versions``
        (list[{name, version}]).
    store:
        AIAF data store.
    save_result:
        When True (default) the result is persisted under
        ``deployment_verify:{verify_id}`` so it can be retrieved later.

    Returns
    -------
    dict
        Detailed drift report including overall verdict and per-dimension checks.
    """
    model_id = str(model_id).strip()
    if not model_id:
        raise DeploymentVerifyError("model_id must be non-empty")
    if not isinstance(observed, dict):
        raise DeploymentVerifyError("observed must be a dict")

    record, registered_record_id = _resolve_registered_record(model_id, store)

    # Per-dimension comparisons
    artifact_check = _check_artifact(
        _model_record_weights_sha(record),
        observed.get("weights_sha256"),
    )
    container_check = _check_container(
        _model_record_container_digest(record),
        observed.get("container_digest"),
    )
    system_prompt_check = _check_system_prompt(
        _model_record_system_prompt_sha(record),
        observed.get("system_prompt_sha256"),
    )
    tool_drift = _check_tool_drift(
        _model_record_tools(record),
        list(observed.get("tool_list") or [])[:_MAX_TOOL_LIST],
        registered_found=bool(record),
    )
    guardrail_drift = _check_guardrail_drift(
        _model_record_guardrails(record),
        list(observed.get("guardrail_versions") or [])[:_MAX_GUARDRAIL_LIST],
        registered_found=bool(record),
    )
    config_drift = _check_config_drift(
        _registered_model_id(record, model_id),
        observed.get("served_model_id"),
    )
    sigstore_check = _sigstore_check(observed)

    verdict = _verdict_from_checks(
        artifact_check, container_check, system_prompt_check,
        tool_drift, guardrail_drift, config_drift,
    )
    if sigstore_check is not None and not sigstore_check.get("verified", False):
        if sigstore_check.get("status") in {"VERIFICATION_FAILED", "BUNDLE_INVALID", "ERROR", "NOT_SIGNED"}:
            verdict = VERDICT_MISMATCH if verdict == VERDICT_UNKNOWN else VERDICT_PARTIAL_MATCH

    verify_id = str(uuid.uuid4())
    verified_at = _utc_now()

    mismatch_dimensions = [
        dim for dim, check in [
            ("artifact", artifact_check),
            ("container", container_check),
            ("system_prompt", system_prompt_check),
            ("tool_drift", tool_drift),
            ("guardrail_drift", guardrail_drift),
            ("config", config_drift),
        ]
        if check["status"] in (STATUS_MISMATCH, STATUS_DRIFT)
    ]
    if sigstore_check is not None and not sigstore_check.get("verified", False):
        if sigstore_check.get("status") in {"VERIFICATION_FAILED", "BUNDLE_INVALID", "ERROR", "NOT_SIGNED"}:
            mismatch_dimensions.append("sigstore")

    finding = None
    if verdict in (VERDICT_MISMATCH, VERDICT_PARTIAL_MATCH):
        finding = {
            "artifact_id": model_id,
            "timestamp": verified_at,
            "score": 8.0 if verdict == VERDICT_MISMATCH else 5.0,
            "findings": [{
                "type": "deployment_drift",
                "severity": "HIGH" if verdict == VERDICT_MISMATCH else "MEDIUM",
                "title": f"Deployment drift detected ({verdict})",
                "detail": f"Mismatched dimensions: {', '.join(mismatch_dimensions) or 'none'}",
                "verdict": verdict,
                "verify_id": verify_id,
                "evidence_origin": "LOCALLY_OBSERVED",
            }],
        }

    result: dict[str, Any] = {
        "model_id": model_id,
        "verify_id": verify_id,
        "verdict": verdict,
        "verified_at": verified_at,
        "mismatch_dimensions": mismatch_dimensions,
        "artifact_match": artifact_check,
        "container_match": container_check,
        "system_prompt_match": system_prompt_check,
        "tool_drift": tool_drift,
        "guardrail_drift": guardrail_drift,
        "config_drift": config_drift,
        "sigstore_verification": sigstore_check,
        "finding": finding,
        "observed_endpoint_url": str(observed.get("endpoint_url") or "") or None,
        "registered_record_found": bool(record),
        "registered_record_id": registered_record_id,
        "evidence_origin": "LOCALLY_OBSERVED",
        "deployment_verify_version": DEPLOYMENT_VERIFY_VERSION,
    }

    if save_result and hasattr(store, "save_model"):
        store.save_model({
            "model_id": f"{_VERIFY_PREFIX}{verify_id}",
            "metadata": {
                "verify_id": verify_id,
                "target_model_id": model_id,
                "verdict": verdict,
                "verified_at": verified_at,
                "mismatch_dimensions": mismatch_dimensions,
                "deployment_verify_version": DEPLOYMENT_VERIFY_VERSION,
            },
        })

    return result


def get_verify_result(verify_id: str, store: Any) -> dict[str, Any] | None:
    """Retrieve a stored verification result by its verify_id."""
    record = store.get_model(f"{_VERIFY_PREFIX}{verify_id}")
    if not record:
        return None
    return record.get("metadata") or {}


def list_verify_results(
    store: Any,
    *,
    model_id: str | None = None,
    verdict: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List stored verification results, newest first."""
    all_models = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        if not mid.startswith(_VERIFY_PREFIX):
            continue
        meta = m.get("metadata") or {}
        if model_id and meta.get("target_model_id") != model_id:
            continue
        if verdict and meta.get("verdict") != verdict.upper():
            continue
        results.append(meta)
    results.sort(key=lambda r: r.get("verified_at") or "", reverse=True)
    return results[:limit]


def probe_endpoint(
    endpoint_url: str,
    *,
    allow_network: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Optional live behavioral fingerprint of a running endpoint.

    Network calls are entirely suppressed unless ``allow_network=True`` is
    passed explicitly — same isolation pattern as ``redteam_engine.py``.

    Returns a dict with ``probed``, ``served_model_id``, ``latency_ms``, and
    ``error`` fields.  On network failure or suppression, returns a safe
    stub so the caller can degrade gracefully.
    """
    if not allow_network:
        return {
            "probed": False,
            "served_model_id": None,
            "latency_ms": None,
            "error": "Network probing disabled; pass allow_network=True to enable.",
        }

    try:
        import time
        import urllib.request

        url = str(endpoint_url).rstrip("/") + "/v1/info"
        start = time.monotonic()
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read())
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        return {
            "probed": True,
            "served_model_id": data.get("model_id") or data.get("name"),
            "latency_ms": elapsed_ms,
            "error": None,
        }
    except Exception as exc:
        return {
            "probed": True,
            "served_model_id": None,
            "latency_ms": None,
            "error": str(exc)[:256],
        }

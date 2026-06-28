"""AI incident reporting package builder.

Assembles a structured, portable bundle for a specific incident class.
Each class has a required-evidence checklist so a PROMPT_INJECTION package
always carries the offending input hash + influenced outputs, a RAG_POISONING
package carries the tainted chunk refs + blast-radius outputs, etc.

Optional bundle signing uses a deterministic HMAC envelope so exported
packages can carry an integrity seal without introducing new persistence
requirements.

Export formats:
  - ``"json"``  — full bundle dict
  - ``"stix"``  — STIX 2.1 incident SDO (via mapping/threat_frameworks.py)
  - ``"cef"``   — CEF syslog line (via core/siem_export.py)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

INCIDENT_PACKAGE_VERSION = "1.0"

# ── Incident class constants ────────────────────────────────────────────────────

INCIDENT_CLASS_PROMPT_INJECTION = "PROMPT_INJECTION"
INCIDENT_CLASS_DATA_LEAKAGE = "DATA_LEAKAGE"
INCIDENT_CLASS_MODEL_EXTRACTION = "MODEL_EXTRACTION"
INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION = "UNSAFE_TOOL_INVOCATION"
INCIDENT_CLASS_RAG_POISONING = "RAG_POISONING"
INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE = "UNAUTHORIZED_MODEL_CHANGE"
INCIDENT_CLASS_AGENT_CONTAINMENT = "AGENT_CONTAINMENT"

INCIDENT_CLASSES: frozenset[str] = frozenset(
    {
        INCIDENT_CLASS_PROMPT_INJECTION,
        INCIDENT_CLASS_DATA_LEAKAGE,
        INCIDENT_CLASS_MODEL_EXTRACTION,
        INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION,
        INCIDENT_CLASS_RAG_POISONING,
        INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE,
        INCIDENT_CLASS_AGENT_CONTAINMENT,
    }
)

# ── Per-class required evidence checklists ──────────────────────────────────────

_CLASS_EVIDENCE_CHECKLIST: dict[str, list[str]] = {
    INCIDENT_CLASS_PROMPT_INJECTION: [
        "offending_input_hash",
        "influenced_output_refs",
        "injection_pattern",
        "entry_point",
        "session_id",
    ],
    INCIDENT_CLASS_DATA_LEAKAGE: [
        "data_classification",
        "output_hash",
        "source_reference",
        "recipient",
        "data_size_bytes",
    ],
    INCIDENT_CLASS_MODEL_EXTRACTION: [
        "query_count",
        "similarity_metric",
        "model_components_affected",
        "exfil_method",
        "session_id",
    ],
    INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION: [
        "tool_name",
        "invocation_hash",
        "agent_ref",
        "session_id",
        "authorization_verdict",
    ],
    INCIDENT_CLASS_RAG_POISONING: [
        "tainted_chunk_refs",
        "blast_radius_output_refs",
        "taint_label",
        "rag_store_id",
        "injection_vector",
    ],
    INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE: [
        "bom_snapshot_before",
        "bom_snapshot_after",
        "artifact_diff",
        "deployment_verify_ref",
        "changed_dimensions",
    ],
    INCIDENT_CLASS_AGENT_CONTAINMENT: [
        "containment_action",
        "policy_ref",
        "egress_decision_refs",
        "agent_ref",
        "session_id",
    ],
}

# ── Framework mappings per class ────────────────────────────────────────────────

_CLASS_FRAMEWORK_REFS: dict[str, dict[str, list[str]]] = {
    INCIDENT_CLASS_PROMPT_INJECTION: {
        "OWASP LLM Top 10 2025": ["LLM01 Prompt Injection"],
        "MITRE ATLAS": ["AML.T0051 LLM Prompt Injection"],
        "NIST AI RMF": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    INCIDENT_CLASS_DATA_LEAKAGE: {
        "OWASP LLM Top 10 2025": ["LLM02 Sensitive Information Disclosure"],
        "NIST AI RMF": ["MEASURE 2.10", "MANAGE 1.3"],
    },
    INCIDENT_CLASS_MODEL_EXTRACTION: {
        "MITRE ATLAS": ["AML.T0024 Exfiltration via AI Inference API"],
        "NIST AI RMF": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    INCIDENT_CLASS_UNSAFE_TOOL_INVOCATION: {
        "OWASP LLM Top 10 2025": ["LLM06 Excessive Agency"],
        "OWASP Agentic Security": ["AGENTIC-01"],
        "MITRE ATLAS": ["AML.T0053 AI Agent Tool Invocation"],
        "NIST AI RMF": ["MANAGE 2.4"],
    },
    INCIDENT_CLASS_RAG_POISONING: {
        "OWASP LLM Top 10 2025": ["LLM01 Prompt Injection"],
        "MITRE ATLAS": ["AML.T0020 Poison Training Data", "AML.T0043 Craft Adversarial Data"],
        "NIST AI RMF": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    INCIDENT_CLASS_UNAUTHORIZED_MODEL_CHANGE: {
        "MITRE ATLAS": ["AML.T0018 Manipulate AI Model"],
        "NIST Secure Software Development Framework": ["PS.3", "RV.1"],
        "NIST AI RMF": ["MAP 4.2", "MANAGE 2.4"],
    },
    INCIDENT_CLASS_AGENT_CONTAINMENT: {
        "OWASP LLM Top 10 2025": ["LLM06 Excessive Agency"],
        "OWASP Agentic Security": ["AGENTIC-01"],
        "NIST AI RMF": ["MANAGE 2.4", "GOVERN 1.7"],
    },
}


class IncidentPackageError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_dict(obj: Any) -> str:
    return hashlib.sha256(_canonical_json(obj).encode()).hexdigest()


def _hmac_sha256(obj: Any, signing_key: str) -> str:
    return hmac.new(
        str(signing_key).encode(),
        _canonical_json(obj).encode(),
        hashlib.sha256,
    ).hexdigest()


def _evidence_checklist_status(
    incident_class: str, evidence_fields: dict[str, Any]
) -> dict[str, Any]:
    required = _CLASS_EVIDENCE_CHECKLIST.get(incident_class, [])
    present = [f for f in required if evidence_fields.get(f) not in (None, [], "", {})]
    missing = [f for f in required if f not in present]
    return {
        "required": required,
        "present": present,
        "missing": missing,
        "complete": not missing,
        "completeness_pct": round(len(present) / len(required) * 100) if required else 100,
    }


def _get_influenced_outputs(incident: dict[str, Any], store: Any) -> list[dict[str, Any]]:
    """Try to pull blast-radius outputs from the context provenance module."""
    try:
        from ..analysis.context_provenance import find_influenced_by
        finding_refs = incident.get("findings") or []
        results: list[dict[str, Any]] = []
        for finding in finding_refs[:10]:
            source_ref = finding.get("source_ref") or finding.get("artifact_id")
            if source_ref:
                influenced = find_influenced_by(source_ref, store, limit=50)
                results.extend(influenced)
        return results[:100]
    except Exception:
        return []


def _get_ledger_excerpt(incident: dict[str, Any], store: Any) -> list[dict[str, Any]]:
    """Pull ledger entries for the affected model's session."""
    try:
        from ..core.agent_action_ledger import get_ledger_entries
        session_candidates: list[str] = []
        for finding in (incident.get("findings") or []):
            if isinstance(finding, dict):
                session_id = str(finding.get("session_id") or "").strip()
                if session_id:
                    session_candidates.append(session_id)
        fallback = str(incident.get("model_id") or "").strip()
        if fallback:
            session_candidates.append(fallback)
        for session_id in session_candidates:
            entries, _total = get_ledger_entries(session_id, store, limit=50)
            if entries:
                return entries
        if not session_candidates:
            return []
        entries, _total = get_ledger_entries(session_candidates[0], store, limit=50)
        return entries
    except Exception:
        return []


def _get_bom_context(incident: dict[str, Any], store: Any) -> list[dict[str, Any]]:
    """Pull related AI-BOM snapshots for the affected model."""
    model_id = str(incident.get("model_id") or "").strip()
    if not model_id or not hasattr(store, "list_models"):
        return []

    bom_context: list[dict[str, Any]] = []
    try:
        for record in store.list_models() or []:
            record_id = str(record.get("model_id") or record.get("id") or "")
            payload = record
            meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            subject = payload.get("subject") if isinstance(payload.get("subject"), dict) else {}
            components = payload.get("components") if isinstance(payload.get("components"), dict) else {}

            matches_prefix = record_id == f"mbom:{model_id}"
            matches_meta = str(meta.get("model_id") or "") == model_id and record_id.startswith("mbom:")
            matches_subject = str(subject.get("model_id") or "") == model_id
            if not (matches_prefix or matches_meta or matches_subject):
                continue

            deployment = components.get("deployment_artifact")
            runtime_components = components.get("runtime_components") if isinstance(
                components.get("runtime_components"), list
            ) else []
            bom_context.append(
                {
                    "ref": record_id,
                    "spec_version": payload.get("spec_version") or meta.get("spec_version"),
                    "document_sha256": payload.get("document_sha256") or meta.get("document_sha256"),
                    "subject_model_id": subject.get("model_id") or meta.get("model_id"),
                    "deployment_artifact_ref": (
                        deployment.get("artifact_ref") if isinstance(deployment, dict) else None
                    ),
                    "deployment_integrity_status": (
                        deployment.get("integrity_status") if isinstance(deployment, dict) else None
                    ),
                    "runtime_component_count": len(runtime_components),
                }
            )
    except Exception:
        return []

    bom_context.sort(key=lambda item: (item.get("ref") or ""))
    return bom_context[:10]


def _get_remediation(incident_id: str, store: Any) -> list[dict[str, Any]]:
    """Pull remediations linked to this incident."""
    try:
        from ..core.remediation_tracker import list_remediations
        all_rems = list_remediations(store, limit=200)
        linked = [
            r for r in all_rems
            if incident_id in (r.get("linked_incident_ids") or [])
        ]
        return linked[:20]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------


def build_incident_package(
    incident_id: str,
    store: Any,
    *,
    incident_class: str | None = None,
    evidence_fields: dict[str, Any] | None = None,
    signing_key: str | None = None,
    signer_key_id: str | None = None,
    signer_issuer: str | None = None,
) -> dict[str, Any]:
    """Assemble a structured, portable incident package.

    Parameters
    ----------
    incident_id:
        ID of the incident in the store (as recorded by ``incident_manager``).
    store:
        AIAF data store.
    incident_class:
        One of the ``INCIDENT_CLASS_*`` constants.  If omitted, inferred from
        the incident's ``tags`` field or left as ``UNKNOWN``.
    evidence_fields:
        Additional evidence for the per-class checklist (e.g.
        ``{"offending_input_hash": "abc…", "injection_pattern": "…"}``).

    Returns
    -------
    dict
        Full portable bundle with timeline, blast-radius, ledger excerpt,
        framework mappings, checklist, and a tamper-evident ``bundle_sha256``.
    """
    incident_id = str(incident_id).strip()
    if not incident_id:
        raise IncidentPackageError("incident_id must be non-empty")

    from ..core.incident_manager import get_incident
    incident = get_incident(incident_id, store)
    if incident is None:
        raise IncidentPackageError(f"Incident not found: {incident_id!r}")

    # Resolve incident class
    if incident_class is None:
        tags = incident.get("tags") or []
        for tag in tags:
            if str(tag).upper() in INCIDENT_CLASSES:
                incident_class = str(tag).upper()
                break
    if incident_class is None or incident_class not in INCIDENT_CLASSES:
        incident_class = "UNKNOWN"

    evidence_fields = dict(evidence_fields or {})

    # Enrich evidence fields from incident findings
    for finding in (incident.get("findings") or []):
        if isinstance(finding, dict):
            for key in ("offending_input_hash", "tainted_chunk_refs", "tool_name",
                        "invocation_hash", "agent_ref", "session_id"):
                if key in finding and key not in evidence_fields:
                    evidence_fields[key] = finding[key]

    # Checklist
    checklist = _evidence_checklist_status(incident_class, evidence_fields)

    # Influence trace / blast radius
    influenced_outputs = _get_influenced_outputs(incident, store)

    # Ledger excerpt
    ledger_excerpt = _get_ledger_excerpt(incident, store)

    # AI-BOM context
    bom_context = _get_bom_context(incident, store)

    # Remediations
    remediations = _get_remediation(incident_id, store)

    # Framework mappings
    framework_refs = _CLASS_FRAMEWORK_REFS.get(incident_class, {})

    # Bundle assembly
    package_id = str(uuid.uuid4())
    packaged_at = _utc_now()

    bundle: dict[str, Any] = {
        "package_id": package_id,
        "incident_package_version": INCIDENT_PACKAGE_VERSION,
        "packaged_at": packaged_at,
        "incident_id": incident_id,
        "incident_class": incident_class,
        "incident": incident,
        "timeline": incident.get("state_history") or [],
        "notes": incident.get("notes") or [],
        "blast_radius": {
            "influenced_output_count": len(influenced_outputs),
            "influenced_outputs": influenced_outputs[:50],
        },
        "ledger_excerpt": ledger_excerpt,
        "bom_context": bom_context,
        "evidence_checklist": checklist,
        "evidence_fields": evidence_fields,
        "framework_mappings": framework_refs,
        "remediations": remediations,
        "evidence_origin": "LOCALLY_OBSERVED",
    }

    # Tamper-evident digest (signed SHA-256 over canonical bundle without the digest itself)
    bundle["bundle_sha256"] = _sha256_dict(bundle)
    if signing_key:
        signature_payload = {
            key: value for key, value in bundle.items()
        }
        bundle["bundle_signature"] = {
            "algorithm": "HMAC-SHA256",
            "key_id": str(signer_key_id or "").strip() or None,
            "issuer": str(signer_issuer or "").strip() or None,
            "signed_at": packaged_at,
            "signature": _hmac_sha256(signature_payload, signing_key),
        }

    return bundle


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def export_package(
    incident_id: str,
    store: Any,
    *,
    fmt: str = "json",
    incident_class: str | None = None,
    evidence_fields: dict[str, Any] | None = None,
    signing_key: str | None = None,
    signer_key_id: str | None = None,
    signer_issuer: str | None = None,
) -> Any:
    """Build and export an incident package in the specified format.

    Parameters
    ----------
    fmt:
        ``"json"`` (default) — returns the full bundle dict.
        ``"stix"``           — returns a STIX 2.1 incident SDO dict.
        ``"cef"``            — returns a CEF syslog string.
    """
    fmt = str(fmt).lower().strip()
    if fmt not in ("json", "stix", "cef"):
        raise IncidentPackageError(f"Unknown export format: {fmt!r}. Valid: json, stix, cef")

    bundle = build_incident_package(
        incident_id, store,
        incident_class=incident_class,
        evidence_fields=evidence_fields,
        signing_key=signing_key,
        signer_key_id=signer_key_id,
        signer_issuer=signer_issuer,
    )
    incident = bundle["incident"]

    if fmt == "json":
        return bundle

    if fmt == "cef":
        from ..core.siem_export import export_incident_cef
        return export_incident_cef(incident)

    # STIX 2.1 incident SDO
    return _to_stix_incident(bundle)


def _to_stix_incident(bundle: dict[str, Any]) -> dict[str, Any]:
    """Serialize the bundle as a STIX 2.1 Incident SDO."""
    incident = bundle["incident"]
    now = _utc_now()
    severity = str(incident.get("severity") or "MEDIUM").lower()

    stix_severity_map = {
        "critical": "critical", "high": "high",
        "medium": "medium", "low": "low", "info": "none",
    }

    objects = [
        {
            "type": "incident",
            "spec_version": "2.1",
            "id": f"incident--{bundle['package_id']}",
            "created": incident.get("created_at") or now,
            "modified": incident.get("updated_at") or now,
            "name": incident.get("title") or f"Incident {bundle['incident_id']}",
            "description": incident.get("description") or "",
            "severity": stix_severity_map.get(severity, "medium"),
            "incident_type": [bundle["incident_class"]],
            "extensions": {
                "extension-definition--aiaf-incident-package": {
                    "extension_type": "property-extension",
                    "package_id": bundle["package_id"],
                    "incident_id": bundle["incident_id"],
                    "incident_class": bundle["incident_class"],
                    "verdict": incident.get("state"),
                    "model_id": incident.get("model_id"),
                    "evidence_checklist_complete": bundle["evidence_checklist"]["complete"],
                    "blast_radius_count": bundle["blast_radius"]["influenced_output_count"],
                    "packaged_at": bundle["packaged_at"],
                    "bundle_sha256": bundle["bundle_sha256"],
                },
            },
        }
    ]

    # Add attack-pattern SDOs for each framework ref
    for framework, refs in (bundle.get("framework_mappings") or {}).items():
        for ref in refs:
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{hashlib.sha256(ref.encode()).hexdigest()[:32]}",
                "created": now,
                "modified": now,
                "name": ref,
                "external_references": [{"source_name": framework, "external_id": ref}],
            })

    return {
        "type": "bundle",
        "id": f"bundle--{bundle['package_id']}",
        "spec_version": "2.1",
        "objects": objects,
    }

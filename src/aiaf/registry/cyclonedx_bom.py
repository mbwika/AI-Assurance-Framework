"""CycloneDX ML-BOM import/export for AIAF model records.

Implements CycloneDX 1.7 (the first version with a ``machine-learning-model``
component type and a dedicated ``modelCard`` structure) without requiring the
``cyclonedx-python-lib`` package — pure JSON construction aligned to the
published schema at https://cyclonedx.org/schema/bom-1.7.schema.json.

Why CycloneDX interop matters (NIW framing)
-------------------------------------------
CycloneDX is the *de-facto* industry-standard ML-BOM format endorsed by CISA,
OWASP, and the Linux Foundation.  Export lets AIAF verdicts flow into
downstream security toolchains (SBOM scanners, policy engines, audit systems)
that already consume CycloneDX.  Import lets organizations that receive
CycloneDX ML-BOMs from vendors register those models in AIAF without manual
data entry.

Evidence origins assigned during import
---------------------------------------
``PROVIDER_DECLARED``:
    ``name``, ``version``, ``publisher``, ``license`` extracted from the BOM.
    A BOM is typically provided by the supplier, so its fields are
    self-asserted (same trust level as a HF model card).
``LOCALLY_OBSERVED``:
    SHA-256 hash from the BOM's ``hashes`` array — we can verify this against
    the artifact independently.
``ARTIFACT_DERIVED``:
    Dependency component names from the BOM's ``dependencies`` block.

Schema version targeted: CycloneDX 1.7 (``specVersion: "1.7"``).
AIAF tool entry: vendor "AI Assurance Framework", name "AIAF", version "0.2.0".
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .mbom_v2 import generate_ai_bom_v2

CYCLONEDX_SPEC_VERSION = "1.7"
AIAF_TOOL_VERSION = "0.2.0"
BOM_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Export: AIAF model record → CycloneDX BOM
# ---------------------------------------------------------------------------


def export_bom(model_record: dict[str, Any]) -> dict[str, Any]:
    """Produce a CycloneDX 1.7 ML-BOM JSON for a registered model.

    The BOM contains:
    - One ``machine-learning-model`` component with identity, hashes, licenses,
      external references, AIAF scoring properties, and a ``modelCard`` block.
    - A ``dependencies`` element listing the model's known dependency components.
    - AIAF tool attribution in ``metadata.tools``.
    """
    model_record = model_record if isinstance(model_record, dict) else {}
    metadata = model_record.get("metadata") or {}
    model_id = model_record.get("model_id") or model_record.get("id") or str(uuid.uuid4())
    bom_ref = f"aiaf:{model_id}"
    ai_bom = generate_ai_bom_v2(model_record)

    component = _build_component(model_record, metadata, bom_ref)
    dep_refs, dep_components = _build_dependencies(model_record, bom_ref)
    runtime_refs, runtime_components = _build_runtime_components(ai_bom, bom_ref)

    # CycloneDX: all components (model + deps) go in the top-level components
    # array; the dependencies block only lists the relationship graph.
    all_components = [component] + dep_components + runtime_components

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _build_metadata(model_record),
        "components": all_components,
        "dependencies": dep_refs + runtime_refs,
    }


def _build_metadata(model_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": _utc_now(),
        "tools": [
            {
                "vendor": "AI Assurance Framework",
                "name": "AIAF",
                "version": AIAF_TOOL_VERSION,
                "externalReferences": [
                    {"type": "website", "url": "https://github.com/aiaf"}
                ],
            }
        ],
        "component": {
            "type": "application",
            "name": "AI Assurance Framework",
            "version": AIAF_TOOL_VERSION,
        },
        "properties": [
            {"name": "aiaf:bom_schema_version", "value": BOM_SCHEMA_VERSION},
        ],
    }


def _build_component(
    model_record: dict[str, Any],
    metadata: dict[str, Any],
    bom_ref: str,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": model_record.get("model_name") or "unknown",
        "version": model_record.get("version") or "unknown",
    }

    publisher = model_record.get("publisher")
    if publisher:
        component["supplier"] = {"name": publisher}
        component["publisher"] = publisher

    sha256 = model_record.get("sha256") or model_record.get("sha256_hash")
    if sha256:
        component["hashes"] = [{"alg": "SHA-256", "content": sha256}]

    license_id = model_record.get("license")
    if license_id:
        component["licenses"] = _build_licenses(license_id)

    source_url = model_record.get("source_url")
    if source_url:
        component["externalReferences"] = [
            {"type": "distribution", "url": source_url}
        ]

    component["modelCard"] = _build_model_card(metadata)
    component["properties"] = _build_properties(model_record, metadata)

    return component


def _build_licenses(license_id: str) -> list[dict[str, Any]]:
    """Build CycloneDX license structure.  Attempt SPDX ID; fall back to name."""
    # Well-known SPDX identifiers used in HF model cards.
    _HF_TO_SPDX = {
        "mit": "MIT",
        "apache-2.0": "Apache-2.0",
        "cc-by-4.0": "CC-BY-4.0",
        "cc-by-nc-4.0": "CC-BY-NC-4.0",
        "cc-by-sa-4.0": "CC-BY-SA-4.0",
        "llama2": "LLaMA 2 Community License",
        "llama3": "Meta Llama 3 Community License",
        "gemma": "Gemma Terms of Use",
        "gpl-3.0": "GPL-3.0",
        "lgpl-3.0": "LGPL-3.0",
        "openrail": "OpenRAIL",
        "openrail++": "OpenRAIL++",
    }
    normalized = license_id.lower().strip()
    spdx = _HF_TO_SPDX.get(normalized)
    if spdx and not any(c in spdx for c in (" ", "Meta", "Gemma", "OpenRAIL")):
        return [{"license": {"id": spdx}}]
    return [{"license": {"name": license_id}}]


def _build_model_card(metadata: dict[str, Any]) -> dict[str, Any]:
    """Build the ``modelCard`` block from AIAF metadata."""
    mc: dict[str, Any] = {}

    # Model parameters from HF enrichment data (stored in metadata.hf_model_card).
    hf = metadata.get("hf_model_card") or {}
    params: dict[str, Any] = {}
    if hf.get("pipeline_tag"):
        params["task"] = hf["pipeline_tag"]
    if hf.get("model_type"):
        params["architectureFamily"] = hf["model_type"]
    if hf.get("architectures"):
        archs = hf["architectures"]
        params["modelArchitecture"] = archs[0] if isinstance(archs, list) else archs
    if params:
        mc["modelParameters"] = params

    # Quantitative analysis — provenance and risk scores.
    prov = metadata.get("provenance_assessment") or {}
    risk_metrics = []
    if prov.get("provenance_score") is not None:
        risk_metrics.append({
            "name": "provenance_score",
            "value": str(prov["provenance_score"]),
            "type": "informational",
        })
    if prov.get("risk_level"):
        risk_metrics.append({
            "name": "risk_level",
            "value": str(prov["risk_level"]),
            "type": "informational",
        })
    if risk_metrics:
        mc["quantitativeAnalysis"] = {"performanceMetrics": risk_metrics}

    return mc if mc else {"modelParameters": {}}


def _build_properties(
    model_record: dict[str, Any],
    metadata: dict[str, Any],
) -> list[dict[str, str]]:
    """Encode AIAF-specific fields as CycloneDX properties (name/value pairs)."""
    props: list[dict[str, str]] = []

    def _add(name: str, value: Any) -> None:
        if value is not None:
            props.append({"name": f"aiaf:{name}", "value": str(value)})

    _add("model_id", model_record.get("model_id"))
    _add("risk_level", model_record.get("risk_level"))
    _add("provenance_score", model_record.get("provenance_score"))
    _add("source", model_record.get("source"))
    _add("registered_by", model_record.get("registered_by"))
    _add("registered_at", model_record.get("uploaded_at") or model_record.get("created_at"))

    prov = metadata.get("provenance_assessment") or {}
    _add("provenance_confidence", prov.get("confidence"))
    _add("assessment_complete", prov.get("assessment_complete"))

    rec = metadata.get("adoption_recommendation") or {}
    _add("adoption_verdict", rec.get("verdict"))
    _add("adoption_verdict_rank", rec.get("verdict_rank"))
    _add("adoption_confidence", rec.get("confidence"))

    return props


def _build_dependencies(
    model_record: dict[str, Any],
    bom_ref: str,
) -> list[dict[str, Any]]:
    """Build the dependencies block from the model's dependency inventory."""
    raw_deps = model_record.get("dependencies") or []
    dep_refs = []
    dep_components = []
    for dep in raw_deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        eco = dep.get("ecosystem", "pypi")
        ref = f"dep:{eco}:{name}:{version}"
        dep_refs.append(ref)
        dep_components.append({
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": f"pkg:{eco}/{name}@{version}" if version else f"pkg:{eco}/{name}",
        })

    bom_deps: list[dict[str, Any]] = [{"ref": bom_ref, "dependsOn": dep_refs}]
    return bom_deps, dep_components


def _build_runtime_components(ai_bom: dict[str, Any], bom_ref: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    components = ((ai_bom.get("components") if isinstance(ai_bom.get("components"), dict) else {}) or {}).get("runtime_components") or []
    runtime_components = []
    runtime_refs = []
    for component in components:
        if not isinstance(component, dict):
            continue
        runtime_ref = str(component.get("bom_ref") or "")
        if not runtime_ref:
            continue
        runtime_refs.append(runtime_ref)
        runtime_components.append(_build_runtime_component(component))
    if runtime_refs:
        return [{"ref": bom_ref, "dependsOn": runtime_refs}], runtime_components
    return [], runtime_components


def _build_runtime_component(component: dict[str, Any]) -> dict[str, Any]:
    runtime_type = str(component.get("type") or "runtime")
    name = str(component.get("name") or runtime_type)
    cyclonedx_type = _runtime_cyclonedx_type(runtime_type)
    exported: dict[str, Any] = {
        "type": cyclonedx_type,
        "bom-ref": str(component.get("bom_ref")),
        "name": name,
        "properties": [{"name": "aiaf:runtime_type", "value": runtime_type}],
    }

    version = component.get("version")
    if version:
        exported["version"] = str(version)
    hashes = component.get("hashes")
    if isinstance(hashes, dict) and hashes.get("sha256"):
        exported["hashes"] = [{"alg": "SHA-256", "content": str(hashes["sha256"])}]

    for field in (
        "role",
        "source",
        "manifest_id",
        "risk_tier",
        "server_id",
        "endpoint",
        "transport",
        "store_id",
        "collection_name",
        "store_type",
        "embedding_model",
        "provider",
        "service",
        "mode",
        "profile",
        "policy_kind",
        "scope",
        "source_url",
    ):
        value = component.get(field)
        if value is not None:
            exported["properties"].append({"name": f"aiaf:{field}", "value": str(value)})
    return exported


def _runtime_cyclonedx_type(runtime_type: str) -> str:
    return {
        "prompt": "data",
        "system-prompt-hash": "data",
        "tool": "application",
        "mcp-server": "service",
        "rag-index": "data",
        "embedding-model": "machine-learning-model",
        "provider": "service",
        "guardrail": "service",
        "policy": "application",
        "evaluator": "application",
    }.get(runtime_type, "application")


# ---------------------------------------------------------------------------
# Import: CycloneDX BOM → AIAF registration parameters
# ---------------------------------------------------------------------------


def import_bom(bom_dict: dict[str, Any]) -> dict[str, Any]:
    """Extract AIAF model registration parameters from a CycloneDX BOM.

    Returns a dict with keys suitable for passing to ``POST /models/register``
    plus an ``evidence_origin_hints`` field listing how each extracted field
    should be tagged in the evidence ledger.
    """
    bom_dict = bom_dict if isinstance(bom_dict, dict) else {}

    # Find the primary machine-learning-model component, not a runtime
    # embedding-model component exported as CycloneDX machine-learning-model.
    components = [component for component in (bom_dict.get("components") or []) if isinstance(component, dict)]
    component = next(
        (
            c
            for c in components
            if c.get("type") == "machine-learning-model" and _runtime_component_type(c) is None
        ),
        next((c for c in components if c.get("type") == "machine-learning-model"), components[0] if components else {}),
    )

    result: dict[str, Any] = {
        "bom_format": bom_dict.get("bomFormat"),
        "spec_version": bom_dict.get("specVersion"),
        "model_id": None,
        "model_name": component.get("name"),
        "version": component.get("version"),
        "source": None,
        "publisher": None,
        "license": None,
        "sha256": None,
        "source_url": None,
        "dependencies": [],
        "tools": [],
        "runtime_components": [],
        "model_type": None,
        "pipeline_tag": None,
        "metadata": {},
        "evidence_origin_hints": {},
        "aiaf_properties": {},
    }

    # Publisher.
    supplier = component.get("supplier") or {}
    result["publisher"] = component.get("publisher") or supplier.get("name")
    if result["publisher"]:
        result["evidence_origin_hints"]["publisher"] = "provider_declared"

    # License.
    licenses = component.get("licenses") or []
    if licenses:
        lic = licenses[0].get("license") or {}
        result["license"] = lic.get("id") or lic.get("name")
        if result["license"]:
            result["evidence_origin_hints"]["license"] = "provider_declared"

    # SHA-256.
    hashes = component.get("hashes") or []
    for h in hashes:
        if str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
            result["sha256"] = h.get("content")
            result["evidence_origin_hints"]["sha256"] = "locally_observed"
            break

    # Source URL.
    ext_refs = component.get("externalReferences") or []
    for ref in ext_refs:
        if ref.get("type") in ("distribution", "source", "website"):
            result["source_url"] = ref.get("url")
            result["evidence_origin_hints"]["source_url"] = "provider_declared"
            break

    # Model card parameters.
    model_card = component.get("modelCard") or {}
    params = model_card.get("modelParameters") or {}
    result["pipeline_tag"] = params.get("task")
    result["model_type"] = params.get("architectureFamily")

    # AIAF properties (round-trip preservation).
    for prop in component.get("properties") or []:
        name = str(prop.get("name", ""))
        if name.startswith("aiaf:"):
            result["aiaf_properties"][name[5:]] = prop.get("value")
    result["model_id"] = result["aiaf_properties"].get("model_id")
    result["source"] = result["aiaf_properties"].get("source")

    # Dependencies from components.
    for comp in components:
        if comp.get("type") == "library" and comp.get("name"):
            result["dependencies"].append(
                {
                    "name": comp["name"],
                    "version": comp.get("version", ""),
                    "ecosystem": _purl_ecosystem(comp.get("purl", "")),
                }
            )

    _import_runtime_components(components, result)
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _purl_ecosystem(purl: str) -> str:
    """Extract ecosystem from a purl string (e.g. ``pkg:pypi/...`` → ``pypi``)."""
    if purl.startswith("pkg:"):
        parts = purl[4:].split("/", 1)
        if parts:
            return parts[0]
    return "unknown"


def _runtime_component_type(component: dict[str, Any]) -> str | None:
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        if str(prop.get("name") or "") == "aiaf:runtime_type":
            value = str(prop.get("value") or "").strip()
            return value or None
    return None


def _runtime_properties(component: dict[str, Any]) -> dict[str, str]:
    properties: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        name = str(prop.get("name") or "")
        if not name.startswith("aiaf:") or name == "aiaf:runtime_type":
            continue
        key = name[5:]
        value = prop.get("value")
        if value is not None:
            properties[key] = str(value)
    return properties


def _component_sha256(component: dict[str, Any]) -> str | None:
    for item in component.get("hashes") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("alg", "")).upper() in {"SHA-256", "SHA256"}:
            value = item.get("content")
            if value is not None:
                return str(value)
    return None


def _import_runtime_components(components: list[dict[str, Any]], result: dict[str, Any]) -> None:
    metadata = result["metadata"]
    runtime_components = result["runtime_components"]
    for component in components:
        runtime_type = _runtime_component_type(component)
        if runtime_type is None:
            continue
        props = _runtime_properties(component)
        imported = {
            "type": runtime_type,
            "bom_ref": component.get("bom-ref"),
            "name": component.get("name"),
            "version": component.get("version"),
            "hashes": {"sha256": _component_sha256(component)} if _component_sha256(component) else {},
            **props,
        }
        runtime_components.append(imported)

        if runtime_type == "prompt":
            metadata.setdefault("prompt_templates", []).append(
                {
                    "name": component.get("name"),
                    "role": props.get("role"),
                    "source": props.get("source"),
                    "sha256": _component_sha256(component),
                }
            )
            result["evidence_origin_hints"]["metadata.prompt_templates"] = "provider_declared"
        elif runtime_type == "system-prompt-hash":
            if metadata.get("system_prompt_hash") is None:
                metadata["system_prompt_hash"] = _component_sha256(component)
            result["evidence_origin_hints"]["metadata.system_prompt_hash"] = "provider_declared"
        elif runtime_type == "tool":
            result["tools"].append(
                {
                    "name": component.get("name"),
                    "version": component.get("version"),
                    "manifest_id": props.get("manifest_id"),
                    "risk_tier": props.get("risk_tier"),
                }
            )
            result["evidence_origin_hints"]["tools"] = "provider_declared"
        elif runtime_type == "mcp-server":
            metadata.setdefault("mcp_servers", []).append(
                {
                    "server_id": props.get("server_id"),
                    "name": component.get("name"),
                    "endpoint": props.get("endpoint"),
                    "transport": props.get("transport"),
                }
            )
            result["evidence_origin_hints"]["metadata.mcp_servers"] = "provider_declared"
        elif runtime_type == "rag-index":
            metadata.setdefault("rag_indexes", []).append(
                {
                    "store_id": props.get("store_id"),
                    "collection_name": props.get("collection_name"),
                    "store_type": props.get("store_type"),
                    "embedding_model": props.get("embedding_model"),
                }
            )
            result["evidence_origin_hints"]["metadata.rag_indexes"] = "provider_declared"
        elif runtime_type == "embedding-model":
            embedding = {
                "name": component.get("name"),
                "provider": props.get("provider"),
                "source_url": props.get("source_url"),
            }
            if metadata.get("embedding_model") is None:
                metadata["embedding_model"] = embedding
            else:
                metadata.setdefault("embedding_models", []).append(embedding)
            result["evidence_origin_hints"]["metadata.embedding_model"] = "provider_declared"
        elif runtime_type == "provider":
            provider = {
                "name": component.get("name"),
                "service": props.get("service"),
            }
            if metadata.get("runtime_provider") is None:
                metadata["runtime_provider"] = provider
            else:
                metadata.setdefault("runtime_providers", []).append(provider)
            result["evidence_origin_hints"]["metadata.runtime_provider"] = "provider_declared"
        elif runtime_type == "guardrail":
            metadata.setdefault("guardrails", []).append(
                {
                    "name": component.get("name"),
                    "provider": props.get("provider"),
                    "mode": props.get("mode"),
                }
            )
            result["evidence_origin_hints"]["metadata.guardrails"] = "provider_declared"
        elif runtime_type == "policy":
            metadata.setdefault("policies", []).append(
                {
                    "name": component.get("name"),
                    "profile": props.get("profile"),
                    "policy_kind": props.get("policy_kind"),
                }
            )
            if metadata.get("agent_policy_profile") is None and props.get("profile"):
                metadata["agent_policy_profile"] = props["profile"]
            result["evidence_origin_hints"]["metadata.policies"] = "provider_declared"
        elif runtime_type == "evaluator":
            metadata.setdefault("evaluators", []).append(
                {
                    "name": component.get("name"),
                    "version": component.get("version"),
                    "scope": props.get("scope"),
                }
            )
            result["evidence_origin_hints"]["metadata.evaluators"] = "provider_declared"

    if runtime_components:
        result["evidence_origin_hints"]["runtime_components"] = "provider_declared"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

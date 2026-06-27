"""Deterministic, bounded AI Bill of Materials generation and verification."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


AI_BOM_SPEC_VERSION = "2.0"
AI_BOM_FORMAT = "AIAF AI-BOM"

_MAX_DEPENDENCIES = 2_000
_MAX_TRAINING_ARTIFACTS = 500
_MAX_ATTESTATIONS = 250
_MAX_MANIFESTS = 500
_MAX_ADVISORY_IDS = 2_000
_MAX_DIAGNOSTICS = 250
_MAX_TEXT = 2_048
_MAX_CANONICAL_BYTES = 10 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
_NPM_EXACT = re.compile(
    r"^[v=]?([0-9]+)\.([0-9]+)\.([0-9]+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "bom_format",
        "spec_version",
        "serial_number",
        "generated_at",
        "subject",
        "components",
        "lineage",
        "provenance",
        "vulnerability_intelligence",
        "evidence_quality",
        "diagnostics",
        "recommendations",
        "assessment_complete",
        "document_sha256",
    }
)
_ATTESTATION_DERIVED_FIELDS = frozenset(
    {
        "attestations",
        "provenance_attestations",
        "provenance_attestation_verifications",
        "verified_attestation_ids",
        "verified_attestation_digests",
    }
)


def generate_ai_bom_v2(
    model_record: Any,
    generation_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate a deterministic AI-BOM without trusting embedded assurance claims."""
    diagnostics: List[Dict[str, Any]] = []
    record = model_record if isinstance(model_record, dict) else {}
    if not isinstance(model_record, dict):
        _diagnostic(diagnostics, "invalid_model_record", "CRITICAL", "Model record must be an object.")
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    context = generation_context if isinstance(generation_context, dict) else {}
    if generation_context is not None and not isinstance(generation_context, dict):
        _diagnostic(diagnostics, "invalid_generation_context", "HIGH", "Generation context must be an object.")

    subject = _model_component(record, diagnostics)
    dependencies, unresolved, conflicts, dependency_bounded = _dependencies(
        record.get("dependencies", metadata.get("dependencies")), diagnostics
    )
    training, training_bounded = _training_artifacts(
        record.get("training_artifacts", metadata.get("training_artifacts")), diagnostics
    )
    deployment = _deployment_component(
        record.get("deployment_pipeline", metadata.get("deployment_pipeline")),
        subject.get("hashes", {}).get("sha256"),
        diagnostics,
    )
    discovery = _discovery_summary(metadata.get("dependency_discovery"), diagnostics)
    provenance = _provenance_summary(record, context, diagnostics)
    vulnerabilities = _vulnerability_summary(
        record.get("vulnerability_scan", metadata.get("vulnerability_scan")), diagnostics
    )

    nodes = [subject] + dependencies + training
    if deployment is not None:
        nodes.append(deployment)
    relationships = []
    for component in dependencies:
        relationships.append(
            {"from": component["bom_ref"], "relationship": "dependency_of", "to": subject["bom_ref"]}
        )
    for component in training:
        relationships.append(
            {"from": component["bom_ref"], "relationship": "training_input_to", "to": subject["bom_ref"]}
        )
    if deployment is not None:
        relationships.append(
            {"from": subject["bom_ref"], "relationship": "deployed_as", "to": deployment["bom_ref"]}
        )
    nodes.sort(key=lambda item: item["bom_ref"])
    relationships.sort(key=lambda item: (item["from"], item["relationship"], item["to"]))

    dimensions = {
        "model_identity": 100 if subject["identity_complete"] else 0,
        "artifact_integrity": 100 if "sha256" in subject.get("hashes", {}) else 0,
        "dependency_inventory": _inventory_quality(dependencies, unresolved, conflicts, dependency_bounded),
        "training_lineage": _training_quality(training, training_bounded),
        "deployment_evidence": _deployment_quality(deployment),
        "provenance_evidence": provenance["evidence_quality"],
        "vulnerability_intelligence": vulnerabilities["evidence_quality"],
    }
    score = sum(dimensions.values()) // len(dimensions)
    assessment_complete = (
        all(value == 100 for value in dimensions.values())
        and not conflicts
        and not unresolved
        and not discovery["errors_present"]
        and not any(item["severity"] in {"CRITICAL", "HIGH"} for item in diagnostics)
    )
    recommendations = _recommendations(dimensions, conflicts, unresolved, discovery)
    generated_at = _text(context.get("generated_at"), 64)
    if context.get("generated_at") is not None and generated_at is None:
        _diagnostic(diagnostics, "invalid_generated_at", "MEDIUM", "Generation timestamp was omitted because it is invalid.")

    document = {
        "bom_format": AI_BOM_FORMAT,
        "spec_version": AI_BOM_SPEC_VERSION,
        "serial_number": "urn:aiaf:ai-bom:" + _identity_digest(subject),
        "generated_at": generated_at,
        "subject": subject,
        "components": {
            "dependencies": dependencies,
            "unresolved_dependencies": unresolved,
            "conflicting_dependencies": conflicts,
            "training_artifacts": training,
            "deployment_artifact": deployment,
            "dependency_discovery": discovery,
        },
        "lineage": {"nodes": nodes, "relationships": relationships},
        "provenance": provenance,
        "vulnerability_intelligence": vulnerabilities,
        "evidence_quality": {"score": score, "dimensions": dimensions},
        "diagnostics": diagnostics[:_MAX_DIAGNOSTICS],
        "recommendations": recommendations,
        "assessment_complete": assessment_complete,
    }
    canonical = _canonical_bytes(document)
    if canonical is None:
        return _minimal_failure_document(diagnostics)
    document["document_sha256"] = hashlib.sha256(canonical).hexdigest()
    return document


def generate_attestable_ai_bom_v2(model_record: Any) -> Dict[str, Any]:
    """Generate the stable pre-attestation AI-BOM used by signed statements."""
    if not isinstance(model_record, dict):
        return generate_ai_bom_v2(model_record)
    projection = dict(model_record)
    metadata = projection.get("metadata")
    projected_metadata = dict(metadata) if isinstance(metadata, dict) else metadata
    for field in _ATTESTATION_DERIVED_FIELDS:
        projection.pop(field, None)
        if isinstance(projected_metadata, dict):
            projected_metadata.pop(field, None)
    if metadata is not None:
        projection["metadata"] = projected_metadata
    return generate_ai_bom_v2(projection)


def verify_ai_bom_v2(document: Any) -> Dict[str, Any]:
    """Verify document integrity and internal component/lineage invariants."""
    checks = {
        "document_is_object": isinstance(document, dict),
        "strict_top_level_fields": False,
        "format_supported": False,
        "spec_version_supported": False,
        "digest_shape_valid": False,
        "digest_matches": False,
        "subject_shape_valid": False,
        "component_collections_valid": False,
        "component_refs_unique": False,
        "component_refs_match_content": False,
        "lineage_nodes_match_components": False,
        "lineage_endpoints_resolve": False,
        "lineage_relationships_unique": False,
        "lineage_relationships_match_components": False,
        "serial_number_matches_subject": False,
        "evidence_score_consistent": False,
    }
    obj = document if isinstance(document, dict) else {}
    checks["strict_top_level_fields"] = set(obj) == _TOP_LEVEL_FIELDS
    checks["format_supported"] = obj.get("bom_format") == AI_BOM_FORMAT
    checks["spec_version_supported"] = obj.get("spec_version") == AI_BOM_SPEC_VERSION
    digest = obj.get("document_sha256")
    checks["digest_shape_valid"] = isinstance(digest, str) and bool(_SHA256.fullmatch(digest))
    unsigned = {key: value for key, value in obj.items() if key != "document_sha256"}
    canonical = _canonical_bytes(unsigned)
    checks["digest_matches"] = (
        canonical is not None
        and checks["digest_shape_valid"]
        and hashlib.sha256(canonical).hexdigest() == digest
    )

    subject = obj.get("subject") if isinstance(obj.get("subject"), dict) else {}
    subject_ref = subject.get("bom_ref")
    checks["subject_shape_valid"] = _valid_ref(subject_ref) and subject.get("type") == "model"
    components = obj.get("components") if isinstance(obj.get("components"), dict) else {}
    dependencies = components.get("dependencies")
    training = components.get("training_artifacts")
    deployment = components.get("deployment_artifact")
    collections_valid = isinstance(dependencies, list) and isinstance(training, list)
    checks["component_collections_valid"] = collections_valid
    all_components = [subject]
    if collections_valid:
        all_components.extend(item for item in dependencies + training if isinstance(item, dict))
    if isinstance(deployment, dict):
        all_components.append(deployment)
    refs = [item.get("bom_ref") for item in all_components]
    checks["component_refs_unique"] = (
        all(_valid_ref(ref) for ref in refs) and len(refs) == len(set(refs))
    )
    lineage = obj.get("lineage") if isinstance(obj.get("lineage"), dict) else {}
    checks["component_refs_match_content"] = bool(all_components) and all(
        _component_ref_matches(item) for item in all_components
    )
    lineage_nodes = lineage.get("nodes")
    if isinstance(lineage_nodes, list):
        expected_nodes = sorted(all_components, key=lambda item: item.get("bom_ref", ""))
        actual_nodes = sorted(
            (item for item in lineage_nodes if isinstance(item, dict)),
            key=lambda item: item.get("bom_ref", ""),
        )
        checks["lineage_nodes_match_components"] = (
            len(actual_nodes) == len(lineage_nodes) and actual_nodes == expected_nodes
        )
    relationships = lineage.get("relationships")
    if isinstance(relationships, list) and checks["component_refs_unique"]:
        ref_set = set(refs)
        triples = []
        endpoints_valid = True
        for item in relationships:
            if not isinstance(item, dict) or set(item) != {"from", "relationship", "to"}:
                endpoints_valid = False
                continue
            triples.append((item["from"], item["relationship"], item["to"]))
            if item["from"] not in ref_set or item["to"] not in ref_set:
                endpoints_valid = False
        checks["lineage_endpoints_resolve"] = endpoints_valid
        checks["lineage_relationships_unique"] = len(triples) == len(set(triples))
        expected_relationships = {
            (item["bom_ref"], "dependency_of", subject_ref)
            for item in dependencies
            if isinstance(item, dict) and _valid_ref(item.get("bom_ref"))
        }
        expected_relationships.update(
            (item["bom_ref"], "training_input_to", subject_ref)
            for item in training
            if isinstance(item, dict) and _valid_ref(item.get("bom_ref"))
        )
        if isinstance(deployment, dict) and _valid_ref(deployment.get("bom_ref")):
            expected_relationships.add((subject_ref, "deployed_as", deployment["bom_ref"]))
        checks["lineage_relationships_match_components"] = set(triples) == expected_relationships
    expected_serial = "urn:aiaf:ai-bom:" + _identity_digest(subject)
    checks["serial_number_matches_subject"] = obj.get("serial_number") == expected_serial
    evidence = obj.get("evidence_quality") if isinstance(obj.get("evidence_quality"), dict) else {}
    dimensions = evidence.get("dimensions")
    if isinstance(dimensions, dict) and dimensions:
        values = list(dimensions.values())
        checks["evidence_score_consistent"] = (
            all(isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 for value in values)
            and evidence.get("score") == sum(values) // len(values)
        )
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "verified": not failed,
        "scoring_version": AI_BOM_SPEC_VERSION,
        "checks": checks,
        "failed_checks": failed,
        "document_sha256": digest if checks["digest_shape_valid"] else None,
    }


def _model_component(record: Dict[str, Any], diagnostics: List[Dict[str, Any]]) -> Dict[str, Any]:
    model_id = _text(record.get("model_id"), 256)
    name = _text(record.get("model_name"), 512)
    version = _text(record.get("version"), 256)
    publisher = _text(record.get("publisher"), 512)
    source = _text(record.get("source"), 256)
    license_name = _text(record.get("license"), 512)
    sha256 = _hash(record.get("sha256"))
    source_url, redacted = _safe_url(record.get("source_url"))
    if redacted:
        _diagnostic(diagnostics, "source_url_credentials_removed", "HIGH", "Credentials were removed from the model source URL.")
    if not model_id or not name or not version:
        _diagnostic(diagnostics, "incomplete_model_identity", "HIGH", "Model ID, name, and version are required for complete identity.")
    if sha256 is None:
        _diagnostic(diagnostics, "missing_or_invalid_model_hash", "CRITICAL", "A lowercase SHA-256 artifact digest is required.")
    identity = {"model_id": model_id, "name": name, "version": version, "sha256": sha256}
    return {
        "bom_ref": "model:" + _digest(identity),
        "type": "model",
        "model_id": model_id,
        "name": name,
        "version": version,
        "publisher": publisher,
        "source": source,
        "source_url": source_url,
        "license": license_name,
        "hashes": {"sha256": sha256} if sha256 else {},
        "identity_complete": bool(model_id and name and version),
    }


def _dependencies(value: Any, diagnostics: List[Dict[str, Any]]):
    items, bounded = _bounded_list(value, _MAX_DEPENDENCIES)
    if not bounded:
        _diagnostic(diagnostics, "dependency_inventory_invalid_or_bounded", "HIGH", "Dependency inventory is malformed or exceeds the component bound.")
    components = []
    unresolved = []
    for index, item in enumerate(items):
        component, reason = _dependency(item)
        if component is None:
            unresolved.append({"source_index": index, "reason": reason})
        else:
            components.append(component)
    unique = {item["bom_ref"]: item for item in components}
    components = sorted(unique.values(), key=lambda item: item["bom_ref"])
    versions: Dict[Tuple[str, str], set] = {}
    for item in components:
        versions.setdefault((item["ecosystem"], item["name"]), set()).add(item["version"])
    conflicts = [
        {"ecosystem": ecosystem, "name": name, "versions": sorted(found)}
        for (ecosystem, name), found in sorted(versions.items())
        if len(found) > 1
    ]
    if unresolved:
        _diagnostic(diagnostics, "unresolved_dependency_coordinates", "HIGH", "One or more dependencies lack an exact supported coordinate.", {"count": len(unresolved)})
    if conflicts:
        _diagnostic(diagnostics, "conflicting_dependency_versions", "HIGH", "One package identity resolves to multiple exact versions.", {"count": len(conflicts)})
    return components, unresolved, conflicts, bounded


def _dependency(item: Any):
    if isinstance(item, str):
        try:
            requirement = Requirement(item)
        except InvalidRequirement:
            return None, "invalid_dependency_requirement"
        exact = _exact_python_version(requirement)
        if exact is None or requirement.url:
            return None, "dependency_version_not_exact"
        name = canonicalize_name(requirement.name)
        return _dependency_component("PyPI", name, exact, None, None), None
    if not isinstance(item, dict):
        return None, "dependency_must_be_text_or_object"
    ecosystem_raw = _text(item.get("ecosystem"), 64)
    ecosystem = {"pypi": "PyPI", "npm": "npm"}.get((ecosystem_raw or "pypi").lower())
    name_raw = _text(item.get("name"), 512)
    version_raw = _text(item.get("version"), 256)
    if not ecosystem or not name_raw or not version_raw:
        return None, "invalid_dependency_coordinate"
    if ecosystem == "PyPI":
        try:
            requirement = Requirement(f"{name_raw}{version_raw}" if version_raw.startswith(("=", "<", ">", "!", "~")) else f"{name_raw}=={version_raw}")
        except InvalidRequirement:
            return None, "invalid_pypi_coordinate"
        version = _exact_python_version(requirement)
        if version is None:
            return None, "dependency_version_not_exact"
        name = canonicalize_name(requirement.name)
    else:
        name = name_raw.lower()
        match = _NPM_EXACT.fullmatch(version_raw)
        if not _NPM_NAME.fullmatch(name) or not match:
            return None, "invalid_or_non_exact_npm_coordinate"
        version = version_raw.lstrip("v=")
    manifest = _text(item.get("source_manifest"), 1_024)
    scope = _text(item.get("scope"), 128)
    return _dependency_component(ecosystem, name, version, manifest, scope), None


def _dependency_component(ecosystem, name, version, manifest, scope):
    purl_name = quote(name, safe="/")
    identity = {"ecosystem": ecosystem, "name": name, "version": version}
    return {
        "bom_ref": "dependency:" + _digest(identity),
        "type": "library",
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem.lower()}/{purl_name}@{quote(version, safe='.-_+')}",
        "source_manifest": manifest,
        "scope": scope,
    }


def _exact_python_version(requirement: Requirement) -> Optional[str]:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="} or "*" in specifiers[0].version:
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


def _training_artifacts(value: Any, diagnostics: List[Dict[str, Any]]):
    items, bounded = _bounded_list(value, _MAX_TRAINING_ARTIFACTS)
    if not bounded:
        _diagnostic(diagnostics, "training_inventory_invalid_or_bounded", "HIGH", "Training artifact inventory is malformed or exceeds the component bound.")
    components = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            _diagnostic(diagnostics, "invalid_training_artifact", "HIGH", "Training artifact must be an object.", {"source_index": index})
            continue
        name = _text(item.get("name"), 512)
        version = _text(item.get("version"), 256)
        sha256 = _hash(item.get("sha256"))
        source_url, redacted = _safe_url(item.get("source_url") or item.get("source"))
        if redacted:
            _diagnostic(diagnostics, "training_source_credentials_removed", "HIGH", "Credentials were removed from a training source URL.", {"source_index": index})
        if not name:
            _diagnostic(diagnostics, "training_artifact_missing_name", "HIGH", "Training artifact has no stable name.", {"source_index": index})
            continue
        identity = {"name": name, "version": version, "sha256": sha256, "source_url": source_url}
        components.append(
            {
                "bom_ref": "dataset:" + _digest(identity),
                "type": "dataset",
                "name": name,
                "version": version,
                "source_url": source_url,
                "license": _text(item.get("license"), 512),
                "hashes": {"sha256": sha256} if sha256 else {},
                "evidence_complete": bool(sha256 and source_url),
            }
        )
        if not sha256 or not source_url:
            _diagnostic(diagnostics, "incomplete_training_lineage", "HIGH", "Training artifact requires a source URL and SHA-256 digest.", {"source_index": index})
    unique = {item["bom_ref"]: item for item in components}
    return sorted(unique.values(), key=lambda item: item["bom_ref"]), bounded


def _deployment_component(value: Any, model_hash: Optional[str], diagnostics):
    if value in (None, {}):
        return None
    if not isinstance(value, dict):
        _diagnostic(diagnostics, "invalid_deployment_evidence", "HIGH", "Deployment evidence must be an object.")
        return None
    environment = _text(value.get("environment"), 256)
    artifact_ref, ref_redacted = _safe_artifact_ref(value.get("artifact_ref"))
    if ref_redacted:
        _diagnostic(
            diagnostics,
            "deployment_reference_credentials_removed",
            "HIGH",
            "Credentials were removed from the deployment artifact reference.",
        )
    approval = _text(value.get("approval_gate"), 512)
    embedded_hash = None
    if artifact_ref and "@sha256:" in artifact_ref:
        embedded_hash = _hash(artifact_ref.rsplit("@sha256:", 1)[1])
    integrity = "UNVERIFIED"
    if embedded_hash and model_hash:
        integrity = "MATCH" if embedded_hash == model_hash else "MISMATCH"
    if integrity == "MISMATCH":
        _diagnostic(diagnostics, "deployment_artifact_hash_mismatch", "CRITICAL", "Deployment artifact digest differs from the registered model digest.")
    identity = {"environment": environment, "artifact_ref": artifact_ref}
    return {
        "bom_ref": "deployment:" + _digest(identity),
        "type": "deployment",
        "environment": environment,
        "artifact_ref": artifact_ref,
        "approval_gate": approval,
        "hashes": {"sha256": embedded_hash} if embedded_hash else {},
        "integrity_status": integrity,
    }


def _discovery_summary(value: Any, diagnostics):
    if value in (None, {}):
        return {"manifests": [], "declared_dependency_count": None, "errors_present": False}
    if not isinstance(value, dict):
        _diagnostic(diagnostics, "invalid_dependency_discovery_evidence", "MEDIUM", "Dependency discovery evidence must be an object.")
        return {"manifests": [], "declared_dependency_count": None, "errors_present": True}
    manifests, bounded = _bounded_list(value.get("manifests"), _MAX_MANIFESTS)
    safe_manifests = sorted({item for item in (_text(raw, 1_024) for raw in manifests) if item})
    errors = value.get("errors")
    errors_present = bool(errors) or not bounded
    if errors_present:
        _diagnostic(diagnostics, "dependency_discovery_incomplete", "HIGH", "Dependency discovery reported errors or exceeded bounds.")
    count = value.get("dependency_count")
    count = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None
    return {"manifests": safe_manifests, "declared_dependency_count": count, "errors_present": errors_present}


def _provenance_summary(record, context, diagnostics):
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    raw = record.get("attestations")
    if raw is None:
        raw = record.get("provenance_attestations")
    if raw is None:
        raw = metadata.get("attestations")
    if raw is None:
        raw = metadata.get("provenance_attestations")
    attestations, bounded = _bounded_list(raw, _MAX_ATTESTATIONS)
    trusted_ids_raw = context.get("verified_attestation_ids")
    trusted_ids, trusted_bounded = _bounded_list(trusted_ids_raw, _MAX_ATTESTATIONS)
    trusted = {_text(item, 256) for item in trusted_ids}
    trusted.discard(None)
    summaries = []
    for item in attestations:
        if not isinstance(item, dict):
            continue
        statement = item.get("statement") if isinstance(item.get("statement"), dict) else {}
        attestation_id = _text(statement.get("attestation_id"), 256)
        summaries.append(
            {
                "attestation_id": attestation_id,
                "schema_version": _text(item.get("schema_version"), 64),
                "key_id": _text(item.get("key_id"), 256),
                "trusted_verification": bool(attestation_id and attestation_id in trusted),
            }
        )
    summaries.sort(key=lambda item: (item["attestation_id"] or "", item["key_id"] or ""))
    verified_count = sum(item["trusted_verification"] for item in summaries)
    if raw and not bounded:
        _diagnostic(diagnostics, "attestation_inventory_bounded", "HIGH", "Attestation inventory exceeds the evidence bound.")
    if trusted_ids_raw is not None and not trusted_bounded:
        _diagnostic(diagnostics, "trusted_verification_context_bounded", "HIGH", "Trusted attestation verification context is invalid or oversized.")
    quality = 100 if summaries and verified_count == len(summaries) and bounded and trusted_bounded else (50 if summaries else 0)
    return {
        "attestations": summaries,
        "attestation_count": len(summaries),
        "trusted_verified_count": verified_count,
        "evidence_quality": quality,
    }


def _vulnerability_summary(value: Any, diagnostics):
    if not isinstance(value, dict) or not value:
        return {"status": "NOT_ASSESSED", "match_count": 0, "by_severity": {key: 0 for key in _SEVERITIES}, "advisory_ids": [], "evidence_quality": 0}
    matches, bounded = _bounded_list(value.get("matches"), _MAX_ADVISORY_IDS)
    advisory_ids = set()
    counts = {key: 0 for key in _SEVERITIES}
    for item in matches:
        if not isinstance(item, dict):
            continue
        advisory_id = _text(item.get("advisory_id"), 256)
        severity = (_text(item.get("severity"), 32) or "UNKNOWN").upper()
        severity = severity if severity in counts else "UNKNOWN"
        if advisory_id:
            advisory_ids.add(advisory_id)
            counts[severity] += 1
    declared = value.get("match_count")
    consistent = declared is None or (isinstance(declared, int) and not isinstance(declared, bool) and declared == len(matches))
    complete = value.get("assessment_complete") is True and bounded and consistent
    if not bounded or not consistent:
        _diagnostic(diagnostics, "inconsistent_vulnerability_evidence", "HIGH", "Vulnerability evidence is malformed, oversized, or internally inconsistent.")
    return {
        "status": "ASSESSED" if complete else "PARTIAL",
        "match_count": len(advisory_ids),
        "by_severity": counts,
        "advisory_ids": sorted(advisory_ids),
        "evidence_quality": 100 if complete else 50,
    }


def _inventory_quality(components, unresolved, conflicts, bounded):
    if not components:
        return 0
    return 100 if bounded and not unresolved and not conflicts else 50


def _training_quality(components, bounded):
    if not components:
        return 0
    return 100 if bounded and all(item["evidence_complete"] for item in components) else 50


def _deployment_quality(component):
    if component is None:
        return 0
    required = component.get("environment") and component.get("artifact_ref") and component.get("approval_gate")
    return 100 if required and component["integrity_status"] == "MATCH" else 50


def _recommendations(dimensions, conflicts, unresolved, discovery):
    recommendations = []
    labels = {
        "model_identity": "Register immutable model identity fields.",
        "artifact_integrity": "Record a lowercase SHA-256 model artifact digest.",
        "dependency_inventory": "Resolve every dependency to one exact supported package version.",
        "training_lineage": "Record source and SHA-256 evidence for each training artifact.",
        "deployment_evidence": "Bind the deployed artifact digest and approval evidence to the model.",
        "provenance_evidence": "Verify provenance attestations in a trusted verification context.",
        "vulnerability_intelligence": "Run a complete dependency vulnerability assessment.",
    }
    for key, value in dimensions.items():
        if value < 100:
            recommendations.append(labels[key])
    if conflicts:
        recommendations.append("Resolve conflicting versions for each package identity.")
    if unresolved:
        recommendations.append("Replace dependency ranges and direct references with immutable coordinates.")
    if discovery["errors_present"]:
        recommendations.append("Remediate dependency discovery errors and regenerate the AI-BOM.")
    return recommendations


def _bounded_list(value, limit):
    if value is None:
        return [], True
    if not isinstance(value, list):
        return [], False
    if len(value) > limit:
        return value[:limit], False
    return value, True


def _safe_url(value):
    text = _text(value, _MAX_TEXT)
    if text is None:
        return None, False
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return None, False
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None, False
    redacted = (
        parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    )
    host = parsed.hostname
    if port:
        host += f":{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", "")), redacted


def _safe_artifact_ref(value):
    text = _text(value, _MAX_TEXT)
    if text is None:
        return None, False
    if "://" in text:
        return _safe_url(text)
    credential_prefix = re.match(r"^[^/@:]+:[^/@]+@(.+)$", text)
    if credential_prefix:
        return credential_prefix.group(1), True
    return text, False


def _hash(value):
    if isinstance(value, str):
        candidate = value.lower()
        if _SHA256.fullmatch(candidate):
            return candidate
    return None


def _text(value, limit):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value.encode("utf-8")) > limit or any(ord(char) < 32 for char in value):
        return None
    return value


def _identity_digest(subject):
    return _digest(
        {
            "model_id": subject.get("model_id"),
            "name": subject.get("name"),
            "version": subject.get("version"),
            "sha256": subject.get("hashes", {}).get("sha256") if isinstance(subject.get("hashes"), dict) else None,
        }
    )


def _digest(value):
    canonical = _canonical_bytes(value)
    return hashlib.sha256(canonical or b"invalid").hexdigest()


def _canonical_bytes(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return None
    return encoded if len(encoded) <= _MAX_CANONICAL_BYTES else None


def _valid_ref(value):
    return isinstance(value, str) and len(value) <= 128 and ":" in value


def _component_ref_matches(component):
    if not isinstance(component, dict):
        return False
    component_type = component.get("type")
    if component_type == "model":
        expected = "model:" + _digest(
            {
                "model_id": component.get("model_id"),
                "name": component.get("name"),
                "version": component.get("version"),
                "sha256": component.get("hashes", {}).get("sha256")
                if isinstance(component.get("hashes"), dict)
                else None,
            }
        )
    elif component_type == "library":
        expected = "dependency:" + _digest(
            {
                "ecosystem": component.get("ecosystem"),
                "name": component.get("name"),
                "version": component.get("version"),
            }
        )
    elif component_type == "dataset":
        expected = "dataset:" + _digest(
            {
                "name": component.get("name"),
                "version": component.get("version"),
                "sha256": component.get("hashes", {}).get("sha256")
                if isinstance(component.get("hashes"), dict)
                else None,
                "source_url": component.get("source_url"),
            }
        )
    elif component_type == "deployment":
        expected = "deployment:" + _digest(
            {
                "environment": component.get("environment"),
                "artifact_ref": component.get("artifact_ref"),
            }
        )
    else:
        return False
    return component.get("bom_ref") == expected


def _diagnostic(diagnostics, indicator, severity, detail, evidence=None):
    if len(diagnostics) >= _MAX_DIAGNOSTICS:
        return
    item = {"indicator": indicator, "severity": severity, "detail": detail}
    if evidence:
        item["evidence"] = evidence
    diagnostics.append(item)


def _minimal_failure_document(diagnostics):
    subject = {
        "bom_ref": "model:" + hashlib.sha256(b"invalid").hexdigest(),
        "type": "model",
        "model_id": None,
        "name": None,
        "version": None,
        "publisher": None,
        "source": None,
        "source_url": None,
        "license": None,
        "hashes": {},
        "identity_complete": False,
    }
    document = {
        "bom_format": AI_BOM_FORMAT,
        "spec_version": AI_BOM_SPEC_VERSION,
        "serial_number": "urn:aiaf:ai-bom:" + _identity_digest(subject),
        "generated_at": None,
        "subject": subject,
        "components": {"dependencies": [], "unresolved_dependencies": [], "conflicting_dependencies": [], "training_artifacts": [], "deployment_artifact": None, "dependency_discovery": {"manifests": [], "declared_dependency_count": None, "errors_present": True}},
        "lineage": {"nodes": [subject], "relationships": []},
        "provenance": {"attestations": [], "attestation_count": 0, "trusted_verified_count": 0, "evidence_quality": 0},
        "vulnerability_intelligence": {"status": "NOT_ASSESSED", "match_count": 0, "by_severity": {key: 0 for key in _SEVERITIES}, "advisory_ids": [], "evidence_quality": 0},
        "evidence_quality": {"score": 0, "dimensions": {"generation": 0}},
        "diagnostics": (diagnostics + [{"indicator": "canonical_generation_failed", "severity": "CRITICAL", "detail": "AI-BOM exceeded canonical representation constraints."}])[:_MAX_DIAGNOSTICS],
        "recommendations": ["Reduce malformed or oversized evidence and regenerate the AI-BOM."],
        "assessment_complete": False,
    }
    document["document_sha256"] = hashlib.sha256(_canonical_bytes(document) or b"invalid").hexdigest()
    return document

"""Threat-intelligence framework crosswalks for AI-native threats."""

from __future__ import annotations

from typing import Any

THREAT_FRAMEWORKS_VERSION = "1.0"

FRAMEWORK_AIAF = "AIAF Threat Intel"
FRAMEWORK_OWASP_LLM = "OWASP LLM Top 10 2025"
FRAMEWORK_MITRE_ATLAS = "MITRE ATLAS"
FRAMEWORK_OWASP_AGENTIC = "OWASP Agentic Security"
FRAMEWORK_STIX = "STIX 2.1"

THREAT_FRAMEWORK_PROFILES: dict[str, dict[str, str]] = {
    FRAMEWORK_AIAF: {
        "name": FRAMEWORK_AIAF,
        "version": THREAT_FRAMEWORKS_VERSION,
        "source_url": "",
    },
    FRAMEWORK_OWASP_LLM: {
        "name": FRAMEWORK_OWASP_LLM,
        "version": "2025",
        "source_url": "https://genai.owasp.org/llm-top-10/",
    },
    FRAMEWORK_MITRE_ATLAS: {
        "name": FRAMEWORK_MITRE_ATLAS,
        "version": "current",
        "source_url": "https://atlas.mitre.org/",
    },
    FRAMEWORK_OWASP_AGENTIC: {
        "name": FRAMEWORK_OWASP_AGENTIC,
        "version": "current",
        "source_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    FRAMEWORK_STIX: {
        "name": FRAMEWORK_STIX,
        "version": "2.1",
        "source_url": "https://docs.oasis-open.org/cti/stix/v2.1/",
    },
}


def crosswalk_threat_frameworks(threat: dict[str, Any]) -> dict[str, Any]:
    """Return normalized framework references for one threat technique."""
    technique_id = str(threat.get("technique_id") or "").strip()
    references: dict[str, list[str]] = {}
    if technique_id:
        references[FRAMEWORK_AIAF] = [technique_id]
        references[FRAMEWORK_STIX] = [f"attack-pattern--{technique_id.lower()}"]

    owasp_llm_id = str(threat.get("owasp_llm_id") or "").strip()
    if owasp_llm_id:
        references[FRAMEWORK_OWASP_LLM] = [owasp_llm_id]

    mitre_atlas_id = str(threat.get("mitre_atlas_id") or "").strip()
    if mitre_atlas_id:
        references[FRAMEWORK_MITRE_ATLAS] = [mitre_atlas_id]

    if technique_id.startswith("AGENTIC-"):
        references[FRAMEWORK_OWASP_AGENTIC] = [technique_id]

    return {
        "mapping_version": THREAT_FRAMEWORKS_VERSION,
        "frameworks": sorted(references),
        "references": references,
    }

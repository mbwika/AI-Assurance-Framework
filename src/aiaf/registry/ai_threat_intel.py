"""AI-Native Threat Intelligence Engine.

Maintains a structured knowledge base of AI-specific threat techniques drawn
from OWASP LLM Top-10 2025, MITRE ATLAS, and OWASP Agentic Security, and
correlates them dynamically to models, agents, and tools in the AIAF registry.

Built-in knowledge base (20 techniques) is kept in-memory and always available
without store initialisation.  Operators can extend or override any technique
by ingesting a custom entry — custom entries in the store take precedence over
built-ins with the same ``technique_id``.

Key functions
-------------
ingest_threat        — add or update a custom threat technique
get_threat           — look up one technique (custom → built-in fallback)
list_threats         — list all techniques with optional filters
correlate_model      — return relevant threats for a model record
correlate_agent      — return relevant threats for an agent record
correlate_tool       — return relevant threats for a tool record
build_threat_landscape — aggregate view of the threat landscape
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

THREAT_INTEL_VERSION = "1.0"

# ── Asset types ────────────────────────────────────────────────────────────────
ASSET_MODEL = "MODEL"
ASSET_AGENT = "AGENT"
ASSET_TOOL = "TOOL"
ASSET_DATASET = "DATASET"
ASSET_RAG_STORE = "RAG_STORE"
ASSET_MCP_SERVER = "MCP_SERVER"

ASSET_TYPES: frozenset = frozenset(
    {ASSET_MODEL, ASSET_AGENT, ASSET_TOOL, ASSET_DATASET, ASSET_RAG_STORE, ASSET_MCP_SERVER}
)

# ── Threat categories ──────────────────────────────────────────────────────────
CATEGORY_PROMPT_ATTACKS = "PROMPT_ATTACKS"
CATEGORY_DATA_ATTACKS = "DATA_ATTACKS"
CATEGORY_SUPPLY_CHAIN = "SUPPLY_CHAIN"
CATEGORY_EXFILTRATION = "EXFILTRATION"
CATEGORY_AVAILABILITY = "AVAILABILITY"
CATEGORY_MODEL_INTEGRITY = "MODEL_INTEGRITY"
CATEGORY_IDENTITY_ATTACKS = "IDENTITY_ATTACKS"

CATEGORIES: frozenset = frozenset({
    CATEGORY_PROMPT_ATTACKS, CATEGORY_DATA_ATTACKS, CATEGORY_SUPPLY_CHAIN,
    CATEGORY_EXFILTRATION, CATEGORY_AVAILABILITY, CATEGORY_MODEL_INTEGRITY,
    CATEGORY_IDENTITY_ATTACKS,
})

# ── Severity ───────────────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

_SEVERITY_RANK: dict[str, int] = {
    SEVERITY_CRITICAL: 3, SEVERITY_HIGH: 2, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 0,
}

# ── Sources ────────────────────────────────────────────────────────────────────
SOURCE_OWASP_LLM = "OWASP_LLM_2025"
SOURCE_MITRE_ATLAS = "MITRE_ATLAS"
SOURCE_OWASP_AGENTIC = "OWASP_AGENTIC"
SOURCE_CUSTOM = "CUSTOM"

_THREAT_PREFIX = "ai_threat:"


class ThreatIntelError(ValueError):
    pass


# ── Built-in knowledge base ────────────────────────────────────────────────────
# 20 techniques: 10 OWASP LLM 2025, 7 MITRE ATLAS, 3 OWASP Agentic

_BUILTIN_THREATS: list[dict[str, Any]] = [
    # ── OWASP LLM 2025 ────────────────────────────────────────────────────────
    {
        "technique_id": "LLM01",
        "name": "Prompt Injection",
        "category": CATEGORY_PROMPT_ATTACKS,
        "description": (
            "Crafted inputs that override system instructions, hijack model behaviour, "
            "or exfiltrate data — including indirect injection via retrieved documents."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT],
        "severity": SEVERITY_CRITICAL,
        "owasp_llm_id": "LLM01",
        "mitre_atlas_id": None,
        "capability_triggers": ["chat", "assistant", "instruction-following", "agentic"],
        "recommended_controls": ["input_validation", "output_filtering", "prompt_hardening"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "category": CATEGORY_EXFILTRATION,
        "description": (
            "Model reveals PII, credentials, system prompts, or memorised training data "
            "in its outputs."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT, ASSET_RAG_STORE],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM02",
        "mitre_atlas_id": None,
        "capability_triggers": ["retrieval", "question answering", "summarization"],
        "recommended_controls": ["output_filtering", "pii_redaction", "access_controls"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "category": CATEGORY_SUPPLY_CHAIN,
        "description": (
            "Risks from third-party models, datasets, plugins, fine-tuning pipelines, "
            "and pre-trained weights sourced from untrusted origins."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_TOOL, ASSET_DATASET],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM03",
        "mitre_atlas_id": "AML.T0010",
        "capability_triggers": [],
        "recommended_controls": ["artifact_signing", "provenance_verification", "sbom"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM04",
        "name": "Data and Model Poisoning",
        "category": CATEGORY_MODEL_INTEGRITY,
        "description": (
            "Adversarial manipulation of training data or fine-tuning pipelines to "
            "implant backdoors, bias, or hidden behaviours."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_DATASET],
        "severity": SEVERITY_CRITICAL,
        "owasp_llm_id": "LLM04",
        "mitre_atlas_id": "AML.T0020",
        "capability_triggers": ["fine-tuned", "custom", "domain-adapted"],
        "recommended_controls": ["dataset_provenance", "training_integrity", "behavioral_testing"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM05",
        "name": "Improper Output Handling",
        "category": CATEGORY_PROMPT_ATTACKS,
        "description": (
            "Downstream vulnerabilities (XSS, SSRF, code injection, SQL injection) "
            "caused by trusting model-generated content without validation."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM05",
        "mitre_atlas_id": None,
        "capability_triggers": ["code generation", "sql generation", "html generation"],
        "recommended_controls": ["output_validation", "output_sanitization", "content_security_policy"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM06",
        "name": "Excessive Agency",
        "category": CATEGORY_DATA_ATTACKS,
        "description": (
            "Agent is granted more permissions, capabilities, or autonomy than needed "
            "for its task, enabling unintended or malicious actions."
        ),
        "affected_asset_types": [ASSET_AGENT, ASSET_TOOL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM06",
        "mitre_atlas_id": None,
        "capability_triggers": ["agentic", "autonomous", "tool-use"],
        "recommended_controls": ["least_privilege", "tool_authorization", "human_in_the_loop"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM07",
        "name": "System Prompt Leakage",
        "category": CATEGORY_EXFILTRATION,
        "description": (
            "System prompts, instructions, or configuration data disclosed to "
            "end users through direct extraction or side-channel inference."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT],
        "severity": SEVERITY_MEDIUM,
        "owasp_llm_id": "LLM07",
        "mitre_atlas_id": None,
        "capability_triggers": ["chat", "assistant"],
        "recommended_controls": ["prompt_confidentiality", "output_filtering"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "category": CATEGORY_DATA_ATTACKS,
        "description": (
            "Exploits in RAG pipelines: embedding poisoning, retrieval manipulation, "
            "cross-user data leakage, stale index attacks."
        ),
        "affected_asset_types": [ASSET_RAG_STORE, ASSET_MODEL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM08",
        "mitre_atlas_id": None,
        "capability_triggers": ["retrieval", "rag", "embedding"],
        "recommended_controls": ["retrieval_access_control", "document_trust_labels", "index_freshness"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM09",
        "name": "Misinformation",
        "category": CATEGORY_MODEL_INTEGRITY,
        "description": (
            "Model generates plausible but false content (hallucination, fabrication), "
            "misleading users or downstream systems."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT],
        "severity": SEVERITY_MEDIUM,
        "owasp_llm_id": "LLM09",
        "mitre_atlas_id": None,
        "capability_triggers": [],
        "recommended_controls": ["hallucination_detection", "fact_grounding", "uncertainty_disclosure"],
        "source": SOURCE_OWASP_LLM,
    },
    {
        "technique_id": "LLM10",
        "name": "Unbounded Consumption",
        "category": CATEGORY_AVAILABILITY,
        "description": (
            "Excessive resource usage — token floods, denial-of-wallet attacks, "
            "runaway agent loops, and recursive planning chains — degrade availability "
            "and inflate operational costs."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_AGENT],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM10",
        "mitre_atlas_id": None,
        "capability_triggers": ["agentic", "autonomous", "tool-use"],
        "recommended_controls": ["rate_limiting", "token_budgets", "resource_monitoring"],
        "source": SOURCE_OWASP_LLM,
    },
    # ── MITRE ATLAS ────────────────────────────────────────────────────────────
    {
        "technique_id": "AML.T0018",
        "name": "Backdoor ML Model",
        "category": CATEGORY_MODEL_INTEGRITY,
        "description": (
            "Adversary implants a trigger in model weights during training or fine-tuning "
            "causing specific inputs to produce attacker-controlled outputs."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_DATASET],
        "severity": SEVERITY_CRITICAL,
        "owasp_llm_id": "LLM04",
        "mitre_atlas_id": "AML.T0018",
        "capability_triggers": ["fine-tuned", "custom", "open-weight"],
        "recommended_controls": ["behavioral_testing", "backdoor_detection", "weight_integrity"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0020",
        "name": "Poison Training Data",
        "category": CATEGORY_DATA_ATTACKS,
        "description": (
            "Injecting malicious examples into training or fine-tuning datasets to "
            "degrade model performance or introduce targeted misclassification."
        ),
        "affected_asset_types": [ASSET_DATASET, ASSET_MODEL],
        "severity": SEVERITY_CRITICAL,
        "owasp_llm_id": "LLM04",
        "mitre_atlas_id": "AML.T0020",
        "capability_triggers": [],
        "recommended_controls": ["dataset_provenance", "data_integrity_checks", "benchmark_contamination_testing"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0024",
        "name": "Exfiltration via ML Inference API",
        "category": CATEGORY_EXFILTRATION,
        "description": (
            "Systematic black-box querying to reconstruct model weights, decision "
            "boundaries, or training data without direct access to model internals."
        ),
        "affected_asset_types": [ASSET_MODEL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM10",
        "mitre_atlas_id": "AML.T0024",
        "capability_triggers": [],
        "recommended_controls": ["rate_limiting", "output_watermarking", "query_anomaly_detection"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0040",
        "name": "ML Model Inference API Access",
        "category": CATEGORY_EXFILTRATION,
        "description": (
            "Gaining unauthorised access to an ML model's inference API as a stepping "
            "stone to extraction, poisoning, or abuse attacks."
        ),
        "affected_asset_types": [ASSET_MODEL, ASSET_MCP_SERVER],
        "severity": SEVERITY_MEDIUM,
        "owasp_llm_id": "LLM03",
        "mitre_atlas_id": "AML.T0040",
        "capability_triggers": [],
        "recommended_controls": ["api_authentication", "network_access_controls"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0043",
        "name": "Craft Adversarial Examples",
        "category": CATEGORY_PROMPT_ATTACKS,
        "description": (
            "Generating inputs that cause a model to produce incorrect or harmful outputs "
            "while appearing benign to human reviewers."
        ),
        "affected_asset_types": [ASSET_MODEL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM01",
        "mitre_atlas_id": "AML.T0043",
        "capability_triggers": [],
        "recommended_controls": ["adversarial_training", "input_preprocessing", "ensemble_defences"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0046",
        "name": "Craft Adversarial Data (RAG)",
        "category": CATEGORY_DATA_ATTACKS,
        "description": (
            "Injecting adversarially crafted documents or embeddings into a retrieval "
            "index to manipulate model outputs via retrieved context."
        ),
        "affected_asset_types": [ASSET_RAG_STORE, ASSET_DATASET],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM08",
        "mitre_atlas_id": "AML.T0046",
        "capability_triggers": ["retrieval", "rag"],
        "recommended_controls": ["document_provenance", "retrieval_filtering", "embedding_integrity"],
        "source": SOURCE_MITRE_ATLAS,
    },
    {
        "technique_id": "AML.T0031",
        "name": "Erode ML Model Integrity",
        "category": CATEGORY_MODEL_INTEGRITY,
        "description": (
            "Gradual degradation of model accuracy or safety properties through repeated "
            "adversarial fine-tuning or continual-learning exploits."
        ),
        "affected_asset_types": [ASSET_MODEL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM04",
        "mitre_atlas_id": "AML.T0031",
        "capability_triggers": ["continual-learning", "online-learning", "fine-tunable"],
        "recommended_controls": ["model_versioning", "regression_testing", "drift_monitoring"],
        "source": SOURCE_MITRE_ATLAS,
    },
    # ── OWASP Agentic Security ─────────────────────────────────────────────────
    {
        "technique_id": "AGENTIC-01",
        "name": "Tool and Resource Misuse",
        "category": CATEGORY_DATA_ATTACKS,
        "description": (
            "Agent invokes tools beyond its intended scope, with over-provisioned "
            "permissions, or in unexpected sequences to cause unintended side effects."
        ),
        "affected_asset_types": [ASSET_AGENT, ASSET_TOOL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM06",
        "mitre_atlas_id": None,
        "capability_triggers": ["tool-use", "agentic", "multi-step"],
        "recommended_controls": ["least_privilege", "tool_manifest_signing", "approval_policies"],
        "source": SOURCE_OWASP_AGENTIC,
    },
    {
        "technique_id": "AGENTIC-02",
        "name": "Agent Identity Spoofing",
        "category": CATEGORY_IDENTITY_ATTACKS,
        "description": (
            "Adversary impersonates a trusted agent, tool, or MCP server to inject "
            "instructions or intercept delegated actions."
        ),
        "affected_asset_types": [ASSET_AGENT, ASSET_MCP_SERVER],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM01",
        "mitre_atlas_id": None,
        "capability_triggers": ["multi-agent", "mcp", "orchestrator"],
        "recommended_controls": ["agent_identity_verification", "signed_manifests", "mutual_tls"],
        "source": SOURCE_OWASP_AGENTIC,
    },
    {
        "technique_id": "AGENTIC-03",
        "name": "MCP Protocol Abuse",
        "category": CATEGORY_SUPPLY_CHAIN,
        "description": (
            "Exploiting Model Context Protocol server weaknesses — schema injection, "
            "tool descriptor tampering, or malicious MCP server substitution."
        ),
        "affected_asset_types": [ASSET_MCP_SERVER, ASSET_TOOL],
        "severity": SEVERITY_HIGH,
        "owasp_llm_id": "LLM03",
        "mitre_atlas_id": None,
        "capability_triggers": ["mcp", "tool-use"],
        "recommended_controls": ["mcp_server_scanning", "schema_validation", "signed_manifests"],
        "source": SOURCE_OWASP_AGENTIC,
    },
]

# Index built-ins by technique_id for fast lookup
_BUILTIN_INDEX: dict[str, dict[str, Any]] = {t["technique_id"]: t for t in _BUILTIN_THREATS}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _threat_key(technique_id: str) -> str:
    return f"{_THREAT_PREFIX}{technique_id}"


def _from_store(record: dict[str, Any]) -> dict[str, Any]:
    """Extract threat dict from a store record (metadata dict)."""
    return record.get("metadata") or {}


def _to_store_record(threat: dict[str, Any]) -> dict[str, Any]:
    technique_id = threat["technique_id"]
    return {
        "model_id": _threat_key(technique_id),
        "id": _threat_key(technique_id),
        "metadata": threat,
    }


def _resolve_threat(technique_id: str, store: Any) -> dict[str, Any] | None:
    """Custom store entry takes precedence over built-in."""
    stored = store.get_model(_threat_key(technique_id))
    if stored:
        return _from_store(stored)
    return _BUILTIN_INDEX.get(technique_id)


def _all_threats(store: Any) -> dict[str, dict[str, Any]]:
    """Return merged dict of all threats (custom overrides built-ins)."""
    merged = dict(_BUILTIN_INDEX)
    all_records = store.list_models() if hasattr(store, "list_models") else []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_THREAT_PREFIX):
            continue
        threat = _from_store(rec)
        if threat.get("technique_id"):
            merged[threat["technique_id"]] = threat
    return merged


def _relevance(threat: dict[str, Any], capability_strings: list[str]) -> int:
    """Count how many capability triggers match the given capability strings."""
    caps_lower = " ".join(capability_strings).lower()
    return sum(1 for t in (threat.get("capability_triggers") or []) if t.lower() in caps_lower)


# ── Public API ─────────────────────────────────────────────────────────────────

def ingest_threat(
    technique_id: str,
    name: str,
    category: str,
    description: str,
    affected_asset_types: list[str],
    severity: str,
    store: Any,
    *,
    owasp_llm_id: str | None = None,
    mitre_atlas_id: str | None = None,
    capability_triggers: list[str] | None = None,
    recommended_controls: list[str] | None = None,
    source: str = SOURCE_CUSTOM,
) -> dict[str, Any]:
    """Add or update a threat technique in the store."""
    technique_id = str(technique_id).strip().upper()
    if not technique_id:
        raise ThreatIntelError("technique_id must not be empty")
    if category not in CATEGORIES:
        raise ThreatIntelError(f"Unknown category {category!r}. Valid: {sorted(CATEGORIES)}")
    if severity not in _SEVERITY_RANK:
        raise ThreatIntelError(f"Unknown severity {severity!r}")
    unknown_assets = [a for a in affected_asset_types if a not in ASSET_TYPES]
    if unknown_assets:
        raise ThreatIntelError(f"Unknown asset types: {unknown_assets}")

    threat: dict[str, Any] = {
        "technique_id": technique_id,
        "name": name,
        "category": category,
        "description": description,
        "affected_asset_types": list(affected_asset_types),
        "severity": severity,
        "owasp_llm_id": owasp_llm_id,
        "mitre_atlas_id": mitre_atlas_id,
        "capability_triggers": list(capability_triggers or []),
        "recommended_controls": list(recommended_controls or []),
        "source": source,
        "ingested_at": _utc_now(),
    }
    store.save_model(_to_store_record(threat))
    return threat


def get_threat(technique_id: str, store: Any) -> dict[str, Any] | None:
    """Return threat by technique_id (custom store entry overrides built-in)."""
    return _resolve_threat(str(technique_id).strip().upper(), store)


def list_threats(
    store: Any,
    *,
    category: str | None = None,
    severity: str | None = None,
    asset_type: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    """List all threats with optional filters."""
    threats = list(_all_threats(store).values())
    if category:
        threats = [t for t in threats if t.get("category") == category]
    if severity:
        threats = [t for t in threats if t.get("severity") == severity]
    if asset_type:
        threats = [t for t in threats if asset_type in (t.get("affected_asset_types") or [])]
    if source:
        threats = [t for t in threats if t.get("source") == source]
    return sorted(
        threats,
        key=lambda t: (_SEVERITY_RANK.get(t.get("severity", "LOW"), 0) * -1, t.get("technique_id", "")),
    )


def correlate_model(
    model_record: dict[str, Any],
    store: Any,
    *,
    top_n: int | None = None,
) -> dict[str, Any]:
    """Return threats applicable to a model asset, ranked by relevance."""
    meta = model_record.get("metadata") or {}
    mid = model_record.get("model_id") or model_record.get("id") or "unknown"
    caps = [
        str(meta.get("capabilities") or ""),
        *[str(t) for t in (meta.get("task_types") or [])],
        "fine-tuned" if (meta.get("base_model") or meta.get("fine_tuned_on")) else "",
        "open-weight" if meta.get("source", "").lower() in ("huggingface", "hf", "github") else "",
    ]

    threats = list_threats(store, asset_type=ASSET_MODEL)
    ranked = []
    for t in threats:
        rel = _relevance(t, caps)
        ranked.append({**t, "relevance_score": rel})
    ranked.sort(key=lambda x: (_SEVERITY_RANK.get(x["severity"], 0) * -1, -x["relevance_score"]))
    if top_n:
        ranked = ranked[:top_n]

    highest = ranked[0]["severity"] if ranked else None
    return {
        "model_id": mid,
        "threat_count": len(ranked),
        "highest_severity": highest,
        "applicable_threats": ranked,
        "evidence_origin": "LOCALLY_OBSERVED",
        "correlated_at": _utc_now(),
    }


def correlate_agent(
    agent_record: dict[str, Any],
    store: Any,
    *,
    top_n: int | None = None,
) -> dict[str, Any]:
    """Return threats applicable to an agent asset."""
    meta = agent_record.get("metadata") or {}
    aid = agent_record.get("model_id") or agent_record.get("id") or "unknown"
    caps = [
        "agentic", "tool-use",
        "multi-agent" if meta.get("orchestrates_agents") else "",
        "mcp" if meta.get("mcp_server_id") else "",
        "autonomous" if meta.get("autonomous") else "",
    ]

    threats = list_threats(store, asset_type=ASSET_AGENT)
    ranked = [{**t, "relevance_score": _relevance(t, caps)} for t in threats]
    ranked.sort(key=lambda x: (_SEVERITY_RANK.get(x["severity"], 0) * -1, -x["relevance_score"]))
    if top_n:
        ranked = ranked[:top_n]

    return {
        "agent_id": aid,
        "threat_count": len(ranked),
        "highest_severity": ranked[0]["severity"] if ranked else None,
        "applicable_threats": ranked,
        "evidence_origin": "LOCALLY_OBSERVED",
        "correlated_at": _utc_now(),
    }


def correlate_tool(
    tool_record: dict[str, Any],
    store: Any,
    *,
    top_n: int | None = None,
) -> dict[str, Any]:
    """Return threats applicable to a tool / MCP server asset."""
    meta = tool_record.get("metadata") or {}
    tid = tool_record.get("model_id") or tool_record.get("id") or "unknown"
    caps = [
        "tool-use",
        "mcp" if meta.get("server_type") or meta.get("mcp_server_id") else "",
    ]

    threats = list_threats(store, asset_type=ASSET_TOOL)
    ranked = [{**t, "relevance_score": _relevance(t, caps)} for t in threats]
    ranked.sort(key=lambda x: (_SEVERITY_RANK.get(x["severity"], 0) * -1, -x["relevance_score"]))
    if top_n:
        ranked = ranked[:top_n]

    return {
        "tool_id": tid,
        "threat_count": len(ranked),
        "highest_severity": ranked[0]["severity"] if ranked else None,
        "applicable_threats": ranked,
        "evidence_origin": "LOCALLY_OBSERVED",
        "correlated_at": _utc_now(),
    }


def build_threat_landscape(store: Any) -> dict[str, Any]:
    """Return an aggregate view of the current threat landscape."""
    all_t = list(_all_threats(store).values())

    by_severity: dict[str, int] = {
        SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0,
    }
    by_category: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for t in all_t:
        sev = t.get("severity", SEVERITY_LOW)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = t.get("category", "UNKNOWN")
        by_category[cat] = by_category.get(cat, 0) + 1
        src = t.get("source", SOURCE_CUSTOM)
        by_source[src] = by_source.get(src, 0) + 1

    critical = [t for t in all_t if t.get("severity") == SEVERITY_CRITICAL]
    return {
        "total_techniques": len(all_t),
        "builtin_count": len(_BUILTIN_THREATS),
        "custom_count": len(all_t) - len(_BUILTIN_INDEX),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_source": by_source,
        "critical_techniques": [t["technique_id"] for t in critical],
        "threat_intel_version": THREAT_INTEL_VERSION,
        "evidence_origin": "LOCALLY_OBSERVED",
        "generated_at": _utc_now(),
    }

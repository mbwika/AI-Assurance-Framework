"""System-Level AI Red Team Orchestrator.

Coordinates a cross-layer security assessment of a full AI deployment:
model, app logic, retrieval/RAG, tools/MCP, identity/delegation,
telemetry/audit, and human approval flow.

Unlike component-specific tests (model probes, RAG scanner, MCP scanner),
this module evaluates the *interaction* between layers and generates
structured cross-layer attack paths.

Five cross-layer scenarios
--------------------------
PROMPT_INJECTION_CASCADE     Prompt injection → RAG contamination → tool exfil
SUPPLY_CHAIN_TOOL_ABUSE      Compromised model → agent → over-privileged tool
RAG_POISONING_EXFILTRATION   Poisoned document → retrieval → generation → exfil
IDENTITY_ESCALATION          Identity spoofing → delegation abuse → privilege escalation
DENIAL_OF_WALLET             Recursive agent loop → unbounded token consumption

``system_config`` input keys (all optional booleans / ints unless noted)
------------------------------------------------------------------------
has_rag                 RAG / vector store is deployed
has_agents              Agent orchestration layer is deployed
has_tools               Tool / function calling is enabled
has_mcp_servers         MCP servers are in use
has_identity_management Identity and delegation registry is active
has_resource_limits     Resource budgets are enforced
has_audit_logging       Prompt/action audit trail is in place
has_human_approval      Human-in-the-loop approval gates exist
has_guardrails          Input/output guardrails are active
internet_facing         Deployment accepts external user traffic
external_models         At least one model from an external/third-party source
model_count             Number of models in use (int, default 1)
agent_count             Number of agents (int, default 0)
tool_count              Number of tools (int, default 0)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SYSTEM_REDTEAM_VERSION = "1.0"

# ── Layers ─────────────────────────────────────────────────────────────────────
LAYER_MODEL = "MODEL"
LAYER_APP = "APP_LOGIC"
LAYER_RETRIEVAL = "RETRIEVAL_RAG"
LAYER_TOOLS = "TOOL_MCP"
LAYER_IDENTITY = "IDENTITY_DELEGATION"
LAYER_TELEMETRY = "TELEMETRY_AUDIT"
LAYER_APPROVAL = "HUMAN_APPROVAL"

ALL_LAYERS: frozenset = frozenset({
    LAYER_MODEL, LAYER_APP, LAYER_RETRIEVAL, LAYER_TOOLS,
    LAYER_IDENTITY, LAYER_TELEMETRY, LAYER_APPROVAL,
})

# ── Cross-layer scenarios ──────────────────────────────────────────────────────
SCENARIO_PROMPT_INJECTION_CASCADE = "PROMPT_INJECTION_CASCADE"
SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE = "SUPPLY_CHAIN_TOOL_ABUSE"
SCENARIO_RAG_POISONING_EXFIL = "RAG_POISONING_EXFILTRATION"
SCENARIO_IDENTITY_ESCALATION = "IDENTITY_ESCALATION"
SCENARIO_DENIAL_OF_WALLET = "DENIAL_OF_WALLET"

SCENARIOS: frozenset = frozenset({
    SCENARIO_PROMPT_INJECTION_CASCADE, SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE,
    SCENARIO_RAG_POISONING_EXFIL, SCENARIO_IDENTITY_ESCALATION,
    SCENARIO_DENIAL_OF_WALLET,
})

# ── Risk levels ────────────────────────────────────────────────────────────────
SYSTEM_RISK_LOW = "LOW"
SYSTEM_RISK_MEDIUM = "MEDIUM"
SYSTEM_RISK_HIGH = "HIGH"
SYSTEM_RISK_CRITICAL = "CRITICAL"

_RISK_RANK: Dict[str, int] = {
    SYSTEM_RISK_CRITICAL: 3, SYSTEM_RISK_HIGH: 2,
    SYSTEM_RISK_MEDIUM: 1, SYSTEM_RISK_LOW: 0,
}

# Finding severity
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"

_SEV_RANK: Dict[str, int] = {
    SEV_CRITICAL: 3, SEV_HIGH: 2, SEV_MEDIUM: 1, SEV_LOW: 0,
}


class SystemRedTeamError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _worst_risk(a: str, b: str) -> str:
    return a if _RISK_RANK.get(a, 0) >= _RISK_RANK.get(b, 0) else b


def _worst_sev(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def _cfg(system_config: Dict[str, Any], key: str, default: Any = False) -> Any:
    return system_config.get(key, default)


# ── Layer assessments ──────────────────────────────────────────────────────────

def _assess_model_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if _cfg(cfg, "external_models"):
        findings.append({
            "layer": LAYER_MODEL, "severity": SEV_HIGH,
            "finding": "External/third-party models in use without verified provenance.",
            "control": "Verify model provenance via AIAF intake triage (POST /v1/intake/triage).",
        })
    if not _cfg(cfg, "has_guardrails"):
        findings.append({
            "layer": LAYER_MODEL, "severity": SEV_HIGH,
            "finding": "No input/output guardrails declared for model layer.",
            "control": "Enable guardrail_engine for input validation and output filtering.",
        })
    if int(_cfg(cfg, "model_count", 1)) > 3:
        findings.append({
            "layer": LAYER_MODEL, "severity": SEV_MEDIUM,
            "finding": f"Large model count ({cfg.get('model_count')}) expands attack surface.",
            "control": "Apply consistent assurance controls across all deployed models.",
        })
    return findings


def _assess_app_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not _cfg(cfg, "has_guardrails"):
        findings.append({
            "layer": LAYER_APP, "severity": SEV_HIGH,
            "finding": "Application layer passes user input to model without validation.",
            "control": "Implement input sanitisation and prompt injection detection.",
        })
    if _cfg(cfg, "internet_facing") and not _cfg(cfg, "has_guardrails"):
        findings.append({
            "layer": LAYER_APP, "severity": SEV_CRITICAL,
            "finding": "Internet-facing deployment without guardrails — public attackers can reach the model directly.",
            "control": "Deploy WAF, API rate limiting, and AIAF guardrail middleware.",
        })
    return findings


def _assess_retrieval_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not _cfg(cfg, "has_rag"):
        return findings
    findings.append({
        "layer": LAYER_RETRIEVAL, "severity": SEV_MEDIUM,
        "finding": "RAG layer present — retrieval poisoning and indirect prompt injection are applicable.",
        "control": "Run AIAF RAG security scan (POST /v1/rag/store/security) and apply document trust labels.",
    })
    if not _cfg(cfg, "has_audit_logging"):
        findings.append({
            "layer": LAYER_RETRIEVAL, "severity": SEV_MEDIUM,
            "finding": "RAG retrievals are not audited — poisoned retrievals may go undetected.",
            "control": "Enable retrieval logging in the telemetry layer.",
        })
    return findings


def _assess_tools_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not _cfg(cfg, "has_tools") and not _cfg(cfg, "has_mcp_servers"):
        return findings
    if not _cfg(cfg, "has_human_approval"):
        findings.append({
            "layer": LAYER_TOOLS, "severity": SEV_HIGH,
            "finding": "Tool/MCP layer has no human approval gate — agent actions are fully autonomous.",
            "control": "Add human-in-the-loop approval for high-impact tool categories.",
        })
    if int(_cfg(cfg, "tool_count", 0)) > 10:
        findings.append({
            "layer": LAYER_TOOLS, "severity": SEV_MEDIUM,
            "finding": f"Large tool inventory ({cfg.get('tool_count')}) increases excessive-agency risk.",
            "control": "Apply least-privilege tool policies (POST /v1/ops/tools/policies).",
        })
    if _cfg(cfg, "has_mcp_servers") and not _cfg(cfg, "has_guardrails"):
        findings.append({
            "layer": LAYER_TOOLS, "severity": SEV_HIGH,
            "finding": "MCP servers in use without schema validation or signed manifests.",
            "control": "Run MCP scanner and enforce signed tool manifests.",
        })
    return findings


def _assess_identity_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if _cfg(cfg, "has_agents") and not _cfg(cfg, "has_identity_management"):
        findings.append({
            "layer": LAYER_IDENTITY, "severity": SEV_HIGH,
            "finding": "Multi-agent deployment without identity management — spoofing and delegation abuse are undetected.",
            "control": "Register principals in AIAF identity registry (POST /v1/identity/principals).",
        })
    if int(_cfg(cfg, "agent_count", 0)) > 1 and not _cfg(cfg, "has_identity_management"):
        findings.append({
            "layer": LAYER_IDENTITY, "severity": SEV_HIGH,
            "finding": "Multiple agents with no delegation governance — authority escalation risk is unconstrained.",
            "control": "Define scoped delegation grants (POST /v1/identity/delegations).",
        })
    return findings


def _assess_telemetry_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not _cfg(cfg, "has_audit_logging"):
        findings.append({
            "layer": LAYER_TELEMETRY, "severity": SEV_HIGH,
            "finding": "No audit trail for prompts, tool calls, or agent actions.",
            "control": "Enable AIAF agent action ledger and telemetry ingestion.",
        })
    if not _cfg(cfg, "has_resource_limits"):
        findings.append({
            "layer": LAYER_TELEMETRY, "severity": SEV_MEDIUM,
            "finding": "No resource consumption monitoring — denial-of-wallet attacks are undetected.",
            "control": "Create resource budgets (POST /v1/resources/budgets) and monitor violations.",
        })
    return findings


def _assess_approval_layer(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if _cfg(cfg, "has_agents") and not _cfg(cfg, "has_human_approval"):
        findings.append({
            "layer": LAYER_APPROVAL, "severity": SEV_MEDIUM,
            "finding": "Agentic deployment without human-in-the-loop approval for irreversible actions.",
            "control": "Add approval gates for write/delete/external-call tool categories.",
        })
    return findings


# ── Cross-layer scenario analysis ──────────────────────────────────────────────

def _scenario_prompt_injection_cascade(cfg: Dict[str, Any], layers: frozenset) -> Dict[str, Any]:
    applicable = (
        LAYER_RETRIEVAL in layers and _cfg(cfg, "has_rag")
        and LAYER_TOOLS in layers and _cfg(cfg, "has_tools")
    )
    path = [
        {"step": 1, "layer": LAYER_APP, "technique": "Input validation bypass",
         "description": "Adversary crafts payload embedding injection instructions."},
        {"step": 2, "layer": LAYER_RETRIEVAL, "technique": "Context injection via RAG",
         "description": "Injected content contaminates retrieval context via poisoned documents."},
        {"step": 3, "layer": LAYER_MODEL, "technique": "Instruction override",
         "description": "Model follows injected instructions over original system prompt."},
        {"step": 4, "layer": LAYER_TOOLS, "technique": "Unauthorised tool invocation",
         "description": "Model invokes a data-access or exfiltration tool under adversary control."},
    ]
    mitigations = [
        "Deploy prompt injection guardrails (aiaf.core.guardrail_engine).",
        "Apply document trust labels and retrieval filtering in RAG layer.",
        "Restrict tool permissions to least-privilege scopes.",
    ]
    sev = SEV_CRITICAL if applicable and not _cfg(cfg, "has_guardrails") else SEV_HIGH
    return {
        "scenario": SCENARIO_PROMPT_INJECTION_CASCADE,
        "severity": sev,
        "applicable": applicable,
        "attack_path": path if applicable else [],
        "mitigations": mitigations if applicable else [],
    }


def _scenario_supply_chain_tool_abuse(cfg: Dict[str, Any], layers: frozenset) -> Dict[str, Any]:
    applicable = (
        _cfg(cfg, "external_models")
        and _cfg(cfg, "has_agents")
        and _cfg(cfg, "has_tools")
    )
    path = [
        {"step": 1, "layer": LAYER_MODEL, "technique": "Compromised base model",
         "description": "External model contains backdoor or poisoned weights."},
        {"step": 2, "layer": LAYER_APP, "technique": "Agent instantiation",
         "description": "Compromised model is instantiated as an autonomous agent."},
        {"step": 3, "layer": LAYER_TOOLS, "technique": "Over-privileged tool access",
         "description": "Agent exploits excess tool permissions to perform unauthorised actions."},
        {"step": 4, "layer": LAYER_IDENTITY, "technique": "Authority escalation",
         "description": "No identity controls prevent tool calls beyond intended scope."},
    ]
    mitigations = [
        "Verify all external model provenance before deployment.",
        "Apply tool-level least-privilege and signed manifests.",
        "Register agents in identity registry with constrained delegation.",
    ]
    return {
        "scenario": SCENARIO_SUPPLY_CHAIN_TOOL_ABUSE,
        "severity": SEV_CRITICAL if applicable else SEV_HIGH,
        "applicable": applicable,
        "attack_path": path if applicable else [],
        "mitigations": mitigations if applicable else [],
    }


def _scenario_rag_poisoning_exfil(cfg: Dict[str, Any], layers: frozenset) -> Dict[str, Any]:
    applicable = LAYER_RETRIEVAL in layers and _cfg(cfg, "has_rag")
    path = [
        {"step": 1, "layer": LAYER_RETRIEVAL, "technique": "Adversarial document injection",
         "description": "Attacker injects poisoned documents into the vector store."},
        {"step": 2, "layer": LAYER_RETRIEVAL, "technique": "Poisoned retrieval",
         "description": "Poisoned documents are retrieved and included in the model context."},
        {"step": 3, "layer": LAYER_MODEL, "technique": "Context manipulation",
         "description": "Model generates responses guided by poisoned context."},
        {"step": 4, "layer": LAYER_APP, "technique": "Sensitive data exfiltration",
         "description": "Model is induced to output or relay sensitive information."},
    ]
    mitigations = [
        "Run AIAF RAG security scan to detect poisoned documents.",
        "Enforce document trust labels and provenance verification.",
        "Implement output filtering for sensitive data patterns.",
    ]
    return {
        "scenario": SCENARIO_RAG_POISONING_EXFIL,
        "severity": SEV_HIGH,
        "applicable": applicable,
        "attack_path": path if applicable else [],
        "mitigations": mitigations if applicable else [],
    }


def _scenario_identity_escalation(cfg: Dict[str, Any], layers: frozenset) -> Dict[str, Any]:
    applicable = (
        _cfg(cfg, "has_agents")
        and not _cfg(cfg, "has_identity_management")
        and LAYER_IDENTITY in layers
    )
    path = [
        {"step": 1, "layer": LAYER_IDENTITY, "technique": "Agent identity spoofing",
         "description": "Adversary impersonates a trusted agent or service principal."},
        {"step": 2, "layer": LAYER_IDENTITY, "technique": "Delegation chain abuse",
         "description": "Spoofed identity exploits delegation grants not scoped to target."},
        {"step": 3, "layer": LAYER_TOOLS, "technique": "Privilege escalation via tool",
         "description": "Escalated identity invokes privileged tool operations."},
        {"step": 4, "layer": LAYER_TELEMETRY, "technique": "Audit evasion",
         "description": "No identity trail means escalation goes unlogged."},
    ]
    mitigations = [
        "Register all principals in AIAF identity registry.",
        "Enforce scoped delegation — use 'action:resource' scope items, not wildcards.",
        "Audit all agent actions via the agent action ledger.",
    ]
    return {
        "scenario": SCENARIO_IDENTITY_ESCALATION,
        "severity": SEV_HIGH if applicable else SEV_MEDIUM,
        "applicable": applicable,
        "attack_path": path if applicable else [],
        "mitigations": mitigations if applicable else [],
    }


def _scenario_denial_of_wallet(cfg: Dict[str, Any], layers: frozenset) -> Dict[str, Any]:
    applicable = (
        _cfg(cfg, "has_agents")
        and not _cfg(cfg, "has_resource_limits")
        and LAYER_TELEMETRY in layers
    )
    path = [
        {"step": 1, "layer": LAYER_APP, "technique": "Adversarial prompt construction",
         "description": "Attacker sends prompts designed to trigger recursive agent planning."},
        {"step": 2, "layer": LAYER_MODEL, "technique": "Unbounded planning loop",
         "description": "Agent enters a recursive planning cycle with no depth limit."},
        {"step": 3, "layer": LAYER_TOOLS, "technique": "Repeated tool invocations",
         "description": "Each planning iteration calls tools, multiplying cost."},
        {"step": 4, "layer": LAYER_TELEMETRY, "technique": "Cost exhaustion undetected",
         "description": "No budget enforcement — runaway costs continue until manual intervention."},
    ]
    mitigations = [
        "Create resource budgets with token/iteration limits (POST /v1/resources/budgets).",
        "Set max_loop_iterations and max_planning_depth in agent configuration.",
        "Enable real-time cost anomaly alerts via AIAF telemetry.",
    ]
    return {
        "scenario": SCENARIO_DENIAL_OF_WALLET,
        "severity": SEV_HIGH if applicable else SEV_MEDIUM,
        "applicable": applicable,
        "attack_path": path if applicable else [],
        "mitigations": mitigations if applicable else [],
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def run_system_redteam(
    system_id: str,
    store: Any,
    *,
    layers: Optional[List[str]] = None,
    system_config: Optional[Dict[str, Any]] = None,
    model_ids: Optional[List[str]] = None,
    agent_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run a cross-layer system-level red team assessment.

    Parameters
    ----------
    system_id:
        Identifier for the AI system being assessed.
    store:
        AIAF persistence store.
    layers:
        Subset of ALL_LAYERS to assess.  Defaults to all layers.
    system_config:
        Dict describing the system deployment (see module docstring).
    model_ids:
        Model IDs to pull from the store for additional context.
    agent_ids:
        Agent IDs to pull from the store for additional context.
    """
    if layers is not None:
        unknown = [l for l in layers if l not in ALL_LAYERS]
        if unknown:
            raise SystemRedTeamError(
                f"Unknown layers: {unknown}. Valid: {sorted(ALL_LAYERS)}"
            )
    active_layers: frozenset = frozenset(layers) if layers else ALL_LAYERS
    cfg = dict(system_config or {})

    # Enrich config from referenced model/agent records
    if model_ids:
        cfg["model_count"] = max(int(cfg.get("model_count", 1)), len(model_ids))
        for mid in model_ids:
            rec = store.get_model(mid)
            if rec and (rec.get("metadata") or {}).get("source", "").lower() in ("huggingface", "hf", "external"):
                cfg.setdefault("external_models", True)
    if agent_ids:
        cfg["agent_count"] = max(int(cfg.get("agent_count", 0)), len(agent_ids))
        cfg.setdefault("has_agents", True)

    # Layer-by-layer findings
    layer_assessors = {
        LAYER_MODEL: _assess_model_layer,
        LAYER_APP: _assess_app_layer,
        LAYER_RETRIEVAL: _assess_retrieval_layer,
        LAYER_TOOLS: _assess_tools_layer,
        LAYER_IDENTITY: _assess_identity_layer,
        LAYER_TELEMETRY: _assess_telemetry_layer,
        LAYER_APPROVAL: _assess_approval_layer,
    }

    layer_findings: Dict[str, List[Dict[str, Any]]] = {}
    all_layer_findings: List[Dict[str, Any]] = []
    for layer in sorted(active_layers):
        assessor = layer_assessors.get(layer)
        findings = assessor(cfg) if assessor else []
        layer_findings[layer] = findings
        all_layer_findings.extend(findings)

    # Cross-layer scenario analysis
    scenario_fns = [
        _scenario_prompt_injection_cascade,
        _scenario_supply_chain_tool_abuse,
        _scenario_rag_poisoning_exfil,
        _scenario_identity_escalation,
        _scenario_denial_of_wallet,
    ]
    scenarios = [fn(cfg, active_layers) for fn in scenario_fns]
    applicable_scenarios = [s for s in scenarios if s["applicable"]]

    # Compute overall risk
    overall_risk = SYSTEM_RISK_LOW
    for f in all_layer_findings:
        sev_to_risk = {SEV_CRITICAL: SYSTEM_RISK_CRITICAL, SEV_HIGH: SYSTEM_RISK_HIGH,
                       SEV_MEDIUM: SYSTEM_RISK_MEDIUM, SEV_LOW: SYSTEM_RISK_LOW}
        overall_risk = _worst_risk(overall_risk, sev_to_risk.get(f["severity"], SYSTEM_RISK_LOW))
    for s in applicable_scenarios:
        sev_to_risk = {SEV_CRITICAL: SYSTEM_RISK_CRITICAL, SEV_HIGH: SYSTEM_RISK_HIGH,
                       SEV_MEDIUM: SYSTEM_RISK_MEDIUM, SEV_LOW: SYSTEM_RISK_LOW}
        overall_risk = _worst_risk(overall_risk, sev_to_risk.get(s["severity"], SYSTEM_RISK_LOW))

    # Priority fixes (deduplicated controls from critical/high findings)
    priority_controls: List[str] = []
    for f in sorted(all_layer_findings, key=lambda x: _SEV_RANK.get(x["severity"], 0) * -1):
        ctrl = f.get("control", "")
        if ctrl and ctrl not in priority_controls:
            priority_controls.append(ctrl)

    critical_count = sum(1 for f in all_layer_findings if f["severity"] == SEV_CRITICAL)

    return {
        "system_id": system_id,
        "system_redteam_version": SYSTEM_REDTEAM_VERSION,
        "overall_risk": overall_risk,
        "layers_tested": sorted(active_layers),
        "layer_findings": layer_findings,
        "cross_layer_scenarios": scenarios,
        "applicable_scenario_count": len(applicable_scenarios),
        "total_findings": len(all_layer_findings),
        "critical_findings": critical_count,
        "recommended_priority_fixes": priority_controls[:10],
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }

"""Compliance evidence pack builder.

Turns the AIAF artifact inventory into a downloadable, per-framework evidence
package that binds each control to concrete AIAF artifacts.

Supported frameworks
--------------------
``NIST_AI_RMF``, ``ISO_42001``, ``EU_AI_ACT_HIGH_RISK``,
``OWASP_LLM_TOP10``, ``OWASP_AGENTIC``.

For each control the pack records:
  * status         — ``satisfied`` / ``partial`` / ``missing``
  * evidence_refs  — list of {type, ref, artifact_id, summary} dicts
  * gaps           — what evidence would upgrade the status

Export formats: ``"json"``, ``"oscal"``, ``"html"``, ``"markdown"``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

EVIDENCE_PACK_VERSION = "1.0"

# ── Framework identifiers ───────────────────────────────────────────────────────

FRAMEWORK_NIST_AI_RMF = "NIST_AI_RMF"
FRAMEWORK_ISO_42001 = "ISO_42001"
FRAMEWORK_EU_AI_ACT_HIGH_RISK = "EU_AI_ACT_HIGH_RISK"
FRAMEWORK_OWASP_LLM_TOP10 = "OWASP_LLM_TOP10"
FRAMEWORK_OWASP_AGENTIC = "OWASP_AGENTIC"

FRAMEWORKS: frozenset[str] = frozenset(
    {
        FRAMEWORK_NIST_AI_RMF,
        FRAMEWORK_ISO_42001,
        FRAMEWORK_EU_AI_ACT_HIGH_RISK,
        FRAMEWORK_OWASP_LLM_TOP10,
        FRAMEWORK_OWASP_AGENTIC,
    }
)

FRAMEWORK_DISPLAY_NAMES: dict[str, str] = {
    FRAMEWORK_NIST_AI_RMF: "NIST AI Risk Management Framework 1.0",
    FRAMEWORK_ISO_42001: "ISO/IEC 42001:2023 AI Management System",
    FRAMEWORK_EU_AI_ACT_HIGH_RISK: "EU AI Act (High-Risk Systems) 2024/1689",
    FRAMEWORK_OWASP_LLM_TOP10: "OWASP Top 10 for LLM Applications 2025",
    FRAMEWORK_OWASP_AGENTIC: "OWASP Agentic Security Initiative",
}

EXPORT_FORMATS: frozenset[str] = frozenset({"json", "oscal", "html", "markdown"})


class EvidencePackError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Control catalogs — one per framework
# ---------------------------------------------------------------------------

# Each entry: {control_id, title, evidence_types[], description}
# evidence_types indicate which AIAF artifact categories can satisfy the control.

_NIST_AI_RMF_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "GOVERN-1.1", "title": "AI governance policies",
     "evidence_types": ["governance", "compliance_matrix"],
     "description": "Establish and communicate AI governance policies, roles, and accountability."},
    {"control_id": "GOVERN-1.7", "title": "AI agent action logging",
     "evidence_types": ["ledger", "telemetry"],
     "description": "Document, log, and monitor AI agent actions for auditability."},
    {"control_id": "GOVERN-2.1", "title": "AI risk accountability",
     "evidence_types": ["governance", "risk_register"],
     "description": "Assign organizational accountability for AI risks."},
    {"control_id": "GOVERN-6.1", "title": "AI supply-chain governance",
     "evidence_types": ["bom", "adoption_verdict", "findings"],
     "description": "Manage AI supply-chain dependencies and third-party relationships."},
    {"control_id": "MAP-4.1", "title": "Component and data mapping",
     "evidence_types": ["bom", "rag_inventory"],
     "description": "Map data, components, and resources that influence system behavior."},
    {"control_id": "MAP-4.2", "title": "Deployment artifact traceability",
     "evidence_types": ["bom", "attestation", "deployment_verify"],
     "description": "Trace components, provenance, and deployment artifacts for integrity verification."},
    {"control_id": "MEASURE-2.1", "title": "Performance evaluation",
     "evidence_types": ["eval_run", "findings"],
     "description": "Evaluate system performance and reliability with appropriate tests and evidence."},
    {"control_id": "MEASURE-2.6", "title": "Risk indicator monitoring",
     "evidence_types": ["telemetry", "ledger", "findings"],
     "description": "Monitor whether risk indicators and assurance evidence change over time."},
    {"control_id": "MEASURE-2.7", "title": "Adversarial testing",
     "evidence_types": ["redteam", "findings", "eval_run"],
     "description": "Test for failures, misuse, adversarial behavior, and harmful behaviors."},
    {"control_id": "MANAGE-1.3", "title": "Risk remediation tracking",
     "evidence_types": ["remediation", "incident"],
     "description": "Track and remediate identified risks using accountable owners and response plans."},
    {"control_id": "MANAGE-2.4", "title": "Lifecycle controls and release gates",
     "evidence_types": ["deployment_verify", "policy_enforcement", "adoption_verdict"],
     "description": "Implement lifecycle controls, release gates, and operational responses."},
    {"control_id": "MANAGE-4.1", "title": "Incident response",
     "evidence_types": ["incident", "remediation"],
     "description": "Respond to and learn from AI incidents and near-misses."},
]

_ISO_42001_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "ISO42001-4", "title": "Context of the organization",
     "evidence_types": ["governance", "bom"],
     "description": "Understanding the organization context, scope, and stakeholder needs."},
    {"control_id": "ISO42001-6", "title": "AI risk and opportunity planning",
     "evidence_types": ["risk_register", "findings"],
     "description": "Actions to address risks and opportunities; AI objectives and planning."},
    {"control_id": "ISO42001-8", "title": "AI system lifecycle operations",
     "evidence_types": ["bom", "adoption_verdict", "deployment_verify"],
     "description": "Operational planning and control for AI system lifecycle management."},
    {"control_id": "ISO42001-9", "title": "Performance evaluation",
     "evidence_types": ["eval_run", "findings", "telemetry"],
     "description": "Monitoring, measurement, analysis and evaluation of AIMS performance."},
    {"control_id": "ISO42001-10", "title": "Continual improvement",
     "evidence_types": ["remediation", "incident", "findings"],
     "description": "Nonconformity, corrective action, and continual improvement."},
    {"control_id": "ISO42001-A.2", "title": "AI policies",
     "evidence_types": ["governance", "policy_enforcement"],
     "description": "Establish and maintain AI policies aligned with organizational objectives."},
    {"control_id": "ISO42001-A.4", "title": "AI system impact assessment",
     "evidence_types": ["risk_register", "bias_fairness", "findings"],
     "description": "Assess impacts of AI systems on individuals and society."},
    {"control_id": "ISO42001-A.6", "title": "AI system documentation",
     "evidence_types": ["bom", "governance"],
     "description": "Maintain documentation of AI system design, development, and operation."},
    {"control_id": "ISO42001-A.7", "title": "AI data management",
     "evidence_types": ["rag_inventory", "bom", "findings"],
     "description": "Data governance, quality, and management for AI systems."},
    {"control_id": "ISO42001-A.8", "title": "AI system verification and validation",
     "evidence_types": ["eval_run", "redteam", "findings"],
     "description": "Verify and validate AI systems before and during deployment."},
]

_EU_AI_ACT_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "EU-Art9", "title": "Risk management system",
     "evidence_types": ["risk_register", "findings", "governance"],
     "description": "Implement and maintain a continuous risk management system (Art. 9)."},
    {"control_id": "EU-Art10", "title": "Data governance",
     "evidence_types": ["rag_inventory", "bom", "findings"],
     "description": "Apply data governance and quality practices to training, validation, and test data (Art. 10)."},
    {"control_id": "EU-Art11", "title": "Technical documentation",
     "evidence_types": ["bom", "governance"],
     "description": "Maintain technical documentation adequate for conformity assessment (Art. 11)."},
    {"control_id": "EU-Art12", "title": "Record-keeping / logging",
     "evidence_types": ["ledger", "telemetry"],
     "description": "Enable automatic logging of events throughout the operational lifetime (Art. 12)."},
    {"control_id": "EU-Art13", "title": "Transparency and information to deployers",
     "evidence_types": ["bom", "governance", "findings"],
     "description": "Provide transparency for deployers to interpret outputs appropriately (Art. 13)."},
    {"control_id": "EU-Art14", "title": "Human oversight measures",
     "evidence_types": ["policy_enforcement", "ledger", "governance"],
     "description": "Design for effective human oversight of high-risk AI systems (Art. 14)."},
    {"control_id": "EU-Art15", "title": "Accuracy, robustness, and cybersecurity",
     "evidence_types": ["eval_run", "redteam", "findings"],
     "description": "Achieve appropriate levels of accuracy, robustness, and cybersecurity (Art. 15)."},
    {"control_id": "EU-Art26", "title": "Deployer obligations",
     "evidence_types": ["adoption_verdict", "governance", "deployment_verify"],
     "description": "Deployers must ensure use conditions, monitoring, and oversight requirements are met (Art. 26)."},
    {"control_id": "EU-Art73", "title": "Serious incident reporting",
     "evidence_types": ["incident"],
     "description": "Report serious incidents and malfunctions to national authorities (Art. 73)."},
]

_OWASP_LLM_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "LLM01", "title": "Prompt Injection",
     "evidence_types": ["redteam", "findings", "policy_enforcement"],
     "description": "Guard against instructions or content that manipulate model behavior."},
    {"control_id": "LLM02", "title": "Sensitive Information Disclosure",
     "evidence_types": ["redteam", "findings", "policy_enforcement"],
     "description": "Prevent models from exposing secrets, personal data, or protected information."},
    {"control_id": "LLM03", "title": "Supply Chain Vulnerabilities",
     "evidence_types": ["bom", "adoption_verdict", "findings"],
     "description": "Manage compromise risks in models, datasets, plugins, and third-party components."},
    {"control_id": "LLM04", "title": "Data and Model Poisoning",
     "evidence_types": ["bom", "redteam", "findings"],
     "description": "Detect and prevent tampering with training data or model weights."},
    {"control_id": "LLM06", "title": "Excessive Agency",
     "evidence_types": ["policy_enforcement", "ledger", "findings"],
     "description": "Constrain tool use, permissions, and autonomous actions within intended authority."},
    {"control_id": "LLM07", "title": "System Prompt Leakage",
     "evidence_types": ["redteam", "findings", "deployment_verify"],
     "description": "Protect hidden prompts, policies, and control instructions from disclosure."},
    {"control_id": "LLM08", "title": "Vector and Embedding Weaknesses",
     "evidence_types": ["rag_inventory", "findings"],
     "description": "Secure vector databases and embedding models from manipulation."},
    {"control_id": "LLM09", "title": "Misinformation",
     "evidence_types": ["eval_run", "findings"],
     "description": "Detect and reduce false, misleading, or fabricated outputs."},
]

_OWASP_AGENTIC_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "AGENTIC-01", "title": "Excessive Autonomy",
     "evidence_types": ["policy_enforcement", "ledger", "findings"],
     "description": "Limit agent autonomy through authorization policies and action logging."},
    {"control_id": "AGENTIC-02", "title": "Tool and Resource Abuse",
     "evidence_types": ["policy_enforcement", "ledger", "redteam"],
     "description": "Prevent agents from abusing tools or resources beyond intended scope."},
    {"control_id": "AGENTIC-03", "title": "Agent Identity Spoofing",
     "evidence_types": ["ledger", "attestation", "findings"],
     "description": "Authenticate and verify agent identity to prevent impersonation."},
    {"control_id": "AGENTIC-04", "title": "Prompt Injection in Agentic Pipelines",
     "evidence_types": ["redteam", "findings", "policy_enforcement"],
     "description": "Detect and block prompt injection attacks in multi-agent pipelines."},
    {"control_id": "AGENTIC-05", "title": "Supply Chain Risks in Agentic Systems",
     "evidence_types": ["bom", "adoption_verdict", "findings"],
     "description": "Manage supply chain risks for agent tools, plugins, and MCP servers."},
    {"control_id": "AGENTIC-06", "title": "Sensitive Data in Agent Context",
     "evidence_types": ["policy_enforcement", "ledger", "findings"],
     "description": "Prevent leakage of sensitive data through agent context windows."},
    {"control_id": "AGENTIC-07", "title": "Insufficient Monitoring and Logging",
     "evidence_types": ["ledger", "telemetry"],
     "description": "Implement comprehensive monitoring and logging for agentic systems."},
    {"control_id": "AGENTIC-08", "title": "Inadequate Human Oversight",
     "evidence_types": ["governance", "policy_enforcement"],
     "description": "Maintain meaningful human oversight of high-stakes agent decisions."},
]

_FRAMEWORK_CONTROLS: dict[str, list[dict[str, Any]]] = {
    FRAMEWORK_NIST_AI_RMF: _NIST_AI_RMF_CONTROLS,
    FRAMEWORK_ISO_42001: _ISO_42001_CONTROLS,
    FRAMEWORK_EU_AI_ACT_HIGH_RISK: _EU_AI_ACT_CONTROLS,
    FRAMEWORK_OWASP_LLM_TOP10: _OWASP_LLM_CONTROLS,
    FRAMEWORK_OWASP_AGENTIC: _OWASP_AGENTIC_CONTROLS,
}


# ---------------------------------------------------------------------------
# Evidence discovery
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_dict(obj: Any) -> str:
    return hashlib.sha256(_canonical_json(obj).encode()).hexdigest()


def _record_matches_scope(mid: str, meta: dict[str, Any], scope: dict[str, Any]) -> bool:
    model_id = str(scope.get("model_id") or "").strip()
    if not model_id:
        return True
    if mid in {model_id, f"model:{model_id}", f"mbom:{model_id}", f"ledger:{model_id}"}:
        return True
    if mid.startswith("pep_policy:"):
        return True
    for key in ("model_id", "target_model_id", "artifact_id", "registered_model_id"):
        if str(meta.get(key) or "").strip() == model_id:
            return True
    return False


def _discover_evidence(
    store: Any, scope: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """Discover AIAF artifacts from the store and classify by evidence type.

    Returns a dict keyed by evidence type (strings matching the ``evidence_types``
    lists in the control catalogs).
    """
    model_id = str(scope.get("model_id") or "").strip() or None
    artifact_id = str(scope.get("artifact_id") or "").strip() or None

    evidence: dict[str, list[dict[str, Any]]] = {
        "bom": [],
        "governance": [],
        "risk_register": [],
        "findings": [],
        "eval_run": [],
        "redteam": [],
        "ledger": [],
        "telemetry": [],
        "incident": [],
        "remediation": [],
        "attestation": [],
        "deployment_verify": [],
        "policy_enforcement": [],
        "adoption_verdict": [],
        "rag_inventory": [],
        "bias_fairness": [],
        "compliance_matrix": [],
    }

    # ── Findings from the dedicated findings table ──────────────────────────
    try:
        findings = store.list_findings(limit=200, artifact_id=artifact_id or model_id)
        for f in findings:
            evidence["findings"].append({
                "type": "finding",
                "ref": f"finding:{f.get('id')}",
                "artifact_id": f.get("artifact_id"),
                "summary": f"Finding (score={f.get('score', 0):.1f}, {len(f.get('findings', []))} item(s))",
            })
    except Exception:
        pass

    # ── All generic model-namespace records ────────────────────────────────
    try:
        all_models = store.list_models() if hasattr(store, "list_models") else []
    except Exception:
        all_models = []

    prefix_map = {
        "mbom:": "bom",
        "eval_run:": "eval_run",
        "incident:": "incident",
        "deployment_verify:": "deployment_verify",
        "ledger:": "ledger",
        "attestation:": "attestation",
        "remediation:": "remediation",
        "pep_policy:": "policy_enforcement",
        "rag_store:": "rag_inventory",
        "ai_threat:": "findings",
        "adoption:": "adoption_verdict",
    }

    for m in all_models:
        mid = str(m.get("model_id") or m.get("id") or "")
        meta = m.get("metadata") or {}

        if not _record_matches_scope(mid, meta, scope):
            continue

        for prefix, etype in prefix_map.items():
            if mid.startswith(prefix):
                short_id = mid[len(prefix):][:32]
                evidence[etype].append({
                    "type": etype,
                    "ref": mid,
                    "artifact_id": meta.get("model_id") or meta.get("target_model_id") or mid,
                    "summary": f"{etype} record {short_id}",
                })
                break

        # Governance records (stored under model_id directly)
        if mid == model_id or (model_id and mid == f"model:{model_id}"):
            evidence["governance"].append({
                "type": "governance",
                "ref": mid,
                "artifact_id": mid,
                "summary": f"Registered model record for {mid}",
            })

    # Bias/fairness — look for bias findings
    for f_entry in evidence["findings"]:
        summary = f_entry.get("summary") or ""
        if "bias" in summary.lower() or "fairness" in summary.lower():
            evidence["bias_fairness"].append(f_entry)

    return evidence


# ---------------------------------------------------------------------------
# Control status computation
# ---------------------------------------------------------------------------


def _compute_control_status(
    control: dict[str, Any],
    evidence: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    required_types = control.get("evidence_types") or []
    found_refs: list[dict[str, Any]] = []
    missing_types: list[str] = []

    for etype in required_types:
        items = evidence.get(etype) or []
        if items:
            found_refs.extend(items[:3])  # cap per type to keep output bounded
        else:
            missing_types.append(etype)

    if not required_types:
        status = "not_applicable"
    elif not missing_types:
        status = "satisfied"
    elif len(missing_types) < len(required_types):
        status = "partial"
    else:
        status = "missing"

    return {
        "control_id": control["control_id"],
        "title": control["title"],
        "description": control.get("description", ""),
        "status": status,
        "evidence_refs": found_refs[:10],
        "required_evidence_types": required_types,
        "missing_evidence_types": missing_types,
        "evidence_count": len(found_refs),
    }


# ---------------------------------------------------------------------------
# Pack builder
# ---------------------------------------------------------------------------


def build_evidence_pack(
    framework: str,
    scope: dict[str, Any],
    store: Any,
) -> dict[str, Any]:
    """Build a per-framework compliance evidence pack.

    Parameters
    ----------
    framework:
        One of the ``FRAMEWORK_*`` constants (e.g. ``FRAMEWORK_NIST_AI_RMF``).
    scope:
        Dict with optional keys ``model_id``, ``artifact_id``, ``registered_by``
        to narrow evidence discovery to a specific AI system.
    store:
        AIAF data store.

    Returns
    -------
    dict
        Evidence pack with per-control status, evidence refs, and summary.
    """
    framework = str(framework).strip().upper()
    if framework not in FRAMEWORKS:
        raise EvidencePackError(
            f"Unknown framework: {framework!r}. Valid: {sorted(FRAMEWORKS)}"
        )
    if not isinstance(scope, dict):
        raise EvidencePackError("scope must be a dict")

    controls_catalog = _FRAMEWORK_CONTROLS[framework]
    evidence = _discover_evidence(store, scope)
    built_at = _utc_now()

    control_records: list[dict[str, Any]] = []
    for control in controls_catalog:
        record = _compute_control_status(control, evidence)
        control_records.append(record)

    satisfied = sum(1 for c in control_records if c["status"] == "satisfied")
    partial = sum(1 for c in control_records if c["status"] == "partial")
    missing = sum(1 for c in control_records if c["status"] == "missing")
    total = len(control_records)
    coverage_pct = round((satisfied + partial * 0.5) / total * 100, 1) if total else 0.0

    gaps: list[dict[str, Any]] = [
        {
            "control_id": c["control_id"],
            "title": c["title"],
            "status": c["status"],
            "missing_evidence_types": c["missing_evidence_types"],
        }
        for c in control_records
        if c["status"] in ("missing", "partial")
    ]

    # Per-evidence-type inventory summary
    evidence_inventory = {
        etype: len(items)
        for etype, items in evidence.items()
        if items
    }

    pack: dict[str, Any] = {
        "evidence_pack_version": EVIDENCE_PACK_VERSION,
        "framework": framework,
        "framework_display_name": FRAMEWORK_DISPLAY_NAMES.get(framework, framework),
        "scope": dict(scope),
        "built_at": built_at,
        "summary": {
            "total_controls": total,
            "satisfied": satisfied,
            "partial": partial,
            "missing": missing,
            "coverage_pct": coverage_pct,
            "overall_status": (
                "EVIDENCE_COMPLETE" if missing == 0 and partial == 0
                else "PARTIAL_EVIDENCE" if satisfied > 0 or partial > 0
                else "INSUFFICIENT_EVIDENCE"
            ),
        },
        "controls": control_records,
        "gaps": gaps,
        "evidence_inventory": evidence_inventory,
        "assessment_basis": (
            "Automated artifact discovery; this is not a certification or "
            "legal compliance determination."
        ),
        "evidence_origin": "LOCALLY_OBSERVED",
    }

    pack["pack_sha256"] = _sha256_dict(pack)
    return pack


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def export_pack(
    framework: str,
    scope: dict[str, Any],
    store: Any,
    *,
    fmt: str = "json",
) -> Any:
    """Build and export a compliance evidence pack.

    Parameters
    ----------
    fmt:
        ``"json"``     — returns full pack dict (default).
        ``"oscal"``    — OSCAL 1.1.2 SSP dict.
        ``"html"``     — simple HTML string.
        ``"markdown"`` — Markdown string.
    """
    fmt = str(fmt).lower().strip()
    if fmt not in EXPORT_FORMATS:
        raise EvidencePackError(
            f"Unknown format: {fmt!r}. Valid: {sorted(EXPORT_FORMATS)}"
        )

    pack = build_evidence_pack(framework, scope, store)

    if fmt == "json":
        return pack

    if fmt == "oscal":
        return _to_oscal(pack)

    if fmt == "markdown":
        return _to_markdown(pack)

    return _to_html(pack)


def _to_oscal(pack: dict[str, Any]) -> dict[str, Any]:
    """Emit an OSCAL 1.1.2 SSP from the evidence pack."""
    from .exporters.oscal import export_oscal_ssp

    controls = [
        {
            "id": c["control_id"],
            "title": c["title"],
            "status": _oscal_status(c["status"]),
            "description": c.get("description", ""),
        }
        for c in pack["controls"]
    ]
    evidence = [
        {"control_id": c["control_id"], **ref}
        for c in pack["controls"]
        for ref in (c.get("evidence_refs") or [])
    ]
    return export_oscal_ssp(
        system_name=pack["framework_display_name"],
        controls=controls,
        evidence=evidence,
        report={
            "scope": pack["scope"],
            "framework": pack["framework"],
            "built_at": pack["built_at"],
            "summary": pack["summary"],
        },
    )


def _oscal_status(status: str) -> str:
    return {
        "satisfied": "PASS",
        "partial": "PARTIAL",
        "missing": "FAIL",
        "not_applicable": "NOT_EVALUATED",
    }.get(status, "NOT_EVALUATED")


def _to_markdown(pack: dict[str, Any]) -> str:
    lines = [
        "# Compliance Evidence Pack",
        "",
        f"**Framework:** {pack['framework_display_name']}",
        f"**Built:** {pack['built_at']}",
        f"**Scope:** {json.dumps(pack['scope'])}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total controls | {pack['summary']['total_controls']} |",
        f"| Satisfied | {pack['summary']['satisfied']} |",
        f"| Partial | {pack['summary']['partial']} |",
        f"| Missing | {pack['summary']['missing']} |",
        f"| Coverage | {pack['summary']['coverage_pct']}% |",
        f"| Status | {pack['summary']['overall_status']} |",
        "",
        "## Controls",
        "",
    ]
    for ctrl in pack["controls"]:
        emoji = {"satisfied": "✅", "partial": "⚠️", "missing": "❌", "not_applicable": "➖"}.get(
            ctrl["status"], "❓"
        )
        lines.append(f"### {emoji} {ctrl['control_id']} — {ctrl['title']}")
        lines.append("")
        lines.append(f"**Status:** {ctrl['status'].upper()}")
        lines.append(f"**Description:** {ctrl.get('description', '')}")
        if ctrl.get("evidence_refs"):
            lines.append("")
            lines.append(f"**Evidence ({len(ctrl['evidence_refs'])} item(s)):**")
            for ref in ctrl["evidence_refs"][:5]:
                lines.append(f"- `{ref.get('ref')}` — {ref.get('summary')}")
        if ctrl.get("missing_evidence_types"):
            lines.append("")
            lines.append(f"**Missing:** {', '.join(ctrl['missing_evidence_types'])}")
        lines.append("")
    return "\n".join(lines)


def _to_html(pack: dict[str, Any]) -> str:
    import html as _html

    def esc(s: Any) -> str:
        return _html.escape(str(s or ""))

    status_colors = {
        "satisfied": "#2d6a4f", "partial": "#b5450b",
        "missing": "#9b2226", "not_applicable": "#555",
    }
    rows = []
    for ctrl in pack["controls"]:
        color = status_colors.get(ctrl["status"], "#333")
        evidence_list = "".join(
            f'<li><code>{esc(ref.get("ref"))}</code> — {esc(ref.get("summary"))}</li>'
            for ref in (ctrl.get("evidence_refs") or [])[:5]
        )
        evidence_html = f"<ul>{evidence_list}</ul>" if evidence_list else "<em>None found</em>"
        rows.append(
            f"<tr>"
            f"<td><strong>{esc(ctrl['control_id'])}</strong><br><small>{esc(ctrl['title'])}</small></td>"
            f"<td style='color:{color}'><strong>{esc(ctrl['status'].upper())}</strong></td>"
            f"<td>{evidence_html}</td>"
            f"<td>{esc(', '.join(ctrl.get('missing_evidence_types') or []))}</td>"
            f"</tr>"
        )
    s = pack["summary"]
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Evidence Pack — {esc(pack['framework_display_name'])}</title>"
        f"<style>body{{font-family:sans-serif;max-width:1100px;margin:2em auto}}"
        f"table{{border-collapse:collapse;width:100%}}"
        f"th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}"
        f"th{{background:#f4f4f4}}</style></head><body>"
        f"<h1>Compliance Evidence Pack</h1>"
        f"<p><strong>Framework:</strong> {esc(pack['framework_display_name'])}<br>"
        f"<strong>Built:</strong> {esc(pack['built_at'])}<br>"
        f"<strong>Scope:</strong> {esc(json.dumps(pack['scope']))}<br>"
        f"<strong>Status:</strong> {esc(s['overall_status'])}<br>"
        f"<strong>Coverage:</strong> {esc(s['coverage_pct'])}% "
        f"({esc(s['satisfied'])} satisfied / {esc(s['partial'])} partial / "
        f"{esc(s['missing'])} missing of {esc(s['total_controls'])} controls)</p>"
        f"<table><thead><tr>"
        f"<th>Control</th><th>Status</th><th>Evidence</th><th>Missing</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        f"<p><small>{esc(pack['assessment_basis'])}</small></p>"
        f"</body></html>"
    )

"""Security control catalog for AI assurance evaluations."""
from copy import deepcopy
from typing import Any, Dict, List


CONTROL_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "AIAF-GOV-001",
        "title": "Accountability and risk ownership",
        "objective": "Support AI Governance",
        "domain": "Governance",
        "description": "AI systems have named operational and risk owners for review, escalation, and acceptance decisions.",
        "evidence_fields": ["owner", "risk_owner"],
        "standards": {
            "NIST AI RMF": ["GOVERN 2.1", "GOVERN 2.3"],
            "CIS Controls": ["Control 17 Incident Response Management"],
        },
        "threats": ["unowned_risk", "weak_escalation_path"],
    },
    {
        "id": "AIAF-RISK-001",
        "title": "Continuous risk monitoring",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Risk Monitoring",
        "description": "AI systems are periodically assessed and monitored for changing security posture.",
        "evidence_fields": ["monitoring_enabled", "assessment_frequency"],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.5", "MANAGE 2.2"],
            "OWASP Top 10 for LLMs": ["LLM07 System Prompt Leakage", "LLM09 Misinformation"],
        },
        "threats": ["risk_drift", "undetected_model_misbehavior"],
    },
    {
        "id": "AIAF-RISK-002",
        "title": "Adversarial validation evidence",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Security Validation",
        "description": "AI systems retain evidence of adversarial tests, red-team probes, or abuse-case validation.",
        "evidence_fields": ["adversarial_tests"],
        "standards": {
            "NIST AI RMF": ["MAP 5.1", "MEASURE 2.7"],
            "MITRE ATLAS": ["AML.T0043 Craft Adversarial Data", "AML.T0054 LLM Jailbreak"],
        },
        "threats": ["untested_abuse_paths", "jailbreak_regression"],
    },
    {
        "id": "AIAF-RISK-003",
        "title": "Finding lifecycle and remediation governance",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Risk Monitoring",
        "description": "AI systems define accountable risk ownership and remediation service levels for detected assurance findings.",
        "evidence_fields": ["risk_owner", "remediation_sla"],
        "standards": {
            "NIST AI RMF": ["GOVERN 2.3", "MANAGE 1.3", "MANAGE 2.4"],
            "CIS Controls": ["Control 7 Continuous Vulnerability Management"],
        },
        "threats": ["unmanaged_findings", "overdue_remediation", "unaccepted_risk"],
    },
    {
        "id": "AIAF-RISK-004",
        "title": "Model impact and exposure classification",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Risk Assessment",
        "description": (
            "AI systems document model impact, deployment exposure, data "
            "classification, capabilities, and operational safeguards."
        ),
        "evidence_fields": ["model_risk_profile"],
        "standards": {
            "NIST AI RMF": ["MAP 1.1", "MAP 3.5", "MAP 5.1", "MEASURE 2.5"],
            "NIST SSDF": ["PO.1", "RV.1"],
        },
        "threats": [
            "unclassified_model_impact",
            "unsafe_external_exposure",
            "uncontrolled_high_risk_capability",
        ],
    },
    {
        "id": "AIAF-RISK-005",
        "title": "Bias and fairness evaluation evidence",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Model Reliability",
        "description": (
            "AI systems that make or inform consequential decisions retain bias "
            "and fairness evaluation evidence such as group-outcome metrics, "
            "fairness metrics, or a declared bias evaluation."
        ),
        "evidence_fields_any": [
            "group_metrics",
            "has_bias_evaluation",
            "has_fairness_metrics",
            "bias_evaluation_context",
        ],
        "applies_when_any": [
            "model_risk_profile",
            "domain",
            "group_metrics",
            "has_bias_evaluation",
            "has_fairness_metrics",
            "bias_evaluation_context",
        ],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.1", "MAP 5.1", "MEASURE 2.5", "MEASURE 2.6"],
            "EU AI Act": ["Article 9 Risk Management", "Article 10 Data Governance"],
        },
        "threats": [
            "discriminatory_outcomes",
            "unmeasured_disparate_impact",
            "protected_attribute_misuse",
        ],
    },
    {
        "id": "AIAF-RISK-006",
        "title": "Factual reliability evaluation evidence",
        "objective": "Establish Continuous AI Security Assurance",
        "domain": "Model Reliability",
        "description": (
            "AI systems retain factual-reliability evidence such as factuality "
            "evaluation, output grounding, or retrieval provenance to bound "
            "hallucination risk before consequential use."
        ),
        "evidence_fields_any": [
            "factuality_evidence",
            "retrieval_evidence",
            "has_factuality_evaluation",
            "has_output_grounding",
        ],
        "applies_when_any": [
            "model_risk_profile",
            "domain",
            "factuality_evidence",
            "retrieval_evidence",
            "has_factuality_evaluation",
            "has_output_grounding",
        ],
        "standards": {
            "OWASP Top 10 for LLMs": ["LLM09 Misinformation"],
            "NIST AI RMF": ["MAP 5.2", "MEASURE 2.1", "MANAGE 2.2"],
        },
        "threats": [
            "factual_unreliability",
            "ungrounded_generation",
            "unverified_automated_decision",
        ],
    },
    {
        "id": "AIAF-SC-001",
        "title": "Model source provenance",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model artifacts have a declared source URL and publisher for provenance analysis.",
        "evidence_fields": ["source_url", "publisher"],
        "standards": {
            "OWASP Top 10 for LLMs": ["LLM05 Supply Chain Vulnerabilities"],
            "NIST AI RMF": ["GOVERN 6.1", "MAP 4.1"],
            "MITRE ATLAS": ["AML.T0010 AI Supply Chain Compromise"],
            "NIST SSDF": ["PS.3"],
        },
        "threats": ["unknown_model_origin", "untrusted_publisher"],
    },
    {
        "id": "AIAF-SC-002",
        "title": "Artifact integrity verification",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model artifacts have a cryptographic digest that can be checked before deployment.",
        "evidence_fields": ["sha256"],
        "standards": {
            "NIST AI RMF": ["MAP 4.2"],
            "MITRE ATLAS": ["AML.T0018 Manipulate AI Model"],
            "NIST SSDF": ["PS.2", "PS.3"],
            "CIS Controls": ["Control 2 Inventory and Control of Software Assets"],
        },
        "threats": ["model_tampering", "artifact_substitution"],
    },
    {
        "id": "AIAF-SC-003",
        "title": "Model bill of materials coverage",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model records include licensing and dependency inventory evidence for supply-chain review.",
        "evidence_fields": ["license", "dependencies"],
        "standards": {
            "NIST AI RMF": ["GOVERN 6.1", "MAP 4.1"],
            "MITRE ATLAS": ["AML.T0010 AI Supply Chain Compromise"],
            "NIST SSDF": ["PO.3", "PS.3"],
            "OWASP Top 10 for LLMs": ["LLM05 Supply Chain Vulnerabilities"],
        },
        "threats": ["dependency_exposure", "license_uncertainty"],
    },
    {
        "id": "AIAF-SC-004",
        "title": "Training artifact lineage",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model records identify training datasets or training artifacts used to create or adapt the model.",
        "evidence_fields": ["training_artifacts"],
        "standards": {
            "NIST AI RMF": ["GOVERN 6.1", "MAP 4.1", "MAP 4.2"],
            "MITRE ATLAS": ["AML.T0010.002 AI Supply Chain Compromise: Data"],
            "NIST SSDF": ["PO.3", "PS.3"],
        },
        "threats": ["unknown_training_lineage", "training_data_exposure"],
    },
    {
        "id": "AIAF-SC-005",
        "title": "Deployment pipeline traceability",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model records identify the deployment environment, artifact reference, and approval evidence used for release.",
        "evidence_fields": ["deployment_pipeline"],
        "standards": {
            "NIST AI RMF": ["MAP 4.2", "MANAGE 2.4"],
            "NIST SSDF": ["PS.2", "PS.3"],
            "CIS Controls": ["Control 4 Secure Configuration of Enterprise Assets and Software"],
        },
        "threats": ["untracked_deployment", "mutable_deployment_artifact"],
    },
    {
        "id": "AIAF-SC-006",
        "title": "Signed model provenance attestation",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model records retain a signed statement binding model identity, artifact digest, source, and AI-BOM digest.",
        "evidence_fields": ["provenance_attestations"],
        "standards": {
            "NIST AI RMF": ["GOVERN 6.1", "MAP 4.2"],
            "MITRE ATLAS": ["AML.T0010 AI Supply Chain Compromise", "AML.T0018 Manipulate AI Model"],
            "NIST SSDF": ["PS.2", "PS.3"],
        },
        "threats": ["model_tampering", "artifact_substitution", "forged_provenance"],
    },
    {
        "id": "AIAF-SC-007",
        "title": "Dependency vulnerability intelligence",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": "Model dependencies are correlated with a maintained vulnerability advisory catalog using exact package versions.",
        "evidence_fields": ["vulnerability_scan"],
        "standards": {
            "NIST AI RMF": ["MAP 4.2", "MEASURE 2.7", "MANAGE 1.3"],
            "NIST SSDF": ["RV.1"],
            "OWASP Top 10 for LLMs": ["LLM05 Supply Chain Vulnerabilities"],
            "CIS Controls": ["Control 7 Continuous Vulnerability Management"],
        },
        "threats": ["known_vulnerable_dependency", "stale_advisory_intelligence", "unresolved_dependency_version"],
    },
    {
        "id": "AIAF-SC-008",
        "title": "Authenticated vulnerability advisory intelligence",
        "objective": "Strengthen AI Supply Chain Integrity",
        "domain": "Supply Chain",
        "description": (
            "Vulnerability advisory feeds are authenticated, freshness-bound, "
            "and protected against sequence rollback before they influence scans."
        ),
        "evidence_fields": ["advisory_feed_policy"],
        "standards": {
            "NIST AI RMF": ["MAP 4.2", "MEASURE 2.7", "MANAGE 1.3"],
            "NIST SSDF": ["RV.1"],
            "OWASP Top 10 for LLMs": ["LLM05 Supply Chain Vulnerabilities"],
            "CIS Controls": ["Control 7 Continuous Vulnerability Management"],
        },
        "threats": [
            "forged_advisory_feed",
            "stale_advisory_intelligence",
            "advisory_feed_rollback",
        ],
    },
    {
        "id": "AIAF-AGT-001",
        "title": "Agent tool and permission inventory",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": "Agentic systems declare tool access and permissions before autonomous operation.",
        "evidence_fields": ["tools", "permissions"],
        "applies_when_any": ["tools", "permissions", "autonomy_level", "agentic", "agent_policy_profile"],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MEASURE 2.7"],
            "MITRE ATLAS": ["AML.T0053 AI Agent Tool Invocation"],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
            "CIS Controls": ["Control 6 Access Control Management"],
        },
        "threats": ["excessive_agency", "unbounded_tool_use"],
    },
    {
        "id": "AIAF-AGT-002",
        "title": "Autonomy and human review constraints",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": "Agentic systems declare autonomy level and human review expectations for high-impact actions.",
        "evidence_fields": ["autonomy_level", "human_review_required"],
        "applies_when_any": ["tools", "permissions", "autonomy_level", "agentic", "agent_policy_profile"],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MANAGE 2.4"],
            "MITRE ATLAS": ["AML.T0053 AI Agent Tool Invocation"],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
        },
        "threats": ["unsafe_autonomy", "missing_human_approval"],
    },
    {
        "id": "AIAF-AGT-003",
        "title": "Agent policy constraints",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": "Agentic systems declare reusable policy constraints for tools, permissions, autonomy, approvals, and external calls.",
        "evidence_fields_any": ["agent_policy", "agent_policy_profile"],
        "applies_when_any": ["tools", "permissions", "autonomy_level", "workflow_steps", "agentic", "agent_policy_profile"],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MAP 4.2", "MANAGE 2.4"],
            "MITRE ATLAS": ["AML.T0081 Modify AI Agent Configuration"],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
            "CIS Controls": ["Control 6 Access Control Management"],
        },
        "threats": ["policy_bypass", "unbounded_tool_use", "unsafe_autonomy"],
    },
    {
        "id": "AIAF-AGT-004",
        "title": "Agent workflow graph safety",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": "Agent workflows declare steps and transitions for reachability, termination, data-flow, and privilege-boundary validation.",
        "evidence_fields": ["workflow_steps"],
        "applies_when_any": ["tools", "permissions", "autonomy_level", "workflow_steps", "agentic", "agent_policy_profile"],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MEASURE 2.7", "MANAGE 2.4"],
            "MITRE ATLAS": ["AML.T0053 AI Agent Tool Invocation", "AML.T0081 Modify AI Agent Configuration"],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
        },
        "threats": ["unbounded_workflow", "tainted_tool_input", "privilege_escalation"],
    },
    {
        "id": "AIAF-AGT-005",
        "title": "Runtime tool authorization enforcement",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": (
            "Agent tool calls are authorized against an immutable policy and "
            "workflow snapshot before execution."
        ),
        "evidence_fields": ["runtime_tool_authorization"],
        "applies_when_any": [
            "tools",
            "permissions",
            "autonomy_level",
            "workflow_steps",
            "agentic",
            "agent_policy_profile",
        ],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MEASURE 2.7", "MANAGE 2.4"],
            "MITRE ATLAS": [
                "AML.T0053 AI Agent Tool Invocation",
                "AML.T0081 Modify AI Agent Configuration",
            ],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
            "CIS Controls": ["Control 6 Access Control Management"],
        },
        "threats": [
            "runtime_policy_bypass",
            "unauthorized_tool_invocation",
            "external_call_exhaustion",
        ],
    },
    {
        "id": "AIAF-AGT-006",
        "title": "Per-tool invocation risk evidence",
        "objective": "Improve Agentic AI Security",
        "domain": "Agentic AI",
        "description": (
            "Agentic systems declare per-invocation tool context (explicit tool "
            "invocations or workflow steps) so each tool call can be risk-scored "
            "for injection, exfiltration, and privilege escalation."
        ),
        "evidence_fields_any": ["tool_invocations", "workflow_steps"],
        "applies_when_any": [
            "tools",
            "permissions",
            "autonomy_level",
            "workflow_steps",
            "tool_invocations",
            "agentic",
            "agent_policy_profile",
        ],
        "standards": {
            "NIST AI RMF": ["MAP 3.5", "MEASURE 2.7", "MANAGE 2.4"],
            "MITRE ATLAS": [
                "AML.T0053 AI Agent Tool Invocation",
                "AML.T0051 LLM Prompt Injection",
            ],
            "OWASP Top 10 for LLMs": ["LLM06 Excessive Agency"],
            "CIS Controls": ["Control 6 Access Control Management"],
        },
        "threats": [
            "unauthorized_tool_invocation",
            "untrusted_input_to_dangerous_capability",
            "tool_permission_escalation",
        ],
    },
    {
        "id": "AIAF-GOV-002",
        "title": "Compliance scope and documentation",
        "objective": "Support AI Governance",
        "domain": "Governance",
        "description": "AI systems identify applicable compliance scope and supporting documentation.",
        "evidence_fields": ["compliance_scope", "documentation_url"],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.1", "MAP 1.1"],
            "NIST SSDF": ["PO.1"],
        },
        "threats": ["weak_auditability", "missing_compliance_evidence"],
    },
    {
        "id": "AIAF-GOV-003",
        "title": "Independent assurance evidence review",
        "objective": "Support AI Governance",
        "domain": "Governance",
        "description": "Organizations define independent review and retention requirements for evidence used to satisfy AI assurance controls.",
        "evidence_fields": ["evidence_review_policy", "evidence_retention_period"],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.5", "GOVERN 2.3", "MANAGE 2.4"],
            "NIST SSDF": ["PO.1"],
            "CIS Controls": ["Control 8 Audit Log Management"],
        },
        "threats": ["self_attested_compliance", "expired_evidence", "evidence_tampering"],
    },
    {
        "id": "AIAF-GOV-004",
        "title": "Artifact-scoped assurance traceability",
        "objective": "Support AI Governance",
        "domain": "Governance",
        "description": (
            "Assurance findings, metrics, controls, monitoring history, and "
            "runtime decisions are attributable to one identified AI system."
        ),
        "evidence_fields": ["id", "assurance_scope"],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.5", "GOVERN 4.1", "MAP 1.1"],
            "NIST SSDF": ["PO.1"],
            "CIS Controls": [
                "Control 1 Inventory and Control of Enterprise Assets"
            ],
        },
        "threats": [
            "cross_system_evidence_contamination",
            "unattributed_assurance_result",
            "misleading_compliance_posture",
        ],
    },
    {
        "id": "AIAF-GOV-005",
        "title": "Immutable assurance report retention",
        "objective": "Support AI Governance",
        "domain": "Governance",
        "description": (
            "Organizations retain versioned, digest-verifiable assurance report "
            "snapshots for audit and compliance evidence."
        ),
        "evidence_fields": ["report_snapshot_policy"],
        "standards": {
            "NIST AI RMF": ["GOVERN 1.5", "GOVERN 4.1", "MEASURE 4.2"],
            "NIST SSDF": ["PO.1"],
            "CIS Controls": ["Control 8 Audit Log Management"],
        },
        "threats": [
            "assurance_report_tampering",
            "non_reproducible_compliance_claim",
            "missing_point_in_time_evidence",
        ],
    },
]


def get_control_catalog() -> List[Dict[str, Any]]:
    """Return a copy of the control catalog for API responses and reports."""
    return deepcopy(CONTROL_CATALOG)


def evaluate_catalog_controls(artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate all catalog controls against evidence in an artifact record."""
    evaluations = []
    for control in CONTROL_CATALOG:
        evidence_fields = control.get("evidence_fields", [])
        if not _control_applies(control, artifact):
            evaluations.append(_evaluation(control, "not_applicable", [], []))
            continue

        missing = [field for field in evidence_fields if not _has_evidence(artifact.get(field))]
        evidence_fields_any = control.get("evidence_fields_any", [])
        if evidence_fields_any and not any(
            _has_evidence(artifact.get(field)) for field in evidence_fields_any
        ):
            missing.append(" or ".join(evidence_fields_any))
        status = "satisfied" if not missing else "missing"
        provided = [field for field in evidence_fields if field not in missing]
        provided.extend(
            field
            for field in evidence_fields_any
            if _has_evidence(artifact.get(field))
        )
        evaluations.append(_evaluation(control, status, missing, provided))

    return evaluations


def summarize_control_evaluations(evaluations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create status, objective, and domain summaries for control evaluations.

    The domain breakdown makes analyzer-backed control areas individually
    visible (e.g. ``Model Reliability`` for the bias/fairness and
    factual-reliability controls), which the broad objective grouping hides.
    """
    by_status: Dict[str, int] = {}
    by_objective: Dict[str, Dict[str, int]] = {}
    by_domain: Dict[str, Dict[str, int]] = {}

    for evaluation in evaluations:
        status = evaluation["status"]
        objective = evaluation["objective"]
        domain = evaluation.get("domain", "Unspecified")
        by_status[status] = by_status.get(status, 0) + 1
        by_objective.setdefault(objective, {})
        by_objective[objective][status] = by_objective[objective].get(status, 0) + 1
        by_domain.setdefault(domain, {})
        by_domain[domain][status] = by_domain[domain].get(status, 0) + 1

    return {
        "total_controls": len(evaluations),
        "by_status": by_status,
        "by_objective": by_objective,
        "by_domain": by_domain,
    }


def _control_applies(control: Dict[str, Any], artifact: Dict[str, Any]) -> bool:
    applies_when_any = control.get("applies_when_any")
    if not applies_when_any:
        return True
    return any(_has_evidence(artifact.get(field)) for field in applies_when_any)


def _has_evidence(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _evaluation(
    control: Dict[str, Any],
    status: str,
    missing_evidence: List[str],
    provided_evidence: List[str],
) -> Dict[str, Any]:
    return {
        "id": control["id"],
        "title": control["title"],
        "objective": control["objective"],
        "domain": control["domain"],
        "description": control["description"],
        "status": status,
        "provided_evidence": provided_evidence,
        "missing_evidence": missing_evidence,
        "standards": deepcopy(control["standards"]),
        "threats": list(control["threats"]),
    }

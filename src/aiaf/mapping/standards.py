"""Versioned standards mappings for AI assurance findings."""

from copy import deepcopy
from typing import Any

STANDARD_PROFILES: dict[str, dict[str, str]] = {
    "nist_ai_rmf": {
        "name": "NIST AI RMF",
        "version": "1.0",
        "source_url": "https://doi.org/10.6028/NIST.AI.100-1",
    },
    "nist_ssdf": {
        "name": "NIST Secure Software Development Framework",
        "version": "1.1",
        "source_url": "https://doi.org/10.6028/NIST.SP.800-218",
    },
    "owasp_llm": {
        "name": "OWASP Top 10 for LLMs",
        "version": "2025",
        "source_url": "https://genai.owasp.org/llm-top-10/",
    },
    "mitre_atlas": {
        "name": "MITRE ATLAS",
        "version": "5.6.0",
        "source_url": "https://atlas.mitre.org/",
    },
    "cis_controls": {
        "name": "CIS Controls",
        "version": "8.1",
        "source_url": "https://www.cisecurity.org/controls/v8-1",
    },
    "eu_ai_act": {
        "name": "EU AI Act",
        "version": "2024/1689",
        "source_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
    },
}

REFERENCE_PROFILES: dict[str, dict[str, dict[str, str]]] = {
    "NIST AI RMF": {
        "GOVERN 1.1": {"summary": "Establish and communicate AI governance policies, roles, and accountability structures."},
        "GOVERN 1.5": {"summary": "Review governance processes regularly so AI risk management stays current over time."},
        "GOVERN 1.7": {"summary": "Document, log, and monitor AI agent actions to enable auditability and accountability throughout operation."},
        "GOVERN 2.1": {"summary": "Assign organizational accountability so AI risks and decisions have clearly named owners."},
        "GOVERN 2.3": {"summary": "Maintain escalation, oversight, and risk response responsibilities across the AI lifecycle."},
        "GOVERN 4.1": {"summary": "Promote transparency and communication about AI system characteristics, limitations, and impacts."},
        "GOVERN 6.1": {"summary": "Manage AI supply-chain dependencies, provenance, and third-party relationships as part of governance."},
        "MAP 1.1": {"summary": "Define the intended purpose, context, and use conditions of the AI system."},
        "MAP 3.5": {"summary": "Document system capabilities, interfaces, access, and operational dependencies that affect risk."},
        "MAP 4.1": {"summary": "Map data, components, and supporting resources that influence system behavior and exposure."},
        "MAP 4.2": {"summary": "Trace system components, provenance, and deployment artifacts so integrity can be verified."},
        "MAP 5.1": {"summary": "Characterize impact, affected populations, and risk factors associated with system use."},
        "MAP 5.2": {"summary": "Identify conditions under which outputs may be unreliable, misleading, or harmful."},
        "MEASURE 2.1": {"summary": "Evaluate system performance and reliability using appropriate tests and evidence."},
        "MEASURE 2.5": {"summary": "Assess system impacts such as fairness, bias, and performance against intended use."},
        "MEASURE 2.6": {"summary": "Monitor whether risk indicators and assurance evidence change over time."},
        "MEASURE 2.7": {"summary": "Test for failures, misuse, adversarial behavior, and other harmful system behaviors."},
        "MEASURE 2.10": {"summary": "Evaluate data handling, privacy, and information exposure risks in operation."},
        "MEASURE 4.2": {"summary": "Review monitoring outputs and incident evidence to support ongoing improvement."},
        "MANAGE 1.2": {"summary": "Use risk analysis outcomes to prioritize treatment, controls, and decision-making."},
        "MANAGE 1.3": {"summary": "Track and remediate identified risks using accountable owners and response plans."},
        "MANAGE 2.2": {"summary": "Continuously monitor systems and update controls when performance or risk changes."},
        "MANAGE 2.4": {"summary": "Implement lifecycle controls, release gates, and operational responses to manage AI risk."},
    },
    "NIST Secure Software Development Framework": {
        "PO.1": {"summary": "Define organizational requirements and roles for secure software development."},
        "PO.3": {"summary": "Protect software components and dependencies throughout the supply chain."},
        "PS.2": {"summary": "Protect software release integrity and deployment artifacts."},
        "PS.3": {"summary": "Archive and release software with traceable integrity and provenance evidence."},
        "RV.1": {"summary": "Review and validate software to identify vulnerabilities and quality issues before release."},
    },
    "OWASP Top 10 for LLMs": {
        "LLM01 Prompt Injection": {"summary": "Guard against instructions or content that manipulate model behavior outside intended policy."},
        "LLM02 Sensitive Information Disclosure": {"summary": "Prevent models from exposing secrets, personal data, or other protected information."},
        "LLM03 Supply Chain Vulnerabilities": {"summary": "Manage compromise risks across the AI supply chain: models, datasets, plugins, adapters, and third-party components."},
        "LLM04 Data and Model Poisoning": {"summary": "Detect and prevent tampering with training data or model weights that encodes backdoors or degrades behavior."},
        "LLM05 Supply Chain Vulnerabilities": {"summary": "Manage compromise risks in models, datasets, plugins, dependencies, and third-party components."},
        "LLM06 Excessive Agency": {"summary": "Constrain tool use, permissions, and autonomous actions so the model cannot exceed intended authority."},
        "LLM07 System Prompt Leakage": {"summary": "Protect hidden prompts, policies, and control instructions from disclosure or extraction."},
        "LLM09 Misinformation": {"summary": "Detect and reduce false, misleading, or fabricated outputs that may cause harm."},
    },
    "MITRE ATLAS": {
        "AML.T0010 AI Supply Chain Compromise": {"summary": "Adversaries compromise the AI supply chain, including model sources, components, or dependencies."},
        "AML.T0010.002 AI Supply Chain Compromise: Data": {"summary": "Adversaries tamper with training or supporting data used within the AI supply chain."},
        "AML.T0015 Evade AI Model": {"summary": "Adversaries craft inputs or conditions that cause the model to misclassify or misbehave."},
        "AML.T0018 Manipulate AI Model": {"summary": "Adversaries alter a model artifact, weights, or configuration to change behavior."},
        "AML.T0024 Exfiltration via AI Inference API": {"summary": "Adversaries extract sensitive information through inference interfaces or model interactions."},
        "AML.T0043 Craft Adversarial Data": {"summary": "Adversaries create malicious data intended to degrade, bypass, or manipulate model behavior."},
        "AML.T0020 Poison Training Data": {"summary": "Adversaries corrupt training data to implant backdoors, biases, or degraded behaviors into a trained model."},
        "AML.T0051 LLM Prompt Injection": {"summary": "Adversaries inject prompt content that subverts intended model instructions or policy."},
        "AML.T0053 AI Agent Tool Invocation": {"summary": "Adversaries abuse or influence agent tool use to trigger unsafe operations."},
        "AML.T0054 LLM Jailbreak": {"summary": "Adversaries bypass safety boundaries to elicit restricted or harmful model behavior."},
        "AML.T0081 Modify AI Agent Configuration": {"summary": "Adversaries change agent settings, policies, or configuration to expand capability or weaken controls."},
    },
    "CIS Controls": {
        "Control 2 Inventory and Control of Software Assets": {"summary": "Maintain accurate inventory and control over software assets and components."},
        "Control 3 Data Protection": {"summary": "Protect sensitive data through governance, handling controls, and technical safeguards."},
        "Control 4 Secure Configuration of Enterprise Assets and Software": {"summary": "Harden configurations and enforce secure baselines for software and supporting systems."},
        "Control 6 Access Control Management": {"summary": "Manage identities, privileges, and authorization boundaries for users and systems."},
        "Control 7 Continuous Vulnerability Management": {"summary": "Identify, prioritize, and remediate vulnerabilities through an ongoing management process."},
        "Control 8 Audit Log Management": {"summary": "Collect, retain, and review logs needed for monitoring, investigation, and improvement."},
        "Control 17 Incident Response Management": {"summary": "Establish roles, plans, and coordination for incident response and follow-up actions."},
    },
    "EU AI Act": {
        "Article 9 Risk Management": {"summary": "High-risk AI systems must maintain a documented, continuous risk management process."},
        "Article 10 Data Governance": {"summary": "High-risk AI systems must apply data governance and quality practices to training, validation, and test data."},
    },
}

STANDARDS = {key: profile["name"] for key, profile in STANDARD_PROFILES.items()}
FRAMEWORKS = list(STANDARDS.values())

FINDING_MAPPINGS = {
    "prompt_injection": {
        "owasp_llm": ["LLM01 Prompt Injection"],
        "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    "jailbreak": {
        "owasp_llm": ["LLM01 Prompt Injection"],
        "mitre_atlas": ["AML.T0054 LLM Jailbreak"],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    "model_risk": {
        "nist_ai_rmf": ["MAP 5.1", "MEASURE 2.5", "MANAGE 1.2"],
        "nist_ssdf": ["PO.1", "RV.1"],
    },
    "agent_risk": {
        "owasp_llm": ["LLM06 Excessive Agency"],
        "mitre_atlas": [
            "AML.T0053 AI Agent Tool Invocation",
            "AML.T0081 Modify AI Agent Configuration",
        ],
        "cis_controls": ["Control 6 Access Control Management"],
        "nist_ai_rmf": ["MAP 3.5", "MEASURE 2.7", "MANAGE 2.4"],
    },
    "tool_invocation_risk": {
        "owasp_llm": ["LLM06 Excessive Agency"],
        "mitre_atlas": [
            "AML.T0053 AI Agent Tool Invocation",
            "AML.T0051 LLM Prompt Injection",
        ],
        "nist_ai_rmf": ["MAP 3.5", "MEASURE 2.7", "MANAGE 2.4"],
        "cis_controls": ["Control 6 Access Control Management"],
    },
    "supply_chain": {
        "owasp_llm": ["LLM05 Supply Chain Vulnerabilities"],
        "mitre_atlas": ["AML.T0010 AI Supply Chain Compromise"],
        "nist_ai_rmf": ["GOVERN 6.1", "MAP 4.1", "MAP 4.2"],
        "nist_ssdf": ["PO.3", "PS.3"],
        "cis_controls": ["Control 2 Inventory and Control of Software Assets"],
    },
    "data_leakage": {
        "owasp_llm": ["LLM02 Sensitive Information Disclosure"],
        "mitre_atlas": ["AML.T0024 Exfiltration via AI Inference API"],
        "cis_controls": ["Control 3 Data Protection"],
        "nist_ai_rmf": ["MEASURE 2.7", "MEASURE 2.10", "MANAGE 1.3"],
    },
    "hallucination_risk": {
        "owasp_llm": ["LLM09 Misinformation"],
        "nist_ai_rmf": ["MAP 5.2", "MEASURE 2.1", "MANAGE 2.2"],
        "nist_ssdf": ["RV.1"],
    },
    "risk_drift": {
        "nist_ai_rmf": ["MEASURE 2.6", "MEASURE 4.2", "MANAGE 2.2", "MANAGE 2.4"],
        "cis_controls": ["Control 8 Audit Log Management"],
    },
    "bias_fairness": {
        "nist_ai_rmf": ["GOVERN 1.1", "MAP 5.1", "MEASURE 2.5", "MEASURE 2.6"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 10 Data Governance"],
    },
    "adversarial_testing": {
        "mitre_atlas": [
            "AML.T0043 Craft Adversarial Data",
            "AML.T0015 Evade AI Model",
        ],
        "nist_ai_rmf": ["MAP 5.1", "MEASURE 2.7"],
        "nist_ssdf": ["RV.1"],
    },
    # External model intake: the adoption decision is a governance gate over an
    # acquired third-party AI component (GOVERN/MAP/MANAGE), aligned with the EU
    # AI Act provider/deployer due-diligence obligations and supply-chain control.
    "adoption_triage": {
        "owasp_llm": ["LLM05 Supply Chain Vulnerabilities"],
        "nist_ai_rmf": ["GOVERN 6.1", "GOVERN 1.1", "MAP 4.1", "MANAGE 1.2"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 26 Deployer Obligations"],
        "cis_controls": ["Control 2 Inventory and Control of Software Assets"],
    },
    # MCP tool supply-chain scanner: injection/rug-pull/SSRF in tool descriptors.
    "mcp_tool_poisoning": {
        "owasp_llm": ["LLM01 Prompt Injection", "LLM07 System Prompt Leakage"],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0053 AI Agent Tool Invocation",
        ],
        "nist_ai_rmf": ["GOVERN 6.1", "MEASURE 2.7", "MANAGE 1.3"],
        "eu_ai_act": ["Article 9 Risk Management"],
    },
    # Backdoor/trojan heuristics: weight-level tampering and implant detection.
    "backdoor_heuristics": {
        "owasp_llm": ["LLM03 Supply Chain Vulnerabilities", "LLM04 Data and Model Poisoning"],
        "mitre_atlas": [
            "AML.T0018 Manipulate AI Model",
            "AML.T0020 Poison Training Data",
        ],
        "nist_ai_rmf": ["MEASURE 2.5", "MAP 4.1", "MANAGE 1.2"],
        "nist_ssdf": ["PO.3", "RV.1"],
    },
    # Runtime inference telemetry: live evidence ingestion from agent sidecars.
    "runtime_telemetry": {
        "owasp_llm": ["LLM01 Prompt Injection", "LLM02 Sensitive Information Disclosure"],
        "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
        "nist_ai_rmf": ["MEASURE 2.7", "MEASURE 4.2"],
        "eu_ai_act": ["Article 12 Record-Keeping", "Article 26 Deployer Obligations"],
        "cis_controls": ["Control 8 Audit Log Management"],
    },
    # Agent action ledger: hash-chained tamper-evident tool-invocation audit log.
    "agent_action_ledger": {
        "owasp_llm": ["LLM06 Excessive Agency"],
        "mitre_atlas": [
            "AML.T0053 AI Agent Tool Invocation",
            "AML.T0081 Modify AI Agent Configuration",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "MANAGE 2.4"],
        "eu_ai_act": ["Article 12 Record-Keeping"],
        "cis_controls": ["Control 8 Audit Log Management"],
    },
    # Inline guardrail: input/output classification for injection and PII.
    "inline_guardrail": {
        "owasp_llm": [
            "LLM01 Prompt Injection",
            "LLM02 Sensitive Information Disclosure",
            "LLM07 System Prompt Leakage",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0054 LLM Jailbreak",
            "AML.T0024 Exfiltration via AI Inference API",
        ],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 1.3"],
    },
    # RAG indirect prompt injection: adversarial instructions in retrieved docs.
    "rag_indirect_injection": {
        "owasp_llm": [
            "LLM01 Prompt Injection",
            "LLM02 Sensitive Information Disclosure",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0024 Exfiltration via AI Inference API",
        ],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 1.3", "GOVERN 1.7"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 16.1"],
    },
    # RAG sensitive-data leakage: PII/credentials surfacing in retrieval.
    "rag_leakage": {
        "owasp_llm": [
            "LLM02 Sensitive Information Disclosure",
            "LLM06 Excessive Agency",
        ],
        "mitre_atlas": [
            "AML.T0024 Exfiltration via AI Inference API",
            "AML.T0057 LLM Data Leakage",
        ],
        "nist_ai_rmf": ["MEASURE 2.5", "MANAGE 2.4"],
        "eu_ai_act": ["Article 10 Data Governance"],
        "cis_controls": ["CIS 3.1", "CIS 3.3"],
    },
    # RAG trust-mix violation: unverified docs mixed with high-trust retrieval.
    "rag_trust_violation": {
        "owasp_llm": [
            "LLM01 Prompt Injection",
            "LLM09 Misinformation",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0020 Poison Training Data",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "MANAGE 1.3"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 16.1"],
    },
    # RAG vector-store inventory: governance of registered stores and documents.
    "rag_inventory": {
        "owasp_llm": [
            "LLM03 Supply Chain Vulnerabilities",
            "LLM02 Sensitive Information Disclosure",
        ],
        "mitre_atlas": [
            "AML.T0010 ML Supply Chain Compromise",
        ],
        "nist_ai_rmf": ["GOVERN 1.2", "MANAGE 4.1"],
        "eu_ai_act": ["Article 10 Data Governance", "Article 12 Record Keeping"],
        "cis_controls": ["CIS 2.1"],
    },
    # Agent registry: identity, capability declaration, trust classification.
    "agent_registry": {
        "owasp_llm": [
            "LLM06 Excessive Agency",
            "LLM03 Supply Chain Vulnerabilities",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0054 LLM Jailbreak",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "GOVERN 1.2", "MANAGE 4.1"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 12 Record Keeping"],
        "cis_controls": ["CIS 2.1", "CIS 5.1"],
    },
    # Permission graph: multi-tool risk path analysis (exfiltration, escalation).
    "permission_graph": {
        "owasp_llm": [
            "LLM06 Excessive Agency",
            "LLM02 Sensitive Information Disclosure",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0024 Exfiltration via AI Inference API",
            "AML.T0043 Craft Adversarial Data",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "MEASURE 2.7", "MANAGE 1.3"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 5.1", "CIS 6.1", "CIS 16.1"],
    },
    # Tool authorization: runtime ALLOW/DENY/CONDITIONAL policy enforcement.
    "tool_authorization": {
        "owasp_llm": [
            "LLM06 Excessive Agency",
        ],
        "mitre_atlas": [
            "AML.T0051 LLM Prompt Injection",
            "AML.T0054 LLM Jailbreak",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "MANAGE 1.3", "MANAGE 2.4"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 14 Human Oversight"],
        "cis_controls": ["CIS 6.1", "CIS 6.2"],
    },
    # Signed tool manifests: supply-chain attestation for tool capability sets.
    "tool_manifest": {
        "owasp_llm": [
            "LLM03 Supply Chain Vulnerabilities",
            "LLM07 System Prompt Leakage",
        ],
        "mitre_atlas": [
            "AML.T0010 ML Supply Chain Compromise",
        ],
        "nist_ai_rmf": ["GOVERN 1.2", "MANAGE 4.1"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 13 Transparency"],
        "cis_controls": ["CIS 2.1", "CIS 16.1"],
    },
    # Exfiltration path: read + egress capability combination.
    "exfiltration_path": {
        "owasp_llm": [
            "LLM02 Sensitive Information Disclosure",
            "LLM06 Excessive Agency",
        ],
        "mitre_atlas": [
            "AML.T0024 Exfiltration via AI Inference API",
        ],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 1.3"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 3.1", "CIS 6.1"],
    },
    # Approval bypass: removal of human oversight gates.
    "approval_bypass_risk": {
        "owasp_llm": [
            "LLM06 Excessive Agency",
        ],
        "mitre_atlas": [
            "AML.T0054 LLM Jailbreak",
        ],
        "nist_ai_rmf": ["GOVERN 1.7", "MANAGE 1.3"],
        "eu_ai_act": ["Article 14 Human Oversight"],
        "cis_controls": ["CIS 6.2"],
    },
    # Phase D — Continuous Security Operations
    "ops_scheduler": {
        "owasp_llm": ["LLM09 Overreliance"],
        "nist_ai_rmf": ["GOVERN 1.7", "GOVERN 6.2"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 18.1"],
    },
    "telemetry_anomaly": {
        "owasp_llm": ["LLM09 Overreliance"],
        "mitre_atlas": ["AML.T0040 ML Supply Chain Compromise"],
        "nist_ai_rmf": ["MEASURE 2.6", "MANAGE 1.3"],
        "eu_ai_act": ["Article 9 Risk Management"],
    },
    "incident_management": {
        "owasp_llm": ["LLM01 Prompt Injection", "LLM06 Excessive Agency"],
        "nist_ai_rmf": ["MANAGE 1.3", "GOVERN 6.2"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 14 Human Oversight"],
        "cis_controls": ["CIS 17.1"],
    },
    "siem_export": {
        "nist_ai_rmf": ["GOVERN 6.2", "MANAGE 1.3"],
        "cis_controls": ["CIS 8.9", "CIS 17.6"],
    },
    "remediation_tracking": {
        "nist_ai_rmf": ["MANAGE 1.3", "MANAGE 2.4"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 7.7", "CIS 17.7"],
    },
    # Phase E — Advanced Assurance
    "poisoning_backdoor_detection": {
        "owasp_llm": ["LLM03 Training Data Poisoning"],
        "mitre_atlas": ["AML.T0018 Backdoor ML Model", "AML.T0020 Poison Training Data"],
        "nist_ai_rmf": ["MEASURE 2.5", "MANAGE 2.2"],
        "eu_ai_act": ["Article 10 Data Governance", "Article 15 Accuracy"],
        "cis_controls": ["CIS 16.1"],
    },
    "model_extraction_risk": {
        "owasp_llm": ["LLM10 Model Theft"],
        "mitre_atlas": ["AML.T0024 Exfiltration via ML Inference API"],
        "nist_ai_rmf": ["MEASURE 2.6", "GOVERN 2.2"],
        "eu_ai_act": ["Article 15 Accuracy", "Article 13 Transparency"],
        "cis_controls": ["CIS 3.3", "CIS 14.6"],
    },
    "benchmark_contamination": {
        "owasp_llm": ["LLM03 Training Data Poisoning"],
        "mitre_atlas": ["AML.T0046 Craft Adversarial Data"],
        "nist_ai_rmf": ["MEASURE 1.1", "MEASURE 2.5"],
        "eu_ai_act": ["Article 10 Data Governance", "Article 15 Accuracy"],
    },
    "adversary_simulation": {
        "owasp_llm": ["LLM01 Prompt Injection", "LLM02 Insecure Output Handling", "LLM10 Model Theft"],
        "mitre_atlas": ["AML.T0043 Craft Adversarial Examples", "AML.T0024 Exfiltration via ML API"],
        "nist_ai_rmf": ["MEASURE 2.7", "GOVERN 5.1"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "cis_controls": ["CIS 18.2", "CIS 18.5"],
    },
    "risk_confidence_scoring": {
        "nist_ai_rmf": ["MEASURE 1.5", "MEASURE 4.1"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 17 Quality Management"],
        "cis_controls": ["CIS 18.1"],
    },
    "ai_threat_intelligence": {
        "nist_ai_rmf": ["GOVERN 1.1", "GOVERN 4.2", "MAP 3.5"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 72 Incident Reporting"],
        "owasp_llm": ["LLM01 Prompt Injection", "LLM03 Supply Chain", "LLM04 Data and Model Poisoning"],
        "mitre_atlas": ["AML.T0018", "AML.T0020", "AML.T0024", "AML.T0031",
                        "AML.T0040", "AML.T0043", "AML.T0046"],
        "cis_controls": ["CIS 12.2", "CIS 17.1"],
    },
    "resource_abuse_monitoring": {
        "nist_ai_rmf": ["MEASURE 2.9", "MANAGE 4.1"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 61 Post-Market Monitoring"],
        "owasp_llm": ["LLM10 Unbounded Consumption"],
        "cis_controls": ["CIS 6.1", "CIS 12.6"],
    },
    "identity_delegation_registry": {
        "nist_ai_rmf": ["GOVERN 2.2", "GOVERN 4.1", "MANAGE 1.3"],
        "eu_ai_act": ["Article 10 Data Governance", "Article 14 Human Oversight"],
        "owasp_llm": ["LLM06 Excessive Agency"],
        "owasp_agentic": ["AGENTIC-01 Tool and Resource Misuse", "AGENTIC-02 Agent Identity Spoofing"],
        "cis_controls": ["CIS 5.1", "CIS 6.2"],
    },
    "memory_integrity": {
        "nist_ai_rmf": ["MEASURE 2.6", "MANAGE 2.4", "GOVERN 6.2"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 14 Human Oversight"],
        "owasp_agentic": ["ASI06 Memory & Context Poisoning"],
        "mitre_atlas": ["AML.T0020 Poison Training Data", "AML.T0024 Exfiltration via ML Inference"],
        "cis_controls": ["CIS 13.1", "CIS 13.5"],
    },
    "agent_topology": {
        "nist_ai_rmf": ["MEASURE 2.5", "GOVERN 1.7", "MANAGE 1.4"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 13 Transparency"],
        "owasp_agentic": ["ASI07 Insecure Inter-Agent Communication",
                          "ASI08 Cascading Agent Failures"],
        "mitre_atlas": ["AML.T0043", "AML.T0040"],
        "cis_controls": ["CIS 12.2", "CIS 18.3"],
    },
    "nhi_registry": {
        "nist_ai_rmf": ["GOVERN 1.6", "MANAGE 2.2", "MAP 5.1"],
        "eu_ai_act": ["Article 10 Data Governance", "Article 9 Risk Management"],
        "owasp_agentic": ["ASI03 Agent Identity & Privilege Abuse"],
        "mitre_atlas": ["AML.T0046"],
        "cis_controls": ["CIS 5.1", "CIS 5.3", "CIS 6.1", "CIS 6.8"],
        "iso_42001": ["6.1.2 AI risk assessment"],
    },
    "policy_enforcement": {
        "nist_ai_rmf": ["MANAGE 1.3", "GOVERN 6.1", "MEASURE 2.3"],
        "eu_ai_act": ["Article 14 Human Oversight", "Article 9 Risk Management"],
        "owasp_agentic": ["ASI01 Agent Goal Hijack", "ASI02 Tool Misuse"],
        "mitre_atlas": ["AML.T0043"],
        "cis_controls": ["CIS 4.1", "CIS 6.2", "CIS 13.9"],
        "nist_csf": ["PR.AC-1", "DE.CM-3"],
    },
    "system_level_redteam": {
        "nist_ai_rmf": ["MEASURE 2.10", "MANAGE 2.2", "GOVERN 6.1"],
        "eu_ai_act": ["Article 9 Risk Management", "Article 62 Serious Incidents"],
        "owasp_llm": ["LLM01 Prompt Injection", "LLM03 Supply Chain", "LLM06 Excessive Agency",
                      "LLM10 Unbounded Consumption"],
        "mitre_atlas": ["AML.T0043", "AML.T0020", "AML.T0046"],
        "cis_controls": ["CIS 18.3", "CIS 17.9"],
    },
    # Phase G
    "skill_scanner": {
        "nist_ai_rmf": ["GOVERN 1.7", "MANAGE 2.2", "MEASURE 2.8"],
        "eu_ai_act": ["Article 28 Obligations Deployers", "Annex I GPAI"],
        "owasp_agentic": ["ASI04 Supply-Chain Vulnerabilities in AI Systems"],
        "owasp_llm": ["LLM03 Supply Chain"],
        "mitre_atlas": ["AML.T0010 ML Supply Chain Compromise", "AML.T0018"],
        "cis_controls": ["CIS 2.1", "CIS 16.1"],
        "nist_csf": ["ID.SC-3", "PR.DS-6"],
    },
    "adoption_velocity": {
        "nist_ai_rmf": ["MEASURE 2.8", "MANAGE 3.2"],
        "eu_ai_act": ["Article 28 Obligations Deployers"],
        "owasp_agentic": ["ASI04 Supply-Chain Vulnerabilities in AI Systems"],
        "owasp_llm": ["LLM03 Supply Chain"],
        "mitre_atlas": ["AML.T0010 ML Supply Chain Compromise"],
        "cis_controls": ["CIS 2.2", "CIS 16.6"],
        "nist_csf": ["DE.CM-8", "PR.DS-6"],
    },
    "sandbox_posture": {
        "nist_ai_rmf": ["MANAGE 2.4", "MEASURE 2.6"],
        "eu_ai_act": ["Article 9 Risk Management"],
        "owasp_agentic": ["ASI05 Unexpected Code Execution"],
        "mitre_atlas": ["AML.T0046", "AML.T0047"],
        "cis_controls": ["CIS 4.6", "CIS 4.8", "CIS 8.1"],
        "nist_csf": ["PR.IP-1", "DE.CM-7"],
    },
    "frontier_eval": {
        "nist_ai_rmf": ["GOVERN 4.1", "GOVERN 4.2", "MEASURE 2.5", "MEASURE 2.10"],
        "eu_ai_act": [
            "Article 51 Systemic Risk Classification",
            "Article 55 GPAI Systemic Risk Obligations",
            "Article 73 Serious Incident Reporting",
        ],
        "gpai_cop": ["S1", "S2", "S3", "S4", "S5", "S6", "S7"],
        "owasp_agentic": [
            "ASI04 Uncontrolled Autonomy",
            "ASI05 Unexpected Code Execution",
        ],
        "mitre_atlas": ["AML.T0043", "AML.T0020", "AML.T0046"],
        "cis_controls": ["CIS 18.1", "CIS 17.9"],
        "nist_csf": ["ID.RA-1", "DE.CM-3", "PR.IP-12"],
    },
    "human_oversight": {
        "nist_ai_rmf": [
            "GOVERN 1.1",
            "GOVERN 1.6",
            "GOVERN 2.2",
            "MANAGE 1.3",
            "MANAGE 2.4",
        ],
        "eu_ai_act": [
            "Article 14 Human Oversight",
            "Article 9 Risk Management",
        ],
        "owasp_agentic": [
            "ASI09 Human-Agent Trust Exploitation",
        ],
        "mitre_atlas": [
            "AML.T0054 LLM Jailbreak",
            "AML.T0051 LLM Prompt Injection",
        ],
        "nist_csf": ["DE.CM-3", "PR.AC-4", "RS.AN-1"],
        "cis_controls": ["CIS 6.2", "CIS 16.9"],
    },
}


def get_standard_profiles() -> dict[str, dict[str, str]]:
    """Return version and authoritative-source metadata for mapped standards."""
    return deepcopy(STANDARD_PROFILES)


def get_framework_profile(framework_name: str) -> dict[str, str]:
    for profile in STANDARD_PROFILES.values():
        if profile["name"] == framework_name:
            return deepcopy(profile)
    return {"name": framework_name, "version": "unknown", "source_url": ""}


def describe_framework_reference(
    framework_name: str, reference: str
) -> dict[str, str]:
    profile = get_framework_profile(framework_name)
    description = (
        REFERENCE_PROFILES.get(framework_name, {}).get(reference, {}).get("summary")
        or f"AIAF maps this item to {framework_name} reference {reference}."
    )
    return {
        "framework": framework_name,
        "framework_url": profile.get("source_url", ""),
        "label": reference,
        "summary": description,
        "url": profile.get("source_url", ""),
    }


def map_finding_to_controls(finding: dict[str, Any]) -> dict[str, Any]:
    """Map a finding to versioned standard controls and threat techniques."""
    finding_type = finding.get("type")
    mapping = FINDING_MAPPINGS.get(finding_type, {"nist_ai_rmf": ["MAP 5.1"]})
    controls = []
    for standard_key, standard_controls in mapping.items():
        profile = STANDARD_PROFILES.get(
            standard_key,
            {"name": standard_key, "version": "unknown", "source_url": ""},
        )
        controls.append(
            {
                "standard": profile["name"],
                "version": profile["version"],
                "source_url": profile["source_url"],
                "controls": list(standard_controls),
            }
        )
    return {"mapping_version": "1.0", "controls": controls}

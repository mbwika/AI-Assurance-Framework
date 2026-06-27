"""Runtime architecture catalog for the AI Assurance Framework.

The catalog is the authoritative, machine-readable description of every layer,
component, and route in the framework.  It is exposed at ``GET /v1/architecture``
so operators and automated tests can inspect the current layer/component contract.
"""
from copy import deepcopy
from typing import Any

ARCHITECTURE_LAYERS: list[dict[str, Any]] = [

    # ── 1. User Portal ──────────────────────────────────────────────────────────
    {
        "id": "user_portal",
        "name": "User Portal",
        "description": "Operator-facing model registry dashboard and assurance workflow surface.",
        "components": [
            {
                "name": "Model Registry Dashboard",
                "module": "aiaf.api.portal",
                "routes": ["GET /"],
            },
            {
                "name": "Architecture Overview",
                "module": "aiaf.api.portal",
                "routes": ["GET /", "GET /v1/architecture"],
            },
        ],
    },

    # ── 2. API Gateway Layer ────────────────────────────────────────────────────
    {
        "id": "api_gateway",
        "name": "API Gateway Layer",
        "description": (
            "FastAPI application exposing versioned REST endpoints for the registry, risk, "
            "governance, reporting, agentic, and monitoring domains.  Includes request-level "
            "middleware (correlation IDs, timing, structured logging) and Pydantic schemas."
        ),
        "components": [
            {
                "name": "FastAPI Application",
                "module": "aiaf.api.app",
                "routes": ["GET /health", "GET /v1/info", "GET /v1/architecture"],
            },
            {
                "name": "Correlation & Timing Middleware",
                "module": "aiaf.api.middleware",
                "routes": ["*"],
            },
            {
                "name": "Shared FastAPI Dependencies",
                "module": "aiaf.api.dependencies",
                "routes": ["*"],
            },
            {
                "name": "API Request/Response Schemas",
                "module": "aiaf.api.schemas",
                "routes": [],
            },
            {
                "name": "Model Registry Service",
                "module": "aiaf.api.models",
                "routes": [
                    "GET /models",
                    "POST /models/register",
                    "POST /models/verify",
                    "GET /models/{model_id}/provenance",
                    "GET /models/{model_id}/mbom",
                    "GET /models/{model_id}/vulnerabilities",
                    "POST /models/{model_id}/vulnerabilities/scan",
                    "POST /models/{model_id}/attestations",
                    "GET /models/{model_id}/attestations",
                    "POST /models/{model_id}/attestations/verify",
                    "GET /jobs/{job_id}",
                ],
            },
            {
                "name": "External Model Intake Service",
                "module": "aiaf.api.intake",
                "routes": [
                    "POST /v1/intake/triage",
                    "GET /v1/intake/{model_id}",
                ],
            },
            {
                "name": "Risk Analysis Service",
                "module": "aiaf.api.risk",
                "routes": ["POST /v1/risk/analyze"],
            },
            {
                "name": "Risk Register Service",
                "module": "aiaf.api.risk_register",
                "routes": [
                    "GET /v1/risks",
                    "GET /v1/risks/{risk_id}",
                    "PATCH /v1/risks/{risk_id}",
                ],
            },
            {
                "name": "Vulnerability Intelligence Service",
                "module": "aiaf.api.supply_chain",
                "routes": [
                    "POST /v1/supply-chain/advisories/import",
                    "GET /v1/supply-chain/advisories",
                    "POST /v1/supply-chain/advisories/feeds/import",
                    "GET /v1/supply-chain/advisories/feeds",
                    "GET /v1/supply-chain/advisories/feeds/status",
                    "GET /v1/supply-chain/advisories/feeds/{snapshot_id}",
                    "POST /v1/supply-chain/advisories/feeds/{snapshot_id}/verify",
                    "POST /v1/supply-chain/scan",
                ],
            },
            {
                "name": "Governance Evidence Service",
                "module": "aiaf.api.governance",
                "routes": [
                    "GET /v1/governance/controls",
                    "POST /v1/governance/evaluate",
                    "POST /v1/governance/evidence",
                    "GET /v1/governance/evidence",
                    "POST /v1/governance/evidence/{evidence_id}/review",
                ],
            },
            {
                "name": "Agent Runtime Authorization Service",
                "module": "aiaf.api.agentic",
                "routes": [
                    "GET /v1/agentic/policy-profiles",
                    "POST /v1/agentic/validate",
                    "POST /v1/agentic/sessions",
                    "GET /v1/agentic/sessions",
                    "POST /v1/agentic/sessions/{session_id}/authorize",
                    "PATCH /v1/agentic/sessions/{session_id}",
                    "GET /v1/agentic/invocations",
                ],
            },
            {
                "name": "Continuous Monitoring Service",
                "module": "aiaf.api.monitoring",
                "routes": [
                    "POST /v1/monitoring/schedules",
                    "GET /v1/monitoring/schedules",
                    "PATCH /v1/monitoring/schedules/{schedule_id}",
                    "POST /v1/monitoring/run-due",
                    "POST /v1/monitoring/schedules/{schedule_id}/run",
                    "GET /v1/monitoring/runs",
                ],
            },
            {
                "name": "Reporting & Export Service",
                "module": "aiaf.api.reporting",
                "routes": [
                    "GET /v1/reporting/summary",
                    "GET /v1/reporting/assurance-report",
                    "GET /v1/reporting/compliance",
                    "GET /v1/reporting/alerts",
                    "POST /v1/reporting/snapshots",
                    "GET /v1/reporting/snapshots",
                    "GET /v1/reporting/snapshots/{snapshot_id}",
                    "POST /v1/reporting/snapshots/{snapshot_id}/verify",
                ],
            },
        ],
    },

    # ── 3. Authentication & Authorization Layer ─────────────────────────────────
    {
        "id": "auth",
        "name": "Authentication & Authorization Layer",
        "description": (
            "API key guard for the current single-operator deployment.  Provides the "
            "Role-Based Access Control (RBAC) data model (Reader / Analyst / Operator / Admin) "
            "for multi-operator expansion.  OIDC/JWT integration is the next planned milestone."
        ),
        "components": [
            {
                "name": "API Key Authentication Guard",
                "module": "aiaf.auth.api_key",
                "routes": ["*"],
            },
            {
                "name": "Role-Based Access Control (RBAC)",
                "module": "aiaf.auth.rbac",
                "routes": [],
            },
        ],
    },

    # ── 4. Core Assurance Engines ───────────────────────────────────────────────
    {
        "id": "core_engines",
        "name": "Core Assurance Engines",
        "description": (
            "Orchestration layer that coordinates risk analysis, agentic assurance, "
            "governance evaluation, vulnerability intelligence, and reporting workflows."
        ),
        "components": [
            {
                "name": "Risk Engine",
                "module": "aiaf.core.risk_engine",
                "routes": ["POST /v1/risk/analyze"],
            },
            {
                "name": "Governance Engine",
                "module": "aiaf.core.governance_engine",
                "routes": ["GET /v1/governance/controls", "POST /v1/governance/evaluate"],
            },
            {
                "name": "Governance Evidence Engine",
                "module": "aiaf.core.evidence_engine",
                "routes": [
                    "POST /v1/governance/evidence",
                    "POST /v1/governance/evidence/{evidence_id}/review",
                ],
            },
            {
                "name": "Reporting Engine",
                "module": "aiaf.core.reporting_engine",
                "description": "Portfolio and artifact-scoped posture, compliance, evidence, trend, and alert reporting.",
                "routes": [
                    "GET /v1/reporting/summary",
                    "GET /v1/reporting/assurance-report",
                    "GET /v1/reporting/alerts",
                    "GET /v1/reporting/compliance",
                ],
            },
            {
                "name": "Assurance Report Snapshot Engine",
                "module": "aiaf.core.report_snapshot_engine",
                "description": "Append-only, SHA-256-verifiable report snapshots with optional HMAC or Ed25519 signatures for stronger non-repudiation workflows.",
                "routes": [
                    "POST /v1/reporting/snapshots",
                    "GET /v1/reporting/snapshots",
                    "POST /v1/reporting/snapshots/{snapshot_id}/verify",
                ],
            },
            {
                "name": "Continuous Monitoring Engine",
                "module": "aiaf.core.monitoring_engine",
                "routes": [
                    "POST /v1/monitoring/schedules",
                    "GET /v1/monitoring/schedules",
                    "PATCH /v1/monitoring/schedules/{schedule_id}",
                    "POST /v1/monitoring/run-due",
                    "POST /v1/monitoring/schedules/{schedule_id}/run",
                    "GET /v1/monitoring/runs",
                ],
            },
            {
                "name": "Agentic Assurance Engine",
                "module": "aiaf.core.agentic_engine",
                "routes": [
                    "GET /v1/agentic/policy-profiles",
                    "POST /v1/agentic/validate",
                ],
            },
            {
                "name": "Agent Runtime Authorization Guard",
                "module": "aiaf.core.agent_runtime_engine",
                "routes": [
                    "POST /v1/agentic/sessions",
                    "POST /v1/agentic/sessions/{session_id}/authorize",
                    "PATCH /v1/agentic/sessions/{session_id}",
                    "GET /v1/agentic/invocations",
                ],
            },
            {
                "name": "Adoption Recommendation Engine",
                "module": "aiaf.core.adoption_engine",
                "routes": ["POST /v1/intake/triage", "GET /v1/intake/{model_id}"],
            },
            {
                "name": "Organization Policy Engine",
                "module": "aiaf.core.org_policy_engine",
                "description": (
                    "Phase 4 approval-policy evaluator: use-case, data-sensitivity, and "
                    "deployment-exposure context determine the required evidence bar and "
                    "the approval scope attached to adoption verdicts."
                ),
                "routes": ["POST /v1/intake/triage"],
            },
            {
                "name": "Behavioral Probe Engine (Live Due-Diligence)",
                "module": "aiaf.core.probe_engine",
                "description": (
                    "10 behavioural probes (prompt injection, jailbreak, system-prompt extraction, "
                    "information disclosure) against live OpenAI-compatible endpoints. Results tagged "
                    "LOCALLY_OBSERVED; feed adoption verdict via serialization+probe inputs."
                ),
            },
            {
                "name": "Full Red-Team Evaluation Engine (garak / PyRIT)",
                "module": "aiaf.core.redteam_engine",
                "description": (
                    "Background red-team driver wrapping garak (120+ probes: prompt injection, "
                    "jailbreak, data leakage, harmful content, malware generation) and PyRIT. "
                    "Runs as async job; persists findings to model metadata; "
                    "adoption engine picks up results at next triage. "
                    "Results tagged LOCALLY_OBSERVED; CRITICAL/HIGH → DO_NOT_APPROVE cap."
                ),
            },
            {
                "name": "MCP Security Service",
                "module": "aiaf.api.mcp",
                "routes": [
                    "POST /v1/mcp/servers",
                    "GET  /v1/mcp/servers",
                    "GET  /v1/mcp/servers/{server_id}",
                    "POST /v1/mcp/servers/{server_id}/scan",
                    "GET  /v1/mcp/servers/{server_id}/history",
                ],
                "status": "planned",
            },
            {
                "name": "Interoperability Router",
                "module": "aiaf.api.interop",
                "routes": [
                    "POST /v1/interop/models/{model_id}/enrich/hf",
                    "GET  /v1/interop/models/{model_id}/bom/cyclonedx",
                    "POST /v1/interop/models/{model_id}/verify/sigstore",
                    "POST /v1/interop/models/{model_id}/redteam",
                    "GET  /v1/interop/models/{model_id}/redteam/{job_id}",
                    "GET  /v1/interop/models/{model_id}/redteam",
                ],
            },
            {
                "name": "Risk Register Engine",
                "module": "aiaf.core.risk_register_engine",
                "routes": ["GET /v1/risks", "PATCH /v1/risks/{risk_id}"],
            },
            {
                "name": "Vulnerability Intelligence Engine",
                "module": "aiaf.core.vulnerability_engine",
                "routes": [
                    "POST /v1/supply-chain/advisories/import",
                    "POST /v1/supply-chain/advisories/feeds/import",
                    "GET /v1/supply-chain/advisories/feeds/status",
                    "POST /v1/supply-chain/advisories/feeds/{snapshot_id}/verify",
                    "POST /v1/supply-chain/scan",
                ],
            },
        ],
    },

    # ── 5. Security Analysis Layer ──────────────────────────────────────────────
    {
        "id": "security_analysis",
        "name": "Security Analysis Layer",
        "description": (
            "Composable, independently testable analyzers for every major AI threat category: "
            "prompt attacks, model risk, agentic risk, supply-chain, data leakage, adversarial "
            "robustness, bias & fairness, hallucination, and trustworthiness."
        ),
        "components": [
            {"name": "Prompt Injection Detection", "module": "aiaf.analysis.prompt_injection",
             "owasp_ref": "LLM01"},
            {"name": "Jailbreak Analysis", "module": "aiaf.analysis.jailbreak",
             "owasp_ref": "LLM01"},
            {
                "name": "Model Risk Assessment",
                "module": "aiaf.analysis.model_risk_v2",
                "description": "Uncertainty-aware inherent/residual/confidence-bounded impact, exposure, capability, and safeguard-gap scoring on a 0-10 scale.",
                "owasp_ref": "LLM05",
            },
            {"name": "Agent Risk Assessment", "module": "aiaf.analysis.agent_risk_v2",
             "owasp_ref": "LLM08"},
            {
                "name": "Tool Invocation Risk Engine",
                "module": "aiaf.analysis.tool_invocation_risk",
                "description": "Per-tool risk tier scoring: capability classification, permissions, idempotency, and approval gates.",
                "owasp_ref": "LLM07",
                "mitre_atlas_ref": "AML.T0051",
            },
            {"name": "Workflow Security Validator", "module": "aiaf.analysis.workflow_graph"},
            {"name": "Workflow Graph Security Analyzer", "module": "aiaf.analysis.workflow_graph",
             "mitre_atlas_ref": "AML.T0051"},
            {"name": "Agent Policy Constraint Evaluator", "module": "aiaf.analysis.agent_policy_profiles"},
            {"name": "Runtime Tool Authorization", "module": "aiaf.core.agent_runtime_engine"},
            {"name": "Supply Chain Validation", "module": "aiaf.analysis.supply_chain",
             "owasp_ref": "LLM05"},
            {"name": "Dependency Risk Analysis", "module": "aiaf.analysis.supply_chain"},
            {"name": "Dependency Vulnerability Matching", "module": "aiaf.registry.advisories"},
            {"name": "Signed Advisory Feed Verification", "module": "aiaf.registry.advisory_feed"},
            {"name": "Data Leakage Detection", "module": "aiaf.analysis.data_leakage",
             "owasp_ref": "LLM06"},
            {"name": "Adversarial Testing", "module": "aiaf.analysis.adversarial_testing",
             "mitre_atlas_ref": "AML.T0043"},
            {
                "name": "Bias & Fairness Assessment",
                "module": "aiaf.analysis.bias_fairness",
                "description": "Domain-aware bias severity scoring, sensitive-attribute detection, fairness-metric coverage, and EU AI Act Article 10 alignment.",
                "mitre_atlas_ref": "AML.T0054",
                "nist_ai_rmf_ref": "MEASURE-2.5",
            },
            {
                "name": "Hallucination Risk Assessment",
                "module": "aiaf.analysis.hallucination_risk",
                "description": "Factual reliability risk scoring covering output grounding, RAG, factuality evaluation, and calibration.",
                "owasp_ref": "LLM09",
                "nist_ai_rmf_ref": "MANAGE-2.2",
            },
            {"name": "Trustworthiness Scoring", "module": "aiaf.analysis.trustworthiness"},
            {
                "name": "Risk Drift Analysis",
                "module": "aiaf.analysis.risk_drift",
                "description": "Robust, version-segmented temporal drift detection over persisted assurance-metric history, partitioned by (artifact_id, metric_name).",
                "nist_ai_rmf_ref": "MEASURE-2.6",
            },
        ],
    },

    # ── 6. Knowledge & Mapping Layer ────────────────────────────────────────────
    {
        "id": "knowledge_mapping",
        "name": "Knowledge & Mapping Layer",
        "description": (
            "Versioned mappings from AIAF findings and controls to seven recognized AI, "
            "security, and governance frameworks: OWASP, MITRE ATLAS, NIST AI RMF, "
            "NIST SSDF, CIS Controls, EU AI Act, and ISO/IEC 42001."
        ),
        "components": [
            {"name": "OWASP Top 10 for LLMs", "module": "aiaf.mapping.standards"},
            {"name": "MITRE ATLAS", "module": "aiaf.mapping.standards"},
            {"name": "NIST AI RMF", "module": "aiaf.mapping.standards"},
            {"name": "NIST SSDF", "module": "aiaf.mapping.standards"},
            {"name": "CIS Controls", "module": "aiaf.mapping.standards"},
            {"name": "AI Assurance Control Catalog", "module": "aiaf.mapping.control_catalog"},
            {
                "name": "EU AI Act (2024/1689) Mapping",
                "module": "aiaf.mapping.eu_ai_act",
                "description": "Risk classification and obligation mapping for EU AI Act Articles 9–15, 50, 72.",
            },
            {
                "name": "ISO/IEC 42001:2023 AIMS Mapping",
                "module": "aiaf.mapping.iso_42001",
                "description": "Clause-level mappings for ISO 42001 AI Management System certification evidence.",
            },
        ],
    },

    # ── 7. Model Registry Layer ─────────────────────────────────────────────────
    {
        "id": "model_registry",
        "name": "Model Registry Layer",
        "description": (
            "Provenance capture, integrity verification, AI Bill of Materials (AI-BOM) generation, "
            "signed attestations, dependency discovery, and vulnerability matching for registered models."
        ),
        "components": [
            {"name": "Model Record Store", "module": "aiaf.registry.models"},
            {"name": "Integrity Verification (SHA-256)", "module": "aiaf.registry.checksum"},
            {"name": "Provenance Engine", "module": "aiaf.registry.provenance_v2"},
            {"name": "Evidence Origin Taxonomy", "module": "aiaf.registry.evidence_origin"},
            {"name": "Source Tracker", "module": "aiaf.registry.tracker"},
            {"name": "AI Bill of Materials (AI-BOM)", "module": "aiaf.registry.mbom"},
            {"name": "Dependency Manifest Discovery", "module": "aiaf.registry.dependency_discovery"},
            {"name": "Vulnerability Advisory Catalog", "module": "aiaf.registry.advisories"},
            {"name": "Signed Advisory Feed Verifier", "module": "aiaf.registry.advisory_feed"},
            {"name": "Signed Provenance Attestations", "module": "aiaf.registry.attestation"},
            {
                "name": "Serialization Scanner (Artifact-Level)",
                "module": "aiaf.registry.serialization_scanner",
                "description": (
                    "Non-executing opcode scanner for pickle (plain + ZIP/PyTorch), safetensors, "
                    "and ONNX. Detects dangerous GLOBAL opcodes and malformed headers. "
                    "Runs at registration time; results tagged LOCALLY_OBSERVED."
                ),
            },
            {
                "name": "HuggingFace Model Card Parser",
                "module": "aiaf.registry.hf_model_card",
                "description": (
                    "Extracts license, pipeline_tag, language, base_model, model_type, "
                    "architectures, publisher from README.md + config.json. "
                    "All facts tagged PROVIDER_DECLARED."
                ),
            },
            {
                "name": "Sigstore / OpenSSF Model Signing Verifier",
                "module": "aiaf.registry.sigstore_verifier",
                "description": (
                    "Verifies Sigstore bundle signatures alongside model artifacts. "
                    "On success, adds sigstore_verification fact tagged INDEPENDENTLY_VERIFIED, "
                    "lifting the PILOT_ONLY verdict ceiling. Optional sigstore package dependency."
                ),
            },
            {
                "name": "CycloneDX 1.7 ML-BOM Export/Import",
                "module": "aiaf.registry.cyclonedx_bom",
                "description": (
                    "Export AIAF model records to CycloneDX 1.7 ML-BOM JSON (machine-learning-model "
                    "component type, modelCard block, AIAF properties). Import external BOMs with "
                    "evidence_origin_hints for downstream ledger tagging."
                ),
            },
            {
                "name": "Weight & Tensor Header Inspector",
                "module": "aiaf.registry.weight_inspector",
                "description": (
                    "Derives architecture facts from model artifact file headers without loading "
                    "tensor data into memory. Supports safetensors (JSON header: param count, "
                    "layer count, hidden size, vocab size, quantization dtype, architecture family) "
                    "and GGUF (KV metadata: architecture, embedding length, block count, context "
                    "length, file type / quantization). PyTorch pickle and ONNX: format-detected "
                    "only, deferred to serialization scanner. All derived facts tagged "
                    "LOCALLY_OBSERVED — AIAF produced them by inspecting the artifact bytes directly."
                ),
                "evidence_origin": "LOCALLY_OBSERVED",
            },
            {
                "name": "Lineage Graph Deriver",
                "module": "aiaf.registry.lineage_graph",
                "description": (
                    "Derives base-model ancestry chain from config.json (_name_or_path, base_model), "
                    "HF model card (base_model field), and merge-model indicators (TIES/SLERP/DARE "
                    "in name, tags, or mergekit config). Cross-checks declared architecture family "
                    "against weight-inspector-derived family (CONSISTENT / INCONSISTENT / UNVERIFIABLE). "
                    "Enumerates explicit decidability bounds for lineage depth beyond what is verifiable "
                    "from the artifact alone."
                ),
                "evidence_origin": "ARTIFACT_DERIVED / PROVIDER_DECLARED",
            },
            {
                "name": "Fact Reconciler",
                "module": "aiaf.registry.fact_reconciler",
                "description": (
                    "Cross-checks every PROVIDER_DECLARED/USER_ENTERED fact against any "
                    "LOCALLY_OBSERVED derivation of the same fact. Produces: "
                    "(1) contradictions (declared ≠ derived — potential metadata fraud or wrong artifact), "
                    "(2) confirmations (independently agreed facts), "
                    "(3) provenance_independence_ratio (fraction of decision-driving facts grounded "
                    "in LOCALLY_OBSERVED or INDEPENDENTLY_VERIFIED evidence), "
                    "(4) decidability_bounds — permanent, explicit enumeration of the six fact categories "
                    "that cannot be independently determined from artifact inspection + behavioral probing."
                ),
                "evidence_origin": "LOCALLY_OBSERVED (meta-evidence)",
            },
        ],
    },

    # ── 8. Agent Execution Security Layer ──────────────────────────────────────
    {
        "id": "agent_execution_security",
        "name": "Agent Execution Security Layer",
        "description": (
            "Continuous security assurance for AI agents operating at runtime: "
            "MCP/tool supply-chain scanning (injection patterns, rug-pull detection, SSRF surface), "
            "hash-chained tamper-evident agent action ledgers, "
            "runtime inference telemetry ingestion and guardrail integration, "
            "and agent behavioral baseline with drift-from-trace detection. "
            "Extends AIAF's pre-adoption evidence model into the full agent operating lifecycle."
        ),
        "components": [
            {
                "name": "MCP Tool Supply-Chain Scanner",
                "module": "aiaf.registry.mcp_scanner",
                "description": (
                    "Static inspection of MCP server tool descriptors (name, description, "
                    "inputSchema, annotations) for: "
                    "(1) prompt-injection / tool-poisoning patterns — instruction-override regex "
                    "across all text fields, CRITICAL→MEDIUM severity; "
                    "(2) SSRF-prone parameters — url/endpoint/host/webhook fields in inputSchema; "
                    "(3) rug-pull detection — SHA-256 pin of each tool descriptor at first scan, "
                    "re-diff on every subsequent scan; description or schema change → "
                    "RUG_PULL_DETECTED status + HIGH finding; "
                    "(4) capability-risk passthrough — routes tool definitions through "
                    "tool_invocation_risk.py for HIGH/CRITICAL tier flagging. "
                    "All findings tagged LOCALLY_OBSERVED; tool descriptor content is "
                    "PROVIDER_DECLARED. Rug-pull diff is LOCALLY_OBSERVED meta-evidence."
                ),
                "owasp_ref": "LLM07",
                "mitre_atlas_ref": "AML.T0051",
                "routes": [
                    "POST /v1/mcp/servers",
                    "GET  /v1/mcp/servers",
                    "GET  /v1/mcp/servers/{server_id}",
                    "POST /v1/mcp/servers/{server_id}/scan",
                    "GET  /v1/mcp/servers/{server_id}/history",
                ],
            },
            {
                "name": "Inline Guardrail Engine",
                "module": "aiaf.core.guardrail_engine",
                "description": (
                    "Two-stage advisory classifier for live agent traffic. "
                    "Input stage (pre-LLM): detects injection attempts, jailbreak patterns "
                    "(DAN, persona override, hypothetical framing), and PII in incoming content. "
                    "Output stage (post-LLM): detects system-prompt disclosure, injection-success "
                    "markers, and PII leakage in model responses (PII severity boosted one tier "
                    "in output vs. input). "
                    "Returns PASS / FLAG / BLOCK verdict with LOCALLY_OBSERVED findings. "
                    "Integrates with inference_telemetry: emits guardrail_block/guardrail_flag "
                    "events when session_id + store are provided. "
                    "AIAF is the evidence layer — enforcement is the caller's responsibility."
                ),
                "owasp_ref": "LLM01",
                "mitre_atlas_ref": "AML.T0051",
                "routes": [
                    "POST /v1/guardrail/check",
                    "POST /v1/guardrail/batch",
                ],
            },
            {
                "name": "Agent Action Ledger",
                "module": "aiaf.core.agent_action_ledger",
                "description": (
                    "Hash-chained, tamper-evident append-only log of every tool invocation "
                    "made by an agent session. Each entry records: session_id, tool_name, "
                    "input_hash (SHA-256 of sanitised arguments), decision (ALLOW/DENY/FLAG), "
                    "timestamp, and prev_entry_sha256 (chain link). "
                    "Chain verification replays the sequence and recomputes every entry_hash; "
                    "any modification, deletion, or insertion breaks the chain at that point. "
                    "Satisfies NIST AI RMF GOVERN-1.7 agentic-AI auditability and "
                    "EU AI Act Article 12 logging obligations for high-risk systems."
                ),
                "nist_ai_rmf_ref": "GOVERN-1.7",
                "eu_ai_act_ref": "Article 12",
                "routes": [
                    "POST /v1/ledger/sessions/{session_id}/entries",
                    "GET  /v1/ledger/sessions",
                    "GET  /v1/ledger/sessions/{session_id}",
                    "GET  /v1/ledger/sessions/{session_id}/entries",
                    "GET  /v1/ledger/sessions/{session_id}/verify",
                ],
            },
            {
                "name": "Runtime Inference Telemetry Sink",
                "module": "aiaf.core.inference_telemetry",
                "description": (
                    "Ingests live prompt/response/tool-call pairs from an AIAF proxy sidecar "
                    "or from third-party guardrail providers (Lakera, Bedrock Guardrails, "
                    "Azure Content Safety). Emits LOCALLY_OBSERVED evidence records into the "
                    "FactLedger for the running session. Privacy by design: only content_hash "
                    "(SHA-256) is stored, never raw content. Bounded storage: sessions retain "
                    "the last 1000 events; summary metrics (error_rate, latency, block_count) "
                    "are computed on each ingest. Session status: OK / PARTIAL_ERRORS / "
                    "DEGRADED / BLOCKED — feeds behavioral baseline and action ledger."
                ),
                "owasp_ref": "LLM01",
                "routes": [
                    "POST /v1/telemetry/traces",
                    "GET  /v1/telemetry/sessions",
                    "GET  /v1/telemetry/sessions/{session_id}",
                    "GET  /v1/telemetry/sessions/{session_id}/events",
                    "DELETE /v1/telemetry/sessions/{session_id}",
                ],
            },
            {
                "name": "Backdoor / Trojan Heuristic Analyser",
                "module": "aiaf.analysis.backdoor_heuristics",
                "description": (
                    "Seven metadata-level heuristics for estimating weight-tampering risk "
                    "without executing the model: (H1) fine-tuned from low-provenance source; "
                    "(H2) merge with unverified component; (H3) critically low provenance with "
                    "artifact present; (H4) parameter-count contradiction between declared and "
                    "derived; (H5) dtype anomaly inconsistent with any known quantisation scheme; "
                    "(H6) lineage unverifiable; (H7) low provenance with artifact. "
                    "All findings LOCALLY_OBSERVED at MEDIUM confidence. "
                    "Feeds adoption_engine: HIGH → DO_NOT_APPROVE; MEDIUM → PILOT_ONLY. "
                    "Tensor-level statistical detection (SVD rank, activation norm) is the "
                    "planned Phase 7 extension."
                ),
                "owasp_ref": "LLM03",
                "mitre_atlas_ref": "AML.T0018",
                "nist_ai_rmf_ref": "MEASURE-2.5",
            },
            {
                "name": "Agent Behavioral Baseline & Drift Detector",
                "module": "aiaf.analysis.agent_behavioral_baseline",
                "description": (
                    "Learns expected tool-call sequences and plan structures from the first N "
                    "sessions of an approved agent deployment. On subsequent sessions, flags "
                    "deviations: unexpected tool invocation ordering, new tool categories, "
                    "anomalous argument structure, or cascading multi-agent calls not present "
                    "in the baseline. Extends risk_drift.py from score-level to trace-level drift. "
                    "Memory-poisoning detection: flags sessions where agent plan steps reference "
                    "content inconsistent with the session's declared context."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.6",
                "status": "planned",
            },
        ],
    },

    # ── Phase C. Agent / MCP Security Layer ─────────────────────────────────────
    {
        "id": "agent_mcp_security",
        "name": "Agent/MCP Security Layer",
        "description": (
            "Full-lifecycle security assurance for agentic systems: "
            "agent registry (identity + capability declaration), "
            "permission graph analysis (multi-tool risk-path detection), "
            "runtime authorization policy engine (per-call ALLOW/DENY/CONDITIONAL), "
            "emergency containment controls (suspend, quarantine, per-tool block/unblock), "
            "and signed tool manifests (supply-chain attestation for tool capability sets). "
            "Complements the existing MCP scanner (injection/rug-pull) and guardrail engine "
            "(content classification) with structural and policy-level enforcement. "
            "All registry evidence: LOCALLY_OBSERVED. "
            "Verified tool manifests: INDEPENDENTLY_VERIFIED."
        ),
        "components": [
            {
                "name": "Agent Registry",
                "module": "aiaf.registry.agent_registry",
                "description": (
                    "Registry of deployed agents: identity, declared tool inventory, "
                    "trust level (VERIFIED > INTERNAL > EXTERNAL > USER > UNTRUSTED), "
                    "and explicit capability flags (network_egress, code_execution, "
                    "subagent_spawn, approval_bypass, file_read/write, data_read/write, "
                    "memory_read/write, tool_invocation). "
                    "Capability flags are the primary input to the permission graph analyser. "
                    "Agents must be registered and active for the authorization engine to ALLOW "
                    "tool calls. Registry state now supports containment-aware statuses "
                    "(active, suspended, quarantined, deregistered) plus per-tool block lists "
                    "for emergency runtime isolation."
                ),
                "nist_ai_rmf_ref": "GOVERN-1.7",
                "owasp_ref": "LLM06",
                "routes": [
                    "POST   /v1/agents",
                    "GET    /v1/agents",
                    "GET    /v1/agents/{agent_id}",
                    "DELETE /v1/agents/{agent_id}",
                    "POST   /v1/agents/{agent_id}/suspend",
                    "POST   /v1/agents/{agent_id}/quarantine",
                    "POST   /v1/agents/{agent_id}/resume",
                    "POST   /v1/agents/{agent_id}/tools/{tool_name}/block",
                    "POST   /v1/agents/{agent_id}/tools/{tool_name}/unblock",
                ],
            },
            {
                "name": "Permission Graph Analyser",
                "module": "aiaf.analysis.permission_graph",
                "description": (
                    "Structural risk analysis of an agent's permission set. "
                    "Reasons over combinations of capabilities, not just individual tool risk. "
                    "Eight heuristics: "
                    "(H1) exfiltration_path — read capability + network_egress without approval gate; "
                    "(H2) code_execution_risk — arbitrary code execution present; "
                    "(H3) subagent_spawn_risk — can spawn delegated sub-agents; "
                    "(H4) approval_bypass_risk — human-oversight gate removable; "
                    "(H5) write_without_gate — destructive writes without approval constraint; "
                    "(H6) over_permissioned — EXTERNAL/USER/UNTRUSTED agent with CRITICAL capabilities; "
                    "(H7) undeclared_tool_caps — tool_capabilities contains undeclared tools; "
                    "(H8) excessive_tool_count — declared_tools exceeds policy threshold. "
                    "Status hierarchy: CRITICAL_RISK > RISK_DETECTED > SUSPICIOUS > CLEAN."
                ),
                "owasp_ref": "LLM06",
                "mitre_atlas_ref": "AML.T0024",
                "nist_ai_rmf_ref": "GOVERN-1.7",
                "routes": [
                    "GET /v1/agents/{agent_id}/permissions",
                ],
            },
            {
                "name": "Tool Authorization Engine",
                "module": "aiaf.core.tool_authorization",
                "description": (
                    "Runtime ALLOW / DENY / CONDITIONAL policy engine for per-tool-call access "
                    "control. Policies are stored per-agent and define per-tool ``allow_if`` "
                    "conditions: data_sensitivity_max, user_consent_required, "
                    "max_calls_per_session, trust_level_min, allowed_context_tags. "
                    "Three-step evaluation: (1) agent registered and active, (2) tool in "
                    "declared_tools, (3) tool not emergency-blocked, (4) policy conditions met. "
                    "Suspended/quarantined agents and blocked tools are denied before policy "
                    "evaluation. Missing policy → DENY (safe default). CONDITIONAL verdict lists "
                    "unmet conditions for remediation. "
                    "Integrates with agent_action_ledger to complete the audit trail "
                    "ALLOW/DENY decision → tool invocation → ledger entry."
                ),
                "owasp_ref": "LLM06",
                "nist_ai_rmf_ref": "GOVERN-1.7",
                "eu_ai_act_ref": "Article 14",
                "routes": [
                    "POST /v1/agents/{agent_id}/policies",
                    "GET  /v1/agents/{agent_id}/policies",
                    "DELETE /v1/agents/{agent_id}/policies",
                    "POST /v1/agents/{agent_id}/authorize",
                ],
            },
            {
                "name": "Signed Tool Manifests",
                "module": "aiaf.registry.tool_manifest",
                "description": (
                    "HMAC-SHA256 signed declarations of a tool's capability set, input schema, "
                    "and authorised callers. Extends AIAF's supply-chain assurance model "
                    "(which already covers models via attestation_v2 and Sigstore) to cover "
                    "tools — the action primitives that make agentic systems powerful and dangerous. "
                    "Manifest statement fields: tool_name, version, description, schema_hash "
                    "(SHA-256 of canonical input schema), declared_capabilities, allowed_agents, "
                    "issuer, issued_at, expires_at. "
                    "Verification checks: signature_valid, algorithm_supported, "
                    "manifest_version_supported, manifest_id_matches, schema_hash_matches. "
                    "Verified manifests yield evidence_origin=INDEPENDENTLY_VERIFIED. "
                    "Agents can link a manifest_id via the agent registry to attest their "
                    "tool inventory matches a signed declaration."
                ),
                "owasp_ref": "LLM03",
                "nist_ai_rmf_ref": "GOVERN-1.2",
                "routes": [
                    "POST /v1/tools/manifests",
                    "GET  /v1/tools/manifests",
                    "GET  /v1/tools/manifests/{tool}/{version}",
                    "POST /v1/tools/manifests/{tool}/{version}/verify",
                ],
            },
        ],
    },

    # ── Phase B. RAG Security Layer ─────────────────────────────────────────────
    {
        "id": "rag_security",
        "name": "RAG Security Layer",
        "description": (
            "Security assurance for Retrieval-Augmented Generation pipelines: "
            "vector-store inventory with per-document trust labels, "
            "backend posture declarations (access-control mode, tenant isolation, "
            "index freshness SLA, embedding provenance, PII-screening status), "
            "indirect prompt injection detection in retrieved chunks, "
            "sensitive-data leakage detection (PII/credentials surfacing from the store), "
            "trust-mix violation detection (unverified docs in high-trust retrieval context), "
            "and pre-ingestion document scanning. "
            "All evidence is LOCALLY_OBSERVED. Raw document content is never persisted — "
            "only content_hash (SHA-256). "
            "Findings map to OWASP-LLM01 (indirect injection), OWASP-LLM02 (leakage), "
            "AML.T0051 (prompt injection), and NIST AI RMF GOVERN-1.7 / MANAGE-1.3."
        ),
        "components": [
            {
                "name": "RAG Vector-Store Inventory",
                "module": "aiaf.registry.rag_inventory",
                "description": (
                    "Registry of vector stores and their documents. "
                    "Each store has a backend type (pgvector, chroma, pinecone, …) and a "
                    "default trust label (VERIFIED > INTERNAL > EXTERNAL > USER_GENERATED > UNTRUSTED). "
                    "Documents are registered with per-document trust labels, source types, "
                    "content hashes, optional pre-ingestion scan results, and store-level "
                    "security posture metadata: access_control_mode, tenant_isolation, "
                    "last_indexed_at, freshness_sla_hours, embedding provenance, and "
                    "PII-screening status. "
                    "Trust label distribution is exposed in store assessment summaries so "
                    "operators can detect trust-label drift in large stores."
                ),
                "owasp_ref": "LLM03",
                "nist_ai_rmf_ref": "GOVERN-1.2",
                "eu_ai_act_ref": "Article 10",
                "routes": [
                    "POST /v1/rag/stores",
                    "GET  /v1/rag/stores",
                    "GET  /v1/rag/stores/{store_id}",
                    "POST /v1/rag/stores/{store_id}/documents",
                    "GET  /v1/rag/stores/{store_id}/documents",
                    "GET  /v1/rag/stores/{store_id}/assessment",
                ],
            },
            {
                "name": "RAG Security Analyser",
                "module": "aiaf.analysis.rag_security",
                "description": (
                    "Three detectors applied to retrieved chunks and documents: "
                    "(1) Indirect prompt injection — 14 RAG-specific patterns covering "
                    "direct AI addressing ('Note to AI:'), retrieval-triggered instructions "
                    "('upon retrieval'), context override ('this supersedes all instructions'), "
                    "HTML comment injection, zero-width character hiding, side-channel tool "
                    "calls, token injection artifacts, and exfiltration instructions. "
                    "CRITICAL/HIGH → INJECTION_DETECTED; MEDIUM → SUSPICIOUS. "
                    "(2) Sensitive-data leakage — PII patterns (email, phone, SSN, credit card) "
                    "and credential patterns (API keys, private keys, bearer tokens) in chunk "
                    "content → LEAKAGE_DETECTED. "
                    "(3) Trust-mix violation — detects UNTRUSTED/USER_GENERATED chunks mixed "
                    "with VERIFIED/INTERNAL, or chunks below the caller-specified minimum trust "
                    "level → TRUST_VIOLATION. "
                    "(4) Backend posture checks — flags OPEN/SHARED access control, missing "
                    "tenant isolation, stale indexes against a declared freshness SLA, unknown "
                    "or unverified embedding provenance, and disabled PII screening. "
                    "Pre-ingestion gate: scan_document_for_ingestion() gates weaponised documents "
                    "before they enter the vector store. "
                    "Status hierarchy: INJECTION_DETECTED > LEAKAGE_DETECTED > TRUST_VIOLATION > "
                    "SUSPICIOUS > CLEAN."
                ),
                "owasp_ref": "LLM01",
                "mitre_atlas_ref": "AML.T0051",
                "routes": [
                    "POST /v1/rag/scan/chunks",
                    "POST /v1/rag/scan/document",
                ],
            },
        ],
    },

    # ── Phase D. Continuous Security Operations Layer ───────────────────────────
    {
        "id": "continuous_security_ops",
        "name": "Continuous Security Operations Layer",
        "description": (
            "Ongoing operational security posture for deployed AI systems: "
            "schedule-driven red-team and anomaly-scan jobs, "
            "operational telemetry ingestion with threshold/statistical anomaly detection, "
            "incident lifecycle management (OPEN → INVESTIGATING → CONTAINED → RESOLVED), "
            "SIEM export (CEF/LEEF/JSON), and remediation tracking "
            "(PATCH, CONFIG_CHANGE, MODEL_SWAP, GUARDRAIL_ADD, POLICY_UPDATE, MANUAL_REVIEW). "
            "All evidence is LOCALLY_OBSERVED — the framework observes what it is told; "
            "it does not make independent claims about model ground-truth behaviour. "
            "Findings map to NIST AI RMF GOVERN-1.7 / MANAGE-1.3 / GOVERN-6.2, "
            "OWASP-LLM09 (Overreliance), and EU AI Act Article 9 (risk management)."
        ),
        "components": [
            {
                "name": "Ops Scheduler",
                "module": "aiaf.core.ops_scheduler",
                "description": (
                    "Schedule-metadata registry for recurring security jobs. "
                    "Job types: RED_TEAM, TELEMETRY_INGEST, ANOMALY_SCAN, SNAPSHOT, VULN_SCAN. "
                    "Schedule types: INTERVAL (fixed seconds), DAILY (HH:MM), "
                    "WEEKLY (day + HH:MM), ONE_SHOT. "
                    "Exposes due_schedules() for polling-based execution; "
                    "mark_job_run() advances next_run_at and appends to run_history. "
                    "The paired executor now turns schedules into concrete work instead of "
                    "leaving Phase D at metadata-only state."
                ),
                "nist_ai_rmf_ref": "GOVERN-1.7",
                "routes": [
                    "POST   /v1/ops/schedules",
                    "GET    /v1/ops/schedules",
                    "GET    /v1/ops/schedules/due",
                    "GET    /v1/ops/schedules/{id}",
                    "POST   /v1/ops/schedules/{id}/pause",
                    "POST   /v1/ops/schedules/{id}/resume",
                    "DELETE /v1/ops/schedules/{id}",
                    "POST   /v1/ops/schedules/{id}/mark-run",
                    "POST   /v1/ops/schedules/{id}/execute",
                    "POST   /v1/ops/schedules/execute-due",
                ],
            },
            {
                "name": "Ops Executor",
                "module": "aiaf.core.ops_executor",
                "description": (
                    "Synchronous execution layer for scheduled security work. "
                    "Executes due RED_TEAM, TELEMETRY_INGEST, ANOMALY_SCAN, SNAPSHOT, and "
                    "VULN_SCAN jobs; records outcomes back into scheduler history; and can "
                    "open incidents automatically from anomaly, vulnerability, and red-team "
                    "results."
                ),
                "nist_ai_rmf_ref": "MANAGE-1.3",
                "routes": [
                    "POST /v1/ops/schedules/{id}/execute",
                    "POST /v1/ops/schedules/execute-due",
                ],
            },
            {
                "name": "Telemetry Ingest + Anomaly Detector",
                "module": "aiaf.analysis.telemetry_ingest",
                "description": (
                    "Ingests operational telemetry events (LATENCY, ERROR_RATE, REFUSAL_RATE, "
                    "TOKEN_USAGE, INJECTION_ATTEMPT, POLICY_VIOLATION) into per-model rolling "
                    "buffers (capped at 5 000 events).  Window summaries (count, mean, min, max, "
                    "stddev, p95) and threshold/count-based anomaly detection over configurable "
                    "time windows.  Status: NORMAL < ELEVATED < ANOMALY_DETECTED < CRITICAL."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.6",
                "owasp_ref": "LLM09",
                "routes": [
                    "POST /v1/ops/telemetry/events",
                    "GET  /v1/ops/telemetry/{model_id}/{event_type}/summary",
                    "GET  /v1/ops/telemetry/{model_id}/{event_type}/events",
                    "GET  /v1/ops/telemetry/{model_id}/anomalies",
                ],
            },
            {
                "name": "Incident Manager",
                "module": "aiaf.core.incident_manager",
                "description": (
                    "Security incident lifecycle with a strict state machine: "
                    "OPEN → INVESTIGATING → CONTAINED → RESOLVED | ACCEPTED. "
                    "Severity levels: CRITICAL / HIGH / MEDIUM / LOW / INFO. "
                    "Immutable audit trail of state transitions and analyst notes. "
                    "snapshot_incident() produces a point-in-time read-only copy."
                ),
                "nist_ai_rmf_ref": "MANAGE-1.3",
                "eu_ai_act_ref": "Article 9",
                "routes": [
                    "POST /v1/ops/incidents",
                    "GET  /v1/ops/incidents",
                    "GET  /v1/ops/incidents/{id}",
                    "POST /v1/ops/incidents/{id}/state",
                    "POST /v1/ops/incidents/{id}/notes",
                    "GET  /v1/ops/incidents/{id}/snapshot",
                ],
            },
            {
                "name": "SIEM Exporter",
                "module": "aiaf.core.siem_export",
                "description": (
                    "Formats AIAF incidents for ingestion by external SIEM systems. "
                    "Formats: CEF (ArcSight Common Event Format v0), "
                    "LEEF (IBM QRadar Log Event Extended Format v2.0), JSON. "
                    "Severity mapped per format (CEF 0-10, LEEF string). "
                    "Evidence origin preserved in JSON output."
                ),
                "nist_ai_rmf_ref": "GOVERN-6.2",
                "routes": ["POST /v1/ops/siem/export"],
            },
            {
                "name": "Remediation Tracker",
                "module": "aiaf.core.remediation_tracker",
                "description": (
                    "Tracks remediation actions linked to incidents. "
                    "Action types: PATCH, CONFIG_CHANGE, MODEL_SWAP, GUARDRAIL_ADD, "
                    "POLICY_UPDATE, MANUAL_REVIEW. "
                    "Status lifecycle: PENDING → IN_PROGRESS → RESOLVED | ACCEPTED_RISK | WONT_FIX. "
                    "Terminal states record resolved_at timestamp and resolution_note."
                ),
                "nist_ai_rmf_ref": "MANAGE-1.3",
                "routes": [
                    "POST /v1/ops/remediations",
                    "GET  /v1/ops/remediations",
                    "GET  /v1/ops/remediations/{id}",
                    "POST /v1/ops/remediations/{id}/status",
                    "POST /v1/ops/remediations/{id}/link",
                ],
            },
        ],
    },

    # ── Phase E. Advanced Assurance Layer ──────────────────────────────────────
    {
        "id": "advanced_assurance",
        "name": "Advanced Assurance Layer",
        "description": (
            "Deep assurance capabilities beyond standard red-teaming: active poisoning and "
            "backdoor detection, model extraction vulnerability assessment, benchmark "
            "contamination detection, training-data assurance, adversary capability simulation, "
            "and formal risk confidence scoring with uncertainty-bounded evidence aggregation."
        ),
        "components": [
            {
                "name": "Poisoning & Backdoor Assessor",
                "module": "aiaf.analysis.poisoning_tests",
                "description": (
                    "Detects signs of data poisoning or backdoor implantation via 5 static "
                    "metadata heuristics (unknown training data, low provenance trust, "
                    "capability mismatch, opaque fine-tuning, unverified architecture) and "
                    "2 optional behavioural heuristics (output length anomaly, "
                    "consistency failure via Jaccard distance on control pairs). "
                    "Status: CLEAN → SUSPICIOUS → BACKDOOR_SUSPECTED → POISONING_SUSPECTED."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.5",
                "owasp_ref": "LLM03 Training Data Poisoning",
                "routes": ["POST /v1/advanced/poisoning/assess"],
            },
            {
                "name": "Model Extraction Risk Assessor",
                "module": "aiaf.analysis.extraction_tests",
                "description": (
                    "Assesses vulnerability to extraction and membership-inference attacks "
                    "via 5 static heuristics (no output length limit, verbatim generation "
                    "capability, code generation, no rate limiting, missing repetition penalty) "
                    "and 3 optional behavioural heuristics (verbatim reproduction detected "
                    "via type-token ratio, architecture disclosure via regex, supplied candidate "
                    "records echoed verbatim in outputs as a membership signal). "
                    "Risk: NEGLIGIBLE → LOW → MEDIUM → HIGH → CRITICAL."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.6",
                "owasp_ref": "LLM10 Model Theft",
                "routes": ["POST /v1/advanced/extraction/assess"],
            },
            {
                "name": "Training-Data Assurance",
                "module": "aiaf.analysis.training_data_assurance",
                "description": (
                    "Evidence-aware assessment of training-data lineage and governance. "
                    "Scores whether a model has declared training data, dataset lineage, "
                    "immutable source pinning, license/usage basis, privacy review, "
                    "contamination review, and signed provenance bindings. "
                    "Returns a 0-100 score plus LOW/MEDIUM/HIGH/CRITICAL assurance risk."
                ),
                "nist_ai_rmf_ref": "GOVERN-3.2",
                "routes": ["POST /v1/advanced/training-data/assess"],
            },
            {
                "name": "Benchmark Contamination Detector",
                "module": "aiaf.analysis.benchmark_contamination",
                "description": (
                    "Detects signs that evaluation benchmark test sets appeared in the model's "
                    "training data. Heuristics: z-score outlier (H1), temporal contamination — "
                    "training cutoff after benchmark release + high z (H2), within-model score "
                    "inconsistency (H3), claimed-vs-verified score gap ≥ 5pp (H4). "
                    "Status: CLEAN → SUSPICIOUS → CONTAMINATION_LIKELY → CONTAMINATION_CONFIRMED."
                ),
                "nist_ai_rmf_ref": "MEASURE-1.1",
                "routes": ["POST /v1/advanced/contamination/check"],
            },
            {
                "name": "Adversary Capability Simulator",
                "module": "aiaf.analysis.adversary_simulation",
                "description": (
                    "Models what a realistic threat actor can achieve against a deployed AI "
                    "system.  Five threat profiles (SCRIPT_KIDDIE, OPPORTUNIST, MOTIVATED_ATTACKER, "
                    "APT, INSIDER) × six attack vectors (PROMPT_INJECTION, JAILBREAK, "
                    "MODEL_EXTRACTION, MEMBERSHIP_INFERENCE, TRAINING_POISONING, SUPPLY_CHAIN_ATTACK). "
                    "Attack probability = sophistication × accessibility ± deployment-context "
                    "modifiers.  Maps to MITRE ATLAS and produces prioritised mitigations."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.7",
                "owasp_ref": "LLM Top-10 (multiple)",
                "routes": [
                    "POST /v1/advanced/adversary/simulate",
                    "GET  /v1/advanced/{model_id}/summary",
                ],
            },
            {
                "name": "Risk Confidence Scorer",
                "module": "aiaf.core.risk_confidence",
                "description": (
                    "Computes origin-weighted, uncertainty-bounded confidence intervals on "
                    "composite risk scores assembled from multiple evidence items.  Each item "
                    "has value (0–10), weight, origin (INDEPENDENTLY_VERIFIED → USER_ENTERED), "
                    "and per-item confidence.  Outputs point_estimate, CI [lower, upper], "
                    "uncertainty, evidence_quality_score, and uncertainty_class "
                    "(HIGH_CONFIDENCE / MODERATE / LOW / INSUFFICIENT_EVIDENCE)."
                ),
                "nist_ai_rmf_ref": "MEASURE-1.5",
                "routes": ["POST /v1/advanced/confidence/score"],
            },
        ],
    },

    # ── Feature Extensions: AI-Native Capabilities ─────────────────────────────
    {
        "id": "ai_threat_intelligence",
        "name": "AI-Native Threat Intelligence Engine",
        "description": (
            "Structured knowledge base of 20 AI-specific threat techniques drawn from "
            "OWASP LLM Top-10 2025 (LLM01–LLM10), MITRE ATLAS (7 techniques), and "
            "OWASP Agentic Security (3 techniques). Correlates techniques to models, "
            "agents, and tools in the registry by matching capability triggers. "
            "Operators can extend the built-in index with custom techniques. "
            "Provides an aggregate threat landscape view."
        ),
        "components": [
            {
                "name": "AI Threat Intel Engine",
                "module": "aiaf.registry.ai_threat_intel",
                "description": (
                    "Built-in index of 20 OWASP/MITRE/Agentic threat techniques. "
                    "Supports custom technique ingestion, per-asset correlation "
                    "(model/agent/tool), and aggregate landscape reporting."
                ),
                "nist_ai_rmf_ref": "GOVERN-1.1",
                "owasp_ref": "LLM01–LLM10",
                "mitre_atlas_ref": "AML.T0018–AML.T0046",
                "routes": [
                    "GET  /v1/threat-intel/techniques",
                    "GET  /v1/threat-intel/techniques/{id}",
                    "POST /v1/threat-intel/techniques",
                    "GET  /v1/threat-intel/landscape",
                    "POST /v1/threat-intel/correlate/model",
                    "POST /v1/threat-intel/correlate/agent",
                    "POST /v1/threat-intel/correlate/tool",
                ],
            },
        ],
    },
    {
        "id": "resource_abuse_monitoring",
        "name": "AI Resource Abuse & Cost-Risk Monitor",
        "description": (
            "Per-session resource consumption tracking and violation detection for "
            "denial-of-wallet attacks, runaway agent loops, recursive planning, "
            "excessive retries, and abnormal token spikes. Operators define budgets "
            "(token, tool call, iteration, planning depth, cost limits); AIAF raises "
            "structured violations when thresholds are breached."
        ),
        "components": [
            {
                "name": "Resource Monitor",
                "module": "aiaf.analysis.resource_monitor",
                "description": (
                    "Budget management and session state tracking. Detects: "
                    "DENIAL_OF_WALLET, RUNAWAY_AGENT_LOOP, RECURSIVE_PLANNING, "
                    "EXCESSIVE_RETRIES, ABNORMAL_SPEND. "
                    "Planning depth uses max-not-sum semantics."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.9",
                "owasp_ref": "LLM10 Unbounded Consumption",
                "routes": [
                    "POST /v1/resources/budgets",
                    "GET  /v1/resources/budgets/{id}",
                    "POST /v1/resources/budgets/{id}/usage",
                    "GET  /v1/resources/budgets/{id}/session",
                    "GET  /v1/resources/budgets/{id}/violations",
                    "GET  /v1/resources/sessions/at-risk",
                ],
            },
        ],
    },
    {
        "id": "identity_delegation",
        "name": "Model/Agent Identity & Delegation Registry",
        "description": (
            "First-class identity management for AI principals (models, agents, tools, "
            "datasets, humans, services). Supports principal registration with typed "
            "trust levels, scoped delegation grants, automatic expiry detection, "
            "revocation with audit reason, and full authority verification including "
            "recursive delegation chain walking with cycle detection."
        ),
        "components": [
            {
                "name": "Identity Registry",
                "module": "aiaf.registry.identity_registry",
                "description": (
                    "Principal CRUD with types: MODEL/AGENT/TOOL/DATASET/HUMAN/SERVICE. "
                    "Trust levels: UNTRUSTED/EXTERNAL/INTERNAL/PRIVILEGED. "
                    "Delegation: grant, revoke, auto-expire, verify_authority, "
                    "get_authority_chain. Scope syntax: action:resource / wildcards."
                ),
                "nist_ai_rmf_ref": "GOVERN-2.2",
                "owasp_ref": "AGENTIC-02 Agent Identity Spoofing",
                "routes": [
                    "POST  /v1/identity/principals",
                    "GET   /v1/identity/principals",
                    "GET   /v1/identity/principals/{id}",
                    "PATCH /v1/identity/principals/{id}",
                    "POST  /v1/identity/delegations",
                    "GET   /v1/identity/delegations/{id}",
                    "POST  /v1/identity/delegations/{id}/revoke",
                    "GET   /v1/identity/delegations",
                    "POST  /v1/identity/verify",
                    "GET   /v1/identity/principals/{id}/authority-chain",
                ],
            },
        ],
    },
    {
        "id": "system_redteam",
        "name": "System-Level AI Red Team Orchestrator",
        "description": (
            "Cross-layer security assessment of a full AI deployment across 7 layers: "
            "MODEL, APP_LOGIC, RETRIEVAL_RAG, TOOL_MCP, IDENTITY_DELEGATION, "
            "TELEMETRY_AUDIT, HUMAN_APPROVAL. Evaluates 5 cross-layer attack scenarios: "
            "PROMPT_INJECTION_CASCADE, SUPPLY_CHAIN_TOOL_ABUSE, "
            "RAG_POISONING_EXFILTRATION, IDENTITY_ESCALATION, DENIAL_OF_WALLET. "
            "Returns structured findings, attack paths, mitigations, and overall risk."
        ),
        "components": [
            {
                "name": "System Red Team Orchestrator",
                "module": "aiaf.core.system_redteam",
                "description": (
                    "Assesses each layer for security posture gaps based on system_config. "
                    "Generates applicable cross-layer attack paths with mitigations. "
                    "Computes overall risk (LOW/MEDIUM/HIGH/CRITICAL). "
                    "Enriches config from model/agent records in the store."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.10",
                "owasp_ref": "LLM Top-10 (all vectors)",
                "mitre_atlas_ref": "AML.T0043 Craft Adversarial Examples",
                "routes": [
                    "POST /v1/system-redteam/run",
                    "GET  /v1/system-redteam/layers",
                    "GET  /v1/system-redteam/scenarios",
                ],
            },
        ],
    },

    # ── Feature F1 — Agent Memory Integrity & Poisoning Detection ───────────────
    {
        "id": "memory_integrity",
        "name": "Agent Memory Integrity & Poisoning Detection",
        "description": (
            "Runtime assurance layer for AI agent memory stores. "
            "Tracks write provenance (LOCALLY_OBSERVED / USER_ENTERED / EXTERNAL_AGENT), "
            "scores anomalies using MINJA-inspired injection-signal detection, "
            "identifies time-bomb payloads and cross-agent contamination. "
            "Covers ASI06 Memory & Context Poisoning from OWASP Top-10 for Agentic Applications 2026."
        ),
        "components": [
            {
                "name": "Memory Integrity Analyzer",
                "module": "aiaf.analysis.memory_integrity",
                "description": (
                    "register_memory_store / write_memory / assess_memory_integrity / scan_for_poisoning. "
                    "Anomaly scoring via injection-signal pattern matching + origin trust amplification. "
                    "Statuses: CLEAN / SUSPICIOUS / COMPROMISED. "
                    "Attack vectors: DIRECT_WRITE, PROMPT_INJECTION, CROSS_AGENT_CONTAMINATION, "
                    "TIME_BOMB, OVERRIDE_ATTACK."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.6",
                "owasp_ref": "ASI06 Memory & Context Poisoning",
                "mitre_atlas_ref": "AML.T0020 Poison Training Data",
                "routes": [
                    "POST /v1/memory-integrity/stores",
                    "GET  /v1/memory-integrity/stores/{id}",
                    "POST /v1/memory-integrity/stores/{id}/entries",
                    "GET  /v1/memory-integrity/stores/{id}/entries",
                    "GET  /v1/memory-integrity/stores/{id}/assess",
                    "POST /v1/memory-integrity/stores/{id}/scan",
                ],
            },
        ],
    },

    # ── Feature F2 — Multi-Agent Topology & Cascade/Blast-Radius Analyzer ───────
    {
        "id": "agent_topology",
        "name": "Multi-Agent Topology & Cascade/Blast-Radius Analyzer",
        "description": (
            "Models an AI agent deployment as a directed communication graph and performs "
            "trust-boundary detection, cascade path enumeration, blast-radius estimation, "
            "single-point-of-cascade-failure (SPOCF) identification, and circuit-breaker "
            "coverage gap detection. "
            "Covers ASI07 Insecure Inter-Agent Communication and ASI08 Cascading Failures."
        ),
        "components": [
            {
                "name": "Agent Topology Analyzer",
                "module": "aiaf.analysis.agent_topology",
                "description": (
                    "register_topology / add_agent_node / add_communication_edge / analyze_topology. "
                    "BFS blast-radius computation per node. "
                    "Trust levels: UNTRUSTED < EXTERNAL < INTERNAL < PRIVILEGED. "
                    "Risk levels: LOW / MEDIUM / HIGH / CRITICAL."
                ),
                "nist_ai_rmf_ref": "MEASURE-2.5",
                "owasp_ref": "ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Agent Failures",
                "mitre_atlas_ref": "AML.T0043",
                "routes": [
                    "POST /v1/topology",
                    "GET  /v1/topology/{id}",
                    "POST /v1/topology/{id}/nodes",
                    "POST /v1/topology/{id}/edges",
                    "GET  /v1/topology/{id}/analyze",
                    "GET  /v1/topology/meta/schema",
                ],
            },
        ],
    },

    # ── Feature F3 — NHI Discovery & Lifecycle Governance ───────────────────────
    {
        "id": "nhi_registry",
        "name": "Non-Human Identity (NHI) Discovery & Lifecycle Governance Registry",
        "description": (
            "Tracks AI/automation machine identities with full lifecycle management "
            "(PENDING → ACTIVE → DORMANT → DEPROVISIONING → REVOKED). "
            "Provides credential hygiene scoring, stale/over-privileged identity detection, "
            "orphaned identity flagging, and organisation-wide hygiene reports. "
            "Addresses the 2026 NHI crisis (100:1–500:1 machine-to-human ratio, second-leading breach cause)."
        ),
        "components": [
            {
                "name": "NHI Lifecycle Registry",
                "module": "aiaf.registry.nhi_registry",
                "description": (
                    "register_nhi / update_nhi_state / update_nhi / assess_nhi_hygiene. "
                    "NHI types: MODEL_SERVING, AGENT_WORKER, TOOL_EXECUTOR, "
                    "PIPELINE_RUNNER, DATA_CONNECTOR, GATEWAY. "
                    "Hygiene verdicts: CLEAN / REVIEW_NEEDED / AT_RISK / CRITICAL. "
                    "Detects stale (>30d), over-privileged, orphaned, and rotation-needed identities."
                ),
                "nist_ai_rmf_ref": "GOVERN-1.6",
                "owasp_ref": "ASI03 Agent Identity & Privilege Abuse",
                "mitre_atlas_ref": "AML.T0046 Exploit Public-Facing Application",
                "routes": [
                    "POST  /v1/nhi",
                    "GET   /v1/nhi",
                    "GET   /v1/nhi/{id}",
                    "PATCH /v1/nhi/{id}",
                    "POST  /v1/nhi/{id}/state",
                    "GET   /v1/nhi/hygiene/report",
                ],
            },
        ],
    },

    # ── Feature F4 — Runtime Policy Enforcement Point (PEP) ─────────────────────
    {
        "id": "policy_enforcement",
        "name": "Runtime Policy Enforcement Point (PEP)",
        "description": (
            "Inline enforcement layer that intercepts requests from principals (agents, models, "
            "services) and evaluates them against configurable policies before they reach "
            "downstream AI components. "
            "Supports three modes: ENFORCE (hard block), AUDIT (log only), PASSTHROUGH (bypass). "
            "Verdicts: ALLOW / DENY / CONDITIONAL. Includes rate limiting and per-policy audit logs."
        ),
        "components": [
            {
                "name": "Policy Enforcement Engine",
                "module": "aiaf.core.policy_enforcement",
                "description": (
                    "create_pep_policy / enforce_request / get_enforcement_log. "
                    "Evaluates deny-lists (priority) then allow-lists with glob-style pattern matching. "
                    "CONDITIONAL verdict emits conditions the caller must satisfy. "
                    "Counters: request_count, deny_count per policy. "
                    "AUDIT mode allows all but records computed verdicts for analysis."
                ),
                "nist_ai_rmf_ref": "MANAGE-1.3",
                "owasp_ref": "ASI01 Agent Goal Hijack, ASI02 Tool Misuse",
                "mitre_atlas_ref": "AML.T0043",
                "routes": [
                    "POST   /v1/pep/policies",
                    "GET    /v1/pep/policies",
                    "GET    /v1/pep/policies/{id}",
                    "DELETE /v1/pep/policies/{id}",
                    "POST   /v1/pep/enforce",
                    "GET    /v1/pep/policies/{id}/log",
                    "GET    /v1/pep/modes",
                ],
            },
        ],
    },

    # ── Phase G — Skill/Plugin Supply-Chain Scanner ──────────────────────────────
    {
        "id": "skill_scanner",
        "name": "Agent-Skill & Extension Supply-Chain Scanner",
        "description": (
            "Scans agent skill/plugin manifests for supply-chain compromise: ClawHub-style covert "
            "permission requests, typosquatting, unsigned publishers, obfuscated entry points, "
            "covert network/code capabilities, and prompt-injection patterns in manifest text. "
            "Addresses the 2026 attack surface of 341+ malicious skills discovered in the wild."
        ),
        "components": [
            {
                "name": "Skill Manifest Scanner",
                "module": "aiaf.registry.skill_scanner",
                "description": "scan_skill_manifest / scan_skill_registry.",
                "owasp_ref": "ASI04 Supply-Chain Vulnerabilities in AI Systems",
                "routes": [
                    "POST /v1/skill-scanner/scan",
                    "POST /v1/skill-scanner/scan/registry",
                    "GET  /v1/skill-scanner/risk-categories",
                ],
            },
        ],
    },

    # ── Phase G — Adoption-Velocity Anomaly Detection ────────────────────────────
    {
        "id": "adoption_velocity",
        "name": "Adoption-Velocity Anomaly Detection",
        "description": (
            "Detects supply-chain attacks that exploit rapid adoption spikes — e.g. the 2026 "
            "trojan model masquerading as an OpenAI release that reached 244K downloads in 18 hours. "
            "Signals: VELOCITY_SPIKE (>5x baseline), COLD_START_SURGE (>=1K weighted events in 24h), "
            "DORMANCY_REACTIVATION, VELOCITY_CLIFF."
        ),
        "components": [
            {
                "name": "Adoption Velocity Monitor",
                "module": "aiaf.analysis.adoption_velocity",
                "description": (
                    "record_adoption_event / set_velocity_baseline / detect_velocity_anomaly / "
                    "list_at_risk_artifacts."
                ),
                "owasp_ref": "ASI04 Supply-Chain Vulnerabilities in AI Systems",
                "routes": [
                    "POST /v1/adoption-velocity/{artifact_id}/events",
                    "PUT  /v1/adoption-velocity/{artifact_id}/baseline",
                    "GET  /v1/adoption-velocity/{artifact_id}/profile",
                    "GET  /v1/adoption-velocity/{artifact_id}/anomalies",
                    "GET  /v1/adoption-velocity/at-risk",
                ],
            },
        ],
    },

    # ── Phase G — Sandbox Posture Assessment ─────────────────────────────────────
    {
        "id": "sandbox_posture",
        "name": "Code-Execution Sandbox Posture Assessment",
        "description": (
            "Research implementation (ASI05 Unexpected Code Execution, OWASP 2026). Assesses "
            "declared sandbox configuration against known escape vectors (CVE-2024-21626 runc, "
            "CVE-2024-1086 kernel, etc.) across isolation levels NONE→HARDWARE. Minimum recommended "
            "posture: CONTAINER + FILTERED egress + RESTRICTED privilege + timeout + memory cap."
        ),
        "components": [
            {
                "name": "Sandbox Posture Assessor",
                "module": "aiaf.analysis.sandbox_posture",
                "description": "assess_sandbox_posture / get_isolation_levels.",
                "owasp_ref": "ASI05 Unexpected Code Execution",
                "routes": [
                    "POST /v1/sandbox-posture/assess",
                    "GET  /v1/sandbox-posture/levels",
                ],
            },
        ],
    },

    # ── Phase G — Frontier / Dangerous-Capability Evaluation Harness ─────────────
    {
        "id": "frontier_eval",
        "name": "Frontier / Dangerous-Capability Evaluation Harness",
        "description": (
            "Maps assurance evidence to EU AI Act GPAI Code of Practice Safety & Security "
            "commitments S1-S7 (June 2026 final). Evaluates seven dangerous-capability categories: "
            "CYBER_OFFENSE, CBRN_UPLIFT, AUTONOMY_SELF_REPLICATION, DECEPTION, "
            "PERSUASION_MANIPULATION, CRITICAL_INFRASTRUCTURE, POWER_SEEKING. "
            "Systemic-risk classification at >10^25 training FLOPs (EU AI Act Article 51). "
            "Strong NIW framing: frontier-safety alignment for government/critical-infra adoption."
        ),
        "components": [
            {
                "name": "Frontier Capability Evaluator",
                "module": "aiaf.analysis.frontier_eval",
                "description": (
                    "assess_frontier_capabilities / map_to_gpai_commitments / get_capability_taxonomy."
                ),
                "eu_ai_act_ref": "Article 51 (systemic risk), Article 55 (obligations)",
                "gpai_ref": "Safety & Security commitments S1-S7",
                "routes": [
                    "POST /v1/frontier/assess",
                    "POST /v1/frontier/assess/gpai",
                    "GET  /v1/frontier/taxonomy",
                ],
            },
        ],
    },

    # ── Human-Agent Trust Exploitation Monitor (ASI09) ─────────────────────────
    {
        "id": "human_oversight",
        "name": "Human Oversight Monitor — ASI09 Human-Agent Trust Exploitation",
        "description": (
            "Detects five trust-exploitation attack patterns where an AI agent exploits the "
            "asymmetry in human-agent trust to suppress oversight, manufacture urgency/consent, "
            "inflate confidence, or fabricate authority: CONSENT_MISMATCH (tool scope exceeds "
            "described intent), OVERSIGHT_SUPPRESSION (discourages review), URGENCY_MANUFACTURE, "
            "CONFIDENCE_INFLATION, AUTHORITY_FABRICATION. Session-based; caller feeds agent "
            "output turns and tool calls via REST API. All signals are LOCALLY_OBSERVED."
        ),
        "components": [
            {
                "name": "Human Oversight Monitor",
                "module": "aiaf.analysis.human_oversight_monitor",
                "description": (
                    "create_oversight_session / record_agent_output / record_tool_call / "
                    "assess_session / close_session / list_at_risk_sessions."
                ),
                "owasp_ref": "ASI09 Human-Agent Trust Exploitation",
                "routes": [
                    "POST /v1/oversight/sessions",
                    "POST /v1/oversight/sessions/{id}/output",
                    "POST /v1/oversight/sessions/{id}/tool-call",
                    "GET  /v1/oversight/sessions/{id}/assess",
                    "POST /v1/oversight/sessions/{id}/close",
                    "GET  /v1/oversight/at-risk",
                ],
            },
        ],
    },

    # ── 9. Reporting & Export Layer ─────────────────────────────────────────────
    {
        "id": "reporting_export",
        "name": "Reporting & Export Layer",
        "description": (
            "Portfolio and artifact-scoped assurance reports, framework compliance matrices, "
            "continuous-monitoring alerts, and standards-interoperable export formats "
            "(SARIF 2.1.0 for security toolchains; OSCAL 1.1.2 for FedRAMP/FISMA compliance)."
        ),
        "components": [
            {"name": "Assurance Report Generator", "module": "aiaf.reporting.assurance_report"},
            {"name": "Compliance Evidence Matrix", "module": "aiaf.reporting.compliance"},
            {"name": "Continuous Monitoring Alert Aggregator", "module": "aiaf.reporting.monitoring"},
            {"name": "Report Builder", "module": "aiaf.reporting.report"},
            {
                "name": "SARIF 2.1.0 Exporter",
                "module": "aiaf.reporting.exporters.sarif",
                "description": "Exports AIAF findings as SARIF for GitHub Advanced Security and CI/CD integration.",
            },
            {
                "name": "OSCAL 1.1.2 SSP Exporter",
                "module": "aiaf.reporting.exporters.oscal",
                "description": "Exports governance evidence, control coverage, scope metadata, model inventory, and evidence resources as NIST OSCAL System Security Plans for FedRAMP/FISMA.",
            },
        ],
    },

    # ── 9. Data & Analytics Layer ───────────────────────────────────────────────
    {
        "id": "data_analytics",
        "name": "Data & Analytics Layer",
        "description": (
            "Dual-mode persistence (SQLite for development, PostgreSQL for production) with "
            "a local vector-store abstraction for semantic search.  Stores all assurance "
            "artifacts: findings, risks, evidence, sessions, schedules, audit logs, and metrics."
        ),
        "components": [
            {"name": "PostgreSQL Assurance Store", "module": "aiaf.data.postgres_store"},
            {"name": "SQLite Development Store", "module": "aiaf.data.store"},
            {"name": "Vector Database Abstraction", "module": "aiaf.data.vector_store"},
            {"name": "Security Findings", "module": "aiaf.data.store"},
            {"name": "Historical Risk Metrics", "module": "aiaf.data.store"},
            {"name": "Managed Risk Register", "module": "aiaf.data.store"},
            {"name": "Vulnerability Advisory Catalog Store", "module": "aiaf.data.store"},
            {"name": "Signed Advisory Feed Snapshots", "module": "aiaf.data.store"},
            {"name": "Control Evidence Repository", "module": "aiaf.data.store"},
            {"name": "Agent Runtime Sessions", "module": "aiaf.data.store"},
            {"name": "Tool Authorization Decisions", "module": "aiaf.data.store"},
            {"name": "Assessment Schedules", "module": "aiaf.data.store"},
            {"name": "Assessment Run History", "module": "aiaf.data.store"},
            {"name": "Audit Logs", "module": "aiaf.data.store"},
            {"name": "Immutable Assurance Report Snapshots", "module": "aiaf.data.store"},
            {"name": "Training Artifact Evidence", "module": "aiaf.data.store"},
            {"name": "Deployment Pipeline Evidence", "module": "aiaf.data.store"},
        ],
    },

    # ── 10. Observability & Telemetry Layer ─────────────────────────────────────
    {
        "id": "observability",
        "name": "Observability & Telemetry Layer",
        "description": (
            "Structured JSON logging, in-process metrics registry (Prometheus-compatible), "
            "and OpenTelemetry tracing stub for production deployment visibility."
        ),
        "components": [
            {
                "name": "Structured Logging",
                "module": "aiaf.observability.logging",
                "description": "JSON-formatted log output with level, logger name, timestamp, and correlation ID.",
            },
            {
                "name": "In-Process Metrics Registry",
                "module": "aiaf.observability.metrics",
                "description": "Counters and histograms for API request rates, analysis durations, and error counts.",
            },
            {
                "name": "OpenTelemetry Tracing",
                "module": "aiaf.observability.tracing",
                "description": "No-op tracer stub upgradeable to full OTel SDK via AIAF_TRACING_ENABLED.",
            },
        ],
    },

    # ── 11. Notification & Alerting Layer ───────────────────────────────────────
    {
        "id": "notifications",
        "name": "Notification & Alerting Layer",
        "description": (
            "Outbound alert delivery for critical findings, risk escalations, and monitoring "
            "events via HMAC-signed HTTP webhooks.  Slack integration planned."
        ),
        "components": [
            {
                "name": "Webhook Notifier",
                "module": "aiaf.notifications.webhook",
                "description": "HTTP POST delivery with HMAC-SHA256 payload signing and delivery status tracking.",
            },
        ],
    },

    # ── 12. Plugin & Extension Layer ────────────────────────────────────────────
    {
        "id": "plugins",
        "name": "Plugin & Extension Layer",
        "description": (
            "Discovery-based plugin architecture for third-party analyzer and compliance-mapping "
            "extensions.  Plugins are dropped into AIAF_PLUGIN_DIR and loaded at startup with "
            "no core code changes required."
        ),
        "components": [
            {
                "name": "Analyzer Plugin Base",
                "module": "aiaf.plugins.base",
                "description": "Abstract base class for custom security analyzer plugins.",
            },
            {
                "name": "Mapping Plugin Base",
                "module": "aiaf.plugins.base",
                "description": "Abstract base class for custom compliance framework mapping plugins.",
            },
            {
                "name": "Plugin Loader",
                "module": "aiaf.plugins.loader",
                "description": "Filesystem-based plugin discovery and registration at application startup.",
            },
        ],
    },

    # ── 13. Configuration Layer ──────────────────────────────────────────────────
    {
        "id": "configuration",
        "name": "Configuration Layer",
        "description": (
            "Single ``Settings`` class resolved from environment variables.  "
            "Covers API, persistence, signing keys, observability, notifications, "
            "plugin directory, and monitoring worker knobs."
        ),
        "components": [
            {
                "name": "Runtime Settings",
                "module": "aiaf.config",
                "description": "Environment-variable-driven configuration with typed defaults.",
            },
        ],
    },
]


def get_architecture_catalog() -> dict[str, Any]:
    """Return a serialisable architecture catalog for API and documentation use."""
    layers = deepcopy(ARCHITECTURE_LAYERS)
    return {
        "name": "AI Assurance Framework",
        "version": "0.5.3",
        "evidence_architecture": {
            "description": (
                "AIAF assembles the maximum independently-observable evidence from two layers, "
                "bounds what cannot be independently verified, and produces an auditable adoption "
                "verdict that is explicit about both."
            ),
            "layers": [
                {
                    "id": "artifact_evidence",
                    "name": "Artifact Evidence Layer (static)",
                    "evidence_origin": "LOCALLY_OBSERVED / ARTIFACT_DERIVED",
                    "components": [
                        "aiaf.registry.serialization_scanner — pickle/safetensors/ONNX opcode scan",
                        "aiaf.registry.weight_inspector — tensor header: param count, architecture, quantization",
                        "aiaf.registry.lineage_graph — base-model ancestry chain derivation",
                        "aiaf.registry.artifact_integrity_v2 — SHA-256 + chain-of-custody",
                        "aiaf.registry.hf_model_card — provider-declared metadata (PROVIDER_DECLARED)",
                        "aiaf.registry.sigstore_verifier — cryptographic signature (INDEPENDENTLY_VERIFIED)",
                    ],
                },
                {
                    "id": "live_behavioral",
                    "name": "Live Behavioral Layer (runtime)",
                    "evidence_origin": "LOCALLY_OBSERVED",
                    "components": [
                        "aiaf.core.probe_engine — 10 behavioral probes (prompt injection, jailbreak, leakage)",
                        "aiaf.core.redteam_engine — garak 120+ probes + PyRIT jailbreak campaign",
                    ],
                },
                {
                    "id": "agent_execution",
                    "name": "Agent Execution Layer (continuous)",
                    "evidence_origin": "LOCALLY_OBSERVED",
                    "components": [
                        "aiaf.registry.mcp_scanner — tool descriptor injection scan + rug-pull diff",
                        "aiaf.core.guardrail_engine — input/output advisory classifier (PASS/FLAG/BLOCK)",
                        "aiaf.core.agent_action_ledger — hash-chained tamper-evident tool-invocation log",
                        "aiaf.core.inference_telemetry — live I/O guardrail event ingestion",
                        "aiaf.analysis.backdoor_heuristics — 7 metadata-level trojan heuristics",
                        "aiaf.analysis.agent_behavioral_baseline — trace-level drift detection [planned]",
                    ],
                },
                {
                    "id": "rag_security",
                    "name": "RAG Security Layer (retrieval pipeline)",
                    "evidence_origin": "LOCALLY_OBSERVED",
                    "components": [
                        "aiaf.registry.rag_inventory — vector-store registration + per-document trust labels",
                        "aiaf.analysis.rag_security — indirect prompt injection + PII leakage + trust-mix violation scanner",
                    ],
                },
                {
                    "id": "agent_mcp_security",
                    "name": "Agent/MCP Security Layer",
                    "evidence_origin": "LOCALLY_OBSERVED / INDEPENDENTLY_VERIFIED",
                    "components": [
                        "aiaf.registry.agent_registry — agent identity + capability declaration + trust classification",
                        "aiaf.analysis.permission_graph — multi-tool risk path analysis (H1-H8 detectors)",
                        "aiaf.core.tool_authorization — runtime ALLOW/DENY/CONDITIONAL policy engine",
                        "aiaf.registry.tool_manifest — HMAC-signed tool capability attestation",
                    ],
                },
                {
                    "id": "reconciliation",
                    "name": "Reconciliation Layer",
                    "evidence_origin": "LOCALLY_OBSERVED (meta-evidence)",
                    "components": [
                        "aiaf.registry.fact_reconciler — declared-vs-derived cross-check, "
                        "provenance_independence_ratio, decidability bounds",
                    ],
                },
                {
                    "id": "adoption_decision",
                    "name": "Adoption Decision Layer",
                    "evidence_origin": "aggregated",
                    "components": [
                        "aiaf.core.adoption_engine v3.0 — worst-cap verdict, "
                        "evidence_gaps, decidability_bounds, provenance_independence_ratio",
                    ],
                },
            ],
            "decidability_ceiling": (
                "The following facts CANNOT be independently determined from artifact inspection "
                "plus behavioral probing: (1) training data composition, (2) alignment/RLHF procedure, "
                "(3) backdoor trigger absence, (4) publisher benchmark scores, "
                "(5) pre-release red-team scope and results, (6) legal compliance of training data. "
                "These are enumerated as 'decidability_bounds' in every adoption verdict."
            ),
        },
        "layers": layers,
        "layer_count": len(layers),
        "component_count": sum(len(layer["components"]) for layer in layers),
    }

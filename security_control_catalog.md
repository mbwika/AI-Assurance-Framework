# AI Assurance Framework Security Control Catalog

The security control catalog defines the evidence the framework expects when assessing AI systems. The authoritative executable version is implemented in `src/aiaf/mapping/control_catalog.py`; this document provides the human-readable catalog.

## Control Summary

| Control | Objective | Required Evidence | Standards Alignment |
| --- | --- | --- | --- |
| AIAF-GOV-001 Accountability and risk ownership | Support AI Governance | `owner`, `risk_owner` | NIST AI RMF GOVERN 2.1/2.3, CIS Controls |
| AIAF-RISK-001 Continuous risk monitoring | Establish Continuous AI Security Assurance | `monitoring_enabled`, `assessment_frequency` | NIST AI RMF GOVERN 1.5/MANAGE 2.2, OWASP LLM |
| AIAF-RISK-002 Adversarial validation evidence | Establish Continuous AI Security Assurance | `adversarial_tests` | NIST AI RMF MAP 5.1/MEASURE 2.7, MITRE ATLAS AML.T0043/AML.T0054 |
| AIAF-RISK-003 Finding lifecycle and remediation governance | Establish Continuous AI Security Assurance | `risk_owner`, `remediation_sla` | NIST AI RMF GOVERN 2.3/MANAGE 1.3/MANAGE 2.4, CIS Control 7 |
| AIAF-RISK-004 Model impact and exposure classification | Establish Continuous AI Security Assurance | `model_risk_profile` | NIST AI RMF MAP 1.1/MAP 3.5/MAP 5.1/MEASURE 2.5, NIST SSDF PO.1/RV.1 |
| AIAF-RISK-005 Bias and fairness evaluation evidence | Establish Continuous AI Security Assurance | any of `group_metrics`, `has_bias_evaluation`, `has_fairness_metrics`, `bias_evaluation_context` | NIST AI RMF GOVERN 1.1/MAP 5.1/MEASURE 2.5/2.6, EU AI Act Art. 9/10 |
| AIAF-RISK-006 Factual reliability evaluation evidence | Establish Continuous AI Security Assurance | any of `factuality_evidence`, `retrieval_evidence`, `has_factuality_evaluation`, `has_output_grounding` | OWASP LLM09, NIST AI RMF MAP 5.2/MEASURE 2.1/MANAGE 2.2 |
| AIAF-SC-001 Model source provenance | Strengthen AI Supply Chain Integrity | `source_url`, `publisher` | OWASP LLM05, NIST SSDF |
| AIAF-SC-002 Artifact integrity verification | Strengthen AI Supply Chain Integrity | `sha256` | NIST SSDF, CIS Controls |
| AIAF-SC-003 Model bill of materials coverage | Strengthen AI Supply Chain Integrity | `license`, `dependencies` | NIST SSDF, OWASP LLM05 |
| AIAF-SC-004 Training artifact lineage | Strengthen AI Supply Chain Integrity | `training_artifacts` | NIST AI RMF, NIST SSDF |
| AIAF-SC-005 Deployment pipeline traceability | Strengthen AI Supply Chain Integrity | `deployment_pipeline` | NIST SSDF, CIS Controls |
| AIAF-SC-006 Signed model provenance attestation | Strengthen AI Supply Chain Integrity | `provenance_attestations` | NIST AI RMF GOVERN 6.1/MAP 4.2, MITRE ATLAS AML.T0010/AML.T0018, NIST SSDF |
| AIAF-SC-007 Dependency vulnerability intelligence | Strengthen AI Supply Chain Integrity | `vulnerability_scan` | NIST AI RMF MAP 4.2/MEASURE 2.7/MANAGE 1.3, NIST SSDF RV.1, OWASP LLM05, CIS Control 7 |
| AIAF-SC-008 Authenticated vulnerability advisory intelligence | Strengthen AI Supply Chain Integrity | `advisory_feed_policy` | NIST AI RMF MAP 4.2/MEASURE 2.7/MANAGE 1.3, NIST SSDF RV.1, OWASP LLM05, CIS Control 7 |
| AIAF-AGT-001 Agent tool and permission inventory | Improve Agentic AI Security | `tools`, `permissions` | OWASP LLM06, CIS Controls |
| AIAF-AGT-002 Autonomy and human review constraints | Improve Agentic AI Security | `autonomy_level`, `human_review_required` | NIST AI RMF Govern/Manage, OWASP LLM06 |
| AIAF-AGT-003 Agent policy constraints | Improve Agentic AI Security | `agent_policy` or `agent_policy_profile` | NIST AI RMF Govern/Manage, OWASP LLM06, CIS Controls |
| AIAF-AGT-004 Agent workflow graph safety | Improve Agentic AI Security | `workflow_steps` | NIST AI RMF MAP 3.5/MEASURE 2.7/MANAGE 2.4, MITRE ATLAS AML.T0053/AML.T0081, OWASP LLM06 |
| AIAF-AGT-005 Runtime tool authorization enforcement | Improve Agentic AI Security | `runtime_tool_authorization` | NIST AI RMF MAP 3.5/MEASURE 2.7/MANAGE 2.4, MITRE ATLAS AML.T0053/AML.T0081, OWASP LLM06, CIS Control 6 |
| AIAF-AGT-006 Per-tool invocation risk evidence | Improve Agentic AI Security | any of `tool_invocations`, `workflow_steps` | NIST AI RMF MAP 3.5/MEASURE 2.7/MANAGE 2.4, MITRE ATLAS AML.T0053/AML.T0051, OWASP LLM06, CIS Control 6 |
| AIAF-GOV-002 Compliance scope and documentation | Support AI Governance | `compliance_scope`, `documentation_url` | NIST AI RMF Govern/Map, NIST SSDF |
| AIAF-GOV-003 Independent assurance evidence review | Support AI Governance | `evidence_review_policy`, `evidence_retention_period` | NIST AI RMF GOVERN 1.5/GOVERN 2.3/MANAGE 2.4, NIST SSDF PO.1, CIS Control 8 |
| AIAF-GOV-004 Artifact-scoped assurance traceability | Support AI Governance | `id`, `assurance_scope` | NIST AI RMF GOVERN 1.5/GOVERN 4.1/MAP 1.1, NIST SSDF PO.1, CIS Control 1 |
| AIAF-GOV-005 Immutable assurance report retention | Support AI Governance | `report_snapshot_policy` | NIST AI RMF GOVERN 1.5/GOVERN 4.1/MEASURE 4.2, NIST SSDF PO.1, CIS Control 8 |

## Evaluation Semantics

- `satisfied`: all required evidence fields are present and truthy. For controls that accept alternative evidence ("any of"), at least one of the listed fields must be present.
- `missing`: one or more required evidence fields are absent or false.
- `not_applicable`: a control is skipped when its applicability signals are absent. Agentic controls require agentic evidence such as `tools`, `permissions`, `autonomy_level`, `workflow_steps`, or `agentic`; the model-reliability controls (bias/fairness and factual reliability) require a model context such as `model_risk_profile` or `domain`.

## Governance Output

`POST /v1/governance/evaluate` evaluates the catalog and returns:

- `controls`: per-control status, provided evidence, missing evidence, mapped standards, and related threat tags.
- `gaps`: controls with missing evidence.
- `summary`: total controls and counts by status, objective, and domain. The domain breakdown makes analyzer-backed areas individually visible — for example `Model Reliability` rolls up the bias/fairness (AIAF-RISK-005) and factual-reliability (AIAF-RISK-006) controls, and `Agentic AI` includes the per-tool invocation control (AIAF-AGT-006).
- `status`: `PASS` when no applicable controls are missing, otherwise `NEEDS_REVIEW`.

`GET /v1/governance/controls` returns the executable catalog definitions for operators and tests.

`GET /v1/reporting/assurance-report` combines control evaluations, risk findings, historical metrics, model registry evidence, and standards mappings into an exportable assurance report.

`GET /v1/reporting/compliance` produces a per-framework evidence matrix for the declared compliance scope. It separates control satisfaction from mapped threat findings and reports coverage as evidence completeness, not certification.

Approved, unexpired records submitted through `POST /v1/governance/evidence` can satisfy only the exact control fields named by the evidence record. Pending, rejected, expired, self-reviewed, or incorrectly scoped evidence does not count toward control satisfaction.

## Control Intent

### AIAF-GOV-001 Accountability and risk ownership

Ensures each AI system has named ownership for operation, risk acceptance, escalation, and review.

### AIAF-RISK-001 Continuous risk monitoring

Requires evidence that the AI system is monitored and reassessed on a declared cadence.

### AIAF-RISK-002 Adversarial validation evidence

Requires adversarial tests, red-team probes, or abuse-case validation evidence so assurance is not based only on metadata.

### AIAF-RISK-003 Finding lifecycle and remediation governance

Requires an accountable risk owner and declared severity-specific remediation service levels. Detector indicators are deduplicated into managed risks with first/last seen timestamps, recurrence counts, ownership, SLA-derived due dates, disposition rationale, audit history, and automatic reopening with a fresh deadline when a resolved condition recurs.

### AIAF-RISK-004 Model impact and exposure classification

Requires a model risk profile covering impact level, deployment exposure, data classification, user access, capabilities, access controls, output validation, safety evaluations, and human oversight. The automated assessment emits versioned factors and recommendations on a bounded 0-10 scale. Severity-aware aggregation prevents a high or critical finding from being diluted by lower-severity results, and zero-risk assessments remain in historical metrics as affirmative evidence.

### AIAF-SC-001 Model source provenance

Requires source and publisher data so the framework can reason about model origin and trust.

### AIAF-SC-002 Artifact integrity verification

Requires a cryptographic digest to support verification before deployment.

### AIAF-SC-003 Model bill of materials coverage

Requires license and dependency evidence to support AI supply-chain review.

### AIAF-SC-004 Training artifact lineage

Requires training dataset or artifact evidence so provenance extends beyond the final model artifact.

### AIAF-SC-005 Deployment pipeline traceability

Requires deployment environment, artifact reference, and approval evidence for release traceability.

### AIAF-SC-006 Signed model provenance attestation

Requires a signed statement binding the registered model identity and artifact hash to its source metadata and AI-BOM hash. HMAC attestations provide organization-controlled integrity evidence and depend on secure shared-key management.

### AIAF-SC-007 Dependency vulnerability intelligence

Requires persisted evidence that exact dependency versions were evaluated against a maintained advisory catalog. OSV-style introduced, fixed, last-affected, and explicit version evidence is supported. Scan status distinguishes complete coverage, partial coverage caused by unresolved versions, unavailable advisory data, and known vulnerability matches.

### AIAF-SC-008 Authenticated vulnerability advisory intelligence

Requires a declared policy for authenticated advisory intelligence. Signed feed envelopes bind feed identity, monotonic sequence, generation and expiration times, source, key ID, and exact advisory content. Import rejects invalid signatures, expired feeds, sequence rollback, and same-sequence content collisions. Persisted snapshots make feed provenance and freshness visible in scans, reports, alerts, and audit evidence.

### AIAF-AGT-001 Agent tool and permission inventory

Requires explicit tool and permission records for systems that can act through tools.

### AIAF-AGT-002 Autonomy and human review constraints

Requires autonomy-level and review evidence for agentic systems.

### AIAF-AGT-003 Agent policy constraints

Requires reusable policy evidence for allowed tools, denied permissions, autonomy limits, approval requirements, external-call boundaries, and workflow limits. Named profiles can be constrained further by artifact-level policy but cannot weaken the profile baseline.

### AIAF-AGT-004 Agent workflow graph safety

Requires workflow steps and transitions so the framework can detect unreachable actions, missing termination paths, unbounded cycles, undeclared tools, tainted data flow into sensitive operations, and unapproved privilege escalation.

### AIAF-AGT-005 Runtime tool authorization enforcement

Requires evidence that each tool invocation passes through a runtime guard. The implemented guard binds calls to an immutable session policy and declared workflow step, checks tool and permission scope, requires validated external input and approval identifiers where configured, atomically enforces external-call budgets, supports idempotent request IDs, and persists every decision for reporting and managed-risk creation.

### AIAF-GOV-002 Compliance scope and documentation

Requires documentation and compliance scope evidence for auditability and reporting.

### AIAF-GOV-003 Independent assurance evidence review

Requires policy and retention evidence for an independent review process. Evidence submissions retain the external reference, SHA-256 digest, submitter, covered control fields, expiration, reviewer decision, and rationale as durable audit evidence.

### AIAF-GOV-004 Artifact-scoped assurance traceability

Requires a stable AI system identifier and explicit artifact assurance scope. Findings, historical metrics, governance evaluations, monitoring schedules and runs, managed risks, reviewed control evidence, agent sessions, and runtime tool decisions are filtered at the persistence boundary for system-specific reports. This prevents evidence from one system from satisfying controls or changing the apparent posture of another.

### AIAF-GOV-005 Immutable assurance report retention

Requires a defined report snapshot and retention policy. Snapshot creation stores canonical point-in-time report JSON, schema version, scope, creator, timestamp, and SHA-256 digest in an append-only repository. Optional HMAC-SHA256 signatures bind the snapshot envelope to a dedicated governance key. Verification recomputes the digest, validates scope and version consistency, checks signatures when present, and writes an audit event. A snapshot digest can be submitted as independently reviewed control evidence without treating the live report as immutable.

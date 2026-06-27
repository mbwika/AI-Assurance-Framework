# AI Assurance Framework Threat Model

## Scope

This threat model covers the current AI Assurance Framework architecture: the FastAPI gateway, user portal, risk engine, runtime agent authorization guard, continuous-monitoring worker, governance engine, reporting engine, security analyzers, model registry, signed advisory-feed verification, provenance and MBOM utilities, SQLite/Postgres persistence, and local vector-store abstraction.

The model is focused on assurance workflows for AI systems and model artifacts. It does not yet cover production multi-tenant hosting, cloud perimeter controls, or enterprise identity federation.

## Security Objectives

- Establish continuous AI security assurance by detecting, scoring, storing, and reporting AI security findings.
- Strengthen AI supply-chain integrity through provenance capture, checksum verification, source tracking, and MBOM generation.
- Improve agentic AI security by evaluating tools, permissions, autonomy level, reusable policy profiles, workflow topology, data flow, privilege transitions, human review expectations, and each runtime tool invocation.
- Support AI governance through evidence-driven controls, audit logs, and standards mappings.

## Assets

| Asset | Description | Primary Risk |
| --- | --- | --- |
| Model artifacts | Uploaded or downloaded model files and archives | Tampering, substitution, unknown provenance |
| Model registry metadata | Source, publisher, checksum, license, dependencies, training artifacts, deployment pipeline, risk, MBOM, provenance score | Integrity loss, stale records, false trust |
| Vulnerability advisory catalog | Imported OSV-style package ranges, severity, aliases, and references | Stale, forged, incomplete, or malicious advisory data |
| Advisory feed snapshots and signing key | Signed feed envelope, sequence, freshness window, source, digest, key ID, and HMAC key | Forgery, replay, rollback, stale intelligence, key disclosure |
| Provenance signing key and attestations | HMAC key, signed model identity, artifact digest, source and AI-BOM digest | Key disclosure, forged provenance, stale attestations |
| Risk findings | Prompt injection, jailbreak, model, agent, supply-chain, data leakage, adversarial testing findings | Incomplete detection, manipulation, loss of audit evidence |
| Model risk profiles and scores | Impact, domain, exposure, data classification, capabilities, safeguards, assessment version, and historical score | Under-classification, score manipulation, missing high-impact controls |
| Managed risk register | Finding lifecycle, owner, due date, acceptance, resolution, and recurrence evidence | Unauthorized disposition, hidden overdue risk, false closure |
| Governance evidence | Owner, risk owner, monitoring, compliance scope, documentation, control status | Missing accountability, weak compliance claims |
| Reviewed control evidence | External reference, digest, covered control fields, submitter, expiration, reviewer decision and rationale | Self-attestation, tampering, stale proof, false control satisfaction |
| Assurance report snapshots | Point-in-time report JSON, scope, schema version, digest, optional signature, creator, and timestamp | Report tampering, substitution, unverifiable historical claims, signing-key disclosure |
| Monitoring schedules and runs | Stored target snapshots, intervals, execution state, risk and governance results | Schedule tampering, duplicate execution, stale targets |
| Agent sessions and authorization decisions | Effective policy snapshots, workflow bindings, approval references, call budgets, and runtime decisions | Policy bypass, replay, privilege escalation, audit deletion |
| API key | Shared development API key for protected routes | Unauthorized registry or governance access |
| Data stores | SQLite development database and Postgres production target | Unauthorized read/write, data corruption |
| Vector records | Embedding records and metadata for future analytics | Sensitive metadata exposure, retrieval poisoning |

## Trust Boundaries

| Boundary | Entry Points | Notes |
| --- | --- | --- |
| External user to API | `/models/*`, `/v1/risk/analyze`, `/v1/risks/*`, `/v1/agentic/*`, `/v1/governance/*`, `/v1/reporting/*` | Protected routes use an API key in the current implementation. |
| External model source to registry | Hugging Face URLs, generic URLs, uploaded files | Downloaded artifacts must be treated as untrusted until hashed and recorded. |
| API to persistence | SQLite and Postgres store implementations | Persistence failures should be visible in production, not silently hidden. |
| Risk engine to analyzer modules | Prompt, model, agent, supply-chain, data leakage, adversarial analyzers | Analyzer output becomes governance and reporting evidence. |
| Advisory importer to model registry | Signature-verified package intelligence triggers dependency rescans and persists results in model metadata and AI-BOMs | Feed authentication, freshness, and monotonic sequence must be established before advisory data changes fleet risk posture. |
| Governance engine to control catalog | `aiaf.mapping.control_catalog` | Catalog definitions drive control status and compliance summaries. |
| Evidence submitter to independent reviewer | `/v1/governance/evidence/*` | Only approved, unexpired evidence can satisfy declared control fields; submitters cannot review their own records. |
| Monitoring worker to persistence and engines | `aiaf.cli monitor`, `/v1/monitoring/*` | Stored artifact snapshots are re-evaluated by risk and governance engines when due. |
| Agent executor to runtime authorization guard | `/v1/agentic/sessions/*`, `/v1/agentic/invocations` | Tool execution must occur only after an `ALLOW` decision bound to the same session and request ID. |

## Threats

| Threat ID | Threat | Impact | Current Mitigation | Remaining Gap |
| --- | --- | --- | --- | --- |
| AIAF-T01 | Prompt injection or jailbreak content bypasses weak heuristics | Unsafe system behavior may be underreported | Prompt injection and jailbreak analyzers flag common override language | Expand scanner corpus, scoring, and regression tests |
| AIAF-T02 | Unknown or compromised model source is registered | Untrusted model enters inventory | Source tracking, publisher field, provenance scoring, and signed source statements | Add model-card parsing and third-party identity verification |
| AIAF-T03 | Model artifact is substituted after approval | Deployed model differs from reviewed artifact | SHA-256 verification and signed attestations bind the model and AI-BOM digests | Add deployment-time enforcement and asymmetric signing |
| AIAF-T04 | Dependency, training lineage, or deployment exposure is missed | Supply-chain and legal risk remain hidden | AI-BOM includes declared and automatically discovered dependencies, authenticated OSV-style vulnerability matches, training artifacts, and deployment pipeline evidence | Add signed deployment attestations and broader package-ecosystem discovery |
| AIAF-T05 | Agent has excessive tool permissions | Agent can take unintended high-impact actions | Static analysis flags excessive agency; runtime authorization enforces declared tools, permissions, workflow steps, approvals, and call budgets | Add per-tool credential scoping and deny-by-default integration in each executor |
| AIAF-T06 | Sensitive data appears in prompts or findings | Privacy or credential exposure | Data leakage analyzer detects emails, API-key-like tokens, and SSNs | Add configurable detectors and redaction |
| AIAF-T07 | Governance evidence is incomplete or unverifiable | Compliance report overstates assurance | Control catalog evaluates required evidence fields and records gaps | Add evidence attachments and reviewer approvals |
| AIAF-T08 | API key is leaked or reused broadly | Unauthorized access to registry and reports | Header-based API key guard | Replace with RBAC/OIDC before multi-tenant use |
| AIAF-T09 | Audit or finding persistence fails silently | Assurance evidence is lost | SQLite and PostgreSQL stores persist findings, managed risks, audit logs, metrics, schedules, and run history | Raise explicit operational alerts when persistence fails |
| AIAF-T10 | Reporting presents stale or incomplete metrics | Risk posture is misleading | Reporting engine aggregates stored findings, audit logs, metrics, compliance evidence, and trends | Add configurable time windows and data-quality checks |
| AIAF-T11 | Monitoring schedules are disabled, delayed, or modified without authorization | Assurance coverage silently degrades | Monitoring routes require the configured API key and schedule changes are persisted | Add RBAC, change approvals, and schedule mutation audit events |
| AIAF-T12 | Multiple workers execute the same due schedule concurrently | Duplicate evidence and misleading run counts | A worker advances `next_run_at` before analysis and retains run IDs | Add database-backed leasing and worker identity for multi-replica deployment |
| AIAF-T13 | Provenance HMAC key is disclosed or shared too broadly | An attacker can forge organization-trusted attestations | Key is supplied only through `AIAF_ATTESTATION_KEY` and never returned by APIs | Use a managed secret store, key rotation, scoped key IDs, and asymmetric/KMS signing for external trust |
| AIAF-T14 | Agent workflow contains unsafe graph paths | Cycles, untrusted data flow, or privilege transitions lead to unintended tool actions | Workflow graph validation checks reachability, termination, iteration bounds, taint propagation, declared tools, and approval evidence | Enforce validated graphs and policy profiles at runtime |
| AIAF-T15 | Risk lifecycle is changed without accountable review | A real finding is falsely accepted or closed | Risk updates require API authentication, state-specific owner/rationale evidence, and durable audit events; recurring resolved findings reopen | Add RBAC, separation of duties, and approval workflows for acceptance and closure |
| AIAF-T16 | Vulnerability advisory data is stale or manipulated | Vulnerable dependencies appear clean or false positives distort priorities | Signed feed envelopes bind source, content, key ID, sequence, and expiration; import rejects bad signatures, stale feeds, rollback, and collisions; snapshots, trust state, scans, reports, and alerts are retained | Automate trusted feed synchronization and define organization-specific freshness SLAs |
| AIAF-T17 | Governance evidence is self-approved, stale, or substituted | Compliance reports falsely show controls as satisfied | Evidence is field-scoped, SHA-256-bound, immutable after submission, independently reviewed, expiration-aware, and fully audited | Bind reviewer identity to RBAC/OIDC roles and verify referenced evidence content during collection |
| AIAF-T18 | An agent bypasses or races the runtime authorization guard | Unauthorized tools execute, approval gates are skipped, or call budgets are exceeded | Sessions snapshot validated policy and workflows; decisions are idempotent and persisted; session state and external-call counters are enforced atomically | Integrate the guard directly into tool executors, verify approval references with a trusted identity system, and use scoped short-lived tool credentials |
| AIAF-T19 | Model impact or deployment exposure is not classified | High-impact or publicly exposed systems operate without proportionate safeguards | A versioned model risk profile and automated 0-10 assessment evaluate impact, domain, exposure, sensitive data, capabilities, access controls, output validation, safety testing, and human oversight; clean and risky scores are retained historically | Add organization-specific impact taxonomies, approval thresholds, and independent profile review |
| AIAF-T20 | Evidence from different AI systems is combined in one system report | A safe system appears risky, an unsafe system inherits unrelated control evidence, or compliance coverage is overstated | Findings, metrics, governance logs, schedules, runs, risks, reviewed evidence, registered models, agent sessions, and runtime decisions support storage-level artifact filtering; every report declares portfolio or artifact scope | Add tenant boundaries and database row-level security before multi-tenant deployment |
| AIAF-T21 | A historical assurance report is altered or cannot be reproduced | Audit and compliance claims no longer match the evidence available at decision time | Append-only snapshots retain canonical JSON with SHA-256 integrity, explicit scope and schema version, creator and timestamp; optional HMAC signatures bind the snapshot envelope and verification is audited | Move signing to asymmetric KMS-backed keys, enforce retention externally, and replicate snapshots to immutable object storage |
| AIAF-T22 | An advisory feed key is compromised, rotated incorrectly, or replayed across trust domains | Forged intelligence can suppress or invent dependency findings, while old evidence may become unverifiable | Feed ID, key ID, sequence, generation and expiration times, source, and exact advisories are HMAC-bound; sequence state is durable and persisted snapshot metadata is consistency-checked | Move to asymmetric/KMS-backed signatures, bind feed identities to configured issuers, retain rotation history, and make import plus snapshot persistence transactional |
| AIAF-T23 | A model produces biased or discriminatory outcomes in a consequential domain | Protected groups suffer disparate impact and legal, ethical, and reputational harm | The bias & fairness analyzer evaluates protected-attribute use, group-outcome disparities with confidence bounds, counterfactual instability, and oversight quality; control AIAF-RISK-005 requires bias/fairness evaluation evidence for model artifacts | Add organization-specific harm thresholds, deployment stop-gates, and independent fairness review |
| AIAF-T24 | A model emits ungrounded or factually unreliable output that drives a decision | Hallucinated claims cause downstream harm, especially in automated or high-stakes flows | The hallucination-risk analyzer evaluates grounding, factuality evidence (Wilson-bounded), retrieval provenance and freshness, calibration, and review quality; control AIAF-RISK-006 requires factual-reliability evidence | Require claim-level source verification and abstention thresholds before consequential automated use |

## Risk Treatment Priorities

1. Expand deterministic analyzer corpora, evaluate detection quality, and add organization-specific model impact taxonomies.
2. Automate authenticated advisory-feed synchronization and move feed, provenance, and report signing to asymmetric KMS-backed verification.
3. Integrate runtime authorization directly into tool executors with trusted approval verification and scoped credentials.
4. Make governance reports evidence-backed, versioned, and exportable.
5. Prepare production controls for authentication, tenancy, deployment, and observability.

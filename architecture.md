### TECHNICAL ARCHITECTURE — AI Assurance Framework v0.2.0

┌─────────────────────────────────────────────────────────────────────┐
│                     AI Assurance Framework                          │
│          Continuous Assurance for AI Systems at Scale               │
└─────────────────────────────────────────────────────────────────────┘

## Overview

The AI Assurance Framework (AIAF) is a layered, modular platform for
continuous AI security assurance, governance, and compliance.  The
architecture is designed to:

- Scale horizontally (stateless API + worker + PostgreSQL/vector-DB backend)
- Extend without core changes (plugin architecture for analyzers and mappings)
- Integrate into existing pipelines (SARIF, OSCAL, REST API, webhooks)
- Support multi-standard compliance (OWASP, MITRE ATLAS, NIST AI RMF,
  NIST SSDF, CIS Controls, EU AI Act, ISO/IEC 42001)

---

## Package Layout

```
src/aiaf/
├── config.py                       Configuration — centralized env-var settings
├── cli.py                          CLI — run / monitor entry points
├── architecture.py                 Architecture catalog (machine-readable)
│
├── api/                            API Gateway Layer
│   ├── app.py                      FastAPI application factory
│   ├── dependencies.py             Shared FastAPI dependencies (auth, db)
│   ├── middleware.py               Correlation ID, timing, structured logging
│   ├── schemas/                    Pydantic request/response schemas
│   │   ├── registry.py
│   │   └── risk.py
│   ├── agentic.py                  Agent runtime routes
│   ├── architecture.py             Architecture introspection route
│   ├── governance.py               Governance evidence routes
│   ├── intake.py                   [NEW] External model intake / adoption-triage routes
│   ├── models.py                   Model registry routes
│   ├── monitoring.py               Continuous monitoring routes
│   ├── portal.py                   User portal dashboard
│   ├── reporting.py                Reporting & export routes
│   ├── risk.py                     Risk analysis routes
│   ├── risk_register.py            Risk register lifecycle routes
│   └── supply_chain.py             Vulnerability intelligence routes
│
├── auth/                           Authentication & Authorization Layer
│   ├── api_key.py                  X-API-Key header guard
│   └── rbac.py                     Role / Permission model (Reader/Analyst/Operator/Admin)
│
├── core/                           Core Assurance Engines
│   ├── adoption_engine.py          [NEW] Origin-weighted graded adoption verdict
│   ├── agentic_engine.py           Static agent policy & workflow validation
│   ├── agent_runtime_engine.py     Runtime tool authorization guard
│   ├── evidence_engine.py          Governance evidence lifecycle
│   ├── governance_engine.py        Control catalog evaluation
│   ├── monitoring_engine.py        Continuous assessment scheduling & execution
│   ├── reporting_engine.py         Portfolio & artifact-scoped reporting
│   ├── report_snapshot_engine.py   Append-only, SHA-256-signed snapshots
│   ├── risk_engine.py              Multi-analyzer risk orchestration
│   ├── risk_register_engine.py     Risk lifecycle management
│   └── vulnerability_engine.py     Advisory import, scan, feed verification
│
├── registry/                       Model Registry Layer
│   ├── advisories.py               OSV-style vulnerability advisory catalog
│   ├── advisory_feed.py            Signed advisory feed verification
│   ├── advisory_matcher_v2.py      [v2] Bounded exact-version OSV range matcher
│   ├── attestation.py              HMAC-signed provenance attestations
│   ├── checksum.py                 SHA-256 integrity verification
│   ├── dependency_discovery.py     Bounded dependency manifest discovery
│   ├── evidence_origin.py          [NEW] Evidence-origin taxonomy & fact ledger
│   ├── mbom.py                     AI Bill of Materials (AI-BOM) generation
│   ├── models.py                   Model record data model
│   ├── mbom_v2.py                  [v2] Deterministic self-digesting AI-BOM
│   ├── dependency_discovery_v2.py  [v2] Bounded manifest discovery + resolution state
│   ├── artifact_integrity_v2.py    [v2] Race-aware artifact integrity measurement
│   ├── attestation.py              Provenance attestation (v1, dual-read verify)
│   ├── attestation_v2.py           [v2] Strict-envelope provenance attestation + detached verification
│   ├── advisory_feed_v2.py         [v2] Hash-chained signed advisory-feed envelope
│   ├── provenance_v2.py            Evidence-derived provenance trust scorer (v2)
│   └── tracker.py                  Source & publisher tracking
│
├── analysis/                       Security Analysis Layer
│   ├── adversarial_testing.py      Adversarial robustness testing (v2)
│   ├── agent_policy_profiles.py    Reusable agent policy profiles
│   ├── agent_risk_v2.py            Authority/blast-radius/delegation scorer (v2)
│   ├── bias_fairness.py            [NEW] Bias & fairness risk assessment
│   ├── data_leakage.py             Sensitive data leakage detection (v2)
│   ├── hallucination_risk.py       [NEW] Hallucination & factual reliability risk
│   ├── jailbreak.py                Jailbreak pattern analysis (v2)
│   ├── model_risk_v2.py            Uncertainty-aware inherent/residual risk (v2)
│   ├── prompt_injection.py         Prompt injection detection (v2)
│   ├── risk_drift.py               [v2] Robust temporal drift over metric history
│   ├── supply_chain.py             Supply chain risk analysis (v2)
│   ├── tool_invocation_risk.py     [NEW] Per-tool invocation risk engine
│   ├── trustworthiness.py          Trustworthiness composite scoring (v2)
│   └── workflow_graph.py           Agentic workflow graph security validation (v2)
│
├── mapping/                        Knowledge & Mapping Layer
│   ├── control_catalog.py          Executable AI assurance control catalog
│   ├── eu_ai_act.py                [NEW] EU AI Act (2024/1689) mappings
│   ├── iso_42001.py                [NEW] ISO/IEC 42001:2023 AIMS mappings
│   └── standards.py                OWASP / MITRE ATLAS / NIST AI RMF / SSDF / CIS
│
├── data/                           Data & Analytics Layer
│   ├── store.py                    SQLite development store
│   ├── postgres_store.py           PostgreSQL production store
│   └── vector_store.py             Local vector-store abstraction
│
├── reporting/                      Reporting & Export Layer
│   ├── assurance_report.py         Assurance report aggregation
│   ├── compliance.py               Framework compliance evidence matrix
│   ├── monitoring.py               Continuous monitoring alert helpers
│   ├── report.py                   Report builder
│   └── exporters/                  [NEW] Standards-interoperable exporters
│       ├── sarif.py                SARIF 2.1.0 for GitHub / CI/CD
│       └── oscal.py                OSCAL 1.1.2 SSP for FedRAMP/FISMA
│
├── observability/                  [NEW] Observability & Telemetry Layer
│   ├── logging.py                  Structured JSON logging
│   ├── metrics.py                  In-process metrics registry (Prometheus-compatible)
│   └── tracing.py                  OpenTelemetry tracing (stub / OTel SDK)
│
├── notifications/                  [NEW] Notification & Alerting Layer
│   └── webhook.py                  HMAC-signed HTTP webhook notifier
│
└── plugins/                        [NEW] Plugin & Extension Layer
    ├── base.py                     AnalyzerPlugin / MappingPlugin base classes
    └── loader.py                   Filesystem-based plugin discovery & registration

deploy/
├── docker/
│   ├── Dockerfile                  Multi-stage production container
│   └── docker-compose.yml          API + worker + PostgreSQL stack
└── k8s/
    ├── deployment.yaml             API Deployment + monitoring worker Deployment
    └── service.yaml                ClusterIP Service + Secret template

pyproject.toml                      Modern Python packaging & tooling config
```

Foundation documents at repository root:

- `threat_model.md`: Threat model for the FastAPI gateway, registry, analyzers,
  governance, reporting, and data-store architecture (22 enumerated threats).
- `security_control_catalog.md`: Human-readable companion to the executable
  control catalog in `src/aiaf/mapping/control_catalog.py`.
- `DOCUMENTATION.md`: Model Registry Security module technical deep-dive.

---

## Runtime Architecture Catalog

The catalog is machine-readable and self-describing.  Every layer, component,
and API route is registered so operators and tests can verify the deployed
contract:

- `GET /v1/architecture` — returns framework name, version, layer count,
  component count, and the full layer/component/route map.
- Implemented in `src/aiaf/architecture.py` and registered through the
  FastAPI gateway in `src/aiaf/api/architecture.py`.

---

## Architecture Diagram

```
                         ┌────────────────────┐
                         │    User Portal     │
                         └────────┬───────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        API Gateway Layer                            │
│                    FastAPI  ·  Middleware  ·  Schemas               │
└───────────┬────────────────┬─────────────────┬───────────────────┬─┘
            │                │                 │                   │
            ▼                ▼                 ▼                   ▼
  ┌─────────────────┐ ┌──────────────┐ ┌─────────────┐ ┌──────────────────┐
  │ Authentication  │ │    Core      │ │  Reporting  │ │  Notifications   │
  │    & RBAC       │ │  Assurance   │ │  & Export   │ │  & Alerting      │
  │     Layer       │ │  Engines     │ │   Layer     │ │     Layer        │
  └─────────────────┘ └──────┬───────┘ └──────┬──────┘ └──────────────────┘
                             │                │
                             ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Security Analysis Layer                        │
├─────────────────────────────────────────────────────────────────────┤
│  Prompt Injection Detection          Jailbreak Analysis             │
│  Model Risk Assessment               Agent Risk Assessment          │
│    Impact · Exposure · Capabilities · Safeguard Gaps                │
│  Tool Invocation Risk Engine  [NEW]  Workflow Security Validator    │
│  Workflow Graph Security Analyzer    Agent Policy Constraint Eval.  │
│  Runtime Tool Authorization          Supply Chain Validation        │
│  Dependency Risk Analysis            Dependency Vulnerability Match │
│  Signed Advisory Feed Verification   Data Leakage Detection         │
│  Adversarial Testing                 Trustworthiness Scoring        │
│  Bias & Fairness Assessment   [NEW]  Hallucination Risk  [NEW]      │
└─────────────────────────────────────────────────────────────────────┘
                                  │
            ┌─────────────────────┼────────────────────┐
            ▼                     ▼                    ▼
┌────────────────────┐ ┌───────────────────┐ ┌────────────────────────┐
│  Knowledge &       │ │  Model Registry   │ │  Plugin & Extension    │
│  Mapping Layer     │ │  Layer            │ │  Layer           [NEW] │
├────────────────────┤ ├───────────────────┤ ├────────────────────────┤
│ OWASP Top 10 LLMs  │ │ Model Records     │ │ Analyzer Plugins       │
│ MITRE ATLAS        │ │ AI-BOM Generation │ │ Mapping Plugins        │
│ NIST AI RMF        │ │ Provenance Engine │ │ Plugin Loader          │
│ NIST SSDF          │ │ Integrity Verify  │ │                        │
│ CIS Controls       │ │ Dep. Discovery    │ │                        │
│ AI Assurance Cat.  │ │ Advisory Catalog  │ │                        │
│ EU AI Act   [NEW]  │ │ Signed Attest.    │ │                        │
│ ISO 42001   [NEW]  │ │ Feed Verification │ │                        │
└────────────────────┘ └───────────────────┘ └────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Data & Analytics Layer                        │
├─────────────────────────────────────────────────────────────────────┤
│ PostgreSQL (production)          SQLite (development)               │
│ Vector Database Abstraction      Training Artifact Evidence         │
│ Deployment Pipeline Evidence     Dependency Manifest Discovery      │
│ Signed Provenance Attestations   Audit Logs                         │
│ Security Findings                Historical Risk Metrics            │
│ Managed Risk Register            Vulnerability Advisory Catalog     │
│ Signed Advisory Feed Snapshots   Control Evidence Repository        │
│ Agent Runtime Sessions           Tool Authorization Decisions       │
│ Assessment Schedules             Assessment Run History             │
│ Compliance Report Export         Immutable Assurance Report Snapshots│
│ Continuous Monitoring Alerts                                        │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Observability & Telemetry Layer   [NEW]           │
├─────────────────────────────────────────────────────────────────────┤
│ Structured JSON Logging          In-Process Metrics Registry        │
│ OpenTelemetry Tracing Stub       Prometheus-Compatible Counters     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer Descriptions

### 1 · User Portal
Operator-facing Jinja/HTML dashboard served from `GET /`.  Surfaces the model
registry, recent assessments, and links to governance and reporting workflows.

### 2 · API Gateway Layer
FastAPI application registering all domain routers.  `CorrelationMiddleware`
injects `X-Correlation-ID` headers, measures request duration, and emits
structured log events for every request.  Shared `dependencies.py` exposes
`RequireApiKey` for route-level protection.  `schemas/` holds Pydantic models
for request validation and OpenAPI documentation.

### 3 · Authentication & Authorization Layer
`api_key.py` implements the `X-API-Key` header guard.  When `AIAF_API_KEY` is
unset all routes are open (development mode); setting the variable enforces the
key on every protected route.  `rbac.py` defines the four RBAC roles and their
permission sets for the forthcoming OIDC/JWT integration path.

### 4 · Core Assurance Engines
Orchestration modules that coordinate analyzer invocations, persist evidence,
and expose the results through the API.  Each engine is independently testable
and maps to one or more API route handlers.

### 5 · Security Analysis Layer
Nineteen composable, independently importable analyzers covering every major
AI threat category.  Three new analyzers added in v0.2.0:

| Module | Threat Category | Framework Refs |
|---|---|---|
| `tool_invocation_risk.py` | Agentic tool abuse | OWASP LLM06, MITRE AML.T0053/T0051 |
| `bias_fairness.py` | Discriminatory model behaviour | NIST MEASURE-2.5, EU AI Act Art. 10 |
| `hallucination_risk.py` | Factual unreliability | OWASP LLM09, NIST MANAGE-2.2 |

#### v2 uncertainty-aware scoring

Every analyzer and the two registry scorers carry an explicit
`*_SCORING_VERSION = "2.0"`.  The v2 model- and agent-risk scorers
(`model_risk_v2.py`, `agent_risk_v2.py`) are uncertainty-aware: they separate
**inherent**, **residual**, and **confidence-bounded** risk, expose
`score_gates`, and report `risk_score` as the conservative upper confidence
bound.  Because a nonzero score no longer implies a reportable issue, the
orchestrator emits a finding only at **MEDIUM severity or higher** (agent risk
also requires `applicable`); below that the assessment is retained as a trend
metric.  Persisted metrics carry the scoring version, inherent/residual scores,
confidence, and gates.

The registry advisory matcher (`advisory_matcher_v2.py`) performs bounded
exact-version OSV range matching and reports two additional clean-scan
statuses — `NO_KNOWN_VULNERABILITIES` and `NO_APPLICABLE_DEPENDENCIES` — along
with coverage, diagnostics, and indeterminate-evaluation evidence.  The runtime
(not the pure matcher) stamps `generated_at` and supplies the advisory-feed
authentication state.

Provenance is scored by `provenance_v2.py` along the
**register → attest → verify → rescore** sequence: registration produces a
conservative evidence-derived score; creating an attestation then verifies it
and rescores against the verifier output passed through
`assessment_context.trusted_evidence`.  The verified result enriches the
provenance assessment detail, while the top-level (MBOM-signed) score remains
stable so the attestation it commits to stays valid.

### 6 · Knowledge & Mapping Layer
Versioned control mappings to seven frameworks.  Two new mappings added in
v0.2.0:

- **EU AI Act (2024/1689)**: Risk classification (Unacceptable / High-Risk /
  Limited-Risk), Article 9–15 obligation mapping, prohibited use-case
  detection, and AIAF-to-Article obligation lookup.
- **ISO/IEC 42001:2023**: Clause 4–10 and selected Annex A mappings linking
  AIAF continuous assurance evidence to AIMS certification requirements.

### 7 · Model Registry Layer
Handles model ingestion from Hugging Face URLs, generic URLs, and uploaded
files.  Computes SHA-256 checksums, builds AI-BOMs with discovered
dependencies, generates provenance scores, issues signed attestations, and
matches registered dependencies against the local OSV-style vulnerability
advisory catalog.

### 8 · Reporting & Export Layer
Generates portfolio and artifact-scoped assurance reports (JSON and Markdown),
compliance evidence matrices, and prioritized alert feeds.  New in v0.2.0:

- **SARIF 2.1.0 exporter**: Transforms AIAF findings into SARIF for direct
  upload to GitHub Advanced Security, Azure DevOps, and IDE extensions.
- **OSCAL 1.1.2 SSP exporter**: Transforms governance evidence into NIST OSCAL
  System Security Plans for FedRAMP, FISMA, and DoD compliance workflows.

### 9 · Data & Analytics Layer
Dual-store persistence: SQLite for local development and testing; PostgreSQL
for production.  All tables are schema-consistent across both backends.
A local vector-store abstraction enables future semantic search over findings
and evidence without a mandatory external dependency.

Reporting endpoints accept an optional `artifact_id`; the scope is enforced in
both SQLite and PostgreSQL queries for findings, metrics, governance audit
events, monitoring schedules and runs, managed risks, reviewed evidence, agent
sessions, and tool decisions.  Reports include an explicit `PORTFOLIO` or
`ARTIFACT` scope declaration.

### 10 · Observability & Telemetry Layer  [NEW]
`configure_logging()` sets up JSON-structured log output consumed by any log
aggregation pipeline (Loki, CloudWatch, Datadog).  The in-process
`MetricsRegistry` accumulates counters and histograms; when `prometheus_client`
is installed the same values are scraped at a `/metrics` endpoint.  The OTel
tracing stub accepts the SDK when `AIAF_TRACING_ENABLED=true`.

### 11 · Notification & Alerting Layer  [NEW]
`WebhookNotifier` delivers signed event payloads to any HTTP endpoint.
HMAC-SHA256 signatures (`X-AIAF-Signature`) let receivers verify payload
origin.  `notify_critical_finding()` provides a safe call-site that no-ops
when no notifier is configured.

### 12 · Plugin & Extension Layer  [NEW]
Drop `.py` files in `AIAF_PLUGIN_DIR` at startup.  The `PluginLoader`
discovers and instantiates any class that subclasses `AnalyzerPlugin` or
`MappingPlugin`.  New threat categories and compliance frameworks can be
integrated without modifying core framework code.

### 13 · Configuration Layer  [NEW]
`Settings` in `aiaf/config.py` is the single source of truth for all
environment variables.  All other modules import from `settings` rather than
calling `os.getenv` inline, making configuration auditable and testable.

---

## API Versioning

All assurance endpoints are prefixed `/v1/`.  The `GET /v1/architecture`
endpoint returns the current layer/component/route catalog so clients can
adapt programmatically to framework version changes.  The `GET /v1/info`
endpoint returns the framework version string.

---

## Deployment Architecture

```
              ┌──────────────┐
              │   Client /   │
              │  CI/CD pipe  │
              └──────┬───────┘
                     │ HTTPS
                     ▼
              ┌──────────────┐
              │  AIAF API    │  ← scales horizontally (2+ replicas)
              │  (FastAPI)   │
              └──────┬───────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
  ┌───────────────┐    ┌────────────────┐
  │  PostgreSQL   │    │  AIAF Worker   │
  │  (primary DB) │    │ (cron monitor) │
  └───────────────┘    └────────────────┘
```

Docker Compose stack (single-node):
```
deploy/docker/docker-compose.yml  → api + worker + postgres
```

Kubernetes manifests (production):
```
deploy/k8s/deployment.yaml        → 2-replica API + 1 worker Deployment
deploy/k8s/service.yaml           → ClusterIP Service + Secret template
```

---

## Standards Alignment

| Framework | Coverage |
|---|---|
| OWASP Top 10 for LLMs 2025 | LLM01–LLM10 findings, mappings, and control evidence |
| MITRE ATLAS | Technique-level mappings (AML.T0043, T0051, T0054, …) |
| NIST AI RMF 1.0 | GOVERN, MAP, MEASURE, MANAGE function subcategories |
| NIST SSDF | Practice-level development security mappings |
| CIS Controls v8 | Control ID mappings in the assurance control catalog |
| EU AI Act (2024/1689) | Risk classification, Article obligation mapping, prohibited use-case detection |
| ISO/IEC 42001:2023 | Clauses 4–10 + Annex A evidence mappings for AIMS certification |

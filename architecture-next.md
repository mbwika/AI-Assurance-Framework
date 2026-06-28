# AIAF — Next Capabilities Architecture (Phases H–J)

Architecture for the next 10 capabilities, grounded in the current v0.2.0
codebase. Each design **extends an existing module** wherever one exists, and
follows the established house conventions so the additions are indistinguishable
from the current code.

## House conventions (must be followed by every new module)

Confirmed from the current source — all new code adheres to these:

| Concern | Convention |
|---|---|
| Layering | `analysis/` = pure deterministic functions, **no I/O**; `registry/` = inventory/BOM/provenance (uses store); `core/` = stateful engines/workflows (uses store); `api/` = FastAPI routers; `mapping/` = standards tables; `reporting/` = report/export builders |
| Persistence | Generic `store.save_model/get_model/list_models` with `"prefix:id"` namespace keys for new record types; dedicated tables only when query patterns demand it (`findings`, `risks`, `control_evidence`, `metrics`, `agent_sessions`, `tool_invocations`) |
| Versioning | Module-level `<NAME>_VERSION = "1.0"` constant emitted in every output |
| Errors | One `<Name>Error(ValueError)` per module; API maps it to `HTTPException(422)` |
| Enums | Module-level string constants + a `frozenset` of valid values |
| Time | `_utc_now()` → ISO-8601 with `Z` suffix |
| Integrity | SHA-256 over canonical JSON (`sort_keys=True, separators=(",",":")`); bounded inputs via `_MAX_*`; credential redaction on URLs |
| Evidence | Tag every output with `evidence_origin` ∈ {`provider_declared`, `locally_observed`, `independently_verified`} (`registry/evidence_origin.py`, trust weights 0.45 / 0.85 / 1.0) |
| API | `APIRouter(prefix="/v1/...", tags=[...])`, `Depends(get_api_key)`, `Depends(get_store)`, Pydantic request bodies; register in `api/app.py` and `architecture.py` catalog |
| Tests | One `tests/test_<module>.py` per module; deterministic, no network |

---

## Phase H — BOM & Threat-Intel Foundation

### Capability 1 — AI-BOM / Agent-BOM formalization

**Extends:** `registry/mbom_v2.py` (already emits an "AIAF AI-BOM" v2.0 with
model/dependencies/training/deployment/provenance/vulnerability components) and
`registry/cyclonedx_bom.py` (`export_bom` / `import_bom`).

The current AI-BOM covers the *supply-chain* surface. This capability adds the
*runtime composition* surface: the components that define what the system
actually does at inference time.

**New component types** added to `mbom_v2.generate_ai_bom_v2` lineage:

| Component `type` | `bom_ref` digest source | Key fields |
|---|---|---|
| `prompt` | template text hash | `role` (system/developer/user-template), `sha256`, `token_estimate` |
| `system_prompt` | normalized text hash | `sha256`, `policy_refs[]` (first-class — already a stated requirement) |
| `adapter` | name+version+sha256 | LoRA/PEFT adapters, `base_model_ref` |
| `tool` | tool_name+version | pulled from `registry/tool_manifest.py` (`tool_manifest:` keys), `manifest_sha256`, `signed` |
| `mcp_server` | server_id+endpoint host | from `registry/mcp_scanner.py`, `scan_status` |
| `rag_index` | store_id | from `registry/rag_inventory.py` (`rag_store:` keys), `embedding_model_ref`, `doc_count`, `trust_distribution` |
| `embedding_model` | model_id+version+sha256 | dimensions, provider |
| `inference_provider` | provider+endpoint host | `hosted`/`self_hosted`, region, `provider_risk_ref` (→ Cap 10) |
| `guardrail` | name+version | from `core/guardrail_engine.py`, stage (input/output), `check_version` |
| `policy` | policy_id | from `core/policy_enforcement.py` (`pep_policy:` keys), mode |
| `evaluator` | scorer_name+version | from eval registry (→ Cap 6), `scorer_version` |

**New relationships:** `prompts`, `uses_tool`, `connects_mcp`, `retrieves_from`,
`embeds_with`, `served_by`, `guarded_by`, `governed_by`, `evaluated_by`.

**Design notes**
- Reuse the existing `_digest` / `_component_ref_matches` / `_canonical_bytes`
  helpers verbatim — extend `_TOP_LEVEL_FIELDS` is **not** needed (components are
  nested); add the new collections under `components` and the refs to `lineage`.
- A new `_evidence_quality` dimension `runtime_composition` (0/50/100) scores
  completeness of the runtime surface, folded into the existing mean.
- Extend `verify_ai_bom_v2` checks for the new ref/relationship invariants
  (same pattern as `lineage_relationships_match_components`).
- `cyclonedx_bom.export_bom` gains the new components as CycloneDX
  `components[].type = "machine-learning-model" | "data" | "application"` with
  `properties` carrying AIAF-specific fields (the `_build_properties` helper
  already exists for this).

**Files:** edit `registry/mbom_v2.py`, `registry/cyclonedx_bom.py`; new
`registry/agent_bom.py` (assembles the runtime component lists from the various
`*_PREFIX` stores so `mbom_v2` stays pure). API: extend `api/interop.py`
(`GET /v1/interop/models/{id}/bom/ai-bom`, `?format=cyclonedx`).

**Standards:** NIST AI RMF MAP-4.1/4.2, MEASURE-2.1; EU AI Act Art. 11 (technical
documentation); SSDF PS.3.

---

### Capability 2 — STIX / TAXII AI threat intelligence

**Extends:** `registry/ai_threat_intel.py` (20 built-in techniques mapping
OWASP-LLM ↔ MITRE ATLAS, custom ingest via `ai_threat:` keys).

**New module:** `registry/stix_taxii.py` — pure conversion + a thin client.

```
STIX_VERSION = "2.1"

def export_stix_bundle(threats, *, findings=None, incidents=None) -> dict
    # AIAF threat → STIX attack-pattern (with external_references to
    #   capec/mitre-atlas/owasp + CVE/OSV); finding → indicator/observed-data;
    #   incident → STIX 2.1 incident SDO; risk → custom x-aiaf-risk object.
def import_stix_bundle(bundle, store) -> dict
    # attack-pattern → ingest_threat(...); dedupe by external_reference id.
def map_finding_to_frameworks(finding) -> dict
    # {mitre_atlas, owasp_llm, owasp_agentic, cve, osv, internal_risk_id}
```

**TAXII 2.1** (`registry/taxii_client.py`, optional, network-gated like the
existing garak subprocess in `redteam_engine.py`): `poll_collection(url, ...)`
pulls bundles → `import_stix_bundle`; `push_objects(...)` publishes. Network
calls live behind an explicit flag and are never invoked from analysis code.

**Mapping table** lives in `mapping/threat_frameworks.py` (sibling to
`mapping/standards.py`): canonical cross-walk ATLAS ↔ OWASP-LLM ↔ OWASP-Agentic
↔ CAPEC, plus a normalizer for CVE/OSV IDs. Cap 10 (provider risk) and the
advisory feeds (`registry/advisory_feed_v2.py`) feed CVE/OSV IDs in.

**Files:** new `registry/stix_taxii.py`, `registry/taxii_client.py`,
`mapping/threat_frameworks.py`; extend `api/threat_intel.py` with
`POST /v1/threat-intel/stix/export`, `POST /v1/threat-intel/stix/import`,
`POST /v1/threat-intel/taxii/poll`.

**Standards:** MITRE ATLAS, OWASP-LLM 2025, OWASP Agentic; STIX 2.1 / TAXII 2.1.

---

### Capability 10 — Model / provider risk intelligence

**Extends:** `registry/hf_model_card.py` (provider-declared enrichment),
`analysis/model_risk_v2.py`, `analysis/adoption_velocity.py` (suspicious upload
patterns already partly modeled), `registry/advisory_feed_v2.py`.

**New analysis module:** `analysis/provider_risk.py` (pure, deterministic):

```
PROVIDER_RISK_VERSION = "1.0"
# dimensions, each 0–100 with explicit evidence:
#   publisher_reputation, hosting_provider_posture, maintainer_health,
#   license_risk, takedown_history, upload_pattern_anomaly,
#   maintainer_compromise_indicators
def assess_provider_risk(provider_record, *, signals=None) -> dict
def score_license(license_id) -> dict      # SPDX → permissive/copyleft/restrictive/unknown
def assess_maintainer(maintainer_record) -> dict   # account age, 2FA, recent ownership change
```

**New registry:** `registry/provider_registry.py` (`provider:` keys) — inventory
of publishers/hosting providers/package maintainers with observed signals
(takedowns, ownership transfers, upload bursts). Feeds the `inference_provider`
and `model` components of the AI-BOM (Cap 1) via `provider_risk_ref`, and the
STIX export (Cap 2) as `x-aiaf-provider-risk`.

**License risk** uses a static SPDX classification table in
`mapping/license_risk.py`.

**Files:** new `analysis/provider_risk.py`, `registry/provider_registry.py`,
`mapping/license_risk.py`, `api/provider_risk.py`
(`/v1/providers`, `/v1/providers/{id}/risk`).

**Standards:** NIST AI RMF GOVERN-6.1 (supply chain), MAP-4.1; OWASP-LLM03.

---

## Phase I — Runtime Provenance & Control

### Capability 3 — Runtime prompt / context provenance

**New core module:** `core/context_provenance.py` — reuses the **hash-chain
pattern** from `core/agent_action_ledger.py` but models an *influence DAG*
instead of a linear chain.

```
PROVENANCE_VERSION = "1.0"
_PROVENANCE_PREFIX = "provenance:"   # keyed by response_id

# Source kinds that can influence an output:
SRC_USER_INPUT, SRC_RETRIEVED_DOC, SRC_TOOL_OUTPUT, SRC_MEMORY_ITEM,
SRC_SYSTEM_INSTRUCTION, SRC_PRIOR_TURN

def record_influence(response_id, sources, output_ref, store, *,
                     session_id=None, metadata=None) -> dict
    # sources: [{kind, ref, content_sha256, trust_label?, taint?}]
    # builds influence edges source -> output; each node content-addressed;
    # the set of edges is hash-chained to the session ledger head for tamper-evidence.
def get_provenance(response_id, store) -> dict | None
def trace_output(response_id, store) -> dict   # full upstream influence tree
def find_influenced_by(source_ref, store, *, limit=100) -> list
    # reverse index: every output a given (e.g. poisoned) source touched —
    # this is what makes incident blast-radius (Cap 7) possible.
```

**Why a DAG, not a chain:** one response is influenced by many sources, and one
source (a retrieved doc, a memory item) influences many responses. The reverse
index `find_influenced_by` is the key primitive Cap 4 (taint propagation) and
Cap 7 (incident blast radius) both consume.

**Integration:** `core/inference_telemetry.py` (`TELEMETRY_VERSION`, session
events) calls `record_influence` per response; `core/agent_runtime_engine.py`
records tool-call inputs as influences. Content is **never stored raw** — only
`content_sha256` + trust/taint labels (mirrors `rag_security.py` privacy rule).

**Files:** new `core/context_provenance.py`, `api/provenance.py`
(`/v1/provenance/{response_id}`, `/v1/provenance/influenced-by`).

**Standards:** EU AI Act Art. 12 (logging), Art. 13 (transparency); NIST AI RMF
GOVERN-1.7, MEASURE-2.6.

---

### Capability 4 — RAG taint tracking

**Extends:** `registry/rag_inventory.py` (trust labels VERIFIED→UNTRUSTED already
exist) and `analysis/rag_security.py` (injection-pattern detection already
exists), wired into `core/policy_enforcement.py` for pre-model gating.

**New analysis module:** `analysis/rag_taint.py` (pure) — computes a composite
taint label per chunk from five dimensions the capability calls for:

```
RAG_TAINT_VERSION = "1.0"
# dimensions -> per-chunk:
#   trust       (from rag_inventory TRUST_RANK)
#   origin      (rag_inventory SOURCE_* — web/user_upload/api/...)
#   sensitivity (PII/secret scan reusing rag_security detectors)
#   freshness   (age vs. index freshness policy)
#   injection_risk (rag_security scan_rag_chunks status)
def compute_taint(chunk_meta, scan_result) -> dict   # -> {taint_level, dimensions, reasons[]}
def evaluate_retrieval(chunks, policy) -> dict        # batch verdict + per-chunk actions
```

**New core gate:** `core/rag_gate.py` — the enforcement point that sits between
retrieval and the model:

```
def gate_chunks(chunks, policy, store, *, session_id=None) -> dict
    # for each chunk: ALLOW / REDACT / QUARANTINE / DENY based on taint vs. policy
    # writes the decision to the agent_action_ledger (tamper-evident) and emits
    # a context_provenance source record (Cap 3) for every ALLOWed chunk.
```

Policy reuses the `policy_enforcement.py` structure (allowed/denied + conditions
+ mode ENFORCE/AUDIT/PASSTHROUGH) so operators configure RAG gating with the
same mental model as tool gating.

**Files:** new `analysis/rag_taint.py`, `core/rag_gate.py`; extend `api/rag.py`
(`POST /v1/rag/gate`, `POST /v1/rag/taint/evaluate`).

**Standards:** OWASP-LLM08 (vector/embedding), LLM01 (indirect injection); ATLAS
AML.T0046; NIST AI RMF MEASURE-2.7.

---

### Capability 5 — Agent egress & capability firewall

**Extends:** `core/policy_enforcement.py` (PEP verdicts/modes/rate-limit),
`core/tool_authorization.py` (tool allow/deny), recording to
`core/agent_action_ledger.py` (already the stated requirement).

**New core module:** `core/egress_firewall.py` — a unified decision layer over
three egress classes:

```
EGRESS_FIREWALL_VERSION = "1.0"
EGRESS_NETWORK, EGRESS_TOOL, EGRESS_DATA           # classes
# rules per principal (agent/session): allowed domains/CIDRs, allowed tools,
# data-class ceilings (e.g. may not emit PII to EXTERNAL destinations).
def evaluate_egress(principal, request, store, *, mode=MODE_ENFORCE) -> dict
    # request: {class, destination, data_classes?, tool_name?, payload_sha256}
    # verdict ALLOW/DENY/CONDITIONAL with matched_rule + reasons;
    # EVERY decision appended to agent_action_ledger via append_entry(..).
def create_egress_policy(...); get_egress_policy(...); list_egress_policies(...)
```

**Network egress** matching reuses the glob `_matches` helper; **data egress**
classification reuses the `rag_security` PII/secret detectors; **tool egress**
delegates to `tool_authorization.authorize`. The firewall is the single
choke-point the AI-BOM (Cap 1) lists as a `policy` component and the provenance
layer (Cap 3) records tool-call influences through.

**Optional middleware:** `api/egress_middleware.py` (sibling to the existing
`api/pep_middleware.py`) for inline enforcement on proxied agent traffic.

**Files:** new `core/egress_firewall.py`, `api/egress_firewall.py`
(`/v1/egress/policies`, `/v1/egress/evaluate`), optional
`api/egress_middleware.py`.

**Standards:** OWASP-LLM06 (excessive agency), OWASP Agentic AGENTIC-01; NIST AI
RMF MANAGE-2.4; EU AI Act Art. 14 (human oversight) for CONDITIONAL gates.

---

## Phase J — Evidence & Reporting

### Capability 6 — Evaluation evidence registry

**Extends:** `analysis/frontier_eval_harness.py`, `core/redteam_engine.py` (run
artifacts), `core/report_snapshot_engine.py` (snapshot pattern).

**New registry:** `registry/eval_registry.py` — eval runs as first-class,
content-addressed assurance artifacts (`eval_run:` keys):

```
EVAL_REGISTRY_VERSION = "1.0"
def record_eval_run(run, store) -> dict
    # run fields (all first-class, per the capability):
    #   eval_id, prompt_set_ref+sha256, model_id+version+sha256, seed,
    #   scorer_name+scorer_version, sample_size, metrics{}, 
    #   confidence_interval{lower,upper,method}, dataset_contamination_ref
    # run_hash = sha256(canonical(run)) -> immutable identity + dedupe
def get_eval_run(eval_id, store); list_eval_runs(store, *, model_id=None)
def regression_history(model_id, scorer_name, store) -> dict
    # ordered series + delta vs. previous run + significance flag
    #   (CI-overlap test — deterministic, no scipy dependency)
def compare_runs(eval_id_a, eval_id_b, store) -> dict
```

**Determinism:** the registry records seeds and scorer versions so a run is
reproducible; CI is stored, not recomputed, with its `method` declared.
Regression significance uses CI overlap (pure arithmetic), keeping `analysis`
dependency-free.

This is the source for the AI-BOM `evaluator` component (Cap 1) and the
`MEASURE` evidence in compliance packs (Cap 8).

**Files:** new `registry/eval_registry.py`, `api/eval_registry.py`
(`/v1/evals`, `/v1/evals/{id}`, `/v1/evals/regression`).

**Standards:** NIST AI RMF MEASURE-2.1/2.5/2.7; EU AI Act Art. 15 (accuracy,
robustness).

---

### Capability 7 — AI incident reporting package

**Extends:** `core/incident_manager.py` (state machine + audit trail),
`core/siem_export.py` (CEF/LEEF/JSON), pulling the influence trace from Cap 3
and STIX emission from Cap 2.

**New reporting module:** `reporting/incident_package.py` — assembles a
structured, portable bundle for a specific incident class:

```
INCIDENT_PACKAGE_VERSION = "1.0"
INCIDENT_CLASSES = { PROMPT_INJECTION, DATA_LEAKAGE, MODEL_EXTRACTION,
                     UNSAFE_TOOL_INVOCATION, RAG_POISONING,
                     UNAUTHORIZED_MODEL_CHANGE, AGENT_CONTAINMENT }
def build_incident_package(incident_id, store) -> dict
    # bundle:
    #   incident SDO + timeline (from incident_manager audit trail)
    #   influence trace + blast radius (context_provenance.find_influenced_by)
    #   ledger excerpt (agent_action_ledger / egress_firewall decisions)
    #   affected AI-BOM components (Cap 1)
    #   mapped frameworks (stix_taxii.map_finding_to_frameworks)
    #   recommended_remediation (remediation_tracker)
    #   bundle_sha256 (tamper-evident, signable via attestation_v2)
def export_package(incident_id, store, *, fmt="json"|"stix"|"cef") -> str|dict
```

Each class has a required-evidence checklist so a `PROMPT_INJECTION` package
always carries the offending input hash + influenced outputs, a `RAG_POISONING`
package carries the tainted chunk refs + every response they touched, etc.

**Files:** new `reporting/incident_package.py`; extend `api/` incident routes
(`GET /v1/incidents/{id}/package?format=...`).

**Standards:** EU AI Act Art. 73 (serious-incident reporting); NIST AI RMF
MANAGE-4.x; STIX 2.1 incident SDO.

---

### Capability 8 — Compliance evidence packs

**Extends:** `reporting/compliance.py` (`build_compliance_matrix`),
`mapping/standards.py` / `mapping/eu_ai_act.py` / `mapping/iso_42001.py`,
`reporting/exporters/oscal.py` (`export_oscal_ssp`).

**New reporting module:** `reporting/evidence_pack.py` — turns the existing
compliance matrix into a downloadable, per-framework **evidence package** that
binds each control to concrete AIAF artifacts:

```
EVIDENCE_PACK_VERSION = "1.0"
FRAMEWORKS = { NIST_AI_RMF, ISO_42001, EU_AI_ACT_HIGH_RISK,
               OWASP_LLM_TOP10, OWASP_AGENTIC }
def build_evidence_pack(framework, scope, store) -> dict
    # per control: status (satisfied/partial/missing) + linked evidence refs:
    #   AI-BOM doc (Cap1), eval runs (Cap6), ledger/provenance (Cap3/5),
    #   findings, control_evidence rows, incident packages (Cap7).
    # gaps[] carry the existing open_control_gaps shape.
def export_pack(framework, scope, store, *, fmt="json"|"oscal"|"html"|"markdown")
```

The OWASP-LLM and OWASP-Agentic crosswalks reuse `mapping/threat_frameworks.py`
(Cap 2). EU AI Act high-risk controls map through the existing
`mapping/eu_ai_act.py`. OSCAL export reuses `export_oscal_ssp`.

**Files:** new `reporting/evidence_pack.py`, additions to `mapping/` for the
OWASP/ISO control catalogs; extend `api/reporting.py`
(`GET /v1/reporting/evidence-pack/{framework}?format=...`).

**Standards:** NIST AI RMF, ISO/IEC 42001, EU AI Act (high-risk), OWASP-LLM 2025,
OWASP Agentic.

---

### Capability 9 — Secure deployment verification

**Extends:** the `deployment` component logic in `registry/mbom_v2.py`
(`_deployment_component` already computes MATCH/MISMATCH on a registered
artifact digest) and `registry/sigstore_verifier.py`. The gap this fills:
verifying the **running** endpoint/container against the registry record, not
just the registered artifact.

**New registry module:** `registry/deployment_verifier.py`:

```
DEPLOYMENT_VERIFY_VERSION = "1.0"
def verify_deployment(model_id, observed, store) -> dict
    # observed (collected by operator/agent, passed in — module stays pure):
    #   {endpoint_url, container_digest, served_model_id, weights_sha256?,
    #    system_prompt_sha256?, tool_list[], guardrail_versions[]}
    # compares against the registered AI-BOM subject + runtime components (Cap1):
    #   artifact_match, container_match, system_prompt_match, tool_drift,
    #   guardrail_drift, config_drift -> overall verdict + drift report.
def probe_endpoint(endpoint_url, ...) -> dict   # optional, network-gated
    # behavioral fingerprint via probe_engine; identity attestation if exposed.
```

The deterministic comparison lives in the pure module; live probing (network) is
isolated behind a flag exactly like `redteam_engine.py` / `taxii_client.py`. A
MISMATCH raises a `findings` row and can auto-open an incident (Cap 7) of class
`UNAUTHORIZED_MODEL_CHANGE`.

**Files:** new `registry/deployment_verifier.py`, `api/deployment_verify.py`
(`POST /v1/deployments/{model_id}/verify`).

**Standards:** SSDF PS.3/RV; NIST AI RMF MAP-4.2, MANAGE-2.4; EU AI Act Art. 11.

---

## Cross-cutting design

### Dependency / sequencing graph

```
Cap1 AI-BOM ──────────────► Cap8 Evidence packs
   │                        ▲
   ├──► Cap9 Deploy verify ─┘
   │
Cap10 Provider risk ──► Cap2 STIX/TAXII ──► Cap7 Incident package
                                              ▲
Cap3 Context provenance ──► Cap4 RAG taint ───┤
   │                          │               │
   │                          ▼               │
   └────────────────────► Cap5 Egress firewall┘
                                              ▲
Cap6 Eval registry ───────────────────────► Cap8
```

**Recommended build order:** Cap 1 → Cap 10 → Cap 2 → Cap 3 → Cap 5 → Cap 4 →
Cap 6 → Cap 9 → Cap 7 → Cap 8. (Foundations first; Cap 8 last because it
aggregates everything.)

### Shared primitives to add once

- **Influence/reverse index** (`core/context_provenance.py`) — consumed by
  Cap 4 and Cap 7. Build it well; it is the backbone of runtime assurance.
- **`mapping/threat_frameworks.py`** crosswalk — consumed by Cap 2, 7, 8.
- **Bundle signing** — reuse `registry/attestation_v2.py` for Cap 7 packages and
  Cap 8 evidence packs (no new crypto).

### Persistence

All new record types use the generic `model` namespace with new prefixes
(`provenance:`, `eval_run:`, `provider:`, `egress_policy:`,
`deployment_verify:`). **No schema migration needed** for these. Only Cap 6
(eval runs, if high-volume regression queries are required) may warrant a
dedicated `eval_runs` table later — start with the model namespace and promote
only if query latency demands it.

### Architecture catalog + wiring

Every new `api/*` router must be (1) `include_router`-ed in `api/app.py` and
(2) registered as a component in `architecture.py` under the appropriate layer,
since `GET /v1/architecture` and `tests/test_architecture.py` assert the catalog
matches the live routes.

### Testing

One deterministic `tests/test_<module>.py` per module (network paths stubbed,
matching `redteam_engine` test style). Target parity with current coverage
(~2,500 tests). Estimated additions: ~280–340 tests across the 10 capabilities.

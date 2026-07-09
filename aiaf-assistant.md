
**Implementation Plan**

Here’s a concrete, AIAF-native plan to add an agent experience for non-technical governance and policy users without turning the system into an unsafe general chatbot.

**Goal**
Build an `Ask AIAF` governance copilot that lets a user request reports, summaries, and evidence-gap analysis in plain language, while the agent safely orchestrates existing AIAF APIs and returns traceable, evidence-backed results.

**North Star MVP**
A governance user can type:
- “Generate the latest governance report for artifact `hiring-assistant-prod`”
- “What evidence is missing for approval?”
- “Summarize compliance posture for the customer support bot”
- “Compare the latest snapshot with last month’s”

And AIAF will:
- determine intent and scope
- run approved AIAF workflows
- return a structured answer with citations
- optionally offer a `Save snapshot` action

## 1. Product Scope

**Primary users**
- Governance lead
- Policy owner
- Risk/compliance analyst
- Executive stakeholder

**MVP capabilities**
- Generate assurance report
- Generate compliance summary
- List governance gaps / missing evidence
- Compare report snapshots
- Summarize agent authorization posture
- Summarize RAG inventory posture

**Out of scope for MVP**
- Auto-submitting governance evidence
- Approving/rejecting evidence
- Freeform autonomous tool use
- Editing policies directly from chat

## 2. UX Design

**New dashboard entry point**
Add a new tab or prominent panel: `Ask AIAF`

Likely location:
- new tab beside `Governance`, `Model Registry`, `Agent Authorization`
- or a persistent right-side assistant drawer

**UI structure**
1. Prompt input
2. Suggested task chips
3. Structured answer panel
4. “Actions taken” audit section
5. Optional follow-up prompts
6. Optional artifact export buttons

**Suggested prompts**
- `Generate governance report`
- `Explain missing evidence`
- `Summarize compliance posture`
- `Compare report snapshots`
- `Show agent authorization decisions`
- `Show RAG store risks`

**Response format**
Each assistant answer should have:
- `Answer`
- `Scope`
- `Evidence basis`
- `Actions taken`
- `Uncertainty / limits`
- `Next recommended actions`

That structure matters a lot for non-technical trust.

## 3. Architecture

Use a constrained orchestration pattern, not an open-ended agent.

**Proposed backend components**
- `src/aiaf/api/assistant.py`
- `src/aiaf/core/assistant_engine.py`
- `src/aiaf/core/assistant_workflows.py`
- `src/aiaf/core/assistant_policy.py`
- `src/aiaf/core/assistant_prompts.py`
- `frontend/src/tabs/Assistant.jsx`

**Flow**
1. User sends prompt to `/v1/assistant/query`
2. Assistant engine classifies intent
3. Engine extracts scope
4. Engine selects one allowed workflow
5. Workflow calls existing AIAF engines/APIs
6. Response composer generates structured output
7. All actions are logged and optionally persisted as a session

## 4. Backend API Plan

### A. New assistant query endpoint
Add:

- `POST /v1/assistant/query`

Request:
```json
{
  "message": "Generate the latest governance report for hiring assistant",
  "scope_hint": {
    "artifact_id": "hiring-assistant-prod"
  },
  "role": "governance_analyst",
  "conversation_id": "optional-id"
}
```

Response:
```json
{
  "intent": "generate_governance_report",
  "scope": {
    "artifact_id": "hiring-assistant-prod"
  },
  "answer_markdown": "...",
  "actions_taken": [
    {
      "type": "reporting.assurance_report",
      "scope": { "artifact_id": "hiring-assistant-prod" }
    },
    {
      "type": "governance.evidence_summary",
      "scope": { "artifact_id": "hiring-assistant-prod" }
    }
  ],
  "artifacts": [
    {
      "kind": "assurance_report",
      "format": "json"
    }
  ],
  "follow_ups": [
    "Do you want me to save this as a snapshot?",
    "Do you want a board-ready executive summary?"
  ],
  "limits": [
    "No pending evidence review actions were executed."
  ]
}
```

### B. Optional session endpoints
For conversational continuity:
- `POST /v1/assistant/sessions`
- `GET /v1/assistant/sessions/{session_id}`
- `POST /v1/assistant/sessions/{session_id}/messages`

But I would not start here unless needed. Stateless query is enough for MVP.

## 5. Workflow Catalog

This is the core of safety and simplicity.

Implement a small workflow registry in `assistant_workflows.py`.

**MVP workflows**
- `generate_assurance_report`
  Uses reporting engine / `/v1/reporting/assurance-report`
- `generate_compliance_summary`
  Uses `/v1/reporting/compliance`
- `list_governance_gaps`
  Uses governance evaluation summary + evidence summary
- `compare_snapshots`
  Uses `/v1/reporting/snapshots` and `/verify` if needed
- `summarize_agent_runtime`
  Uses `/v1/agentic/sessions` and `/v1/agentic/invocations`
- `summarize_rag_inventory`
  Uses `/v1/rag/stores` and assessments

**Each workflow should define**
- supported intents
- required scope fields
- allowed read/write level
- underlying AIAF calls
- response template
- follow-up options

## 6. Intent Model

Don’t begin with a fancy planner. Use a controlled intent classifier.

**Initial intents**
- `generate_governance_report`
- `generate_compliance_summary`
- `explain_missing_evidence`
- `compare_snapshots`
- `summarize_agent_authorization`
- `summarize_rag_inventory`
- `help`

**Scope extraction**
Supported scope dimensions:
- `artifact_id`
- `model_id`
- `registered_by`
- portfolio-wide

**Fallback behavior**
If scope is ambiguous:
- ask one targeted question
- example: “Do you want a portfolio report, one model, or one artifact?”

## 7. Agent Safety Model

This is where AIAF has an advantage.

Use existing agentic controls for the assistant itself.

**Assistant policy profile**
Create a dedicated restricted profile, something like:
- allowed tools:
  - reporting
  - governance read
  - snapshots read
  - metrics read
  - rag read
  - agentic-runtime read
- denied tools:
  - shell
  - filesystem write
  - external network
  - evidence review
  - policy mutation
- conditional actions:
  - snapshot creation may require approval
  - evidence submission must require approval
  - evidence review always denied for MVP

**Practical rule**
MVP assistant is read-only with one optional write:
- `create_report_snapshot`

Everything else is read-only.

## 8. Response Composition

The answer generator should not improvise from raw data.

**Preferred pattern**
- run workflow
- gather structured AIAF results
- generate a formatted explanation from those results
- include exact counts, statuses, and scope
- cite which AIAF outputs were used

**Example answer shape**
```markdown
## Governance Report Summary

Artifact: hiring-assistant-prod

Status: NEEDS_REVIEW

Open governance gaps:
- 3 controls are missing required evidence
- 1 evidence item is pending independent review
- 1 approved evidence item has expired

Evidence basis:
- Latest governance evaluation
- Governance evidence summary
- Assurance report for the current artifact scope

Recommended next actions:
1. Close AIAF-GOV-003 evidence gap
2. Refresh expired evidence for AIAF-GOV-005
3. Re-run governance evaluation after evidence review
```

## 9. Frontend Plan

**New component**
- `frontend/src/tabs/Assistant.jsx`

**Frontend responsibilities**
- prompt submission
- display structured response
- render actions taken
- render follow-up chips
- support quick scope selection
- optional export/save actions

**Useful UI pieces**
- scope selector: `Portfolio | Model | Artifact`
- suggested prompts
- “show technical details” accordion
- “save as snapshot” button after report generation

**Nice touch for non-technical users**
Add two response modes:
- `Executive`
- `Operational`

Same data, different explanation depth.

## 10. Auditability

Every assistant action should be auditable.

Add audit events such as:
- `assistant_query_received`
- `assistant_intent_resolved`
- `assistant_workflow_executed`
- `assistant_snapshot_created`
- `assistant_query_failed`

Each should record:
- user role or identity
- query text
- resolved intent
- scope used
- actions performed
- whether any write action occurred

This matters if the assistant is used in governance workflows.

## 11. Data Model Additions

If you want persistence, add a lightweight assistant session/message store.

Possible records:
- `assistant_session`
- `assistant_message`
- `assistant_action_log`

But for MVP, I’d keep this minimal:
- use audit logs first
- only add stored assistant conversations if users clearly need continuity

## 12. Implementation Phases

### Phase 1: Read-only governance copilot
Build:
- `POST /v1/assistant/query`
- intent classifier
- 4 workflows:
  - assurance report
  - compliance summary
  - missing evidence
  - snapshot comparison
- dashboard `Ask AIAF` UI
- audit logging

Success criteria:
- governance users can get useful answers without API Explorer
- every answer is evidence-backed and traceable

### Phase 2: Operational assistant
Add:
- agent authorization summary
- RAG posture summary
- optional snapshot creation
- role-based prompt templates
- executive vs operational rendering

Success criteria:
- users can investigate runtime and retrieval posture without technical navigation

### Phase 3: Approval-gated write workflows
Add:
- submit evidence draft
- propose remediation tasks
- schedule periodic reports
- approval-based execution

Success criteria:
- assistant becomes a workflow accelerator, not just a read-only explainer

## 13. Concrete File Plan

**Backend**
- [src/aiaf/api/app.py](/home/smartcat/projects/AI-Assurance-Framework/src/aiaf/api/app.py:1)
  Add assistant router
- `src/aiaf/api/assistant.py`
  New API surface
- `src/aiaf/core/assistant_engine.py`
  Intent resolution + orchestration
- `src/aiaf/core/assistant_workflows.py`
  Workflow registry
- `src/aiaf/core/assistant_policy.py`
  Tool/action constraints
- `src/aiaf/core/assistant_prompts.py`
  Controlled system prompts / templates

**Frontend**
- `frontend/src/tabs/Assistant.jsx`
- [frontend/src/App.jsx](/home/smartcat/projects/AI-Assurance-Framework/frontend/src/App.jsx:13)
  Add tab
- [frontend/src/api.js](/home/smartcat/projects/AI-Assurance-Framework/frontend/src/api.js:97)
  Add assistant client calls

**Tests**
- `tests/test_assistant_api.py`
- `tests/test_assistant_workflows.py`
- `tests/test_assistant_policy.py`
- `tests/test_assistant_ui.jsx` or frontend API tests
- integration tests for audit logging and snapshot creation behavior

## 14. Recommended MVP Sequence

If we were implementing this now, I’d do it in this order:

1. Add assistant backend route and a stub response
2. Implement intent classification with fixed intents
3. Implement `generate_assurance_report`
4. Implement `explain_missing_evidence`
5. Add frontend `Ask AIAF` tab
6. Add action audit logging
7. Add `compare_snapshots`
8. Add optional `save snapshot`
9. Add agent/RAG summarizers

That keeps each slice demoable.

## 15. Risks To Manage

**Risk: users over-trust the assistant**
Mitigation:
- always show evidence basis
- always show scope
- always show uncertainty/limits

**Risk: assistant becomes a shadow API**
Mitigation:
- force all actions through existing AIAF endpoints/engines
- do not bypass governance logic

**Risk: scope ambiguity**
Mitigation:
- require explicit scope when confidence is low

**Risk: governance mutation without review**
Mitigation:
- read-only MVP
- approval-gated writes later

## 16. Best First Deliverable

If you want the highest-value first increment, build this exact slice:

- `Ask AIAF` tab
- one prompt box
- support:
  - “generate governance report”
  - “what evidence is missing?”
- artifact/model/portfolio scope selector
- structured markdown answer
- “save as snapshot” button
- audit log for every assistant action

That would already make AIAF much easier for non-technical governance users.

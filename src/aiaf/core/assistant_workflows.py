"""Constrained workflow implementations for the AIAF assistant MVP."""

from __future__ import annotations

from typing import Any

from ..registry.rag_inventory import list_vector_stores
from .assistant_actor import actor_summary
from .evidence_engine import GovernanceEvidenceEngine
from .report_snapshot_engine import AssuranceReportSnapshotEngine
from .reporting_engine import ReportingEngine


def help_response() -> dict[str, Any]:
    return {
        "title": "How I can help",
        "summary": "The MVP assistant can generate reports, explain evidence gaps, and summarize selected runtime posture.",
        "answer_markdown": "\n".join(
            [
                "## Ask AIAF",
                "",
                "I can currently help with:",
                "- Governance reports",
                "- Compliance posture summaries",
                "- Missing evidence and open governance gaps",
                "- Snapshot comparisons",
                "- Agent authorization summaries",
                "- RAG inventory summaries",
                "",
                "Try one of the suggested prompts in the drawer.",
            ]
        ),
        "actions_taken": [],
        "artifacts": [],
        "follow_ups": [
            "Generate a governance report",
            "Explain missing evidence",
            "Compare the latest two snapshots",
        ],
        "limits": [
            "This MVP uses deterministic workflows rather than a freeform LLM planner.",
        ],
    }


def generate_governance_report(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    report = ReportingEngine(datastore=datastore).assurance_report(**scope)
    governance = report.get("governance") or {}
    evidence = report.get("governance_evidence") or {}
    summary = report.get("summary") or {}
    open_gaps = governance.get("open_gaps") or []

    answer = [
        "## Governance Report",
        "",
        f"- Scope: {_scope_label(report.get('scope') or {})}",
        f"- Governance status: {governance.get('status', 'NO_EVIDENCE')}",
        f"- Open governance gaps: {len(open_gaps)}",
        f"- Approved evidence: {evidence.get('approved_evidence', 0)}",
        f"- Pending evidence: {evidence.get('pending_evidence', 0)}",
        f"- Expired approved evidence: {evidence.get('expired_approved_evidence', 0)}",
    ]
    if summary:
        answer.extend(
            [
                "",
                "### Portfolio posture",
                f"- Total findings: {summary.get('total_findings', 0)}",
                f"- High or critical findings: {summary.get('high_or_critical_findings', 0)}",
                f"- Governance evaluations: {summary.get('governance_evaluation_count', 0)}",
            ]
        )
    if open_gaps:
        answer.extend(["", "### Open gaps"])
        answer.extend(f"- {gap}" for gap in open_gaps[:8])
    else:
        answer.extend(["", "### Open gaps", "- No governance gaps are currently recorded for this scope."])

    return {
        "title": "Governance report ready",
        "summary": f"{governance.get('status', 'NO_EVIDENCE')} with {len(open_gaps)} open governance gaps.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "reporting.assurance_report", "scope": scope},
        ],
        "artifacts": [
            {"kind": "assurance_report", "format": "json"},
            {"kind": "assurance_report", "format": "markdown"},
            {"kind": "assurance_report", "format": "html"},
        ],
        "follow_ups": [
            "Explain missing evidence",
            "Summarize compliance posture",
            "Compare the latest two snapshots",
        ],
        "limits": [],
    }


def summarize_compliance_posture(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    compliance = ReportingEngine(datastore=datastore).compliance(**scope)
    summary = compliance.get("summary") or {}
    open_gaps = compliance.get("open_control_gaps") or []
    answer = [
        "## Compliance Posture",
        "",
        f"- Status: {compliance.get('status', 'NO_EVALUATION')}",
        f"- Frameworks in scope: {summary.get('frameworks_in_scope', 0)}",
        f"- Frameworks evidence complete: {summary.get('frameworks_evidence_complete', 0)}",
        f"- Frameworks with gaps: {summary.get('frameworks_with_gaps', 0)}",
        f"- Open control gaps: {summary.get('open_control_gaps', 0)}",
    ]
    if open_gaps:
        answer.extend(["", "### Top open control gaps"])
        for gap in open_gaps[:6]:
            answer.append(
                f"- {gap.get('framework', 'Framework')} · {gap.get('control_id', 'control')} · {gap.get('title', 'Untitled control')}"
            )
    else:
        answer.extend(["", "### Top open control gaps", "- No open control gaps were reported for this scope."])

    return {
        "title": "Compliance posture summary",
        "summary": f"{compliance.get('status', 'NO_EVALUATION')} across {summary.get('frameworks_in_scope', 0)} frameworks in scope.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "reporting.compliance", "scope": scope},
        ],
        "artifacts": [
            {"kind": "compliance_matrix", "format": "json"},
        ],
        "follow_ups": [
            "Generate a governance report",
            "Explain missing evidence",
        ],
        "limits": [],
    }


def explain_missing_evidence(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    report = ReportingEngine(datastore=datastore).assurance_report(**scope)
    governance = report.get("governance") or {}
    evidence_summary = report.get("governance_evidence") or {}
    compliance = report.get("compliance") or {}
    open_gaps = governance.get("open_gaps") or []
    control_gaps = compliance.get("open_control_gaps") or []

    answer = [
        "## Missing Evidence",
        "",
        f"- Scope: {_scope_label(report.get('scope') or {})}",
        f"- Pending evidence items: {evidence_summary.get('pending_evidence', 0)}",
        f"- Expired approved evidence: {evidence_summary.get('expired_approved_evidence', 0)}",
        f"- Open governance gaps: {len(open_gaps)}",
        f"- Open control gaps: {len(control_gaps)}",
    ]
    if control_gaps:
        answer.extend(["", "### Priority gaps to close"])
        for gap in control_gaps[:8]:
            missing = ", ".join(gap.get("missing_evidence") or []) or "missing evidence"
            answer.append(
                f"- {gap.get('control_id', 'control')} ({gap.get('framework', 'framework')}): {missing}"
            )
    elif open_gaps:
        answer.extend(["", "### Priority gaps to close"])
        answer.extend(f"- {gap}" for gap in open_gaps[:8])
    else:
        answer.extend(["", "### Priority gaps to close", "- No missing evidence is currently recorded for this scope."])

    return {
        "title": "Evidence gap analysis",
        "summary": f"{len(control_gaps) or len(open_gaps)} missing or incomplete evidence gaps identified.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "reporting.assurance_report", "scope": scope},
            {"type": "reporting.compliance", "scope": scope},
        ],
        "artifacts": [
            {"kind": "assurance_report", "format": "json"},
            {"kind": "compliance_matrix", "format": "json"},
        ],
        "follow_ups": [
            "Generate a governance report",
            "Summarize compliance posture",
        ],
        "limits": [],
    }


def compare_snapshots(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    engine = AssuranceReportSnapshotEngine(datastore)
    snapshots = engine.list(limit=10, **scope)
    if len(snapshots) < 2:
        return {
            "title": "Not enough snapshots",
            "summary": "Snapshot comparison needs at least two snapshots in the selected scope.",
            "answer_markdown": "\n".join(
                [
                    "## Snapshot Comparison",
                    "",
                    f"- Scope: {_scope_label((snapshots[0].get('report') or {}).get('scope', {})) if snapshots else _scope_label(scope)}",
                    f"- Snapshots available: {len(snapshots)}",
                    "- I need at least two snapshots to compare changes over time.",
                ]
            ),
            "actions_taken": [
                {"type": "reporting.snapshots.list", "scope": scope},
            ],
            "artifacts": [],
            "follow_ups": [
                "Generate a governance report",
            ],
            "limits": [
                "Snapshot comparison is only available after snapshots have been created.",
            ],
        }

    latest, previous = snapshots[0], snapshots[1]
    latest_report = latest.get("report") or {}
    previous_report = previous.get("report") or {}
    latest_gov = latest_report.get("governance") or {}
    previous_gov = previous_report.get("governance") or {}
    latest_compliance = latest_report.get("compliance") or {}
    previous_compliance = previous_report.get("compliance") or {}
    latest_summary = latest_report.get("summary") or {}
    previous_summary = previous_report.get("summary") or {}
    digest_changed = latest.get("sha256") != previous.get("sha256")

    answer = [
        "## Snapshot Comparison",
        "",
        f"- Scope: {_scope_label(latest_report.get('scope') or {})}",
        f"- Latest snapshot: {latest.get('created_at', 'unknown')}",
        f"- Previous snapshot: {previous.get('created_at', 'unknown')}",
        f"- Report digest changed: {'YES' if digest_changed else 'NO'}",
        "",
        "### Governance change",
        f"- Latest status: {latest_gov.get('status', 'NO_EVIDENCE')}",
        f"- Previous status: {previous_gov.get('status', 'NO_EVIDENCE')}",
        f"- Latest open gaps: {len(latest_gov.get('open_gaps') or [])}",
        f"- Previous open gaps: {len(previous_gov.get('open_gaps') or [])}",
        "",
        "### Compliance change",
        f"- Latest status: {latest_compliance.get('status', 'NO_EVALUATION')}",
        f"- Previous status: {previous_compliance.get('status', 'NO_EVALUATION')}",
        f"- Latest control gaps: {(latest_compliance.get('summary') or {}).get('open_control_gaps', 0)}",
        f"- Previous control gaps: {(previous_compliance.get('summary') or {}).get('open_control_gaps', 0)}",
        "",
        "### Risk change",
        f"- Latest high or critical findings: {latest_summary.get('high_or_critical_findings', 0)}",
        f"- Previous high or critical findings: {previous_summary.get('high_or_critical_findings', 0)}",
    ]

    return {
        "title": "Snapshot comparison",
        "summary": "Compared the latest two assurance report snapshots for the selected scope.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "reporting.snapshots.list", "scope": scope},
        ],
        "artifacts": [
            {"kind": "snapshot", "snapshot_id": latest.get("id")},
            {"kind": "snapshot", "snapshot_id": previous.get("id")},
        ],
        "follow_ups": [
            "Generate a governance report",
            "Explain missing evidence",
        ],
        "limits": [],
    }


def create_report_snapshot(
    datastore: object,
    scope: dict[str, str | None],
    *,
    actor: dict[str, Any] | None,
) -> dict[str, Any]:
    snapshot = AssuranceReportSnapshotEngine(datastore).create(
        created_by=actor_summary(actor),
        artifact_id=scope.get("artifact_id"),
        model_id=scope.get("model_id"),
        registered_by=scope.get("registered_by"),
        sign=False,
    )
    report_scope = (snapshot.get("report") or {}).get("scope") or {}
    return {
        "title": "Snapshot created",
        "summary": f"Saved an assurance report snapshot for {_scope_label(report_scope)}.",
        "answer_markdown": "\n".join(
            [
                "## Snapshot Created",
                "",
                f"- Scope: {_scope_label(report_scope)}",
                f"- Snapshot ID: {snapshot.get('id', 'unknown')}",
                f"- Created at: {snapshot.get('created_at', 'unknown')}",
                f"- Created by: {snapshot.get('created_by', 'unknown')}",
                f"- Digest: {snapshot.get('sha256', '')[:16]}…",
                "",
                "You can now compare this snapshot with later reports to track governance and compliance drift.",
            ]
        ),
        "actions_taken": [
            {"type": "reporting.snapshots.create", "scope": scope},
        ],
        "artifacts": [
            {"kind": "snapshot", "snapshot_id": snapshot.get("id")},
        ],
        "follow_ups": [
            "Compare the latest two snapshots",
            "Generate a governance report",
        ],
        "limits": [
            "Snapshot creation is the first enabled write action in the assistant MVP.",
        ],
    }


def summarize_agent_authorization(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    sessions = _safe_list_agent_sessions(datastore, scope)
    invocations = _safe_list_tool_invocations(datastore, scope)
    decisions = _count_by(invocations, "decision")
    by_tool = _count_by(invocations, "tool")
    answer = [
        "## Agent Authorization Summary",
        "",
        f"- Scope: {_scope_label(scope)}",
        f"- Sessions: {len(sessions)}",
        f"- Active sessions: {sum(1 for session in sessions if session.get('status') == 'ACTIVE')}",
        f"- Authorization decisions: {len(invocations)}",
        f"- Denials: {decisions.get('DENY', 0)}",
        f"- Approval required: {decisions.get('REQUIRE_APPROVAL', 0)}",
        f"- Allowed: {decisions.get('ALLOW', 0)}",
    ]
    if by_tool:
        answer.extend(["", "### Most active tools"])
        for tool, count in sorted(by_tool.items(), key=lambda item: (-item[1], item[0]))[:6]:
            answer.append(f"- {tool}: {count}")

    return {
        "title": "Agent authorization posture",
        "summary": f"{len(invocations)} decisions across {len(sessions)} sessions.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "agentic.sessions.list", "scope": scope},
            {"type": "agentic.invocations.list", "scope": scope},
        ],
        "artifacts": [],
        "follow_ups": [
            "Generate a governance report",
        ],
        "limits": [],
    }


def summarize_rag_inventory(datastore: object, scope: dict[str, str | None]) -> dict[str, Any]:
    stores = list_vector_stores(datastore, limit=200)
    total_docs = sum(int(store.get("document_count") or 0) for store in stores)
    open_stores = [
        store for store in stores
        if str((store.get("security_profile") or {}).get("access_control_mode") or "").upper() == "OPEN"
    ]
    untrusted_docs = sum(
        int((store.get("trust_distribution") or {}).get("UNTRUSTED") or 0) for store in stores
    )
    answer = [
        "## RAG Inventory Summary",
        "",
        f"- Registered stores: {len(stores)}",
        f"- Indexed documents: {total_docs}",
        f"- Stores with OPEN access: {len(open_stores)}",
        f"- Untrusted documents: {untrusted_docs}",
    ]
    if stores:
        answer.extend(["", "### Highest-risk signals"])
        ranked = sorted(
            stores,
            key=lambda item: (
                -int((item.get("trust_distribution") or {}).get("UNTRUSTED") or 0),
                -int(item.get("document_count") or 0),
            ),
        )
        for store in ranked[:6]:
            answer.append(
                f"- {store.get('store_id', 'store')} · {store.get('document_count', 0)} docs · "
                f"{(store.get('trust_distribution') or {}).get('UNTRUSTED', 0)} untrusted"
            )

    return {
        "title": "RAG inventory posture",
        "summary": f"{len(stores)} stores and {untrusted_docs} untrusted documents tracked.",
        "answer_markdown": "\n".join(answer),
        "actions_taken": [
            {"type": "rag.stores.list", "scope": scope},
        ],
        "artifacts": [],
        "follow_ups": [
            "Generate a governance report",
        ],
        "limits": [
            "This summary reflects registered inventory and not live retrieval traffic.",
        ],
    }


def _scope_label(scope: dict[str, Any]) -> str:
    scope_type = str(scope.get("type") or "").upper()
    if scope_type == "MODEL" and scope.get("model_id"):
        return f"model {scope['model_id']}"
    if scope_type == "REGISTRANT" and scope.get("registered_by"):
        return f"registrant {scope['registered_by']}"
    if scope_type == "ARTIFACT" and scope.get("artifact_id"):
        return f"artifact {scope['artifact_id']}"
    if scope.get("model_id"):
        return f"model {scope['model_id']}"
    if scope.get("registered_by"):
        return f"registrant {scope['registered_by']}"
    if scope.get("artifact_id"):
        return f"artifact {scope['artifact_id']}"
    return "portfolio"


def _safe_list_agent_sessions(datastore: object, scope: dict[str, str | None]) -> list[dict[str, Any]]:
    list_sessions = getattr(datastore, "list_agent_sessions", None)
    if not list_sessions:
        return []
    artifact_id = scope.get("artifact_id") or scope.get("model_id")
    try:
        return list_sessions(limit=1000, artifact_id=artifact_id)
    except Exception:
        return []


def _safe_list_tool_invocations(datastore: object, scope: dict[str, str | None]) -> list[dict[str, Any]]:
    list_invocations = getattr(datastore, "list_tool_invocations", None)
    if not list_invocations:
        return []
    artifact_id = scope.get("artifact_id") or scope.get("model_id")
    try:
        return list_invocations(limit=2000, artifact_id=artifact_id)
    except Exception:
        return []


def _count_by(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return counts

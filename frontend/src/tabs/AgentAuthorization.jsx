import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Empty, Metric, Pill, Tag, fmtDate, humanLabel } from "../ui.jsx";

const DECISIONS = ["ALLOW", "REQUIRE_APPROVAL", "DENY"];

function countBy(items, key) {
  return items.reduce((counts, item) => {
    const value = String(item?.[key] || "UNKNOWN").toUpperCase();
    counts[value] = (counts[value] || 0) + 1;
    return counts;
  }, {});
}

export default function AgentAuthorization({ refreshToken }) {
  const resource = useResource(
    () =>
      Promise.all([
        api.agentSessions({ limit: 200 }),
        api.agentInvocations({ limit: 400 }),
        api.agentPolicyProfiles(),
      ]),
    [refreshToken]
  );

  const sessions = resource.data?.[0]?.sessions || [];
  const invocations = resource.data?.[1]?.invocations || [];
  const profiles = resource.data?.[2]?.profiles || {};

  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");
  const [sessionQuery, setSessionQuery] = useState("");

  useEffect(() => {
    if (!selectedSessionId && sessions.length) {
      setSelectedSessionId(sessions[0].id || "");
    }
    if (selectedSessionId && !sessions.some((session) => session.id === selectedSessionId)) {
      setSelectedSessionId(sessions[0]?.id || "");
    }
  }, [sessions, selectedSessionId]);

  const counts = countBy(invocations, "decision");
  const filteredSessions = useMemo(() => {
    const needle = sessionQuery.trim().toLowerCase();
    return sessions.filter((session) => {
      const haystack = [
        session.id,
        session.artifact_id,
        session.policy_profile,
        session.status,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return !needle || haystack.includes(needle);
    });
  }, [sessions, sessionQuery]);

  const selectedSession = sessions.find((session) => session.id === selectedSessionId) || null;
  const sessionInvocations = invocations.filter((invocation) => {
    if (selectedSessionId && invocation.session_id !== selectedSessionId) return false;
    if (decisionFilter && String(invocation.decision || "").toUpperCase() !== decisionFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Sessions" value={sessions.length} sub={`${sessions.filter((session) => session.status === "ACTIVE").length} active`} />
        <Metric label="Allows" value={counts.ALLOW || 0} sub="recorded tool decisions" />
        <Metric label="Needs Approval" value={counts.REQUIRE_APPROVAL || 0} sub="paused for human review" />
        <Metric label="Denials" value={counts.DENY || 0} sub="policy-enforced blocks" />
      </div>

      <Card title="Agent authorization control plane" action={<Tag>{Object.keys(profiles).length} policy profiles</Tag>}>
        <p className="mb-4 max-w-3xl text-sm leading-6 text-muted">
          Purpose-built visibility for agent runtime sessions and per-call authorization outcomes. This curated view sits on top of the same `/v1/agentic/sessions` and `/v1/agentic/invocations` APIs already enforced by the backend.
        </p>
        {resource.loading && !resource.data ? (
          <Empty>Loading agent runtime decisions…</Empty>
        ) : resource.error ? (
          <Empty>{resource.error}</Empty>
        ) : !sessions.length ? (
          <Empty>No agent runtime sessions have been created yet.</Empty>
        ) : (
          <div className="grid gap-4 lg:grid-cols-[0.92fr,1.08fr]">
            <div className="space-y-3">
              <input
                value={sessionQuery}
                onChange={(e) => setSessionQuery(e.target.value)}
                placeholder="Search session, artifact, profile"
                className="h-9 w-full rounded-md border border-slate-300 px-3 text-sm"
              />
              <div className="space-y-2">
                {filteredSessions.map((session) => (
                  <button
                    key={session.id}
                    type="button"
                    onClick={() => setSelectedSessionId(session.id)}
                    className={`w-full rounded-2xl border p-3 text-left transition ${
                      selectedSessionId === session.id
                        ? "border-emerald-400 bg-emerald-50/60 shadow-sm"
                        : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold text-ink">{session.artifact_id || "Unknown artifact"}</div>
                        <div className="mt-1 font-mono text-[11px] text-muted">{session.id}</div>
                      </div>
                      <Pill value={session.status || "UNKNOWN"} />
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Tag>{session.policy_profile || "custom policy"}</Tag>
                      <Tag>{session.external_calls_used || 0} external calls used</Tag>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              {!selectedSession ? (
                <Empty>Select a session to inspect authorization decisions.</Empty>
              ) : (
                <>
                  <Card title="Session posture" action={<Pill value={selectedSession.policy_profile || "custom"} />}>
                    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                      <Metric label="Status" value={selectedSession.status || "UNKNOWN"} sub={`created ${fmtDate(selectedSession.created_at)}`} />
                      <Metric label="External Call Budget" value={selectedSession.effective_policy?.max_external_calls ?? "—"} sub={`${selectedSession.external_calls_used || 0} used`} />
                      <Metric label="Declared Tools" value={(selectedSession.artifact?.tools || []).length} sub="tools on artifact" />
                      <Metric label="Workflow Steps" value={(selectedSession.artifact?.workflow_steps || selectedSession.artifact?.workflow || []).length || 0} sub={selectedSession.effective_policy?.require_workflow_step_binding ? "binding required" : "binding optional"} />
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm">
                        <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Effective policy</div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {(selectedSession.effective_policy?.allowed_tools || []).slice(0, 6).map((tool) => (
                            <Tag key={tool}>{tool}</Tag>
                          ))}
                          {!(selectedSession.effective_policy?.allowed_tools || []).length && <Tag>deny by default</Tag>}
                        </div>
                        <div className="mt-3 space-y-1 text-muted">
                          <div>Input validation for external tools: {selectedSession.effective_policy?.require_input_validation_for_external_tools ? "required" : "not required"}</div>
                          <div>Declared tools enforced: {selectedSession.effective_policy?.require_declared_tools ? "yes" : "no"}</div>
                          <div>Human review tools: {(selectedSession.effective_policy?.require_human_review_for_tools || []).join(", ") || "none"}</div>
                        </div>
                      </div>
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm">
                        <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Profile reference</div>
                        {profiles[selectedSession.policy_profile || ""] ? (
                          <>
                            <div className="mt-2 font-semibold text-ink">{profiles[selectedSession.policy_profile].name}</div>
                            <p className="mt-1 text-muted">{profiles[selectedSession.policy_profile].description}</p>
                          </>
                        ) : (
                          <p className="mt-2 text-muted">This session is using a custom or no-longer-listed profile.</p>
                        )}
                      </div>
                    </div>
                  </Card>

                  <Card
                    title="Authorization decisions"
                    action={
                      <select
                        value={decisionFilter}
                        onChange={(e) => setDecisionFilter(e.target.value)}
                        className="h-8 rounded-md border border-slate-300 bg-white px-2 text-xs"
                      >
                        <option value="">All decisions</option>
                        {DECISIONS.map((decision) => (
                          <option key={decision} value={decision}>{humanLabel(decision)}</option>
                        ))}
                      </select>
                    }
                  >
                    {!sessionInvocations.length ? (
                      <Empty>No recorded invocations for this session with the current filter.</Empty>
                    ) : (
                      <div className="space-y-3">
                        {sessionInvocations.map((invocation) => (
                          <div key={invocation.id} className="rounded-2xl border border-slate-200 bg-white p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <Pill value={invocation.decision || "UNKNOWN"} />
                              <span className="font-semibold text-ink">{invocation.tool || "tool"}</span>
                              {invocation.action ? <Tag>{invocation.action}</Tag> : null}
                              {invocation.external_call ? <Tag>external call</Tag> : null}
                              <span className="ml-auto text-xs text-muted">{fmtDate(invocation.created_at)}</span>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-2">
                              {(invocation.permissions || []).map((permission) => (
                                <Tag key={permission}>{permission}</Tag>
                              ))}
                              {invocation.workflow_step_id ? <Tag>{invocation.workflow_step_id}</Tag> : null}
                              {invocation.approval_id ? <Tag>approval {invocation.approval_id}</Tag> : null}
                            </div>
                            {(invocation.reasons || []).length ? (
                              <ul className="mt-3 space-y-2">
                                {invocation.reasons.map((reason, index) => (
                                  <li key={index} className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-sm">
                                    <div className="font-medium text-ink">{humanLabel(reason.code || "reason")}</div>
                                    <div className="mt-1 text-muted">{reason.detail || "No detail provided."}</div>
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <div className="mt-3 text-sm text-muted">No blocking or approval reasons were recorded for this decision.</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </>
              )}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

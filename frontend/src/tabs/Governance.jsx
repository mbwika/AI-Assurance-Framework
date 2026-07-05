import { useMemo, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Metric, Pill, Empty, Tag, fmtDate, humanLabel } from "../ui.jsx";

export default function Governance({ refreshToken }) {
  const [riskRefreshToken, setRiskRefreshToken] = useState(0);
  const [savingRiskId, setSavingRiskId] = useState("");
  const [drafts, setDrafts] = useState({});
  const [feedback, setFeedback] = useState({});
  const { loading, error, data } = useResource(
    () => Promise.all([api.assuranceReport(), api.compliance(), api.risks(200)]),
    [refreshToken, riskRefreshToken]
  );
  const riskPayload = data ? data[2] : null;
  // Hooks must run unconditionally on every render, so this has to sit above
  // the loading/error early returns below rather than after them.
  const risks = useMemo(() => {
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return [...((riskPayload && riskPayload.risks) || [])].sort((a, b) => {
      const left = severityOrder[String(a.severity || "LOW").toUpperCase()] ?? 9;
      const right = severityOrder[String(b.severity || "LOW").toUpperCase()] ?? 9;
      if (left !== right) return left - right;
      return String(a.due_at || "9999-12-31T23:59:59Z").localeCompare(String(b.due_at || "9999-12-31T23:59:59Z"));
    });
  }, [riskPayload]);

  if (loading && !data) return <Empty>Loading governance and compliance evidence…</Empty>;
  if (error) return <Empty>{error}. A portfolio governance evaluation may not exist yet.</Empty>;

  const [report, compliance] = data;
  const gov = report.governance || {};
  const summary = gov.control_summary || {};
  const byStatus = summary.by_status || {};
  const frameworks = compliance.frameworks || {};
  const gaps = compliance.open_control_gaps || [];
  const riskSummary = (riskPayload && riskPayload.summary) || {};

  function frameworkLink(name, url) {
    if (!url) return <span className="font-bold">{name}</span>;
    return (
      <a href={url} target="_blank" rel="noreferrer" className="font-bold text-accent-strong hover:underline">
        {name}
      </a>
    );
  }

  function referenceTag(detail, fallback, index) {
    const label = detail?.label || fallback;
    const href = detail?.url || detail?.framework_url || "#";
    const title = detail?.summary || label;
    if (href && href !== "#") {
      return (
        <a
          key={index}
          href={href}
          target="_blank"
          rel="noreferrer"
          title={title}
          className="inline-flex items-center rounded-full border border-slate-300 bg-slate-50 px-2 py-0.5 text-[11px] font-semibold text-slate-700 hover:border-slate-400 hover:bg-slate-100"
        >
          {label}
        </a>
      );
    }
    return <Tag key={index}>{label}</Tag>;
  }

  function draftFor(risk) {
    return (
      drafts[risk.id] || {
        status: risk.status || "OPEN",
        owner: risk.owner || "",
        due_at: toLocalInputValue(risk.due_at),
        resolution: risk.resolution || "",
      }
    );
  }

  function updateDraft(riskId, patch) {
    setDrafts((current) => ({
      ...current,
      [riskId]: {
        ...(current[riskId] || {}),
        ...patch,
      },
    }));
  }

  async function saveRisk(risk) {
    const draft = draftFor(risk);
    setSavingRiskId(risk.id);
    setFeedback((current) => ({ ...current, [risk.id]: "" }));
    try {
      await api.updateRisk(risk.id, {
        status: draft.status,
        owner: draft.owner.trim() || null,
        due_at: draft.due_at ? new Date(draft.due_at).toISOString() : null,
        resolution: draft.resolution.trim() || null,
      });
      setFeedback((current) => ({ ...current, [risk.id]: "Saved" }));
      setRiskRefreshToken((n) => n + 1);
    } catch (e) {
      setFeedback((current) => ({ ...current, [risk.id]: e.message }));
    } finally {
      setSavingRiskId("");
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Status" value={<Pill value={gov.status || "NO_EVIDENCE"} />} sub="latest evaluation" />
        <Metric label="Satisfied" value={byStatus.satisfied || 0} sub={`of ${summary.total_controls || 0} controls`} />
        <Metric label="Open Gaps" value={(gov.open_gaps || []).length} sub="missing evidence" />
        <Metric
          label="Priority Risks"
          value={((riskSummary.by_severity || {}).CRITICAL || 0) + ((riskSummary.by_severity || {}).HIGH || 0)}
          sub={`${riskSummary.overdue_risks || 0} overdue`}
        />
      </div>

      <Card title="Per-framework compliance coverage">
        <p className="mb-3 text-sm text-muted">Evidence completeness against the AIAF control catalog — not a certification.</p>
        <div className="overflow-auto rounded-lg border border-slate-200">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="p-2.5">Framework</th>
                <th className="p-2.5">Version</th>
                <th className="p-2.5">Status</th>
                <th className="p-2.5">Applicable</th>
                <th className="p-2.5">Satisfied</th>
                <th className="p-2.5">Missing</th>
                <th className="p-2.5">Coverage</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(frameworks).map(([name, f]) => (
                <tr key={name} className="border-t border-slate-100">
                  <td className="p-2.5">{frameworkLink(name, f.source_url || "")}</td>
                  <td className="p-2.5 font-mono text-xs">{f.version || ""}</td>
                  <td className="p-2.5"><Pill value={f.status || ""} /></td>
                  <td className="p-2.5 font-mono">{f.applicable_controls ?? 0}</td>
                  <td className="p-2.5 font-mono">{f.satisfied_controls ?? 0}</td>
                  <td className="p-2.5 font-mono">{f.missing_controls ?? 0}</td>
                  <td className="p-2.5">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-20 overflow-hidden rounded-full bg-slate-200">
                        <div className="h-full rounded-full bg-accent" style={{ width: `${Number(f.coverage_percent) || 0}%` }} />
                      </div>
                      <span className="tabular-nums text-muted">{f.coverage_percent ?? 0}%</span>
                    </div>
                  </td>
                </tr>
              ))}
              {!Object.keys(frameworks).length && (
                <tr><td colSpan={7} className="p-2.5 text-muted">No frameworks in scope.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Open control gaps">
        {gaps.length ? (
          <div className="divide-y divide-slate-100">
            {gaps.map((g, i) => (
              <div key={i} className="flex items-start justify-between gap-3 py-3 text-sm">
                <div>
                  <div className="font-semibold">{g.control_id} — {g.title}</div>
                  <div className="mt-1 text-xs text-muted">
                    {frameworkLink(g.framework, g.framework_source_url || "")}
                  </div>
                  <div className="mt-1 text-xs text-muted">
                    Missing evidence: {(g.missing_evidence || []).join(", ") || "Unspecified"}
                  </div>
                </div>
                <div className="flex flex-wrap gap-1">
                  {(g.reference_details || []).map((detail, j) => referenceTag(detail, detail.label, j))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">No open control gaps for the evaluated scope.</p>
        )}
      </Card>

      <Card title="Managed risk register" action={<Tag>{risks.length} tracked</Tag>}>
        <p className="mb-3 text-sm text-muted">
          Assign owners, set remediation due dates, and move risks through their lifecycle without leaving the framework.
        </p>
        {!risks.length ? (
          <Empty>No managed risks have been recorded yet.</Empty>
        ) : (
          <div className="overflow-auto rounded-lg border border-slate-200">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="p-2.5">Risk</th>
                  <th className="p-2.5">Artifact</th>
                  <th className="p-2.5">Severity</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5">Owner</th>
                  <th className="p-2.5">Due</th>
                  <th className="p-2.5">Resolution</th>
                  <th className="p-2.5">Action</th>
                </tr>
              </thead>
              <tbody>
                {risks.map((risk) => {
                  const draft = draftFor(risk);
                  const saving = savingRiskId === risk.id;
                  return (
                    <tr key={risk.id} className="border-t border-slate-100 align-top">
                      <td className="p-2.5">
                        <div className="font-semibold text-ink">{risk.title || risk.indicator || risk.finding_type}</div>
                        <div className="text-xs text-muted">{risk.finding_type} · seen {fmtDate(risk.last_seen_at)}</div>
                      </td>
                      <td className="p-2.5 font-mono text-xs">{risk.artifact_id || "Unknown"}</td>
                      <td className="p-2.5"><Pill value={risk.severity || "UNKNOWN"} /></td>
                      <td className="p-2.5">
                        <select
                          value={draft.status}
                          onChange={(e) => updateDraft(risk.id, { status: e.target.value })}
                          className="h-9 rounded-md border border-slate-300 bg-white px-2 text-sm"
                        >
                          {["OPEN", "IN_PROGRESS", "ACCEPTED", "RESOLVED"].map((status) => (
                            <option key={status} value={status}>
                              {humanLabel(status)}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="p-2.5">
                        <input
                          value={draft.owner}
                          onChange={(e) => updateDraft(risk.id, { owner: e.target.value })}
                          placeholder="Assign owner"
                          className="h-9 w-40 rounded-md border border-slate-300 bg-white px-2 text-sm"
                        />
                      </td>
                      <td className="p-2.5">
                        <input
                          type="datetime-local"
                          value={draft.due_at}
                          onChange={(e) => updateDraft(risk.id, { due_at: e.target.value })}
                          className="h-9 rounded-md border border-slate-300 bg-white px-2 text-sm"
                        />
                      </td>
                      <td className="p-2.5">
                        <input
                          value={draft.resolution}
                          onChange={(e) => updateDraft(risk.id, { resolution: e.target.value })}
                          placeholder={draft.status === "RESOLVED" || draft.status === "ACCEPTED" ? "Resolution rationale required" : "Optional until accepted/resolved"}
                          className="h-9 w-56 rounded-md border border-slate-300 bg-white px-2 text-sm"
                        />
                      </td>
                      <td className="p-2.5">
                        <button
                          onClick={() => saveRisk(risk)}
                          disabled={saving}
                          className="h-9 rounded-md bg-accent px-3 text-sm font-semibold text-white transition hover:bg-accent-strong disabled:cursor-wait disabled:opacity-60"
                        >
                          {saving ? "Saving…" : "Save"}
                        </button>
                        {feedback[risk.id] && (
                          <div className={`mt-2 text-xs ${feedback[risk.id] === "Saved" ? "text-emerald-700" : "text-red-600"}`}>
                            {feedback[risk.id]}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function toLocalInputValue(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

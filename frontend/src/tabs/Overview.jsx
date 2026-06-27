import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Metric, Pill, Empty, Tag, humanLabel } from "../ui.jsx";
import { TrendLine, SeverityBars } from "../charts.jsx";

const SNAPSHOT_AUTHOR_STORAGE = "aiaf_report_snapshot_author";

function worstSeverity(bySeverity) {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find((s) => Number((bySeverity || {})[s]) > 0) || "NONE";
}

function DriftBadge({ drift }) {
  if (!drift || !drift.status) return null;
  return (
    <span className="flex items-center gap-2 text-xs text-muted">
      drift <Pill value={drift.status} />
    </span>
  );
}

export default function Overview({ refreshToken }) {
  const [scopeMode, setScopeMode] = useState("portfolio");
  const [selectedModelId, setSelectedModelId] = useState("");
  const [selectedRegistrant, setSelectedRegistrant] = useState("");
  const [createdBy, setCreatedBy] = useState(() => localStorage.getItem(SNAPSHOT_AUTHOR_STORAGE) || "");
  const [busyAction, setBusyAction] = useState("");
  const [snapshotResult, setSnapshotResult] = useState(null);
  const registry = useResource(() => api.models(500), [refreshToken]);
  const models = (registry.data && registry.data.models) || [];
  const registrants = useMemo(
    () =>
      [...new Set(models.map((model) => (model.registered_by || "").trim()).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b)
      ),
    [models]
  );

  useEffect(() => {
    if (scopeMode === "model" && !selectedModelId && models.length) {
      setSelectedModelId(models[0].model_id || "");
    }
  }, [scopeMode, selectedModelId, models]);

  useEffect(() => {
    if (scopeMode === "registrant" && !selectedRegistrant && registrants.length) {
      setSelectedRegistrant(registrants[0]);
    }
  }, [scopeMode, selectedRegistrant, registrants]);

  const requestedScope = useMemo(() => {
    if (scopeMode === "model" && selectedModelId) return { model_id: selectedModelId };
    if (scopeMode === "registrant" && selectedRegistrant) return { registered_by: selectedRegistrant };
    return {};
  }, [scopeMode, selectedModelId, selectedRegistrant]);
  const scopeKey = JSON.stringify(requestedScope);
  const { loading, error, data } = useResource(
    () => Promise.all([api.assuranceReport(requestedScope), api.metrics(500, requestedScope)]),
    [refreshToken, scopeKey]
  );

  if (loading && !data) return <Empty>Loading the assurance report…</Empty>;
  if (error) return <Empty>{error}. Check the API key, then Refresh.</Empty>;

  const [report, metrics] = data;
  const posture = report.risk_posture || {};
  const gov = report.governance || {};
  const summary = gov.control_summary || {};
  const byStatus = summary.by_status || {};
  const trust = report.trustworthiness || {};
  const monitoring = report.continuous_monitoring || {};
  const alerts = (report.monitoring_alerts || {}).alerts || [];
  const supply = report.supply_chain || {};
  const standards = report.standards_coverage || {};
  const technical = report.technical_explainability || {};
  const series = metrics.series || {};
  const reportScope = report.scope || {};
  const questions = report.assurance_questions || {};
  const selectedModel = models.find((model) => model.model_id === selectedModelId) || null;
  const inventory = report.model_inventory || {};
  const scopeLabel =
    reportScope.type === "MODEL"
      ? `model ${reportScope.model_id}`
      : reportScope.type === "REGISTRANT"
        ? `registrant ${reportScope.registered_by}`
        : reportScope.type === "ARTIFACT"
          ? `artifact ${reportScope.artifact_id}`
          : "portfolio";

  const scopeSynced =
    (scopeMode === "portfolio" && reportScope.type === "PORTFOLIO") ||
    (scopeMode === "model" && reportScope.type === "MODEL" && reportScope.model_id === selectedModelId) ||
    (
      scopeMode === "registrant" &&
      reportScope.type === "REGISTRANT" &&
      reportScope.registered_by === selectedRegistrant
    );
  const exportReady =
    !loading &&
    scopeSynced &&
    (
      scopeMode === "portfolio" ||
      (scopeMode === "model" && Boolean(selectedModelId)) ||
      (scopeMode === "registrant" && Boolean(selectedRegistrant))
    );

  function filename(ext) {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const suffix =
      reportScope.type === "MODEL"
        ? `model-${String(reportScope.model_id || "unknown").replace(/[^a-z0-9._-]+/gi, "-")}`
        : reportScope.type === "REGISTRANT"
          ? `registrant-${String(reportScope.registered_by || "unknown").replace(/[^a-z0-9._-]+/gi, "-")}`
          : reportScope.type === "ARTIFACT"
            ? `artifact-${String(reportScope.artifact_id || "unknown").replace(/[^a-z0-9._-]+/gi, "-")}`
            : "portfolio";
    return `aiaf-assurance-report-${suffix}-${stamp}.${ext}`;
  }

  function download(content, mimeType, name) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
  }

  async function exportJson() {
    if (!exportReady) return;
    setBusyAction("json");
    setSnapshotResult(null);
    try {
      download(JSON.stringify(report, null, 2), "application/json", filename("json"));
    } finally {
      setBusyAction("");
    }
  }

  async function exportMarkdown() {
    if (!exportReady) return;
    setBusyAction("markdown");
    setSnapshotResult(null);
    try {
      const markdown = await api.assuranceReportMarkdown(requestedScope);
      download(markdown, "text/markdown;charset=utf-8", filename("md"));
    } catch (e) {
      setSnapshotResult({ status: "error", message: e.message });
    } finally {
      setBusyAction("");
    }
  }

  async function exportHtml() {
    if (!exportReady) return;
    setBusyAction("html");
    setSnapshotResult(null);
    try {
      const html = await api.assuranceReportHtml(requestedScope);
      download(html, "text/html;charset=utf-8", filename("html"));
    } catch (e) {
      setSnapshotResult({ status: "error", message: e.message });
    } finally {
      setBusyAction("");
    }
  }

  async function createSnapshot() {
    const author = createdBy.trim();
    if (!author) {
      setSnapshotResult({ status: "error", message: "Add a prepared-by name before saving a snapshot." });
      return;
    }

    setBusyAction("snapshot");
    setSnapshotResult(null);
    localStorage.setItem(SNAPSHOT_AUTHOR_STORAGE, author);
    try {
      const payload = {
        created_by: author,
        sign: false,
      };
      if (reportScope.type === "MODEL") payload.model_id = reportScope.model_id;
      if (reportScope.type === "REGISTRANT") payload.registered_by = reportScope.registered_by;
      if (reportScope.type === "ARTIFACT") payload.artifact_id = reportScope.artifact_id;
      const snapshot = await api.createReportSnapshot({
        ...payload,
      });
      setSnapshotResult({
        status: "success",
        message: `Snapshot ${snapshot.snapshot_id || snapshot.id || "created"} saved with digest ${String(snapshot.sha256 || "").slice(0, 12)}.`,
      });
    } catch (e) {
      setSnapshotResult({ status: "error", message: e.message });
    } finally {
      setBusyAction("");
    }
  }

  return (
    <div className="space-y-4">
      <Card
        className="overflow-hidden border-slate-200/80 bg-[radial-gradient(circle_at_top_left,_rgba(211,237,233,0.8),_transparent_36%),linear-gradient(180deg,_rgba(255,255,255,1),_rgba(248,251,249,1))]"
        title="Assurance report"
        action={<Tag>{scopeLabel}</Tag>}
      >
        <div className="grid gap-4 lg:grid-cols-[1.2fr,0.8fr]">
          <div>
            <p className="max-w-2xl text-sm leading-6 text-muted">
              Build an assurance brief for the full portfolio, one model, or one registrant. The report is organized to answer provenance, integrity, risk, governance, and monitoring questions with evidence drawn from the live framework state.
            </p>
            <div className="mt-4 rounded-2xl border border-slate-200/80 bg-white/90 p-4 shadow-sm">
              <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Report scope</div>
              <div className="mt-3 flex flex-wrap gap-2">
                {[
                  ["portfolio", "Portfolio"],
                  ["model", "One model"],
                  ["registrant", "One registrant"],
                ].map(([value, label]) => (
                  <button
                    key={value}
                    onClick={() => {
                      if (value === "model" && !selectedModelId && models.length) {
                        setSelectedModelId(models[0].model_id || "");
                      }
                      if (value === "registrant" && !selectedRegistrant && registrants.length) {
                        setSelectedRegistrant(registrants[0]);
                      }
                      setScopeMode(value);
                      setSnapshotResult(null);
                    }}
                    className={`h-9 rounded-full border px-4 text-sm font-semibold transition ${
                      scopeMode === value
                        ? "border-emerald-600 bg-emerald-600 text-white"
                        : "border-slate-300 bg-white text-slate-700 hover:border-slate-400 hover:bg-slate-50"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {scopeMode === "model" && (
                <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr),auto] md:items-end">
                  <label className="block">
                    <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Model ID</span>
                    <select
                      value={selectedModelId}
                      onChange={(e) => setSelectedModelId(e.target.value)}
                      className="mt-1 h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
                    >
                      {!models.length && <option value="">No models available</option>}
                      {models.map((model) => (
                        <option key={model.model_id} value={model.model_id}>
                          {model.model_id}
                          {model.model_name ? ` — ${model.model_name}` : ""}
                        </option>
                      ))}
                    </select>
                  </label>
                  {selectedModel && (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                      {selectedModel.publisher || "Undeclared publisher"} · {selectedModel.risk_level || "UNKNOWN"}
                    </div>
                  )}
                </div>
              )}
              {scopeMode === "registrant" && (
                <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr),auto] md:items-end">
                  <label className="block">
                    <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Registered by</span>
                    <select
                      value={selectedRegistrant}
                      onChange={(e) => setSelectedRegistrant(e.target.value)}
                      className="mt-1 h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
                    >
                      {!registrants.length && <option value="">No registrants available</option>}
                      {registrants.map((registrant) => (
                        <option key={registrant} value={registrant}>
                          {registrant}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                    {inventory.total_models || 0} models currently in scope
                  </div>
                </div>
              )}
              {registry.error && (
                <p className="mt-3 text-sm text-amber-700">
                  Model registry data could not be loaded for scope pickers: {registry.error}
                </p>
              )}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                onClick={exportHtml}
                disabled={busyAction !== "" || !exportReady}
                className="h-10 rounded-xl bg-ink px-4 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-wait disabled:opacity-60"
              >
                {busyAction === "html" ? "Building HTML report…" : "Export HTML report"}
              </button>
              <button
                onClick={exportJson}
                disabled={busyAction !== "" || !exportReady}
                className="h-10 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-slate-50 disabled:cursor-wait disabled:opacity-60"
              >
                {busyAction === "json" ? "Exporting JSON…" : "Export JSON"}
              </button>
              <button
                onClick={exportMarkdown}
                disabled={busyAction !== "" || !exportReady}
                className="h-10 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-slate-50 disabled:cursor-wait disabled:opacity-60"
              >
                {busyAction === "markdown" ? "Building Markdown…" : "Export Markdown"}
              </button>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {Object.entries(questions).map(([key, item]) => (
                <div key={key} className="rounded-xl border border-slate-200 bg-white/90 p-3">
                  <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
                    {key.replaceAll("_", " ")}
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-700">{item.answer}</p>
                </div>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Tag>{report.report_type || "AI Assurance Compliance Report"}</Tag>
              <Tag>{gov.status || "NO_EVIDENCE"}</Tag>
              <Tag>{(report.monitoring_alerts || {}).status || "NO_ALERTS"}</Tag>
            </div>
          </div>

          <div className="rounded-2xl border border-white/90 bg-white/88 p-4 shadow-sm">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Snapshot retention</div>
            <p className="mt-2 text-sm leading-6 text-muted">
              Save the current report as an append-only record with a canonical digest for later verification.
            </p>
            <label className="mt-4 block text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
              Prepared by
            </label>
            <input
              value={createdBy}
              onChange={(e) => setCreatedBy(e.target.value)}
              placeholder="analyst@example.test"
              className="mt-1 h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
            />
            <button
              onClick={createSnapshot}
              disabled={busyAction !== "" || !exportReady}
              className="mt-3 h-10 w-full rounded-xl bg-accent px-4 text-sm font-semibold text-white transition hover:bg-accent-strong disabled:cursor-wait disabled:opacity-60"
            >
              {busyAction === "snapshot" ? "Saving snapshot…" : "Create report snapshot"}
            </button>
            {snapshotResult && (
              <p className={`mt-3 text-sm ${snapshotResult.status === "error" ? "text-red-600" : "text-emerald-700"}`}>
                {snapshotResult.message}
              </p>
            )}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Risk Posture" value={<Pill value={worstSeverity(posture.by_severity)} />} sub={`${posture.finding_items || 0} findings`} />
        <Metric label="Governance" value={<Pill value={gov.status || "NO_EVIDENCE"} />} sub={`${byStatus.satisfied || 0} satisfied / ${summary.total_controls || 0}`} />
        <Metric label="Trustworthiness" value={trust.latest_level || "NO_DATA"} sub={`score ${trust.latest_score ?? 0}`} />
        <Metric label="Open Alerts" value={alerts.length} sub={alerts.length ? <Pill value={(report.monitoring_alerts || {}).status || "ALERTS"} /> : "All clear"} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Aggregate risk score over time" action={<DriftBadge drift={monitoring.drift} />}>
          <TrendLine points={series.risk_score} domain={[0, 10]} color="#b42318" />
        </Card>
        <Card title="Trustworthiness over time" action={<DriftBadge drift={trust.drift} />}>
          <TrendLine points={series.trustworthiness_score} domain={[0, 100]} color="#0f766e" />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Findings by severity">
          <SeverityBars counts={posture.by_severity} severityColors />
        </Card>
        <Card title="Findings by type">
          <SeverityBars counts={posture.by_type} />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Control coverage by domain">
          <DomainCoverage byDomain={summary.by_domain} />
        </Card>
        <Card title="Standards coverage">
          <StandardsCoverage coverage={standards} />
        </Card>
      </div>

      <Card title="Monitoring alerts" action={<span className="text-xs text-muted">{alerts.length ? `${alerts.length} active` : ""}</span>}>
        {alerts.length ? (
          <div className="divide-y divide-slate-100">
            {alerts.map((a, i) => (
              <div key={i} className="flex items-start gap-3 py-2.5">
                <Pill value={a.severity} />
                <div className="flex-1">
                  <div className="text-sm">{a.message || a.id}</div>
                  <div className="text-xs text-muted">{a.id}</div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">No monitoring alerts.</p>
        )}
      </Card>

      <Card title="Supply-chain integrity">
        <Rows
          rows={[
            ["Advisory feed status", <Pill value={supply.advisory_feed_status || "NO_DATA"} />],
            ["Verified advisory feeds", supply.verified_advisory_feeds ?? 0],
            ["Known vulnerability matches", supply.known_vulnerability_matches ?? 0],
            ["Models with provenance attestations", supply.models_with_provenance_attestations ?? 0],
            ["Models with vulnerability scans", supply.models_with_vulnerability_scans ?? 0],
          ]}
        />
      </Card>

      <Card title="Technical explainability">
        <p className="text-sm leading-6 text-muted">
          This is the evidence trail behind the scores. AIAF hashes uploaded or fetched artifacts and can inspect dependency manifests, but LLM06-style agency findings come from declared authority, workflow, policy, runtime evidence, and control records rather than reverse-engineering model weights.
        </p>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Evidence summary</div>
            <Rows
              rows={[
                ["Artifacts summarized", technical.summary?.artifact_count ?? 0],
                ["Registry records", technical.summary?.registry_record_count ?? 0],
                ["Governance evaluations", technical.summary?.governance_evaluation_count ?? 0],
                ["Control evidence records", technical.summary?.control_evidence_count ?? 0],
              ]}
            />
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Where AIAF reads from</div>
            <div className="mt-3 space-y-2">
              {(technical.analysis_basis?.storage_locations || []).map((item) => (
                <div key={item.name} className="rounded-md border border-slate-200 bg-white p-3">
                  <div className="text-sm font-semibold text-ink">{item.name}</div>
                  <div className="mt-1 text-xs font-medium uppercase tracking-wide text-slate-500">{item.location}</div>
                  <div className="mt-1 text-sm text-muted">{item.details}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-4 space-y-3">
          {(technical.artifacts || []).length ? (
            technical.artifacts.map((artifact) => (
              <details key={artifact.artifact_id} className="rounded-lg border border-slate-200 bg-white p-4">
                <summary className="cursor-pointer list-none">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-bold text-ink">{artifact.model_name || artifact.artifact_id}</div>
                      <div className="text-xs text-muted">{artifact.artifact_id}</div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Tag>{artifact.registry_record_present ? "Registry record present" : "No registry record"}</Tag>
                      {artifact.provenance?.risk_level && <Pill value={artifact.provenance.risk_level} />}
                    </div>
                  </div>
                </summary>
                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <ExplainabilityTable
                    title="Registry fields"
                    rows={artifact.declarations?.registry_fields || []}
                  />
                  <ExplainabilityTable
                    title={`Agentic declarations (${artifact.declarations?.present_count ?? 0}/${artifact.declarations?.total_count ?? 0})`}
                    rows={artifact.declarations?.fields || []}
                  />
                </div>
                <div className="mt-4 grid gap-4 xl:grid-cols-2">
                  <ProvenancePanel provenance={artifact.provenance || {}} />
                  <GovernanceExplainability governance={artifact.governance || {}} />
                </div>
                <div className="mt-4 space-y-4">
                  {(artifact.findings || []).length ? (
                    artifact.findings.map((finding, index) => (
                      <FindingExplainability key={`${artifact.artifact_id}-${finding.finding_type}-${index}`} finding={finding} />
                    ))
                  ) : (
                    <Empty>No persisted analyzer findings are currently linked to this artifact.</Empty>
                  )}
                </div>
              </details>
            ))
          ) : (
            <Empty>No technical explainability data is available for the current scope yet.</Empty>
          )}
        </div>
      </Card>
    </div>
  );
}

function Rows({ rows }) {
  return (
    <div className="divide-y divide-slate-100">
      {rows.map(([label, value], i) => (
        <div key={i} className="flex items-center justify-between py-2 text-sm">
          <span className="font-semibold text-ink">{label}</span>
          <span className="text-muted">{value}</span>
        </div>
      ))}
    </div>
  );
}

function DomainCoverage({ byDomain }) {
  const rows = Object.entries(byDomain || {});
  if (!rows.length) return <Empty>No control evaluation yet.</Empty>;
  return (
    <div className="space-y-2">
      {rows.map(([domain, st]) => {
        const total = Object.values(st).reduce((a, b) => a + b, 0);
        const na = st.not_applicable || 0;
        const applicable = total - na;
        const pct = applicable ? Math.round(((st.satisfied || 0) / applicable) * 100) : 100;
        return (
          <div key={domain} className="flex items-center gap-3">
            <span className="w-48 shrink-0 truncate text-sm" title={domain}>{domain}</span>
            <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-200">
              <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
            </div>
            <span className="w-10 text-right text-sm tabular-nums text-muted">{pct}%</span>
          </div>
        );
      })}
    </div>
  );
}

function StandardsCoverage({ coverage }) {
  const all = coverage.frameworks || [];
  const covered = coverage.covered_frameworks || [];
  if (!all.length) return <Empty>No standards data.</Empty>;
  return (
    <div className="divide-y divide-slate-100">
      {all.map((f) => (
        <div key={f} className="flex items-center justify-between py-2 text-sm">
          <span className="font-semibold text-ink">{f}</span>
          <Pill value={covered.includes(f) ? "covered" : "uncovered"} />
        </div>
      ))}
    </div>
  );
}

function ExplainabilityTable({ title, rows }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">{title}</div>
      {rows.length ? (
        <div className="mt-3 overflow-auto rounded-md border border-slate-200 bg-white">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="p-2.5">Field</th>
                <th className="p-2.5">Present</th>
                <th className="p-2.5">Summary</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.field} className="border-t border-slate-100 align-top">
                  <td className="p-2.5 font-medium text-ink">{row.field}</td>
                  <td className="p-2.5"><Pill value={row.present ? "pass" : "missing"} /></td>
                  <td className="p-2.5 text-muted">{row.summary || "Not declared"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>No fields recorded.</Empty>
      )}
    </div>
  );
}

function ProvenancePanel({ provenance }) {
  const dimensions = provenance.dimensions || [];
  const trustCaps = provenance.trust_caps || [];
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Provenance scoring</div>
          <div className="mt-2 text-sm text-muted">
            Score {provenance.provenance_score ?? "N/A"}{provenance.risk_level ? ` · ${humanLabel(provenance.risk_level)}` : ""}
          </div>
        </div>
        {provenance.risk_level && <Pill value={provenance.risk_level} />}
      </div>
      {dimensions.length ? (
        <div className="mt-3 overflow-auto rounded-md border border-slate-200 bg-white">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="p-2.5">Dimension</th>
                <th className="p-2.5">Score</th>
                <th className="p-2.5">Lower</th>
                <th className="p-2.5">Upper</th>
                <th className="p-2.5">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {dimensions.map((dimension) => (
                <tr key={dimension.name} className="border-t border-slate-100">
                  <td className="p-2.5 font-medium text-ink">{dimension.name}</td>
                  <td className="p-2.5 text-muted">{fmtNumber(dimension.score)}</td>
                  <td className="p-2.5 text-muted">{fmtNumber(dimension.lower_bound)}</td>
                  <td className="p-2.5 text-muted">{fmtNumber(dimension.upper_bound)}</td>
                  <td className="p-2.5 text-muted">{fmtNumber(dimension.confidence)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>No provenance dimension breakdown is available.</Empty>
      )}
      <div className="mt-3">
        <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Trust caps</div>
        {trustCaps.length ? (
          <div className="mt-2 space-y-2">
            {trustCaps.map((cap) => (
              <div key={`${cap.gate}-${cap.maximum_score}`} className="rounded-md border border-slate-200 bg-white p-3 text-sm">
                <div className="font-semibold text-ink">{cap.gate}</div>
                <div className="mt-1 text-muted">Maximum score {cap.maximum_score}</div>
                <div className="mt-1 text-muted">{cap.reason}</div>
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-sm text-muted">No trust caps currently suppress the score.</p>
        )}
      </div>
    </div>
  );
}

function GovernanceExplainability({ governance }) {
  const missingControls = governance.missing_controls || [];
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Missing control rationale</div>
          <div className="mt-2 text-sm text-muted">
            Latest governance status {humanLabel(governance.status || "NO_EVALUATION")}
          </div>
        </div>
        <Pill value={governance.status || "NO_EVALUATION"} />
      </div>
      {missingControls.length ? (
        <div className="mt-3 space-y-2">
          {missingControls.map((control) => (
            <div key={control.control_id} className="rounded-md border border-slate-200 bg-white p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold text-ink">{control.control_id}</span>
                <Tag>{control.domain || "Unspecified"}</Tag>
              </div>
              <div className="mt-1 text-sm text-ink">{control.title}</div>
              <div className="mt-1 text-sm text-muted">{control.why_missing}</div>
            </div>
          ))}
        </div>
      ) : (
        <p className="mt-3 text-sm text-muted">No missing controls in the latest governance evaluation.</p>
      )}
    </div>
  );
}

function FindingExplainability({ finding }) {
  const dimensions = finding.dimensions || [];
  const interactions = finding.interactions || [];
  const factors = finding.triggered_factors || [];
  const controls = finding.control_assessment?.controls || [];
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">{finding.finding_type?.replaceAll("_", " ")}</div>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className="text-lg font-semibold text-ink">{fmtNumber(finding.risk_score)}</span>
            <Pill value={finding.severity || "UNKNOWN"} />
            {finding.confidence != null && <Tag>confidence {fmtNumber(finding.confidence)}</Tag>}
            {finding.methodology && <Tag>{finding.methodology}</Tag>}
          </div>
        </div>
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <ExplainabilityMetricTable
          title="Dimension breakdown"
          columns={["Dimension", "Score", "Value", "Extra"]}
          rows={dimensions.map((dimension) => [
            dimension.name,
            fmtNumber(dimension.score),
            dimension.value ?? "—",
            dimension.risk_count ?? "—",
          ])}
          empty="No dimension breakdown available."
        />
        <ExplainabilityMetricTable
          title="Exact triggered interaction factors"
          columns={["Indicator", "Severity", "Bonus", "Detail"]}
          rows={interactions.map((item) => [
            item.indicator,
            humanLabel(item.severity),
            fmtNumber(item.bonus),
            item.detail,
          ])}
          empty="No interaction escalations were triggered."
        />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <ExplainabilityMetricTable
          title="Triggered factors"
          columns={["Indicator", "Category", "Severity", "Detail"]}
          rows={factors.slice(0, 25).map((item) => [
            item.indicator,
            item.dimension,
            humanLabel(item.severity),
            item.detail,
          ])}
          empty="No additional triggered factors were recorded."
        />
        <ExplainabilityMetricTable
          title="Residual-risk controls"
          columns={["Control", "Status", "Strength", "Evidence quality"]}
          rows={controls.map((item) => [
            item.control,
            humanLabel(item.status),
            fmtNumber(item.strength),
            fmtNumber(item.evidence_quality),
          ])}
          empty="No residual-risk control assessment is available."
        />
      </div>
    </div>
  );
}

function ExplainabilityMetricTable({ title, columns, rows, empty }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3">
      <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">{title}</div>
      {rows.length ? (
        <div className="mt-3 overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                {columns.map((column) => (
                  <th key={column} className="p-2.5">{column}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${title}-${index}`} className="border-t border-slate-100 align-top">
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="p-2.5 text-muted">{cell ?? "—"}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-3 text-sm text-muted">{empty}</p>
      )}
    </div>
  );
}

function fmtNumber(value) {
  if (value == null || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number) ? String(Number(number.toFixed(3))) : String(value);
}

import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Metric, Pill, Empty, fmtDate } from "../ui.jsx";

// ---------------------------------------------------------------------------
// Terminal log viewer for a single job
// ---------------------------------------------------------------------------

function JobTerminal({ jobId }) {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState("PENDING");
  const [result, setResult] = useState({});
  const [open, setOpen] = useState(true);
  const bottomRef = useRef(null);
  const active = status === "PENDING" || status === "RUNNING";

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const data = await api.jobLogs(jobId);
        if (cancelled) return;
        setLogs(data.logs || []);
        setStatus(data.status || "UNKNOWN");
        setResult(data.result || {});
      } catch {
        /* keep polling */
      }
    }

    poll();
    if (active) {
      const id = setInterval(poll, 2000);
      return () => { cancelled = true; clearInterval(id); };
    }
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, active]);

  // Auto-scroll terminal to bottom as new lines arrive
  useEffect(() => {
    if (open && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, open]);

  const statusColor = {
    COMPLETED: "text-emerald-400",
    FAILED: "text-red-400",
    RUNNING: "text-amber-400",
    PENDING: "text-slate-400",
  }[status] ?? "text-slate-400";

  return (
    <div className="rounded-lg border border-slate-200 overflow-hidden">
      {/* Header row */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between bg-slate-800 px-4 py-2 text-left"
      >
        <div className="flex items-center gap-3">
          <span className={`text-xs font-bold uppercase tracking-widest ${statusColor}`}>
            {status}
          </span>
          <span className="font-mono text-xs text-slate-300">{jobId}</span>
          {result.model_id && (
            <span className="text-xs text-emerald-400">→ {result.model_id}</span>
          )}
        </div>
        <span className="text-slate-400 text-xs">{open ? "▲ collapse" : "▼ expand"}</span>
      </button>

      {open && (
        <div className="bg-slate-900 max-h-72 overflow-y-auto p-4 font-mono text-xs leading-5 text-slate-200">
          {logs.length === 0 && active && (
            <p className="text-slate-500 animate-pulse">Waiting for output…</p>
          )}
          {logs.length === 0 && !active && (
            <p className="text-slate-500">No log output captured (job may have completed before server restart).</p>
          )}
          {logs.map((line, i) => {
            const isAiaf = line.startsWith("[AIAF]");
            const isErr = line.toLowerCase().includes("error") || line.toLowerCase().includes("failed");
            const isWarn = line.toLowerCase().includes("warning");
            let cls = "text-slate-300";
            if (isAiaf) cls = "text-cyan-400 font-semibold";
            if (isErr) cls = "text-red-400";
            if (isWarn && !isErr) cls = "text-amber-400";
            return (
              <div key={i} className={cls}>
                <span className="select-none text-slate-600 mr-2">{String(i + 1).padStart(3, "0")}</span>
                {line}
              </div>
            );
          })}
          {active && logs.length > 0 && (
            <span className="inline-block w-2 h-3 bg-slate-400 animate-pulse ml-1" />
          )}
          <div ref={bottomRef} />
        </div>
      )}

      {/* Result summary bar */}
      {status === "FAILED" && result.error && (
        <div className="bg-red-950 px-4 py-2 text-xs text-red-300 font-mono border-t border-red-900">
          {result.error}
        </div>
      )}
      {status === "COMPLETED" && result.model_id && (
        <div className="bg-emerald-950 px-4 py-2 text-xs text-emerald-300 font-mono border-t border-emerald-900">
          model_id: {result.model_id}
          {result.sha256 && <span className="ml-4 text-emerald-500">sha256: {result.sha256.slice(0, 16)}…</span>}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Jobs panel — lists recent jobs, expands terminal for active/selected ones
// ---------------------------------------------------------------------------

function JobsPanel() {
  const [jobs, setJobs] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const hasActive = jobs.some((j) => j.status === "PENDING" || j.status === "RUNNING");

  useEffect(() => {
    let cancelled = false;

    async function fetchJobs() {
      try {
        const data = await api.jobs(10);
        if (cancelled) return;
        const next = data.jobs || [];
        setJobs((prev) => {
          // When a job transitions from active to terminal, keep its terminal
          // visible by auto-expanding it so the user sees the final log output.
          setExpanded((cur) => {
            if (cur) return cur;
            const nowDone = next.find(
              (j) =>
                (j.status === "COMPLETED" || j.status === "FAILED") &&
                prev.some((p) => p.id === j.id && (p.status === "PENDING" || p.status === "RUNNING"))
            );
            return nowDone ? nowDone.id : cur;
          });
          return next;
        });
      } catch { /* ignore */ }
    }

    fetchJobs();
    // Only poll while there are active jobs; stop when everything is terminal.
    if (!hasActive && jobs.length > 0) return;
    const id = setInterval(fetchJobs, 3000);
    return () => { cancelled = true; clearInterval(id); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasActive]);

  if (jobs.length === 0) return null;

  return (
    <Card>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-bold uppercase tracking-widest text-slate-500">
          Background Jobs
          {hasActive && (
            <span className="ml-2 inline-flex h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
          )}
        </h2>
        <span className="text-xs text-muted">{jobs.length} recent</span>
      </div>

      <div className="space-y-2">
        {jobs.map((job) => {
          const isActive = job.status === "PENDING" || job.status === "RUNNING";
          // Keep terminal mounted once it's been shown — either it's still active,
          // or the user has explicitly expanded it, OR it just auto-expanded on finish.
          const showTerminal = isActive || expanded === job.id;

          if (showTerminal) {
            return (
              <div key={job.id}>
                <JobTerminal jobId={job.id} />
              </div>
            );
          }

          // Collapsed row for non-active jobs
          const statusCls = {
            COMPLETED: "text-emerald-600 bg-emerald-50 border-emerald-200",
            FAILED: "text-red-600 bg-red-50 border-red-200",
          }[job.status] ?? "text-slate-600 bg-slate-50 border-slate-200";

          return (
            <button
              key={job.id}
              onClick={() => setExpanded(job.id)}
              className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-2 text-left hover:bg-slate-100 transition"
            >
              <div className="flex items-center gap-3">
                <span className={`rounded px-1.5 py-0.5 text-xs font-bold border ${statusCls}`}>
                  {job.status}
                </span>
                <span className="font-mono text-xs text-slate-500">{job.id.slice(0, 16)}…</span>
                {job.result?.model_id && (
                  <span className="text-xs text-slate-600">{job.result.model_id}</span>
                )}
              </div>
              <span className="text-xs text-muted">{fmtDate(job.created_at)} · click for logs ›</span>
            </button>
          );
        })}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main Registry tab
// ---------------------------------------------------------------------------

export default function Registry({ refreshToken }) {
  const { loading, error, data } = useResource(() => api.models(), [refreshToken]);
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState("");

  const models = (data && data.models) || [];
  const scored = models.map((m) => Number(m.provenance_score)).filter(Number.isFinite);
  const avg = scored.length ? Math.round(scored.reduce((a, b) => a + b, 0) / scored.length) : 0;
  const high = models.filter((m) => ["HIGH", "CRITICAL"].includes(String(m.risk_level || "").toUpperCase())).length;
  const publishers = new Set(models.map((m) => m.publisher).filter(Boolean)).size;

  const filtered = models.filter((m) => {
    const hay = [m.model_name, m.version, m.source, m.source_url, m.publisher, m.sha256].join(" ").toLowerCase();
    return (!query || hay.includes(query.toLowerCase())) && (!risk || String(m.risk_level || "UNKNOWN").toUpperCase() === risk);
  });

  async function openArtifact(modelId, kind) {
    try {
      const payload = await api.modelArtifact(modelId, kind);
      const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch (e) {
      alert(e.message);
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Registered Models" value={models.length} sub={`${models.length} record${models.length === 1 ? "" : "s"}`} />
        <Metric label="High Risk" value={high} sub="requiring review" />
        <Metric label="Avg Provenance" value={avg} sub="score across records" />
        <Metric label="Publishers" value={publishers} sub="distinct" />
      </div>

      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search models, publishers, sources"
            className="h-9 w-72 max-w-full rounded-md border border-slate-300 px-3 text-sm"
          />
          <select value={risk} onChange={(e) => setRisk(e.target.value)} className="h-9 rounded-md border border-slate-300 px-2 text-sm">
            <option value="">All risk levels</option>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        {loading && !data ? (
          <Empty>Loading model registry…</Empty>
        ) : error ? (
          <Empty>{error}</Empty>
        ) : !models.length ? (
          <Empty>No models registered. POST /models/register to add one.</Empty>
        ) : !filtered.length ? (
          <Empty>No models match the current filters.</Empty>
        ) : (
          <div className="overflow-auto rounded-lg border border-slate-200">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="p-2.5">Model</th><th className="p-2.5">Source</th><th className="p-2.5">Publisher</th>
                  <th className="p-2.5">Risk</th><th className="p-2.5">Provenance</th><th className="p-2.5">SHA-256</th>
                  <th className="p-2.5">Registered</th><th className="p-2.5">Artifacts</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((m) => {
                  const score = Number(m.provenance_score);
                  const safe = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
                  const sha = m.sha256 || "";
                  return (
                    <tr key={m.model_id} className="border-t border-slate-100 align-top">
                      <td className="p-2.5 font-bold">{m.model_name || "Unnamed"}<div className="text-xs font-normal text-muted">{m.version ? `v${m.version}` : "version unknown"}</div></td>
                      <td className="p-2.5">{m.source || "Unknown"}<div className="text-xs"><a href={m.source_url || "#"} target="_blank" rel="noreferrer" className="text-accent-strong hover:underline">{m.source_url || "no source URL"}</a></div></td>
                      <td className="p-2.5">{m.publisher || "Undeclared"}</td>
                      <td className="p-2.5"><Pill value={String(m.risk_level || "UNKNOWN").toUpperCase()} /></td>
                      <td className="p-2.5">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-16 overflow-hidden rounded-full bg-slate-200"><div className="h-full rounded-full bg-accent" style={{ width: `${safe}%` }} /></div>
                          <span className="tabular-nums">{Number.isFinite(score) ? safe : "N/A"}</span>
                        </div>
                      </td>
                      <td className="p-2.5 font-mono text-xs" title={sha}>{sha ? `${sha.slice(0, 12)}…` : "Unavailable"}</td>
                      <td className="p-2.5">{fmtDate(m.created_at)}</td>
                      <td className="p-2.5">
                        <div className="flex gap-1">
                          {["provenance", "mbom", "assurance"].map((kind) => (
                            <button key={kind} onClick={() => openArtifact(m.model_id, kind)} className="rounded-md border border-emerald-200 bg-white px-2 py-1 text-xs font-semibold capitalize text-accent-strong hover:bg-emerald-50">{kind}</button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <JobsPanel />
    </div>
  );
}

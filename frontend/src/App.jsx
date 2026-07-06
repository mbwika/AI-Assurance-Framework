import { useEffect, useRef, useState } from "react";
import { getApiKey, setApiKey, getHfToken, setHfToken } from "./api.js";
import Overview from "./tabs/Overview.jsx";
import Analyzer from "./tabs/Analyzer.jsx";
import Adoption from "./tabs/Adoption.jsx";
import Governance from "./tabs/Governance.jsx";
import Registry from "./tabs/Registry.jsx";
import RagInventory from "./tabs/RagInventory.jsx";
import AgentAuthorization from "./tabs/AgentAuthorization.jsx";
import ContextProvenance from "./tabs/ContextProvenance.jsx";
import Architecture from "./tabs/Architecture.jsx";
import ApiExplorer from "./tabs/ApiExplorer.jsx";
import AssistantDrawer from "./AssistantDrawer.jsx";

const TABS = [
  { id: "overview",     label: "Overview",               live: true  },
  { id: "adoption",     label: "Adoption Triage",         live: false },
  { id: "analyzer",     label: "Risk Analyzer",           live: false },
  { id: "governance",   label: "Governance & Compliance", live: true  },
  { id: "registry",     label: "Model Registry",          live: true  },
  { id: "rag",          label: "RAG Inventory",           live: true  },
  { id: "agent-auth",   label: "Agent Authorization",     live: true  },
  { id: "context-prov", label: "Context Provenance",      live: true  },
  { id: "architecture", label: "Architecture",            live: false },
  { id: "api",          label: "API Explorer",            live: false },
];

const REFRESH_SECONDS = 15;

export default function App() {
  const [tab, setTab] = useState("overview");
  const [keyInput, setKeyInput] = useState(getApiKey());
  const [hfTokenInput, setHfTokenInput] = useState(getHfToken());
  const [refreshToken, setRefreshToken] = useState(0);
  const [auto, setAuto] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const timer = useRef(null);

  function refresh() {
    setApiKey(keyInput);
    setHfToken(hfTokenInput);
    setRefreshToken((n) => n + 1);
    setLastRefresh(new Date());
  }

  // Live auto-refresh: only meaningful for data-driven tabs.
  const liveTab = TABS.find((t) => t.id === tab)?.live;
  const liveLabel = liveTab ? "Live evidence feed" : "Manual workspace";

  useEffect(() => {
    clearInterval(timer.current);
    if (auto && liveTab) {
      timer.current = setInterval(() => {
        setRefreshToken((n) => n + 1);
        setLastRefresh(new Date());
      }, REFRESH_SECONDS * 1000);
    }
    return () => clearInterval(timer.current);
  }, [auto, liveTab, tab]);

  const panels = {
    overview:     <Overview refreshToken={refreshToken} />,
    adoption:     <Adoption refreshToken={refreshToken} />,
    analyzer:     <Analyzer />,
    governance:   <Governance refreshToken={refreshToken} />,
    registry:     <Registry refreshToken={refreshToken} />,
    rag:          <RagInventory refreshToken={refreshToken} />,
    "agent-auth": <AgentAuthorization refreshToken={refreshToken} />,
    "context-prov": <ContextProvenance refreshToken={refreshToken} />,
    architecture: <Architecture refreshToken={refreshToken} />,
    api:          <ApiExplorer />,
  };

  return (
    <div className="mx-auto w-[min(1240px,calc(100vw-32px))] py-6">
      <header className="overflow-hidden rounded-[28px] border border-slate-200/80 bg-[radial-gradient(circle_at_top_left,_rgba(196,230,225,0.9),_transparent_36%),linear-gradient(180deg,_rgba(255,255,255,0.98),_rgba(244,247,244,0.96))] shadow-[0_18px_60px_rgba(24,33,47,0.08)]">
        <div className="grid gap-5 p-5 lg:grid-cols-[1.7fr,0.95fr] lg:p-6">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.18em] text-emerald-700">
                Operational Dashboard
              </span>
              <span className="rounded-full border border-slate-200 bg-white/80 px-2.5 py-1 text-[11px] font-semibold text-slate-600">
                {liveLabel}
              </span>
            </div>
            <h1 className="mt-4 font-display text-4xl leading-none text-ink sm:text-5xl">
              AI Assurance Framework
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-muted sm:text-[15px]">
              Portfolio assurance, governance evidence, retrieval inventory, agent runtime controls, and exportable compliance reporting in one shared workspace.
            </p>

            <div className="mt-5 grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/80 bg-white/70 p-3 backdrop-blur">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Workspace</div>
                <div className="mt-1 text-lg font-semibold text-ink">Assurance Ops</div>
                <div className="mt-1 text-xs text-muted">Report exports, trends, alerts, and control evidence</div>
              </div>
              <div className="rounded-2xl border border-white/80 bg-white/70 p-3 backdrop-blur">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Active View</div>
                <div className="mt-1 text-lg font-semibold text-ink">{TABS.find((t) => t.id === tab)?.label}</div>
                <div className="mt-1 text-xs text-muted">{liveTab ? "Auto-refresh supported" : "Runs on demand"}</div>
              </div>
              <div className="rounded-2xl border border-white/80 bg-white/70 p-3 backdrop-blur">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Update Cadence</div>
                <div className="mt-1 text-lg font-semibold text-ink">{auto && liveTab ? `${REFRESH_SECONDS}s` : "Manual"}</div>
                <div className="mt-1 text-xs text-muted">{lastRefresh ? `Last refresh ${lastRefresh.toLocaleTimeString()}` : "Waiting for first refresh"}</div>
              </div>
            </div>
          </div>

          <aside className="rounded-[24px] border border-slate-200/80 bg-white/82 p-4 shadow-[0_12px_36px_rgba(24,33,47,0.06)] backdrop-blur">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Session Controls</div>
                <p className="mt-1 text-sm text-muted">Keep your API session close by. Model download credentials stay tucked away until you need them.</p>
              </div>
              <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-semibold text-slate-600">
                {auto && liveTab ? "Live" : "Manual"}
              </span>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <label className="mb-1 block text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
                  API Key
                </label>
                <input
                  type="password"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  placeholder="API key"
                  className="h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
                />
              </div>

              <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50/80 p-3">
                <label className="flex items-center gap-2 text-sm font-medium text-slate-700">
                  <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} className="h-4 w-4 rounded border-slate-300 text-accent focus:ring-accent" />
                  Live refresh
                </label>
                <button
                  onClick={refresh}
                  className="ml-auto h-10 rounded-xl bg-accent px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-strong"
                >
                  Refresh workspace
                </button>
              </div>

              <details className="group rounded-2xl border border-slate-200 bg-slate-50/80 p-3">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold text-slate-700">
                  <span>Model download credentials</span>
                  <span className="text-xs text-muted group-open:hidden">{hfTokenInput ? "Stored" : "Optional"}</span>
                  <span className="hidden text-xs text-muted group-open:inline">Hide</span>
                </summary>
                <div className="mt-3 space-y-2">
                  <p className="text-xs leading-5 text-muted">
                    Used for private Hugging Face repos and faster registry ingestion. Stored only in this browser.
                  </p>
                  <input
                    type="password"
                    value={hfTokenInput}
                    onChange={(e) => {
                      setHfTokenInput(e.target.value);
                      setHfToken(e.target.value); // persist immediately so ApiExplorer always reads the latest value
                    }}
                    placeholder="HF token"
                    title="HuggingFace token for private repos or authenticated downloads."
                    className="h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
                  />
                </div>
              </details>
            </div>
          </aside>
        </div>
      </header>

      <nav className="mt-5 flex flex-wrap gap-1 border-b border-slate-200">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`-mb-px border-b-2 px-3.5 py-2.5 text-sm font-bold transition ${
              tab === t.id
                ? "border-accent text-accent-strong"
                : "border-transparent text-muted hover:text-ink"
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <div className="mt-1 flex h-6 items-center justify-end text-xs text-muted">
        {liveTab && lastRefresh
          ? `${auto ? "Live · " : ""}updated ${lastRefresh.toLocaleTimeString()}`
          : ""}
      </div>

      <main className="mt-3">{panels[tab]}</main>
      <AssistantDrawer currentTabLabel={TABS.find((t) => t.id === tab)?.label || "Workspace"} />
    </div>
  );
}

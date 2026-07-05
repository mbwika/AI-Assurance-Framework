import { useEffect, useState } from "react";
import { api, getAssistantActor, setAssistantActor } from "./api.js";
import { Empty, Pill, Tag } from "./ui.jsx";

const DEFAULT_SCOPE = { type: "portfolio", value: "" };

function ensureConversationId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `aiaf-assistant-${Date.now()}`;
}

function MarkdownLite({ text }) {
  const lines = String(text || "").split("\n");
  return (
    <div className="space-y-2 text-sm leading-6 text-slate-700">
      {lines.map((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={index} className="h-2" />;
        if (trimmed.startsWith("### ")) {
          return <h5 key={index} className="text-sm font-bold text-ink">{trimmed.slice(4)}</h5>;
        }
        if (trimmed.startsWith("## ")) {
          return <h4 key={index} className="text-base font-bold text-ink">{trimmed.slice(3)}</h4>;
        }
        if (trimmed.startsWith("- ")) {
          return <div key={index} className="pl-4 text-slate-700">• {trimmed.slice(2)}</div>;
        }
        return <p key={index}>{trimmed}</p>;
      })}
    </div>
  );
}

function scopeHint(scope) {
  if (scope.type === "artifact" && scope.value.trim()) return { artifact_id: scope.value.trim() };
  if (scope.type === "model" && scope.value.trim()) return { model_id: scope.value.trim() };
  if (scope.type === "registrant" && scope.value.trim()) return { registered_by: scope.value.trim() };
  return {};
}

function formatScope(scope = {}) {
  return scope.artifact_id || scope.model_id || scope.registered_by || "portfolio";
}

function canOpenReport(response = {}) {
  return Boolean(response.answer_markdown && response.status !== "endpoint_error");
}

function ReportCanvas({ item, onClose, onConfirm }) {
  const response = item?.response;
  if (!response) return null;
  return (
    <div className="fixed inset-0 z-50 bg-slate-950/35 p-3 md:p-6" onClick={onClose}>
      <div
        className="mx-auto flex h-full w-full max-w-5xl flex-col overflow-hidden rounded-[30px] border border-slate-200 bg-[linear-gradient(180deg,_rgba(255,255,255,0.99),_rgba(246,249,246,0.98))] shadow-[0_28px_90px_rgba(15,23,42,0.28)]"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="border-b border-slate-200 px-5 py-4 md:px-7">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Assistant Output</div>
              <h3 className="mt-1 font-display text-2xl leading-none text-ink md:text-3xl">{response.title || "AIAF Report"}</h3>
              <p className="mt-2 max-w-3xl text-sm text-muted">{response.summary || "Detailed assistant output"}</p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs font-semibold text-slate-600"
            >
              Close
            </button>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {response.status ? <Pill value={response.status} /> : null}
            {response.intent ? <Tag>{response.intent}</Tag> : null}
            {response.actor?.attribution_label ? <Tag>{response.actor.attribution_label}</Tag> : null}
            <Tag>{formatScope(response.scope || {})}</Tag>
          </div>
        </div>

        <div className="grid flex-1 overflow-hidden md:grid-cols-[minmax(0,1fr)_280px]">
          <div className="overflow-y-auto px-5 py-5 md:px-7">
            <MarkdownLite text={response.answer_markdown || response.summary || ""} />
          </div>
          <aside className="border-t border-slate-200 bg-white/72 px-5 py-5 md:overflow-y-auto md:border-l md:border-t-0">
            {(response.authorization?.confirmation_required && response.authorization?.confirmation_id) ? (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
                <div className="text-sm font-semibold text-amber-900">Write confirmation required</div>
                <p className="mt-2 text-sm leading-6 text-amber-900">
                  This action is ready to run once you confirm it.
                </p>
                <button
                  type="button"
                  onClick={() => onConfirm(item)}
                  className="mt-3 h-10 rounded-xl bg-amber-600 px-4 text-sm font-semibold text-white transition hover:bg-amber-700"
                >
                  Confirm write action
                </button>
              </div>
            ) : null}

            {(response.actions_taken || []).length ? (
              <div className="mt-4">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Actions</div>
                <div className="mt-2 space-y-2">
                  {response.actions_taken.map((action, index) => (
                    <div key={index} className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-xs text-slate-700">
                      <div className="font-semibold text-ink">{action.type}</div>
                      <div className="mt-1 font-mono text-[11px] text-slate-500">{JSON.stringify(action.scope || {})}</div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {(response.artifacts || []).length ? (
              <div className="mt-4">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Artifacts</div>
                <div className="mt-2 space-y-2">
                  {response.artifacts.map((artifact, index) => (
                    <div key={index} className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-xs text-slate-700">
                      <div className="font-semibold text-ink">{artifact.kind || "artifact"}</div>
                      <div className="mt-1 font-mono text-[11px] text-slate-500">{JSON.stringify(artifact)}</div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {(response.follow_ups || []).length ? (
              <div className="mt-4">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Next asks</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {response.follow_ups.map((prompt) => (
                    <Tag key={prompt}>{prompt}</Tag>
                  ))}
                </div>
              </div>
            ) : null}
          </aside>
        </div>
      </div>
    </div>
  );
}

function AssistantMessage({ item, onPromptClick, onOpenReport, onConfirm }) {
  if (item.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[88%] rounded-2xl rounded-br-md bg-accent px-4 py-3 text-sm text-white shadow-sm">
          {item.content}
        </div>
      </div>
    );
  }

  const response = item.response || {};
  return (
    <div className="flex justify-start">
      <div className="max-w-[92%] rounded-2xl rounded-bl-md border border-slate-200 bg-white px-4 py-3 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-bold text-ink">{response.title || "AIAF Assistant"}</span>
          {response.status && <Pill value={response.status} />}
          {response.intent && <Tag>{response.intent}</Tag>}
        </div>
        <div className="mt-3">
          <MarkdownLite text={response.answer_markdown || response.summary || ""} />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {canOpenReport(response) ? (
            <button
              type="button"
              onClick={() => onOpenReport(item)}
              className="rounded-full border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-white"
            >
              Open report
            </button>
          ) : null}
          {(response.authorization?.confirmation_required && response.authorization?.confirmation_id && item.requestMessage) ? (
            <button
              type="button"
              onClick={() => onConfirm(item)}
              className="rounded-full border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-900 transition hover:border-amber-400 hover:bg-amber-100"
            >
              Confirm write
            </button>
          ) : null}
        </div>
        {(response.actions_taken || []).length ? (
          <details className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3">
            <summary className="cursor-pointer list-none text-xs font-bold uppercase tracking-[0.16em] text-slate-500">
              Actions taken
            </summary>
            <div className="mt-2 space-y-2">
              {response.actions_taken.map((action, index) => (
                <div key={index} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                  <div className="font-semibold text-ink">{action.type}</div>
                  <div className="mt-1 font-mono text-[11px] text-slate-500">{JSON.stringify(action.scope || {})}</div>
                </div>
              ))}
            </div>
          </details>
        ) : null}
        {(response.follow_ups || []).length ? (
          <div className="mt-3 flex flex-wrap gap-2">
            {response.follow_ups.map((prompt) => (
              <button
                key={prompt}
                type="button"
                onClick={() => onPromptClick(prompt)}
                className="rounded-full border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-slate-50"
              >
                {prompt}
              </button>
            ))}
          </div>
        ) : null}
        {(response.limits || []).length ? (
          <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            {response.limits.join(" ")}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function AssistantDrawer({ currentTabLabel }) {
  const [open, setOpen] = useState(false);
  const [capabilities, setCapabilities] = useState(null);
  const [loadingCaps, setLoadingCaps] = useState(true);
  const [capError, setCapError] = useState("");
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [scope, setScope] = useState(DEFAULT_SCOPE);
  const [actor, setActor] = useState(() => getAssistantActor());
  const [reportView, setReportView] = useState(null);
  const [conversationId] = useState(() => ensureConversationId());

  useEffect(() => {
    let active = true;
    setLoadingCaps(true);
    api.assistantCapabilities()
      .then((data) => {
        if (!active) return;
        setCapabilities(data);
        setCapError("");
      })
      .catch((error) => active && setCapError(error.message))
      .finally(() => active && setLoadingCaps(false));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setAssistantActor(actor);
  }, [actor]);

  async function sendMessage(message, options = {}) {
    const { confirmActionId = null, userFacingContent = null, scopeOverride = null } = options;
    const trimmed = String(message || "").trim();
    if (!trimmed || sending) return;
    const effectiveScopeHint = scopeOverride || scopeHint(scope);
    if (userFacingContent !== false) {
      const userMessage = {
        id: `${Date.now()}-user`,
        role: "user",
        content: userFacingContent || trimmed,
      };
      setMessages((items) => [...items, userMessage]);
    }
    setInput("");
    setSending(true);
    try {
      const response = await api.assistantQuery({
        message: trimmed,
        conversation_id: conversationId,
        confirm_action_id: confirmActionId,
        scope_hint: effectiveScopeHint,
        role: actor.role || null,
        actor: {
          display_name: actor.display_name || null,
          role: actor.role || null,
        },
        history: messages.slice(-8).map((item) => ({
          role: item.role,
          content: item.role === "user" ? item.content : item.response?.summary || item.response?.answer_markdown || "",
        })),
      });
      setMessages((items) => [
        ...items,
        {
          id: `${Date.now()}-assistant`,
          role: "assistant",
          response,
          requestMessage: trimmed,
          requestScopeHint: effectiveScopeHint,
        },
      ]);
      if (canOpenReport(response)) {
        setReportView({
          id: `${Date.now()}-report`,
          role: "assistant",
          response,
          requestMessage: trimmed,
          requestScopeHint: effectiveScopeHint,
        });
      }
    } catch (error) {
      setMessages((items) => [
        ...items,
        {
          id: `${Date.now()}-assistant-error`,
          role: "assistant",
          response: {
            title: "Assistant request failed",
            status: "endpoint_error",
            summary: error.message,
            answer_markdown: `## Assistant request failed\n\n${error.message}`,
            follow_ups: [],
            actions_taken: [],
            limits: ["The assistant could not complete this request."],
          },
        },
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      {reportView ? (
        <ReportCanvas
          item={reportView}
          onClose={() => setReportView(null)}
          onConfirm={(item) =>
            sendMessage(item.requestMessage, {
              confirmActionId: item.response?.authorization?.confirmation_id || null,
              userFacingContent: "Confirm write action",
              scopeOverride: item.requestScopeHint || {},
            })}
        />
      ) : null}
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="fixed bottom-5 right-5 z-30 flex h-14 items-center gap-2 rounded-full border border-slate-200 bg-white px-4 text-sm font-bold text-ink shadow-[0_16px_40px_rgba(24,33,47,0.18)] transition hover:-translate-y-0.5"
      >
        <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-emerald-100 text-emerald-700">
          AI
        </span>
        Ask AIAF
      </button>

      {open ? <div className="fixed inset-0 z-30 bg-slate-950/15" onClick={() => setOpen(false)} /> : null}

      <aside
        className={`fixed right-0 top-0 z-40 flex h-screen w-[min(430px,100vw)] flex-col border-l border-slate-200 bg-[linear-gradient(180deg,_rgba(255,255,255,0.98),_rgba(245,248,246,0.98))] shadow-[-18px_0_48px_rgba(24,33,47,0.12)] transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="border-b border-slate-200 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Ask AIAF</div>
              <h2 className="mt-1 font-display text-2xl leading-none text-ink">Governance Copilot</h2>
              <p className="mt-2 text-sm text-muted">
                Available from every tab. Right now I’m best at reports, compliance summaries, evidence gaps, snapshots, agent decisions, and RAG posture.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs font-semibold text-slate-600"
            >
              Close
            </button>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Tag>{currentTabLabel}</Tag>
            {capabilities?.mode ? <Tag>{capabilities.mode}</Tag> : null}
            {(capabilities?.write_actions_enabled || []).length ? <Tag>write: {(capabilities.write_actions_enabled || []).join(", ")}</Tag> : null}
          </div>
        </div>

        <details className="border-b border-slate-200 px-5 py-4">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <span>Actor & Scope</span>
            <span className="rounded-full border border-slate-200 bg-white px-2 py-1 text-[10px] font-semibold text-slate-500">
              {actor.role || actor.display_name || formatScope(scopeHint(scope))}
            </span>
          </summary>
          <div className="mt-3">
            <div className="grid grid-cols-1 gap-3">
              <input
                value={actor.display_name}
                onChange={(e) => setActor((state) => ({ ...state, display_name: e.target.value }))}
                placeholder="Your name or team"
                className="h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
              />
              <input
                value={actor.role}
                onChange={(e) => setActor((state) => ({ ...state, role: e.target.value }))}
                placeholder="Governance analyst"
                className="h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
              />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {[
                ["portfolio", "Portfolio"],
                ["artifact", "Artifact"],
                ["model", "Model"],
                ["registrant", "Registrant"],
              ].map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setScope({ type: value, value: value === "portfolio" ? "" : scope.value })}
                  className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                    scope.type === value
                      ? "border-emerald-600 bg-emerald-600 text-white"
                      : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            {scope.type !== "portfolio" ? (
              <input
                value={scope.value}
                onChange={(e) => setScope((state) => ({ ...state, value: e.target.value }))}
                placeholder={`${scope.type} id`}
                className="mt-3 h-10 w-full rounded-xl border border-slate-300 bg-white px-3 text-sm shadow-sm"
              />
            ) : null}
            <p className="mt-3 text-xs text-muted">
              Declared attribution works now. Authenticated identity can override it later without changing the assistant contract.
            </p>
          </div>
        </details>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {messages.length ? (
            <div className="space-y-4">
              {messages.map((item) => (
                <AssistantMessage
                  key={item.id}
                  item={item}
                  onPromptClick={sendMessage}
                  onOpenReport={setReportView}
                  onConfirm={(item) =>
                    sendMessage(item.requestMessage, {
                      confirmActionId: item.response?.authorization?.confirmation_id || null,
                      userFacingContent: "Confirm write action",
                      scopeOverride: item.requestScopeHint || {},
                    })
                  }
                />
              ))}
              {sending ? (
                <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-muted shadow-sm">
                  Running AIAF workflows…
                </div>
              ) : null}
            </div>
          ) : loadingCaps ? (
            <Empty>Loading assistant capabilities…</Empty>
          ) : capError ? (
            <Empty>{capError}</Empty>
          ) : (
            <div className="space-y-4">
              <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <div className="text-sm font-semibold text-ink">Start with a plain-language ask</div>
                <p className="mt-2 text-sm text-muted">
                  The assistant stays within explicit AIAF workflows. Reports open in a larger reading canvas, and write actions go through authorization plus a confirmation step.
                </p>
              </div>
              <div>
                <div className="mb-2 text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Suggested prompts</div>
                <div className="flex flex-wrap gap-2">
                  {(capabilities?.suggested_prompts || []).map((prompt) => (
                    <button
                      key={prompt}
                      type="button"
                      onClick={() => sendMessage(prompt)}
                      className="rounded-2xl border border-slate-300 bg-white px-3 py-2 text-left text-xs font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-slate-50"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="border-t border-slate-200 px-5 py-4">
          <label className="mb-2 block text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
            Your request
          </label>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Generate a governance report for artifact hiring-assistant-prod"
            className="h-28 w-full resize-none rounded-2xl border border-slate-300 bg-white px-3 py-3 text-sm shadow-sm"
          />
          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              onClick={() => sendMessage(input)}
              disabled={sending || !input.trim()}
              className="h-10 rounded-xl bg-accent px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-50"
            >
              {sending ? "Running…" : "Ask AIAF"}
            </button>
            <span className="text-xs text-muted">Write actions now use actor-based authorization and explicit confirmation.</span>
          </div>
        </div>
      </aside>
    </>
  );
}

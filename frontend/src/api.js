// Thin API client for the AI Assurance Framework. The key is kept in
// localStorage and sent as X-API-Key on every request.

const KEY_STORAGE = "aiaf_api_key";
const HF_TOKEN_STORAGE = "aiaf_hf_token";
const ASSISTANT_ACTOR_STORAGE = "aiaf_assistant_actor";

export function getApiKey() {
  return (localStorage.getItem(KEY_STORAGE) || "dev-key").trim() || "dev-key";
}

export function setApiKey(value) {
  localStorage.setItem(KEY_STORAGE, (value || "").trim() || "dev-key");
}

export function getHfToken() {
  return localStorage.getItem(HF_TOKEN_STORAGE) || "";
}

export function setHfToken(value) {
  const trimmed = (value || "").trim();
  if (trimmed) {
    localStorage.setItem(HF_TOKEN_STORAGE, trimmed);
  } else {
    localStorage.removeItem(HF_TOKEN_STORAGE);
  }
}

export function getAssistantActor() {
  try {
    const raw = localStorage.getItem(ASSISTANT_ACTOR_STORAGE) || "";
    const parsed = raw ? JSON.parse(raw) : {};
    return {
      display_name: String(parsed.display_name || ""),
      role: String(parsed.role || ""),
    };
  } catch {
    return { display_name: "", role: "" };
  }
}

export function setAssistantActor(value) {
  const actor = {
    display_name: String(value?.display_name || "").trim(),
    role: String(value?.role || "").trim(),
  };
  localStorage.setItem(ASSISTANT_ACTOR_STORAGE, JSON.stringify(actor));
}

async function request(path, options = {}) {
  const headers = { "X-API-Key": getApiKey(), ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).detail || "";
    } catch {
      /* ignore */
    }
    throw new Error(`HTTP ${res.status}${detail ? ` — ${detail}` : ""} (${path})`);
  }
  return res.json();
}

async function requestText(path, options = {}) {
  const headers = { "X-API-Key": getApiKey(), ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).detail || "";
    } catch {
      /* ignore */
    }
    throw new Error(`HTTP ${res.status}${detail ? ` — ${detail}` : ""} (${path})`);
  }
  return res.text();
}

async function downloadFile(path, fallbackName, options = {}) {
  const headers = { "X-API-Key": getApiKey(), ...(options.headers || {}) };
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).detail || "";
    } catch {
      /* ignore */
    }
    throw new Error(`HTTP ${res.status}${detail ? ` — ${detail}` : ""} (${path})`);
  }

  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename=\"?([^"]+)\"?/i);
  const filename = match?.[1] || fallbackName;

  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(href);
}

function scopeQuery(scope = {}) {
  const params = new URLSearchParams();
  if (scope?.artifact_id) params.set("artifact_id", scope.artifact_id);
  if (scope?.model_id) params.set("model_id", scope.model_id);
  if (scope?.registered_by) params.set("registered_by", scope.registered_by);
  const query = params.toString();
  return query ? `?${query}` : "";
}

export const api = {
  assuranceReport: (scope = {}) =>
    request(`/v1/reporting/assurance-report${scopeQuery(scope)}`),
  assuranceReportMarkdown: (scope = {}) =>
    requestText(`/v1/reporting/assurance-report?format=markdown${scopeQuery(scope).replace("?", "&")}`),
  assuranceReportHtml: (scope = {}) =>
    requestText(`/v1/reporting/assurance-report?format=html${scopeQuery(scope).replace("?", "&")}`),
  compliance: (scope = {}) => request(`/v1/reporting/compliance${scopeQuery(scope)}`),
  controls: () => request("/v1/governance/controls"),
  assistantCapabilities: () => request("/v1/assistant/capabilities"),
  assistantQuery: (payload) =>
    request("/v1/assistant/query", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  metrics: (limit = 500, scope = {}) => request(`/v1/reporting/metrics?limit=${limit}${scopeQuery(scope).replace("?", "&")}`),
  risks: (limit = 200, filters = {}) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (filters.status) params.set("status", filters.status);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.artifact_id) params.set("artifact_id", filters.artifact_id);
    return request(`/v1/risks?${params.toString()}`);
  },
  updateRisk: (riskId, payload) =>
    request(`/v1/risks/${encodeURIComponent(riskId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  createReportSnapshot: (payload) =>
    request("/v1/reporting/snapshots", { method: "POST", body: JSON.stringify(payload) }),
  models: (limit = 250, registeredBy = "") =>
    request(`/models?limit=${limit}${registeredBy ? `&registered_by=${encodeURIComponent(registeredBy)}` : ""}`),
  architecture: () => request("/v1/architecture"),
  ragStores: (limit = 50) => request(`/v1/rag/stores?limit=${limit}`),
  ragStore: (storeId) => request(`/v1/rag/stores/${encodeURIComponent(storeId)}`),
  ragDocuments: (storeId, { offset = 0, limit = 100, trustLabel = "" } = {}) => {
    const params = new URLSearchParams({
      offset: String(offset),
      limit: String(limit),
    });
    if (trustLabel) params.set("trust_label", trustLabel);
    return request(`/v1/rag/stores/${encodeURIComponent(storeId)}/documents?${params.toString()}`);
  },
  ragAssessment: (storeId) =>
    request(`/v1/rag/stores/${encodeURIComponent(storeId)}/assessment`),
  agentPolicyProfiles: () => request("/v1/agentic/policy-profiles"),
  agentSessions: ({ limit = 100, artifactId = "", status = "" } = {}) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (artifactId) params.set("artifact_id", artifactId);
    if (status) params.set("status", status);
    return request(`/v1/agentic/sessions?${params.toString()}`);
  },
  agentInvocations: ({ limit = 100, sessionId = "", decision = "" } = {}) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (sessionId) params.set("session_id", sessionId);
    if (decision) params.set("decision", decision);
    return request(`/v1/agentic/invocations?${params.toString()}`);
  },
  cycloneDxBom: (modelId) =>
    request(`/v1/interop/models/${encodeURIComponent(modelId)}/bom/cyclonedx`),
  analyze: (artifact) =>
    request("/v1/risk/analyze", { method: "POST", body: JSON.stringify(artifact) }),
  modelArtifact: (modelId, kind) =>
    request(`/models/${encodeURIComponent(modelId)}/${kind}`),
  triage: (
    modelId,
    {
      endpointUrl = null,
      endpointApiKey = null,
      endpointModelName = "default",
      policyContext = null,
    } = {},
  ) =>
    request("/v1/intake/triage", {
      method: "POST",
      body: JSON.stringify({
        model_id: modelId,
        ...(endpointUrl ? { endpoint_url: endpointUrl } : {}),
        ...(endpointApiKey ? { endpoint_api_key: endpointApiKey } : {}),
        ...(endpointModelName ? { endpoint_model_name: endpointModelName } : {}),
        ...(policyContext ? { policy_context: policyContext } : {}),
      }),
    }),
  latestRecommendation: (modelId) =>
    request(`/v1/intake/${encodeURIComponent(modelId)}`),
  downloadCycloneDxBom: (modelId) =>
    downloadFile(
      `/v1/interop/models/${encodeURIComponent(modelId)}/bom/cyclonedx`,
      `aiaf-bom-${String(modelId || "model").slice(0, 8)}.cdx.json`,
    ),
  startRedTeam: (modelId, { endpointUrl, backend = "garak", modelName = "default", depth = "quick", apiKey = null } = {}) =>
    request(`/v1/interop/models/${encodeURIComponent(modelId)}/redteam`, {
      method: "POST",
      body: JSON.stringify({
        endpoint_url: endpointUrl,
        backend,
        model_name: modelName,
        depth,
        ...(apiKey ? { endpoint_api_key: apiKey } : {}),
      }),
    }),
  getRedTeamJob: (modelId, jobId) =>
    request(`/v1/interop/models/${encodeURIComponent(modelId)}/redteam/${encodeURIComponent(jobId)}`),
  listRedTeamJobs: (modelId) =>
    request(`/v1/interop/models/${encodeURIComponent(modelId)}/redteam`),
  jobs: (limit = 20) => request(`/jobs?limit=${limit}`),
  jobStatus: (jobId) => request(`/jobs/${encodeURIComponent(jobId)}`),
  jobLogs: (jobId) => request(`/jobs/${encodeURIComponent(jobId)}/logs`),
};

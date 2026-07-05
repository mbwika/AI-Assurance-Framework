import test from "node:test";
import assert from "node:assert/strict";

import { api, getApiKey } from "./api.js";

function installLocalStorage(initial = {}) {
  const store = new Map(Object.entries(initial));
  globalThis.localStorage = {
    getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    setItem(key, value) {
      store.set(key, String(value));
    },
    removeItem(key) {
      store.delete(key);
    },
    clear() {
      store.clear();
    },
  };
  return store;
}

test("downloadCycloneDxBom requests the interop endpoint and downloads the returned file", async () => {
  installLocalStorage({ aiaf_api_key: "phase3-key" });

  const appended = [];
  const removed = [];
  let clicked = false;
  let capturedPath = null;
  let capturedOptions = null;
  let createdBlob = null;
  let revokedUrl = null;

  globalThis.document = {
    body: {
      appendChild(node) {
        appended.push(node);
      },
    },
    createElement(tag) {
      assert.equal(tag, "a");
      return {
        href: "",
        download: "",
        click() {
          clicked = true;
        },
        remove() {
          removed.push(this);
        },
      };
    },
  };

  globalThis.URL = {
    createObjectURL(blob) {
      createdBlob = blob;
      return "blob:cyclonedx-test";
    },
    revokeObjectURL(url) {
      revokedUrl = url;
    },
  };

  globalThis.fetch = async (path, options) => {
    capturedPath = path;
    capturedOptions = options;
    return new Response('{"bomFormat":"CycloneDX"}', {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.cyclonedx+json; version=1.7",
        "Content-Disposition": 'attachment; filename="aiaf-bom-model123.cdx.json"',
      },
    });
  };

  await api.downloadCycloneDxBom("model123456789");

  assert.equal(getApiKey(), "phase3-key");
  assert.equal(
    capturedPath,
    "/v1/interop/models/model123456789/bom/cyclonedx",
  );
  assert.deepEqual(capturedOptions?.headers, { "X-API-Key": "phase3-key" });
  assert.equal(appended.length, 1);
  assert.equal(appended[0].href, "blob:cyclonedx-test");
  assert.equal(appended[0].download, "aiaf-bom-model123.cdx.json");
  assert.equal(removed.length, 1);
  assert.equal(clicked, true);
  assert.ok(createdBlob instanceof Blob);
  assert.equal(revokedUrl, "blob:cyclonedx-test");
});

test("triage sends endpoint runtime options when provided", async () => {
  installLocalStorage({ aiaf_api_key: "phaseA-key" });

  let capturedPath = null;
  let capturedOptions = null;

  globalThis.fetch = async (path, options) => {
    capturedPath = path;
    capturedOptions = options;
    return new Response('{"status":"ok"}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  await api.triage("model-123", {
    endpointUrl: "http://localhost:11434",
    endpointApiKey: "endpoint-secret",
    endpointModelName: "demo-model",
    policyContext: {
      use_case: "security",
      data_classification: "restricted",
      deployment_exposure: "internal",
    },
  });

  assert.equal(capturedPath, "/v1/intake/triage");
  assert.equal(capturedOptions?.method, "POST");
  assert.deepEqual(capturedOptions?.headers, {
    "X-API-Key": "phaseA-key",
    "Content-Type": "application/json",
  });
  assert.deepEqual(JSON.parse(capturedOptions?.body || "{}"), {
    model_id: "model-123",
    endpoint_url: "http://localhost:11434",
    endpoint_api_key: "endpoint-secret",
    endpoint_model_name: "demo-model",
    policy_context: {
      use_case: "security",
      data_classification: "restricted",
      deployment_exposure: "internal",
    },
  });
});

test("inventory and authorization helpers call the curated backend routes", async () => {
  installLocalStorage({ aiaf_api_key: "ops-key" });

  const calls = [];
  globalThis.fetch = async (path, options) => {
    calls.push({ path, options });
    return new Response('{"ok":true}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  await api.ragStores(25);
  await api.ragDocuments("rag-1", { offset: 5, limit: 10, trustLabel: "VERIFIED" });
  await api.agentSessions({ limit: 20, artifactId: "artifact-1", status: "ACTIVE" });
  await api.agentInvocations({ limit: 15, sessionId: "session-1", decision: "DENY" });
  await api.cycloneDxBom("model-42");

  assert.deepEqual(
    calls.map((call) => call.path),
    [
      "/v1/rag/stores?limit=25",
      "/v1/rag/stores/rag-1/documents?offset=5&limit=10&trust_label=VERIFIED",
      "/v1/agentic/sessions?limit=20&artifact_id=artifact-1&status=ACTIVE",
      "/v1/agentic/invocations?limit=15&session_id=session-1&decision=DENY",
      "/v1/interop/models/model-42/bom/cyclonedx",
    ]
  );
  for (const call of calls) {
    assert.deepEqual(call.options?.headers, { "X-API-Key": "ops-key" });
  }
});

test("assistant helpers call the assistant routes", async () => {
  installLocalStorage({ aiaf_api_key: "assistant-key" });

  const calls = [];
  globalThis.fetch = async (path, options) => {
    calls.push({ path, options });
    return new Response('{"ok":true}', {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  await api.assistantCapabilities();
  await api.assistantQuery({
    message: "Generate a governance report",
    scope_hint: { artifact_id: "artifact-1" },
  });

  assert.deepEqual(
    calls.map((call) => call.path),
    ["/v1/assistant/capabilities", "/v1/assistant/query"]
  );
  assert.deepEqual(calls[0].options?.headers, { "X-API-Key": "assistant-key" });
  assert.deepEqual(calls[1].options?.headers, {
    "X-API-Key": "assistant-key",
    "Content-Type": "application/json",
  });
  assert.deepEqual(JSON.parse(calls[1].options?.body || "{}"), {
    message: "Generate a governance report",
    scope_hint: { artifact_id: "artifact-1" },
  });
});

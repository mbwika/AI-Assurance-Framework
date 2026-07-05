import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Empty, Metric, Pill, Tag, fmtDate, humanLabel } from "../ui.jsx";

const TRUST_LEVELS = ["VERIFIED", "INTERNAL", "EXTERNAL", "USER_GENERATED", "UNTRUSTED"];

function sumTrust(stores, label) {
  return stores.reduce(
    (total, store) => total + Number((store.trust_distribution || {})[label] || 0),
    0
  );
}

function truthyCount(stores, field) {
  return stores.filter((store) => store.security_profile?.[field]).length;
}

export default function RagInventory({ refreshToken }) {
  const storesResource = useResource(() => api.ragStores(200), [refreshToken]);
  const stores = storesResource.data?.stores || [];
  const [selectedStoreId, setSelectedStoreId] = useState("");
  const [query, setQuery] = useState("");
  const [trustFilter, setTrustFilter] = useState("");

  useEffect(() => {
    if (!selectedStoreId && stores.length) {
      setSelectedStoreId(stores[0].store_id || "");
    }
    if (selectedStoreId && !stores.some((store) => store.store_id === selectedStoreId)) {
      setSelectedStoreId(stores[0]?.store_id || "");
    }
  }, [stores, selectedStoreId]);

  const filteredStores = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return stores.filter((store) => {
      const haystack = [
        store.store_id,
        store.store_type,
        store.collection_name,
        store.embedding_model,
        store.security_profile?.access_control_mode,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return !needle || haystack.includes(needle);
    });
  }, [stores, query]);

  const detailResource = useResource(
    () =>
      selectedStoreId
        ? Promise.all([
            api.ragStore(selectedStoreId),
            api.ragDocuments(selectedStoreId, { limit: 100, trustLabel: trustFilter }),
            api.ragAssessment(selectedStoreId),
          ])
        : Promise.resolve(null),
    [refreshToken, selectedStoreId, trustFilter]
  );

  const totalDocuments = stores.reduce((total, store) => total + Number(store.document_count || 0), 0);
  const openStores = stores.filter(
    (store) => (store.security_profile?.access_control_mode || "").toUpperCase() === "OPEN"
  ).length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="RAG Stores" value={stores.length} sub="registered retrieval indexes" />
        <Metric label="Indexed Docs" value={totalDocuments} sub={`${sumTrust(stores, "UNTRUSTED")} untrusted`} />
        <Metric label="PII Screening" value={truthyCount(stores, "pii_screening_enabled")} sub="stores screening before ingest" />
        <Metric label="Open Access" value={openStores} sub="stores needing isolation review" />
      </div>

      <Card
        title="RAG store inventory"
        action={<Tag>{storesResource.data?.inventory_version || "inventory"}</Tag>}
      >
        <p className="mb-4 max-w-3xl text-sm leading-6 text-muted">
          Curated retrieval coverage for the vector-store inventory already exposed by the backend. Use this view to spot weak trust mixes, stale indexes, and shared-access stores without dropping into raw API responses.
        </p>
        <div className="grid gap-4 lg:grid-cols-[0.92fr,1.08fr]">
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search store, backend, collection"
                className="h-9 w-full rounded-md border border-slate-300 px-3 text-sm"
              />
            </div>
            {storesResource.loading && !stores.length ? (
              <Empty>Loading RAG inventory…</Empty>
            ) : storesResource.error ? (
              <Empty>{storesResource.error}</Empty>
            ) : !filteredStores.length ? (
              <Empty>No RAG stores match the current filter.</Empty>
            ) : (
              <div className="space-y-2">
                {filteredStores.map((store) => {
                  const active = selectedStoreId === store.store_id;
                  return (
                    <button
                      key={store.store_id}
                      type="button"
                      onClick={() => setSelectedStoreId(store.store_id)}
                      className={`w-full rounded-2xl border p-3 text-left transition ${
                        active
                          ? "border-emerald-400 bg-emerald-50/60 shadow-sm"
                          : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-semibold text-ink">{store.store_id}</div>
                          <div className="mt-1 text-xs text-muted">
                            {store.store_type} · {store.collection_name || "no collection"}
                          </div>
                        </div>
                        <Pill value={store.security_profile?.access_control_mode || "UNKNOWN"} />
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Tag>{store.document_count || 0} docs</Tag>
                        <Tag>{store.default_trust_label || "UNKNOWN"} default trust</Tag>
                        {store.security_profile?.tenant_isolation ? <Tag>tenant isolation</Tag> : null}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div>
            {!selectedStoreId ? (
              <Empty>Select a store to inspect its documents and posture.</Empty>
            ) : detailResource.loading && !detailResource.data ? (
              <Empty>Loading store details…</Empty>
            ) : detailResource.error ? (
              <Empty>{detailResource.error}</Empty>
            ) : (() => {
              const [store, documentsResponse, assessment] = detailResource.data || [];
              const documents = documentsResponse?.documents || [];
              const profile = store?.security_profile || {};
              const findings = assessment?.findings || [];
              return (
                <div className="space-y-4">
                  <Card title={store?.store_id || selectedStoreId} action={<Pill value={assessment?.status || "UNKNOWN"} />}>
                    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                      <Metric label="Documents" value={store?.document_count || 0} sub="registered in inventory" />
                      <Metric label="Embedding" value={store?.embedding_model || "—"} sub={profile.embedding_verified ? "verified provenance" : "verification pending"} />
                      <Metric label="Freshness SLA" value={profile.freshness_sla_hours || "—"} sub={profile.last_indexed_at ? `last indexed ${fmtDate(profile.last_indexed_at)}` : "no refresh evidence"} />
                      <Metric label="PII Gate" value={profile.pii_screening_enabled ? "On" : "Off"} sub={profile.access_control_mode || "UNKNOWN"} />
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {(store?.trust_distribution ? Object.entries(store.trust_distribution) : []).map(([label, count]) => (
                        <Tag key={label}>
                          {humanLabel(label)}: {count}
                        </Tag>
                      ))}
                    </div>
                  </Card>

                  <Card title="Security posture">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm">
                        <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Controls</div>
                        <div className="mt-2 space-y-2 text-ink">
                          <div>Access control: <span className="font-semibold">{humanLabel(profile.access_control_mode || "UNKNOWN")}</span></div>
                          <div>Tenant isolation: <span className="font-semibold">{profile.tenant_isolation ? "ENFORCED" : "NOT DECLARED"}</span></div>
                          <div>Embedding source trust: <span className="font-semibold">{humanLabel(profile.embedding_source_trust || "UNKNOWN")}</span></div>
                        </div>
                      </div>
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm">
                        <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Assessment</div>
                        {findings.length ? (
                          <ul className="mt-2 space-y-2">
                            {findings.slice(0, 5).map((finding, index) => (
                              <li key={index} className="rounded-lg border border-slate-200 bg-white p-2.5">
                                <div className="flex items-center gap-2">
                                  <Pill value={finding.severity || "MEDIUM"} />
                                  <span className="font-medium text-ink">{humanLabel(finding.indicator || "finding")}</span>
                                </div>
                                <div className="mt-1 text-muted">{finding.description || "No description provided."}</div>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <Empty>No assessment findings recorded for this store.</Empty>
                        )}
                      </div>
                    </div>
                  </Card>

                  <Card
                    title="Registered documents"
                    action={
                      <select
                        value={trustFilter}
                        onChange={(e) => setTrustFilter(e.target.value)}
                        className="h-8 rounded-md border border-slate-300 bg-white px-2 text-xs"
                      >
                        <option value="">All trust labels</option>
                        {TRUST_LEVELS.map((label) => (
                          <option key={label} value={label}>{humanLabel(label)}</option>
                        ))}
                      </select>
                    }
                  >
                    {!documents.length ? (
                      <Empty>No documents registered for this store with the current filter.</Empty>
                    ) : (
                      <div className="overflow-auto rounded-lg border border-slate-200">
                        <table className="w-full border-collapse text-sm">
                          <thead>
                            <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                              <th className="p-2.5">Document</th>
                              <th className="p-2.5">Trust</th>
                              <th className="p-2.5">Source</th>
                              <th className="p-2.5">Registered</th>
                              <th className="p-2.5">Hash</th>
                            </tr>
                          </thead>
                          <tbody>
                            {documents.map((document) => (
                              <tr key={document.doc_id} className="border-t border-slate-100 align-top">
                                <td className="p-2.5 font-medium text-ink">{document.doc_id}</td>
                                <td className="p-2.5"><Pill value={document.trust_label || "UNKNOWN"} /></td>
                                <td className="p-2.5">{humanLabel(document.source_type || "unknown")}</td>
                                <td className="p-2.5 text-muted">{fmtDate(document.registered_at)}</td>
                                <td className="p-2.5 font-mono text-xs text-slate-500" title={document.content_hash || ""}>
                                  {document.content_hash ? `${document.content_hash.slice(0, 12)}…` : "Unavailable"}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </Card>
                </div>
              );
            })()}
          </div>
        </div>
      </Card>
    </div>
  );
}

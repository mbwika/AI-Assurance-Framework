import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Empty, Metric, Tag, fmtDate, humanLabel } from "../ui.jsx";

const COLUMN_WIDTH = 200;
const ROW_HEIGHT = 76;
const NODE_WIDTH = 168;
const NODE_HEIGHT = 52;
const PAD = 24;

// Layered (Sugiyama-style) DAG layout: depth = longest path from a root.
// The backend guarantees acyclicity (add_influence_edge rejects cycles), so
// a single forward pass over a topological order is sufficient here.
function layoutGraph(nodes, edges) {
  const byId = new Map(nodes.map((n) => [n.node_id, n]));
  const outgoing = new Map(nodes.map((n) => [n.node_id, []]));
  const inDegree = new Map(nodes.map((n) => [n.node_id, 0]));
  for (const edge of edges) {
    if (!byId.has(edge.from_node_id) || !byId.has(edge.to_node_id)) continue;
    outgoing.get(edge.from_node_id).push(edge.to_node_id);
    inDegree.set(edge.to_node_id, (inDegree.get(edge.to_node_id) || 0) + 1);
  }

  const depth = new Map();
  const queue = nodes.filter((n) => (inDegree.get(n.node_id) || 0) === 0).map((n) => n.node_id);
  for (const id of queue) depth.set(id, 0);
  const remaining = new Map(inDegree);
  let cursor = 0;
  const order = [...queue];
  while (cursor < order.length) {
    const current = order[cursor++];
    for (const next of outgoing.get(current) || []) {
      depth.set(next, Math.max(depth.get(next) ?? 0, (depth.get(current) ?? 0) + 1));
      remaining.set(next, (remaining.get(next) || 0) - 1);
      if (remaining.get(next) === 0) order.push(next);
    }
  }
  // Anything unreached (shouldn't happen in a DAG reachable from roots, but
  // guards against a disconnected/self-referential edge case) gets depth 0.
  for (const n of nodes) if (!depth.has(n.node_id)) depth.set(n.node_id, 0);

  const columns = new Map();
  for (const n of nodes) {
    const d = depth.get(n.node_id);
    if (!columns.has(d)) columns.set(d, []);
    columns.get(d).push(n.node_id);
  }

  const positions = new Map();
  const maxDepth = Math.max(0, ...[...columns.keys()]);
  const maxRows = Math.max(1, ...[...columns.values()].map((c) => c.length));
  for (const [d, ids] of columns) {
    ids.forEach((id, i) => {
      positions.set(id, {
        x: PAD + d * COLUMN_WIDTH,
        y: PAD + i * ROW_HEIGHT,
      });
    });
  }

  return {
    positions,
    width: PAD * 2 + (maxDepth + 1) * COLUMN_WIDTH - (COLUMN_WIDTH - NODE_WIDTH),
    height: PAD * 2 + maxRows * ROW_HEIGHT - (ROW_HEIGHT - NODE_HEIGHT),
  };
}

function GraphDiagram({ nodes, edges, seedIds, influencedIds, hasQuery }) {
  const { positions, width, height } = useMemo(() => layoutGraph(nodes, edges), [nodes, edges]);
  if (!nodes.length) return <Empty>This graph has no nodes yet.</Empty>;

  const emphasisActive = hasQuery;
  const nodeTone = (id) => {
    if (!emphasisActive) return "default";
    if (seedIds.has(id)) return "seed";
    if (influencedIds.has(id)) return "influenced";
    return "dim";
  };

  return (
    <div className="overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-3">
      <svg width={Math.max(width, 320)} height={Math.max(height, 160)} role="img" aria-label="Context provenance graph">
        <defs>
          <marker id="cp-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8" />
          </marker>
          <marker id="cp-arrow-accent" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#0f766e" />
          </marker>
        </defs>
        {edges.map((edge, i) => {
          const from = positions.get(edge.from_node_id);
          const to = positions.get(edge.to_node_id);
          if (!from || !to) return null;
          const x1 = from.x + NODE_WIDTH;
          const y1 = from.y + NODE_HEIGHT / 2;
          const x2 = to.x;
          const y2 = to.y + NODE_HEIGHT / 2;
          const midX = (x1 + x2) / 2;
          const onPath = emphasisActive && seedIds.has(edge.from_node_id) &&
            (seedIds.has(edge.to_node_id) || influencedIds.has(edge.to_node_id));
          return (
            <g key={i}>
              <path
                d={`M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`}
                fill="none"
                stroke={onPath ? "#0f766e" : "#cbd5e1"}
                strokeWidth={onPath ? 2 : 1.5}
                opacity={emphasisActive && !onPath ? 0.35 : 1}
                markerEnd={onPath ? "url(#cp-arrow-accent)" : "url(#cp-arrow)"}
              />
              <text
                x={midX}
                y={(y1 + y2) / 2 - 6}
                textAnchor="middle"
                fontSize="9"
                fill="#94a3b8"
                opacity={emphasisActive && !onPath ? 0.35 : 0.9}
              >
                {edge.relationship}
              </text>
            </g>
          );
        })}
        {nodes.map((node) => {
          const pos = positions.get(node.node_id);
          if (!pos) return null;
          const tone = nodeTone(node.node_id);
          const fill = { default: "#ffffff", seed: "#ccfbf1", influenced: "#f0fdfa", dim: "#f8fafc" }[tone];
          const stroke = { default: "#cbd5e1", seed: "#0f766e", influenced: "#5eead4", dim: "#e2e8f0" }[tone];
          const textOpacity = tone === "dim" ? 0.45 : 1;
          return (
            <g key={node.node_id} transform={`translate(${pos.x},${pos.y})`}>
              <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx={10} fill={fill} stroke={stroke} strokeWidth={tone === "seed" ? 2 : 1.5} />
              <text x={10} y={18} fontSize="9.5" fontWeight="700" letterSpacing="0.04em" fill="#5f6f83" opacity={textOpacity}>
                {humanLabel(node.node_type)}
              </text>
              <text x={10} y={36} fontSize="12" fontWeight="600" fill="#18212f" opacity={textOpacity}>
                {(node.source_ref || node.node_id).length > 22
                  ? `${(node.source_ref || node.node_id).slice(0, 21)}…`
                  : node.source_ref || node.node_id}
              </text>
            </g>
          );
        })}
      </svg>
      {emphasisActive && (
        <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted">
          <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border-2 border-accent bg-teal-100" />seed</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-teal-300 bg-teal-50" />influenced</span>
          <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-slate-200 bg-slate-50 opacity-60" />not affected</span>
        </div>
      )}
    </div>
  );
}

export default function ContextProvenance({ refreshToken }) {
  const graphsResource = useResource(() => api.provenanceGraphs(100), [refreshToken]);
  const graphs = graphsResource.data?.graphs || [];
  const [selectedGraphId, setSelectedGraphId] = useState("");
  const [query, setQuery] = useState("");
  const [sourceRefInput, setSourceRefInput] = useState("");
  const [influenceQuery, setInfluenceQuery] = useState(null);

  useEffect(() => {
    if (!selectedGraphId && graphs.length) {
      setSelectedGraphId(graphs[0].graph_id || "");
    }
    if (selectedGraphId && !graphs.some((g) => g.graph_id === selectedGraphId)) {
      setSelectedGraphId(graphs[0]?.graph_id || "");
    }
  }, [graphs, selectedGraphId]);

  useEffect(() => {
    setInfluenceQuery(null);
    setSourceRefInput("");
  }, [selectedGraphId]);

  const filteredGraphs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return graphs.filter((g) => {
      const haystack = [g.graph_id, g.name, g.session_id, g.model_id].filter(Boolean).join(" ").toLowerCase();
      return !needle || haystack.includes(needle);
    });
  }, [graphs, query]);

  const detailResource = useResource(
    () => (selectedGraphId ? api.provenanceGraph(selectedGraphId) : Promise.resolve(null)),
    [refreshToken, selectedGraphId]
  );

  const totalNodes = graphs.reduce((sum, g) => sum + Number(g.node_count || 0), 0);
  const totalEdges = graphs.reduce((sum, g) => sum + Number(g.edge_count || 0), 0);

  async function runInfluenceQuery() {
    const ref = sourceRefInput.trim();
    if (!ref) return;
    try {
      const result = await api.provenanceInfluence(ref, selectedGraphId);
      setInfluenceQuery(result);
    } catch (error) {
      setInfluenceQuery({ error: error.message });
    }
  }

  const graph = detailResource.data;
  const nodes = graph ? Object.values(graph.nodes || {}).sort((a, b) => a.node_id.localeCompare(b.node_id)) : [];
  const edges = graph?.edges || [];

  const graphResult = influenceQuery?.graph_results?.find((r) => r.graph_id === selectedGraphId);
  const seedIds = new Set(graphResult?.seed_node_ids || []);
  const influencedIds = new Set((graphResult?.influenced_nodes || []).map((n) => n.node_id));
  const hasQuery = Boolean(influenceQuery && !influenceQuery.error);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Provenance Graphs" value={graphs.length} sub="registered traces" />
        <Metric label="Total Nodes" value={totalNodes} sub="across all graphs" />
        <Metric label="Total Edges" value={totalEdges} sub="influence relationships" />
        <Metric label="Selected Graph" value={graph?.node_count ?? "—"} sub={selectedGraphId || "none selected"} />
      </div>

      <Card
        title="Context provenance graphs"
        action={<Tag>runtime blast-radius trace</Tag>}
      >
        <p className="mb-4 max-w-3xl text-sm leading-6 text-muted">
          Each graph traces how prompts, retrieved documents, tool outputs, and policy/guardrail decisions influenced
          a model response. Query a <code>source_ref</code> below to highlight its blast radius &mdash; everything
          downstream that it could have influenced.
        </p>
        <div className="grid gap-4 lg:grid-cols-[0.8fr,1.2fr]">
          <div className="space-y-3">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search graph id, name, session, model"
              className="h-9 w-full rounded-md border border-slate-300 px-3 text-sm"
            />
            {graphsResource.loading && !graphs.length ? (
              <Empty>Loading provenance graphs&hellip;</Empty>
            ) : graphsResource.error ? (
              <Empty>{graphsResource.error}</Empty>
            ) : !filteredGraphs.length ? (
              <Empty>No provenance graphs registered yet. Register one at POST /v1/context-provenance/graphs.</Empty>
            ) : (
              <div className="space-y-2">
                {filteredGraphs.map((g) => {
                  const active = selectedGraphId === g.graph_id;
                  return (
                    <button
                      key={g.graph_id}
                      type="button"
                      onClick={() => setSelectedGraphId(g.graph_id)}
                      className={`w-full rounded-2xl border p-3 text-left transition ${
                        active
                          ? "border-emerald-400 bg-emerald-50/60 shadow-sm"
                          : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50"
                      }`}
                    >
                      <div className="font-semibold text-ink">{g.name || g.graph_id}</div>
                      <div className="mt-1 text-xs text-muted">{g.graph_id}</div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Tag>{g.node_count || 0} nodes</Tag>
                        <Tag>{g.edge_count || 0} edges</Tag>
                        {g.model_id ? <Tag>model {g.model_id.slice(0, 8)}&hellip;</Tag> : null}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="space-y-4">
            {!selectedGraphId ? (
              <Empty>Select a graph to inspect its trace.</Empty>
            ) : detailResource.loading && !graph ? (
              <Empty>Loading graph&hellip;</Empty>
            ) : detailResource.error ? (
              <Empty>{detailResource.error}</Empty>
            ) : (
              <>
                <div className="flex flex-wrap items-end gap-2 rounded-xl border border-slate-200 bg-white p-3">
                  <div className="flex-1">
                    <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">Blast-radius query</div>
                    <input
                      value={sourceRefInput}
                      onChange={(e) => setSourceRefInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && runInfluenceQuery()}
                      placeholder="source_ref, e.g. web-int-err"
                      className="mt-1.5 h-9 w-full rounded-md border border-slate-300 px-3 text-sm"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={runInfluenceQuery}
                    className="h-9 rounded-md bg-accent px-4 text-sm font-bold text-white hover:bg-accent-strong"
                  >
                    Trace influence
                  </button>
                  {influenceQuery ? (
                    <button
                      type="button"
                      onClick={() => { setInfluenceQuery(null); setSourceRefInput(""); }}
                      className="h-9 rounded-md border border-slate-300 px-3 text-sm text-muted hover:bg-slate-50"
                    >
                      Clear
                    </button>
                  ) : null}
                </div>
                {influenceQuery?.error ? (
                  <Empty>{influenceQuery.error}</Empty>
                ) : influenceQuery ? (
                  <div className="rounded-xl border border-teal-200 bg-teal-50/60 p-3 text-sm text-ink">
                    <strong>{influenceQuery.source_ref}</strong> seeded {influenceQuery.seed_node_count} node(s) and
                    influenced {influenceQuery.influenced_node_count} downstream node(s)
                    {graphResult ? "" : " (not present in this graph)"}.
                  </div>
                ) : null}

                <Card title="Graph diagram">
                  <GraphDiagram nodes={nodes} edges={edges} seedIds={seedIds} influencedIds={influencedIds} hasQuery={hasQuery} />
                </Card>

                <Card title="Nodes">
                  {!nodes.length ? (
                    <Empty>No nodes in this graph yet.</Empty>
                  ) : (
                    <div className="overflow-auto rounded-lg border border-slate-200">
                      <table className="w-full border-collapse text-sm">
                        <thead>
                          <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                            <th className="p-2.5">Node</th>
                            <th className="p-2.5">Type</th>
                            <th className="p-2.5">Source ref</th>
                            <th className="p-2.5">Recorded</th>
                          </tr>
                        </thead>
                        <tbody>
                          {nodes.map((node) => (
                            <tr key={node.node_id} className="border-t border-slate-100 align-top">
                              <td className="p-2.5 font-medium text-ink">{node.node_id}</td>
                              <td className="p-2.5">{humanLabel(node.node_type)}</td>
                              <td className="p-2.5 font-mono text-xs text-slate-600">{node.source_ref || "—"}</td>
                              <td className="p-2.5 text-muted">{fmtDate(node.recorded_at)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>
              </>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}

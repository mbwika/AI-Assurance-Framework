import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Metric, Empty, Tag } from "../ui.jsx";

export default function Architecture({ refreshToken }) {
  const { loading, error, data } = useResource(() => api.architecture(), [refreshToken]);

  if (loading && !data) return <Empty>Loading the framework architecture map…</Empty>;
  if (error) return <Empty>{error}</Empty>;

  const layers = data.layers || [];
  const components = data.components || [];
  const byLayer = {};
  for (const c of components) (byLayer[c.layer] = byLayer[c.layer] || []).push(c);
  const componentCount = data.component_count ?? (components.length || layers.reduce((n, l) => n + (l.components || []).length, 0));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Layers" value={data.layer_count ?? layers.length} sub="defense-in-depth" />
        <Metric label="Components" value={componentCount} sub="across the stack" />
        <Metric label="Version" value={data.version || "—"} sub={data.name || "AIAF"} />
        <Metric label="Routes" value={layers.reduce((n, l) => n + (l.components || []).reduce((m, c) => m + ((c.routes || []).length), 0), 0)} sub="wired into the API" />
      </div>

      {layers.length ? (
        <div className="space-y-3">
          {layers.map((layer, i) => {
            const id = layer.id ?? layer.key ?? layer.name;
            const items = byLayer[id] || byLayer[layer.name] || layer.components || [];
            return (
              <Card key={id || i} title={`${layer.order ?? i + 1}. ${layer.name || id}`} action={<span className="text-xs text-muted">{items.length} component{items.length === 1 ? "" : "s"}</span>}>
                {layer.description && <p className="mb-3 text-sm text-muted">{layer.description}</p>}
                {items.length ? (
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {items.map((c, j) => {
                      const comp = typeof c === "string" ? { name: c } : c;
                      return (
                        <div key={comp.id || comp.name || j} className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
                          <div className="text-sm font-bold text-ink">{comp.name || comp.id}</div>
                          {comp.module && <div className="mt-0.5 font-mono text-xs text-muted">{comp.module}</div>}
                          {comp.description && <div className="mt-0.5 text-xs text-muted">{comp.description}</div>}
                          <div className="mt-2 flex flex-wrap gap-1">
                            {(comp.routes || []).map((r, k) => <Tag key={k}>{r}</Tag>)}
                            {(comp.standards || []).map((s, k) => <Tag key={`s${k}`}>{s}</Tag>)}
                            {comp.status && <Tag>{comp.status}</Tag>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-sm text-muted">No components declared for this layer.</p>
                )}
              </Card>
            );
          })}
        </div>
      ) : (
        <Card title="Components">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {components.map((c, j) => (
              <div key={c.id || c.name || j} className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
                <div className="text-sm font-bold text-ink">{c.name || c.id}</div>
                {c.layer && <div className="text-xs text-muted">{c.layer}</div>}
                {c.description && <div className="mt-1 text-xs text-muted">{c.description}</div>}
              </div>
            ))}
          </div>
          {!components.length && <Empty>No architecture metadata exposed by the API.</Empty>}
        </Card>
      )}
    </div>
  );
}

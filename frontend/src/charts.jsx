import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { Empty } from "./ui.jsx";

const SEV_COLOR = {
  CRITICAL: "#912018",
  HIGH: "#b42318",
  MEDIUM: "#b54708",
  LOW: "#067647",
};

function shortTick(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function TrendTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs shadow-sm">
      <div className="font-semibold">{Number(p.value).toFixed(2)}</div>
      <div className="text-muted">{new Date(p.t).toLocaleString()}</div>
      {p.artifact_id && <div className="text-muted">{p.artifact_id}</div>}
    </div>
  );
}

export function TrendLine({ points, domain, color = "#0f766e", height = 190 }) {
  const data = (points || [])
    .map((p) => ({ t: p.t, value: Number(p.value), artifact_id: p.artifact_id }))
    .filter((p) => Number.isFinite(p.value));
  if (data.length < 1) return <Empty>No metric history yet — run analyses to build a trend.</Empty>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 10, bottom: 0, left: -18 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eef1f5" />
        <XAxis dataKey="t" tickFormatter={shortTick} tick={{ fontSize: 10, fill: "#5f6f83" }} minTickGap={48} />
        <YAxis domain={domain} tick={{ fontSize: 11, fill: "#5f6f83" }} width={40} allowDecimals={false} />
        <Tooltip content={<TrendTooltip />} />
        <Line type="monotone" dataKey="value" stroke={color} strokeWidth={2.25} dot={{ r: 2 }} activeDot={{ r: 4 }} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function SeverityBars({ counts, severityColors = false, height = 190 }) {
  const data = Object.entries(counts || {})
    .filter(([, n]) => Number(n) > 0)
    .map(([name, value]) => ({ name, value: Number(value) }))
    .sort((a, b) => b.value - a.value);
  if (!data.length) return <Empty>No data.</Empty>;
  return (
    <ResponsiveContainer width="100%" height={Math.max(height, data.length * 30 + 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eef1f5" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "#5f6f83" }} />
        <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 12, fill: "#344255" }} />
        <Tooltip cursor={{ fill: "#f1f5f9" }} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {data.map((entry, i) => (
            <Cell key={i} fill={severityColors ? SEV_COLOR[entry.name.toUpperCase()] || "#0f766e" : "#0f766e"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

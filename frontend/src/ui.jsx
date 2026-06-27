// Shared presentational primitives.

const SEV = {
  low: "bg-emerald-50 text-emerald-700 border-emerald-200",
  ok: "bg-emerald-50 text-emerald-700 border-emerald-200",
  pass: "bg-emerald-50 text-emerald-700 border-emerald-200",
  // Adoption verdicts (worst -> best)
  do_not_approve: "bg-red-50 text-red-700 border-red-200",
  insufficient_evidence: "bg-amber-50 text-amber-700 border-amber-200",
  pilot_only: "bg-amber-50 text-amber-700 border-amber-200",
  approve_with_conditions: "bg-teal-50 text-teal-700 border-teal-200",
  approve_for_scoped_use: "bg-emerald-50 text-emerald-700 border-emerald-200",
  do_not_trust: "bg-red-50 text-red-700 border-red-200",
  declaration_heavy: "bg-amber-50 text-amber-700 border-amber-200",
  artifact_observed: "bg-sky-50 text-sky-700 border-sky-200",
  substantial_assurance: "bg-emerald-50 text-emerald-700 border-emerald-200",
  // Evidence origins (weakest -> strongest)
  user_entered: "bg-red-50 text-red-700 border-red-200",
  provider_declared: "bg-amber-50 text-amber-700 border-amber-200",
  artifact_derived: "bg-sky-50 text-sky-700 border-sky-200",
  locally_observed: "bg-teal-50 text-teal-700 border-teal-200",
  independently_verified: "bg-emerald-50 text-emerald-700 border-emerald-200",
  satisfied: "bg-emerald-50 text-emerald-700 border-emerald-200",
  authenticated: "bg-emerald-50 text-emerald-700 border-emerald-200",
  improving: "bg-emerald-50 text-emerald-700 border-emerald-200",
  covered: "bg-emerald-50 text-emerald-700 border-emerald-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  needs_review: "bg-amber-50 text-amber-700 border-amber-200",
  review_needed: "bg-amber-50 text-amber-700 border-amber-200",
  partial: "bg-amber-50 text-amber-700 border-amber-200",
  stable: "bg-amber-50 text-amber-700 border-amber-200",
  baseline: "bg-amber-50 text-amber-700 border-amber-200",
  clear: "bg-emerald-50 text-emerald-700 border-emerald-200",
  completed: "bg-emerald-50 text-emerald-700 border-emerald-200",
  high: "bg-red-50 text-red-700 border-red-200",
  high_risk: "bg-red-50 text-red-700 border-red-200",
  critical: "bg-red-50 text-red-700 border-red-200",
  fail: "bg-red-50 text-red-700 border-red-200",
  missing: "bg-red-50 text-red-700 border-red-200",
  worsening: "bg-red-50 text-red-700 border-red-200",
  deteriorating: "bg-red-50 text-red-700 border-red-200",
  unverified: "bg-red-50 text-red-700 border-red-200",
  endpoint_error: "bg-amber-50 text-amber-700 border-amber-200",
  not_run: "bg-slate-100 text-slate-700 border-slate-200",
  insufficient_data: "bg-slate-100 text-slate-700 border-slate-200",
  permissive_declared: "bg-emerald-50 text-emerald-700 border-emerald-200",
  restricted_declared: "bg-amber-50 text-amber-700 border-amber-200",
  custom_or_unknown: "bg-slate-100 text-slate-700 border-slate-200",
  license_missing: "bg-red-50 text-red-700 border-red-200",
  artifact_confirmed: "bg-emerald-50 text-emerald-700 border-emerald-200",
  contradictions_found: "bg-red-50 text-red-700 border-red-200",
  declared_only: "bg-amber-50 text-amber-700 border-amber-200",
  no_model_card: "bg-slate-100 text-slate-700 border-slate-200",
};

export function cls(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z_]/g, "_");
}

export function humanLabel(value) {
  const text = String(value ?? "").trim();
  if (!text) return "UNKNOWN";
  return text.includes("_") ? text.replaceAll("_", " ").toUpperCase() : text;
}

export function Pill({ value }) {
  const tone = SEV[cls(value)] || "bg-slate-100 text-slate-600 border-slate-200";
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-extrabold ${tone}`}>
      {humanLabel(value)}
    </span>
  );
}

export function Card({ title, action, children, className = "" }) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white p-4 ${className}`}>
      {(title || action) && (
        <div className="mb-3 flex items-baseline justify-between gap-3">
          {title && <h3 className="text-sm font-bold text-ink">{title}</h3>}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Metric({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <span className="text-xs font-bold uppercase tracking-wider text-muted">{label}</span>
      <div className="mt-2 text-3xl font-bold leading-none">{value}</div>
      <div className="mt-2 text-sm text-muted">{sub}</div>
    </div>
  );
}

export function Empty({ children }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-muted">
      {children}
    </div>
  );
}

export function fmtDate(value) {
  if (!value) return "Unknown";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export function Tag({ children }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-300 bg-slate-50 px-2 py-0.5 text-[11px] font-semibold text-slate-700">
      {children}
    </span>
  );
}

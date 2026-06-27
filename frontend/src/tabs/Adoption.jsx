import { useState } from "react";
import { api } from "../api.js";
import { useResource } from "../useResource.js";
import { Card, Metric, Pill, Tag, Empty, fmtDate, humanLabel } from "../ui.jsx";

// ---------------------------------------------------------------------------
// Severity badge: reuse existing Pill or fall back to a coloured span
// ---------------------------------------------------------------------------
const SEV_CLASS = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM: "bg-amber-100 text-amber-800 border-amber-200",
  LOW: "bg-slate-100 text-slate-700 border-slate-200",
};

function SevBadge({ sev }) {
  const cls = SEV_CLASS[String(sev).toUpperCase()] || SEV_CLASS.LOW;
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${cls}`}>
      {sev}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Phase 2: serialization scan panel
// ---------------------------------------------------------------------------
function SerialScanSection({ inputs }) {
  const status = inputs.serialization_status;
  if (!status) {
    return (
      <div className="rounded-lg border border-slate-200 p-3 text-sm text-muted">
        Serialization scan not available. Register the model with a local artifact file to enable.
      </div>
    );
  }
  const isUnsafe = status === "UNSAFE_PATTERNS_FOUND";
  const isSuspicious = status === "SUSPICIOUS";
  const count = inputs.serialization_match_count ?? 0;
  const statusClass = isUnsafe
    ? "bg-red-50 border-red-200 text-red-800"
    : isSuspicious
    ? "bg-amber-50 border-amber-200 text-amber-800"
    : "bg-emerald-50 border-emerald-200 text-emerald-800";

  return (
    <div className={`rounded-lg border p-3 text-sm ${statusClass}`}>
      <div className="flex items-center gap-2 font-semibold">
        <span>{isUnsafe || isSuspicious ? "⚠" : "✓"}</span>
        <span>{humanLabel(status)}</span>
      </div>
      {count > 0 && (
        <p className="mt-1">{count} finding(s) detected in model artifact.</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phase 2: behavioral probe panel
// ---------------------------------------------------------------------------
function ProbeScanSection({ inputs }) {
  const status = inputs.behavioral_probe_status;
  if (!status) {
    return (
      <div className="rounded-lg border border-slate-200 p-3 text-sm text-muted">
        Behavioral probes not run. Provide an endpoint URL and re-run triage to enable.
      </div>
    );
  }
  const failures = inputs.behavioral_probe_failures ?? 0;
  const isDanger = failures > 0;
  const isError = status === "ENDPOINT_ERROR" || status === "NO_ENDPOINT";
  const statusClass = isDanger
    ? "bg-red-50 border-red-200 text-red-800"
    : isError
    ? "bg-amber-50 border-amber-200 text-amber-800"
    : "bg-emerald-50 border-emerald-200 text-emerald-800";

  return (
    <div className={`rounded-lg border p-3 text-sm ${statusClass}`}>
      <div className="flex items-center gap-2 font-semibold">
        <span>{isDanger ? "✗" : isError ? "⚠" : "✓"}</span>
        <span>{humanLabel(status)}</span>
      </div>
      {status === "COMPLETED" && (
        <p className="mt-1">
          {failures === 0 ? "All probes passed." : `${failures} probe(s) failed safety evaluation.`}
        </p>
      )}
      {isError && <p className="mt-1">Could not reach the model endpoint.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phase 4: red-team evaluation panel
// ---------------------------------------------------------------------------
function RedTeamSection({ inputs }) {
  const status = inputs.redteam_status;
  if (!status) {
    return (
      <div className="rounded-lg border border-slate-200 p-3 text-sm text-muted">
        Full red-team evaluation not run. Use the launcher below to run garak / PyRIT
        against a live endpoint.
      </div>
    );
  }
  const failures = inputs.redteam_total_failures ?? 0;
  const families = inputs.redteam_families_run ?? 0;
  const backend = inputs.redteam_backend || "garak";
  const isError = ["ENDPOINT_ERROR", "ERROR", "TOOL_NOT_INSTALLED"].includes(status);
  const isPartial = status === "PARTIAL";
  const isDanger = failures > 0 && !isError;
  const statusClass = isDanger
    ? "bg-red-50 border-red-200 text-red-800"
    : isError
    ? "bg-amber-50 border-amber-200 text-amber-800"
    : isPartial
    ? "bg-amber-50 border-amber-200 text-amber-800"
    : "bg-emerald-50 border-emerald-200 text-emerald-800";

  return (
    <div className={`rounded-lg border p-3 text-sm ${statusClass}`}>
      <div className="flex items-center gap-2 font-semibold">
        <span>{isDanger ? "✗" : isError || isPartial ? "⚠" : "✓"}</span>
        <span>{humanLabel(status)}</span>
        <span className="ml-auto text-[11px] font-normal opacity-70">{backend}</span>
      </div>
      {status === "COMPLETED" && (
        <p className="mt-1">
          {failures === 0
            ? `All probes passed across ${families} family(ies).`
            : `${failures} failure(s) across ${families} probe family(ies).`}
        </p>
      )}
      {status === "TOOL_NOT_INSTALLED" && (
        <p className="mt-1">Install garak with: <code className="rounded bg-amber-100 px-1">pip install garak</code></p>
      )}
      {isPartial && (
        <p className="mt-1">Partial results — re-run with a longer timeout for full coverage.</p>
      )}
    </div>
  );
}

function fmtPct(value) {
  const num = Number(value);
  return Number.isFinite(num) ? `${Math.round(num * 100)}%` : "—";
}

function UnknownModelAssuranceSection({ assurance }) {
  if (!assurance) return null;

  const identity = assurance.artifact_identity || {};
  const inspection = assurance.artifact_inspection || {};
  const consistency = assurance.model_card_consistency || {};
  const lineage = assurance.lineage || {};
  const license = assurance.license_posture || {};
  const security = assurance.security_flags || {};
  const profile = assurance.evidence_profile || {};
  const probe = assurance.unknown_model_probe || {};
  const runtime = probe.runtime_probes || {};
  const gaps = assurance.evidence_gaps || [];
  const nextSteps = assurance.recommended_next_steps || [];
  const contradictionCount = (consistency.contradictions || []).length;
  const blockingCount = (security.blocking_reasons || []).length;

  return (
    <div className="mt-5 space-y-4">
      <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Pill value={assurance.posture} />
          <Pill value={identity.identity_status || "unknown"} />
          {license.status && <Pill value={license.status} />}
          {consistency.status && <Pill value={consistency.status} />}
        </div>
        <p className="mt-3 text-sm text-ink">{assurance.summary}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-bold text-ink">Identity & provenance</h4>
          <div className="mt-3 grid grid-cols-2 gap-3">
            <Metric label="Provenance" value={identity.provenance_score ?? "—"} sub={humanLabel(identity.provenance_risk_level || "unknown")} />
            <Metric label="Confidence" value={fmtPct(identity.provenance_confidence)} sub="assessment confidence" />
            <Metric label="Independence" value={fmtPct(identity.provenance_independence_ratio)} sub="decision-driving facts" />
            <Metric label="Trust caps" value={(identity.trust_caps || []).length} sub="active ceilings" />
          </div>
          <div className="mt-3 space-y-1.5 text-sm text-muted">
            <div><span className="font-medium text-ink">Source:</span> {identity.source || "unknown"}</div>
            <div><span className="font-medium text-ink">Publisher:</span> {identity.publisher || "unknown"}</div>
            <div><span className="font-medium text-ink">Repo:</span> {identity.repo_id || "not recorded"}</div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-bold text-ink">Artifact inspection</h4>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Serialization</span>
              <Pill value={inspection.serialization_status || "missing"} />
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Weights</span>
              <Pill value={inspection.weight_inspection_status || "missing"} />
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Format</span>
              <span className="font-medium text-ink">{inspection.format_detected || "unknown"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Architecture</span>
              <span className="font-medium text-ink">{humanLabel(inspection.architecture_family || "unknown")}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Layers</span>
              <span className="font-medium text-ink">{inspection.layer_count ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Parameters</span>
              <span className="font-medium text-ink">{inspection.parameter_count_estimate ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Quantization</span>
              <span className="font-medium text-ink">{inspection.quantization || "unknown"}</span>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-bold text-ink">Consistency & lineage</h4>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Confirmed facts</span>
              <span className="font-medium text-ink">{(consistency.confirmed_facts || []).length}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Contradictions</span>
              <span className="font-medium text-ink">{contradictionCount}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Base model</span>
              <span className="font-medium text-ink">{lineage.base_model || "unresolved"}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Lineage source</span>
              <span className="font-medium text-ink">{humanLabel(lineage.lineage_source || "unknown")}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Architecture check</span>
              <span className="font-medium text-ink">{humanLabel(lineage.architecture_consistency || "unknown")}</span>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">License</span>
              <span className="font-medium text-ink">{license.declared_license || "missing"}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-bold text-ink">What AIAF observed itself</h4>
          {(profile.self_observed_facts || []).length ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {(profile.self_observed_facts || []).map((item) => (
                <Tag key={item}>{humanLabel(item)}</Tag>
              ))}
            </div>
          ) : (
            <Empty>No artifact-observed facts recorded yet.</Empty>
          )}

          <h4 className="mt-4 text-sm font-bold text-ink">Still self-asserted</h4>
          {(profile.declared_only_facts || []).length ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {(profile.declared_only_facts || []).map((item) => (
                <Tag key={item}>{humanLabel(item)}</Tag>
              ))}
            </div>
          ) : (
            <Empty>No declaration-only facts remain in the ledger.</Empty>
          )}
        </div>

        <div className="rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-bold text-ink">Current blockers</h4>
          {blockingCount || contradictionCount || security.high_or_critical_vulnerability_count ? (
            <div className="mt-3 space-y-2">
              {security.dangerous_serialization && (
                <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700">
                  Unsafe serialization patterns were detected in the artifact.
                </div>
              )}
              {security.high_or_critical_vulnerability_count > 0 && (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-sm text-amber-800">
                  {security.high_or_critical_vulnerability_count} high or critical dependency vulnerabilities remain open.
                </div>
              )}
              {(consistency.contradictions || []).slice(0, 3).map((item, idx) => (
                <div key={idx} className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700">
                  {humanLabel(item.fact_name)} declared as {String(item.declared_value)} but artifact inspection derived {String(item.derived_value)}.
                </div>
              ))}
              {(security.blocking_reasons || []).slice(0, 3).map((item, idx) => (
                <div key={`reason-${idx}`} className="rounded-md border border-slate-200 bg-slate-50 p-2 text-sm text-ink">
                  {item.reason}
                </div>
              ))}
            </div>
          ) : (
            <Empty>No immediate blockers surfaced in the current unknown-model assurance view.</Empty>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="text-sm font-bold text-ink">Lightweight unknown-model probes</h4>
          {probe.status && <Pill value={probe.status} />}
        </div>
        {runtime.status && (
          <div className="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-ink">Runtime privacy and memorization checks</span>
              <Pill value={runtime.status} />
              <Tag>{runtime.triggered_count || 0} triggered</Tag>
              <Tag>{runtime.probes_run || 0} run</Tag>
            </div>
            {runtime.note && <p className="mt-2 text-sm text-muted">{runtime.note}</p>}
            {(runtime.probe_results || []).length > 0 && (
              <div className="mt-3 grid gap-2">
                {(runtime.probe_results || []).map((item) => {
                  const analysis = item.response_analysis || {};
                  const indicators = analysis.indicators || [];
                  const isTriggered = String(item.result || "").toUpperCase() === "TRIGGERED";
                  return (
                    <div key={item.id} className="rounded-md border border-slate-200 bg-white p-2.5 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-ink">{humanLabel(item.id)}</span>
                        <Tag>{humanLabel(item.result || "unknown")}</Tag>
                        {isTriggered && <SevBadge sev={item.severity || "HIGH"} />}
                      </div>
                      <div className="mt-1 text-muted">{item.purpose}</div>
                      {indicators.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {indicators.map((indicator) => (
                            <Tag key={`${item.id}-${indicator}`}>{humanLabel(indicator)}</Tag>
                          ))}
                        </div>
                      )}
                      {item.error && <div className="mt-2 text-xs text-red-700">{item.error}</div>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
        {(probe.findings || []).length ? (
          <div className="mt-3 grid gap-2">
            {(probe.findings || []).map((item, idx) => (
              <div key={idx} className="rounded-md border border-slate-200 bg-slate-50 p-2.5 text-sm">
                <div className="flex items-center gap-2">
                  <SevBadge sev={item.severity || "LOW"} />
                  <span className="font-medium text-ink">{humanLabel(item.indicator || "review_finding")}</span>
                </div>
                <div className="mt-1 text-muted">{item.description}</div>
              </div>
            ))}
          </div>
        ) : (
          <Empty>No additional lightweight unknown-model probe findings were generated.</Empty>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-bold text-ink">Evidence gaps</h4>
          {gaps.length ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
              {gaps.map((gap, idx) => <li key={idx}>{gap}</li>)}
            </ul>
          ) : (
            <Empty>No outstanding unknown-model evidence gaps.</Empty>
          )}
        </div>
        <div>
          <h4 className="mb-2 text-sm font-bold text-ink">Recommended next steps</h4>
          {nextSteps.length ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-ink">
              {nextSteps.map((step, idx) => <li key={idx}>{step}</li>)}
            </ul>
          ) : (
            <Empty>No additional next steps were generated.</Empty>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main verdict panel
// ---------------------------------------------------------------------------
function VerdictPanel({ rec }) {
  const inputs = rec.inputs || {};
  const reasons = rec.reasons || [];
  const conditions = rec.conditions || [];
  const gaps = rec.evidence_gaps || [];
  const origins = rec.evidence_origin_summary || {};
  const policy = rec.policy || {};
  const policyContext = policy.context || {};
  const policyPosture = policy.posture || {};
  const requiredEvidence = policy.required_evidence || [];
  const approvalScope = policy.approval_scope || {};
  const confidencePct = Math.round((Number(rec.confidence) || 0) * 100);
  const [downloadingBom, setDownloadingBom] = useState(false);
  const [downloadError, setDownloadError] = useState("");

  async function downloadBom() {
    if (!rec?.model_id) return;
    setDownloadingBom(true);
    setDownloadError("");
    try {
      await api.downloadCycloneDxBom(rec.model_id);
    } catch (e) {
      setDownloadError(e.message || "Could not download CycloneDX BOM.");
    } finally {
      setDownloadingBom(false);
    }
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Pill value={rec.verdict} />
          <span className="text-sm text-muted">decision confidence {confidencePct}%</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={downloadBom}
            disabled={!rec?.model_id || downloadingBom}
            className="h-8 rounded-md border border-slate-300 bg-white px-3 text-sm font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {downloadingBom ? "Preparing BOM…" : "Download CycloneDX BOM"}
          </button>
          <span className="text-xs text-muted">{rec.generated_at ? `triaged ${fmtDate(rec.generated_at)}` : ""}</span>
        </div>
      </div>
      {downloadError && (
        <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700">
          {downloadError}
        </div>
      )}
      <p className="mt-3 text-sm text-ink">{rec.summary}</p>

      {/* Core scoring inputs */}
      <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Risk" value={inputs.risk_score ?? "—"} sub={humanLabel(inputs.risk_severity || "—")} />
        <Metric label="Provenance" value={inputs.provenance_score ?? "—"} sub={humanLabel(inputs.provenance_risk_level || "—")} />
        <Metric label="Trust" value={inputs.trustworthiness_score ?? "—"} sub={humanLabel(inputs.trustworthiness_level || "—")} />
        <Metric label="Control gaps" value={inputs.governance_open_gaps ?? "—"} sub={humanLabel(inputs.governance_status || "—")} />
      </div>

      {/* Live due-diligence row */}
      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Serialization scan</h4>
          <SerialScanSection inputs={inputs} />
        </div>
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Behavioral probes (quick)</h4>
          <ProbeScanSection inputs={inputs} />
        </div>
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Full red-team (garak)</h4>
          <RedTeamSection inputs={inputs} />
        </div>
      </div>

      <UnknownModelAssuranceSection assurance={rec.unknown_model_assurance} />

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-bold text-ink">Why this verdict</h4>
          {reasons.length ? (
            <ul className="space-y-2">
              {reasons.map((r, i) => (
                <li key={i} className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-sm">
                  <div className="flex items-center gap-2">
                    <Pill value={r.verdict} />
                    {r.origin && <Tag>{humanLabel(r.origin)}</Tag>}
                  </div>
                  <div className="mt-1.5 text-ink">{r.reason}</div>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No downgrades — evidence supports the strongest verdict.</Empty>
          )}
        </div>

        <div className="space-y-4">
          <div>
            <h4 className="mb-2 text-sm font-bold text-ink">Conditions to satisfy</h4>
            {conditions.length ? (
              <ul className="list-disc space-y-1 pl-5 text-sm text-ink">
                {conditions.map((c, i) => <li key={i}>{c}</li>)}
              </ul>
            ) : <Empty>None.</Empty>}
          </div>
          <div>
            <h4 className="mb-2 text-sm font-bold text-ink">Evidence we could not obtain</h4>
            {gaps.length ? (
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
                {gaps.map((g, i) => <li key={i}>{g}</li>)}
              </ul>
            ) : <Empty>No outstanding evidence gaps.</Empty>}
          </div>
        </div>
      </div>

      <div className="mt-5">
        <h4 className="mb-2 text-sm font-bold text-ink">Evidence by origin</h4>
        {Object.keys(origins).length ? (
          <div className="space-y-2">
            {Object.entries(origins).map(([origin, names]) => (
              <div key={origin} className="flex flex-wrap items-center gap-2 text-sm">
                <Pill value={origin} />
                <span className="text-muted">{(names || []).join(", ")}</span>
              </div>
            ))}
          </div>
        ) : <Empty>No origin-tagged facts recorded for this model.</Empty>}
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-bold text-ink">Organization policy</h4>
          {Object.keys(policyContext).length ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Tag>Use case: {humanLabel(policyContext.use_case || "general")}</Tag>
                <Tag>Data: {humanLabel(policyContext.data_classification || "internal")}</Tag>
                <Tag>Exposure: {humanLabel(policyContext.deployment_exposure || "internal")}</Tag>
                {policyPosture.level && <Pill value={policyPosture.level} />}
              </div>
              {requiredEvidence.length ? (
                <div className="space-y-2">
                  {requiredEvidence.map((item) => (
                    <div key={item.id} className="flex items-start justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-sm">
                      <div>
                        <div className="font-medium text-ink">{item.label}</div>
                        {!item.met && <div className="mt-1 text-muted">{item.gap}</div>}
                      </div>
                      <Tag>{item.met ? "Met" : item.required ? "Required" : "Optional"}</Tag>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty>No organization-specific evidence requirements applied.</Empty>
              )}
            </div>
          ) : (
            <Empty>No organization policy context was supplied for this triage run.</Empty>
          )}
        </div>

        <div>
          <h4 className="mb-2 text-sm font-bold text-ink">Approval scope</h4>
          {Object.keys(approvalScope).length ? (
            <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
              <div className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">Allowed exposure</div>
                  <div className="mt-1 text-ink">{humanLabel(approvalScope.allowed_exposure || "unspecified")}</div>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-muted">Allowed data</div>
                  <div className="mt-1 text-ink">{humanLabel(approvalScope.allowed_data || "unspecified")}</div>
                </div>
              </div>
              {(approvalScope.notes || []).length ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-ink">
                  {(approvalScope.notes || []).map((note, idx) => <li key={idx}>{note}</li>)}
                </ul>
              ) : (
                <Empty>No additional scope notes.</Empty>
              )}
            </div>
          ) : (
            <Empty>No approval scope was generated.</Empty>
          )}
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main tab component
// ---------------------------------------------------------------------------
export default function Adoption({ refreshToken }) {
  const { loading, error, data } = useResource(() => api.models(), [refreshToken]);
  const [selected, setSelected] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [endpointModelName, setEndpointModelName] = useState("default");
  const [endpointApiKey, setEndpointApiKey] = useState("");
  const [useCase, setUseCase] = useState("general");
  const [dataClassification, setDataClassification] = useState("internal");
  const [deploymentExposure, setDeploymentExposure] = useState("internal");
  const [rec, setRec] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  // Red-team launcher state
  const [rtDepth, setRtDepth] = useState("quick");
  const [rtBusy, setRtBusy] = useState(false);
  const [rtJob, setRtJob] = useState(null);
  const [rtMsg, setRtMsg] = useState("");
  const [rtPolling, setRtPolling] = useState(null);

  const models = (data && data.models) || [];

  async function runTriage(modelId) {
    if (!modelId) return;
    setBusy(true);
    setMsg("");
    try {
      const result = await api.triage(modelId, {
        endpointUrl: endpointUrl || null,
        endpointApiKey: endpointApiKey || null,
        endpointModelName: endpointModelName || "default",
        policyContext: {
          use_case: useCase,
          data_classification: dataClassification,
          deployment_exposure: deploymentExposure,
        },
      });
      setRec(result);
      setSelected(modelId);
    } catch (e) {
      setMsg(e.message);
      setRec(null);
    } finally {
      setBusy(false);
    }
  }

  async function launchRedTeam() {
    if (!selected || !endpointUrl) return;
    setRtBusy(true);
    setRtMsg("");
    setRtJob(null);
    if (rtPolling) clearInterval(rtPolling);
    try {
      const job = await api.startRedTeam(selected, {
        endpointUrl,
        depth: rtDepth,
        modelName: endpointModelName || "default",
        apiKey: endpointApiKey || null,
      });
      setRtJob(job);
      // Poll every 10 s until terminal state.
      const timer = setInterval(async () => {
        try {
          const updated = await api.getRedTeamJob(selected, job.job_id);
          setRtJob(updated);
          if (["COMPLETED", "FAILED"].includes(updated.status)) {
            clearInterval(timer);
            setRtPolling(null);
            setRtBusy(false);
            if (updated.status === "COMPLETED") {
              setRtMsg("Red-team complete. Re-run triage to include results in the verdict.");
            }
          }
        } catch {
          /* poll silently */
        }
      }, 10000);
      setRtPolling(timer);
    } catch (e) {
      setRtMsg(e.message);
      setRtBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card title="External Model Intake — Adoption Triage">
        <p className="text-sm text-muted">
          Pick a registered model and run triage. AIAF assembles provenance, risk, governance,
          dependency, serialization, and live behavioral evidence — tagged by where each fact came
          from — into one graded adoption decision with explicit conditions and the evidence it
          could not obtain.
        </p>

        {loading && !data ? (
          <Empty>Loading registered models…</Empty>
        ) : error ? (
          <Empty>{error}</Empty>
        ) : !models.length ? (
          <Empty>No models registered. Register one in the Model Registry tab first.</Empty>
        ) : (
          <div className="mt-3 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="h-9 w-80 max-w-full rounded-md border border-slate-300 px-2 text-sm"
              >
                <option value="">Select a model…</option>
                {models.map((m) => (
                  <option key={m.model_id} value={m.model_id}>
                    {(m.model_name || "Unnamed")}{m.version ? ` v${m.version}` : ""} — {m.model_id.slice(0, 8)}…
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="url"
                placeholder="Endpoint URL (optional) — e.g. http://localhost:11434"
                value={endpointUrl}
                onChange={(e) => setEndpointUrl(e.target.value)}
                className="h-9 w-96 max-w-full rounded-md border border-slate-300 px-2 text-sm placeholder:text-slate-400"
              />
              <span className="text-xs text-muted">Provide to run live behavioral and unknown-model runtime probes</span>
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              <label className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">Endpoint model name</span>
                <input
                  type="text"
                  value={endpointModelName}
                  onChange={(e) => setEndpointModelName(e.target.value)}
                  className="h-9 w-full rounded-md border border-slate-300 px-2 text-sm"
                  placeholder="default"
                />
              </label>
              <label className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">Endpoint API key</span>
                <input
                  type="password"
                  value={endpointApiKey}
                  onChange={(e) => setEndpointApiKey(e.target.value)}
                  className="h-9 w-full rounded-md border border-slate-300 px-2 text-sm"
                  placeholder="Optional bearer token"
                />
              </label>
            </div>
            <div className="grid gap-2 md:grid-cols-3">
              <label className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">Use case</span>
                <select
                  value={useCase}
                  onChange={(e) => setUseCase(e.target.value)}
                  className="h-9 w-full rounded-md border border-slate-300 px-2 text-sm"
                >
                  {["general", "customer_support", "productivity", "security", "finance", "healthcare", "hiring", "legal"].map((value) => (
                    <option key={value} value={value}>{humanLabel(value)}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">Data sensitivity</span>
                <select
                  value={dataClassification}
                  onChange={(e) => setDataClassification(e.target.value)}
                  className="h-9 w-full rounded-md border border-slate-300 px-2 text-sm"
                >
                  {["public", "internal", "restricted", "pii", "phi"].map((value) => (
                    <option key={value} value={value}>{humanLabel(value)}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <span className="text-xs font-semibold uppercase tracking-wide text-muted">Deployment exposure</span>
                <select
                  value={deploymentExposure}
                  onChange={(e) => setDeploymentExposure(e.target.value)}
                  className="h-9 w-full rounded-md border border-slate-300 px-2 text-sm"
                >
                  {["internal", "authenticated", "external", "public"].map((value) => (
                    <option key={value} value={value}>{humanLabel(value)}</option>
                  ))}
                </select>
              </label>
            </div>
            <div>
              <button
                onClick={() => runTriage(selected)}
                disabled={!selected || busy}
                className="h-9 rounded-md bg-accent px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-strong disabled:opacity-50"
              >
                {busy ? "Running triage…" : "Run adoption triage"}
              </button>
            </div>
          </div>
        )}
        {msg && <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700">{msg}</div>}
      </Card>

      {/* Red-team launcher — only shown when a model + endpoint are selected */}
      {selected && endpointUrl && (
        <Card title="Full Red-Team Evaluation (garak / PyRIT)">
          <p className="text-sm text-muted">
            Runs garak against your endpoint as a background job (2–90 min depending on depth).
            Results are saved to the model and picked up automatically on the next triage run.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <select
              value={rtDepth}
              onChange={(e) => setRtDepth(e.target.value)}
              className="h-9 rounded-md border border-slate-300 px-2 text-sm"
            >
              <option value="quick">Quick — 4 families (~2–10 min)</option>
              <option value="full">Full — all families (~30–90 min)</option>
            </select>
            <button
              onClick={launchRedTeam}
              disabled={rtBusy}
              className="h-9 rounded-md border border-slate-300 bg-white px-4 text-sm font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
            >
              {rtBusy ? "Launching…" : "Launch red-team"}
            </button>
          </div>
          {rtJob && (
            <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm">
              <div className="flex items-center gap-2 font-semibold text-ink">
                <Pill value={rtJob.status} />
                <span className="font-mono text-xs text-muted">{rtJob.job_id?.slice(0, 8)}…</span>
              </div>
              {rtJob.result && (
                <div className="mt-2 text-muted">
                  {rtJob.result.total_failures != null &&
                    `${rtJob.result.total_failures} failure(s) across ${rtJob.result.total_probes_run} probes`}
                  {rtJob.result.error && ` — ${rtJob.result.error}`}
                </div>
              )}
              {rtBusy && (
                <p className="mt-1 text-xs text-muted animate-pulse">Polling every 10s…</p>
              )}
            </div>
          )}
          {rtMsg && (
            <div className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 p-2 text-sm text-emerald-800">
              {rtMsg}
            </div>
          )}
        </Card>
      )}

      {rec && <VerdictPanel rec={rec} />}
    </div>
  );
}

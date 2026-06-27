"""Phase 2 adoption engine tests: serialization scan + behavioral probe evaluators."""


from aiaf.core.adoption_engine import (
    ADOPTION_SCORING_VERSION,
    AdoptionVerdict,
    recommend_adoption,
)

# ---------------------------------------------------------------------------
# Minimal model record (no ledger, triggers evidence-gap path only)
# ---------------------------------------------------------------------------

_BASE_MODEL = {
    "model_id": "test-model-p2",
    "metadata": {},
}


def _serial_scan(status: str, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0):
    match_count = critical + high + medium + low
    findings = []
    for _ in range(critical):
        findings.append({"type": "dangerous_import", "severity": "CRITICAL",
                         "description": "os.system", "module": "os", "name": "system", "offset": 0})
    for _ in range(high):
        findings.append({"type": "dangerous_import", "severity": "HIGH",
                         "description": "subprocess.Popen", "module": "subprocess", "name": "Popen", "offset": 0})
    for _ in range(medium):
        findings.append({"type": "unknown_import", "severity": "MEDIUM",
                         "description": "unusual module", "module": "unusual", "name": "fn", "offset": 0})
    return {
        "scan_version": "1.0",
        "scanner": "aiaf-native",
        "format_detected": "pytorch_pickle",
        "status": status,
        "findings": findings,
        "by_severity": {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
        "match_count": match_count,
        "scanned_at": "2026-06-21T00:00:00Z",
        "assessment_complete": True,
    }


def _probe_result(status: str, critical: int = 0, high: int = 0, medium: int = 0,
                  failures: int = 0, complete: bool = True):
    by_severity = {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": 0}
    return {
        "probe_version": "1.0",
        "status": status,
        "probes_run": 10,
        "probe_failures": failures or critical + high + medium,
        "probe_results": [],
        "by_category": {},
        "by_severity": by_severity,
        "match_count": failures or critical + high + medium,
        "evaluation_method": "keyword_match",
        "scanned_at": "2026-06-21T00:00:00Z",
        "assessment_complete": complete,
    }


# ---------------------------------------------------------------------------
# Scoring version
# ---------------------------------------------------------------------------


def test_scoring_version_is_v3():
    rec = recommend_adoption(_BASE_MODEL)
    assert rec["scoring_version"] == ADOPTION_SCORING_VERSION == "3.0"


# ---------------------------------------------------------------------------
# Serialization scan: no scan → evidence gap only, no verdict cap
# ---------------------------------------------------------------------------


def test_no_serialization_scan_adds_evidence_gap():
    rec = recommend_adoption(_BASE_MODEL)
    gaps = " ".join(rec["evidence_gaps"])
    assert "serialization" in gaps.lower()


def test_no_serialization_scan_does_not_add_cap():
    # Without a scan, the model can still achieve higher verdicts from other inputs
    # (the gap is informational, not a blocking cap).
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=None)
    # Verdict should not be forced to DO_NOT_APPROVE solely by missing scan.
    assert rec["verdict"] != AdoptionVerdict.DO_NOT_APPROVE.value


# ---------------------------------------------------------------------------
# Serialization scan: clean
# ---------------------------------------------------------------------------


def test_clean_serialization_scan_adds_no_cap():
    scan = _serial_scan("CLEAN")
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    # Clean scan should not add any cap.
    scan_caps = [r for r in rec["reasons"] if r["category"] == "serialization_scan"]
    assert len(scan_caps) == 0


# ---------------------------------------------------------------------------
# Serialization scan: CRITICAL finding → DO_NOT_APPROVE
# ---------------------------------------------------------------------------


def test_critical_serialization_finding_blocks_adoption():
    scan = _serial_scan("UNSAFE_PATTERNS_FOUND", critical=1)
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    assert rec["verdict"] == AdoptionVerdict.DO_NOT_APPROVE.value


def test_critical_serialization_reason_is_locally_observed():
    scan = _serial_scan("UNSAFE_PATTERNS_FOUND", critical=1)
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    serial_reason = next(
        (r for r in rec["reasons"] if r["category"] == "serialization_scan"), None
    )
    assert serial_reason is not None
    assert serial_reason["origin"] == "locally_observed"


# ---------------------------------------------------------------------------
# Serialization scan: HIGH finding → DO_NOT_APPROVE
# ---------------------------------------------------------------------------


def test_high_serialization_finding_blocks_adoption():
    scan = _serial_scan("UNSAFE_PATTERNS_FOUND", high=1)
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    assert rec["verdict"] == AdoptionVerdict.DO_NOT_APPROVE.value


# ---------------------------------------------------------------------------
# Serialization scan: MEDIUM → APPROVE_WITH_CONDITIONS (worst-of-caps)
# ---------------------------------------------------------------------------


def test_medium_serialization_finding_caps_at_approve_with_conditions():
    scan = _serial_scan("SUSPICIOUS", medium=1)
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    rank = rec["verdict_rank"]
    # Must not reach APPROVE_FOR_SCOPED_USE (rank 4) with a medium finding.
    assert rank <= 3


def test_medium_serialization_adds_condition():
    scan = _serial_scan("SUSPICIOUS", medium=1)
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    conds = " ".join(rec["conditions"]).lower()
    assert "medium" in conds or "anomal" in conds or "serialization" in conds


# ---------------------------------------------------------------------------
# Serialization scan: SCAN_ERROR → INSUFFICIENT_EVIDENCE cap
# ---------------------------------------------------------------------------


def test_scan_error_yields_insufficient_evidence_cap():
    scan = {
        "scan_version": "1.0",
        "scanner": "aiaf-native",
        "format_detected": "unknown",
        "status": "SCAN_ERROR",
        "findings": [],
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "match_count": 0,
        "scanned_at": "2026-06-21T00:00:00Z",
        "assessment_complete": False,
    }
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    assert any(r["verdict"] == AdoptionVerdict.INSUFFICIENT_EVIDENCE.value
               for r in rec["reasons"])


# ---------------------------------------------------------------------------
# Behavioral probes: no probes → evidence gap only
# ---------------------------------------------------------------------------


def test_no_behavioral_probes_adds_evidence_gap():
    rec = recommend_adoption(_BASE_MODEL)
    gaps = " ".join(rec["evidence_gaps"]).lower()
    assert "behavioral" in gaps or "endpoint" in gaps or "probe" in gaps


# ---------------------------------------------------------------------------
# Behavioral probes: CRITICAL failures → DO_NOT_APPROVE
# ---------------------------------------------------------------------------


def test_critical_probe_failure_blocks_adoption():
    probes = _probe_result("COMPLETED", critical=1, failures=1)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    assert rec["verdict"] == AdoptionVerdict.DO_NOT_APPROVE.value


def test_critical_probe_reason_is_locally_observed():
    probes = _probe_result("COMPLETED", critical=1, failures=1)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    probe_reason = next(
        (r for r in rec["reasons"] if r["category"] == "behavioral_probes"), None
    )
    assert probe_reason is not None
    assert probe_reason["origin"] == "locally_observed"


# ---------------------------------------------------------------------------
# Behavioral probes: HIGH failures → DO_NOT_APPROVE
# ---------------------------------------------------------------------------


def test_high_probe_failure_blocks_adoption():
    probes = _probe_result("COMPLETED", high=1, failures=1)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    assert rec["verdict"] == AdoptionVerdict.DO_NOT_APPROVE.value


# ---------------------------------------------------------------------------
# Behavioral probes: MEDIUM failures → PILOT_ONLY cap
# ---------------------------------------------------------------------------


def test_medium_probe_failure_caps_at_pilot_only():
    probes = _probe_result("COMPLETED", medium=1, failures=1)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    rank = rec["verdict_rank"]
    # Must not exceed PILOT_ONLY (rank 2).
    assert rank <= 2


# ---------------------------------------------------------------------------
# Behavioral probes: all probes passed → no cap from probes
# ---------------------------------------------------------------------------


def test_all_probes_passed_adds_no_cap():
    probes = _probe_result("COMPLETED", failures=0)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    probe_caps = [r for r in rec["reasons"] if r["category"] == "behavioral_probes"]
    assert len(probe_caps) == 0


# ---------------------------------------------------------------------------
# Behavioral probes: ENDPOINT_ERROR → INSUFFICIENT_EVIDENCE cap
# ---------------------------------------------------------------------------


def test_endpoint_error_yields_insufficient_evidence():
    probes = _probe_result("ENDPOINT_ERROR", complete=False)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    assert any(r["verdict"] == AdoptionVerdict.INSUFFICIENT_EVIDENCE.value
               for r in rec["reasons"])


# ---------------------------------------------------------------------------
# Combined: both scan clean and probes passed → higher verdict possible
# ---------------------------------------------------------------------------


def test_clean_scan_and_passing_probes_dont_lower_verdict():
    scan = _serial_scan("CLEAN")
    probes = _probe_result("COMPLETED", failures=0)
    rec_with = recommend_adoption(_BASE_MODEL, serialization_scan=scan, behavioral_probes=probes)
    rec_without = recommend_adoption(_BASE_MODEL)
    # Having clean scan + passing probes should not lower the verdict.
    assert rec_with["verdict_rank"] >= rec_without["verdict_rank"]


# ---------------------------------------------------------------------------
# inputs echo includes Phase 2 fields
# ---------------------------------------------------------------------------


def test_input_echo_includes_serialization_fields():
    scan = _serial_scan("CLEAN")
    rec = recommend_adoption(_BASE_MODEL, serialization_scan=scan)
    assert "serialization_status" in rec["inputs"]
    assert rec["inputs"]["serialization_status"] == "CLEAN"
    assert "serialization_match_count" in rec["inputs"]


def test_input_echo_includes_probe_fields():
    probes = _probe_result("COMPLETED", failures=0)
    rec = recommend_adoption(_BASE_MODEL, behavioral_probes=probes)
    assert "behavioral_probe_status" in rec["inputs"]
    assert rec["inputs"]["behavioral_probe_status"] == "COMPLETED"
    assert "behavioral_probe_failures" in rec["inputs"]

"""Tests for frontier eval evidence registry."""

from aiaf.analysis.frontier_eval_harness import (
    EVAL_EVIDENCE_VERSION,
    EvidenceStrength,
    Finding,
    Job,
    JobState,
    compare_eval_runs,
    get_eval_run,
    list_eval_runs,
    register_eval_run,
)


class _Store:
    def __init__(self):
        self._data = {}

    def get_model(self, key):
        return self._data.get(key)

    def save_model(self, record):
        self._data[record.get("model_id") or record.get("id")] = record

    def list_models(self):
        return list(self._data.values())


def _job(job_id, strengths):
    findings = [
        Finding(
            probe_id=f"probe-{idx}",
            category="safety",
            job_id=job_id,
            response="response",
            strength=strength,
            matched_indicators=[],
            latency_ms=10.0,
        )
        for idx, strength in enumerate(strengths)
    ]
    job = Job(job_id=job_id, state=JobState.COMPLETED)
    job.findings = findings
    return job


def test_register_eval_run_is_content_addressed():
    store = _Store()
    job = _job("job-1", [EvidenceStrength.INSUFFICIENT, EvidenceStrength.POSSIBLE])

    run1 = register_eval_run(job, store, target_id="model-a", random_seed=7)
    run2 = register_eval_run(job, store, target_id="model-a", random_seed=7)

    assert run1["run_id"] == run2["run_id"]
    assert run1["eval_evidence_version"] == EVAL_EVIDENCE_VERSION


def test_get_and_list_eval_runs():
    store = _Store()
    run = register_eval_run(
        _job("job-1", [EvidenceStrength.INSUFFICIENT]),
        store,
        target_id="model-a",
    )

    fetched = get_eval_run(run["run_id"], store)
    listed = list_eval_runs(store, target_id="model-a")

    assert fetched["run_id"] == run["run_id"]
    assert listed[0]["run_id"] == run["run_id"]


def test_compare_eval_runs_detects_regression():
    store = _Store()
    baseline = register_eval_run(
        _job("job-base", [EvidenceStrength.INSUFFICIENT] * 4),
        store,
        target_id="model-a",
    )
    candidate = register_eval_run(
        _job("job-cand", [EvidenceStrength.CONFIRMED] * 4),
        store,
        target_id="model-a",
    )

    result = compare_eval_runs(baseline["run_id"], candidate["run_id"], store)

    assert result["status"] == "REGRESSION"
    assert result["regressed"] is True
    assert result["score_delta"] > 0


def test_compare_eval_runs_handles_no_overlap():
    store = _Store()
    baseline = _job("job-base", [EvidenceStrength.INSUFFICIENT])
    baseline.findings[0].probe_id = "probe-a"
    candidate = _job("job-cand", [EvidenceStrength.CONFIRMED])
    candidate.findings[0].probe_id = "probe-b"
    base_run = register_eval_run(baseline, store)
    cand_run = register_eval_run(candidate, store)

    result = compare_eval_runs(base_run["run_id"], cand_run["run_id"], store)

    assert result["status"] == "INSUFFICIENT_OVERLAP"
    assert result["overlap_probe_count"] == 0

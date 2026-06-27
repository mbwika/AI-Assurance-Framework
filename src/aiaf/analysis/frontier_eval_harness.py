
"""
frontier_eval_harness.py
========================

A pluggable evaluation harness for assessing model behavior against
a catalog of probes scored by regex-based indicator rubrics.

Design principles
-----------------
* **No bundled dangerous-capability probes.** The harness ships with
  a benign sample catalog (instruction-following, refusal consistency,
  factuality, reasoning, format adherence). Operators bring their own
  private probe sets for sensitive categories and load them via a
  ``CatalogProvider``.
* **Catalog loading is fully injected.** Any object implementing the
  ``CatalogProvider`` protocol can supply probes — local JSON, signed
  bundles, a database, an internal service, etc.
* **Findings are structured for downstream attestation.** The report
  format is SARIF-inspired and is intended to feed regulatory mapping
  pipelines (e.g. NIST AI RMF, EU AI Act Article 15 logging).

Public surface
--------------
* ``JobState``, ``EvidenceStrength`` — lifecycle and rubric enums.
* ``Probe``, ``IndicatorRubric``, ``Finding``, ``Job`` — data models.
* ``CatalogProvider`` (Protocol), ``JsonCatalogProvider``,
  ``DictCatalogProvider`` — pluggable catalog sources.
* ``RubricScorer`` — applies a probe's rubrics to a response.
* ``execute_harness_job(job_id, tasks, endpoint_callable)`` — runner.
* ``write_job_report(job, path)`` — persist a structured report.
"""



import json
import logging
import re
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Protocol,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class JobState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class EvidenceStrength(str, Enum):
    NOT_EVALUATED = "NOT_EVALUATED"
    INSUFFICIENT = "INSUFFICIENT"
    POSSIBLE = "POSSIBLE"
    PROBABLE = "PROBABLE"
    CONFIRMED = "CONFIRMED"

    @property
    def rank(self) -> int:
        return _STRENGTH_RANK[self]


_STRENGTH_RANK: dict["EvidenceStrength", int] = {
    EvidenceStrength.NOT_EVALUATED: 0,
    EvidenceStrength.INSUFFICIENT: 1,
    EvidenceStrength.POSSIBLE: 2,
    EvidenceStrength.PROBABLE: 3,
    EvidenceStrength.CONFIRMED: 4,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndicatorRubric:
    """A single regex-based scoring rule for a probe.

    If ``pattern`` matches the model response, the indicator contributes
    ``target_strength`` to the overall finding. Multiple indicators may
    match; the final strength for the probe is the maximum (by rank) of
    matched indicators.
    """

    label: str
    pattern: str
    target_strength: EvidenceStrength
    description: str = ""

    def matches(self, response: str) -> bool:
        try:
            return (
                re.search(self.pattern, response, re.IGNORECASE | re.MULTILINE)
                is not None
            )
        except re.error as exc:
            logger.warning("Invalid regex in rubric %r: %s", self.label, exc)
            return False


@dataclass(frozen=True)
class Probe:
    """A single evaluation task."""

    id: str
    category: str
    prompt: str
    rubrics: tuple[IndicatorRubric, ...]
    expected_behavior: str = ""
    tags: tuple[str, ...] = ()
    source: str = ""


@dataclass
class Finding:
    """The recorded outcome for one probe in one job."""

    probe_id: str
    category: str
    job_id: str
    response: str
    strength: EvidenceStrength
    matched_indicators: list[str]
    latency_ms: float
    error: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["strength"] = self.strength.value
        return d


@dataclass
class Job:
    """Stateful record of a harness execution."""

    job_id: str
    state: JobState = JobState.PENDING
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: str | None = None
    finished_at: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    abort_event: threading.Event = field(default_factory=threading.Event)

    def request_abort(self) -> None:
        """Signal cooperative abort. The runner checks between probes."""
        self.abort_event.set()

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Catalog providers (dependency injection point)
# ---------------------------------------------------------------------------


class CatalogProvider(Protocol):
    """Protocol for any source of probes.

    Operators implement this to plug in private catalogs (filesystem,
    object store, database, signed bundle, internal API, etc.) without
    modifying the harness.
    """

    def load(self) -> Sequence[Probe]:  # pragma: no cover - protocol
        ...


class JsonCatalogProvider:
    """Loads probes from a JSON file (e.g. ``probes.json`` next to this module)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> Sequence[Probe]:
        with self.path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return tuple(_probe_from_dict(item) for item in raw["probes"])


class DictCatalogProvider:
    """Loads probes from an in-memory dict.

    Useful for tests and for operators who fetch their catalog from a
    non-file source (e.g. parsing a signed bundle in memory).
    """

    def __init__(self, catalog: dict[str, Any]) -> None:
        self.catalog = catalog

    def load(self) -> Sequence[Probe]:
        return tuple(_probe_from_dict(item) for item in self.catalog["probes"])


def _probe_from_dict(item: dict[str, Any]) -> Probe:
    rubrics = tuple(
        IndicatorRubric(
            label=r["label"],
            pattern=r["pattern"],
            target_strength=EvidenceStrength(r["target_strength"]),
            description=r.get("description", ""),
        )
        for r in item.get("rubrics", [])
    )
    return Probe(
        id=item["id"],
        category=item["category"],
        prompt=item["prompt"],
        rubrics=rubrics,
        expected_behavior=item.get("expected_behavior", ""),
        tags=tuple(item.get("tags", [])),
        source=item.get("source", ""),
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class RubricScorer:
    """Applies a probe's indicator rubrics to a model response.

    Strategy:
      * If the probe has no rubrics  -> ``NOT_EVALUATED``.
      * If rubrics exist but none match -> ``INSUFFICIENT``.
      * Otherwise -> the highest-ranked ``target_strength`` among matched.
    """

    def score(
        self, probe: Probe, response: str
    ) -> tuple[EvidenceStrength, list[str]]:
        if not probe.rubrics:
            return EvidenceStrength.NOT_EVALUATED, []

        matched: list[tuple[str, EvidenceStrength]] = [
            (r.label, r.target_strength)
            for r in probe.rubrics
            if r.matches(response)
        ]

        if not matched:
            return EvidenceStrength.INSUFFICIENT, []

        best = max(matched, key=lambda pair: pair[1].rank)
        return best[1], [label for label, _ in matched]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


EndpointCallable = Callable[[str], str]


def execute_harness_job(
    job_id: str,
    tasks: Sequence[Probe],
    endpoint_callable: EndpointCallable,
    *,
    scorer: RubricScorer | None = None,
    job: Job | None = None,
    on_finding: Callable[[Finding], None] | None = None,
) -> Job:
    """Execute the harness for ``tasks`` against ``endpoint_callable``.

    Parameters
    ----------
    job_id:
        Caller-supplied identifier for this job.
    tasks:
        Probes to run. Typically loaded via a ``CatalogProvider``.
    endpoint_callable:
        Adapter that takes a prompt and returns the model's response.
        Operators wrap their model client (OpenAI, Anthropic, vLLM,
        local HF pipeline, etc.) to satisfy this contract.
    scorer:
        Override the default ``RubricScorer``. Useful for plugging in
        semantic or LLM-judge scorers downstream.
    job:
        Pre-existing ``Job`` record (e.g. resumed from storage). If
        omitted, a new one is created in ``PENDING`` state.
    on_finding:
        Streaming callback invoked after each probe completes — useful
        for live dashboards or incremental persistence.

    Returns
    -------
    Job
        The job record with its final state and accumulated findings.
    """
    scorer = scorer or RubricScorer()
    job = job or Job(job_id=job_id)

    if job.state != JobState.PENDING:
        raise ValueError(
            f"Job {job_id} is in state {job.state.value}; expected PENDING."
        )

    job.state = JobState.RUNNING
    job.started_at = datetime.now(timezone.utc).isoformat()
    logger.info("Job %s starting with %d probes", job_id, len(tasks))

    try:
        for probe in tasks:
            if job.abort_event.is_set():
                job.state = JobState.ABORTED
                logger.info("Job %s aborted by request", job_id)
                return job

            finding = _run_single_probe(probe, endpoint_callable, scorer, job_id)
            job.findings.append(finding)
            if on_finding is not None:
                try:
                    on_finding(finding)
                except Exception:  # noqa: BLE001
                    logger.exception("on_finding callback raised")

        if job.state == JobState.RUNNING:
            job.state = JobState.COMPLETED

    except Exception as exc:  # noqa: BLE001
        job.state = JobState.FAILED
        job.error = f"{type(exc).__name__}: {exc}"
        logger.exception("Job %s failed", job_id)

    finally:
        job.finished_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Job %s finished in state %s with %d findings",
            job_id,
            job.state.value,
            len(job.findings),
        )

    return job


def _run_single_probe(
    probe: Probe,
    endpoint: EndpointCallable,
    scorer: RubricScorer,
    job_id: str,
) -> Finding:
    start = time.perf_counter()
    try:
        response = endpoint(probe.prompt)
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return Finding(
            probe_id=probe.id,
            category=probe.category,
            job_id=job_id,
            response="",
            strength=EvidenceStrength.NOT_EVALUATED,
            matched_indicators=[],
            latency_ms=elapsed_ms,
            error=f"{type(exc).__name__}: {exc}",
        )

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    strength, matched = scorer.score(probe, response)
    return Finding(
        probe_id=probe.id,
        category=probe.category,
        job_id=job_id,
        response=response,
        strength=strength,
        matched_indicators=matched,
        latency_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def write_job_report(job: Job, path: Path | str) -> None:
    """Persist a job's findings in a SARIF-inspired JSON envelope.

    The shape is intentionally simple: a top-level ``job`` block with
    full findings, plus a ``summary`` block suitable for dashboards
    and downstream regulatory mapping.
    """
    out = {
        "schema_version": "1.0",
        "tool": {"name": "frontier_eval_harness", "version": "0.1.0"},
        "job": job.to_dict(),
        "summary": _summarize(job),
    }
    Path(path).write_text(json.dumps(out, indent=2), encoding="utf-8")


def _summarize(job: Job) -> dict[str, Any]:
    by_strength: dict[str, int] = {s.value: 0 for s in EvidenceStrength}
    by_category: dict[str, dict[str, int]] = {}
    for f in job.findings:
        by_strength[f.strength.value] += 1
        cat = by_category.setdefault(
            f.category, {s.value: 0 for s in EvidenceStrength}
        )
        cat[f.strength.value] += 1
    return {
        "total_findings": len(job.findings),
        "by_strength": by_strength,
        "by_category": by_category,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _echo_endpoint(prompt: str) -> str:
    """Trivial endpoint for smoke-testing — echoes the prompt back.

    Replace with a real adapter in production:

        def my_endpoint(prompt: str) -> str:
            return my_model_client.complete(prompt).text
    """
    return f"[echo] {prompt}"


def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the frontier eval harness against a probes catalog."
    )
    parser.add_argument(
        "--catalog",
        default=str(Path(__file__).with_name("probes.json")),
        help="Path to a probes catalog JSON file.",
    )
    parser.add_argument("--job-id", default=None)
    parser.add_argument("--out", default="harness_report.json")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    probes = JsonCatalogProvider(args.catalog).load()
    job_id = args.job_id or f"job-{uuid.uuid4().hex[:8]}"
    job = execute_harness_job(job_id, probes, _echo_endpoint)
    write_job_report(job, args.out)
    print(
        f"Wrote {args.out}  (state={job.state.value}, "
        f"findings={len(job.findings)})"
    )


if __name__ == "__main__":
    _cli()



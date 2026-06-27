import io
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
)
from fastapi.responses import JSONResponse

from ..core import VulnerabilityIntelligenceEngine
from ..data.postgres_store import PostgresStore
from ..data.store import DataStore
from ..registry import (
    PROVENANCE_ATTESTATION_SCHEMA_VERSION,
    PROVENANCE_SCORING_VERSION,
    EvidenceOrigin,
    FactLedger,
    ModelRecord,
    SourceTracker,
    assess_provenance_v2,
    calculate_sha256,
    create_provenance_attestation_v2,
    discover_dependencies_v2,
    generate_mbom,
    merge_dependencies,
    verify_provenance_attestation,
    verify_provenance_attestation_v2,
)
from ..registry.serialization_scanner import scan_file as _scan_artifact

router = APIRouter()

# ---------------------------------------------------------------------------
# Per-job log telemetry — in-memory ring buffer, cleared on server restart.
# ---------------------------------------------------------------------------

_JOB_LOGS: dict[str, deque] = {}
_JOB_LOGS_LOCK = threading.Lock()
_STDERR_REDIRECT_LOCK = threading.Lock()  # serialises stderr redirects for tqdm capture
_JOB_LOG_MAX = 500
_JOB_LOG_DICT_CAP = 200  # max number of jobs whose logs are kept in memory


def _job_log_init(job_id: str) -> None:
    with _JOB_LOGS_LOCK:
        # Evict oldest entries when the dict would exceed the cap.
        while len(_JOB_LOGS) >= _JOB_LOG_DICT_CAP:
            _JOB_LOGS.pop(next(iter(_JOB_LOGS)))
        _JOB_LOGS[job_id] = deque(maxlen=_JOB_LOG_MAX)


def _job_log_append(job_id: str, line: str) -> None:
    with _JOB_LOGS_LOCK:
        buf = _JOB_LOGS.get(job_id)
        if buf is not None:
            buf.append(line)


def get_job_logs(job_id: str) -> list[str]:
    with _JOB_LOGS_LOCK:
        buf = _JOB_LOGS.get(job_id)
        return list(buf) if buf is not None else []


def _redact_token(text: str, token: str | None) -> str:
    """Replace a literal token value in error messages with [REDACTED]."""
    if token and token in text:
        return text.replace(token, "[REDACTED]")
    return text


class _LogCapture:
    """File-like writer that tees text to a job log buffer *and* original stderr.

    Returning ``isatty() -> False`` causes tqdm to emit ``\\n``-terminated lines
    instead of ``\\r`` in-place updates, producing clean capturable log lines.
    """

    def __init__(self, job_id: str, original):
        self._job_id = job_id
        self._orig = original
        self._partial = ""

    def write(self, text: str) -> int:
        if self._orig:
            try:
                self._orig.write(text)
                self._orig.flush()
            except Exception:
                pass
        self._partial += text
        # Flush complete lines terminated by \n or \r
        while True:
            nl = self._partial.find("\n")
            cr = self._partial.find("\r")
            candidates = [i for i in (nl, cr) if i >= 0]
            if not candidates:
                break
            idx = min(candidates)
            line = self._partial[:idx].rstrip()
            self._partial = self._partial[idx + 1:]
            if line:
                _job_log_append(self._job_id, line)
        return len(text)

    def flush(self) -> None:
        remaining = self._partial.strip()
        if remaining:
            _job_log_append(self._job_id, remaining)
            self._partial = ""
        if self._orig:
            try:
                self._orig.flush()
            except Exception:
                pass

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        raise io.UnsupportedOperation("fileno")


class _JobLogHandler(logging.Handler):
    """Routes Python log records into the job's in-memory log buffer."""

    def __init__(self, job_id: str, level: int = logging.DEBUG) -> None:
        super().__init__(level)
        self._job_id = job_id

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _job_log_append(self._job_id, self.format(record))
        except Exception:
            pass


# Simple API key auth dependency
API_KEY = os.getenv("AIAF_API_KEY", "dev-key")


def get_api_key(x_api_key: str | None = Header(None, alias="X-API-Key")):
    """Dependency that extracts the API key from the `X-API-Key` header."""
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


# Singleton store instances — created once, shared across all request threads.
# SQLite's check_same_thread=False + WAL mode + busy_timeout handles concurrent
# reads/writes safely; creating a fresh DataStore per request caused _ensure_schema
# DDL to race and produce "database is locked" errors under concurrent load.
PG_DSN = os.getenv("AIAF_PG_DSN")
_pg_store = None
_sqlite_store = None
_store_lock = threading.Lock()


def get_store():
    """Return a shared store instance (PostgresStore when configured, else SQLite).

    Both store types are singletons: the first call initialises and caches the
    instance; every subsequent call returns the same object. A threading lock
    prevents duplicate initialisation when multiple request threads call this
    simultaneously at startup.
    """
    global _pg_store, _sqlite_store

    # Fast path — no lock needed once initialised.
    if _pg_store is not None:
        return _pg_store
    if _sqlite_store is not None:
        return _sqlite_store

    with _store_lock:
        # Re-check inside the lock (another thread may have initialised while we
        # were waiting).
        if _pg_store is not None:
            return _pg_store
        if _sqlite_store is not None:
            return _sqlite_store

        if PG_DSN:
            try:
                _pg_store = PostgresStore(PG_DSN)
                return _pg_store
            except Exception as e:
                logging.warning("PostgresStore init failed, falling back to SQLite: %s", e)

        try:
            _sqlite_store = DataStore()
            return _sqlite_store
        except Exception as e:
            logging.error("Failed to initialize SQLite DataStore: %s", e)
            raise RuntimeError("No available datastore")


def _register_from_file(
    file_path: str,
    source_url: str | None,
    registered_by: str | None = None,
    metadata: dict[str, Any] | None = None,
    artifact_name: str = "",
):
    sha = calculate_sha256(file_path)
    st = SourceTracker()
    meta = st.capture_source(source_url or "")
    record_metadata = dict(metadata or {})

    # Phase 2: run the serialization scanner while the artifact is still on disk.
    serial_scan = _scan_artifact(file_path)
    record_metadata["serialization_scan"] = serial_scan
    discovery = discover_dependencies_v2(file_path, artifact_name=artifact_name)
    # Only exact, supported coordinates flow into the dependency inventory used
    # for advisory matching; unresolved/range coordinates are preserved as
    # discovery coverage evidence so the gap is visible without being scanned as
    # if it were an exact match.
    exact_coordinates = [
        {"name": item["name"], "version": item["version"], "ecosystem": item["ecosystem"]}
        for item in discovery["dependencies"]
        if item.get("resolution") == "EXACT"
    ]
    if exact_coordinates:
        record_metadata["dependencies"] = merge_dependencies(
            record_metadata.get("dependencies"), exact_coordinates
        )
    if discovery["manifests"] or discovery["diagnostics"]:
        record_metadata["dependency_discovery"] = {
            "scoring_version": discovery["scoring_version"],
            "assessment_status": discovery["assessment_status"],
            "manifest_paths": sorted(item["path"] for item in discovery["manifests"]),
            "manifests": discovery["manifests"],
            "dependency_count": discovery["dependency_count"],
            "exact_dependency_count": discovery["exact_dependency_count"],
            "unresolved_dependency_count": discovery["unresolved_dependency_count"],
            "conflicting_dependencies": discovery["conflicting_dependencies"],
            "coverage": discovery["coverage"],
            "inventory_complete": discovery["inventory_complete"],
            "resolution_complete": discovery["resolution_complete"],
            "diagnostics": discovery["diagnostics"],
        }
    rec = ModelRecord.create(
        model_name=meta.get("repository") or Path(file_path).name,
        version=record_metadata.get("version", "1.0"),
        source=meta.get("provider") or "upload",
        source_url=source_url or "",
        sha256=sha,
        publisher=record_metadata.get("publisher"),
        registered_by=registered_by,
        license=record_metadata.get("license"),
        training_data=record_metadata.get("training_data"),
        dependencies=record_metadata.get("dependencies"),
        training_artifacts=record_metadata.get("training_artifacts"),
        deployment_pipeline=record_metadata.get("deployment_pipeline"),
        metadata=record_metadata,
    )

    # Evidence-derived provenance trust. At registration there is no independent
    # verifier output yet, so the assessment is conservative; it is rescored once
    # a signed attestation is created and verified.
    assessment = assess_provenance_v2(rec.to_dict())
    rec.provenance_score = int(round(assessment["provenance_score"]))
    rec.risk_level = assessment["risk_level"]
    rec.metadata["provenance_assessment"] = _summarize_provenance(assessment)

    # Origin-tag every intake fact so the adoption verdict can weight (and
    # explain) evidence by where it came from. Operator-typed claims are
    # low-trust; the SHA-256 AIAF computed over the bytes is locally observed;
    # dependencies parsed from bundled manifests are artifact-derived.
    rec.metadata["evidence_ledger"] = _build_evidence_ledger(
        rec, record_metadata, discovery
    ).to_list()

    return rec


def _build_evidence_ledger(
    rec: "ModelRecord",
    record_metadata: dict[str, Any],
    discovery: dict[str, Any],
) -> FactLedger:
    """Build the origin-tagged fact ledger for a freshly registered model."""
    ledger = FactLedger()
    # Locally observed: AIAF measured these on the artifact in hand.
    ledger.add("sha256", rec.sha256, EvidenceOrigin.LOCALLY_OBSERVED)
    # User-entered: the operator supplied the URL and any manual metadata.
    ledger.add("source_url", rec.source_url, EvidenceOrigin.USER_ENTERED)
    for name in ("publisher", "license", "training_data", "version"):
        if record_metadata.get(name):
            ledger.add(name, record_metadata.get(name), EvidenceOrigin.USER_ENTERED)
    # Artifact-derived: dependency coordinates parsed from bundled manifests.
    if discovery.get("exact_dependency_count"):
        ledger.add(
            "discovered_dependencies",
            f"{discovery['exact_dependency_count']} exact coordinate(s)",
            EvidenceOrigin.ARTIFACT_DERIVED,
            detail="parsed from bundled dependency manifests",
        )
    # Phase 3: model card facts — provider-declared (self-asserted by publisher).
    hf_card = record_metadata.get("hf_model_card") or {}
    for field in ("license", "pipeline_tag", "model_type", "publisher",
                  "language", "base_model", "architectures"):
        if hf_card.get(field) is not None:
            ledger.add(field, hf_card[field], EvidenceOrigin.PROVIDER_DECLARED,
                       detail="from HuggingFace model card / config.json")

    # Phase 2: serialization scan — locally observed (AIAF ran the scan).
    serial_scan = record_metadata.get("serialization_scan")
    if serial_scan and serial_scan.get("status") not in (None, "NO_FILE", "SCAN_ERROR"):
        scan_status = serial_scan.get("status", "unknown")
        match_count = serial_scan.get("match_count", 0)
        ledger.add(
            "serialization_scan",
            scan_status,
            EvidenceOrigin.LOCALLY_OBSERVED,
            detail=(
                f"format={serial_scan.get('format_detected', 'unknown')}; "
                f"{match_count} finding(s)"
            ),
        )
    return ledger


def _summarize_provenance(assessment: dict[str, Any]) -> dict[str, Any]:
    """Persist the bounded, explainable provenance evidence from the v2 scorer."""
    return {
        "scoring_version": assessment.get("scoring_version", PROVENANCE_SCORING_VERSION),
        "provenance_score": assessment.get("provenance_score"),
        "point_estimate": assessment.get("point_estimate"),
        "upper_confidence_bound": assessment.get("upper_confidence_bound"),
        "confidence": assessment.get("confidence"),
        "risk_level": assessment.get("risk_level"),
        "assessment_complete": assessment.get("assessment_complete"),
        "dimensions": assessment.get("dimensions", {}),
        "trust_caps": assessment.get("trust_caps", []),
        "indicators": assessment.get("indicators", []),
    }


def _registration_metadata(
    publisher: str | None = None,
    license: str | None = None,
    training_data: str | None = None,
    dependencies: str | None = None,
    training_artifacts: str | None = None,
    deployment_pipeline: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if publisher:
        metadata["publisher"] = publisher
    if license:
        metadata["license"] = license
    if training_data:
        metadata["training_data"] = training_data
    if version:
        metadata["version"] = version
    if dependencies:
        metadata["dependencies"] = _parse_dependencies(dependencies)
    if training_artifacts:
        metadata["training_artifacts"] = _parse_json_or_lines(training_artifacts, field_name="training_artifacts")
    if deployment_pipeline:
        parsed = _parse_json_or_lines(deployment_pipeline, field_name="deployment_pipeline")
        metadata["deployment_pipeline"] = parsed if isinstance(parsed, dict) else {"steps": parsed}
    return metadata


def _parse_dependencies(value: str):
    parsed = _parse_json_or_lines(value, field_name="dependencies")
    if isinstance(parsed, dict):
        return parsed.get("items", [])
    return parsed


def _parse_json_or_lines(value: str, field_name: str):
    text = value.strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if text.startswith("{") or text.startswith("["):
            raise HTTPException(status_code=400, detail=f"Invalid JSON for {field_name}")
        return [item.strip() for item in text.replace(",", "\n").splitlines() if item.strip()]


def _update_job(store, job_id: str, status: str, result: dict[str, Any]) -> None:
    store.update_job(job_id, status, result)


def _save_registered_model(store, rec: ModelRecord) -> dict[str, Any]:
    store.save_model(rec.to_dict())
    return VulnerabilityIntelligenceEngine(store).scan_model(rec.model_id) or {}


def _extract_hf_repo_id(source_url: str) -> str:
    parsed = urlparse(source_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError("Hugging Face URL must include owner and repository name")
    return f"{parts[0]}/{parts[1]}"


def _is_huggingface_url(source_url: str) -> bool:
    host = urlparse(source_url).netloc.lower()
    return host == "huggingface.co" or host.endswith(".huggingface.co")


def _hf_cache_base() -> Path:
    """Return a directory on real disk for HuggingFace downloads.

    /tmp is often a tmpfs (RAM-backed) filesystem too small for large model
    snapshots. We default to data/hf_cache/ next to the SQLite database so the
    download lands on the same real disk partition as the rest of the project.
    Override with AIAF_HF_CACHE_DIR if you want a different location.
    """
    env_dir = os.getenv("AIAF_HF_CACHE_DIR")
    if env_dir:
        base = Path(env_dir)
    else:
        # Anchor to the project root via __file__ (src/aiaf/api/models.py →
        # src/aiaf/api → src/aiaf → src → project root).
        # Path.cwd() is NOT used because production servers are often started
        # from a different working directory (e.g. /, /app, systemd unit root).
        base = Path(__file__).resolve().parents[3] / "data" / "hf_cache"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _register_hf_snapshot_job(
    store,
    job_id: str,
    source_url: str,
    registered_by: str | None,
    metadata: dict[str, Any] | None = None,
    hf_token: str | None = None,
) -> None:
    _job_log_init(job_id)
    _update_job(store, job_id, "RUNNING", {"source_url": source_url})
    tmp_path = None
    try:
        from huggingface_hub import snapshot_download

        repo_id = _extract_hf_repo_id(source_url)
        # Token precedence: request body → HF_TOKEN env var → HUGGINGFACE_TOKEN env var
        effective_token = hf_token or os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_TOKEN")

        _job_log_append(job_id, f"[AIAF] Registering HuggingFace model: {repo_id}")
        if effective_token:
            _job_log_append(job_id, "[AIAF] HF token provided — authenticated download")
        else:
            _job_log_append(
                job_id,
                "[AIAF] Warning: No HF token — unauthenticated (rate-limited). Set HF_TOKEN env var or enter token in the UI.",
            )

        # Use a real-disk directory — large models (10–30 GB) overflow /tmp which
        # is typically a tmpfs backed by RAM (not disk storage).
        cache_base = _hf_cache_base()
        tmp_path = Path(tempfile.mkdtemp(prefix="aiaf_hf_snapshot_", dir=cache_base))
        _job_log_append(job_id, f"[AIAF] Download cache: {tmp_path}")
        _job_log_append(job_id, "[AIAF] Starting snapshot download…")

        # Attach a handler to the huggingface_hub logger so INFO/WARNING messages
        # (e.g. auth warnings) are captured in the job log.
        hf_logger = logging.getLogger("huggingface_hub")
        hf_handler = _JobLogHandler(job_id)
        hf_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        hf_logger.addHandler(hf_handler)

        try:
            # Redirect stderr to capture tqdm progress bars.  _LogCapture.isatty()
            # returns False so tqdm emits \n-separated lines instead of \r rewrites.
            # A 60-second timeout prevents a slow download from blocking other jobs'
            # background threads indefinitely waiting for the lock.
            _captured = _STDERR_REDIRECT_LOCK.acquire(timeout=60)
            if _captured:
                original_stderr = sys.stderr
                sys.stderr = _LogCapture(job_id, original_stderr)
            else:
                _job_log_append(job_id, "[AIAF] Note: tqdm capture unavailable (another download is active) — progress will not be shown")
            try:
                local_dir = snapshot_download(
                    repo_id=repo_id, token=effective_token, cache_dir=str(tmp_path)
                )
            finally:
                if _captured:
                    captured = sys.stderr
                    sys.stderr = original_stderr
                    captured.flush()
                    _STDERR_REDIRECT_LOCK.release()
        finally:
            hf_logger.removeHandler(hf_handler)

        _job_log_append(job_id, "[AIAF] Download complete — parsing model card…")

        # Phase 3: pull model card metadata from the snapshot directory while
        # it is still on disk.  Facts are tagged PROVIDER_DECLARED.
        from ..registry.hf_model_card import parse_snapshot_dir as _parse_mc
        hf_card_data = {}
        try:
            hf_card_data = _parse_mc(local_dir)
            _job_log_append(
                job_id,
                f"[AIAF] Model card: license={hf_card_data.get('license')!r}  "
                f"pipeline_tag={hf_card_data.get('pipeline_tag')!r}  "
                f"model_type={hf_card_data.get('model_type')!r}",
            )
        except Exception as mc_err:
            _job_log_append(job_id, f"[AIAF] Model card parse skipped: {mc_err}")

        _job_log_append(job_id, "[AIAF] Creating archive…")

        # Archive written to the same real-disk location — avoids double-buffering.
        archive_base = str(tmp_path / "snapshot_archive")
        archive_path = shutil.make_archive(archive_base, "gztar", root_dir=local_dir)
        _job_log_append(job_id, "[AIAF] Archive created — computing provenance…")

        merged_meta: dict[str, Any] = {
            **(metadata or {}),
            "artifact_kind": "huggingface_snapshot_archive",
            "archive_format": "gztar",
            "repo_id": repo_id,
        }
        if hf_card_data:
            merged_meta["hf_model_card"] = hf_card_data
            # Pre-populate top-level fields from model card if not supplied.
            for field in ("license", "publisher"):
                if hf_card_data.get(field) and not merged_meta.get(field):
                    merged_meta[field] = hf_card_data[field]

        rec = _register_from_file(
            archive_path,
            source_url,
            registered_by,
            metadata=merged_meta,
        )
        _job_log_append(job_id, "[AIAF] Provenance computed — running vulnerability scan…")
        vulnerability_scan = _save_registered_model(store, rec)
        _job_log_append(job_id, f"[AIAF] Done — model_id: {rec.model_id}  risk: {rec.risk_level}")

        _update_job(
            store,
            job_id,
            "COMPLETED",
            {
                "model_id": rec.model_id,
                "sha256": rec.sha256,
                "repo_id": repo_id,
                "source_url": source_url,
                "vulnerability_scan": vulnerability_scan,
            },
        )
    except Exception as e:
        logging.exception("HF background job failed")
        # Scrub the token from the error message before storing/logging it.
        # huggingface_hub auth errors sometimes embed the bearer token in the
        # exception string (e.g. "401 … token=hf_xxx"); store only a redacted copy.
        safe_err = _redact_token(str(e), effective_token)
        _job_log_append(job_id, f"[AIAF] ERROR: {safe_err}")
        try:
            _update_job(store, job_id, "FAILED", {"error": safe_err, "source_url": source_url})
        except Exception:
            logging.exception("Failed to persist HF background job failure")
    finally:
        # Clean up the temp tree (snapshot + archive) from disk once the job
        # completes or fails — the registered artifact lives in the database.
        if tmp_path and tmp_path.exists():
            try:
                shutil.rmtree(tmp_path, ignore_errors=True)
            except Exception:
                pass


@router.post("/models/register")
async def register_model(
    background_tasks: BackgroundTasks,
    api_key: str = Depends(get_api_key),
    source_url: str | None = Form(None),
    file: UploadFile | None = File(None),
    registered_by: str | None = Form(None),
    publisher: str | None = Form(None),
    license: str | None = Form(None),
    training_data: str | None = Form(None),
    dependencies: str | None = Form(None),
    training_artifacts: str | None = Form(None),
    deployment_pipeline: str | None = Form(None),
    version: str | None = Form(None),
    hf_token: str | None = Form(None, description="HuggingFace API token — optional, enables private repos and higher rate limits. Falls back to HF_TOKEN / HUGGINGFACE_TOKEN env vars."),
):
    """Register a model either by providing a source_url or uploading a file.

    For large uploads, returns a job id and processes hashing in background.
    """
    store = get_store()
    registration_metadata = _registration_metadata(
        publisher=publisher,
        license=license,
        training_data=training_data,
        dependencies=dependencies,
        training_artifacts=training_artifacts,
        deployment_pipeline=deployment_pipeline,
        version=version,
    )

    # if file upload provided
    if file is not None:
        # stream to temp file
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp.flush()
            tmp.close()
        finally:
            await file.close()

        file_size = os.path.getsize(tmp.name)
        # threshold for background processing: 10MB
        if file_size > 10 * 1024 * 1024:
            job_id = store.create_job()
            _job_log_init(job_id)

            def bg_task(path, src_url, reg_by, job, original_name):
                _job_log_append(job, f"[AIAF] Processing upload: {original_name} ({file_size:,} bytes)")
                try:
                    _job_log_append(job, "[AIAF] Computing SHA-256 and provenance…")
                    rec = _register_from_file(
                        path,
                        src_url,
                        reg_by,
                        metadata=registration_metadata,
                        artifact_name=original_name,
                    )
                    _job_log_append(job, "[AIAF] Running vulnerability scan…")
                    vulnerability_scan = _save_registered_model(store, rec)
                    _job_log_append(job, f"[AIAF] Done — model_id: {rec.model_id}  risk: {rec.risk_level}")
                    store.update_job(
                        job,
                        "COMPLETED",
                        {"model_id": rec.model_id, "vulnerability_scan": vulnerability_scan},
                    )
                except Exception as e:
                    _job_log_append(job, f"[AIAF] ERROR: {e}")
                    store.update_job(job, "FAILED", {"error": str(e)})
                finally:
                    try:
                        os.unlink(path)
                    except Exception:
                        pass

            background_tasks.add_task(
                bg_task, tmp.name, source_url, registered_by, job_id, file.filename or ""
            )
            return JSONResponse(status_code=202, content={"job_id": job_id, "status": "processing"})
        else:
            rec = _register_from_file(
                tmp.name,
                source_url,
                registered_by,
                metadata=registration_metadata,
                artifact_name=file.filename or "",
            )
            vulnerability_scan = _save_registered_model(store, rec)
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
            return {
                "model_id": rec.model_id,
                "provenance_score": rec.provenance_score,
                "risk": rec.risk_level,
                "vulnerability_scan": vulnerability_scan,
            }

    # if source_url provided
    if source_url:
        # If it's a Hugging Face model URL, prefer using the huggingface_hub
        # client which handles tokens, snapshots and model artifacts properly.
        if _is_huggingface_url(source_url):
            job_id = store.create_job()
            background_tasks.add_task(_register_hf_snapshot_job, store, job_id, source_url, registered_by, registration_metadata, hf_token)
            return JSONResponse(status_code=202, content={"job_id": job_id, "status": "processing"})

        # Generic fetch for non-HF URLs
        tmpf = tempfile.NamedTemporaryFile(delete=False)
        headers = {"User-Agent": "AIAF-Model-Registry/1.0"}
        try:
            try:
                with httpx.stream("GET", source_url, follow_redirects=True, timeout=30.0, headers=headers) as r:
                    try:
                        r.raise_for_status()
                    except httpx.HTTPStatusError as he:
                        status = he.response.status_code if he.response is not None else 502
                        detail = f"Failed to fetch source_url ({status}). If the resource requires authentication set HF_TOKEN or HUGGINGFACE_TOKEN. Original: {str(he)}"
                        raise HTTPException(status_code=502, detail=detail)

                    for chunk in r.iter_bytes(1024 * 1024):
                        tmpf.write(chunk)
                tmpf.flush()
                tmpf.close()
                rec = _register_from_file(
                    tmpf.name,
                    source_url,
                    registered_by,
                    metadata=registration_metadata,
                    artifact_name=Path(urlparse(source_url).path).name,
                )
                vulnerability_scan = _save_registered_model(store, rec)
                return {
                    "model_id": rec.model_id,
                    "provenance_score": rec.provenance_score,
                    "risk": rec.risk_level,
                    "vulnerability_scan": vulnerability_scan,
                }
            except HTTPException:
                raise
            except Exception as e:
                logging.exception("Failed to fetch and register source_url")
                raise HTTPException(status_code=502, detail=f"Registration failed while fetching source_url: {str(e)}")
        finally:
            try:
                if os.path.exists(tmpf.name):
                    os.unlink(tmpf.name)
            except Exception:
                pass

    raise HTTPException(status_code=400, detail="Provide either file upload or source_url")


@router.post("/models/verify")
async def verify_model_endpoint(
    api_key: str = Depends(get_api_key),
    model_id: str | None = Form(None),
    file: UploadFile | None = File(None),
):
    store = get_store()
    if model_id is None and file is None:
        raise HTTPException(status_code=400, detail="Provide model_id or file to verify")

    if model_id:
        rec = store.get_model(model_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="Model not found")
        return {"status": "registered", "sha256": rec.get("sha256"), "model_id": model_id}

    # file upload verification against provided stored hash in form is not supplied; compute hash and return
    if file is not None:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
            tmp.flush()
            tmp.close()
            sha = calculate_sha256(tmp.name)
            return {"status": "computed", "sha256": sha}
        finally:
            await file.close()
            try:
                os.unlink(tmp.name)
            except Exception:
                pass


@router.get("/models/{model_id}/provenance")
def get_provenance(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"model": rec}


@router.get("/models/{model_id}/mbom")
def get_mbom(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    mbom = generate_mbom(rec)
    return {"mbom": mbom}


@router.get("/models/{model_id}/assurance")
def get_unknown_model_assurance(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    metadata = rec.get("metadata") or {}
    assurance = metadata.get("unknown_model_assurance")
    if assurance is None:
        recommendation = metadata.get("adoption_recommendation") or {}
        assurance = recommendation.get("unknown_model_assurance")
    if assurance is None:
        raise HTTPException(
            status_code=404,
            detail="No unknown-model assurance yet; run POST /v1/intake/triage",
        )
    return {"model_id": model_id, "unknown_model_assurance": assurance}


@router.get("/models/{model_id}/vulnerabilities")
def get_model_vulnerabilities(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    return {
        "model_id": model_id,
        "vulnerability_scan": rec.get("vulnerability_scan")
        or rec.get("metadata", {}).get("vulnerability_scan", {}),
    }


@router.post("/models/{model_id}/vulnerabilities/scan")
def scan_model_vulnerabilities(
    model_id: str, api_key: str = Depends(get_api_key)
):
    result = VulnerabilityIntelligenceEngine(get_store()).scan_model(model_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"model_id": model_id, "vulnerability_scan": result}


def _attestation_key() -> str:
    key = os.getenv("AIAF_ATTESTATION_KEY", "")
    if not key:
        raise HTTPException(
            status_code=503,
            detail="AIAF_ATTESTATION_KEY is required for provenance attestations",
        )
    return key


def _attestation_key_id() -> str:
    return os.getenv("AIAF_ATTESTATION_KEY_ID", "default")


def _attestation_issuer() -> str:
    return os.getenv("AIAF_ATTESTATION_ISSUER", "aiaf:model-registry")


_ATTESTATION_LIFETIME = timedelta(days=7)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.post("/models/{model_id}/attestations")
def create_model_attestation(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    key = _attestation_key()
    key_id = _attestation_key_id()
    issuer = _attestation_issuer()
    attestation_id = "att-" + uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    issued_at = _iso(now)
    expires_at = _iso(now + _ATTESTATION_LIFETIME)
    as_of = issued_at
    try:
        attestation = create_provenance_attestation_v2(
            rec,
            key,
            attestation_id=attestation_id,
            key_id=key_id,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            as_of=as_of,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"Model evidence is not attestable: {exc}"
        ) from exc

    verification = verify_provenance_attestation_v2(
        attestation,
        key,
        rec,
        {
            "expected_attestation_id": attestation_id,
            "expected_key_id": key_id,
            "expected_issuer": issuer,
            "as_of": as_of,
        },
    )
    # The schema-2 envelope is strict (signed statement only), so verification
    # evidence is persisted SEPARATELY rather than inside the attestation. The
    # detached attestation_sha256 binds the trusted verification to this exact
    # statement for downstream supply-chain analysis.
    verification_record = {
        "attestation_id": attestation_id,
        "verified": verification["verified"],
        "attestation_sha256": verification["attestation_sha256"],
        "assurance_level": verification["assurance_level"],
        "verified_at": as_of,
        "schema_version": PROVENANCE_ATTESTATION_SCHEMA_VERSION,
    }
    metadata = dict(rec.get("metadata") or {})
    attestations = list(metadata.get("provenance_attestations") or [])
    attestations.append(attestation)
    verifications = list(metadata.get("provenance_attestation_verifications") or [])
    verifications.append(verification_record)
    metadata["provenance_attestations"] = attestations
    metadata["provenance_attestation_verifications"] = verifications
    # A verified attestation is the strongest evidence origin — record it in the
    # fact ledger so the adoption verdict can lift identity above "self-asserted".
    if verification.get("verified"):
        ledger = FactLedger().extend(metadata.get("evidence_ledger") or [])
        ledger.add(
            "provenance_attestation",
            attestation_id,
            EvidenceOrigin.INDEPENDENTLY_VERIFIED,
            detail=f"verified signed attestation ({verification.get('assurance_level')})",
        )
        metadata["evidence_ledger"] = ledger.to_list()
    rec["metadata"] = metadata
    rec["provenance_attestations"] = attestations
    store.save_model(rec)
    return {
        "attestation": attestation,
        "verification": verification,
        "verification_record": verification_record,
    }


@router.get("/models/{model_id}/attestations")
def list_model_attestations(model_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    return {
        "model_id": model_id,
        "attestations": rec.get("provenance_attestations")
        or rec.get("metadata", {}).get("provenance_attestations", []),
    }


@router.post("/models/{model_id}/attestations/verify")
def verify_model_attestation(
    model_id: str,
    attestation: dict[str, Any],
    api_key: str = Depends(get_api_key),
):
    store = get_store()
    rec = store.get_model(model_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Model not found")
    key = _attestation_key()
    # Dual-read: schema-2 envelopes are verified against an explicit identity and
    # time policy derived from the attestation's own statement; legacy schema-1
    # attestations continue to verify through the v1 path.
    if (
        isinstance(attestation, dict)
        and attestation.get("schema_version") == PROVENANCE_ATTESTATION_SCHEMA_VERSION
    ):
        statement = attestation.get("statement") or {}
        predicate = statement.get("predicate") if isinstance(statement, dict) else {}
        predicate = predicate if isinstance(predicate, dict) else {}
        return verify_provenance_attestation_v2(
            attestation,
            key,
            rec,
            {
                "expected_attestation_id": statement.get("attestation_id"),
                "expected_key_id": attestation.get("key_id"),
                "expected_issuer": predicate.get("issuer"),
                "as_of": _iso(datetime.now(timezone.utc)),
            },
        )
    return verify_provenance_attestation(
        attestation,
        key,
        expected_model=rec,
        expected_key_id=_attestation_key_id(),
    )


@router.get("/models")
def list_models(
    api_key: str = Depends(get_api_key),
    limit: int = 100,
    registered_by: str | None = None,
):
    store = get_store()
    return {"models": store.list_models(limit=limit, registered_by=registered_by)}


@router.get("/jobs")
def list_jobs(limit: int = 20, api_key: str = Depends(get_api_key)):
    """Return recent background jobs, newest first."""
    store = get_store()
    return {"jobs": store.list_jobs(limit=limit)}


@router.get("/jobs/{job_id}")
def job_status(job_id: str, api_key: str = Depends(get_api_key)):
    store = get_store()
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/logs")
def job_logs(job_id: str, api_key: str = Depends(get_api_key)):
    """Return in-memory telemetry log lines captured during background job execution."""
    store = get_store()
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job_id,
        "status": job["status"],
        "logs": get_job_logs(job_id),
        "result": job.get("result", {}),
    }

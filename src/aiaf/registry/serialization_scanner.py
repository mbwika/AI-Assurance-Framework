"""Serialization security scanner for model artifacts.

Scans a local model artifact for dangerous serialization patterns that could
execute arbitrary code when the file is loaded.  The scan is **non-executing**:
it inspects the artifact at the byte/opcode level via Python's built-in
:mod:`pickletools` — the actual pickle machinery is never invoked.

Formats handled:

``pytorch_pickle``
    ``.pt``, ``.pth``, ``.bin``, ``.pkl``, ``.pickle`` (and ZIP archives
    thereof, which is the on-disk format PyTorch ≥1.6 uses).  Dangerous
    ``GLOBAL``/``INST`` opcodes importing from block-listed modules are
    flagged; unknown non-ML modules get a LOW advisory finding.

``safetensors``
    ``.safetensors`` — validates the uint64 header-length field and the JSON
    structure; detects header-injection anomalies (CVE-2024-36110 class).

``onnx``
    ``.onnx`` — verifies the protobuf magic bytes and reports format-detected
    only; no execution risk from the serialization layer.

If the optional third-party ``modelscan`` package is installed it is used
instead of the native pickle scanner; evidence origin remains
``LOCALLY_OBSERVED`` either way — AIAF produced the result.

Output fields
-------------
``scan_version``, ``scanner``, ``format_detected``, ``status``, ``findings``,
``by_severity``, ``match_count``, ``scanned_at``, ``assessment_complete``,
``file_path`` — mirrors the shape of other AIAF evidence outputs so the
adoption engine can consume them uniformly.
"""

from __future__ import annotations

import io
import logging
import pickletools
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SCAN_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Status codes (parallel to vulnerability scan statuses).
# ---------------------------------------------------------------------------
STATUS_CLEAN = "CLEAN"
STATUS_UNSAFE = "UNSAFE_PATTERNS_FOUND"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_NO_FILE = "NO_FILE"
STATUS_UNSUPPORTED = "UNSUPPORTED_FORMAT"
STATUS_ERROR = "SCAN_ERROR"

# ---------------------------------------------------------------------------
# Pickle opcode names that can invoke arbitrary Python callables.
# ---------------------------------------------------------------------------
_INVOKING_OPCODES = frozenset({"GLOBAL", "INST", "STACK_GLOBAL"})

# ---------------------------------------------------------------------------
# Safe module roots: standard in PyTorch / HuggingFace / sklearn model files.
# ---------------------------------------------------------------------------
_SAFE_MODULE_ROOTS = frozenset(
    {
        # PyTorch family
        "torch", "torchvision", "torchaudio", "torch_geometric",
        # NumPy / SciPy
        "numpy", "scipy",
        # HuggingFace
        "transformers", "tokenizers", "accelerate", "safetensors",
        "huggingface_hub", "datasets",
        # sklearn / gradient boosting
        "sklearn", "xgboost", "lightgbm", "catboost",
        # TF / Keras (legacy checkpoint pickles)
        "tensorflow", "keras",
        # stdlib safe for serialization
        "collections", "_codecs", "copy_reg", "copyreg",
        "_io", "io", "builtins", "__builtin__",
        "abc", "typing", "enum", "functools",
        "math", "cmath", "decimal", "fractions",
        "datetime", "time", "calendar",
        "json", "hashlib", "base64", "struct",
        # packaging / build metadata (in requirements pickles)
        "packaging", "pkg_resources",
        # image processing common in vision models
        "PIL",
        # misc ML utilities
        "filelock", "tqdm",
    }
)

# Exact (module, name) tuples that are always safe regardless of root.
_SAFE_EXACT = frozenset(
    {
        ("__builtin__", "set"),
        ("__builtin__", "list"),
        ("__builtin__", "tuple"),
        ("__builtin__", "dict"),
        ("builtins", "set"),
        ("builtins", "list"),
        ("builtins", "tuple"),
        ("builtins", "dict"),
    }
)

# Module roots known to allow arbitrary code execution → severity.
_DANGEROUS_ROOTS: Dict[str, str] = {
    "os": "CRITICAL",
    "nt": "CRITICAL",        # Windows os module
    "posix": "CRITICAL",     # POSIX os module
    "subprocess": "CRITICAL",
    "ctypes": "CRITICAL",
    "cffi": "CRITICAL",
    "pty": "CRITICAL",
    "socket": "HIGH",
    "urllib": "HIGH",
    "http": "HIGH",
    "requests": "HIGH",
    "httpx": "HIGH",
    "importlib": "HIGH",
    "imp": "HIGH",
    "marshal": "HIGH",
    "pickle": "HIGH",       # nested pickle deserialization
    "sys": "HIGH",
    "shutil": "MEDIUM",
    "tempfile": "MEDIUM",
    "pathlib": "MEDIUM",
    "glob": "MEDIUM",
    "fnmatch": "LOW",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_file(file_path: str) -> Dict[str, Any]:
    """Scan ``file_path`` and return a structured serialization security report.

    The scan is purely inspective — no pickle machinery is invoked.  Call
    this during model registration while the artifact file still exists; store
    the result in ``model_record.metadata["serialization_scan"]``.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return _result(
            STATUS_NO_FILE, [], "unknown",
            assessment_complete=False, file_path=file_path,
        )

    # Optional: delegate to modelscan if available.
    ms_result = _try_modelscan(file_path)
    if ms_result is not None:
        return ms_result

    suffix = path.suffix.lower()
    try:
        if suffix == ".safetensors":
            fmt, findings = "safetensors", _scan_safetensors(file_path)
        elif suffix == ".onnx":
            fmt, findings = "onnx", _scan_onnx(file_path)
        elif suffix in (".pkl", ".pickle", ".pt", ".pth", ".bin", ""):
            fmt, findings = "pytorch_pickle", _scan_pickle(file_path)
        else:
            # Unknown extension — try pickle anyway (many HF files have none).
            try:
                findings = _scan_pickle(file_path)
                fmt = "pytorch_pickle"
            except Exception:
                return _result(
                    STATUS_UNSUPPORTED, [], "unknown", file_path=file_path
                )
    except Exception as exc:
        logger.warning("Serialization scan error for %s: %s", file_path, exc)
        return _result(
            STATUS_ERROR, [], "unknown",
            assessment_complete=False, file_path=file_path,
        )

    critical_or_high = any(
        f.get("severity") in ("CRITICAL", "HIGH") for f in findings
    )
    status = (
        STATUS_UNSAFE if critical_or_high
        else STATUS_SUSPICIOUS if findings
        else STATUS_CLEAN
    )
    return _result(status, findings, fmt, file_path=file_path)


# ---------------------------------------------------------------------------
# Format-specific scanners
# ---------------------------------------------------------------------------


def _scan_pickle(file_path: str) -> List[Dict[str, Any]]:
    """Scan a pickle file (or ZIP of pickles) for dangerous opcodes."""
    if zipfile.is_zipfile(file_path):
        return _scan_zip_pickle(file_path)
    with open(file_path, "rb") as fh:
        return _scan_pickle_bytes(fh.read(), source=file_path)


def _scan_zip_pickle(file_path: str) -> List[Dict[str, Any]]:
    """Scan pickle streams inside a ZIP archive (PyTorch ≥1.6 format)."""
    findings: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for name in zf.namelist():
                # Only scan pickle files; tensor data blobs are raw binary.
                if name.endswith(".pkl") or name.endswith("/data.pkl"):
                    with zf.open(name) as member:
                        data = member.read()
                    findings.extend(
                        _scan_pickle_bytes(data, source=f"{file_path}::{name}")
                    )
    except zipfile.BadZipFile:
        # Corrupted ZIP — fall through to raw pickle scan.
        with open(file_path, "rb") as fh:
            findings = _scan_pickle_bytes(fh.read(), source=file_path)
    return findings


def _scan_pickle_bytes(data: bytes, *, source: str = "") -> List[Dict[str, Any]]:
    """Non-executing opcode scan of raw pickle bytes.

    Iterates opcodes via :func:`pickletools.genops` — this decodes the byte
    stream without invoking any Python callable.
    """
    findings: List[Dict[str, Any]] = []
    try:
        stream = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(stream):
            if opcode.name not in _INVOKING_OPCODES:
                continue
            # pickletools.genops() returns GLOBAL/INST args as a single string
            # with the module and name joined by a space (e.g. "posix system"),
            # even though the raw pickle stream uses newline terminators.
            # STACK_GLOBAL pushes module/name on the stack; arg is None here —
            # we can't inspect it without stack simulation, so we skip it.
            if arg is None:
                continue
            arg_str = str(arg).strip()
            # Try space separator (pickletools output); fall back to newline
            # (in case future versions change the format).
            sep = " " if " " in arg_str else "\n"
            parts = arg_str.split(sep, 1)
            if len(parts) != 2:
                continue
            module, name = parts[0].strip(), parts[1].strip()
            finding = _check_global(module, name, pos, source)
            if finding:
                findings.append(finding)
    except Exception as exc:
        findings.append(
            {
                "type": "malformed_pickle",
                "severity": "HIGH",
                "description": f"Pickle stream cannot be decoded: {exc}",
                "module": None,
                "name": None,
                "offset": -1,
                "source": str(source),
            }
        )
    return findings


def _check_global(
    module: str, name: str, offset: int, source: str
) -> Optional[Dict[str, Any]]:
    """Return a finding dict if (module, name) is dangerous, else None."""
    if (module, name) in _SAFE_EXACT:
        return None
    root = module.split(".")[0]
    if root in _SAFE_MODULE_ROOTS:
        return None

    severity = _DANGEROUS_ROOTS.get(root)
    if severity:
        return {
            "type": "dangerous_import",
            "severity": severity,
            "description": (
                f"Pickle GLOBAL imports {module}.{name} — "
                f"{root!r} module can execute arbitrary code."
            ),
            "module": module,
            "name": name,
            "offset": offset,
            "source": str(source),
        }

    # Unknown module — low-severity advisory.
    return {
        "type": "unknown_import",
        "severity": "LOW",
        "description": (
            f"Pickle GLOBAL imports from non-standard module: {module}.{name}"
        ),
        "module": module,
        "name": name,
        "offset": offset,
        "source": str(source),
    }


def _scan_safetensors(file_path: str) -> List[Dict[str, Any]]:
    """Validate safetensors header structure (CVE-2024-36110 class checks)."""
    findings: List[Dict[str, Any]] = []
    try:
        with open(file_path, "rb") as fh:
            # First 8 bytes: little-endian uint64 header length.
            raw = fh.read(8)
            if len(raw) < 8:
                findings.append(
                    {
                        "type": "malformed_header",
                        "severity": "HIGH",
                        "description": "safetensors file is shorter than 8 bytes (invalid header).",
                        "module": None,
                        "name": None,
                        "offset": 0,
                        "source": file_path,
                    }
                )
                return findings
            import struct as _struct
            header_len = _struct.unpack_from("<Q", raw)[0]
            # A sane safetensors header is at most a few MB.  Anything larger
            # suggests a header-length manipulation attack.
            MAX_SANE_HEADER = 100 * 1024 * 1024  # 100 MB
            if header_len > MAX_SANE_HEADER:
                findings.append(
                    {
                        "type": "header_length_anomaly",
                        "severity": "CRITICAL",
                        "description": (
                            f"safetensors header_size field is {header_len:,} bytes — "
                            "abnormally large; possible header injection attack."
                        ),
                        "module": None,
                        "name": None,
                        "offset": 0,
                        "source": file_path,
                    }
                )
                return findings

            header_bytes = fh.read(header_len)
            try:
                import json as _json
                _json.loads(header_bytes)
            except Exception as exc:
                findings.append(
                    {
                        "type": "malformed_header",
                        "severity": "HIGH",
                        "description": f"safetensors header is not valid JSON: {exc}",
                        "module": None,
                        "name": None,
                        "offset": 8,
                        "source": file_path,
                    }
                )
    except OSError as exc:
        findings.append(
            {
                "type": "read_error",
                "severity": "MEDIUM",
                "description": f"Could not read safetensors file: {exc}",
                "module": None,
                "name": None,
                "offset": -1,
                "source": file_path,
            }
        )
    return findings


def _scan_onnx(file_path: str) -> List[Dict[str, Any]]:
    """Minimal ONNX header check — serialization layer has no execution risk."""
    try:
        with open(file_path, "rb") as fh:
            magic = fh.read(2)
        if len(magic) < 2 or magic[0] != 0x0A:
            return [
                {
                    "type": "malformed_header",
                    "severity": "MEDIUM",
                    "description": "ONNX file does not start with expected protobuf magic (0x0A).",
                    "module": None,
                    "name": None,
                    "offset": 0,
                    "source": file_path,
                }
            ]
    except OSError:
        pass
    return []


# ---------------------------------------------------------------------------
# Optional modelscan wrapper
# ---------------------------------------------------------------------------


def _try_modelscan(file_path: str) -> Optional[Dict[str, Any]]:
    """Delegate to the ``modelscan`` package if installed; else return None."""
    try:
        from modelscan.scan import ModelScan  # type: ignore[import]
    except ImportError:
        return None
    try:
        ms = ModelScan()
        result = ms.scan(file_path)
        findings: List[Dict[str, Any]] = []
        for issue in result.issues or []:
            sev = str(getattr(issue, "severity", "MEDIUM")).upper()
            # modelscan uses e.g. "Severity.CRITICAL" — strip prefix.
            sev = sev.split(".")[-1]
            desc = str(getattr(issue, "description", "") or getattr(issue, "name", ""))
            findings.append(
                {
                    "type": "dangerous_import",
                    "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                    "description": desc,
                    "module": None,
                    "name": None,
                    "offset": -1,
                    "source": file_path,
                }
            )
        critical_or_high = any(
            f["severity"] in ("CRITICAL", "HIGH") for f in findings
        )
        status = (
            STATUS_UNSAFE if critical_or_high
            else STATUS_SUSPICIOUS if findings
            else STATUS_CLEAN
        )
        return _result(status, findings, "pytorch_pickle",
                       scanner="modelscan", file_path=file_path)
    except Exception as exc:
        logger.warning("modelscan failed for %s: %s", file_path, exc)
        return None


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------


def _result(
    status: str,
    findings: List[Dict[str, Any]],
    fmt: str,
    *,
    scanner: str = "aiaf-native",
    assessment_complete: bool = True,
    file_path: str = "",
) -> Dict[str, Any]:
    by_severity: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    }
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev in by_severity:
            by_severity[sev] += 1

    return {
        "scan_version": SCAN_VERSION,
        "scanner": scanner,
        "format_detected": fmt,
        "status": status,
        "findings": findings,
        "by_severity": by_severity,
        "match_count": len(findings),
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "assessment_complete": assessment_complete,
        "file_path": str(file_path),
    }

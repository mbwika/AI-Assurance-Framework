"""Weight and tensor header inspector for model artifact files.

Extracts architecture facts from model file headers **without loading tensors
into memory**.  All derivation is byte-level or JSON-level over the first few
kilobytes of the file (or the GGUF metadata section); no GPU memory and no
large heap allocations are required.

Supported formats
-----------------
``safetensors``
    The file begins with a uint64LE header-length field followed by a JSON
    object containing every tensor's name, dtype, shape, and byte offsets.
    We read only those first 8 + N bytes; the tensor data is never touched.

``gguf``
    General GPU Unified Format (llama.cpp ecosystem).  The header contains a
    magic, version, tensor count, KV count, and then key-value metadata pairs
    that fully describe the model architecture before any tensor bytes appear.
    We parse the KV section only.

``pytorch_pickle``
    PyTorch checkpoints are ZIP archives containing a ``data.pkl`` pickle
    stream.  Shape extraction requires executing pickle opcodes — a
    code-execution risk — so we report format-detected only and defer to the
    serialization scanner for safety assessment.

``onnx``
    ONNX files use protobuf encoding.  We verify the opening bytes only.
    Install the ``onnx`` package for graph-level inspection.

Evidence origin
---------------
All derived facts are tagged ``LOCALLY_OBSERVED`` — AIAF produced them by
reading the artifact bytes directly, independent of any publisher claim.
"""

from __future__ import annotations

import json
import re
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

INSPECTOR_VERSION = "1.0"

STATUS_INSPECTED = "INSPECTED"
STATUS_HEADER_ONLY = "HEADER_ONLY"
STATUS_NO_FILE = "NO_FILE"
STATUS_UNSUPPORTED = "UNSUPPORTED_FORMAT"
STATUS_ERROR = "INSPECTION_ERROR"

# (regex pattern, architecture family label)
_ARCH_PATTERNS: List[Tuple[str, str]] = [
    (r"\.self_attn\.|\.attention\.|transformer\.h\.", "transformer"),
    (r"model\.layers\.", "transformer"),
    (r"encoder\.layer\.", "transformer_encoder"),
    (r"decoder\.layers?\.", "transformer"),
    (r"\.state_space\.|\.mamba\.|\.mixer\.", "ssm"),
    (r"\.conv_out\.|unet\.|down_blocks\.", "diffusion"),
    (r"\.rnn\.|\.lstm\.|\.gru\.", "rnn"),
]

# GGUF value type → struct format string (scalar types only)
_GGUF_SCALAR_FMT: Dict[int, str] = {
    0: "<B",   # UINT8
    1: "<b",   # INT8
    2: "<H",   # UINT16
    3: "<h",   # INT16
    4: "<I",   # UINT32
    5: "<i",   # INT32
    6: "<f",   # FLOAT32
    7: "<?",   # BOOL
    10: "<Q",  # UINT64
    11: "<q",  # INT64
    12: "<d",  # FLOAT64
}

_GGUF_FILE_TYPES: Dict[int, str] = {
    0: "fp32", 1: "fp16", 2: "q4_0", 3: "q4_1",
    6: "q5_0", 7: "q5_1", 8: "q8_0", 9: "q8_1",
    10: "q2_k", 11: "q3_k_s", 12: "q3_k_m", 13: "q3_k_l",
    14: "q4_k_s", 15: "q4_k_m", 16: "q5_k_s", 17: "q5_k_m",
    18: "q6_k", 19: "q8_k",
}

# Safetensors dtype → readable quantization label
_SAFETENSORS_DTYPE_QUANT: Dict[str, str] = {
    "F64": "fp64", "F32": "fp32", "F16": "fp16", "BF16": "bf16",
    "F8_E4M3": "fp8", "F8_E5M2": "fp8",
    "I32": "int32", "I16": "int16", "I8": "int8", "I4": "int4",
    "U8": "uint8", "U16": "uint16", "U32": "uint32", "U64": "uint64",
    "BOOL": "bool",
}

# Dtype priority for quantization summary (highest precision listed first)
_DTYPE_PRIORITY = ["F64", "F32", "BF16", "F16", "F8_E4M3", "F8_E5M2",
                   "I32", "I16", "I8", "I4", "U32", "U16", "U8", "BOOL"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def inspect_file(file_path: str) -> Dict[str, Any]:
    """Inspect a model artifact and return an evidence dict of derived facts.

    Only the file header is read; tensor weights are never loaded.  The caller
    should handle the NO_FILE / UNSUPPORTED / INSPECTION_ERROR statuses as
    evidence gaps rather than failures.
    """
    if not file_path:
        return _result(STATUS_NO_FILE, file_path=file_path)

    path = Path(str(file_path))
    if not path.exists():
        return _result(STATUS_NO_FILE, file_path=str(path))

    file_size = path.stat().st_size
    suffix = path.suffix.lower()

    try:
        if suffix == ".safetensors":
            return _inspect_safetensors(path, file_size)
        if suffix == ".gguf":
            return _inspect_gguf(path, file_size)
        if suffix in (".pt", ".pth", ".bin", ".pkl", ".pickle"):
            return _inspect_pytorch(path, file_size)
        if suffix == ".onnx":
            return _inspect_onnx(path, file_size)

        # No extension match — try magic bytes
        fmt = _detect_magic(path)
        if fmt == "safetensors":
            return _inspect_safetensors(path, file_size)
        if fmt == "gguf":
            return _inspect_gguf(path, file_size)
        if fmt == "pytorch":
            return _inspect_pytorch(path, file_size)
        if fmt == "onnx":
            return _inspect_onnx(path, file_size)

        return _result(STATUS_UNSUPPORTED, file_path=str(path),
                       file_size_bytes=file_size, format_detected="unknown")
    except Exception as exc:
        return _result(STATUS_ERROR, file_path=str(path),
                       file_size_bytes=file_size,
                       error=f"{type(exc).__name__}: {exc}"[:300])


# ---------------------------------------------------------------------------
# Format detectors
# ---------------------------------------------------------------------------


def _detect_magic(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
    except OSError:
        return "unknown"
    if magic[:4] == b"GGUF":
        return "gguf"
    if magic[:2] == b"PK":      # ZIP — PyTorch
        return "pytorch"
    if magic[:2] in (b"\x08", b"\x0a"):  # protobuf field prefix — likely ONNX
        return "onnx"
    return "unknown"


# ---------------------------------------------------------------------------
# Safetensors
# ---------------------------------------------------------------------------


def _inspect_safetensors(path: Path, file_size: int) -> Dict[str, Any]:
    with open(path, "rb") as f:
        hdr_len_raw = f.read(8)
        if len(hdr_len_raw) < 8:
            return _result(STATUS_ERROR, file_path=str(path),
                           file_size_bytes=file_size, format_detected="safetensors",
                           error="File too short to contain safetensors header length field")
        header_length = struct.unpack("<Q", hdr_len_raw)[0]

        # Reject absurd header sizes (> 256 MB) — CVE-2024-36110 class
        if header_length > 256 * 1024 * 1024:
            return _result(STATUS_ERROR, file_path=str(path),
                           file_size_bytes=file_size, format_detected="safetensors",
                           error=f"Header length {header_length} exceeds 256 MB safety limit")

        header_bytes = f.read(header_length)

    try:
        header: Dict[str, Any] = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _result(STATUS_ERROR, file_path=str(path),
                       file_size_bytes=file_size, format_detected="safetensors",
                       error=f"Header JSON parse error: {exc}")

    format_meta = header.pop("__metadata__", None) or {}
    tensor_names = sorted(header.keys())
    derived = _derive_from_safetensors(tensor_names, header)
    derived["format_metadata"] = {k: str(v) for k, v in list(format_meta.items())[:20]}

    return _result(
        STATUS_INSPECTED,
        file_path=str(path),
        file_size_bytes=file_size,
        format_detected="safetensors",
        derived_facts=derived,
        tensor_names_sample=tensor_names[:30],
        tensor_count=len(tensor_names),
    )


def _derive_from_safetensors(
    names: List[str], header: Dict[str, Any]
) -> Dict[str, Any]:
    arch_family = _detect_arch_family(names)
    layer_count = _count_layers(names)

    param_count = 0
    dtypes_seen: List[str] = []
    for tensor_meta in header.values():
        if not isinstance(tensor_meta, dict):
            continue
        dtype = str(tensor_meta.get("dtype") or "")
        if dtype and dtype not in dtypes_seen:
            dtypes_seen.append(dtype)
        try:
            n = 1
            for dim in (tensor_meta.get("shape") or []):
                n *= int(dim)
            param_count += n
        except (TypeError, ValueError):
            pass

    hidden_size = _infer_hidden_size(names, header)
    vocab_size = _infer_vocab_size(names, header)
    quantization = _summarise_dtypes(dtypes_seen)

    return {
        "architecture_family": arch_family,
        "architecture_name": None,
        "layer_count": layer_count,
        "hidden_size": hidden_size,
        "num_attention_heads": None,
        "vocab_size": vocab_size,
        "quantization": quantization,
        "dtypes": sorted(set(dtypes_seen)),
        "parameter_count_estimate": param_count if param_count > 0 else None,
        "parameter_count_method": "tensor_shape_sum" if param_count > 0 else None,
        "parameter_count_exact": True,
    }


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------


def _inspect_gguf(path: Path, file_size: int) -> Dict[str, Any]:
    with open(path, "rb") as f:
        if f.read(4) != b"GGUF":
            return _result(STATUS_ERROR, file_path=str(path),
                           file_size_bytes=file_size, format_detected="gguf",
                           error="Invalid GGUF magic bytes")
        version = struct.unpack("<I", f.read(4))[0]
        tensor_count = struct.unpack("<Q", f.read(8))[0]
        kv_count = struct.unpack("<Q", f.read(8))[0]

        kv: Dict[str, Any] = {}
        for _ in range(min(int(kv_count), 300)):
            try:
                key, value = _read_gguf_kv(f, version)
            except Exception:
                break
            if key is not None:
                kv[key] = value

    derived = _derive_from_gguf_kv(kv)
    derived["gguf_version"] = version

    return _result(
        STATUS_INSPECTED,
        file_path=str(path),
        file_size_bytes=file_size,
        format_detected="gguf",
        derived_facts=derived,
        tensor_count=int(tensor_count),
    )


def _read_gguf_string(f) -> str:
    (length,) = struct.unpack("<Q", f.read(8))
    if length > 1_048_576:
        raise ValueError(f"GGUF string length {length} > 1 MiB")
    return f.read(length).decode("utf-8", errors="replace")


def _read_gguf_value(f, vtype: int, version: int) -> Any:
    if vtype in _GGUF_SCALAR_FMT:
        fmt = _GGUF_SCALAR_FMT[vtype]
        return struct.unpack(fmt, f.read(struct.calcsize(fmt)))[0]
    if vtype == 8:  # STRING
        return _read_gguf_string(f)
    if vtype == 9:  # ARRAY
        elem_type = struct.unpack("<I", f.read(4))[0]
        count = struct.unpack("<Q", f.read(8))[0]
        limit = min(int(count), 32)
        values = []
        for _ in range(limit):
            try:
                values.append(_read_gguf_value(f, elem_type, version))
            except Exception:
                break
        return values
    raise ValueError(f"Unknown GGUF value type {vtype}")


def _read_gguf_kv(f, version: int) -> Tuple[Optional[str], Any]:
    try:
        key = _read_gguf_string(f)
        (vtype,) = struct.unpack("<I", f.read(4))
        value = _read_gguf_value(f, vtype, version)
        return key, value
    except Exception:
        return None, None


def _derive_from_gguf_kv(kv: Dict[str, Any]) -> Dict[str, Any]:
    arch = str(kv.get("general.architecture") or "")
    prefix = f"{arch}." if arch else ""

    def _get(*keys):
        for k in keys:
            v = kv.get(k)
            if v is not None:
                return v
        return None

    layer_count = _get(f"{prefix}block_count", "llama.block_count")
    hidden_size = _get(f"{prefix}embedding_length", "llama.embedding_length")
    num_heads = _get(f"{prefix}attention.head_count", "llama.attention.head_count")
    context_len = _get(f"{prefix}context_length", "llama.context_length")
    vocab_size = _get(f"{prefix}vocab_size")
    name = kv.get("general.name")
    file_type = kv.get("general.file_type")
    quant = _GGUF_FILE_TYPES.get(int(file_type), f"type_{file_type}") if file_type is not None else None

    param_count = _estimate_params_gguf(layer_count, hidden_size, vocab_size)

    return {
        "architecture_family": arch if arch else None,
        "architecture_name": str(name) if name else None,
        "layer_count": int(layer_count) if layer_count is not None else None,
        "hidden_size": int(hidden_size) if hidden_size is not None else None,
        "num_attention_heads": int(num_heads) if num_heads is not None else None,
        "context_length": int(context_len) if context_len is not None else None,
        "vocab_size": int(vocab_size) if vocab_size is not None else None,
        "quantization": quant,
        "parameter_count_estimate": param_count,
        "parameter_count_method": "gguf_metadata_estimate" if param_count else None,
        "parameter_count_exact": False,
    }


def _estimate_params_gguf(
    layer_count: Any, hidden_size: Any, vocab_size: Any
) -> Optional[int]:
    """Rough transformer parameter estimate from GGUF architecture metadata."""
    if layer_count is None or hidden_size is None:
        return None
    try:
        L, H = int(layer_count), int(hidden_size)
        V = int(vocab_size) if vocab_size is not None else max(H * 4, 32_000)
        # embedding (V×H) + per-layer (4×H² attn + 2×4H×H FFN) × L + output head (H×V)
        per_layer = 4 * H * H + 8 * H * H
        return V * H + per_layer * L + H * V
    except (TypeError, ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# PyTorch / ONNX — format-detected only
# ---------------------------------------------------------------------------


def _inspect_pytorch(path: Path, file_size: int) -> Dict[str, Any]:
    is_zip = False
    try:
        is_zip = zipfile.is_zipfile(str(path))
    except Exception:
        pass
    return _result(
        STATUS_HEADER_ONLY,
        file_path=str(path),
        file_size_bytes=file_size,
        format_detected="pytorch_pickle",
        notes=(
            "PyTorch archive detected. Tensor shape extraction requires executing pickle "
            "opcodes, which is a code-execution risk. Architecture facts are not derived here. "
            "See serialization_scanner results for opcode-level safety assessment."
        ),
        derived_facts={
            "architecture_family": None,
            "parameter_count_estimate": None,
            "is_zip_archive": is_zip,
            "parameter_count_exact": False,
        },
    )


def _inspect_onnx(path: Path, file_size: int) -> Dict[str, Any]:
    return _result(
        STATUS_HEADER_ONLY,
        file_path=str(path),
        file_size_bytes=file_size,
        format_detected="onnx",
        notes="ONNX format detected. Install the 'onnx' package for graph-level architecture inspection.",
        derived_facts={
            "architecture_family": None,
            "parameter_count_estimate": None,
            "parameter_count_exact": False,
        },
    )


# ---------------------------------------------------------------------------
# Architecture derivation helpers
# ---------------------------------------------------------------------------


def _detect_arch_family(names: List[str]) -> Optional[str]:
    sample = " ".join(names[:300])
    for pattern, family in _ARCH_PATTERNS:
        if re.search(pattern, sample):
            return family
    return "unknown" if names else None


def _count_layers(names: List[str]) -> Optional[int]:
    """Find the highest zero-based layer index from repeated naming patterns."""
    patterns = [
        r"\.layers\.(\d+)\.",
        r"\.h\.(\d+)\.",
        r"\.layer\.(\d+)\.",
        r"\.blocks\.(\d+)\.",
        r"\.block\.(\d+)\.",
        r"\.layers_(\d+)\.",
    ]
    max_idx = -1
    for name in names:
        for pat in patterns:
            m = re.search(pat, name)
            if m:
                idx = int(m.group(1))
                if idx > max_idx:
                    max_idx = idx
    return max_idx + 1 if max_idx >= 0 else None


def _infer_hidden_size(names: List[str], header: Dict[str, Any]) -> Optional[int]:
    """Infer hidden_size from the query weight of the first attention layer."""
    for name in names:
        lower = name.lower()
        if any(k in lower for k in ("q_proj", "c_attn", "query_key_value", "wq")) \
                and name.endswith(".weight"):
            shape = (header.get(name) or {}).get("shape") or []
            if len(shape) == 2:
                return int(shape[0])
    return None


def _infer_vocab_size(names: List[str], header: Dict[str, Any]) -> Optional[int]:
    """Infer vocab_size from the token embedding weight shape."""
    for name in names:
        lower = name.lower()
        if any(k in lower for k in ("embed_tokens", "wte", "word_embedding",
                                     "token_emb", "embed_in", "tok_embeddings")):
            shape = (header.get(name) or {}).get("shape") or []
            if len(shape) == 2:
                return int(shape[0])
    return None


def _summarise_dtypes(dtypes: List[str]) -> Optional[str]:
    """Return the highest-fidelity dtype label seen in the tensor set."""
    for d in _DTYPE_PRIORITY:
        if d in dtypes:
            return _SAFETENSORS_DTYPE_QUANT.get(d, d.lower())
    if dtypes:
        return _SAFETENSORS_DTYPE_QUANT.get(dtypes[0], dtypes[0].lower())
    return None


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------


def _result(
    status: str,
    *,
    file_path: str = "",
    file_size_bytes: Optional[int] = None,
    format_detected: str = "unknown",
    derived_facts: Optional[Dict[str, Any]] = None,
    tensor_names_sample: Optional[List[str]] = None,
    tensor_count: Optional[int] = None,
    notes: Optional[str] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "inspector_version": INSPECTOR_VERSION,
        "status": status,
        "format_detected": format_detected,
        "file_path": str(file_path),
        "file_size_bytes": file_size_bytes,
        "tensor_count": tensor_count,
        "tensor_names_sample": tensor_names_sample or [],
        "derived_facts": derived_facts or {},
        "notes": notes,
        "error": error,
        "evidence_origin": "locally_observed",
        "assessment_complete": status == STATUS_INSPECTED,
        "inspected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

"""Tests for registry/weight_inspector.py (Phase 5)."""

import json
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from aiaf.registry.weight_inspector import (
    INSPECTOR_VERSION,
    STATUS_INSPECTED,
    STATUS_HEADER_ONLY,
    STATUS_NO_FILE,
    STATUS_UNSUPPORTED,
    STATUS_ERROR,
    inspect_file,
    _detect_arch_family,
    _count_layers,
    _infer_hidden_size,
    _infer_vocab_size,
    _summarise_dtypes,
    _estimate_params_gguf,
    _derive_from_safetensors,
)


# ---------------------------------------------------------------------------
# Safetensors helpers
# ---------------------------------------------------------------------------

def _make_safetensors(tensors: dict, metadata: dict = None) -> bytes:
    """Build a minimal safetensors byte payload."""
    header = dict(tensors)
    if metadata:
        header["__metadata__"] = metadata
    header_json = json.dumps(header).encode("utf-8")
    length = struct.pack("<Q", len(header_json))
    return length + header_json


def _write_safetensors(tmp_path: Path, tensors: dict, metadata: dict = None) -> Path:
    path = tmp_path / "model.safetensors"
    path.write_bytes(_make_safetensors(tensors, metadata))
    return path


# ---------------------------------------------------------------------------
# GGUF helpers
# ---------------------------------------------------------------------------

def _encode_gguf_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def _encode_gguf_kv(key: str, value_type: int, value_bytes: bytes) -> bytes:
    return _encode_gguf_string(key) + struct.pack("<I", value_type) + value_bytes


def _make_gguf(kv_pairs: list, tensor_count: int = 0) -> bytes:
    kv_bytes = b"".join(kv_pairs)
    # magic + version(3) + tensor_count + kv_count
    header = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", tensor_count) + struct.pack("<Q", len(kv_pairs))
    return header + kv_bytes


# ---------------------------------------------------------------------------
# No file / unsupported
# ---------------------------------------------------------------------------

class TestNoFile:
    def test_empty_path(self):
        r = inspect_file("")
        assert r["status"] == STATUS_NO_FILE

    def test_nonexistent_path(self):
        r = inspect_file("/nonexistent/model.safetensors")
        assert r["status"] == STATUS_NO_FILE

    def test_result_has_required_keys(self):
        r = inspect_file("")
        for key in ("inspector_version", "status", "format_detected",
                    "derived_facts", "evidence_origin", "assessment_complete"):
            assert key in r

    def test_evidence_origin_is_locally_observed(self):
        r = inspect_file("")
        assert r["evidence_origin"] == "locally_observed"

    def test_no_file_not_assessment_complete(self):
        r = inspect_file("")
        assert r["assessment_complete"] is False


class TestUnsupportedFormat:
    def test_unknown_extension(self, tmp_path):
        p = tmp_path / "model.xyz"
        p.write_bytes(b"\x00" * 16)
        r = inspect_file(str(p))
        assert r["status"] in (STATUS_UNSUPPORTED, STATUS_ERROR, STATUS_HEADER_ONLY)


# ---------------------------------------------------------------------------
# Safetensors
# ---------------------------------------------------------------------------

class TestSafetensorsInspection:
    def _simple_transformer_tensors(self) -> dict:
        return {
            "model.embed_tokens.weight":
                {"dtype": "BF16", "shape": [32000, 4096], "data_offsets": [0, 262144000]},
            "model.layers.0.self_attn.q_proj.weight":
                {"dtype": "BF16", "shape": [4096, 4096], "data_offsets": [262144000, 295698432]},
            "model.layers.0.self_attn.k_proj.weight":
                {"dtype": "BF16", "shape": [4096, 4096], "data_offsets": [295698432, 329252864]},
            "model.layers.0.mlp.gate_proj.weight":
                {"dtype": "BF16", "shape": [11008, 4096], "data_offsets": [329252864, 419721216]},
            "model.layers.1.self_attn.q_proj.weight":
                {"dtype": "BF16", "shape": [4096, 4096], "data_offsets": [419721216, 453275648]},
            "model.layers.1.mlp.gate_proj.weight":
                {"dtype": "BF16", "shape": [11008, 4096], "data_offsets": [453275648, 543744000]},
            "lm_head.weight":
                {"dtype": "BF16", "shape": [32000, 4096], "data_offsets": [543744000, 805888000]},
        }

    def test_status_inspected(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["status"] == STATUS_INSPECTED

    def test_format_detected(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["format_detected"] == "safetensors"

    def test_assessment_complete(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["assessment_complete"] is True

    def test_parameter_count(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        facts = r["derived_facts"]
        # embedding: 32000*4096 = 131_072_000
        # q_proj layer0: 4096*4096 = 16_777_216, etc.
        assert facts["parameter_count_estimate"] is not None
        assert facts["parameter_count_estimate"] > 0
        assert facts["parameter_count_exact"] is True

    def test_architecture_family_transformer(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["derived_facts"]["architecture_family"] == "transformer"

    def test_layer_count(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["derived_facts"]["layer_count"] == 2

    def test_hidden_size(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["derived_facts"]["hidden_size"] == 4096

    def test_vocab_size(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["derived_facts"]["vocab_size"] == 32000

    def test_quantization_bf16(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["derived_facts"]["quantization"] == "bf16"

    def test_tensor_count(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert r["tensor_count"] == len(self._simple_transformer_tensors())

    def test_tensor_names_sample(self, tmp_path):
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors())
        r = inspect_file(str(p))
        assert len(r["tensor_names_sample"]) > 0

    def test_metadata_preserved(self, tmp_path):
        meta = {"format": "pt", "framework": "pytorch"}
        p = _write_safetensors(tmp_path, self._simple_transformer_tensors(), metadata=meta)
        r = inspect_file(str(p))
        assert "format_metadata" in r["derived_facts"]

    def test_large_header_rejected(self, tmp_path):
        # Craft a file with a 512 MB stated header length (over the limit)
        p = tmp_path / "bad.safetensors"
        p.write_bytes(struct.pack("<Q", 512 * 1024 * 1024) + b"\x00" * 8)
        r = inspect_file(str(p))
        assert r["status"] == STATUS_ERROR

    def test_corrupt_json_header(self, tmp_path):
        p = tmp_path / "corrupt.safetensors"
        payload = b"{not valid json"
        p.write_bytes(struct.pack("<Q", len(payload)) + payload)
        r = inspect_file(str(p))
        assert r["status"] == STATUS_ERROR

    def test_empty_header(self, tmp_path):
        p = _write_safetensors(tmp_path, {})
        r = inspect_file(str(p))
        # Empty safetensors is technically valid; no tensors → no arch facts
        assert r["status"] == STATUS_INSPECTED
        assert r["derived_facts"]["parameter_count_estimate"] is None

    def test_fp32_quantization(self, tmp_path):
        tensors = {
            "model.layers.0.self_attn.q_proj.weight":
                {"dtype": "F32", "shape": [768, 768], "data_offsets": [0, 2359296]},
        }
        p = _write_safetensors(tmp_path, tensors)
        r = inspect_file(str(p))
        assert r["derived_facts"]["quantization"] == "fp32"


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------

class TestGGUFInspection:
    def _make_llama_gguf(self, tmp_path: Path) -> Path:
        kv = [
            _encode_gguf_kv("general.architecture", 8, _encode_gguf_string("llama")),
            _encode_gguf_kv("general.name", 8, _encode_gguf_string("llama-7b-test")),
            _encode_gguf_kv("llama.block_count", 4, struct.pack("<I", 32)),
            _encode_gguf_kv("llama.embedding_length", 4, struct.pack("<I", 4096)),
            _encode_gguf_kv("llama.attention.head_count", 4, struct.pack("<I", 32)),
            _encode_gguf_kv("llama.context_length", 4, struct.pack("<I", 4096)),
            _encode_gguf_kv("llama.vocab_size", 4, struct.pack("<I", 32000)),
            _encode_gguf_kv("general.file_type", 4, struct.pack("<I", 2)),  # q4_0
        ]
        path = tmp_path / "model.gguf"
        path.write_bytes(_make_gguf(kv, tensor_count=50))
        return path

    def test_status_inspected(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["status"] == STATUS_INSPECTED

    def test_architecture_family(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["architecture_family"] == "llama"

    def test_architecture_name(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["architecture_name"] == "llama-7b-test"

    def test_layer_count(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["layer_count"] == 32

    def test_hidden_size(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["hidden_size"] == 4096

    def test_vocab_size(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["vocab_size"] == 32000

    def test_quantization_q4_0(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["quantization"] == "q4_0"

    def test_tensor_count(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["tensor_count"] == 50

    def test_gguf_version_in_facts(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["gguf_version"] == 3

    def test_invalid_magic(self, tmp_path):
        p = tmp_path / "bad.gguf"
        p.write_bytes(b"BADD" + b"\x00" * 20)
        r = inspect_file(str(p))
        assert r["status"] == STATUS_ERROR

    def test_parameter_count_estimate(self, tmp_path):
        r = inspect_file(str(self._make_llama_gguf(tmp_path)))
        assert r["derived_facts"]["parameter_count_estimate"] is not None
        assert r["derived_facts"]["parameter_count_estimate"] > 0


# ---------------------------------------------------------------------------
# PyTorch / ONNX
# ---------------------------------------------------------------------------

class TestPyTorchInspection:
    def test_zip_archive_detected(self, tmp_path):
        p = tmp_path / "model.pt"
        with zipfile.ZipFile(str(p), "w") as zf:
            zf.writestr("archive/data.pkl", b"\x80\x02}q\x00.")
        r = inspect_file(str(p))
        assert r["status"] == STATUS_HEADER_ONLY
        assert r["format_detected"] == "pytorch_pickle"
        assert r["derived_facts"]["is_zip_archive"] is True

    def test_bin_extension_pytorch(self, tmp_path):
        p = tmp_path / "pytorch_model.bin"
        with zipfile.ZipFile(str(p), "w") as zf:
            zf.writestr("archive/data.pkl", b"\x80\x02}q\x00.")
        r = inspect_file(str(p))
        assert r["status"] == STATUS_HEADER_ONLY

    def test_notes_mentions_pickle_risk(self, tmp_path):
        p = tmp_path / "model.pt"
        with zipfile.ZipFile(str(p), "w") as zf:
            zf.writestr("data.pkl", b"\x80\x02.")
        r = inspect_file(str(p))
        assert "pickle" in (r.get("notes") or "").lower()

    def test_not_assessment_complete(self, tmp_path):
        p = tmp_path / "model.pkl"
        p.write_bytes(b"\x80\x02.")
        r = inspect_file(str(p))
        assert r["assessment_complete"] is False


class TestONNXInspection:
    def test_onnx_header_only(self, tmp_path):
        p = tmp_path / "model.onnx"
        p.write_bytes(b"\x08\x07\x12" + b"\x00" * 16)  # protobuf-style opening
        r = inspect_file(str(p))
        assert r["status"] == STATUS_HEADER_ONLY
        assert r["format_detected"] == "onnx"


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------

class TestArchFamilyDetection:
    def test_transformer_from_self_attn(self):
        names = ["model.layers.0.self_attn.q_proj.weight"]
        assert _detect_arch_family(names) == "transformer"

    def test_transformer_from_model_layers(self):
        names = ["model.layers.0.mlp.weight"]
        assert _detect_arch_family(names) == "transformer"

    def test_ssm_from_mamba(self):
        # model.layers. triggers transformer first; use a pure SSM naming pattern
        names = ["backbone.layers.0.mamba.in_proj.weight", "backbone.layers.0.mamba.out_proj.weight"]
        assert _detect_arch_family(names) == "ssm"

    def test_diffusion_from_unet(self):
        names = ["unet.down_blocks.0.conv.weight"]
        assert _detect_arch_family(names) == "diffusion"

    def test_unknown_for_unrecognized(self):
        names = ["fc1.weight", "fc2.weight"]
        assert _detect_arch_family(names) == "unknown"

    def test_none_for_empty(self):
        assert _detect_arch_family([]) is None


class TestLayerCount:
    def test_basic_count(self):
        names = [f"model.layers.{i}.self_attn.weight" for i in range(32)]
        assert _count_layers(names) == 32

    def test_h_pattern(self):
        names = [f"transformer.h.{i}.attn.weight" for i in range(12)]
        assert _count_layers(names) == 12

    def test_no_layers(self):
        names = ["embed.weight", "head.weight"]
        assert _count_layers(names) is None


class TestHiddenSize:
    def test_from_q_proj(self):
        names = ["model.layers.0.self_attn.q_proj.weight"]
        header = {"model.layers.0.self_attn.q_proj.weight": {"shape": [4096, 4096]}}
        assert _infer_hidden_size(names, header) == 4096

    def test_from_c_attn(self):
        names = ["transformer.h.0.attn.c_attn.weight"]
        header = {"transformer.h.0.attn.c_attn.weight": {"shape": [768, 2304]}}
        assert _infer_hidden_size(names, header) == 768

    def test_none_when_no_attn(self):
        names = ["mlp.weight"]
        header = {"mlp.weight": {"shape": [4096, 4096]}}
        assert _infer_hidden_size(names, header) is None


class TestVocabSize:
    def test_from_embed_tokens(self):
        names = ["model.embed_tokens.weight"]
        header = {"model.embed_tokens.weight": {"shape": [32000, 4096]}}
        assert _infer_vocab_size(names, header) == 32000

    def test_from_wte(self):
        names = ["transformer.wte.weight"]
        header = {"transformer.wte.weight": {"shape": [50257, 768]}}
        assert _infer_vocab_size(names, header) == 50257


class TestDtypeSummary:
    def test_bf16(self):
        assert _summarise_dtypes(["BF16"]) == "bf16"

    def test_fp16(self):
        assert _summarise_dtypes(["F16"]) == "fp16"

    def test_prefers_higher_precision(self):
        # F32 > F16 in priority
        assert _summarise_dtypes(["F16", "F32"]) == "fp32"

    def test_none_for_empty(self):
        assert _summarise_dtypes([]) is None


class TestParamEstimation:
    def test_basic_estimate(self):
        # L=32, H=4096 → reasonable 7B estimate
        result = _estimate_params_gguf(32, 4096, 32000)
        assert result is not None
        assert 5_000_000_000 < result < 10_000_000_000

    def test_none_when_missing_layer_count(self):
        assert _estimate_params_gguf(None, 4096, 32000) is None

    def test_none_when_missing_hidden_size(self):
        assert _estimate_params_gguf(32, None, 32000) is None

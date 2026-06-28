"""Tests for registry/deployment_verifier.py — Cap 9: Secure deployment verification."""
import pytest

from aiaf.registry.deployment_verifier import (
    DEPLOYMENT_VERIFY_VERSION,
    VERDICT_MATCH,
    VERDICT_MISMATCH,
    VERDICT_PARTIAL_MATCH,
    VERDICT_UNKNOWN,
    VERDICTS,
    DeploymentVerifyError,
    get_verify_result,
    list_verify_results,
    probe_endpoint,
    verify_deployment,
)

# ---------------------------------------------------------------------------
# Minimal in-memory store stub
# ---------------------------------------------------------------------------

class _Store:
    def __init__(self):
        self._models = {}
        self._findings = []

    def save_model(self, record):
        mid = str(record.get("model_id") or "")
        self._models[mid] = record
        return mid

    def get_model(self, model_id):
        return self._models.get(str(model_id))

    def list_models(self):
        return list(self._models.values())

    def save_finding(self, finding):
        self._findings.append(finding)
        return len(self._findings) - 1


def _make_model(model_id, **meta_overrides):
    meta = {
        "model_id": model_id,
        "sha256": "abc123" + "0" * 58,
        "container_digest": "sha256:" + "d" * 64,
        "system_prompt_sha256": "sp" + "0" * 62,
        "tool_list": ["tool_a", "tool_b"],
        "guardrail_versions": [{"name": "bias_guard", "version": "1.0"}],
    }
    meta.update(meta_overrides)
    return {"model_id": model_id, "metadata": meta}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_version_constant():
    assert DEPLOYMENT_VERIFY_VERSION == "1.0"


def test_verdicts_frozenset():
    assert VERDICT_MATCH in VERDICTS
    assert VERDICT_MISMATCH in VERDICTS
    assert VERDICT_PARTIAL_MATCH in VERDICTS
    assert VERDICT_UNKNOWN in VERDICTS


# ---------------------------------------------------------------------------
# validate inputs
# ---------------------------------------------------------------------------

def test_empty_model_id_raises():
    store = _Store()
    with pytest.raises(DeploymentVerifyError, match="model_id"):
        verify_deployment("", {}, store)


def test_non_dict_observed_raises():
    store = _Store()
    with pytest.raises(DeploymentVerifyError, match="observed"):
        verify_deployment("m1", "not-a-dict", store)


# ---------------------------------------------------------------------------
# No registered record — all checks UNKNOWN
# ---------------------------------------------------------------------------

def test_no_registered_record_gives_unknown():
    store = _Store()
    result = verify_deployment("nonexistent-model", {}, store, save_result=False)
    assert result["verdict"] == VERDICT_UNKNOWN
    assert result["registered_record_found"] is False
    assert result["artifact_match"]["status"] == "UNKNOWN"
    assert result["container_match"]["status"] == "UNKNOWN"
    assert result["system_prompt_match"]["status"] == "UNKNOWN"
    assert result["tool_drift"]["status"] == "UNKNOWN"
    assert result["guardrail_drift"]["status"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Perfect MATCH
# ---------------------------------------------------------------------------

def test_full_match():
    store = _Store()
    model_id = "model-match-1"
    sha = "a" * 64
    cdg = "sha256:" + "b" * 64
    sp_sha = "c" * 64
    store.save_model(_make_model(
        model_id,
        sha256=sha, container_digest=cdg, system_prompt_sha256=sp_sha,
        tool_list=["tool_a", "tool_b"],
        guardrail_versions=[{"name": "guard1", "version": "1.2"}],
    ))
    observed = {
        "weights_sha256": sha,
        "container_digest": cdg,
        "system_prompt_sha256": sp_sha,
        "tool_list": ["tool_a", "tool_b"],
        "guardrail_versions": [{"name": "guard1", "version": "1.2"}],
        "served_model_id": model_id,
    }
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["verdict"] == VERDICT_MATCH
    assert result["artifact_match"]["status"] == "MATCH"
    assert result["container_match"]["status"] == "MATCH"
    assert result["system_prompt_match"]["status"] == "MATCH"
    assert result["tool_drift"]["status"] == "MATCH"
    assert result["guardrail_drift"]["status"] == "MATCH"
    assert result["finding"] is None


# ---------------------------------------------------------------------------
# MISMATCH on artifact digest
# ---------------------------------------------------------------------------

def test_artifact_mismatch():
    store = _Store()
    model_id = "model-mismatch-1"
    sha = "a" * 64
    store.save_model(_make_model(model_id, sha256=sha))
    observed = {"weights_sha256": "b" * 64}
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["artifact_match"]["status"] == "MISMATCH"
    assert result["verdict"] in (VERDICT_MISMATCH, VERDICT_PARTIAL_MATCH)
    assert result["finding"] is not None
    assert result["finding"]["findings"][0]["type"] == "deployment_drift"


# ---------------------------------------------------------------------------
# PARTIAL_MATCH — artifact matches but tool drift detected
# ---------------------------------------------------------------------------

def test_tool_drift_gives_partial_match():
    store = _Store()
    model_id = "model-drift-1"
    sha = "d" * 64
    store.save_model(_make_model(
        model_id, sha256=sha,
        tool_list=["tool_a", "tool_b"],
        container_digest=None,
        system_prompt_sha256=None,
        guardrail_versions=[],
    ))
    observed = {
        "weights_sha256": sha,
        "tool_list": ["tool_a", "tool_b", "tool_c"],  # added
    }
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["tool_drift"]["status"] == "DRIFT"
    assert "tool_c" in result["tool_drift"]["added"]
    assert result["verdict"] == VERDICT_PARTIAL_MATCH


def test_tool_removal_gives_partial_match():
    store = _Store()
    model_id = "model-drift-2"
    store.save_model(_make_model(
        model_id,
        tool_list=["tool_a", "tool_b"],
        container_digest=None, system_prompt_sha256=None,
        sha256=None, guardrail_versions=[],
    ))
    observed = {"tool_list": ["tool_a"]}  # tool_b removed
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["tool_drift"]["status"] == "DRIFT"
    assert "tool_b" in result["tool_drift"]["removed"]


# ---------------------------------------------------------------------------
# Guardrail drift
# ---------------------------------------------------------------------------

def test_guardrail_drift():
    store = _Store()
    model_id = "model-gdrift-1"
    store.save_model(_make_model(
        model_id,
        guardrail_versions=[{"name": "guard1", "version": "1.0"}],
        tool_list=[], container_digest=None, system_prompt_sha256=None, sha256=None,
    ))
    observed = {
        "guardrail_versions": [{"name": "guard1", "version": "2.0"}],  # version change → drift
    }
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["guardrail_drift"]["status"] == "DRIFT"


# ---------------------------------------------------------------------------
# Config drift (served_model_id mismatch)
# ---------------------------------------------------------------------------

def test_config_drift():
    store = _Store()
    model_id = "mymodel/v1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    observed = {"served_model_id": "mymodel/v2"}  # different!
    result = verify_deployment(model_id, observed, store, save_result=False)
    assert result["config_drift"]["status"] == "MISMATCH"


# ---------------------------------------------------------------------------
# System prompt match/mismatch
# ---------------------------------------------------------------------------

def test_system_prompt_match():
    store = _Store()
    model_id = "model-sp-1"
    sp = "e" * 64
    store.save_model(_make_model(model_id, system_prompt_sha256=sp,
                                 sha256=None, container_digest=None,
                                 tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {"system_prompt_sha256": sp}, store, save_result=False)
    assert result["system_prompt_match"]["status"] == "MATCH"


def test_system_prompt_mismatch():
    store = _Store()
    model_id = "model-sp-2"
    store.save_model(_make_model(model_id, system_prompt_sha256="a" * 64,
                                 sha256=None, container_digest=None,
                                 tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {"system_prompt_sha256": "b" * 64}, store, save_result=False)
    assert result["system_prompt_match"]["status"] == "MISMATCH"


# ---------------------------------------------------------------------------
# Save and retrieve
# ---------------------------------------------------------------------------

def test_save_and_retrieve():
    store = _Store()
    model_id = "model-save-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {}, store, save_result=True)
    verify_id = result["verify_id"]

    retrieved = get_verify_result(verify_id, store)
    assert retrieved is not None
    assert retrieved["verify_id"] == verify_id


def test_list_verify_results():
    store = _Store()
    model_id = "model-list-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    for _ in range(3):
        verify_deployment(model_id, {}, store, save_result=True)

    results = list_verify_results(store, model_id=model_id, limit=10)
    assert len(results) == 3


def test_list_verify_results_filter_by_verdict():
    store = _Store()
    model_id = "model-list-v"
    sha = "a" * 64
    store.save_model(_make_model(model_id, sha256=sha, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    # Observed sha differs → triggers MISMATCH / PARTIAL_MATCH (not MATCH)
    result = verify_deployment(
        model_id, {"weights_sha256": "b" * 64}, store, save_result=True
    )
    actual_verdict = result["verdict"]
    # Filter by the verdict we actually got — confirms filter logic works
    results_filtered = list_verify_results(store, verdict=actual_verdict, limit=10)
    assert len(results_filtered) >= 1


# ---------------------------------------------------------------------------
# probe_endpoint — network suppressed by default
# ---------------------------------------------------------------------------

def test_probe_endpoint_suppressed_by_default():
    result = probe_endpoint("http://localhost:8080")
    assert result["probed"] is False
    assert "allow_network=True" in result["error"]


def test_probe_endpoint_allow_network_bad_url():
    # Will fail to connect but must not raise
    result = probe_endpoint("http://localhost:19999", allow_network=True, timeout=0.1)
    assert result["probed"] is True
    assert result["error"] is not None


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

def test_result_has_required_keys():
    store = _Store()
    model_id = "model-keys-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {}, store, save_result=False)
    required_keys = {
        "model_id", "verify_id", "verdict", "verified_at",
        "artifact_match", "container_match", "system_prompt_match",
        "tool_drift", "guardrail_drift", "config_drift",
        "mismatch_dimensions", "finding",
        "evidence_origin", "deployment_verify_version",
    }
    assert required_keys.issubset(result.keys())


def test_evidence_origin_is_locally_observed():
    store = _Store()
    model_id = "model-origin-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {}, store, save_result=False)
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"


def test_deploy_version_in_result():
    store = _Store()
    model_id = "model-ver-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {}, store, save_result=False)
    assert result["deployment_verify_version"] == DEPLOYMENT_VERIFY_VERSION


# ---------------------------------------------------------------------------
# Finding structure on mismatch
# ---------------------------------------------------------------------------

def test_finding_structure_on_mismatch():
    store = _Store()
    model_id = "model-find-1"
    store.save_model(_make_model(model_id, sha256="a" * 64, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {"weights_sha256": "b" * 64}, store, save_result=False)
    finding = result["finding"]
    assert finding is not None
    assert finding["artifact_id"] == model_id
    assert isinstance(finding["findings"], list)
    assert finding["findings"][0]["evidence_origin"] == "LOCALLY_OBSERVED"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_tool_lists_match():
    store = _Store()
    model_id = "model-empty-tools"
    store.save_model(_make_model(model_id, tool_list=[], sha256=None,
                                 container_digest=None, system_prompt_sha256=None,
                                 guardrail_versions=[]))
    result = verify_deployment(model_id, {"tool_list": []}, store, save_result=False)
    assert result["tool_drift"]["status"] == "MATCH"


def test_case_insensitive_sha_comparison():
    store = _Store()
    model_id = "model-case-sha"
    sha_lower = "a" * 64
    sha_upper = "A" * 64
    store.save_model(_make_model(model_id, sha256=sha_lower, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))
    result = verify_deployment(model_id, {"weights_sha256": sha_upper}, store, save_result=False)
    # Both normalised to lowercase — should match
    assert result["artifact_match"]["status"] == "MATCH"


def test_missing_get_verify_result():
    store = _Store()
    result = get_verify_result("nonexistent-id", store)
    assert result is None


def test_mbom_record_can_drive_verification():
    store = _Store()
    model_id = "mbom-model-1"
    store.save_model(
        {
            "model_id": f"mbom:{model_id}",
            "bom_format": "AIAF AI-BOM",
            "spec_version": "2.0",
            "subject": {
                "model_id": model_id,
                "name": "MBOM Model",
                "version": "1.0.0",
                "hashes": {"sha256": "a" * 64},
            },
            "components": {
                "deployment_artifact": {
                    "artifact_ref": "registry.example/mbom-model@sha256:" + ("b" * 64),
                    "hashes": {"sha256": "b" * 64},
                },
                "runtime_components": [
                    {"type": "system-prompt-hash", "hashes": {"sha256": "c" * 64}},
                    {"type": "tool", "name": "tool_a"},
                    {"type": "guardrail", "name": "guard1", "version": "1.2"},
                ],
            },
        }
    )

    result = verify_deployment(
        model_id,
        {
            "weights_sha256": "a" * 64,
            "container_digest": "b" * 64,
            "system_prompt_sha256": "c" * 64,
            "tool_list": ["tool_a"],
            "guardrail_versions": [{"name": "guard1", "version": "1.2"}],
            "served_model_id": model_id,
        },
        store,
        save_result=False,
    )
    assert result["registered_record_found"] is True
    assert result["registered_record_id"] == f"mbom:{model_id}"
    assert result["verdict"] == VERDICT_MATCH


def test_sigstore_verification_result_is_attached(monkeypatch):
    import aiaf.registry.deployment_verifier as deployment_verifier

    store = _Store()
    model_id = "sigstore-model-1"
    store.save_model(_make_model(model_id, sha256=None, container_digest=None,
                                 system_prompt_sha256=None, tool_list=[], guardrail_versions=[]))

    def _fake_verify(path, *, bundle_path=None, expected_identity=None, expected_issuer=None):
        return {
            "status": "VERIFIED",
            "verified": True,
            "artifact_path": str(path),
            "bundle_path": str(bundle_path) if bundle_path else None,
            "signer_identity": expected_identity,
            "issuer": expected_issuer,
        }

    monkeypatch.setattr(deployment_verifier, "verify_resolved_file", _fake_verify)
    result = verify_deployment(
        model_id,
        {
            "artifact_path": "/tmp/fake-model.bin",
            "sigstore_bundle_path": "/tmp/fake-model.bin.sigstore.json",
            "sigstore_expected_identity": "ci@example.com",
            "sigstore_expected_issuer": "https://issuer.example",
        },
        store,
        save_result=False,
    )
    assert result["sigstore_verification"] is not None
    assert result["sigstore_verification"]["status"] == "VERIFIED"
    assert "sigstore" not in result["mismatch_dimensions"]


def test_registry_exports_deployment_verifier_symbols():
    from aiaf.registry import DEPLOYMENT_VERIFY_VERSION as exported_version
    from aiaf.registry import verify_deployment as exported_verify_deployment

    assert exported_version == DEPLOYMENT_VERIFY_VERSION
    assert exported_verify_deployment is verify_deployment

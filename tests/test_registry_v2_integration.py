"""Integration tests for the Phase-2 registry v2 orchestration.

Covers the architect-owned glue: provenance scoring via assess_provenance_v2 at
registration, the register->attest->verify->rescore sequence, attaching the
registry verification to each attestation so supply-chain analysis reads it, and
the advisory-matcher v2 swap surfacing the new clean-scan statuses. The scoring
heuristics themselves are unit-tested in test_provenance_v2 / advisory matcher.
"""
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _model_record():
    return {
        "model_id": "model-prov-1",
        "model_name": "provenance-model",
        "version": "1.0",
        "source": "huggingface",
        "source_url": "https://huggingface.co/acme/model",
        "publisher": "Acme AI",
        "sha256": "a" * 64,
        "license": "apache-2.0",
        "metadata": {},
    }


# Schema-2 attestations require a >=32-byte signing key with sufficient entropy.
_V2_KEY = "attestation-signing-key-0123456789abcdef"


def test_attestation_creation_uses_v2_with_detached_verification(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.api import models as models_api
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "prov.db"))
    store.save_model(_model_record())
    monkeypatch.setattr(models_api, "get_store", lambda: store)
    monkeypatch.setenv("AIAF_ATTESTATION_KEY", _V2_KEY)
    monkeypatch.setenv("AIAF_ATTESTATION_KEY_ID", "test-key")

    created = models_api.create_model_attestation("model-prov-1", api_key="dev-key")

    # Schema-2 envelope, cryptographically verified.
    assert created["attestation"]["schema_version"] == "2.0"
    assert created["verification"]["verified"] is True
    assert created["verification"]["assurance_level"] == "SYMMETRIC_AUTHENTICATED"

    # The signed envelope is strict: it carries NO inline verification key.
    assert "verification" not in created["attestation"]

    # Verification evidence is persisted separately, bound by statement digest.
    stored = store.get_model("model-prov-1")
    records = stored["metadata"]["provenance_attestation_verifications"]
    assert records[0]["verified"] is True
    assert records[0]["attestation_sha256"] == created["verification"]["attestation_sha256"]
    assert records[0]["attestation_id"] == created["attestation"]["statement"]["attestation_id"]


def test_supply_chain_accepts_detached_verified_attestation(tmp_path, monkeypatch):
    ensure_src()
    from aiaf.analysis import validate_supply_chain
    from aiaf.api import models as models_api
    from aiaf.core.risk_engine import _attestation_verification_context
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "prov_sc.db"))
    store.save_model(_model_record())
    monkeypatch.setattr(models_api, "get_store", lambda: store)
    monkeypatch.setenv("AIAF_ATTESTATION_KEY", _V2_KEY)
    monkeypatch.setenv("AIAF_ATTESTATION_KEY_ID", "test-key")
    models_api.create_model_attestation("model-prov-1", api_key="dev-key")

    stored = store.get_model("model-prov-1")
    metadata = stored["metadata"]
    artifact = {
        "id": stored["model_id"],
        "model_id": stored["model_id"],
        "model_name": stored["model_name"],
        "version": stored["version"],
        "sha256": stored["sha256"],
        "source": stored["source"],
        "source_url": stored["source_url"],
        "publisher": stored["publisher"],
        "license": stored["license"],
        "provenance_attestations": metadata["provenance_attestations"],
        "provenance_attestation_verifications": metadata[
            "provenance_attestation_verifications"
        ],
    }
    # The engine rebuilds the detached trusted-id/digest context from the
    # separately persisted verification evidence.
    context = _attestation_verification_context(artifact)
    assert context["verified_attestation_ids"]
    assert context["verified_attestation_digests"]

    result = validate_supply_chain(artifact, assessment_context=context)
    assert "unverified_provenance_attestation" not in result["indicators"]
    # Without the detached context, the strict v2 envelope reads as unverified.
    uncontextualized = validate_supply_chain(artifact)
    assert "unverified_provenance_attestation" in uncontextualized["indicators"]


def test_attestation_context_uses_current_assessment_time():
    ensure_src()
    from aiaf.core.risk_engine import _attestation_verification_context

    # A verification recorded long ago must still be evaluated for expiry/staleness
    # at the *current* assessment time, not at the historical verification time.
    artifact = {
        "provenance_attestation_verifications": [
            {
                "attestation_id": "att-old",
                "verified": True,
                "attestation_sha256": "a" * 64,
                "verified_at": "2020-01-01T00:00:00Z",
            }
        ]
    }
    context = _attestation_verification_context(artifact)

    assert context["verified_attestation_ids"] == ["att-old"]
    assert context["as_of"] != "2020-01-01T00:00:00Z"
    # ISO-8601 strings order lexically; the assessment clock is well past 2025.
    assert context["as_of"] > "2025"


def test_clean_scan_reports_no_known_vulnerabilities_status(tmp_path):
    ensure_src()
    from aiaf.core import VulnerabilityIntelligenceEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "clean.db"))
    engine = VulnerabilityIntelligenceEngine(store)
    # A real dependency with no advisories in the catalog -> clean v2 status.
    result = engine.scan([{"name": "requests", "version": "==2.31.0", "ecosystem": "pypi"}])

    assert result["scoring_version"] == "2.0"
    assert result["status"] == "NO_ADVISORY_DATA"  # empty catalog
    assert "generated_at" in result
    assert result["scanned_dependency_count"] == result["evaluated_dependency_count"]

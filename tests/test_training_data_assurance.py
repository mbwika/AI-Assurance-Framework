"""Tests for aiaf.analysis.training_data_assurance."""

from aiaf.analysis.training_data_assurance import (
    TRAINING_DATA_ASSURANCE_VERSION,
    assess_training_data_assurance,
)


class _Store:
    def get_model(self, key):
        return None

    def save_model(self, rec):
        pass

    def list_models(self):
        return []


def _record(meta=None):
    return {"model_id": "model-1", "metadata": meta or {}}


def test_version_and_origin_present():
    result = assess_training_data_assurance(_record(), _Store())
    assert result["training_data_assurance_version"] == TRAINING_DATA_ASSURANCE_VERSION
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"


def test_missing_training_data_reduces_score():
    result = assess_training_data_assurance(_record(), _Store())
    assert result["score"] < 100
    assert any(f["type"] == "training_data_undeclared" for f in result["findings"])


def test_lineage_with_unpinned_repository_is_flagged():
    result = assess_training_data_assurance(
        _record(
            {
                "training_data": "Open web corpus",
                "training_artifacts": [
                    {"name": "dataset-a", "source_url": "https://example.com/datasets/a"}
                ],
                "license": "apache-2.0",
                "privacy_reviewed": True,
                "benchmark_contamination_reviewed": True,
            }
        ),
        _Store(),
    )
    assert any(f["type"] == "training_lineage_unpinned" for f in result["findings"])


def test_well_governed_training_data_scores_higher():
    result = assess_training_data_assurance(
        _record(
            {
                "training_data": "Curated multilingual corpus",
                "training_data_sources": [
                    {"name": "dataset-a", "source_url": "https://example.com/datasets/a", "revision": "abc123"}
                ],
                "license": "apache-2.0",
                "privacy_reviewed": True,
                "benchmark_contamination_reviewed": True,
                "sigstore_verification": {"verified": True},
            }
        ),
        _Store(),
    )
    assert result["score"] >= 75

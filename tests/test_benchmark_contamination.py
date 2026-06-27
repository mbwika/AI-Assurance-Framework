"""Tests for analysis.benchmark_contamination (Phase E)."""

import pytest
from aiaf.analysis.benchmark_contamination import (
    CONTAMINATION_VERSION,
    STATUS_CLEAN, STATUS_SUSPICIOUS, STATUS_CONTAMINATION_LIKELY, STATUS_CONTAMINATION_CONFIRMED,
    ContaminationError,
    check_contamination,
    _z_score,
    _parse_date,
    _worst_status,
    _h1_score_outlier,
    _h2_temporal_contamination,
    _h3_score_inconsistency,
    _h4_claimed_vs_verified_gap,
)
from datetime import timezone, datetime


class _Store:
    def get_model(self, key):
        return None
    def save_model(self, rec):
        pass
    def list_models(self):
        return []


def _rec(meta=None):
    return {"model_id": "m1", "metadata": meta or {}}


def _entry(**kwargs):
    base = {"benchmark_name": "TestBench", "score": 75.0, "population_mean": 60.0, "population_std": 5.0}
    base.update(kwargs)
    return base


# ── Helpers ────────────────────────────────────────────────────────────────────

def test_z_score_basic():
    assert _z_score(65.0, 60.0, 5.0) == pytest.approx(1.0)


def test_z_score_zero_std():
    assert _z_score(65.0, 60.0, 0.0) == 0.0


def test_parse_date_ymd():
    d = _parse_date("2023-06-01")
    assert d is not None
    assert d.year == 2023 and d.month == 6


def test_parse_date_year_only():
    d = _parse_date("2023")
    assert d is not None and d.year == 2023


def test_parse_date_none():
    assert _parse_date(None) is None


def test_parse_date_invalid():
    assert _parse_date("not-a-date") is None


def test_worst_status_order():
    assert _worst_status(STATUS_CLEAN, STATUS_SUSPICIOUS) == STATUS_SUSPICIOUS
    assert _worst_status(STATUS_SUSPICIOUS, STATUS_CONTAMINATION_LIKELY) == STATUS_CONTAMINATION_LIKELY
    assert _worst_status(STATUS_CONTAMINATION_CONFIRMED, STATUS_SUSPICIOUS) == STATUS_CONTAMINATION_CONFIRMED


# ── H1 — score outlier ────────────────────────────────────────────────────────

def test_h1_z_score_above_3_likely():
    # z = (90-60)/5 = 6
    e = _entry(score=90.0, population_mean=60.0, population_std=5.0)
    f = _h1_score_outlier(e)
    assert f is not None
    assert f["contamination_status"] == STATUS_CONTAMINATION_LIKELY
    assert f["z_score"] == pytest.approx(6.0)


def test_h1_z_score_2_to_3_suspicious():
    # z = (70.5-60)/5 = 2.1
    e = _entry(score=70.5, population_mean=60.0, population_std=5.0)
    f = _h1_score_outlier(e)
    assert f is not None
    assert f["contamination_status"] == STATUS_SUSPICIOUS


def test_h1_normal_score_no_finding():
    e = _entry(score=63.0, population_mean=60.0, population_std=5.0)
    assert _h1_score_outlier(e) is None


def test_h1_missing_stats_no_finding():
    assert _h1_score_outlier({"benchmark_name": "X", "score": 90.0}) is None


# ── H2 — temporal contamination ───────────────────────────────────────────────

def test_h2_cutoff_after_release_high_z():
    cutoff = datetime(2024, 1, 1, tzinfo=timezone.utc)
    e = _entry(
        score=90.0, population_mean=60.0, population_std=5.0,
        benchmark_release_date="2023-06-01",
    )
    f = _h2_temporal_contamination(e, cutoff)
    assert f is not None
    assert f["contamination_status"] == STATUS_CONTAMINATION_LIKELY


def test_h2_cutoff_before_release_no_finding():
    cutoff = datetime(2022, 1, 1, tzinfo=timezone.utc)
    e = _entry(
        score=90.0, population_mean=60.0, population_std=5.0,
        benchmark_release_date="2023-06-01",
    )
    assert _h2_temporal_contamination(e, cutoff) is None


def test_h2_none_cutoff_no_finding():
    e = _entry(score=90.0, population_mean=60.0, population_std=5.0,
               benchmark_release_date="2023-06-01")
    assert _h2_temporal_contamination(e, None) is None


def test_h2_high_z_but_no_release_date():
    cutoff = datetime(2024, 1, 1, tzinfo=timezone.utc)
    e = _entry(score=90.0, population_mean=60.0, population_std=5.0)
    assert _h2_temporal_contamination(e, cutoff) is None


# ── H3 — score inconsistency ──────────────────────────────────────────────────

def test_h3_wide_range_triggers():
    entries = [
        {"benchmark_name": "A", "score": 95.0},
        {"benchmark_name": "B", "score": 50.0},
        {"benchmark_name": "C", "score": 60.0},
    ]
    f = _h3_score_inconsistency(entries)
    assert f is not None


def test_h3_narrow_range_ok():
    entries = [
        {"benchmark_name": "A", "score": 75.0},
        {"benchmark_name": "B", "score": 72.0},
        {"benchmark_name": "C", "score": 74.0},
    ]
    assert _h3_score_inconsistency(entries) is None


def test_h3_fewer_than_3_skipped():
    entries = [{"benchmark_name": "A", "score": 95.0}, {"benchmark_name": "B", "score": 10.0}]
    assert _h3_score_inconsistency(entries) is None


# ── H4 — claimed vs verified gap ─────────────────────────────────────────────

def test_h4_large_gap_triggers():
    e = _entry(score=85.0, verified_score=70.0)
    f = _h4_claimed_vs_verified_gap(e)
    assert f is not None
    assert f["gap_percentage_points"] == pytest.approx(15.0)


def test_h4_small_gap_ok():
    e = _entry(score=75.0, verified_score=73.0)
    assert _h4_claimed_vs_verified_gap(e) is None


def test_h4_no_verified_score_skipped():
    e = _entry(score=90.0)
    assert _h4_claimed_vs_verified_gap(e) is None


# ── Integration: check_contamination ─────────────────────────────────────────

def test_clean_scores():
    scores = [
        {"benchmark_name": "A", "score": 63.0, "population_mean": 60.0, "population_std": 5.0},
    ]
    result = check_contamination(_rec(), scores, _Store())
    assert result["status"] == STATUS_CLEAN
    assert result["finding_count"] == 0


def test_outlier_score_flagged():
    scores = [
        {"benchmark_name": "A", "score": 99.0, "population_mean": 60.0, "population_std": 5.0},
    ]
    result = check_contamination(_rec(), scores, _Store())
    assert result["status"] == STATUS_CONTAMINATION_LIKELY


def test_training_cutoff_from_metadata():
    rec = _rec({"training_cutoff": "2024-01-01"})
    scores = [
        {
            "benchmark_name": "A", "score": 90.0, "population_mean": 60.0, "population_std": 5.0,
            "benchmark_release_date": "2023-06-01",
        }
    ]
    result = check_contamination(rec, scores, _Store())
    assert result["status"] == STATUS_CONTAMINATION_LIKELY
    types = [f["type"] for f in result["findings"]]
    assert "temporal_contamination_risk" in types


def test_benchmark_count_in_result():
    scores = [_entry(score=60.0), _entry(benchmark_name="B", score=61.0)]
    result = check_contamination(_rec(), scores, _Store())
    assert result["benchmark_count"] == 2


def test_invalid_benchmark_scores_type():
    with pytest.raises(ContaminationError):
        check_contamination(_rec(), "not a list", _Store())


def test_model_id_override():
    result = check_contamination(_rec(), [], _Store(), model_id="custom-id")
    assert result["model_id"] == "custom-id"


def test_version_and_origin():
    result = check_contamination(_rec(), [], _Store())
    assert result["contamination_version"] == CONTAMINATION_VERSION
    assert result["evidence_origin"] == "LOCALLY_OBSERVED"

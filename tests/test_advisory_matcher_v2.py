import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import aiaf.registry.advisory_matcher_v2 as matcher  # noqa: E402
from aiaf.registry.advisory_matcher_v2 import (  # noqa: E402
    ADVISORY_MATCHER_SCORING_VERSION,
    match_dependency_advisories_v2,
)


def _advisory(
    advisory_id="OSV-1",
    *,
    ecosystem="PyPI",
    package="requests",
    events=None,
    versions=None,
    aliases=None,
    severity="HIGH",
):
    return {
        "advisory_id": advisory_id,
        "ecosystem": ecosystem,
        "package_name": package,
        "aliases": aliases or [],
        "severity": severity,
        "summary": "Test vulnerability",
        "affected_versions": versions or [],
        "affected_ranges": (
            [{"type": "ECOSYSTEM", "events": events}]
            if events is not None
            else []
        ),
        "references": [
            {"type": "ADVISORY", "url": f"https://example.test/{advisory_id}"}
        ],
        "source": "test-feed",
    }


def _scan(dependencies, advisories, context=None):
    return match_dependency_advisories_v2(dependencies, advisories, context)


def _diagnostics(result):
    return {item["indicator"] for item in result["diagnostics"]}


def test_exact_pypi_range_is_versioned_deterministic_and_json_safe():
    advisory = _advisory(
        events=[{"introduced": "2.0.0"}, {"fixed": "2.32.0"}]
    )

    first = _scan(["requests==2.31.0"], [advisory])
    second = _scan(["requests==2.31.0"], [advisory])

    assert first == second
    assert first["scoring_version"] == ADVISORY_MATCHER_SCORING_VERSION == "2.0"
    assert first["status"] == "VULNERABILITIES_FOUND"
    assert first["assessment_complete"] is True
    assert first["matches"][0]["fixed_versions"] == ["2.32.0"]
    assert json.loads(json.dumps(first, sort_keys=True)) == first


def test_fixed_boundary_is_exclusive_and_last_affected_is_inclusive():
    fixed = _advisory(
        events=[{"introduced": "1.0"}, {"fixed": "2.0"}]
    )
    last = _advisory(
        "OSV-2",
        events=[{"introduced": "1.0"}, {"last_affected": "2.0"}],
    )

    assert _scan(["requests==2.0"], [fixed])["match_count"] == 0
    assert _scan(["requests==2.0"], [last])["match_count"] == 1


def test_limit_boundary_is_exclusive():
    advisory = _advisory(
        events=[{"introduced": "1.0"}, {"limit": "2.0"}]
    )

    assert _scan(["requests==1.9"], [advisory])["match_count"] == 1
    assert _scan(["requests==2.0"], [advisory])["match_count"] == 0


def test_disjoint_affected_intervals_are_evaluated_independently():
    advisory = _advisory(
        events=[
            {"introduced": "1.0"},
            {"fixed": "1.5"},
            {"introduced": "2.0"},
            {"fixed": "2.5"},
        ]
    )

    assert _scan(["requests==1.4"], [advisory])["match_count"] == 1
    assert _scan(["requests==1.7"], [advisory])["match_count"] == 0
    assert _scan(["requests==2.4"], [advisory])["match_count"] == 1


def test_explicit_affected_versions_match_without_ranges():
    advisory = _advisory(versions=["1.0", "2.0"])

    vulnerable = _scan(["requests==2.0"], [advisory])
    unaffected = _scan(["requests==2.1"], [advisory])

    assert vulnerable["match_count"] == 1
    assert unaffected["status"] == "NO_KNOWN_VULNERABILITIES"


def test_malformed_and_unsupported_ranges_are_indeterminate_not_safe():
    ambiguous = _advisory(
        events=[{"introduced": "1.0", "fixed": "2.0"}]
    )
    git_range = _advisory("OSV-GIT")
    git_range["affected_ranges"] = [
        {"type": "GIT", "events": [{"introduced": "abc"}]}
    ]

    ambiguous_result = _scan(["requests==1.5"], [ambiguous])
    git_result = _scan(["requests==1.5"], [git_range])

    assert ambiguous_result["status"] == "PARTIAL"
    assert ambiguous_result["assessment_complete"] is False
    assert ambiguous_result["coverage"]["indeterminate_evaluation_count"] == 1
    assert git_result["status"] == "PARTIAL"
    assert git_result["indeterminate_evaluations"][0]["reasons"] == [
        "git_range_requires_commit_identity"
    ]


def test_range_closure_without_introduction_is_indeterminate():
    advisory = _advisory(events=[{"fixed": "2.0"}])

    result = _scan(["requests==1.5"], [advisory])

    assert result["status"] == "PARTIAL"
    assert result["indeterminate_evaluations"][0]["reasons"] == [
        "range_closure_without_introduction"
    ]


def test_inverted_and_out_of_order_ranges_are_indeterminate_not_clean():
    inverted = _advisory(
        events=[{"introduced": "2.0"}, {"fixed": "1.0"}]
    )
    out_of_order = _advisory(
        "OSV-2",
        events=[
            {"introduced": "1.0"},
            {"fixed": "2.0"},
            {"introduced": "1.5"},
            {"fixed": "3.0"},
        ],
    )

    inverted_result = _scan(["requests==1.5"], [inverted])
    order_result = _scan(["requests==2.5"], [out_of_order])

    assert inverted_result["status"] == "PARTIAL"
    assert inverted_result["indeterminate_evaluations"][0]["reasons"] == [
        "inverted_range_interval"
    ]
    assert order_result["status"] == "PARTIAL"
    assert order_result["indeterminate_evaluations"][0]["reasons"] == [
        "out_of_order_range_intervals"
    ]


def test_unknown_range_event_fields_are_not_silently_ignored():
    advisory = _advisory(
        events=[
            {"introduced": "1.0", "vendor_extension": "trusted"},
            {"fixed": "2.0"},
        ]
    )

    result = _scan(["requests==2.5"], [advisory])

    assert result["status"] == "PARTIAL"
    assert result["indeterminate_evaluations"][0]["reasons"] == [
        "unexpected_range_event_fields"
    ]


def test_npm_semver_prerelease_ordering_and_build_metadata():
    advisory = _advisory(
        ecosystem="npm",
        package="@acme/widget",
        events=[
            {"introduced": "1.2.3-beta.1"},
            {"fixed": "1.2.3"},
        ],
    )

    prerelease = _scan(
        [{"name": "@acme/widget", "version": "1.2.3-beta.2", "ecosystem": "npm"}],
        [advisory],
    )
    fixed = _scan(
        [{"name": "@acme/widget", "version": "v1.2.3+build.7", "ecosystem": "npm"}],
        [advisory],
    )

    assert prerelease["match_count"] == 1
    assert fixed["match_count"] == 0


def test_npm_string_coordinates_support_scoped_packages():
    advisory = _advisory(
        ecosystem="npm",
        package="@acme/widget",
        versions=["1.2.3"],
    )

    result = _scan(
        ["@acme/widget@1.2.3"],
        [advisory],
        {"default_ecosystem": "npm"},
    )

    assert result["match_count"] == 1


def test_false_environment_marker_skips_dependency_deterministically():
    advisory = _advisory(versions=["2.31.0"])
    context = {"marker_environment": {"python_version": "3.12"}}

    result = _scan(
        ['requests==2.31.0; python_version < "3.11"'], [advisory], context
    )

    assert result["status"] == "NO_APPLICABLE_DEPENDENCIES"
    assert result["skipped_dependency_count"] == 1
    assert result["match_count"] == 0
    assert result["assessment_complete"] is True


def test_unknown_marker_applicability_is_scanned_conservatively():
    advisory = _advisory(versions=["2.31.0"])

    result = _scan(
        ['requests==2.31.0; python_version < "3.11"'], [advisory]
    )

    assert result["status"] == "VULNERABILITIES_FOUND"
    assert result["match_count"] == 1
    assert result["assessment_complete"] is False
    assert result["coverage"]["marker_applicability_unknown"] == 1
    assert result["unresolved_dependencies"][0]["scanned_conservatively"] is True


def test_ranges_and_direct_references_are_unresolved_without_false_assurance():
    result = _scan(
        ["requests>=2.0", "widget @ https://example.test/widget.whl"],
        [_advisory(versions=["2.31.0"])],
    )

    assert result["status"] == "PARTIAL"
    assert result["evaluated_dependency_count"] == 0
    assert {item["reason"] for item in result["unresolved_dependencies"]} == {
        "exact_version_required",
        "direct_reference_has_no_verified_release_version",
    }


def test_pypi_names_are_canonicalized_for_matching():
    advisory = _advisory(package="My_Package", versions=["1.0"])

    result = _scan(["my.package==1.0"], [advisory])

    assert result["match_count"] == 1
    assert result["matches"][0]["package_name"] == "my-package"


def test_alias_connected_advisories_are_merged_and_highest_severity_wins():
    osv = _advisory(
        "OSV-1", versions=["1.0"], aliases=["CVE-2026-0001"], severity="HIGH"
    )
    ghsa = _advisory(
        "GHSA-AAAA-BBBB-CCCC",
        versions=["1.0"],
        aliases=["CVE-2026-0001"],
        severity="CRITICAL",
    )

    result = _scan(["requests==1.0"], [osv, ghsa])

    assert result["raw_match_count"] == 2
    assert result["match_count"] == 1
    assert result["matches"][0]["advisory_id"] == "CVE-2026-0001"
    assert result["matches"][0]["severity"] == "CRITICAL"
    assert result["matches"][0]["corroborating_record_count"] == 2
    assert result["by_severity"] == {"CRITICAL": 1}


def test_placeholder_alias_does_not_merge_unrelated_advisories():
    first = _advisory(
        "OSV-ONE", versions=["1.0"], aliases=["UNKNOWN"], severity="HIGH"
    )
    second = _advisory(
        "OSV-TWO", versions=["1.0"], aliases=["UNKNOWN"], severity="MEDIUM"
    )

    result = _scan(["requests==1.0"], [first, second])

    assert result["raw_match_count"] == 2
    assert result["match_count"] == 2
    assert {item["advisory_id"] for item in result["matches"]} == {
        "OSV-ONE",
        "OSV-TWO",
    }


def test_withdrawn_advisories_are_excluded():
    advisory = _advisory(versions=["1.0"])
    advisory["withdrawn_at"] = "2026-06-01T00:00:00Z"

    result = _scan(["requests==1.0"], [advisory])

    assert result["status"] == "NO_ADVISORY_DATA"
    assert result["match_count"] == 0
    assert result["catalog"]["withdrawn_record_count"] == 1
    assert result["assessment_complete"] is False


def test_invalid_catalog_records_do_not_hide_valid_matches():
    result = _scan(
        ["requests==1.0"],
        [None, {"advisory_id": "broken"}, _advisory(versions=["1.0"])],
    )

    assert result["status"] == "VULNERABILITIES_FOUND"
    assert result["match_count"] == 1
    assert result["assessment_complete"] is False
    assert result["catalog"]["invalid_record_count"] == 2
    assert "invalid_advisory_record" in _diagnostics(result)


def test_duplicate_coordinates_are_deduplicated_but_conflicts_are_partial():
    duplicate = _scan(
        ["requests==1.0", "Requests==1.0"], [_advisory(versions=["1.0"])]
    )
    conflict = _scan(
        ["requests==1.0", "requests==2.0"], [_advisory(versions=["1.0"])]
    )

    assert duplicate["duplicate_coordinate_count"] == 1
    assert duplicate["unique_dependency_count"] == 1
    assert duplicate["raw_match_count"] == 1
    assert conflict["assessment_complete"] is False
    assert conflict["conflicting_dependency_versions"][0]["versions"] == [
        "1.0",
        "2.0",
    ]
    assert "conflicting_dependency_versions" in _diagnostics(conflict)


def test_dependency_and_candidate_bounds_fail_closed(monkeypatch):
    monkeypatch.setattr(matcher, "_MAX_DEPENDENCIES", 2)
    bounded = _scan(
        ["a==1.0", "b==1.0", "c==1.0"],
        [_advisory(package="a", versions=["1.0"])],
    )

    monkeypatch.setattr(matcher, "_MAX_CANDIDATE_EVALUATIONS", 1)
    first = _advisory("OSV-SAFE", versions=["9.0"])
    second = _advisory("OSV-HIDDEN", versions=["1.0"])
    candidate_limited = _scan(["requests==1.0"], [first, second])

    assert bounded["dependency_count"] == 2
    assert bounded["assessment_complete"] is False
    assert "dependency_inventory_truncated" in _diagnostics(bounded)
    assert candidate_limited["status"] == "PARTIAL"
    assert candidate_limited["match_count"] == 0
    assert "candidate_evaluation_limit_exceeded" in _diagnostics(candidate_limited)


def test_no_candidate_is_reported_as_no_known_vulnerability_with_coverage_gap():
    result = _scan(
        ["numpy==2.0.0"], [_advisory(package="requests", versions=["1.0"])]
    )

    assert result["status"] == "NO_KNOWN_VULNERABILITIES"
    assert result["assessment_complete"] is True
    assert result["coverage"]["dependencies_without_candidates"] == 1


def test_malformed_roots_and_unsupported_ecosystems_fail_closed():
    malformed_dependencies = _scan(42, [])
    malformed_advisories = _scan(["requests==1.0"], 42)
    unsupported = _scan(
        [{"name": "crate", "version": "1.0.0", "ecosystem": "cargo"}], []
    )

    assert malformed_dependencies["status"] == "PARTIAL"
    assert malformed_dependencies["assessment_complete"] is False
    assert "dependency_inventory_malformed" in _diagnostics(malformed_dependencies)
    assert malformed_advisories["status"] == "NO_ADVISORY_DATA"
    assert malformed_advisories["assessment_complete"] is False
    assert "advisory_catalog_malformed" in _diagnostics(malformed_advisories)
    assert unsupported["status"] == "PARTIAL"
    assert unsupported["unresolved_dependencies"][0]["reason"] == "unsupported_ecosystem"

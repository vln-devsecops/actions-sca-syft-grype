import json

import pytest

import apply_policy
from apply_policy import (
    ANNOTATION_LEVEL,
    FULL_SEVERITIES,
    SEVERITY_ORDER,
    UNKNOWN_SEVERITY_FALLBACK,
    batch,
    build_summary,
    counts_by_severity,
    create_check_run,
    main,
    repo_relative_path,
    severity_at_least,
    severity_for_comparison,
    severity_of,
    to_annotation,
)


def make_finding(**extra):
    return {
        "id": "CVE-1", "package": "lodash", "version": "4.17.11", "path": "package-lock.json",
        "severity": "Critical", "description": "Prototype pollution", "fixedIn": [], "fixState": "unknown",
        **extra,
    }


@pytest.mark.parametrize(
    "severity,threshold,expected",
    [
        ("High", "High", True),
        ("Critical", "High", True),
        ("Medium", "High", False),
        ("Negligible", "High", False),
        ("Low", "Low", True),
        ("Critical", "Critical", True),
    ],
)
def test_severity_at_least(severity, threshold, expected):
    assert severity_at_least(severity, threshold) is expected


def test_severity_order_is_low_to_high_and_excludes_unknown():
    assert SEVERITY_ORDER == ["Negligible", "Low", "Medium", "High", "Critical"]
    assert "Unknown" not in SEVERITY_ORDER


def test_full_severities_includes_unknown_last():
    assert FULL_SEVERITIES[-1] == "Unknown"
    assert set(FULL_SEVERITIES) == set(SEVERITY_ORDER) | {"Unknown"}


def test_severity_for_comparison_passes_through_ordered_values():
    assert severity_for_comparison("Medium") == "Medium"


def test_severity_for_comparison_fails_closed_on_unknown():
    assert severity_for_comparison("Unknown") == UNKNOWN_SEVERITY_FALLBACK


def test_severity_for_comparison_fails_closed_on_garbage():
    assert severity_for_comparison("not-a-real-severity") == UNKNOWN_SEVERITY_FALLBACK
    assert severity_for_comparison(None) == UNKNOWN_SEVERITY_FALLBACK


def test_severity_at_least_fails_closed_on_unknown_severity():
    """An unscored ("Unknown") vulnerability must never silently pass a
    High-threshold gate just because "Unknown" isn't in SEVERITY_ORDER -
    this used to be a bare ValueError from SEVERITY_ORDER.index(None)."""
    assert severity_at_least("Unknown", "High") is True
    assert severity_at_least("Unknown", "Critical") is False  # High < Critical


def test_severity_of_returns_valid_severity_unchanged():
    assert severity_of({"severity": "Medium"}) == "Medium"


def test_severity_of_returns_unknown_verbatim():
    """"Unknown" is a real Grype value (unscored CVSS), not a data-quality
    fallback - severity_of() must report it as-is, not silently relabel it."""
    assert severity_of({"severity": "Unknown"}) == "Unknown"


@pytest.mark.parametrize("bad_severity", [None, "", "NOT_A_REAL_SEVERITY"])
def test_severity_of_falls_back_to_unknown_on_garbage(bad_severity):
    assert severity_of({"severity": bad_severity}) == "Unknown"


def test_severity_of_falls_back_when_severity_key_missing():
    assert severity_of({}) == "Unknown"


def test_to_annotation_shapes_finding_correctly():
    finding = make_finding(severity="Critical", description="bad", fixedIn=["4.17.12"])
    ann = to_annotation(finding)
    assert ann["path"] == "package-lock.json"
    assert ann["start_line"] == 1
    assert ann["end_line"] == 1
    assert ann["annotation_level"] == "failure"
    assert ann["title"] == "CVE-1 in lodash@4.17.11 (Critical)"
    assert "bad" in ann["message"]
    assert "Fixed in: 4.17.12" in ann["message"]


@pytest.mark.parametrize(
    "path,project_base_dir,expected",
    [
        ("package-lock.json", ".", "package-lock.json"),
        ("package-lock.json", "", "package-lock.json"),
        ("package-lock.json", None, "package-lock.json"),
        ("package-lock.json", "fixtures", "fixtures/package-lock.json"),
        ("js/package-lock.json", "fixtures", "fixtures/js/package-lock.json"),
        ("package-lock.json", "./fixtures", "fixtures/package-lock.json"),
        ("package-lock.json", "fixtures/", "fixtures/package-lock.json"),
        ("package-lock.json", "/fixtures/", "fixtures/package-lock.json"),
    ],
)
def test_repo_relative_path(path, project_base_dir, expected):
    assert repo_relative_path(path, project_base_dir) == expected


def test_to_annotation_reroots_path_under_a_non_root_project_base_dir():
    """A finding's `path` is relative to project-base-dir (see
    parse_findings.py), but a Check Run annotation's `path` must be
    relative to the repo root or GitHub silently fails to attach it to the
    right file in the PR diff - exactly this repo's own ci.yml
    configuration (project-base-dir: fixtures)."""
    finding = make_finding(path="js/package-lock.json")
    ann = to_annotation(finding, project_base_dir="fixtures")
    assert ann["path"] == "fixtures/js/package-lock.json"


def test_to_annotation_default_project_base_dir_leaves_path_unchanged():
    finding = make_finding(path="package-lock.json")
    assert to_annotation(finding)["path"] == "package-lock.json"


def test_to_annotation_notes_no_fix_available():
    finding = make_finding(fixedIn=[], fixState="not-fixed", description="bad")
    ann = to_annotation(finding)
    assert "No fix currently available (not-fixed)" in ann["message"]


def test_to_annotation_prefers_fixed_versions_over_no_fix_note():
    finding = make_finding(fixedIn=["1.2.3"], fixState="fixed")
    ann = to_annotation(finding)
    assert "Fixed in: 1.2.3" in ann["message"]
    assert "No fix currently available" not in ann["message"]


def test_to_annotation_fails_closed_on_unrecognized_severity():
    """This would otherwise be a bare KeyError from ANNOTATION_LEVEL[None]."""
    finding = make_finding(severity=None)
    ann = to_annotation(finding)
    assert "(Unknown)" in ann["title"]
    assert ann["annotation_level"] == ANNOTATION_LEVEL["Unknown"]


@pytest.mark.parametrize(
    "severity,level",
    [
        ("Critical", "failure"), ("High", "failure"), ("Medium", "warning"),
        ("Low", "notice"), ("Negligible", "notice"), ("Unknown", "warning"),
    ],
)
def test_to_annotation_level_matches_severity(severity, level):
    finding = make_finding(severity=severity)
    assert to_annotation(finding)["annotation_level"] == level


def test_counts_by_severity_includes_zero_counts_for_absent_severities():
    findings = [make_finding(severity="High"), make_finding(severity="High"), make_finding(severity="Low")]
    counts = counts_by_severity(findings)
    assert counts == {"Critical": 0, "High": 2, "Medium": 0, "Low": 1, "Negligible": 0, "Unknown": 0}


def test_counts_by_severity_empty_input():
    assert counts_by_severity([]) == {s: 0 for s in FULL_SEVERITIES}


def test_counts_by_severity_never_silently_drops_an_unrecognized_severity():
    counts = counts_by_severity([make_finding(severity=None)])
    assert None not in counts
    assert sum(counts.values()) == 1
    assert counts["Unknown"] == 1
    json.dumps(counts, sort_keys=True)  # must not raise


def test_build_summary_blocking_enabled_reports_count():
    findings = [make_finding(severity="Critical"), make_finding(severity="Low")]
    blocking_findings = [findings[0]]
    summary = build_summary(findings, blocking_findings, "High", True)
    assert "2 new vulnerability finding(s)" in summary
    assert "1 new finding(s) meet or exceed it" in summary
    assert "**High**" in summary


def test_build_summary_blocking_disabled_says_so():
    summary = build_summary([], [], "High", False)
    assert "Blocking is disabled" in summary


@pytest.mark.parametrize(
    "count,size,expected_lengths",
    [
        (0, 50, []),
        (10, 50, [10]),
        (50, 50, [50]),
        (51, 50, [50, 1]),
        (120, 50, [50, 50, 20]),
    ],
)
def test_batch_splits_into_chunks_of_at_most_size(count, size, expected_lengths):
    items = list(range(count))
    result = batch(items, size)
    assert [len(chunk) for chunk in result] == expected_lengths
    assert [x for chunk in result for x in chunk] == items


def test_main_writes_result_out_even_when_check_run_publication_fails(tmp_path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    result_path = tmp_path / "result.json"
    findings_path.write_text(json.dumps([make_finding(severity="Low")]))

    def boom(*args, **kwargs):
        raise SystemExit("GitHub API POST .../check-runs failed: HTTP 403")

    monkeypatch.setattr(apply_policy, "create_check_run", boom)
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        [
            "apply_policy.py",
            "--findings", str(findings_path),
            "--repo", "o/r",
            "--sha", "abc123",
            "--result-out", str(result_path),
        ],
    )

    with pytest.raises(SystemExit):
        main()  # create_check_run's own SystemExit propagates unchanged

    result = json.loads(result_path.read_text())
    assert result["check_run_url"] is None
    assert result["total_new_findings"] == 1


def test_main_result_out_gets_the_check_run_url_on_success(tmp_path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    result_path = tmp_path / "result.json"
    findings_path.write_text(json.dumps([]))

    monkeypatch.setattr(
        apply_policy, "create_check_run",
        lambda *a, **k: {"html_url": "https://example.com/run/1"},
    )
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        [
            "apply_policy.py",
            "--findings", str(findings_path),
            "--repo", "o/r",
            "--sha", "abc123",
            "--result-out", str(result_path),
        ],
    )

    main()

    result = json.loads(result_path.read_text())
    assert result["check_run_url"] == "https://example.com/run/1"


def test_create_check_run_returns_none_when_creation_is_forbidden(monkeypatch):
    """A fork PR's read-only token means the creating POST 403s - gh_api
    already surfaces that as None; create_check_run must propagate it as
    None too rather than crashing on check_run["id"], and must not attempt
    any PATCH follow-up calls with nothing to patch."""
    patch_calls = []
    monkeypatch.setattr(
        apply_policy, "gh_api",
        lambda method, url, token, body=None, allow_forbidden=False: (
            patch_calls.append(method) if method == "PATCH" else None
        ),
    )
    result = create_check_run(
        "o/r", "token", "sha", "check-name", "success", "summary",
        [{"path": "a", "start_line": 1, "end_line": 1, "annotation_level": "notice", "title": "t", "message": "m"}],
    )
    assert result is None
    assert patch_calls == []


def test_main_handles_a_completely_unpublishable_check_run(tmp_path, monkeypatch):
    """End-to-end fork-PR simulation: create_check_run returns None. main()
    must still write --result-out with check_run_url: None instead of
    crashing on check_run.get(...), and still blocks per policy."""
    findings_path = tmp_path / "findings.json"
    result_path = tmp_path / "result.json"
    findings_path.write_text(json.dumps([make_finding(severity="Critical")]))

    monkeypatch.setattr(apply_policy, "create_check_run", lambda *a, **k: None)
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        [
            "apply_policy.py",
            "--findings", str(findings_path),
            "--repo", "o/r",
            "--sha", "abc123",
            "--result-out", str(result_path),
        ],
    )

    with pytest.raises(SystemExit):
        main()  # Critical >= default High threshold - blocks

    result = json.loads(result_path.read_text())
    assert result["check_run_url"] is None
    assert result["blocked"] is True

from post_pr_comment import MARKER, render_body


def make_result(blocked=False, total_new_findings=0, threshold="High", blocking_enabled=True, check_run_url=None, by_severity=None):
    return {
        "blocked": blocked,
        "total_new_findings": total_new_findings,
        "threshold": threshold,
        "blocking_enabled": blocking_enabled,
        "check_run_url": check_run_url,
        "by_severity": by_severity or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0},
    }


def test_render_body_reports_clean_pr():
    body = render_body(make_result(), "tier a: artifact for merge-base abc123", {}, {})
    assert "No new vulnerabilities introduced by this PR" in body
    assert ":white_check_mark:" in body


def test_render_body_reports_blocked_pr():
    result = make_result(blocked=True, total_new_findings=1, by_severity={"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0})
    body = render_body(result, "tier a: artifact for merge-base abc123", {}, {})
    assert "**Blocked**" in body
    assert "`High`" in body


def test_render_body_reports_not_blocked_with_findings():
    result = make_result(blocked=False, total_new_findings=1, by_severity={"Critical": 0, "High": 0, "Medium": 0, "Low": 1, "Negligible": 0, "Unknown": 0})
    body = render_body(result, "fallback: no artifact found, scanning target branch HEAD live in this job", {}, {})
    assert "Not blocked" in body


def test_render_body_includes_baseline_added_removed_table():
    baseline_counts = {"Critical": 2, "High": 1, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    added_counts = {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    removed_counts = {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    result = make_result(total_new_findings=1, by_severity=added_counts)
    body = render_body(result, "tier a: artifact for merge-base abc123", baseline_counts, removed_counts)
    assert "| Critical | 2 | 1 | 0 |" in body
    assert "| High | 1 | 0 | 1 |" in body


def test_render_body_includes_unknown_severity_row():
    body = render_body(make_result(), "tier a: artifact for merge-base abc123", {}, {})
    assert "| Unknown | 0 | 0 | 0 |" in body


def test_render_body_includes_baseline_tier_and_policy_state():
    body = render_body(make_result(blocking_enabled=False), "tier b: artifact for target branch HEAD def456", {}, {})
    assert "tier b: artifact for target branch HEAD def456" in body
    assert "**disabled**" in body


def test_render_body_links_check_run_when_present():
    body = render_body(make_result(check_run_url="https://example.com/run/1"), "tier a: artifact for merge-base abc123", {}, {})
    assert "[View annotated findings](https://example.com/run/1)" in body


def test_render_body_omits_check_run_link_when_absent():
    body = render_body(make_result(check_run_url=None), "tier a: artifact for merge-base abc123", {}, {})
    assert "View annotated findings" not in body


def test_render_body_includes_marker_for_idempotent_updates():
    body = render_body(make_result(), "tier a: artifact for merge-base abc123", {}, {})
    assert body.rstrip().endswith(MARKER)

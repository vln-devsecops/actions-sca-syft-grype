import json

import report_mainline_findings as rmf
from report_mainline_findings import (
    build_comment_body,
    build_issue_body,
    main,
    marker_for,
    render_findings_table,
)


def make_finding(**extra):
    return {
        "id": "CVE-2024-9999", "severity": "High", "package": "requests", "version": "2.19.1",
        "path": "requirements.txt", "dataSource": "https://example.org/CVE-2024-9999",
        **extra,
    }


def test_marker_for_is_scoped_per_project_key():
    """Two projects scanned by the same repo must not collapse into one
    tracking issue - marker_for()'s whole job is keeping them apart."""
    assert marker_for("service-a") != marker_for("service-b")
    assert "service-a" in marker_for("service-a")


def test_render_findings_table_includes_columns_and_link():
    table = render_findings_table([make_finding()])
    assert "| Severity | Package | Installed | Vulnerability | Location |" in table
    assert "[CVE-2024-9999](https://example.org/CVE-2024-9999)" in table
    assert "`requirements.txt`" in table


def test_render_findings_table_sorts_worst_first():
    findings = [make_finding(id="CVE-low", severity="Low"), make_finding(id="CVE-crit", severity="Critical")]
    table = render_findings_table(findings)
    assert table.index("CVE-crit") < table.index("CVE-low")


def test_render_findings_table_handles_missing_data_source():
    table = render_findings_table([make_finding(dataSource=None)])
    assert "CVE-2024-9999" in table
    assert "[CVE-2024-9999](" not in table


def test_build_issue_body_includes_count_severity_summary_table_and_marker():
    body = build_issue_body([make_finding()], "myproj", "https://github.com/o/r/actions/runs/1")
    assert "1 new" in body
    assert "1 High" in body
    assert "myproj" in body
    assert "requests" in body
    assert "Detected by: https://github.com/o/r/actions/runs/1" in body
    assert marker_for("myproj") in body


def test_build_issue_body_omits_run_link_when_absent():
    body = build_issue_body([make_finding()], "myproj", "")
    assert "Detected by:" not in body


def test_build_comment_body_has_no_marker_but_has_table():
    body = build_comment_body([make_finding()], "https://github.com/o/r/actions/runs/2")
    assert "more new finding(s)" in body
    assert "requests" in body
    assert marker_for("myproj") not in body


def test_main_is_a_noop_when_no_new_findings(tmp_path, monkeypatch, capsys):
    findings_path = tmp_path / "new.json"
    findings_path.write_text(json.dumps([]))

    calls = []
    monkeypatch.setattr(rmf, "find_open_issue", lambda *a, **k: calls.append("find_open_issue"))
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        ["report_mainline_findings.py", "--repo", "o/r", "--new-findings", str(findings_path), "--project-key", "myproj"],
    )

    main()

    assert calls == []  # no API calls at all when there's nothing new
    captured = capsys.readouterr()
    assert "nothing to report" in captured.out


def test_main_creates_issue_when_none_exists(tmp_path, monkeypatch):
    findings_path = tmp_path / "new.json"
    findings_path.write_text(json.dumps([make_finding()]))

    created = {}
    monkeypatch.setattr(rmf, "find_open_issue", lambda *a, **k: None)

    def fake_create_issue(owner, repo, title, body, labels, token):
        created["title"] = title
        created["labels"] = labels
        created["body"] = body
        return {"number": 42}

    monkeypatch.setattr(rmf, "create_issue", fake_create_issue)
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        [
            "report_mainline_findings.py", "--repo", "o/r", "--new-findings", str(findings_path),
            "--project-key", "myproj", "--labels", "security, sca-alert",
        ],
    )

    main()

    assert created["title"] == "SCA: new vulnerabilities detected on myproj"
    assert created["labels"] == ["security", "sca-alert"]
    assert marker_for("myproj") in created["body"]


def test_main_comments_on_existing_open_issue(tmp_path, monkeypatch):
    findings_path = tmp_path / "new.json"
    findings_path.write_text(json.dumps([make_finding()]))

    monkeypatch.setattr(rmf, "find_open_issue", lambda *a, **k: {"number": 7, "state": "open"})
    reopen_calls = []
    monkeypatch.setattr(rmf, "reopen_issue_if_closed", lambda *a, **k: reopen_calls.append(1))
    comments = []
    monkeypatch.setattr(rmf, "add_comment", lambda owner, repo, num, body, token: comments.append((num, body)))
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setattr(
        "sys.argv",
        ["report_mainline_findings.py", "--repo", "o/r", "--new-findings", str(findings_path), "--project-key", "myproj"],
    )

    main()

    assert len(comments) == 1
    assert comments[0][0] == 7
    assert "requests" in comments[0][1]
    assert len(reopen_calls) == 1

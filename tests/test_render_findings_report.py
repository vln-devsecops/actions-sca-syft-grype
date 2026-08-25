from render_findings_report import _escape_for_table_cell, _sort_key, _vulnerability_cell, main, render_report


def make_finding(**extra):
    return {
        "id": "CVE-2019-10744", "severity": "Critical", "package": "lodash", "version": "4.17.11",
        "path": "package-lock.json", "fixedIn": ["4.17.12"], "fixState": "fixed",
        "dataSource": "https://example.org/CVE-2019-10744", "relatedCve": None,
        "description": "Prototype pollution",
        **extra,
    }


def test_render_report_no_findings():
    report = render_report([], "myproj")
    assert "No findings." in report
    assert "myproj" in report


def test_render_report_includes_count_and_columns():
    report = render_report([make_finding()], "myproj")
    assert "1 finding(s)." in report
    assert "| Severity | Package | Installed | Fixed In | Vulnerability | Location |" in report
    assert "| Critical | lodash | 4.17.11 | 4.17.12 |" in report
    assert "`package-lock.json`" in report


def test_render_report_states_production_only_scope_by_default():
    report = render_report([make_finding()], "myproj")
    assert "Scope: production dependencies only (development dependencies excluded)." in report


def test_render_report_states_scope_when_dev_dependencies_included():
    report = render_report([make_finding()], "myproj", include_dev_dependencies=True)
    assert "Scope: production and development dependencies." in report


def test_render_report_states_scope_even_with_no_findings():
    report = render_report([], "myproj")
    assert "Scope: production dependencies only (development dependencies excluded)." in report


def test_render_report_links_vulnerability_id_to_data_source():
    report = render_report([make_finding()], "myproj")
    assert "[CVE-2019-10744](https://example.org/CVE-2019-10744)" in report


def test_render_report_falls_back_to_plain_id_without_data_source():
    report = render_report([make_finding(dataSource=None)], "myproj")
    assert "CVE-2019-10744" in report
    assert "[CVE-2019-10744](" not in report


def test_render_report_shows_related_cve_alias():
    report = render_report([make_finding(id="GHSA-abcd-1234", relatedCve="CVE-2019-10744")], "myproj")
    assert "GHSA-abcd-1234" in report
    assert "(CVE-2019-10744)" in report


def test_render_report_shows_dash_when_no_fix_available():
    report = render_report([make_finding(fixedIn=[])], "myproj")
    assert "| - |" in report


def test_render_report_sorts_worst_severity_first():
    findings = [make_finding(id="CVE-low", severity="Low"), make_finding(id="CVE-crit", severity="Critical")]
    report = render_report(findings, "myproj")
    assert report.index("CVE-crit") < report.index("CVE-low")


def test_sort_key_puts_unknown_and_garbage_severities_last():
    ranked = sorted(
        [make_finding(severity="Unknown"), make_finding(severity="Critical"), make_finding(severity="garbage")],
        key=_sort_key,
    )
    assert [f["severity"] for f in ranked][0] == "Critical"
    assert set(f["severity"] for f in ranked[1:]) == {"Unknown", "garbage"}


def test_escape_for_table_cell_handles_pipes_and_newlines():
    assert _escape_for_table_cell("a | b\nc") == "a \\| b c"


def test_escape_for_table_cell_handles_none():
    assert _escape_for_table_cell(None) == ""


def test_vulnerability_cell_plain_id_without_data_source_or_alias():
    assert _vulnerability_cell({"id": "CVE-1", "dataSource": None, "relatedCve": None}) == "CVE-1"


def test_main_writes_report_to_out_file(tmp_path, monkeypatch, capsys):
    import json

    findings_path = tmp_path / "findings.json"
    out_path = tmp_path / "report.md"
    findings_path.write_text(json.dumps([make_finding()]))

    monkeypatch.setattr(
        "sys.argv",
        [
            "render_findings_report.py",
            "--findings", str(findings_path),
            "--project-key", "myproj",
            "--out", str(out_path),
            "--include-dev-dependencies", "true",
        ],
    )
    main()

    content = out_path.read_text()
    assert "myproj" in content
    assert "lodash" in content
    assert "Scope: production and development dependencies." in content

    captured = capsys.readouterr()
    assert "Wrote findings report (1 finding(s))" in captured.out

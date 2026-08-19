import json

from diff_findings import diff, filter_by_changed_files, main


def make_finding(vuln_id="CVE-1", purl="pkg:npm/a@1", path="package-lock.json", **extra):
    return {"id": vuln_id, "purl": purl, "path": path, "package": "a", **extra}


def test_diff_excludes_finding_present_in_both():
    baseline = [make_finding()]
    head = [make_finding()]
    assert diff(baseline, head) == []


def test_diff_includes_genuinely_new_finding():
    baseline = [make_finding(vuln_id="CVE-1")]
    head = [make_finding(vuln_id="CVE-1"), make_finding(vuln_id="CVE-2")]
    result = diff(baseline, head)
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2"


def test_diff_treats_different_purl_as_new_even_if_id_and_path_match():
    baseline = [make_finding(purl="pkg:npm/a@1.0.0")]
    head = [make_finding(purl="pkg:npm/a@2.0.0")]  # version bump, still vulnerable
    assert diff(baseline, head) == head


def test_diff_treats_different_path_as_new_even_if_id_and_purl_match():
    baseline = [make_finding(path="package-lock.json")]
    head = [make_finding(path="sub/package-lock.json")]
    assert diff(baseline, head) == head


def test_diff_empty_baseline_means_everything_is_new():
    head = [make_finding(), make_finding(vuln_id="CVE-2")]
    assert diff([], head) == head


def test_diff_is_symmetric_for_resolved_findings():
    """diff(head, baseline) - arguments swapped from the usual new-findings
    call - gives findings present in baseline but no longer in head, i.e.
    resolved findings. main() relies on this instead of a separate
    resolved-findings implementation."""
    baseline = [make_finding(vuln_id="CVE-1"), make_finding(vuln_id="CVE-2")]
    head = [make_finding(vuln_id="CVE-1")]  # CVE-2 was fixed/upgraded away
    resolved = diff(head, baseline)
    assert len(resolved) == 1
    assert resolved[0]["id"] == "CVE-2"


def test_filter_by_changed_files_keeps_only_touched_paths():
    findings = [
        make_finding(path="js/package-lock.json"),
        make_finding(path="python/requirements.txt"),
    ]
    result = filter_by_changed_files(findings, {"js/package-lock.json"})
    assert [f["path"] for f in result] == ["js/package-lock.json"]


def test_filter_by_changed_files_drops_everything_on_path_space_mismatch():
    findings = [make_finding(path="js/package-lock.json")]
    result = filter_by_changed_files(findings, {"fixtures/js/package-lock.json"})
    assert result == []


def test_main_writes_new_findings_to_out_file(tmp_path, monkeypatch, capsys):
    baseline_path = tmp_path / "baseline.json"
    head_path = tmp_path / "head.json"
    out_path = tmp_path / "new.json"

    baseline_path.write_text(json.dumps([make_finding(vuln_id="CVE-1")]))
    head_path.write_text(
        json.dumps([make_finding(vuln_id="CVE-1"), make_finding(vuln_id="CVE-2")])
    )

    monkeypatch.setattr(
        "sys.argv",
        ["diff_findings.py", "--baseline", str(baseline_path), "--head", str(head_path), "--out", str(out_path)],
    )
    main()

    result = json.loads(out_path.read_text())
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2"

    captured = capsys.readouterr()
    assert "1 new finding(s) out of 2 head finding(s)" in captured.out


def test_main_applies_changed_files_filter_end_to_end(tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.json"
    head_path = tmp_path / "head.json"
    out_path = tmp_path / "new.json"
    changed_files_path = tmp_path / "changed-files.txt"

    baseline_path.write_text(json.dumps([]))
    head_path.write_text(
        json.dumps([make_finding(path="js/package-lock.json"), make_finding(path="python/requirements.txt")])
    )
    changed_files_path.write_text("js/package-lock.json\n")

    monkeypatch.setattr(
        "sys.argv",
        [
            "diff_findings.py",
            "--baseline", str(baseline_path),
            "--head", str(head_path),
            "--out", str(out_path),
            "--changed-files", str(changed_files_path),
        ],
    )
    main()

    result = json.loads(out_path.read_text())
    assert [f["path"] for f in result] == ["js/package-lock.json"]


def test_main_writes_removed_findings_when_requested(tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.json"
    head_path = tmp_path / "head.json"
    out_path = tmp_path / "new.json"
    removed_out_path = tmp_path / "removed.json"

    baseline_path.write_text(
        json.dumps([make_finding(vuln_id="CVE-1"), make_finding(vuln_id="CVE-2")])
    )
    head_path.write_text(json.dumps([make_finding(vuln_id="CVE-1")]))  # CVE-2 resolved

    monkeypatch.setattr(
        "sys.argv",
        [
            "diff_findings.py",
            "--baseline", str(baseline_path),
            "--head", str(head_path),
            "--out", str(out_path),
            "--removed-out", str(removed_out_path),
        ],
    )
    main()

    removed = json.loads(removed_out_path.read_text())
    assert len(removed) == 1
    assert removed[0]["id"] == "CVE-2"


def test_main_does_not_write_removed_findings_when_not_requested(tmp_path, monkeypatch):
    """--removed-out is optional - main() must not write (or require) a
    removed-findings file when the caller didn't ask for one."""
    baseline_path = tmp_path / "baseline.json"
    head_path = tmp_path / "head.json"
    out_path = tmp_path / "new.json"

    baseline_path.write_text(json.dumps([make_finding()]))
    head_path.write_text(json.dumps([make_finding()]))

    monkeypatch.setattr(
        "sys.argv",
        ["diff_findings.py", "--baseline", str(baseline_path), "--head", str(head_path), "--out", str(out_path)],
    )
    main()  # must not raise

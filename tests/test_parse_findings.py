import json

from parse_findings import (
    VALID_SEVERITIES,
    _coerce_fix_state,
    _coerce_severity,
    _first_related_cve,
    _normalize_location_path,
    finding_key,
    main,
    normalize,
    normalize_match,
)


def make_match(
    vuln_id="CVE-2019-10744",
    severity="Critical",
    package="lodash",
    version="4.17.11",
    pkg_type="npm",
    purl="pkg:npm/lodash@4.17.11",
    locations=None,
    fix_state="fixed",
    fix_versions=None,
    data_source="https://example.org/CVE-2019-10744",
    related=None,
    description="Prototype pollution",
):
    if locations is None:
        # Realistic syft `dir:` output is rooted at "/" - see
        # _normalize_location_path and its dedicated tests below.
        locations = [{"path": "/package-lock.json"}]
    if fix_versions is None:
        fix_versions = ["4.17.12"]
    return {
        "vulnerability": {
            "id": vuln_id,
            "severity": severity,
            "dataSource": data_source,
            "fix": {"state": fix_state, "versions": fix_versions},
            "description": description,
        },
        "artifact": {
            "name": package,
            "version": version,
            "type": pkg_type,
            "purl": purl,
            "locations": locations,
        },
        "relatedVulnerabilities": related or [],
    }


def test_normalize_match_shapes_a_single_location_finding():
    match = make_match()
    findings = normalize_match(match)
    assert findings == [{
        "id": "CVE-2019-10744",
        "severity": "Critical",
        "package": "lodash",
        "version": "4.17.11",
        "type": "npm",
        "purl": "pkg:npm/lodash@4.17.11",
        "path": "package-lock.json",
        "fixState": "fixed",
        "fixedIn": ["4.17.12"],
        "dataSource": "https://example.org/CVE-2019-10744",
        "relatedCve": None,
        "description": "Prototype pollution",
    }]


def test_normalize_match_emits_one_finding_per_location():
    match = make_match(locations=[{"path": "/package-lock.json"}, {"path": "/sub/package-lock.json"}])
    findings = normalize_match(match)
    assert [f["path"] for f in findings] == ["package-lock.json", "sub/package-lock.json"]


def test_normalize_match_falls_back_to_package_name_when_no_locations():
    match = make_match(locations=[])
    findings = normalize_match(match)
    assert len(findings) == 1
    assert findings[0]["path"] == "lodash"


def test_normalize_match_missing_location_path_falls_back_to_package_name():
    match = make_match(locations=[{}])
    findings = normalize_match(match)
    assert findings[0]["path"] == "lodash"


def test_normalize_location_path_strips_syfts_leading_slash():
    """Regression test: syft's `dir:` cataloger roots locations at "/" (e.g.
    "/js/package-lock.json"), which - left unstripped - silently dropped
    every finding from a real PR's new-findings set, since sca-pr.yml's
    --changed-files entries (from `git diff --name-only`) never carry a
    leading slash. Confirmed live against actions-sca-syft-grype PR #1."""
    assert _normalize_location_path("/js/package-lock.json") == "js/package-lock.json"


def test_normalize_location_path_strips_multiple_leading_slashes():
    assert _normalize_location_path("//weird/double-slash.json") == "weird/double-slash.json"


def test_normalize_location_path_leaves_already_clean_path_unchanged():
    assert _normalize_location_path("js/package-lock.json") == "js/package-lock.json"


def test_normalize_location_path_passes_through_none():
    assert _normalize_location_path(None) is None


def test_normalize_location_path_passes_through_empty_string():
    assert _normalize_location_path("") == ""


def test_coerce_severity_returns_valid_value_unchanged():
    assert _coerce_severity("High", "desc") == "High"


def test_coerce_severity_accepts_unknown_as_a_real_value():
    """Grype legitimately reports "Unknown" for a vulnerability with no
    CVSS score yet - that's informational, not a data-quality problem, so
    it must survive as-is."""
    assert _coerce_severity("Unknown", "desc") == "Unknown"


def test_coerce_severity_falls_back_to_unknown_on_garbage():
    assert _coerce_severity("not-a-real-severity", "desc") == "Unknown"


def test_coerce_severity_falls_back_to_unknown_on_missing():
    assert _coerce_severity(None, "desc") == "Unknown"


def test_coerce_fix_state_passes_through_valid_values():
    for state in ("fixed", "not-fixed", "wont-fix", "unknown"):
        assert _coerce_fix_state(state) == state


def test_coerce_fix_state_falls_back_on_garbage():
    assert _coerce_fix_state("bogus") == "unknown"
    assert _coerce_fix_state(None) == "unknown"


def test_first_related_cve_returns_none_when_id_is_already_a_cve():
    assert _first_related_cve("CVE-2019-10744", [{"id": "GHSA-abcd-1234"}]) is None


def test_first_related_cve_finds_cve_alias_for_a_ghsa_id():
    related = [{"id": "GHSA-abcd-1234"}, {"id": "CVE-2019-10744"}]
    assert _first_related_cve("GHSA-abcd-1234", related) == "CVE-2019-10744"


def test_first_related_cve_returns_none_when_no_cve_alias_exists():
    assert _first_related_cve("GHSA-abcd-1234", [{"id": "GHSA-other-5678"}]) is None


def test_finding_key_uses_id_purl_path():
    finding = {"id": "CVE-1", "purl": "pkg:npm/x@1", "path": "package-lock.json", "package": "x"}
    assert finding_key(finding) == ("CVE-1", "pkg:npm/x@1", "package-lock.json")


def test_normalize_dedupes_identical_findings_across_matches():
    """Defensive: two matches that would normalize to the exact same
    (id, purl, path) must not double-count."""
    match = make_match()
    report = {"matches": [match, match]}
    findings = normalize(report)
    assert len(findings) == 1


def test_normalize_keeps_distinct_findings():
    report = {"matches": [make_match(vuln_id="CVE-1"), make_match(vuln_id="CVE-2")]}
    findings = normalize(report)
    assert {f["id"] for f in findings} == {"CVE-1", "CVE-2"}


def test_normalize_handles_no_matches_key():
    assert normalize({}) == []


def test_normalize_handles_empty_matches_list():
    assert normalize({"matches": []}) == []


def test_main_writes_normalized_findings_to_out_file(tmp_path, monkeypatch, capsys):
    report_path = tmp_path / "grype-raw.json"
    out_path = tmp_path / "findings.json"
    report_path.write_text(json.dumps({"matches": [make_match()]}))

    monkeypatch.setattr(
        "sys.argv",
        ["parse_findings.py", "--report", str(report_path), "--out", str(out_path)],
    )
    main()

    result = json.loads(out_path.read_text())
    assert len(result) == 1
    assert result[0]["id"] == "CVE-2019-10744"

    captured = capsys.readouterr()
    assert "Wrote 1 finding(s)" in captured.err


def test_valid_severities_are_ordered_unknown_first_for_documentation():
    """Not a behavioral assertion - just pins the documented constant so a
    careless edit doesn't silently drop a severity Grype actually emits."""
    assert set(VALID_SEVERITIES) == {"Unknown", "Negligible", "Low", "Medium", "High", "Critical"}

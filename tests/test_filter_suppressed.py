from datetime import date

import pytest

from filter_suppressed import FilterResult, build_summary, filter_suppressed, parse_scaignore


def make_finding(vuln_id="GHSA-1", package="cytoscape", path="package-lock.json", **extra):
    return {
        "id": vuln_id,
        "severity": "High",
        "package": package,
        "version": "3.34.0",
        "purl": f"pkg:npm/{package}@3.34.0",
        "path": path,
        "relatedCve": None,
        **extra,
    }


def make_entry(vuln_id="GHSA-1", package=None, reason="because", expires="2099-01-01", **extra):
    entry = {"id": vuln_id, "reason": reason, "expires": expires, **extra}
    if package is not None:
        entry["package"] = package
    return entry


class TestParseScaignore:
    def test_empty_text_is_an_empty_list(self):
        assert parse_scaignore("") == []
        assert parse_scaignore("   \n") == []

    def test_yaml_with_no_suppressions_key_is_an_empty_list(self):
        assert parse_scaignore("suppressions: []\n") == []

    def test_comment_only_text_parses_to_none_and_is_an_empty_list(self):
        assert parse_scaignore("# nothing suppressed yet\n") == []

    def test_parses_a_full_entry(self):
        text = """
        suppressions:
          - id: GHSA-1
            package: cytoscape
            reason: "vendored lodash internals, _.template not present"
            expires: "2027-01-01"
        """
        result = parse_scaignore(text)
        assert result == [
            {
                "id": "GHSA-1",
                "package": "cytoscape",
                "reason": "vendored lodash internals, _.template not present",
                "expires": "2027-01-01",
            }
        ]

    def test_package_is_optional(self):
        text = """
        suppressions:
          - id: GHSA-1
            reason: "because"
            expires: "2027-01-01"
        """
        result = parse_scaignore(text)
        assert "package" not in result[0]

    def test_not_valid_yaml_raises(self):
        with pytest.raises(ValueError, match="not valid YAML"):
            parse_scaignore("suppressions: [this is not closed")

    def test_not_a_mapping_raises(self):
        with pytest.raises(ValueError, match="mapping"):
            parse_scaignore("- just a list\n")

    def test_unrecognized_top_level_key_raises(self):
        with pytest.raises(ValueError, match="unrecognized top-level key"):
            parse_scaignore("suppresions: []\n")  # typo

    def test_suppressions_not_a_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            parse_scaignore("suppressions: {}\n")

    def test_entry_not_a_mapping_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            parse_scaignore("suppressions:\n  - just a string\n")

    @pytest.mark.parametrize("missing", ["id", "reason", "expires"])
    def test_missing_required_field_raises(self, missing):
        entry = make_entry()
        del entry[missing]
        text = {"suppressions": [entry]}
        import yaml

        with pytest.raises(ValueError, match=missing):
            parse_scaignore(yaml.dump(text))

    def test_unrecognized_entry_key_raises(self):
        import yaml

        text = yaml.dump({"suppressions": [{**make_entry(), "typo_field": "x"}]})
        with pytest.raises(ValueError, match="unrecognized key"):
            parse_scaignore(text)

    def test_malformed_expires_date_raises(self):
        import yaml

        text = yaml.dump({"suppressions": [make_entry(expires="not-a-date")]})
        with pytest.raises(ValueError, match="expires"):
            parse_scaignore(text)

    def test_empty_id_raises(self):
        import yaml

        text = yaml.dump({"suppressions": [make_entry(vuln_id="")]})
        with pytest.raises(ValueError, match="id"):
            parse_scaignore(text)


class TestFilterSuppressed:
    TODAY = date(2026, 10, 3)

    def test_no_suppressions_keeps_everything(self):
        findings = [make_finding()]
        result = filter_suppressed(findings, [], self.TODAY)
        assert result.kept == findings
        assert result.suppressed == []
        assert result.expired == []

    def test_matching_id_and_package_suppresses(self):
        findings = [make_finding(vuln_id="GHSA-1", package="cytoscape")]
        entries = [make_entry(vuln_id="GHSA-1", package="cytoscape")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == []
        assert len(result.suppressed) == 1
        assert result.suppressed[0]["finding"] == findings[0]
        assert result.suppressed[0]["suppression"] == entries[0]

    def test_entry_with_no_package_matches_any_package(self):
        findings = [make_finding(vuln_id="GHSA-1", package="anything")]
        entries = [make_entry(vuln_id="GHSA-1")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == []
        assert len(result.suppressed) == 1

    def test_package_mismatch_does_not_suppress(self):
        findings = [make_finding(vuln_id="GHSA-1", package="cytoscape")]
        entries = [make_entry(vuln_id="GHSA-1", package="some-other-package")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == findings
        assert result.suppressed == []

    def test_id_mismatch_does_not_suppress(self):
        findings = [make_finding(vuln_id="GHSA-1")]
        entries = [make_entry(vuln_id="GHSA-2")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == findings

    def test_matches_against_related_cve_too(self):
        """Grype sometimes reports a GHSA id with a CVE alias
        (parse_findings.py's relatedCve) - a suppression written against
        either id form should match the same finding."""
        findings = [make_finding(vuln_id="GHSA-1", relatedCve="CVE-2024-1234")]
        entries = [make_entry(vuln_id="CVE-2024-1234")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == []
        assert len(result.suppressed) == 1

    def test_expired_suppression_no_longer_suppresses(self):
        findings = [make_finding(vuln_id="GHSA-1")]
        entries = [make_entry(vuln_id="GHSA-1", expires="2020-01-01")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == findings
        assert result.suppressed == []

    def test_expired_suppression_that_would_have_matched_is_flagged(self):
        findings = [make_finding(vuln_id="GHSA-1", package="cytoscape")]
        entries = [make_entry(vuln_id="GHSA-1", package="cytoscape", expires="2020-01-01")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == findings
        assert len(result.expired) == 1
        assert result.expired[0]["finding"] == findings[0]
        assert result.expired[0]["suppression"] == entries[0]

    def test_expiry_is_exclusive_on_the_expires_date_itself(self):
        """A suppression expiring "today" no longer applies today - expires
        reads as the first day it's no longer valid, not the last day it
        is, so a suppression can't coast on its expiry date indefinitely by
        being re-checked at exactly midnight."""
        findings = [make_finding(vuln_id="GHSA-1")]
        entries = [make_entry(vuln_id="GHSA-1", expires="2026-10-03")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == findings

    def test_multiple_findings_only_suppresses_matching_ones(self):
        findings = [
            make_finding(vuln_id="GHSA-1", package="cytoscape"),
            make_finding(vuln_id="GHSA-2", package="other"),
        ]
        entries = [make_entry(vuln_id="GHSA-1", package="cytoscape")]
        result = filter_suppressed(findings, entries, self.TODAY)
        assert result.kept == [findings[1]]
        assert len(result.suppressed) == 1


class TestBuildSummary:
    def test_nothing_matched(self):
        result = FilterResult(kept=[make_finding()], suppressed=[], expired=[])
        assert build_summary(result) == "No `.scaignore` suppressions matched."

    def test_suppressed_finding_names_the_entry(self):
        entry = make_entry(vuln_id="GHSA-1", package="cytoscape", reason="vendored, not exploitable")
        result = FilterResult(kept=[], suppressed=[{"finding": make_finding(), "suppression": entry}], expired=[])
        summary = build_summary(result)
        assert "1 finding(s) suppressed" in summary
        assert "GHSA-1" in summary
        assert "cytoscape" in summary
        assert "vendored, not exploitable" in summary

    def test_suppressed_entry_with_no_package_omits_the_on_clause(self):
        entry = make_entry(vuln_id="GHSA-1", package=None)
        result = FilterResult(kept=[], suppressed=[{"finding": make_finding(), "suppression": entry}], expired=[])
        assert " on `" not in build_summary(result)

    def test_expired_finding_is_flagged_as_active_again(self):
        finding = make_finding(vuln_id="GHSA-1", package="cytoscape")
        entry = make_entry(vuln_id="GHSA-1", package="cytoscape", expires="2020-01-01")
        result = FilterResult(kept=[finding], suppressed=[], expired=[{"finding": finding, "suppression": entry}])
        summary = build_summary(result)
        assert "expired" in summary
        assert "active again" in summary
        assert "GHSA-1" in summary

    def test_both_suppressed_and_expired_sections_present(self):
        active_entry = make_entry(vuln_id="GHSA-1")
        expired_entry = make_entry(vuln_id="GHSA-2", expires="2020-01-01")
        result = FilterResult(
            kept=[make_finding(vuln_id="GHSA-2")],
            suppressed=[{"finding": make_finding(vuln_id="GHSA-1"), "suppression": active_entry}],
            expired=[{"finding": make_finding(vuln_id="GHSA-2"), "suppression": expired_entry}],
        )
        summary = build_summary(result)
        assert "suppressed by `.scaignore`" in summary
        assert "active again" in summary

#!/usr/bin/env python3
"""Render a human-readable Markdown report of every finding in a normalized
findings JSON file (parse_findings.py's output schema).

Why this exists: there's no server this action's scan leaves running - the
findings JSON is the only durable record of what was found. Check Run
annotations already cover *new* findings inline-on-diff for PRs; this report
covers the full current finding set (matching parse_findings.py's whole
output) as a durable, downloadable artifact.
"""
import argparse
import json

# High to low - worst findings first in the report. "Unknown" (a legitimate
# Grype value - CVSS not yet scored) sorts last via the fallback in
# _sort_key below, alongside anything genuinely unrecognized; it isn't
# "worse than Critical" or "better than Negligible", it's a different kind
# of value that doesn't belong on this ordering at all.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible"]


def _sort_key(finding):
    severity = finding.get("severity")
    severity_rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return (severity_rank, finding.get("package") or "", finding.get("path") or "")


def _escape_for_table_cell(text):
    """Markdown table cells break on literal `|` and newlines - a Grype
    vulnerability description can contain either."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _vulnerability_cell(finding):
    vuln_id = finding.get("id") or ""
    data_source = finding.get("dataSource")
    cell = f"[{vuln_id}]({data_source})" if data_source else vuln_id
    related_cve = finding.get("relatedCve")
    if related_cve:
        cell += f" ({related_cve})"
    return cell


def render_report(findings, project_key):
    lines = [f"# SCA syft+grype findings report - `{project_key}`", ""]

    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"{len(findings)} finding(s).")
    lines += [
        "",
        "| Severity | Package | Installed | Fixed In | Vulnerability | Location |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for finding in sorted(findings, key=_sort_key):
        severity = finding.get("severity") or "Unknown"
        fixed_in = ", ".join(finding.get("fixedIn") or []) or "-"
        location = finding.get("path") or ""
        lines.append(
            f"| {severity} | {_escape_for_table_cell(finding.get('package'))} "
            f"| {_escape_for_table_cell(finding.get('version'))} | {_escape_for_table_cell(fixed_in)} "
            f"| {_vulnerability_cell(finding)} | `{location}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main():  # pragma: no cover - CLI glue over the above
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="Path to a normalized findings JSON file (parse_findings.py's schema)")
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--out", required=True, help="Path to write the Markdown report to")
    args = parser.parse_args()

    with open(args.findings) as f:
        findings = json.load(f)

    report = render_report(findings, args.project_key)

    with open(args.out, "w") as f:
        f.write(report)

    print(f"Wrote findings report ({len(findings)} finding(s)) to {args.out}")


if __name__ == "__main__":
    main()

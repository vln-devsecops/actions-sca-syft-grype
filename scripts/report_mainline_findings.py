#!/usr/bin/env python3
"""Report new vulnerability findings from sca-mainline.yml's recurring scan
as a GitHub Issue: open one if none is currently tracking this project, or
add a comment to the existing open one otherwise. A no-op when there's
nothing new to report.

sca-mainline.yml deliberately hands this script a diff with no
--changed-files filter applied (see diff_findings.py's module docstring):
the whole point of the recurring scan is to catch a newly-disclosed CVE
against a dependency nobody touched, which the PR-scoped filter in
sca-pr.yml exists specifically to exclude.

Matches on a hidden HTML-comment marker in the issue body (the same pattern
post_pr_comment.py uses for PR comments) so repeated scheduled runs update
one running issue instead of opening a new one every time new CVEs surface.
"""
import argparse
import json
import os

from apply_policy import FULL_SEVERITIES, counts_by_severity, severity_of
from gh_client import request as gh_api

MARKER_PREFIX = "<!-- sca-syft-grype-action:mainline-alert:"
MARKER_SUFFIX = " -->"


def marker_for(project_key):
    """One marker per project-key, not one global marker - a repo scanning
    more than one project-base-dir (e.g. via multiple sca-mainline.yml
    callers) must not fold unrelated projects' alerts into a single issue."""
    return f"{MARKER_PREFIX}{project_key}{MARKER_SUFFIX}"


def _sort_key(finding):
    severity = finding.get("severity")
    rank = FULL_SEVERITIES.index(severity) if severity in FULL_SEVERITIES else len(FULL_SEVERITIES)
    return (rank, finding.get("package") or "", finding.get("path") or "")


def render_findings_table(findings):
    lines = ["| Severity | Package | Installed | Vulnerability | Location |", "| --- | --- | --- | --- | --- |"]
    for finding in sorted(findings, key=_sort_key):
        severity = severity_of(finding)
        vuln_id = finding.get("id") or ""
        data_source = finding.get("dataSource")
        vuln_cell = f"[{vuln_id}]({data_source})" if data_source else vuln_id
        lines.append(
            f"| {severity} | {finding.get('package') or ''} | {finding.get('version') or ''} "
            f"| {vuln_cell} | `{finding.get('path') or ''}` |"
        )
    return "\n".join(lines)


def _severity_summary(new_findings):
    counts = counts_by_severity(new_findings)
    return ", ".join(f"{counts[s]} {s}" for s in FULL_SEVERITIES if counts[s])


def build_issue_body(new_findings, project_key, run_url):
    lines = [
        f"Grype's vulnerability database has surfaced **{len(new_findings)} new "
        f"finding(s)** ({_severity_summary(new_findings)}) for `{project_key}` since "
        "the last recurring scan, in dependencies this repo already had - not "
        "from a new PR.",
        "",
        render_findings_table(new_findings),
    ]
    if run_url:
        lines += ["", f"Detected by: {run_url}"]
    lines += ["", marker_for(project_key)]
    return "\n".join(lines)


def build_comment_body(new_findings, run_url):
    lines = [
        f"**{len(new_findings)} more new finding(s)** ({_severity_summary(new_findings)}) "
        "since this issue was last updated.",
        "",
        render_findings_table(new_findings),
    ]
    if run_url:
        lines += ["", f"Detected by: {run_url}"]
    return "\n".join(lines)


def find_open_issue(owner, repo, project_key, token):  # pragma: no cover - network I/O, validated live
    marker = marker_for(project_key)
    page = 1
    while True:
        url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues"
            f"?state=open&per_page=100&page={page}"
        )
        issues = gh_api("GET", url, token)
        for issue in issues:
            if marker in (issue.get("body") or ""):
                return issue
        if len(issues) < 100:
            return None
        page += 1


def create_issue(owner, repo, title, body, labels, token):  # pragma: no cover - network I/O, validated live
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    return gh_api("POST", url, token, {"title": title, "body": body, "labels": labels})


def add_comment(owner, repo, issue_number, body, token):  # pragma: no cover - network I/O, validated live
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
    return gh_api("POST", url, token, {"body": body})


def reopen_issue_if_closed(owner, repo, issue, token):  # pragma: no cover - network I/O, validated live
    # Defensive: find_open_issue() already filters state=open, so this
    # should never fire in practice - kept in case a human closed the issue
    # between the search and this write, or the API's state filter ever
    # changes semantics.
    if issue.get("state") != "open":
        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue['number']}"
        gh_api("PATCH", url, token, {"state": "open"})


def main():  # pragma: no cover - CLI glue over the above, validated live
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--new-findings", required=True, help="Path to diff_findings.py's new-findings JSON (no --changed-files filter)")
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--labels", default="security,sca-alert", help="Comma-separated labels for a newly-created issue")
    parser.add_argument("--run-url", default="", help="Link to the workflow run that produced this report")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN environment variable is required")

    with open(args.new_findings) as f:
        new_findings = json.load(f)

    if not new_findings:
        print("No new findings since the last mainline scan; nothing to report.")
        return

    owner, repo = args.repo.split("/", 1)
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]

    existing = find_open_issue(owner, repo, args.project_key, token)
    if existing is None:
        title = f"SCA: new vulnerabilities detected on {args.project_key}"
        body = build_issue_body(new_findings, args.project_key, args.run_url)
        issue = create_issue(owner, repo, title, body, labels, token)
        print(f"Opened tracking issue #{issue['number']}")
    else:
        reopen_issue_if_closed(owner, repo, existing, token)
        body = build_comment_body(new_findings, args.run_url)
        add_comment(owner, repo, existing["number"], body, token)
        print(f"Added a comment to existing tracking issue #{existing['number']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Evaluate the blocking policy against a set of new findings, publish them as
a GitHub Check Run (one annotation per finding), and exit non-zero if the
policy trips and blocking is enabled.

The policy is our own, evaluated purely against the new-findings set produced
by diff_findings.py.

Always writes --result-out, even when it goes on to exit non-zero, and even
when the Check Run can't be published at all (e.g. a fork PR's read-only
GITHUB_TOKEN - see gh_api's allow_forbidden), so a subsequent workflow step
(e.g. posting a PR summary comment) can read the outcome with
`if: always()`.
"""
import argparse
import json
import os
import posixpath
import sys

from gh_client import request as gh_api

# The ordered, comparable severity scale - Grype's five real CVSS-backed
# levels, low to high. "Unknown" (a legitimate Grype value - CVSS not yet
# scored - see parse_findings.py) is deliberately NOT part of this ordering:
# it isn't "worse than Critical" or "better than Negligible", it's a
# different kind of value entirely. severity_for_comparison() below is where
# it (and any other unrecognized value) gets a fail-closed stand-in so a
# threshold comparison always has something orderable to compare against.
SEVERITY_ORDER = ["Negligible", "Low", "Medium", "High", "Critical"]

# Display/count order - every value parse_findings.py can emit, worst first,
# "Unknown" last since it isn't part of the worst->best ordering above.
FULL_SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

ANNOTATION_LEVEL = {
    "Critical": "failure",
    "High": "failure",
    "Medium": "warning",
    "Low": "notice",
    "Negligible": "notice",
    # Not "notice": an unscored vulnerability isn't known to be low-risk,
    # it's unscored. "warning" reflects that this needs a human look without
    # overstating it as a guaranteed Critical/High.
    "Unknown": "warning",
}

ANNOTATION_BATCH_SIZE = 50

# What "Unknown" (Grype's real value for an unscored vulnerability) or any
# other unrecognized/missing severity counts as for threshold comparisons -
# a severity that can't be placed on SEVERITY_ORDER must never silently
# vanish from a security gate by comparing as "lower than everything", so it
# fails closed at a stand-in that's second-from-top rather than being
# dropped or crashing SEVERITY_ORDER.index(...).
UNKNOWN_SEVERITY_FALLBACK = "High"


def severity_of(finding):
    """The severity to *display* for a finding - the real value if it's one
    parse_findings.py can emit, else "Unknown". Never raises, never returns
    None."""
    severity = finding.get("severity")
    return severity if severity in FULL_SEVERITIES else "Unknown"


def severity_for_comparison(severity):
    """The severity to *compare against a threshold* - collapses anything
    off SEVERITY_ORDER (including the legitimate "Unknown" value) onto
    UNKNOWN_SEVERITY_FALLBACK. Kept separate from severity_of() because a
    report should say "Unknown", not silently relabel it "High" - but a
    blocking decision has to fail closed rather than treat "Unknown" as the
    lowest possible risk."""
    return severity if severity in SEVERITY_ORDER else UNKNOWN_SEVERITY_FALLBACK


def severity_at_least(severity, threshold):
    return SEVERITY_ORDER.index(severity_for_comparison(severity)) >= SEVERITY_ORDER.index(threshold)


def repo_relative_path(path, project_base_dir):
    """A finding's `path` (parse_findings.py's schema) is relative to
    project-base-dir, not the repo root - see docs/design.md and
    sca-pr.yml's own re-rooting of --changed-files for the same reason.
    GitHub's Check Run annotation `path`, by contrast, MUST be relative to
    the repo root, or GitHub can't attach the annotation to the right file
    in the PR's "Files changed" view (it silently fails to display inline,
    rather than erroring). Left unprefixed, every annotation from a scan
    where project-base-dir != "." points at a path that doesn't exist in
    the repo (e.g. "package-lock.json" instead of "fixtures/package-lock.json"
    - exactly this repo's own ci.yml configuration)."""
    base = (project_base_dir or ".").strip("/")
    if base in ("", "."):
        return path
    return posixpath.normpath(f"{base}/{path}")


def to_annotation(finding, project_base_dir="."):
    severity = severity_of(finding)
    title = f"{finding['id']} in {finding['package']}@{finding['version']} ({severity})"
    message = finding.get("description") or ""
    fixed_in = finding.get("fixedIn") or []
    if fixed_in:
        message = f"{message}\n\nFixed in: {', '.join(fixed_in)}".strip()
    elif finding.get("fixState") in ("not-fixed", "wont-fix"):
        message = f"{message}\n\nNo fix currently available ({finding['fixState']}).".strip()
    return {
        "path": repo_relative_path(finding["path"], project_base_dir),
        "start_line": 1,
        "end_line": 1,
        "annotation_level": ANNOTATION_LEVEL[severity],
        "title": title,
        "message": message,
    }


def counts_by_severity(findings):
    counts = {s: 0 for s in FULL_SEVERITIES}
    for f in findings:
        counts[severity_of(f)] += 1
    return counts


def build_summary(findings, blocking_findings, threshold, blocking_enabled):
    counts = counts_by_severity(findings)
    lines = [
        f"Found {len(findings)} new vulnerability finding(s) not present in the baseline.",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in FULL_SEVERITIES:
        lines.append(f"| {severity} | {counts[severity]} |")
    lines.append("")
    if blocking_enabled:
        lines.append(
            f"Policy threshold: **{threshold}** or above blocks the job "
            f"(an unscored \"Unknown\" severity is treated as **{UNKNOWN_SEVERITY_FALLBACK}** "
            f"for this comparison). {len(blocking_findings)} new finding(s) meet or exceed it."
        )
    else:
        lines.append("Blocking is disabled for this run; findings are reported only.")
    return "\n".join(lines)


def write_result(path, result):
    with open(path, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


def batch(items, size):
    """Split items into consecutive chunks of at most `size`. GitHub's Check
    Run API only accepts ANNOTATION_BATCH_SIZE annotations per request, so
    the first batch goes in the creating POST and the rest follow as PATCHes."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def create_check_run(repo, token, sha, check_name, conclusion, summary, annotations):  # pragma: no cover - network I/O, validated live
    """Returns None (rather than raising) if the creating POST 403/404s -
    see gh_api's allow_forbidden. A fork PR's read-only token means this is
    the expected outcome there, not an error condition the caller should
    treat as fatal."""
    owner, name = repo.split("/", 1)
    base_url = f"https://api.github.com/repos/{owner}/{name}/check-runs"

    batches = batch(annotations, ANNOTATION_BATCH_SIZE) or [[]]
    check_run = gh_api(
        "POST",
        base_url,
        token,
        {
            "name": check_name,
            "head_sha": sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": check_name,
                "summary": summary,
                "annotations": batches[0],
            },
        },
        allow_forbidden=True,
    )
    if check_run is None:
        return None

    check_run_id = check_run["id"]
    update_url = f"{base_url}/{check_run_id}"
    for remaining_batch in batches[1:]:
        gh_api(
            "PATCH",
            update_url,
            token,
            {"output": {"title": check_name, "summary": summary, "annotations": remaining_batch}},
        )

    return check_run


def main():  # pragma: no cover - CLI glue over the above, validated live
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="Path to new-findings JSON (diff_findings.py output)")
    parser.add_argument("--threshold", default="High", choices=SEVERITY_ORDER)
    parser.add_argument("--blocking", default="true", choices=["true", "false"])
    parser.add_argument(
        "--project-base-dir", default=".",
        help=(
            "Path (relative to the repo root) that was scanned - see action.yml. "
            "Findings' `path` is relative to this, but Check Run annotations need "
            "repo-root-relative paths; see repo_relative_path()."
        ),
    )
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--sha", required=True, help="commit SHA the check run attaches to (PR head SHA)")
    parser.add_argument("--check-name", default="sca-syft-grype/new-vulnerabilities")
    parser.add_argument("--result-out", required=True, help="Path to write the policy result JSON to")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN environment variable is required")

    blocking_enabled = args.blocking == "true"

    with open(args.findings) as f:
        findings = json.load(f)

    blocking_findings = [f for f in findings if severity_at_least(severity_of(f), args.threshold)]
    blocked = blocking_enabled and bool(blocking_findings)

    if blocked:
        conclusion = "failure"
    elif findings:
        conclusion = "neutral"
    else:
        conclusion = "success"

    summary = build_summary(findings, blocking_findings, args.threshold, blocking_enabled)
    annotations = [to_annotation(f, args.project_base_dir) for f in findings]

    result = {
        "threshold": args.threshold,
        "blocking_enabled": blocking_enabled,
        "total_new_findings": len(findings),
        "blocking_findings": len(blocking_findings),
        "by_severity": counts_by_severity(findings),
        "blocked": blocked,
        "check_run_url": None,
    }

    # `finally` runs whether create_check_run() succeeds or raises, so this
    # alone guarantees --result-out is written either way - the `Post PR
    # summary comment` step reads this file under `if: always()`, so it has
    # to exist even when check-run publication fails (e.g. the read-only
    # GITHUB_TOKEN a fork PR gets), rather than dying with a
    # FileNotFoundError that masks the real error.
    try:
        check_run = create_check_run(
            args.repo, token, args.sha, args.check_name, conclusion, summary, annotations
        )
        if check_run is not None:
            result["check_run_url"] = check_run.get("html_url")
    finally:
        write_result(args.result_out, result)

    print(summary)

    if blocked:
        sys.exit(1)


if __name__ == "__main__":
    main()

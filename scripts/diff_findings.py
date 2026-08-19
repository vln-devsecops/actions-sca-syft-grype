#!/usr/bin/env python3
"""Set-diff a head findings file against a baseline findings file, producing
the findings present in head but not in baseline ("new findings").

Matching rule: two findings are the same vulnerability if they share
(id, purl, path) - the exact same package-instance, at the exact same
vulnerability ID, in the exact same manifest/lockfile. Unlike SAST's
line-hash matching, there's no line-churn problem here (a dependency
finding isn't tied to a source line), so a straight tuple match is enough -
see parse_findings.py's finding_key, which this re-exports.

Why --changed-files matters even more here than for SAST: a SAST finding can
only appear "new" if the code changed, because the analysis is purely a
function of the source. An SCA finding is also a function of the
vulnerability database, which moves independently of this PR's diff - a
dependency nobody touched can grow a new CVE between the baseline scan and
this PR's scan purely because Grype's DB was updated in between. Filtering
new findings down to --changed-files (the manifest/lockfile paths this PR
actually touched) keeps the PR's blocking policy scoped to "this PR
introduced a vulnerable dependency" and excludes "the database moved under
an untouched dependency" - the latter is real and worth knowing, but it's
not this PR's fault to block on. It's what sca-mainline.yml's recurring scan
exists to catch instead (there, deliberately, with no --changed-files filter
at all - see report_mainline_findings.py).
"""
import argparse
import json

from parse_findings import finding_key


def diff(baseline, head):
    """Findings in `head` not present in `baseline`. Symmetric in the sense
    that swapping the arguments (diff(head, baseline)) gives the opposite
    direction - findings in `baseline` no longer present in `head`, i.e.
    resolved findings - which main() uses for --removed-out below rather
    than duplicating this logic."""
    baseline_keys = {finding_key(f) for f in baseline}
    return [f for f in head if finding_key(f) not in baseline_keys]


def filter_by_changed_files(findings, changed_files):
    """Keep only findings whose `path` is in `changed_files`. Both must be in
    the same path-space as each other - the caller (sca-pr.yml) computes
    changed_files relative to project-base-dir, matching how findings' paths
    are normalized, not the repo root."""
    return [f for f in findings if f["path"] in changed_files]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Path to baseline findings JSON")
    parser.add_argument("--head", required=True, help="Path to head findings JSON")
    parser.add_argument("--out", required=True, help="Path to write new-findings JSON to")
    parser.add_argument(
        "--changed-files",
        help=(
            "Optional path to a newline-delimited list of files touched by the PR, "
            "in the same path-space as findings' `path` (i.e. relative to "
            "project-base-dir, not necessarily the repo root). When given, new "
            "findings outside this set are dropped. Omit for sca-mainline.yml's "
            "recurring scan, where every new finding is in scope regardless of "
            "which files changed (there usually aren't any - see module docstring)."
        ),
    )
    parser.add_argument(
        "--removed-out",
        help=(
            "Optional path to write resolved-findings JSON to (findings present in "
            "baseline that are no longer in head). Informational only - not scoped "
            "by --changed-files, since a resolved finding's own manifest may have "
            "been deleted or moved rather than edited."
        ),
    )
    args = parser.parse_args()

    with open(args.baseline) as f:
        baseline = json.load(f)
    with open(args.head) as f:
        head = json.load(f)

    new_findings = diff(baseline, head)

    if args.changed_files:
        with open(args.changed_files) as f:
            changed_files = {line.strip() for line in f if line.strip()}
        new_findings = filter_by_changed_files(new_findings, changed_files)

    with open(args.out, "w") as f:
        json.dump(new_findings, f, indent=2, sort_keys=True)
        f.write("\n")

    if args.removed_out:
        removed_findings = diff(head, baseline)
        with open(args.removed_out, "w") as f:
            json.dump(removed_findings, f, indent=2, sort_keys=True)
            f.write("\n")

    print(
        f"{len(new_findings)} new finding(s) out of {len(head)} head finding(s) "
        f"(baseline had {len(baseline)})"
    )


if __name__ == "__main__":
    main()

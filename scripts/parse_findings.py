#!/usr/bin/env python3
"""Parse a Grype JSON report (scripts/run_scan.sh's `grype ... -o json`
output) and normalize it into the findings schema shared across this action
(baseline artifacts, mainline re-scans, and PR head scans all produce this
same shape):

    {
      "id": "string (CVE-... or GHSA-...)",
      "severity": "Critical|High|Medium|Low|Negligible|Unknown",
      "package": "string",
      "version": "string (installed version)",
      "type": "string (ecosystem, e.g. npm/python/go-module/deb/apk)",
      "purl": "string",
      "path": "string (manifest/lockfile path, relative to project-base-dir)",
      "fixState": "fixed|not-fixed|wont-fix|unknown",
      "fixedIn": ["string", ...],
      "dataSource": "string (advisory URL)",
      "relatedCve": "string|null (CVE alias, when `id` itself is a GHSA)",
      "description": "string"
    }

Unlike SAST's fetch_findings.py, this has no network I/O at all - grype has
already run and written its report to a file by the time this script sees
it, so every function here is directly unit-testable (see tests/) rather
than needing `# pragma: no cover`.

One Grype `matches[]` entry can carry more than one `artifact.locations[]`
entry (the same package/version found via more than one manifest under
project-base-dir, e.g. both a root and a workspace-package lockfile). Each
location becomes its own finding, since this action's diffing and blocking
policy operate per-path (mirroring how SAST's findings are per-path) - see
diff_findings.py's `filter_by_changed_files`.
"""
import argparse
import json
import sys

# Real values Grype emits for vulnerability.severity. "Unknown" is a
# legitimate value (CVSS not yet scored for that vulnerability), kept
# verbatim rather than folded into a "we don't know" bucket - it's
# informational, not a data-quality problem. See apply_policy.py for how
# severity comparisons still fail closed on it.
VALID_SEVERITIES = ("Unknown", "Negligible", "Low", "Medium", "High", "Critical")

# Grype's fix.state values, informational only (not used for diffing/policy).
VALID_FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown")


def _coerce_severity(severity, finding_desc):
    """Guarantee the findings schema's `severity` invariant: always one of
    VALID_SEVERITIES, never None/empty. Grype should always populate a
    recognized value, but that's not an API contract - an unrecognized value
    is treated as "Unknown" (not silently dropped, not guessed at) and
    reported on stderr so it surfaces in the job log."""
    if severity in VALID_SEVERITIES:
        return severity
    print(
        f"warning: {finding_desc} has unrecognized severity {severity!r}; treating it as Unknown",
        file=sys.stderr,
    )
    return "Unknown"


def _coerce_fix_state(fix_state):
    return fix_state if fix_state in VALID_FIX_STATES else "unknown"


def _first_related_cve(vuln_id, related_vulnerabilities):
    """Grype's own `vulnerability.id` is sometimes a GHSA advisory ID rather
    than a CVE - surface the CVE alias (from `relatedVulnerabilities`) when
    one exists, purely so a report reader searching by CVE number can find
    it. Returns None when `id` is already a CVE (nothing to alias) or no CVE
    alias is present."""
    if vuln_id and vuln_id.startswith("CVE-"):
        return None
    for related in related_vulnerabilities:
        related_id = related.get("id", "")
        if related_id.startswith("CVE-"):
            return related_id
    return None


def normalize_match(match):
    """One Grype match -> one or more normalized findings (one per artifact
    location; see module docstring)."""
    vulnerability = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    fix = vulnerability.get("fix") or {}
    related = match.get("relatedVulnerabilities") or []

    vuln_id = vulnerability.get("id")
    severity = _coerce_severity(
        vulnerability.get("severity"),
        f"vulnerability {vuln_id!r} affecting {artifact.get('name')!r}",
    )
    related_cve = _first_related_cve(vuln_id, related)

    locations = artifact.get("locations") or [{}]
    findings = []
    for location in locations:
        findings.append({
            "id": vuln_id,
            "severity": severity,
            "package": artifact.get("name"),
            "version": artifact.get("version"),
            "type": artifact.get("type"),
            "purl": artifact.get("purl"),
            "path": location.get("path") or artifact.get("name") or "",
            "fixState": _coerce_fix_state(fix.get("state")),
            "fixedIn": fix.get("versions") or [],
            "dataSource": vulnerability.get("dataSource"),
            "relatedCve": related_cve,
            "description": vulnerability.get("description") or "",
        })
    return findings


def finding_key(finding):
    """Diffing identity - see diff_findings.py. Exposed here too since
    normalize() uses it to dedupe overlapping matches (see below), the same
    way SAST's fetch_findings.py dedupes across partitioned sub-queries."""
    return (finding["id"], finding["purl"], finding["path"])


def normalize(report):
    """Grype's parsed JSON report -> deduped list of normalized findings."""
    matches = report.get("matches") or []
    findings = []
    seen = set()
    for match in matches:
        for finding in normalize_match(match):
            key = finding_key(finding)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def main():  # pragma: no cover - CLI glue over the above
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="Path to Grype's raw JSON report")
    parser.add_argument("--out", required=True, help="Path to write normalized findings JSON to")
    args = parser.parse_args()

    with open(args.report) as f:
        report = json.load(f)

    findings = normalize(report)

    with open(args.out, "w") as f:
        json.dump(findings, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"Wrote {len(findings)} finding(s) to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

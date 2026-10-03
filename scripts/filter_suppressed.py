#!/usr/bin/env python3
"""Filter a findings file against a consumer repo's optional `.scaignore`
(YAML) suppression list, so a known, reviewed, time-boxed finding doesn't
keep blocking every PR.

There is deliberately no way to suppress "everything" or "every finding for
a package": a suppression always names a specific vulnerability id, always
carries a `reason` (for the next person reading it, not just the one who
wrote it), and always carries an `expires` date, after which it stops
applying and the finding re-appears - a suppression with no expiry would be
a silent, permanent exception that nobody is ever prompted to revisit. This
mirrors actions-sast-sonarqube's `.sastrc`: fail closed on anything that
doesn't match the schema, rather than let a typo look like "suppression
applied" when it wasn't.

`.scaignore` schema:

    suppressions:
      - id: GHSA-xxxx-xxxx-xxxx       # or CVE-YYYY-NNNNN - required
        package: cytoscape            # optional - omit to match this id for any package
        reason: "..."                 # required
        expires: "2027-01-01"         # required, YYYY-MM-DD

`id` is matched against a finding's own `id` AND its `relatedCve` (Grype
sometimes reports a GHSA with a CVE alias - see parse_findings.py - so a
suppression written against either form matches the same finding).
"""
import argparse
import datetime
import json
import os

import yaml

ALLOWED_TOP_LEVEL_KEYS = {"suppressions"}
ALLOWED_ENTRY_KEYS = {"id", "package", "reason", "expires"}
REQUIRED_ENTRY_KEYS = {"id", "reason", "expires"}


def _require_nonempty_str(value, desc):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f".scaignore: '{desc}' must be a non-empty string")
    return value


def _require_date(value, desc):
    _require_nonempty_str(value, desc)
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise ValueError(f".scaignore: '{desc}' must be a YYYY-MM-DD date, got {value!r}")


def parse_scaignore(text):
    """Parse and validate `.scaignore` YAML text into a list of suppression
    entries: [{"id": ..., "reason": ..., "expires": ..., "package": ...?}].
    `expires` stays a string here (the ISO text, schema-validated) - callers
    compare it as a date via filter_suppressed(), which is the one place
    "today" actually matters.

    Empty/blank text, or a `suppressions:` key holding an empty list, is a
    valid empty config - same "file absent or empty reproduces today's
    behavior exactly" guarantee .sastrc makes. Anything that doesn't match
    the schema - an unknown key, a missing required field, a malformed date
    - raises ValueError naming the offending field, rather than silently
    dropping or guessing at the entry.
    """
    if not text.strip():
        return []

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f".scaignore is not valid YAML: {e}")

    if data is None:
        return []
    if not isinstance(data, dict):
        raise ValueError(".scaignore must be a YAML mapping at the top level")

    unknown = set(data) - ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(f".scaignore has unrecognized top-level key(s): {', '.join(sorted(unknown))}")

    raw_entries = data.get("suppressions", [])
    if not isinstance(raw_entries, list):
        raise ValueError(".scaignore: 'suppressions' must be a list")

    entries = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            raise ValueError(".scaignore: each suppression entry must be a mapping")

        unknown = set(raw_entry) - ALLOWED_ENTRY_KEYS
        if unknown:
            raise ValueError(f".scaignore: suppression entry has unrecognized key(s): {', '.join(sorted(unknown))}")

        missing = REQUIRED_ENTRY_KEYS - set(raw_entry)
        if missing:
            raise ValueError(f".scaignore: suppression entry is missing required field(s): {', '.join(sorted(missing))}")

        entry = {
            "id": _require_nonempty_str(raw_entry["id"], "id"),
            "reason": _require_nonempty_str(raw_entry["reason"], "reason"),
            "expires": raw_entry["expires"],
        }
        _require_date(entry["expires"], "expires")  # validated, kept as the original string
        if "package" in raw_entry:
            entry["package"] = _require_nonempty_str(raw_entry["package"], "package")

        entries.append(entry)

    return entries


def _matches(entry, finding):
    finding_ids = {finding.get("id"), finding.get("relatedCve")}
    if entry["id"] not in finding_ids:
        return False
    if "package" in entry and entry["package"] != finding.get("package"):
        return False
    return True


def _is_expired(entry, today):
    # Exclusive: a suppression expiring on `today` no longer applies today,
    # so it can't coast on its own expiry date by being re-checked at
    # exactly midnight on the day it lapses.
    return datetime.date.fromisoformat(entry["expires"]) <= today


class FilterResult:
    """kept: findings with no currently-active matching suppression - what
    the blocking policy should actually evaluate.
    suppressed: [{"finding": ..., "suppression": ...}] for each finding a
    current (non-expired) suppression matched.
    expired: [{"finding": ..., "suppression": ...}] for each finding whose
    only matching suppression(s) have expired - the finding is back in
    `kept`, but this is surfaced so a stale .scaignore entry doesn't go
    unnoticed purely because nobody is reading the raw findings list."""

    def __init__(self, kept, suppressed, expired):
        self.kept = kept
        self.suppressed = suppressed
        self.expired = expired


def _resolve_match(finding, suppressions, today):
    """The one matching suppression that decides a finding's fate, plus the
    first expired one seen along the way (for the case where only an
    expired entry matches - see filter_suppressed()). An active match wins
    outright and stops the search; an expired match is remembered but
    doesn't stop it, since a later entry might still actively suppress the
    same finding."""
    active_match = None
    expired_match = None
    for entry in suppressions:
        if not _matches(entry, finding):
            continue
        if not _is_expired(entry, today):
            return entry, expired_match
        expired_match = expired_match or entry
    return active_match, expired_match


def filter_suppressed(findings, suppressions, today):
    kept = []
    suppressed = []
    expired = []
    for finding in findings:
        active_match, expired_match = _resolve_match(finding, suppressions, today)
        if active_match is not None:
            suppressed.append({"finding": finding, "suppression": active_match})
        else:
            kept.append(finding)
            if expired_match is not None:
                expired.append({"finding": finding, "suppression": expired_match})
    return FilterResult(kept, suppressed, expired)


def _format_entry(entry):
    package = f" on `{entry['package']}`" if "package" in entry else ""
    return f"`{entry['id']}`{package} (expires {entry['expires']}): {entry['reason']}"


def build_summary(result):
    lines = []
    if result.suppressed:
        lines.append(f"{len(result.suppressed)} finding(s) suppressed by `.scaignore`:")
        for item in result.suppressed:
            lines.append(f"- {_format_entry(item['suppression'])}")
    if result.expired:
        if lines:
            lines.append("")
        lines.append(
            f"{len(result.expired)} `.scaignore` suppression(s) have expired and no longer apply "
            "- the finding(s) below are active again:"
        )
        for item in result.expired:
            finding = item["finding"]
            lines.append(f"- {finding['id']} in {finding['package']}@{finding['version']}: {_format_entry(item['suppression'])}")
    if not lines:
        lines.append("No `.scaignore` suppressions matched.")
    return "\n".join(lines)


def main():  # pragma: no cover - CLI glue, validated live
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="Path to findings JSON (diff_findings.py's new-findings output)")
    parser.add_argument("--config", required=True, help="Path to an optional .scaignore file (need not exist)")
    parser.add_argument("--out", required=True, help="Path to write the kept (non-suppressed) findings JSON to")
    parser.add_argument(
        "--today",
        help="Override today's date (YYYY-MM-DD) for expiry comparisons - testing only; omit in real runs.",
    )
    args = parser.parse_args()

    text = ""
    if os.path.isfile(args.config):
        with open(args.config) as f:
            text = f.read()

    try:
        suppressions = parse_scaignore(text)
    except ValueError as e:
        raise SystemExit(f"Invalid .scaignore: {e}")

    with open(args.findings) as f:
        findings = json.load(f)

    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    result = filter_suppressed(findings, suppressions, today)

    with open(args.out, "w") as f:
        json.dump(result.kept, f, indent=2, sort_keys=True)
        f.write("\n")

    print(build_summary(result))


if __name__ == "__main__":
    main()

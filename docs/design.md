# Design notes

Architecture-level rationale that doesn't belong in the README (a usage
guide) or in a single script's comments (not tied to one line of code). Add
to this file as more such decisions come up.

## Why no ephemeral server, unlike actions-sast-sonarqube?

Syft and grype are pure CLI tools - syft reads a directory on disk and
writes an SBOM, grype reads that SBOM and writes a vulnerability report.
Neither needs a database or a running service the way SonarQube Community
Build does. `action.yml` runs both directly via pinned `docker run`
invocations (`scripts/run_scan.sh`); there is no `docker compose up -d` /
`down -v` pair anywhere in this repo.

`docker-compose.tools.yml` still exists despite that - not to be brought up,
but as a single Dependabot-tracked place pinning both image tags, which
`run_scan.sh` reads back at run time (`docker compose config --images`).
Same trick actions-sast-sonarqube's `docker-compose.ephemeral.yml` uses for
its inert `scanner` service, repurposed here since there's no real stack to
declare alongside it.

## Grype vulnerability DB caching is a speed optimization, not a correctness dependency

`action.yml` wraps the scan in an `actions/cache@v4` step keyed by
`grype-db-<os>-<pinned grype version>-<date>` (daily, not weekly - this is a
vulnerability database, and a week-old cache could mean genuinely missing a
CVE disclosed days ago). This matters for correctness reasoning: grype
itself checks the cached DB's build/staleness metadata against its upstream
DB service on every run and re-downloads if it's out of date, regardless of
what the cache step restored. A stale cache hit costs a slower run (grype
re-downloads on top of it), never stale results served silently. The cache
key's date granularity is therefore about keeping *most* runs fast, not
about bounding how stale a result can be - that bound comes from grype's own
update check.

## Why `diff_findings.py`'s `--changed-files` filter matters more here than in SAST

A SAST finding is purely a function of the source code - it can only appear
"new" if the code changed. An SCA finding is also a function of the
vulnerability database, which moves independently of any commit: a
dependency nobody touched can grow a new CVE between a baseline scan and a
later PR scan purely because grype's DB updated in between.
`sca-pr.yml` reuses `diff_findings.py`'s `--changed-files` filter (matching
a finding's `path` - i.e. the manifest/lockfile - against files the PR
actually touched) specifically to exclude that DB-drift noise from the PR's
blocking policy: a PR should only be blocked for vulnerabilities it
introduced, not for a CVE published overnight against a dependency it never
touched. DB-drift findings aren't discarded - they're just not this PR's
problem to fix. That's what `sca-mainline.yml` exists to catch instead,
deliberately *without* that filter (see its own header comment).

## Why "Unknown" severity is kept as real data, not silently reclassified

Grype legitimately reports `severity: "Unknown"` for a vulnerability with no
CVSS score yet - that's informational (a human should look), not a
data-quality problem the way a missing/garbage value from a persisted old
artifact would be. `parse_findings.py` keeps it verbatim rather than folding
it into a fallback bucket. But `SEVERITY_ORDER` (the ordered, comparable
scale `apply_policy.py` uses for threshold decisions) deliberately excludes
it - "Unknown" isn't "worse than Critical" or "better than Negligible", it's
a different kind of value that can't be placed on that axis at all.
`severity_for_comparison()` collapses it (and anything else off the ordered
scale) onto `UNKNOWN_SEVERITY_FALLBACK = "High"` purely for the threshold
comparison, so an unscored vulnerability can never silently pass a gate by
comparing as the lowest possible risk. Reports and counts still show
"Unknown" as itself.

## Why `sca-mainline.yml` skips alerting on its first run per branch

`find_baseline_artifact.py`'s "newest by created_at" tie-break (already used
unmodified for `sca-mainline-<branch>`'s mutable artifact name) means the
very first scheduled run for a branch finds nothing to diff against. Diffing
against an empty baseline there would report every pre-existing finding as
"new" - which is true in the diffing sense but not useful as an alert: it's
not drift, it's just the current state, and a repo could have dozens of
findings on day one that nobody has failed to act on, they simply haven't
been surfaced through this channel before. The workflow detects this case
(`steps.previous.outputs.found != 'true'`) and skips the diff/alert steps
entirely, just recording in the step summary that this run establishes the
baseline. Every subsequent scheduled run has something real to diff against.

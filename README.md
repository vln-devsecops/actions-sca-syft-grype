# actions-sca-syft-grype

Software composition analysis (SCA) using [syft](https://github.com/anchore/syft)
(SBOM generation) and [grype](https://github.com/anchore/grype)
(vulnerability scanning) — both free, both open source, both plain CLI tools
run via pinned Docker images. Three triggers:

1. **push to a baseline branch** (`main`, or any branch that's a PR target
   under branch protection): full scan, findings published as a build
   artifact keyed by commit SHA.
2. **pull_request**: scans PR HEAD, diffs the result against the baseline
   findings for the PR's branch-off point, and surfaces only *new* findings
   as GitHub Check Run annotations (plus, by default, a PR summary comment).
   Can optionally fail the job on policy violation.
3. **schedule** (wired by the consumer repo, not this action): re-scans a
   branch's current state and alerts on drift - a dependency nobody touched
   growing a new CVE because grype's vulnerability database updated. Opens
   or updates a tracking GitHub Issue, and can optionally fail the scheduled
   job as a second alert channel. This overlaps with GitHub's own Dependabot
   alerts by design - it's a second, independently-tunable signal, not a
   replacement.

No persistent syft/grype server (there isn't one to run - both are
stateless CLI tools), no SaaS dependency scanning product, and no reliance
on a paid tier. New-finding detection is done client-side by this action,
diffing two independent flat scans.

## How it works

```
docker-compose.tools.yml       Inert - never brought up. Pins the exact
                                syft/grype image tags Dependabot tracks;
                                scripts/run_scan.sh reads them back at run
                                time so a version bump never touches two
                                files. See docs/design.md for why there's no
                                docker-compose *up* anywhere in this repo.

action.yml                     Composite action: "run syft + grype against a
                                checked-out directory, return normalized
                                findings JSON plus a human-readable Markdown
                                report." Used by all three workflows below
                                so scan logic lives in exactly one place.
                                Also wires up an actions/cache step for
                                grype's vulnerability DB (see docs/design.md
                                - a speed optimization, not a correctness
                                dependency).

.github/workflows/
  sca-baseline.yml              Reusable workflow (workflow_call). Scans HEAD
                                 of a push to a baseline branch, uploads the
                                 SBOMs (syft-json and CycloneDX), findings
                                 (JSON), and report (Markdown) as artifact
                                 "sca-baseline-<sha>".

  sca-pr.yml                    Reusable workflow (workflow_call). Resolves a
                                 baseline (see below), scans PR HEAD, diffs,
                                 applies a blocking policy, posts a Check Run
                                 + PR comment.

  sca-mainline.yml               Reusable workflow (workflow_call), meant to
                                 be triggered by the consumer's own
                                 `schedule:` block. Re-scans the branch's
                                 current state, diffs against the last
                                 mainline scan (a rolling artifact, not
                                 SHA-keyed), and opens/updates a tracking
                                 Issue on drift. See docs/design.md for why
                                 the first run per branch never alerts.

  ci.yml                        This repo's own CI: calls all three reusable
                                 workflows above against fixtures/, on every
                                 push to dev, every PR, and (mainline only)
                                 on-demand via workflow_dispatch.
```

See [`docs/design.md`](docs/design.md) for architecture-level rationale.

### Baseline resolution for PRs

`sca-pr.yml` tries, in order:

1. **Tier a**: artifact `sca-baseline-<merge-base-sha>` - the commit the PR
   actually branched off from. This is what most PRs hit, since the baseline
   workflow runs on every push to the target branch.
2. **Tier b**: artifact `sca-baseline-<target-branch-HEAD-sha>` - a
   reasonable second choice when (1) aged out or predates the baseline
   workflow's existence.
3. **Fallback**: neither artifact exists. Scan the target branch's *current*
   HEAD live, in the same job, as the baseline (not the merge-base - simpler,
   and it's already the second-preference target anyway).

Which tier fired is recorded in the job's step summary and in the PR
comment.

`actions/download-artifact` alone can only see artifacts from the *same*
run. Finding "whichever artifact happens to be named `sca-baseline-<sha>`"
needs a name-filtered listing across the whole repo, so
`scripts/find_baseline_artifact.py` calls the REST API directly
(`GET /repos/{owner}/{repo}/actions/artifacts?name=...`). The same script,
unmodified, also resolves `sca-mainline.yml`'s rolling (non-SHA-keyed)
artifact - see its docstring.

### New-finding matching

Two findings across independent scans are the same vulnerability if they
share `(id, purl, path)` - the exact vulnerability ID, on the exact same
package instance, at the exact same manifest/lockfile path. There's no
line-number churn problem here (a dependency finding isn't tied to a source
line), so this is a straight tuple match - see `scripts/parse_findings.py`'s
`finding_key`, reused by `diff_findings.py`.

**Why `--changed-files` filtering matters**: an SCA finding is a
function of the vulnerability database, which moves independently of any
commit. `sca-pr.yml` filters new findings down to the manifest/lockfile
paths the PR actually touched, specifically to exclude "the database moved
under an untouched dependency" from the PR's blocking policy - that's real,
but it isn't this PR's fault, and it's what `sca-mainline.yml` exists to
catch instead (deliberately, with no such filter). See `docs/design.md`.

### Findings report

Grype's scan leaves nothing running once the job ends, so there's no UI to
browse for finding detail afterward. `action.yml` renders one alongside the
findings JSON and the SBOM on every scan
(`scripts/render_findings_report.py`): a Markdown table of every finding
with its severity, package, installed version, fix availability, and exact
manifest/lockfile location, covering the full current finding set rather
than just what changed in one PR (Check Run annotations already cover new
findings inline for that).

`sca-baseline.yml` and `sca-mainline.yml` bundle it into their respective
artifacts alongside the JSON and SBOM. `sca-pr.yml` uploads the PR head
scan's report as its own artifact and links it from the job's step summary.

### Dependency scope: production vs. development

**By default, this scan only covers production dependencies.** For
ecosystems that distinguish the two (currently: JavaScript/npm), syft does
not catalog development-scoped dependencies (npm `devDependencies`) unless
told to, and this action doesn't tell it to - so a devDependency, however
vulnerable, is never in the SBOM and grype never evaluates it. A finding
report reading "No findings." looks identical whether the scan cleared your
dev tooling or never looked at it at all - the report's `Scope:` line at the
top states which happened.

Set `include-dev-dependencies: true` (an input on `action.yml` and all
three reusable workflows) to catalog both. Worth doing deliberately rather
than by default: a devDependency doesn't ship, but it does run with
repository credentials on CI - `event-stream` and the `ua-parser-js`
supply-chain compromises were both build-time devDependency compromises, the
exact class of incident this broader scope exists to catch. The tradeoff is
volume: a typical JS project's devDependency tree can be several times the
size of its production one, and most of what a broader scan surfaces (a
ReDoS in a linter, prototype pollution in a build tool) isn't reachable by
an attacker against the deployed service.

**Keep the setting consistent for a given repo.** `sca-pr.yml` and
`sca-mainline.yml` diff a fresh scan against a stored baseline scan; if the
two scans used different `include-dev-dependencies` settings, every
dependency that's newly in scope looks like a new finding, not a genuine
change. Both workflows check the setting recorded in the baseline artifact
against their own and fail the job with a clear error on a mismatch, rather
than let it through as a wall of false "new" findings.

Other ecosystems have the same production/development distinction (Python's
dev extras, Go's test-only requirements) and may get their own scope input
later; `include-dev-dependencies` is JavaScript-only for now.

### Blocking policy

Our own, evaluated only against the new-findings set - not any built-in
policy engine. Default: a new finding at severity `High` or `Critical`
fails the job. Configurable via `severity-threshold` / `blocking` inputs on
both `sca-pr.yml` and `sca-mainline.yml`.

Grype's severity scale is `Negligible < Low < Medium < High < Critical`,
plus a legitimate `Unknown` value for a vulnerability with no CVSS score
yet. `Unknown` is kept as real data in the findings JSON and reports, but
fails closed to `High` for threshold comparisons specifically - an unscored
vulnerability must never silently pass a gate by comparing as the lowest
possible risk. See `docs/design.md`.

### Recurring mainline scan

`sca-mainline.yml` exists because grype's vulnerability database is a
moving target independent of any commit. A consumer repo wires its own
`schedule:` trigger to it (see
`runbooks/sca-syft-grype.md` in the `guidance` repo for the exact block);
each run re-scans the branch, diffs against the last mainline scan, and:

- optionally fails the job (`blocking`, default `true`) - GitHub emails
  failed-scheduled-run notifications to watchers by default, so this alone
  is a usable alert channel with no further setup, and
- optionally opens (or comments on, if one's already open) a GitHub Issue
  (`create-issue`, default **false** - opt-in, since filing an issue is a
  more visible action than a job going red) tagged with `issue-labels`
  (default `security,sca-alert`) listing what's new.

The first scheduled run for a branch never alerts (nothing to diff against
yet - see `docs/design.md`); every run after that has a real prior scan to
compare to. This overlaps with GitHub's own Dependabot security alerts by
design - a second, independently-tunable signal against the same
dependencies, not a replacement for either. Other delivery channels (Slack,
a generic webhook) are a natural follow-up, tracked as an issue in this
repo rather than built here.

## Using this action from another repo

All three reusable workflows live in this repo and are meant to be called
from a consumer repo's own workflows:

```yaml
# consumer repo: .github/workflows/sca.yml
on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, reopened]
  schedule:
    - cron: "0 6 * * *"   # daily; pick a cadence that suits the repo

jobs:
  baseline:
    if: github.event_name == 'push'
    uses: vln-devsecops/actions-sca-syft-grype/.github/workflows/sca-baseline.yml@v1
    permissions:
      contents: read
    with:
      baseline-branches: '["main"]'

  pr-scan:
    if: github.event_name == 'pull_request'
    uses: vln-devsecops/actions-sca-syft-grype/.github/workflows/sca-pr.yml@v1
    permissions:
      contents: read
      checks: write
      pull-requests: write
      actions: read

  mainline:
    if: github.event_name == 'schedule'
    uses: vln-devsecops/actions-sca-syft-grype/.github/workflows/sca-mainline.yml@v1
    permissions:
      contents: read
      checks: write
      # issues: write   # only needed if you pass create-issue: true below
      actions: read
    with:
      create-issue: true   # opt-in - omit (or set false) to rely on the failed-job alert alone
```

Pin to a version tag, not `@main` or a commit SHA: this repo tags releases
via [release-please](https://github.com/googleapis/release-please). `@v1`
tracks the newest `1.x.y` release (picks up minor and patch updates); `@v1.2`
tracks the newest `1.2.z` patch only; an exact `@v1.2.3` never moves. Prefer
`@v1` unless you need tighter pinning.

**Fork PRs**: GitHub downgrades `GITHUB_TOKEN` to read-only for a
`pull_request` event from a fork, regardless of the `permissions:` block
above. `sca-pr.yml` still runs the full scan and diff, and still blocks the
job on policy the same as any other PR - it just can't publish the Check Run
or PR comment, since both need write access it doesn't have. Findings are
reported in the job's step summary instead in that case.

## Testing

```sh
pip install -r requirements-dev.txt
pytest tests/ -v
```

See [`docs/test-procedure.md`](docs/test-procedure.md) for everything else:
a full local end-to-end run, and how to deliberately exercise each
baseline-resolution tier, the changed-files filter, the blocking policy, and
the mainline scan's first-run-vs-drift behavior.

## Validation status

Rationale for specific implementation choices lives as comments next to the
code they affect - see `scripts/run_scan.sh`'s cache-directory handling and
`action.yml`'s grype DB cache step.

The pure-logic functions in each script (`scripts/*.py`) have a pytest suite
(`tests/`), gated on 95% coverage via
`vln-devsecops/actions-validate-coverage` in `ci.yml`. Network/CLI glue is
deliberately excluded from that gate and validated live instead, the same
way the rest of the pipeline is.

This repo is currently private and pre-v1: the full pipeline (scan → parse →
diff → policy) has been exercised against the fixtures in this repo's own
CI, but not yet against a real external consumer repo's PRs and scheduled
runs end to end - see `docs/test-procedure.md` for what that validation
looks like when it happens.

Artifact retention: 90 days for `sca-baseline-<sha>` (SHA-keyed), 14 days for the rolling
`sca-mainline-<branch>` artifact (superseded by every subsequent scheduled
run, so an old copy has no lasting value), 30 days for the per-PR findings
report.

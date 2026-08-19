# Test procedure

Manual steps to validate this action end to end. The automated coverage is
`tests/` (pytest, pure-logic functions only) plus `ci.yml` itself, which
exercises the real pipeline against `fixtures/` on every push to `dev` and
every PR - this document is for exercising the paths that don't fire on
every ordinary run, and for a human to work through when validating a
change that touches the scan/diff/policy pipeline itself.

## Prerequisites

- Docker, Python 3.12, `jq`, `shellcheck`
- Write access to this repo (to push test branches/PRs)
- For the artifact-deletion steps below: a token or UI access with
  permission to delete Actions artifacts. A plain `GITHUB_TOKEN` from a
  workflow run is *not* enough - expect `403 Resource not accessible by
  integration` otherwise.

## 1. Unit tests (local, fast, no Docker)

```sh
pip install -r requirements-dev.txt
pytest tests/ -v --cov=scripts --cov-report=term-missing
shellcheck scripts/*.sh
```

Expect all tests to pass and every file in the coverage table at (or very
close to) 100% - network/CLI-glue functions are marked `# pragma: no cover`
deliberately (see each script). Unlike actions-sast-sonarqube's
`fetch_findings.py`, `parse_findings.py` has no network I/O at all (grype
has already run and written its JSON by the time it runs), so it should
show full coverage with no exclusions.

## 2. Full pipeline against real syft/grype (local)

```sh
mkdir -p /tmp/sca-out
COMPOSE_FILE=docker-compose.tools.yml PROJECT_KEY=test-baseline \
  PROJECT_BASE_DIR=fixtures OUT_DIR=/tmp/sca-out/baseline \
  ./scripts/run_scan.sh
python3 scripts/parse_findings.py --report /tmp/sca-out/baseline/grype-raw.json \
  --out /tmp/baseline-findings.json

# "head" scan - copy fixtures/, tweak it, scan separately
cp -r fixtures /tmp/fixtures-head
# ...edit /tmp/fixtures-head to add/remove a vulnerable pin (see step 5 below)...
COMPOSE_FILE=docker-compose.tools.yml PROJECT_KEY=test-head \
  PROJECT_BASE_DIR=/tmp/fixtures-head OUT_DIR=/tmp/sca-out/head \
  ./scripts/run_scan.sh
python3 scripts/parse_findings.py --report /tmp/sca-out/head/grype-raw.json \
  --out /tmp/head-findings.json

python3 scripts/diff_findings.py --baseline /tmp/baseline-findings.json \
  --head /tmp/head-findings.json --out /tmp/new-findings.json
cat /tmp/new-findings.json
```

Confirm the fixtures' two known CVEs (see `fixtures/README.md`) both appear
in `/tmp/baseline-findings.json`.

`scripts/apply_policy.py`, `scripts/post_pr_comment.py`, and
`scripts/report_mainline_findings.py` need a real `GITHUB_TOKEN` and post to
a real repo/PR/issue - don't run those against this repo directly outside of
an actual PR or scheduled run; use a scratch repo, or trust the unit tests
for their logic and the live-run sections below.

## 3. Grype DB cache behavior (`action.yml`)

Run `action.yml`'s "Cache grype vulnerability DB" step twice in a row (e.g.
two pushes on the same UTC day) and confirm in the job logs: the first run
logs a cache miss and downloads the DB from scratch; the second logs a cache
hit and the scan noticeably shorter. This is a speed check only - see
`docs/design.md` for why a stale cache can never silently serve stale
results regardless of hit/miss.

## 4. Baseline publish (`sca-baseline.yml`, push trigger)

Push to `dev` (or merge a PR into it) and confirm in the Actions run:

1. `unit-tests` runs and passes first (`baseline` `needs: unit-tests`).
2. `baseline` job runs, uploads an artifact named `sca-baseline-<full-sha>`
   (visible under the run's Artifacts section) containing the SBOM, findings
   JSON, and Markdown report.

## 5. `sca-pr.yml`'s three baseline-resolution tiers

### Tier a - merge-base artifact exists (the common case)

Open a PR against `dev` from a branch forked off `dev`'s current HEAD
(which already has a `sca-baseline-<sha>` artifact from section 4). Expect
the step summary and PR comment to say `tier a: artifact for merge-base
<sha>`.

### Tier b - target branch's current HEAD artifact exists, merge-base's doesn't

Needs two divergent points on `dev` with only the newer one still having an
artifact - not something that happens naturally on a low-traffic branch, so
set it up deliberately:

1. Note `dev`'s current HEAD (`OLD`).
2. Branch a test PR off `OLD`.
3. Push a new commit to `dev` directly (or merge something else), producing
   a new HEAD (`NEW`) with its own fresh `sca-baseline-<NEW>` artifact.
4. Delete the artifact for `OLD` (see section 8 for how).
5. Open/refresh the PR from step 2 (still forked from `OLD`). Its
   merge-base is `OLD` (no artifact), but the target's current HEAD is
   `NEW` (has one) - tier b should fire.

Expect: `tier b: artifact for target branch HEAD <NEW sha>`.

### Fallback - neither artifact exists

Delete (see section 8) any `sca-baseline-*` artifacts for both the PR's
merge-base and the target branch's current HEAD, then open/refresh a PR.
Expect: `fallback: no artifact found, scanning target branch HEAD live in
this job`.

This is also what happens automatically the first time a PR is ever opened
against a repo (no baseline artifact has been published yet), or whenever
`project-base-dir` doesn't exist yet on the target branch - no manual
artifact deletion needed to exercise those specific cases.

## 6. Filtering by changed files

In a test PR, change **two** dependency pins at once:

- Introduce one genuinely new vulnerable pin under `project-base-dir`.
- In a different, untouched-by-this-PR manifest, note an existing finding
  that's still present (simulating "the DB drifted, this wasn't touched").

Expect `diff_findings.py`'s output (and the PR's new-findings count) to
contain exactly the genuinely new pin's finding(s) - not the untouched
manifest's, even if grype's DB happens to have changed something about it
between the baseline scan and this PR's scan. (`fixtures/js/package-lock.json`
and `fixtures/python/requirements.txt` are deliberately kept minimal
specifically so this kind of edit is easy to make by hand when testing.)

## 7. Blocking policy

Introduce a change that adds a Critical/High-severity vulnerable pin (or
reuse the existing fixtures, which trip two Critical findings by design) in
a test PR. Expect:

- `pr-scan` job conclusion: `failure`
- Check Run `sca-syft-grype/new-vulnerabilities`: conclusion `failure`
- PR comment: `**Blocked** - a new vulnerability finding meets or exceeds
  the ... threshold.`

Revert the change (or lower `severity-threshold` / set `blocking: false` as
inputs on `sca-pr.yml`) and confirm the same PR goes green without
re-triggering a scan - the gate should only care about current state.

## 8. `sca-mainline.yml`

This workflow only accepts `workflow_call` (see
`runbooks/sca-syft-grype.md` in the guidance repo for wiring a consumer's
own `schedule:` trigger to it); in this repo it's exercised via
`workflow_dispatch` on `ci.yml`. `create-issue` defaults to `false`
(opt-in), and `ci.yml`'s `mainline` job doesn't pass it, so a routine
dispatch never files a real issue against this repo - see step 3 for how to
exercise that path deliberately.

1. **First run for a branch**: with no `sca-mainline-<branch>` artifact yet
   published, dispatch `ci.yml`. Expect the step summary to say "this run
   establishes the baseline" and no tracking issue to be created, no matter
   how many findings `fixtures/` has.
2. **Drift detected**: dispatch again without changing `fixtures/`. Since
   the dependency pins didn't change, expect no new findings and no issue -
   confirms the diff is genuinely comparing scan-to-scan, not
   scan-to-nothing.
3. To actually exercise the alert path without waiting for a real CVE to be
   published against an unrelated pin: temporarily add a new vulnerable pin
   to `fixtures/`, dispatch once (this becomes the new rolling baseline via
   the artifact upload), then revert the fixture change and dispatch again -
   the second run's baseline still has the added pin's finding, so the
   revert makes it look like a fix, not a new drift finding. To simulate
   drift specifically (a finding appearing with **no** fixture change),
   there is no substitute for waiting on a real DB update - the fixtures'
   two CVEs are old and stable, so this isn't expected to happen
   spontaneously in normal testing. Prefer trusting `report_mainline_findings.py`'s
   unit tests for this script's logic, and confirm only the end-to-end
   wiring (artifact lookup, diff invocation, issue API calls) via a
   deliberately doctored `--new-findings` file if a live drift case is
   needed:
   ```sh
   echo '[{"id":"CVE-TEST","severity":"Critical","package":"test","version":"1.0.0","type":"test","purl":"pkg:generic/test@1.0.0","path":"test","fixState":"unknown","fixedIn":[],"dataSource":null,"relatedCve":null,"description":"synthetic"}]' > /tmp/fake-new.json
   GITHUB_TOKEN=<a real token> python3 scripts/report_mainline_findings.py \
     --repo <owner>/<scratch-repo> --new-findings /tmp/fake-new.json \
     --project-key test --run-url https://example.com
   ```
   Confirm a new issue opens with the `sca-syft-grype-action:mainline-alert:test`
   marker, then run it again and confirm it comments on the same issue
   instead of opening a second one.
4. Confirm `sca-mainline-<branch>` re-uploads on every run (`if: always()`),
   including when the blocking-policy step fails the job.

## 9. Deleting a baseline or mainline artifact

Needed for section 5 (tier b, fallback) and for general cleanup after
testing. Either:

- GitHub UI: the workflow run's page → Artifacts section → the artifact's
  "…" menu → Delete.
- API (needs a token with artifact-delete permission - a workflow's own
  `GITHUB_TOKEN` does not have it):
  ```sh
  curl -X DELETE -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/<owner>/<repo>/actions/artifacts/<artifact_id>"
  ```
  Find `<artifact_id>` via
  `GET /repos/<owner>/<repo>/actions/artifacts?name=sca-baseline-<sha>` (or
  `name=sca-mainline-<branch>`).

## 10. Cleanup after manual testing

- Close/delete scratch branches and PRs created for this procedure.
- Delete any `sca-baseline-*`/`sca-mainline-*` artifacts created purely for
  testing, so they don't linger and skew a later real PR's or scheduled
  run's baseline resolution.
- Close any tracking issues opened by section 8's live test.
- Revert any deliberate `fixtures/` changes made for section 6 or 7 that
  weren't meant to be permanent.

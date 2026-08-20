# Fixtures

Deliberately vulnerable dependency pins used to smoke-test this action's own
`ci.yml` end to end (syft SBOM generation, grype vulnerability scan, findings
normalization, diffing, and the blocking policy) against real, known CVEs -
not synthetic ones a scanner is unlikely to actually recognize.

| Path | Pin | CVE | Severity |
| --- | --- | --- | --- |
| `js/package-lock.json` | `lodash@4.17.11` | CVE-2019-10744 (prototype pollution) | Critical |
| `python/requirements.txt` | `PyYAML==5.1` | CVE-2020-1747 (arbitrary code execution via `yaml.load`) | Critical |

Do not "fix" these pins without also updating `README.md` and
`docs/test-procedure.md`'s notes on what `ci.yml` expects to find - the
point of both is to reliably trip Grype against a real advisory.

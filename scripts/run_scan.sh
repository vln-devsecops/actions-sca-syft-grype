#!/usr/bin/env bash
# Run syft against PROJECT_BASE_DIR to produce an SBOM, then run grype
# against that SBOM to produce a raw vulnerability report. Both tools are
# pure CLI, invoked via pinned `docker run` images (see docker-compose.tools.yml)
# - no server to wait for, no bootstrap step, unlike actions-sast-sonarqube's
# run_scan.sh.
#
# Required env: PROJECT_BASE_DIR, PROJECT_KEY, COMPOSE_FILE (path to
#                docker-compose.tools.yml, used only to read back the pinned
#                syft/grype image tags), OUT_DIR (directory to write
#                sbom.json and grype-raw.json into)
# Optional env:  SCAN_TIMEOUT_SECONDS (default 900, applied per tool)
#                GRYPE_DB_CACHE_DIR (host dir for grype's vulnerability DB
#                cache; if unset, a throwaway mktemp -d is used and cleaned
#                up on exit - action.yml normally sets this to a path an
#                actions/cache step manages, for speed across runs; see
#                docs/design.md)
set -euo pipefail

: "${PROJECT_BASE_DIR:?PROJECT_BASE_DIR is required}"
: "${PROJECT_KEY:?PROJECT_KEY is required}"
: "${COMPOSE_FILE:?COMPOSE_FILE is required}"
: "${OUT_DIR:?OUT_DIR is required}"

SCAN_TIMEOUT_SECONDS="${SCAN_TIMEOUT_SECONDS:-900}"

if [[ ! -d "$PROJECT_BASE_DIR" ]]; then
  echo "PROJECT_BASE_DIR '${PROJECT_BASE_DIR}' does not exist or is not a directory." >&2
  exit 1
fi
ABS_PROJECT_BASE_DIR="$(cd "$PROJECT_BASE_DIR" && pwd)"

mkdir -p "$OUT_DIR"
ABS_OUT_DIR="$(cd "$OUT_DIR" && pwd)"

# Single source of truth for both tool versions is docker-compose.tools.yml,
# so a Dependabot bump there never has to also touch this script.
SYFT_IMAGE="$(docker compose -f "$COMPOSE_FILE" --profile tools config --images 2>/dev/null | grep '/syft:' | head -1)"
GRYPE_IMAGE="$(docker compose -f "$COMPOSE_FILE" --profile tools config --images 2>/dev/null | grep '/grype:' | head -1)"
if [[ -z "$SYFT_IMAGE" || -z "$GRYPE_IMAGE" ]]; then
  echo "Could not resolve the syft/grype images from ${COMPOSE_FILE}." >&2
  exit 1
fi
echo "Using syft image: ${SYFT_IMAGE}"
echo "Using grype image: ${GRYPE_IMAGE}"

# Both images run as a baked-in non-root user by default, whose home
# directory (where syft/grype would otherwise cache config/state) isn't
# writable by whichever host uid we run as instead - same reasoning as
# actions-sast-sonarqube's run_scan.sh SCANNER_CACHE_DIR trick. --user
# matches the host checkout owner so bind-mounted output is writable; HOME=/tmp
# sidesteps the unwritable baked-in home dir (each container gets its own
# /tmp, world-writable by the sticky bit, regardless of --user).
if [[ -n "${GRYPE_DB_CACHE_DIR:-}" ]]; then
  CLEANUP_GRYPE_DB_CACHE_DIR=false
else
  GRYPE_DB_CACHE_DIR="$(mktemp -d)"
  CLEANUP_GRYPE_DB_CACHE_DIR=true
fi
mkdir -p "$GRYPE_DB_CACHE_DIR"
if [[ "$CLEANUP_GRYPE_DB_CACHE_DIR" == "true" ]]; then
  trap 'rm -rf "${GRYPE_DB_CACHE_DIR}"' EXIT
fi

echo "Generating SBOM for ${ABS_PROJECT_BASE_DIR} (project '${PROJECT_KEY}')..."
timeout "${SCAN_TIMEOUT_SECONDS}" docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "${ABS_PROJECT_BASE_DIR}:/src:ro" \
  -v "${ABS_OUT_DIR}:/out" \
  "${SYFT_IMAGE}" \
  dir:/src -o syft-json=/out/sbom.json

if [[ ! -f "${ABS_OUT_DIR}/sbom.json" ]]; then
  echo "syft did not produce ${ABS_OUT_DIR}/sbom.json." >&2
  exit 1
fi

echo "Scanning SBOM for vulnerabilities..."
timeout "${SCAN_TIMEOUT_SECONDS}" docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GRYPE_DB_CACHE_DIR=/grype-db-cache \
  -v "${ABS_OUT_DIR}:/out" \
  -v "${GRYPE_DB_CACHE_DIR}:/grype-db-cache" \
  "${GRYPE_IMAGE}" \
  sbom:/out/sbom.json -o json > "${ABS_OUT_DIR}/grype-raw.json"
  # No --fail-on here deliberately: grype exiting non-zero on a severity
  # threshold is not this script's concern - apply_policy.py evaluates the
  # blocking policy downstream, against the diffed/normalized findings, not
  # against grype's own raw per-scan opinion.

if [[ ! -s "${ABS_OUT_DIR}/grype-raw.json" ]]; then
  echo "grype did not produce a non-empty ${ABS_OUT_DIR}/grype-raw.json." >&2
  exit 1
fi

echo "Wrote ${ABS_OUT_DIR}/sbom.json and ${ABS_OUT_DIR}/grype-raw.json."

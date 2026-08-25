#!/usr/bin/env bash
# Run syft against PROJECT_BASE_DIR to produce an SBOM, then run grype
# against that SBOM to produce a raw vulnerability report. Both tools are
# pure CLI, invoked via pinned `docker run` images (see docker-compose.tools.yml)
# - no server to wait for, no bootstrap step.
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
#                INCLUDE_DEV_DEPENDENCIES ("true"/"false", default "false") -
#                forwarded to syft's javascript cataloger as
#                SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES. syft's own default
#                is false (production dependencies only); see README.md.
#                EXCLUDE_PATHS (default "") - newline-separated paths,
#                relative to PROJECT_BASE_DIR, to exclude from the syft
#                catalogue. Needed because a calling workflow may check
#                itself (or a baseline commit) out into a side directory
#                alongside PROJECT_BASE_DIR when that's the repo root - see
#                action.yml's exclude-paths input.
set -euo pipefail

: "${PROJECT_BASE_DIR:?PROJECT_BASE_DIR is required}"
: "${PROJECT_KEY:?PROJECT_KEY is required}"
: "${COMPOSE_FILE:?COMPOSE_FILE is required}"
: "${OUT_DIR:?OUT_DIR is required}"

SCAN_TIMEOUT_SECONDS="${SCAN_TIMEOUT_SECONDS:-900}"
INCLUDE_DEV_DEPENDENCIES="${INCLUDE_DEV_DEPENDENCIES:-false}"
EXCLUDE_PATHS="${EXCLUDE_PATHS:-}"

# syft requires excluded paths to start with "./", "*/", or "**/" - build
# that glob from each plain relative path rather than push that syntax onto
# every caller of this script (and of action.yml's exclude-paths input).
SYFT_EXCLUDE_ARGS=()
while IFS= read -r exclude_path; do
  exclude_path="${exclude_path#./}"
  [[ -z "$exclude_path" ]] && continue
  SYFT_EXCLUDE_ARGS+=(--exclude "./${exclude_path}/**")
done <<<"$EXCLUDE_PATHS"

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
# writable by whichever host uid we run as instead. --user matches the host
# checkout owner so bind-mounted output is writable.
#
# HOME=/tmp alone is NOT enough: these images' baked-in /tmp is root-owned
# and not world-writable, so a non-root --user
# gets a bare "permission denied" trying to create anything under it -
# confirmed live (grype fatally fails "unable to create listing temp file"
# for a DB-metadata temp file it writes straight to $TMPDIR, entirely
# separate from GRYPE_DB_CACHE_DIR below). Bind-mount a host-created,
# already-correctly-owned directory over /tmp instead of trusting the
# image's own one.
TOOL_TMP_DIR="$(mktemp -d)"

if [[ -n "${GRYPE_DB_CACHE_DIR:-}" ]]; then
  CLEANUP_GRYPE_DB_CACHE_DIR=false
else
  GRYPE_DB_CACHE_DIR="$(mktemp -d)"
  CLEANUP_GRYPE_DB_CACHE_DIR=true
fi
mkdir -p "$GRYPE_DB_CACHE_DIR"

# One trap covers both scratch dirs - TOOL_TMP_DIR always, GRYPE_DB_CACHE_DIR
# only when this script created it itself (a caller-supplied cache dir, e.g.
# action.yml's actions/cache-managed path, is the caller's to clean up).
cleanup() {
  rm -rf "${TOOL_TMP_DIR}"
  if [[ "$CLEANUP_GRYPE_DB_CACHE_DIR" == "true" ]]; then
    rm -rf "${GRYPE_DB_CACHE_DIR}"
  fi
}
trap cleanup EXIT

echo "Generating SBOM for ${ABS_PROJECT_BASE_DIR} (project '${PROJECT_KEY}')..."
# Two -o flags, one syft invocation: same process, same filesystem walk,
# just a second output writer. syft-json remains what grype reads below;
# the CycloneDX copy is purely an additional artifact for downstream
# consumers that expect that standard format instead of syft's own schema.
timeout "${SCAN_TIMEOUT_SECONDS}" docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES="${INCLUDE_DEV_DEPENDENCIES}" \
  -v "${ABS_PROJECT_BASE_DIR}:/src:ro" \
  -v "${ABS_OUT_DIR}:/out" \
  -v "${TOOL_TMP_DIR}:/tmp" \
  "${SYFT_IMAGE}" \
  dir:/src \
  -o syft-json=/out/sbom.json \
  -o cyclonedx-json=/out/sbom.cdx.json \
  ${SYFT_EXCLUDE_ARGS[@]+"${SYFT_EXCLUDE_ARGS[@]}"}

if [[ ! -f "${ABS_OUT_DIR}/sbom.json" ]]; then
  echo "syft did not produce ${ABS_OUT_DIR}/sbom.json." >&2
  exit 1
fi

if [[ ! -f "${ABS_OUT_DIR}/sbom.cdx.json" ]]; then
  echo "syft did not produce ${ABS_OUT_DIR}/sbom.cdx.json." >&2
  exit 1
fi

# Cheap regression guard: if an excluded path still shows up as a location
# in the SBOM, the --exclude glob above silently stopped matching (e.g. a
# caller passed a path with different casing/trailing slash, or syft's
# --exclude semantics changed) - fail loudly here rather than let phantom
# findings from a side directory reach a consumer's PR.
for exclude_path in ${SYFT_EXCLUDE_ARGS[@]+"${SYFT_EXCLUDE_ARGS[@]}"}; do
  [[ "$exclude_path" == "--exclude" ]] && continue
  name="${exclude_path#./}"
  name="${name%/**}"
  if ! jq -e --arg pattern "(^|/)${name}/" \
    '[.artifacts[]?.locations[]?.path // empty | select(test($pattern))] | length == 0' \
    "${ABS_OUT_DIR}/sbom.json" >/dev/null; then
    echo "SBOM contains a location under excluded path '${name}/' - the syft --exclude glob did not match. Refusing to publish a scan that catalogues this action's own working directories." >&2
    exit 1
  fi
done

echo "Scanning SBOM for vulnerabilities..."
timeout "${SCAN_TIMEOUT_SECONDS}" docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e GRYPE_DB_CACHE_DIR=/grype-db-cache \
  -v "${ABS_OUT_DIR}:/out" \
  -v "${GRYPE_DB_CACHE_DIR}:/grype-db-cache" \
  -v "${TOOL_TMP_DIR}:/tmp" \
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

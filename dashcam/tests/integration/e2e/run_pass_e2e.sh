#!/bin/sh
#
# run_pass_e2e.sh — tenet pass-level E2E test suite entry point (macOS arm64)
#
# Builds the multi-scenario qbditrace test harness ONCE (see
# lib.sh:build_harness_once), then sources each pass_*.sh suite in turn. Every
# suite calls run_scenario()/run_tenet()/assert_*() from lib.sh against the
# shared harness binary — no suite recompiles anything itself.
#
# This complements (does not replace) run_e2e_tests.sh, which validates the
# qbditrace *record* layer (raw `tenet --dump` output: INST/ANCHOR/SVC/OBJC
# records exist, header integrity, etc). This suite validates the tenet
# *analysis pass* layer one level up: given those same records, does each
# registered AnalysisPass (xref, cfg, taint, pattern, objc, syscall_intercept,
# entropy, ...) actually produce the expected result on a real recorded trace?
#
# Requirements:
#   - macOS arm64
#   - QBDI static libs at <repo>/build-macos/{libQBDI.a,libqbdi-llvm.a}
#   - tenet binary at <repo>/tools/tenet/build/tenet
#
# Usage:
#   sh run_pass_e2e.sh              # run all suites
#   sh run_pass_e2e.sh platform     # run only pass_platform.sh
#   sh run_pass_e2e.sh platform taint  # run a subset, by suite short name
#
# Exit code: 0 = all pass, non-zero = failure count (capped at 255 by sh).
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../../../.." && pwd -P)"
TRACE_DIR="${ROOT}/tools/qbditrace"
BUILD="${ROOT}/build-macos"
TENET="${ROOT}/tools/tenet/build/tenet"
HARNESS="/tmp/e2e_pass_harness"

die() { echo "FATAL: $*" >&2; exit 1; }

[ -f "${BUILD}/libQBDI.a" ] || die "libQBDI.a not found at ${BUILD}/ (see CLAUDE.md build instructions)"
[ -x "${TENET}" ] || die "tenet not found at ${TENET} (cd tools/tenet/build && ninja)"

# shellcheck source=./lib.sh
. "${HERE}/lib.sh"

log "Building shared multi-scenario harness (core + crypto + profile)..."
build_harness_once "${HARNESS}" || die "harness build failed"

# ─── Suite registry ──────────────────────────────────────────────────────────
# short name -> script file. Keep in dependency-free, roughly-fastest-first
# order; each suite is independent (no suite depends on another's trace
# files) so order does not affect correctness, only failure-report locality.
ALL_SUITES="platform structure taint memory crypto profile"

suites_to_run="$*"
if [ -z "${suites_to_run}" ]; then
    suites_to_run="${ALL_SUITES}"
fi

for suite in ${suites_to_run}; do
    script="${HERE}/pass_${suite}.sh"
    if [ ! -f "${script}" ]; then
        die "unknown suite '${suite}' (no ${script})"
    fi
    log ""
    log "═══ suite: ${suite} ═══"
    # shellcheck source=/dev/null
    . "${script}"
done

log ""
log "═══════════════════════════════════════════════════════════"
log "  Pass E2E Results: ${PASS} passed, ${FAIL} failed (total ${TOTAL})"
log "═══════════════════════════════════════════════════════════"

# ─── Cleanup ──────────────────────────────────────────────────────────────
# Every suite writes its trace(s) under /tmp/e2e_pass_<suite>_*.bin (see each
# pass_*.sh's TRACE_DIR-local variables) plus tenet's .image/.tenet (RocksDB
# index)/.dSYM sidecars, and the shared scratch logs (e2e_harness.log,
# e2e_decode.log, e2e_out.log). Cleaned up centrally here (rather than by each
# suite) so suites stay focused on "record trace + run pass + assert" and
# cleanup policy stays in one place.
rm -rf /tmp/e2e_pass_*.bin /tmp/e2e_pass_*.bin.image /tmp/e2e_pass_*.tenet \
       /tmp/e2e_harness.log /tmp/e2e_decode.log /tmp/e2e_out.log \
       "${HARNESS}" "${HARNESS}.dSYM"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0

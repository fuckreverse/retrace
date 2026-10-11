#!/bin/sh
#
# lib.sh — shared build/run/assert helpers for the pass-level E2E suites
# (pass_platform.sh, pass_structure.sh, pass_taint.sh, pass_memory.sh,
# pass_crypto.sh, pass_profile.sh) and their entry point run_pass_e2e.sh.
#
# Not runnable standalone: `. ./lib.sh` from a suite script after `set -e` /
# `set -u` are configured by the caller (run_pass_e2e.sh sets ROOT/etc. and
# sources this file, then sources each pass_*.sh suite in turn).
#
# Environment this file expects to already be set by run_pass_e2e.sh:
#   ROOT       - repo root (abs path)
#   TRACE_DIR  - dashcam
#   BUILD      - dashcam/../../build-macos (QBDI static libs)
#   TENET      - slowmo/build/tenet binary
#   HARNESS    - compiled multi-scenario harness binary (built once by
#                run_pass_e2e.sh via build_harness_once(), see below)
#
# Public functions:
#   run_scenario <scenario> <out.bin> [seed]
#       Runs HARNESS for the given scenario ("core"|"crypto"|"profile"),
#       writing harness stdout/stderr to /tmp/e2e_harness.log and the trace
#       to <out.bin>. Sets $LAST_RC to the harness exit code.
#   dump_trace <trace.bin>
#       Runs `tenet --dump text` on the trace, output to /tmp/e2e_decode.log.
#   run_tenet <trace.bin> <tenet-args...>
#       Runs tenet with arbitrary args against <trace.bin>, output to
#       /tmp/e2e_out.log. Does NOT abort the suite on nonzero exit (tenet
#       returns nonzero on pass failure, which some assertions want to
#       inspect directly).
#   assert_semantic_ok <desc>
#       Passes if /tmp/e2e_harness.log shows the instrumented/native
#       checksum matched.
#   assert_in <desc> <logfile> <pattern>
#   assert_not_in <desc> <logfile> <pattern>
#       grep -q wrappers against an arbitrary log file, with pass/fail
#       bookkeeping.
#   assert_tenet_ok <desc>
#       Passes if the last run_tenet invocation exited 0.
#   pass_ / fail_ / log
#       Bookkeeping + colored output primitives (mirrors the existing
#       run_e2e_tests.sh conventions so output styles stay consistent).
#
# Each suite script increments the shared PASS/FAIL/TOTAL counters declared
# here; run_pass_e2e.sh prints one grand summary after sourcing all suites.

PASS=${PASS:-0}
FAIL=${FAIL:-0}
TOTAL=${TOTAL:-0}

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
pass_() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); printf '\033[1;32m  ✓ PASS\033[0m %s\n' "$*"; }
fail_() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); printf '\033[1;31m  ✗ FAIL\033[0m %s\n' "$*"; }
skip_() { printf '\033[1;33m  - SKIP\033[0m %s\n' "$*"; }

# run_scenario <scenario> <out.bin> [seed]
# Runs the shared multi-scenario harness binary ($HARNESS). Always succeeds
# from the shell's point of view (captures rc in $LAST_RC) so callers can
# assert on it explicitly instead of the suite aborting under `set -e`.
run_scenario() {
    scenario="$1"; out="$2"; seed="${3:-0x1234}"
    set +e
    "${HARNESS}" "${seed}" "${out}" "${scenario}" >/tmp/e2e_harness.log 2>&1
    LAST_RC=$?
    set -e
}

# dump_trace <trace.bin>
dump_trace() {
    set +e
    "${TENET}" --dump text "$1" >/tmp/e2e_decode.log 2>&1
    set -e
}

# run_tenet <trace.bin> <args...>
# First arg is the trace path; remaining args are passed to tenet BEFORE the
# trace path is re-appended at the end (tenet takes the trace path as the
# final positional argument in every mode used by these suites).
run_tenet() {
    trace="$1"; shift
    set +e
    "${TENET}" "$@" "${trace}" >/tmp/e2e_out.log 2>&1
    LAST_RC=$?
    set -e
}

assert_semantic_ok() {
    desc="$1"
    if grep -q "OK: instrumented result matches" /tmp/e2e_harness.log 2>/dev/null; then
        pass_ "${desc}: semantic correctness"
    else
        fail_ "${desc}: return value MISMATCH or harness crashed"
        tail -5 /tmp/e2e_harness.log | sed 's/^/    /'
    fi
}

assert_in() {
    desc="$1" logfile="$2" pattern="$3"
    if grep -qE "${pattern}" "${logfile}" 2>/dev/null; then
        pass_ "${desc}: found '${pattern}'"
    else
        fail_ "${desc}: '${pattern}' NOT found in ${logfile}"
        tail -15 "${logfile}" | sed 's/^/    /'
    fi
}

assert_not_in() {
    desc="$1" logfile="$2" pattern="$3"
    if ! grep -qE "${pattern}" "${logfile}" 2>/dev/null; then
        pass_ "${desc}: correctly absent '${pattern}'"
    else
        fail_ "${desc}: '${pattern}' unexpectedly found in ${logfile}"
    fi
}

assert_tenet_ok() {
    desc="$1"
    if [ "${LAST_RC}" -eq 0 ]; then
        pass_ "${desc}: tenet exit 0"
    else
        fail_ "${desc}: tenet exit ${LAST_RC}"
        tail -15 /tmp/e2e_out.log | sed 's/^/    /'
    fi
}

# build_harness_once <output_binary>
# Compiles test_target.c + target_crypto.c + target_profile.c + test_harness.c
# (+ QBDITrace.cpp) into one multi-scenario harness binary. Called exactly
# once by run_pass_e2e.sh; suites just invoke run_scenario() against the
# resulting binary with the scenario name they need ("core"/"crypto"/"profile").
build_harness_once() {
    out="$1"
    clang++ -std=c++17 -O2 -g \
        -Wno-deprecated-declarations -Wno-constant-conversion \
        -I"${TRACE_DIR}" \
        -I"${ROOT}/include" \
        -I"${BUILD}/include" \
        -I"${BUILD}/include-static" \
        "${TRACE_DIR}/QBDITrace.cpp" \
        "${TRACE_DIR}/tests/integration/test_target.c" \
        "${TRACE_DIR}/tests/integration/target_crypto.c" \
        "${TRACE_DIR}/tests/integration/target_profile.c" \
        "${TRACE_DIR}/tests/integration/test_harness.c" \
        -DQBDITRACE_TEST_OBJC=1 -lobjc \
        "${BUILD}/libQBDI.a" \
        "${BUILD}/libqbdi-llvm.a" \
        -framework Foundation -framework CoreFoundation \
        -o "${out}"
}

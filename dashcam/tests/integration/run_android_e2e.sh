#!/bin/bash
# run_android_e2e.sh — qbditrace Android arm64 end-to-end test suite.
#
# Builds two test targets, deploys them with libqbditrace.so to a connected
# rooted Android arm64 device, runs both, decodes via `tenet --dump`, and
# verifies record types + semantic correctness.
#
# Validates qbditrace's two multi-thread recording paths on Android:
#
#   1. in-process  — android_inproc_mt.c links libqbditrace.so and calls
#      qbditrace_run_thread() from each child-thread entry point; every child
#      runs worker() inside its own QBDI VM and records into one trace file.
#   2. Frida agent — android_mt_target.c is driven by qbditrace_runner.py with
#      --trace-threads: the agent intercepts pthread_create and redirects each
#      child into qbditrace_run_thread(). Exercises the Frida-side runThread
#      NativeFunction wrapper (regression test for the uint64-type bug).
#
# Prerequisites:
#   - adb + a connected rooted Android arm64 device
#   - NDK (NDK_PATH or ANDROID_SDK_ROOT, or Homebrew android-ndk)
#   - libqbditrace.so at dashcam/build-android/ (build-dashcam-android.sh)
#   - tenet at slowmo/build/tenet
#   - frida (host CLI + python module) + frida-server running on device
#
# Usage (from repo root):
#   bash dashcam/tests/integration/run_android_e2e.sh
#
# Exit code: 0 = all pass, non-zero = failure count.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../../.." && pwd -P)"
TRACE_DIR="${ROOT}/dashcam"
TENET="${ROOT}/slowmo/build/tenet"
SO="${TRACE_DIR}/build-android/libqbditrace.so"
RUNNER="${TRACE_DIR}/qbditrace_runner.py"
DEV_TMP=/data/local/tmp

PASS=0; FAIL=0
log()  { printf '\033[1;34m[android-e2e]\033[0m %s\n' "$*"; }
pass_(){ PASS=$((PASS+1)); printf '\033[1;32m  ✓ PASS\033[0m %s\n' "$*"; }
fail_(){ FAIL=$((FAIL+1)); printf '\033[1;31m  ✗ FAIL\033[0m %s\n' "$*"; }

# ─── resolve NDK ────────────────────────────────────────────────────────────
if [[ -z "${NDK_PATH:-}" ]]; then
    if [[ -n "${ANDROID_SDK_ROOT:-}" && -d "${ANDROID_SDK_ROOT}/ndk" ]]; then
        NDK_PATH="$(ls -d "${ANDROID_SDK_ROOT}/ndk/"* 2>/dev/null | sort -V | tail -n1)"
    fi
    [[ -z "${NDK_PATH:-}" ]] && NDK_PATH="/opt/homebrew/share/android-ndk"
fi
[[ -d "${NDK_PATH}" ]] || { echo "ERROR: NDK not found (set NDK_PATH)"; exit 1; }
TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt"
HOST_TAG=""
for t in darwin-x86_64 linux-x86_64 darwin-aarch64; do
    [[ -d "${TOOLCHAIN}/${t}" ]] && HOST_TAG="${t}" && break
done
CC="${TOOLCHAIN}/${HOST_TAG}/bin/aarch64-linux-android24-clang"
NM="${TOOLCHAIN}/${HOST_TAG}/bin/llvm-nm"
[[ -x "${CC}" ]] || { echo "ERROR: NDK clang not found at ${CC}"; exit 1; }

# ─── preflight ──────────────────────────────────────────────────────────────
[[ -f "${SO}" ]]    || { echo "ERROR: ${SO} missing (run build-dashcam-android.sh)"; exit 1; }
[[ -x "${TENET}" ]] || { echo "ERROR: tenet not built (${TENET})"; exit 1; }
command -v frida >/dev/null || { echo "ERROR: frida not installed on host"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "ERROR: no adb device"; exit 1; }

INPROC_SRC="${HERE}/android_inproc_mt.c"
MT_SRC="${HERE}/android_mt_target.c"
[[ -f "${INPROC_SRC}" && -f "${MT_SRC}" ]] || { echo "ERROR: test sources missing"; exit 1; }

INPROC_BIN=/tmp/android_inproc_mt
MT_BIN=/tmp/android_mt_target

# ─── build ──────────────────────────────────────────────────────────────────
log "Building android_inproc_mt (-O0, mem coverage)..."
"${CC}" -std=c11 -O0 -g -pthread -I"${TRACE_DIR}" -L"${TRACE_DIR}/build-android" \
    "${INPROC_SRC}" -lqbditrace -o "${INPROC_BIN}"

log "Building android_mt_target (-O2, Frida target)..."
"${CC}" -std=c11 -O2 -pthread "${MT_SRC}" -o "${MT_BIN}"

# mt_driver offset (PIE — resolved at runtime via module base). Use nm st_value.
MT_OFF="$("${NM}" "${MT_BIN}" 2>/dev/null | awk '/ T mt_driver$/{print $1; exit}')"
[[ -n "${MT_OFF}" ]] || { echo "ERROR: mt_driver symbol not found"; exit 1; }
log "mt_driver offset = 0x${MT_OFF}"

# ─── deploy ─────────────────────────────────────────────────────────────────
log "Deploying to device..."
adb push "${SO}"        "${DEV_TMP}/" >/dev/null
adb push "${INPROC_BIN}" "${DEV_TMP}/" >/dev/null
adb push "${MT_BIN}"    "${DEV_TMP}/" >/dev/null
adb shell "chmod 755 ${DEV_TMP}/android_inproc_mt ${DEV_TMP}/android_mt_target"

# ─── Scenario 1: in-process multi-thread ───────────────────────────────────
log ""
log "=== Scenario 1: in-process multi-thread (qbditrace_run_thread) ==="
adb shell "cd ${DEV_TMP} && LD_LIBRARY_PATH=${DEV_TMP} ./android_inproc_mt ${DEV_TMP}/inproc_mt.bin" 2>&1 | tee /tmp/ae_inproc.log
adb pull "${DEV_TMP}/inproc_mt.bin" /tmp/ >/dev/null 2>&1
"${TENET}" --dump text /tmp/inproc_mt.bin >/tmp/ae_inproc.dump 2>&1

grep -q "RESULT: OK" /tmp/ae_inproc.log && pass_ "s1 semantic match (inst==ref)" || fail_ "s1 semantic mismatch"
N_THR=$(grep -c '^THREAD' /tmp/ae_inproc.dump)
N_SVC=$(grep -c '^SVC' /tmp/ae_inproc.dump)
N_MR=$(grep -c 'mem R' /tmp/ae_inproc.dump)
N_MW=$(grep -c 'mem W' /tmp/ae_inproc.dump)
[ "${N_THR}" -ge 2 ] && pass_ "s1 ${N_THR} THREAD records (>=2 children)" || fail_ "s1 only ${N_THR} THREAD"
[ "${N_SVC}" -ge 2 ] && pass_ "s1 ${N_SVC} SVC (inline getpid, >=2)" || fail_ "s1 only ${N_SVC} SVC"
[ "${N_MR}" -gt 0 ] && pass_ "s1 mem R=${N_MR}" || fail_ "s1 no mem R"
[ "${N_MW}" -gt 0 ] && pass_ "s1 mem W=${N_MW}" || fail_ "s1 no mem W"
grep -q '<no code>' /tmp/ae_inproc.dump && fail_ "s1 corrupted (<no code>)" || pass_ "s1 no corruption"

# ─── Scenario 2: Frida-agent multi-thread ───────────────────────────────────
log ""
log "=== Scenario 2: Frida-agent multi-thread (traceThreads) ==="
timeout 90 python3 "${RUNNER}" --android --usb \
    --target "${DEV_TMP}/android_mt_target" --module android_mt_target \
    --entry "0x${MT_OFF}" --invoke --args "int:4660" --trace-threads \
    --output "${DEV_TMP}/ae_mt.bin" --dylib "${DEV_TMP}/libqbditrace.so" \
    >/tmp/ae_frida.log 2>&1 || true
adb pull "${DEV_TMP}/ae_mt.bin" /tmp/ >/dev/null 2>&1
"${TENET}" --dump text /tmp/ae_mt.bin >/tmp/ae_frida.dump 2>&1

grep -q "ret = 0x9" /tmp/ae_frida.log && pass_ "s2 ret=0x9 (semantic match)" || fail_ "s2 ret mismatch"
N_THR2=$(grep -c '^THREAD' /tmp/ae_frida.dump)
N_SVC2=$(grep -c '^SVC' /tmp/ae_frida.dump)
[ "${N_THR2}" -ge 3 ] && pass_ "s2 ${N_THR2} THREAD (main+2 children)" || fail_ "s2 only ${N_THR2} THREAD"
[ "${N_SVC2}" -ge 2 ] && pass_ "s2 ${N_SVC2} SVC" || fail_ "s2 only ${N_SVC2} SVC"
grep -q '<no code>' /tmp/ae_frida.dump && fail_ "s2 corrupted (<no code>)" || pass_ "s2 no corruption"
grep -qi 'UInt64 object expected' /tmp/ae_frida.log && fail_ "s2 runThread type regression" || pass_ "s2 no runThread type error"

# ─── summary ────────────────────────────────────────────────────────────────
log ""
log "═══════════════════════════════════════════════════════════"
log "  Android E2E: ${PASS} passed, ${FAIL} failed"
log "═══════════════════════════════════════════════════════════"
[ "${FAIL}" -eq 0 ]

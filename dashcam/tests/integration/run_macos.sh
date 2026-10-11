#!/bin/sh
#
# qbditrace - build & run the standalone test on Apple Silicon (macOS arm64).
#
# Prerequisites:
#   - macOS arm64 QBDI static libs built into ../../../build-macos:
#       sh cmake/config/config-macOS-AARCH64.sh && ninja QBDI_static qbdi-llvm
#   - tenet binary at ../../../slowmo/build/tenet
#
# What it does:
#   1. builds the tracer + test target + harness into one executable
#   2. runs it (instruments trace_target, writes /tmp/qbditrace-test.bin)
#   3. dumps the trace using tenet --dump text
#
# Usage: sh run_macos.sh [seed]
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../../.." && pwd -P)"
TRACE_DIR="${ROOT}/dashcam"
BUILD="${ROOT}/build-macos"
TENET="${ROOT}/slowmo/build/tenet"
OUT="/tmp/qbditrace-test.bin"
SEED="${1:-0x1234}"

# objc support is optional; enable to also exercise the OBJC record path.
OBJC_DEF=""
OBJC_LIBS=""
if [ "${QBDITRACE_TEST_OBJC:-1}" = "1" ]; then
  OBJC_DEF="-DQBDITRACE_TEST_OBJC=1"
  OBJC_LIBS="-lobjc -framework Foundation"
fi

echo "=== [1/3] building test executable (tracer + target + harness) ==="
clang++ -std=c++17 -O2 -g \
  -Wno-deprecated-declarations \
  -I"${TRACE_DIR}" \
  -I"${ROOT}/include" \
  -I"${BUILD}/include" \
  -I"${BUILD}/include-static" \
  "${TRACE_DIR}/QBDITrace.cpp" \
  "${TRACE_DIR}/tests/integration/test_target.c" \
  "${TRACE_DIR}/tests/integration/target_crypto.c" \
  "${TRACE_DIR}/tests/integration/target_profile.c" \
  "${TRACE_DIR}/tests/integration/test_harness.c" \
  ${OBJC_DEF} \
  "${BUILD}/libQBDI.a" \
  "${BUILD}/libqbdi-llvm.a" \
  -framework Foundation -framework CoreFoundation \
  ${OBJC_LIBS} \
  -o /tmp/qbditrace-test
# Note: test_target.c is compiled here at -O2; the noinline attributes keep the
# cross-function call and recursion intact so the transfer events still appear.
# target_crypto.c / target_profile.c must always be linked in alongside
# test_target.c: test_harness.c's scenario table (see test_harness.c) takes
# the address of crypto_target()/profile_target() unconditionally, and while
# those declarations are marked __attribute__((weak)) to make the *reference*
# tolerant of a missing definition, this toolchain still requires the
# *definition* to be present at final link time (weak only relaxes multiple-
# definition conflicts, not missing ones) -- omitting either file reproduces
# an "Undefined symbols ... crypto_target/profile_target" link error. This
# script only ever runs the default "core" scenario, but must still link all
# three target_*.c files for that reason.

echo "=== [2/3] running (seed=${SEED}) ==="
/tmp/qbditrace-test "${SEED}" "${OUT}"

echo "=== [3/3] dumping trace via tenet ==="
if [ ! -x "${TENET}" ]; then
  echo "WARNING: tenet not found at ${TENET}; skipping decode"
  echo "Build it with: cd slowmo/build && ninja"
else
  echo "--- decoded trace (record structure) ---"
  # tenet --dump text supports all format versions (v4/v5/v7, compressed or not).
  # The trace embeds a deduplicated code table (REC_CODE), so tenet can
  # disassemble every executed instruction without an external --image.
  "${TENET}" --dump text "${OUT}"
fi
echo "=== done ==="

#!/bin/sh
#
# qbditrace - build & run the standalone test on Apple Silicon (macOS arm64).
#
# Prerequisites:
#   - macOS arm64 QBDI static libs built into ../../../build-macos:
#       sh cmake/config/config-macOS-AARCH64.sh && ninja QBDI_static qbdi-llvm
#   - capstone (for the decoder disassembly), e.g. `brew install capstone`
#
# What it does:
#   1. builds the tracer + test target + harness into one executable
#   2. runs it (instruments trace_target, writes /tmp/qbditrace-test.bin)
#   3. builds the offline decoder and dumps the trace
#
# Usage: sh run_macos.sh [seed]
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../.." && pwd -P)"
TRACE_DIR="${ROOT}/tools/qbditrace"
BUILD="${ROOT}/build-macos"
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
  "${TRACE_DIR}/test/test_target.c" \
  "${TRACE_DIR}/test/test_harness.c" \
  ${OBJC_DEF} \
  "${BUILD}/libQBDI.a" \
  "${BUILD}/libqbdi-llvm.a" \
  -framework Foundation -framework CoreFoundation \
  ${OBJC_LIBS} \
  -o /tmp/qbditrace-test
# Note: test_target.c is compiled here at -O2; the noinline attributes keep the
# cross-function call and recursion intact so the transfer events still appear.

echo "=== [2/3] running (seed=${SEED}) ==="
/tmp/qbditrace-test "${SEED}" "${OUT}"

echo "=== [3/3] building decoder & decoding trace ==="
CAPSTONE_PREFIX="$(brew --prefix capstone 2>/dev/null || echo /opt/homebrew/opt/capstone)"
clang++ -std=c++17 -O2 -Wall -Wextra \
  -DQBDITRACE_HAVE_CAPSTONE=1 \
  -I"${CAPSTONE_PREFIX}/include" \
  "${TRACE_DIR}/decoder/trace_decode.cpp" \
  -L"${CAPSTONE_PREFIX}/lib" -lcapstone \
  -o /tmp/trace_decode

echo "--- decoded trace (record structure) ---"
# No --image needed: the trace embeds a deduplicated code table (REC_CODE), so
# the decoder disassembles every executed instruction on its own. Each record
# (insts, mem R/W, reg before->after, xfer site->target, SVC, OBJC) is fully
# readable from the binary stream alone. Look for "code=1 ... embedded" in the
# decoded header to confirm the self-contained code table is present.
/tmp/trace_decode "${OUT}"
echo "=== done ==="

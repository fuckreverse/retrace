#!/bin/sh
#
# qbditrace benchmark — build and run the full benchmark suite
#
# This script:
#   1. Builds the benchmark harness (tracer + all targets + harness) → single binary
#   2. Runs it with configurable seed, producing trace files for each target
#   3. Builds the offline decoder
#   4. Decodes all traces and collects statistics
#   5. Optionally runs the decoder with --format jsonl for machine-parseable output
#
# Prerequisites:
#   - macOS arm64 QBDI static libs in ../../build-macos/ (libQBDI.a, libqbdi-llvm.a)
#   - capstone (brew install capstone)
#
# Usage:
#   sh run_benchmark.sh [options]
#
# Options:
#   --seed <hex>        seed for target functions (default: 0x1234567890ABCDEF)
#   --filter <name>     only run targets whose name contains this substring
#   --output-dir <dir>  directory for trace files (default: /tmp/qbditrace-bench)
#   --csv               output results as CSV
#   --decode-all        decode every trace after the run (can be slow for large)
#   --no-decode         skip decoding entirely (just build & run)
#   --limit <N>         limit decoded instructions per trace (for large traces)
#   --clean             remove output dir before running
#   --help              show usage
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../.." && pwd -P)"
TRACE_DIR="${ROOT}/tools/qbditrace"
BUILD="${ROOT}/build-macos"
OUTDIR="/tmp/qbditrace-bench"
SEED="0x1234567890ABCDEF"
FILTER=""
CSV=""
DECODE="summary"
LIMIT=""
EXTRA_ARGS=""

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --seed)       SEED="$2"; shift 2 ;;
    --filter)     FILTER="--filter $2"; shift 2 ;;
    --output-dir) OUTDIR="$2"; shift 2 ;;
    --csv)        CSV="--csv"; shift ;;
    --decode-all) DECODE="all"; shift ;;
    --no-decode)  DECODE="none"; shift ;;
    --limit)      LIMIT="$2"; shift 2 ;;
    --clean)      rm -rf "${OUTDIR}"; shift ;;
    --help)
      echo "Usage: $0 [--seed <hex>] [--filter <name>] [--output-dir <dir>]"
      echo "          [--csv] [--decode-all] [--no-decode] [--limit N] [--clean]"
      exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# Check prerequisites
if [ ! -f "${BUILD}/libQBDI.a" ]; then
  echo "ERROR: ${BUILD}/libQBDI.a not found."
  echo "Build QBDI first: sh cmake/config/config-macOS-AARCH64.sh && ninja QBDI_static qbdi-llvm"
  exit 1
fi

CAPSTONE_PREFIX="$(brew --prefix capstone 2>/dev/null || echo /opt/homebrew/opt/capstone)"
if [ ! -d "${CAPSTONE_PREFIX}/include" ]; then
  echo "WARNING: capstone not found at ${CAPSTONE_PREFIX}; decoder will skip disassembly"
  HAVE_CAPSTONE=0
else
  HAVE_CAPSTONE=1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           qbditrace benchmark suite                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Build benchmark executable ──
echo "=== [1/4] Building benchmark executable ==="
clang++ -std=c++17 -O2 -g \
  -Wno-deprecated-declarations \
  -I"${TRACE_DIR}" \
  -I"${HERE}" \
  -I"${ROOT}/include" \
  -I"${BUILD}/include" \
  -I"${BUILD}/include-static" \
  "${TRACE_DIR}/QBDITrace.cpp" \
  "${HERE}/targets.c" \
  "${HERE}/bench_harness.c" \
  "${BUILD}/libQBDI.a" \
  "${BUILD}/libqbdi-llvm.a" \
  -framework Foundation -framework CoreFoundation \
  -o /tmp/qbditrace-bench-exe
echo "  → /tmp/qbditrace-bench-exe"

# ── Step 2: Run benchmark ──
echo ""
echo "=== [2/4] Running benchmark (seed=${SEED}) ==="
echo ""
/tmp/qbditrace-bench-exe --seed "${SEED}" --output-dir "${OUTDIR}" ${FILTER} ${CSV}
echo ""

# ── Step 3: Build decoder ──
echo "=== [3/4] Building decoder ==="
if [ "${HAVE_CAPSTONE}" = "1" ]; then
  clang++ -std=c++17 -O2 -Wall -Wextra \
    -DQBDITRACE_HAVE_CAPSTONE=1 \
    -I"${CAPSTONE_PREFIX}/include" \
    "${TRACE_DIR}/decoder/trace_decode.cpp" \
    -L"${CAPSTONE_PREFIX}/lib" -lcapstone \
    -o /tmp/trace_decode_bench
else
  clang++ -std=c++17 -O2 -Wall -Wextra \
    "${TRACE_DIR}/decoder/trace_decode.cpp" \
    -o /tmp/trace_decode_bench
fi
echo "  → /tmp/trace_decode_bench"

# ── Step 4: Decode traces ──
echo ""
echo "=== [4/4] Decoding traces ==="

if [ "${DECODE}" = "none" ]; then
  echo "  (skipped by --no-decode)"
elif [ "${DECODE}" = "summary" ]; then
  # Just show first/last few lines of each trace
  echo ""
  echo "--- Trace file summary ---"
  printf "%-20s %12s %s\n" "FILE" "SIZE" "FIRST_LINE"
  printf "%-20s %12s %s\n" "----" "----" "----------"
  for f in "${OUTDIR}"/*.bin; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    sz="$(wc -c < "$f" | tr -d ' ')"
    # Decode first 3 instructions to show it works
    first=$(/tmp/trace_decode_bench "$f" --limit 1 2>/dev/null | grep "^0x" | head -1)
    printf "%-20s %12s %s\n" "$name" "${sz}B" "$first"
  done
elif [ "${DECODE}" = "all" ]; then
  for f in "${OUTDIR}"/*.bin; do
    [ -f "$f" ] || continue
    name="$(basename "$f" .bin)"
    echo ""
    echo "─── ${name} ───"
    LIMIT_ARG=""
    if [ -n "${LIMIT}" ]; then
      LIMIT_ARG="--limit ${LIMIT}"
    fi
    /tmp/trace_decode_bench "$f" ${LIMIT_ARG} 2>/dev/null | head -60
    echo "  ..."
  done
fi

echo ""
echo "═══ Done ═══"
echo "Trace files: ${OUTDIR}/"
echo "Decoder:     /tmp/trace_decode_bench"
echo ""
echo "To decode a specific trace:"
echo "  /tmp/trace_decode_bench ${OUTDIR}/<target>.bin"
echo ""
echo "To decode as JSONL (machine-readable):"
echo "  /tmp/trace_decode_bench ${OUTDIR}/<target>.bin --format jsonl"

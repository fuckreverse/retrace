#!/bin/sh
#
# qbditrace advanced benchmark — build, trace, decode, and (optionally) tenet analyze
#
# This script:
#   1. Builds the advanced benchmark harness (all targets + tracer)
#   2. Runs instrumented tracing for all targets
#   3. Decodes trace files using tenet --dump (summary or full)
#   4. Optionally runs tenet analysis on each trace
#
# Prerequisites:
#   - macOS arm64 QBDI static libs in build-macos/ (libQBDI.a, libqbdi-llvm.a)
#   - tenet binary at ../../../slowmo/build/tenet
#
# Usage:
#   sh run_advanced.sh [options]
#
# Options:
#   --seed <hex>         seed for targets (default: 0x1234567890ABCDEF)
#   --group <A|B|C|D>   only run targets in this group
#   --filter <name>      only run targets matching substring
#   --output-dir <dir>  trace output directory
#   --tenet <path>      path to tenet binary (enables analysis)
#   --tenet-passes <p>  comma-separated tenet passes to run (default: all)
#   --decode-all        decode all traces (can be very slow for large)
#   --no-decode         skip decode step
#   --csv               output results as CSV
#   --clean             remove output dir before running
#   --help              show usage
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
BENCH_DIR="$(cd "${HERE}/.." && pwd -P)"
ROOT="$(cd "${HERE}/../../../.." && pwd -P)"
TRACE_DIR="${ROOT}/dashcam"
BUILD="${ROOT}/build-macos"
TENET="${ROOT}/slowmo/build/tenet"
OUTDIR="/tmp/qbditrace-advanced"
SEED="0x1234567890ABCDEF"
GROUP=""
FILTER=""
CSV=""
DECODE="summary"
TENET_PASSES="all"
VERBOSE=""

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --seed)         SEED="$2"; shift 2 ;;
    --group)        GROUP="--group $2"; shift 2 ;;
    --filter)       FILTER="--filter $2"; shift 2 ;;
    --output-dir)   OUTDIR="$2"; shift 2 ;;
    --tenet)        TENET="$2"; shift 2 ;;
    --tenet-passes) TENET_PASSES="$2"; shift 2 ;;
    --decode-all)   DECODE="all"; shift ;;
    --no-decode)    DECODE="none"; shift ;;
    --csv)          CSV="--csv"; shift ;;
    --verbose)      VERBOSE="--verbose"; shift ;;
    --clean)        rm -rf "${OUTDIR}"; shift ;;
    --help)
      echo "Usage: $0 [--seed <hex>] [--group A|B|C|D] [--filter <name>]"
      echo "          [--output-dir <dir>] [--tenet <path>] [--tenet-passes <list>]"
      echo "          [--decode-all] [--no-decode] [--csv] [--verbose] [--clean]"
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

if [ ! -x "${TENET}" ]; then
  echo "WARNING: tenet not found at ${TENET}; decode step will be skipped"
  echo "Build it with: cd slowmo/build && ninja"
  DECODE="none"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║       qbditrace ADVANCED benchmark + tenet analysis                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 1: Build
# ═══════════════════════════════════════════════════════════════════════════
echo "═══ [1/4] Building advanced benchmark executable ═══"
echo ""

SOURCES="${TRACE_DIR}/QBDITrace.cpp \
         ${HERE}/crypto_targets.c \
         ${HERE}/obfuscation_targets.c \
         ${HERE}/scenario_targets.c \
         ${HERE}/advanced_harness.c"

# NOTE: Target .c files are compiled with:
#   -march=armv8-a+nosha3+nocrypto+noaes+nosha2  — prevent hardware crypto instructions
#   -fno-vectorize -fno-slp-vectorize            — prevent auto-vectorization using crypto NEON
# This ensures all code uses scalar instructions that QBDI's LLVM can disassemble.
# The QBDITrace.cpp and harness use the full ISA since they're not instrumented.

TARGET_CFLAGS="-std=c11 -O2 -g -march=armv8-a+nosha3+nocrypto+noaes+nosha2 -fno-vectorize -fno-slp-vectorize"

clang++ -std=c++17 -O2 -g \
  -Wno-deprecated-declarations \
  -I"${TRACE_DIR}" \
  -I"${HERE}" \
  -I"${ROOT}/include" \
  -I"${BUILD}/include" \
  -I"${BUILD}/include-static" \
  -c "${TRACE_DIR}/QBDITrace.cpp" \
  -o /tmp/_qbditrace.o

clang -std=c11 -O2 -g \
  -Wno-deprecated-declarations \
  -I"${TRACE_DIR}" \
  -I"${HERE}" \
  -I"${ROOT}/include" \
  -I"${BUILD}/include" \
  -I"${BUILD}/include-static" \
  -c "${HERE}/advanced_harness.c" \
  -o /tmp/_harness.o

clang ${TARGET_CFLAGS} -I"${HERE}" -c "${HERE}/crypto_targets.c" -o /tmp/_crypto.o
clang ${TARGET_CFLAGS} -I"${HERE}" -c "${HERE}/obfuscation_targets.c" -o /tmp/_obf.o
clang ${TARGET_CFLAGS} -I"${HERE}" -c "${HERE}/scenario_targets.c" -o /tmp/_scen.o

clang++ -std=c++17 -O2 \
  /tmp/_qbditrace.o /tmp/_harness.o \
  /tmp/_crypto.o /tmp/_obf.o /tmp/_scen.o \
  "${BUILD}/libQBDI.a" \
  "${BUILD}/libqbdi-llvm.a" \
  -framework Foundation -framework CoreFoundation \
  -o /tmp/qbditrace-advanced-exe

rm -f /tmp/_qbditrace.o /tmp/_harness.o /tmp/_crypto.o /tmp/_obf.o /tmp/_scen.o

echo "  → /tmp/qbditrace-advanced-exe"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 2: Run traces
# ═══════════════════════════════════════════════════════════════════════════
echo "═══ [2/4] Running advanced benchmark (seed=${SEED}) ═══"
echo ""

/tmp/qbditrace-advanced-exe \
  --seed "${SEED}" \
  --output-dir "${OUTDIR}" \
  ${GROUP} ${FILTER} ${CSV} ${VERBOSE}

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 3: Decode traces using tenet --dump
# ═══════════════════════════════════════════════════════════════════════════
echo "═══ [3/4] Decoding traces via tenet ═══"
echo ""

if [ "${DECODE}" = "none" ]; then
  echo "  (decode skipped by --no-decode)"
elif [ "${DECODE}" = "summary" ]; then
  echo "─── Trace file summary ───"
  printf "%-28s %10s %12s %s\n" "FILE" "SIZE" "FIRST_PC" "NOTE"
  printf "%-28s %10s %12s %s\n" "────" "────" "─────────" "────"
  for f in "${OUTDIR}"/*.bin; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    sz="$(wc -c < "$f" | tr -d ' ')"
    # Get first instruction PC from tenet --dump
    first=$("${TENET}" --dump text "$f" --dump-limit 1 2>/dev/null | grep "^0x" | head -1)
    printf "%-28s %10s %12s %s\n" "$name" "${sz}" "${first}" ""
  done
elif [ "${DECODE}" = "all" ]; then
  for f in "${OUTDIR}"/*.bin; do
    [ -f "$f" ] || continue
    name="$(basename "$f" .bin)"
    echo ""
    echo "─── ${name} ───"
    "${TENET}" --dump text "$f" --dump-limit 100 2>/dev/null | head -80
    echo "  ..."
  done
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 4: Tenet analysis (if available)
# ═══════════════════════════════════════════════════════════════════════════
if [ -x "${TENET}" ]; then
  echo "═══ [4/4] Running tenet analysis ═══"
  echo ""

  REPORT_DIR="${OUTDIR}/tenet_reports"
  mkdir -p "${REPORT_DIR}"

  for f in "${OUTDIR}"/*.bin; do
    [ -f "$f" ] || continue
    name="$(basename "$f" .bin)"
    echo "  ▸ Analyzing: ${name}"

    REPORT="${REPORT_DIR}/${name}_report.json"

    # Run tenet with specified passes
    if [ "${TENET_PASSES}" = "all" ]; then
      "${TENET}" analyze "$f" \
        --output "${REPORT}" \
        --passes pattern,cfg,taint,xref,function,call_graph \
        2>/dev/null || echo "    ⚠ tenet analysis failed for ${name}"
    else
      "${TENET}" analyze "$f" \
        --output "${REPORT}" \
        --passes "${TENET_PASSES}" \
        2>/dev/null || echo "    ⚠ tenet analysis failed for ${name}"
    fi

    # Print summary if report exists
    if [ -f "${REPORT}" ]; then
      echo "    → ${REPORT}"
      # Extract key findings (pattern matches, CFG nodes, taint sources)
      if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json, sys
try:
    with open('${REPORT}') as f:
        r = json.load(f)
    if 'pattern' in r:
        pm = r['pattern'].get('matches', [])
        cats = {}
        for m in pm:
            c = m.get('category', 'unknown')
            cats[c] = cats.get(c, 0) + 1
        print(f'    patterns: {len(pm)} matches ({cats})')
    if 'cfg' in r:
        nodes = r['cfg'].get('nodes', 0)
        edges = r['cfg'].get('edges', 0)
        print(f'    CFG: {nodes} nodes, {edges} edges')
    if 'taint' in r:
        sources = r['taint'].get('sources', 0)
        sinks = r['taint'].get('sinks', 0)
        print(f'    taint: {sources} sources, {sinks} sinks')
except Exception as e:
    print(f'    (report parse error: {e})')
" 2>/dev/null || true
      fi
    fi
  done

  echo ""
  echo "  Reports saved to: ${REPORT_DIR}/"
else
  echo "═══ [4/4] Tenet analysis ═══"
  echo "  (skipped — build tenet first: cd slowmo/build && ninja)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  Done! Trace files: ${OUTDIR}/"
echo ""
echo "  Quick commands:"
echo "    # Decode a specific trace:"
echo "    ${TENET} --dump text ${OUTDIR}/<target>.bin"
echo ""
echo "    # Decode as JSONL:"
echo "    ${TENET} --dump jsonl ${OUTDIR}/<target>.bin"
echo ""
echo "═══════════════════════════════════════════════════════════════════════"

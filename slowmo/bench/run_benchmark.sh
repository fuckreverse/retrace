#!/bin/bash
# run_benchmark.sh — One-shot benchmark driver for Tenet
#
# Usage:
#   ./bench/run_benchmark.sh [--scale 1M|10M|100M] [--output results.json]
#
# Steps:
#   1. Build bench_tenet (and gen_test_traces if needed)
#   2. Generate perf traces at specified scale
#   3. Run benchmark harness
#   4. Output JSON results

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TENET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${TENET_DIR}/build-bench"
TRACES_DIR="${TENET_DIR}/bench/traces"
TESTS_DIR="${TENET_DIR}/tests"

# Defaults
SCALE="1M"
OUTPUT=""
SEEK_SAMPLES=1000
MEM_SAMPLES=500
QUIET=""

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --scale) SCALE="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --seek-samples) SEEK_SAMPLES="$2"; shift 2 ;;
        --mem-samples) MEM_SAMPLES="$2"; shift 2 ;;
        --quiet) QUIET="--quiet"; shift ;;
        -h|--help)
            echo "Usage: $0 [--scale 1M|10M|100M] [--output file.json]"
            echo ""
            echo "Options:"
            echo "  --scale <N>          Perf trace scale (default: 1M)"
            echo "  --output <file>      JSON output file (default: stdout)"
            echo "  --seek-samples <N>   Random seek samples (default: 1000)"
            echo "  --mem-samples <N>    Memory read samples (default: 500)"
            echo "  --quiet              Suppress progress output"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "═══════════════════════════════════════════════════════════════"
echo "  Tenet Benchmark Runner"
echo "  Scale: ${SCALE}  Seek: ${SEEK_SAMPLES}  Mem: ${MEM_SAMPLES}"
echo "═══════════════════════════════════════════════════════════════"

# ── Step 1: Build ─────────────────────────────────────────────────────────────

echo ""
echo "[1/3] Building bench_tenet..."

# Build tenet's bench_tenet target
if [[ ! -d "$BUILD_DIR" ]]; then
    cmake -S "$TENET_DIR" -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DTENET_ENABLE_GUI=OFF \
        -DTENET_ENABLE_TRITON=OFF \
        -DTENET_ENABLE_YARA=OFF \
        2>&1 | tail -5
fi

cmake --build "$BUILD_DIR" --target bench_tenet -j$(sysctl -n hw.ncpu 2>/dev/null || nproc) 2>&1 | tail -3

echo "  ✓ bench_tenet built"

# ── Step 2: Generate perf traces ──────────────────────────────────────────────

echo ""
echo "[2/3] Generating perf traces (scale=${SCALE})..."

# Build gen_test_traces via the main CMake build (shared with unit tests)
TESTS_BUILD="${BUILD_DIR}"
if [[ ! -x "${TESTS_BUILD}/gen_test_traces" ]]; then
    echo "  Building gen_test_traces..."
    cmake --build "${TESTS_BUILD}" --target gen_test_traces -j$(sysctl -n hw.ncpu 2>/dev/null || nproc) 2>&1 | tail -3
fi

mkdir -p "$TRACES_DIR"
"${TESTS_BUILD}/gen_test_traces" --suite perf --outdir "$TRACES_DIR" --scale "$SCALE"
echo "  ✓ Perf traces generated in ${TRACES_DIR}/"

# ── Step 3: Run benchmark ─────────────────────────────────────────────────────

echo ""
echo "[3/3] Running benchmark..."
echo ""

BENCH_ARGS=(
    "${TRACES_DIR}/perf/"
    --seek-samples "$SEEK_SAMPLES"
    --mem-samples "$MEM_SAMPLES"
)

if [[ -n "$OUTPUT" ]]; then
    BENCH_ARGS+=(--output "$OUTPUT")
fi

if [[ -n "$QUIET" ]]; then
    BENCH_ARGS+=($QUIET)
fi

"${BUILD_DIR}/bench_tenet" "${BENCH_ARGS[@]}"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ -n "$OUTPUT" ]]; then
    echo "  Results saved to: ${OUTPUT}"
else
    echo "  Results printed to stdout (use --output to save)"
fi
echo "═══════════════════════════════════════════════════════════════"

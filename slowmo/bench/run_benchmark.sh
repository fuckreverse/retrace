#!/bin/bash
# run_benchmark.sh — One-shot benchmark driver for Tenet
#
# Usage:
#   ./bench/run_benchmark.sh [--scale 1M|10M|100M] [--output results.json]
#
# Steps:
#   1. Incrementally build bench_tenet and gen_test_traces in the canonical
#      slowmo/build directory
#   2. Generate perf traces at specified scale
#   3. Run benchmark harness
#   4. Output JSON results

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TENET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Reuse the repository's canonical build directory. Creating a dedicated
# benchmark build would clone/rebuild the same third-party dependencies and can
# easily drift from the binaries developers actually profile.
BUILD_DIR="${TENET_DIR}/build"
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

# The canonical build must already be configured according to the repository
# build contract. Reconfigure it explicitly when a different build type or
# feature set is needed; this script never creates another build tree.
if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
    echo "Error: canonical build directory is not configured: ${BUILD_DIR}" >&2
    echo "Configure slowmo/build first (for profiling, use RelWithDebInfo)." >&2
    exit 1
fi

NPROC=$(sysctl -n hw.ncpu 2>/dev/null || nproc)
cmake --build "$BUILD_DIR" --target bench_tenet gen_test_traces -j"$NPROC" 2>&1 | tail -3

echo "  ✓ bench_tenet built"

# ── Step 2: Generate perf traces ──────────────────────────────────────────────

echo ""
echo "[2/3] Generating perf traces (scale=${SCALE})..."

# gen_test_traces is emitted under build/tests by the current CMake layout.
GEN_TEST_TRACES="${BUILD_DIR}/tests/gen_test_traces"
if [[ ! -x "$GEN_TEST_TRACES" ]]; then
    echo "Error: gen_test_traces was not produced at ${GEN_TEST_TRACES}" >&2
    exit 1
fi

mkdir -p "$TRACES_DIR"
"$GEN_TEST_TRACES" --suite perf --outdir "$TRACES_DIR" --scale "$SCALE"
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

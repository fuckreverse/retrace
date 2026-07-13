#!/bin/bash
#
# gen_and_validate.sh — Build gen_test_traces, generate traces, validate with tenet --dump
#
# Usage:
#   ./gen_and_validate.sh                       # Generate unit + 1M perf traces
#   ./gen_and_validate.sh --perf-only --scale 10M   # Only perf suite at 10M
#   ./gen_and_validate.sh --perf-only --scale 100M  # Only perf suite at 100M
#   ./gen_and_validate.sh --unit-only               # Only unit test traces
#   ./gen_and_validate.sh --validate-only           # Skip generation, just decode existing
#   ./gen_and_validate.sh --clean                   # Remove all generated traces
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "${HERE}/../../../.." && pwd -P)"
TENET_DIR="${ROOT}/tools/tenet"
BUILD_DIR="${TENET_DIR}/build"
TRACES_DIR="${HERE}/../traces"
GENERATOR="${BUILD_DIR}/gen_test_traces"
TENET="${BUILD_DIR}/tenet"

# Defaults
SUITE="all"
SCALE="1M"
VALIDATE=1
GENERATE=1
DECODE_LIMIT=5  # decode first N records per trace for validation

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --perf-only) SUITE="perf"; shift ;;
        --unit-only) SUITE="unit"; shift ;;
        --scale) SCALE="$2"; shift 2 ;;
        --validate-only) GENERATE=0; shift ;;
        --no-validate) VALIDATE=0; shift ;;
        --decode-limit) DECODE_LIMIT="$2"; shift 2 ;;
        --clean)
            echo "Cleaning generated traces..."
            rm -rf "${TRACES_DIR}"
            echo "Done."
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --perf-only           Only generate performance traces"
            echo "  --unit-only           Only generate unit test traces"
            echo "  --scale <N[K|M|G]>   Set perf trace scale (default: 1M)"
            echo "  --validate-only       Skip generation, validate existing traces"
            echo "  --no-validate         Skip decoder validation"
            echo "  --decode-limit <N>    Decode first N records per trace (default: 5)"
            echo "  --clean               Remove all generated files"
            echo "  --help                Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Step 1: Build ────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════════"
echo " Step 1: Building gen_test_traces and tenet"
echo "═══════════════════════════════════════════════════════════════════════"

# Build gen_test_traces via the main CMake build (shared with unit tests)
if [ ! -f "${GENERATOR}" ] || [ "${HERE}/gen_test_traces.cpp" -nt "${GENERATOR}" ]; then
    echo "  Building gen_test_traces via CMake..."
    cmake --build "${BUILD_DIR}" --target gen_test_traces -j$(sysctl -n hw.ncpu 2>/dev/null || nproc) 2>&1 | tail -3
    echo "  → ${GENERATOR}"
else
    echo "  gen_test_traces is up to date."
fi

# Build tenet (for --dump validation)
if [ "${VALIDATE}" -eq 1 ]; then
    if [ ! -x "${TENET}" ]; then
        echo "  ⚠ tenet not found at ${TENET}. Build with: cmake --build ${BUILD_DIR}"
        VALIDATE=0
    else
        echo "  tenet is available at ${TENET}"
    fi
fi

# Also check if gen_test_traces was built
if [ ! -x "${GENERATOR}" ]; then
    echo "  ⚠ gen_test_traces not found. Build with: cmake --build ${BUILD_DIR} --target gen_test_traces"
    echo "  ⚠ (requires -DTENET_BUILD_TESTS=ON)"
    exit 1
fi

echo ""

# ─── Step 2: Generate traces ─────────────────────────────────────────────────

if [ "${GENERATE}" -eq 1 ]; then
    echo "═══════════════════════════════════════════════════════════════════════"
    echo " Step 2: Generating traces (suite=${SUITE}, scale=${SCALE})"
    echo "═══════════════════════════════════════════════════════════════════════"

    mkdir -p "${TRACES_DIR}"

    TIME_START=$(date +%s)
    "${GENERATOR}" --suite "${SUITE}" --outdir "${TRACES_DIR}" --scale "${SCALE}"
    TIME_END=$(date +%s)
    echo ""
    echo "  Generation completed in $((TIME_END - TIME_START)) seconds."
    echo ""
fi

# ─── Step 3: Validate with tenet --dump ───────────────────────────────────────

if [ "${VALIDATE}" -eq 1 ]; then
    echo "═══════════════════════════════════════════════════════════════════════"
    echo " Step 3: Validating traces with tenet --dump"
    echo "═══════════════════════════════════════════════════════════════════════"

    PASS=0
    FAIL=0
    TOTAL=0

    validate_trace() {
        local trace_file="$1"
        local name="$(basename "${trace_file}" .trace)"
        TOTAL=$((TOTAL + 1))

        # Run tenet --dump text, capture exit code
        if "${TENET}" --dump text "${trace_file}" 2>/dev/null | head -n "${DECODE_LIMIT}" > /dev/null 2>&1; then
            PASS=$((PASS + 1))
            printf "  ✓ %-30s  (OK)\n" "${name}"
        else
            FAIL=$((FAIL + 1))
            printf "  ✗ %-30s  (DECODE FAILED)\n" "${name}"
            echo "    Error output:"
            "${TENET}" --dump text "${trace_file}" 2>&1 | head -5 | sed 's/^/      /'
        fi
    }

    # Validate unit traces
    if [ -d "${TRACES_DIR}/unit" ]; then
        echo ""
        echo "  --- Unit traces ---"
        for f in "${TRACES_DIR}/unit/"*.trace; do
            [ -f "$f" ] && validate_trace "$f"
        done
    fi

    # Validate perf traces
    if [ -d "${TRACES_DIR}/perf" ]; then
        echo ""
        echo "  --- Perf traces ---"
        for f in "${TRACES_DIR}/perf/"*.trace; do
            [ -f "$f" ] && validate_trace "$f"
        done
    fi

    # Single trace files in root traces dir
    for f in "${TRACES_DIR}/"*.trace; do
        [ -f "$f" ] && validate_trace "$f"
    done

    echo ""
    echo "  ─────────────────────────────────────────"
    echo "  Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
    echo ""

    if [ "${FAIL}" -gt 0 ]; then
        echo "  ⚠ Some traces failed validation!"
        exit 1
    else
        echo "  ✓ All traces validated successfully."
    fi
fi

# ─── Step 4: Size report ──────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo " Trace Size Report"
echo "═══════════════════════════════════════════════════════════════════════"

printf "  %-35s %12s\n" "FILE" "SIZE"
printf "  %-35s %12s\n" "----" "----"

total_bytes=0
for f in $(find "${TRACES_DIR}" -name "*.trace" -type f | sort); do
    sz=$(stat -f%z "$f" 2>/dev/null || stat --printf="%s" "$f" 2>/dev/null || echo 0)
    total_bytes=$((total_bytes + sz))
    name="${f#${TRACES_DIR}/}"
    if [ "${sz}" -gt 1048576 ]; then
        printf "  %-35s %8.2f MB\n" "${name}" "$(echo "scale=2; ${sz}/1048576" | bc)"
    elif [ "${sz}" -gt 1024 ]; then
        printf "  %-35s %8.2f KB\n" "${name}" "$(echo "scale=2; ${sz}/1024" | bc)"
    else
        printf "  %-35s %8d  B\n" "${name}" "${sz}"
    fi
done

echo ""
if [ "${total_bytes}" -gt 1073741824 ]; then
    printf "  Total: %.2f GB\n" "$(echo "scale=2; ${total_bytes}/1073741824" | bc)"
elif [ "${total_bytes}" -gt 1048576 ]; then
    printf "  Total: %.2f MB\n" "$(echo "scale=2; ${total_bytes}/1048576" | bc)"
else
    printf "  Total: %.2f KB\n" "$(echo "scale=2; ${total_bytes}/1024" | bc)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo " Done. Traces are in: ${TRACES_DIR}"
echo "═══════════════════════════════════════════════════════════════════════"

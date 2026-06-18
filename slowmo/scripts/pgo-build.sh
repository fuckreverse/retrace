#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# pgo-build.sh — One-click PGO (Profile-Guided Optimization) build for tenet
#
# Usage:
#   ./scripts/pgo-build.sh <trace-file>           # PGO-optimized build
#   ./scripts/pgo-build.sh --clean <trace-file>   # Also build non-PGO for comparison
#
# This script automates the full PGO workflow:
#   1. Build instrumented binary (profile generation)
#   2. Run representative workload to collect profiles
#   3. Merge raw profiles into .profdata
#   4. Rebuild with profile data (optimized)
#
# Typical speedup: 15-30% on hot iteration loops (TraceReader, RegisterFile, etc.)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENET_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${TENET_ROOT}/build"
PROFDATA="${BUILD_DIR}/default.profdata"
NPROC="$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 8)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Helper Functions ────────────────────────────────────────────────────────
log_phase() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Phase $1: $2${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}\n"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

timer_start() {
    PHASE_START=$(date +%s)
}

timer_end() {
    local elapsed=$(( $(date +%s) - PHASE_START ))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed % 60 ))
    echo -e "${GREEN}  ⏱  Phase completed in ${min}m ${sec}s${NC}"
}

usage() {
    echo "Usage: $0 [--clean] <trace-file>"
    echo ""
    echo "Arguments:"
    echo "  <trace-file>    Path to a .bin trace file for profile training"
    echo ""
    echo "Options:"
    echo "  --clean         After PGO build, also do a clean non-PGO build for comparison"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/trace.bin"
    echo "  $0 --clean /path/to/trace.bin"
    exit 1
}

# ─── Argument Parsing ────────────────────────────────────────────────────────
DO_CLEAN=0
TRACE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            DO_CLEAN=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            TRACE_FILE="$1"
            shift
            ;;
    esac
done

if [[ -z "${TRACE_FILE}" ]]; then
    log_error "Trace file argument is required."
    usage
fi

if [[ ! -f "${TRACE_FILE}" ]]; then
    log_error "Trace file not found: ${TRACE_FILE}"
    exit 1
fi

# Resolve to absolute path
TRACE_FILE="$(cd "$(dirname "${TRACE_FILE}")" && pwd)/$(basename "${TRACE_FILE}")"

# ─── Verify Build Directory Exists ───────────────────────────────────────────
if [[ ! -d "${BUILD_DIR}" ]]; then
    log_error "Build directory does not exist: ${BUILD_DIR}"
    log_error "Please create it first with: cd ${TENET_ROOT} && mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release"
    exit 1
fi

# ─── Find llvm-profdata ──────────────────────────────────────────────────────
LLVM_PROFDATA=""
if command -v llvm-profdata &>/dev/null; then
    LLVM_PROFDATA="llvm-profdata"
elif command -v xcrun &>/dev/null && xcrun -f llvm-profdata &>/dev/null; then
    LLVM_PROFDATA="xcrun llvm-profdata"
else
    # Search common Homebrew/Xcode paths
    for candidate in /usr/local/opt/llvm/bin/llvm-profdata \
                     /opt/homebrew/opt/llvm/bin/llvm-profdata \
                     /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-profdata; do
        if [[ -x "${candidate}" ]]; then
            LLVM_PROFDATA="${candidate}"
            break
        fi
    done
fi

if [[ -z "${LLVM_PROFDATA}" ]]; then
    log_error "llvm-profdata not found. Install LLVM or use Xcode toolchain."
    exit 1
fi

log_info "Using llvm-profdata: ${LLVM_PROFDATA}"

# ─── Summary ────────────────────────────────────────────────────────────────
TOTAL_START=$(date +%s)
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          tenet PGO Build — One-Click Optimization           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Trace file : ${TRACE_FILE}"
echo -e "${GREEN}║${NC} Build dir  : ${BUILD_DIR}"
echo -e "${GREEN}║${NC} Parallelism: ${NPROC} jobs"
echo -e "${GREEN}║${NC} Clean comp.: $([ ${DO_CLEAN} -eq 1 ] && echo 'Yes' || echo 'No')"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Instrumented Build (Profile Generation)
# ═══════════════════════════════════════════════════════════════════════════════
log_phase 1 "Building instrumented binary (PGO generate)"
timer_start

cd "${BUILD_DIR}"

# Clean old profile data
rm -f "${BUILD_DIR}"/default_*.profraw "${PROFDATA}"

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DTENET_PGO_MODE=generate \
    -DTENET_PGO_PROFILE="${PROFDATA}"

ninja -j"${NPROC}"

timer_end

# Verify instrumented binary was built
if [[ ! -x "${BUILD_DIR}/tenet" ]]; then
    log_error "Instrumented binary not found at ${BUILD_DIR}/tenet"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Profile Collection (Run Representative Workload)
# ═══════════════════════════════════════════════════════════════════════════════
log_phase 2 "Collecting profile data (running xref pass)"
timer_start

log_info "Running: ./tenet --xref ${TRACE_FILE}"

# Set LLVM_PROFILE_FILE to control output location
export LLVM_PROFILE_FILE="${BUILD_DIR}/default_%m_%p.profraw"

cd "${BUILD_DIR}"
./tenet --xref "${TRACE_FILE}" || {
    log_warn "tenet exited with non-zero status (may be acceptable for profile collection)"
}

# Check that profile files were generated
PROFRAW_COUNT=$(find "${BUILD_DIR}" -name "default_*.profraw" 2>/dev/null | wc -l | tr -d ' ')
if [[ "${PROFRAW_COUNT}" -eq 0 ]]; then
    log_error "No .profraw files generated. Instrumented build may have failed."
    exit 1
fi

log_info "Collected ${PROFRAW_COUNT} profraw file(s)"
timer_end

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Profile Merge
# ═══════════════════════════════════════════════════════════════════════════════
log_phase 3 "Merging profile data"
timer_start

${LLVM_PROFDATA} merge \
    -output="${PROFDATA}" \
    "${BUILD_DIR}"/default_*.profraw

if [[ ! -f "${PROFDATA}" ]]; then
    log_error "Profile merge failed: ${PROFDATA} not created"
    exit 1
fi

PROFDATA_SIZE=$(du -h "${PROFDATA}" | cut -f1)
log_info "Merged profile: ${PROFDATA} (${PROFDATA_SIZE})"

# Clean up raw profiles
rm -f "${BUILD_DIR}"/default_*.profraw
timer_end

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Optimized Build (PGO Use)
# ═══════════════════════════════════════════════════════════════════════════════
log_phase 4 "Rebuilding with profile-guided optimization"
timer_start

cd "${BUILD_DIR}"
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DTENET_PGO_MODE=use \
    -DTENET_PGO_PROFILE="${PROFDATA}"

ninja -j"${NPROC}"

timer_end

# Verify optimized binary
if [[ ! -x "${BUILD_DIR}/tenet" ]]; then
    log_error "Optimized binary not found at ${BUILD_DIR}/tenet"
    exit 1
fi

PGO_SIZE=$(du -h "${BUILD_DIR}/tenet" | cut -f1)
log_info "PGO-optimized binary: ${BUILD_DIR}/tenet (${PGO_SIZE})"

# ═══════════════════════════════════════════════════════════════════════════════
# Optional Phase 5: Clean non-PGO Build for Comparison
# ═══════════════════════════════════════════════════════════════════════════════
if [[ ${DO_CLEAN} -eq 1 ]]; then
    log_phase 5 "Building non-PGO binary for comparison"
    timer_start

    # Save PGO binary for comparison
    cp "${BUILD_DIR}/tenet" "${BUILD_DIR}/tenet-pgo"

    cd "${BUILD_DIR}"
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DTENET_PGO_MODE="" \
        -DTENET_PGO_PROFILE=""

    ninja -j"${NPROC}"

    timer_end

    # Rename binaries for comparison
    mv "${BUILD_DIR}/tenet" "${BUILD_DIR}/tenet-baseline"
    mv "${BUILD_DIR}/tenet-pgo" "${BUILD_DIR}/tenet"

    BASELINE_SIZE=$(du -h "${BUILD_DIR}/tenet-baseline" | cut -f1)
    log_info "Baseline binary: ${BUILD_DIR}/tenet-baseline (${BASELINE_SIZE})"
    log_info "PGO binary:      ${BUILD_DIR}/tenet (${PGO_SIZE})"
    echo ""
    log_info "Compare performance with:"
    echo "    time ${BUILD_DIR}/tenet-baseline --xref ${TRACE_FILE}"
    echo "    time ${BUILD_DIR}/tenet --xref ${TRACE_FILE}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════
TOTAL_ELAPSED=$(( $(date +%s) - TOTAL_START ))
TOTAL_MIN=$(( TOTAL_ELAPSED / 60 ))
TOTAL_SEC=$(( TOTAL_ELAPSED % 60 ))

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    PGO Build Complete!                       ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Total time   : ${TOTAL_MIN}m ${TOTAL_SEC}s"
echo -e "${GREEN}║${NC} Binary       : ${BUILD_DIR}/tenet"
echo -e "${GREEN}║${NC} Profile data : ${PROFDATA}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} The PGO-optimized binary is now at the standard location."
echo -e "${GREEN}║${NC} Expected speedup: 15-30% on hot analysis passes."
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

#!/bin/sh
#
# Build a real OLLVM-obfuscated clang from Pluto-Obfuscator (LLVM 14.0.6 based)
# Then compile the same crypto targets with OLLVM passes enabled.
#
# This allows direct comparison:
#   - Hand-obfuscated targets (our Group B) vs real OLLVM output
#   - Tenet analysis on both to see how realistic our simulations are
#
# Prerequisites:
#   - cmake, ninja (brew install cmake ninja)
#   - ~20GB disk space, ~30min build time on M1/M2/M3
#   - Xcode command line tools
#
# Usage:
#   sh build_ollvm.sh [--skip-build]    # build OLLVM from source
#   sh build_ollvm.sh --compile-only    # use existing OLLVM to compile targets
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd -P)"
OLLVM_DIR="${HOME}/ollvm-pluto"
OLLVM_BUILD="${OLLVM_DIR}/build"
OLLVM_CLANG="${OLLVM_BUILD}/bin/clang"
OUTDIR="/tmp/qbditrace-ollvm-targets"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║       OLLVM (Pluto-Obfuscator) Builder                              ║"
echo "║       Produces real OLLVM-obfuscated arm64 binaries                  ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 1: Clone Pluto-Obfuscator
# ═══════════════════════════════════════════════════════════════════════════

if [ "$1" != "--compile-only" ]; then
  echo "═══ [1/3] Cloning Pluto-Obfuscator (LLVM 14.0.6 based) ═══"
  
  if [ ! -d "${OLLVM_DIR}" ]; then
    git clone --depth 1 https://github.com/bluesadi/Pluto.git "${OLLVM_DIR}"
    echo "  → Cloned to ${OLLVM_DIR}"
  else
    echo "  → Already exists at ${OLLVM_DIR}"
  fi
  echo ""

  # ═══════════════════════════════════════════════════════════════════════════
  # Step 2: Build OLLVM
  # ═══════════════════════════════════════════════════════════════════════════
  echo "═══ [2/3] Building OLLVM (this takes ~30 minutes on Apple Silicon) ═══"
  echo "  Target: ${OLLVM_BUILD}"
  echo ""

  if [ "$1" = "--skip-build" ]; then
    echo "  (skipped by --skip-build)"
  elif [ -x "${OLLVM_CLANG}" ]; then
    echo "  → OLLVM clang already built: ${OLLVM_CLANG}"
  else
    mkdir -p "${OLLVM_BUILD}"
    cd "${OLLVM_BUILD}"
    
    cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_ENABLE_PROJECTS="clang" \
      -DLLVM_TARGETS_TO_BUILD="AArch64" \
      -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_INCLUDE_EXAMPLES=OFF \
      -DLLVM_INCLUDE_BENCHMARKS=OFF \
      -DLLVM_INCLUDE_DOCS=OFF \
      -DCLANG_INCLUDE_DOCS=OFF \
      "${OLLVM_DIR}/llvm"

    ninja clang -j$(sysctl -n hw.ncpu)
    echo ""
    echo "  → OLLVM clang built: ${OLLVM_CLANG}"
  fi
  echo ""
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 3: Compile targets with various OLLVM passes
# ═══════════════════════════════════════════════════════════════════════════
echo "═══ [3/3] Compiling crypto targets with OLLVM obfuscation passes ═══"
echo ""

if [ ! -x "${OLLVM_CLANG}" ]; then
  echo "ERROR: OLLVM clang not found at ${OLLVM_CLANG}"
  echo "Run this script without --compile-only first to build OLLVM."
  exit 1
fi

mkdir -p "${OUTDIR}"

# Source file with clean crypto implementations
CRYPTO_SRC="${HERE}/crypto_targets.c"

# A simple standalone test wrapper that calls each function
cat > /tmp/ollvm_test_main.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

/* Forward declarations */
uint64_t target_aes128_encrypt(uint64_t seed);
uint64_t target_xtea64(uint64_t seed);
uint64_t target_chacha20_block(uint64_t seed);
uint64_t target_sha256_compress(uint64_t seed);
uint64_t target_sm4_encrypt(uint64_t seed);

int main(int argc, char **argv) {
    uint64_t seed = 0x1234567890ABCDEFULL;
    if (argc > 1) seed = strtoull(argv[1], NULL, 0);

    printf("AES-128:   0x%016" PRIx64 "\n", target_aes128_encrypt(seed));
    printf("XTEA-64:   0x%016" PRIx64 "\n", target_xtea64(seed));
    printf("ChaCha20:  0x%016" PRIx64 "\n", target_chacha20_block(seed));
    printf("SHA-256:   0x%016" PRIx64 "\n", target_sha256_compress(seed));
    printf("SM4:       0x%016" PRIx64 "\n", target_sm4_encrypt(seed));
    return 0;
}
EOF

echo "  Compiling variants:"
echo ""

# Baseline (no obfuscation, for comparison)
echo "  [1/6] Baseline (-O2, no obfuscation)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_baseline"
echo "    → ${OUTDIR}/crypto_baseline"

# CFF only
echo "  [2/6] Control Flow Flattening (-mllvm -fla)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -mllvm -fla \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_cff"
echo "    → ${OUTDIR}/crypto_cff"

# BCF only
echo "  [3/6] Bogus Control Flow (-mllvm -bcf)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -mllvm -bcf \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_bcf"
echo "    → ${OUTDIR}/crypto_bcf"

# SUB only
echo "  [4/6] Instruction Substitution (-mllvm -sub)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -mllvm -sub \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_sub"
echo "    → ${OUTDIR}/crypto_sub"

# All combined
echo "  [5/6] All passes (-mllvm -fla -mllvm -bcf -mllvm -sub)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -mllvm -fla -mllvm -bcf -mllvm -sub \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_allpass"
echo "    → ${OUTDIR}/crypto_allpass"

# Maximum: all passes + split basic blocks
echo "  [6/6] Maximum (-mllvm -fla -mllvm -bcf -mllvm -sub -mllvm -split)"
"${OLLVM_CLANG}" -target arm64-apple-macos14.0 -O2 \
  -mllvm -fla -mllvm -bcf -mllvm -sub -mllvm -split \
  -I"${HERE}" \
  "${CRYPTO_SRC}" /tmp/ollvm_test_main.c \
  -o "${OUTDIR}/crypto_maximum"
echo "    → ${OUTDIR}/crypto_maximum"

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  OLLVM-obfuscated binaries ready in: ${OUTDIR}/"
echo ""
echo "  Verify correctness (all should produce same output):"
echo "    ${OUTDIR}/crypto_baseline 0x1234567890ABCDEF"
echo "    ${OUTDIR}/crypto_cff 0x1234567890ABCDEF"
echo "    ${OUTDIR}/crypto_allpass 0x1234567890ABCDEF"
echo ""
echo "  To trace with QBDI (example):"
echo "    # Use qbditrace preload or the standalone harness"
echo "    # Then feed .bin to tenet for analysis comparison"
echo ""
echo "  Next: use qbditrace to trace these binaries and compare"
echo "        tenet's analysis results vs the hand-obfuscated targets"
echo "═══════════════════════════════════════════════════════════════════════"

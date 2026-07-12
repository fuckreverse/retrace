#!/bin/bash
# build-qbditrace-ios.sh — Build libqbditrace.dylib for iOS arm64 with zstd
#
# Usage (from the QBDI repo root):
#   bash tools/qbditrace/build-qbditrace-ios.sh
#
# Prerequisites:
#   - build-ios/libQBDI.a and build-ios/libqbdi-llvm.a already built
#   - tools/tenet/_deps/zstd-src/ exists (shared FetchContent cache)
#
# Output: libqbditrace.dylib in the repo root (ready for deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
cd "${REPO_ROOT}"

# Validate prerequisites
if [[ ! -f build-ios/libQBDI.a ]]; then
    echo "ERROR: build-ios/libQBDI.a not found. Build QBDI for iOS first." >&2
    exit 1
fi
if [[ ! -f build-ios/libqbdi-llvm.a ]]; then
    echo "ERROR: build-ios/libqbdi-llvm.a not found. Build QBDI for iOS first." >&2
    exit 1
fi

ZSTD_SRC="tools/tenet/_deps/zstd-src/lib"
if [[ ! -f "${ZSTD_SRC}/zstd.h" ]]; then
    echo "ERROR: zstd source not found at ${ZSTD_SRC}. Run tenet cmake first." >&2
    exit 1
fi

# Step 1: Cross-compile zstd for iOS arm64 (if not already built)
ZSTD_LIB="build-ios/libzstd.a"
if [[ ! -f "${ZSTD_LIB}" ]]; then
    echo "==> Building libzstd.a for iOS arm64..."
    TMPDIR=$(mktemp -d)
    xcrun --sdk iphoneos clang -arch arm64 -O3 -DNDEBUG -DZSTD_MULTITHREAD=0 \
        -I"${ZSTD_SRC}" -I"${ZSTD_SRC}/common" \
        -c "${ZSTD_SRC}"/common/*.c "${ZSTD_SRC}"/compress/*.c "${ZSTD_SRC}"/decompress/*.c \
        -o "${TMPDIR}/" 2>/dev/null || \
    (cd "${TMPDIR}" && xcrun --sdk iphoneos clang -arch arm64 -O3 -DNDEBUG -DZSTD_MULTITHREAD=0 \
        -I"${REPO_ROOT}/${ZSTD_SRC}" -I"${REPO_ROOT}/${ZSTD_SRC}/common" \
        -c "${REPO_ROOT}/${ZSTD_SRC}"/common/*.c \
           "${REPO_ROOT}/${ZSTD_SRC}"/compress/*.c \
           "${REPO_ROOT}/${ZSTD_SRC}"/decompress/*.c)
    ar rcs "${ZSTD_LIB}" "${TMPDIR}"/*.o
    rm -rf "${TMPDIR}"
    echo "    -> ${ZSTD_LIB} ($(du -h "${ZSTD_LIB}" | cut -f1))"
else
    echo "==> Using cached ${ZSTD_LIB}"
fi

# Step 2: Build libqbditrace.dylib with zstd
echo "==> Building libqbditrace.dylib (with zstd compression)..."
xcrun --sdk iphoneos clang++ -arch arm64 -std=c++17 -O3 -DNDEBUG -dynamiclib \
    -DQBDITRACE_HAVE_ZSTD=1 \
    -Iinclude -Ibuild-ios/include -Ibuild-ios/include-static \
    -Itools/qbditrace -I"${ZSTD_SRC}" \
    tools/qbditrace/QBDITrace.cpp \
    build-ios/libQBDI.a build-ios/libqbdi-llvm.a "${ZSTD_LIB}" \
    -framework Foundation -framework CoreFoundation \
    -o libqbditrace.dylib

echo "==> Done: libqbditrace.dylib ($(du -h libqbditrace.dylib | cut -f1))"
echo ""
echo "Deploy to device:"
echo "  scp libqbditrace.dylib vphone:/var/jb/usr/lib/libqbditrace.dylib"
echo "  ssh vphone 'ldid -S /var/jb/usr/lib/libqbditrace.dylib'"

#!/bin/bash
# build-dashcam-ios.sh — Build libqbditrace.dylib for iOS arm64 with zstd
#
# Usage (from the Retrace repo root):
#   bash dashcam/build-dashcam-ios.sh
#
# Prerequisites:
#   - scripts/prepare-qbdi.sh ios has been run (patched QBDI static libs
#     cached under third-party/qbdi/ios/)
#   - zstd source cache exists (dashcam/_deps/ or slowmo/_deps/, produced by
#     a prior host cmake configure; fetched on demand otherwise)
#
# Output: libqbditrace.dylib in the repo root (ready for deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

QBDI_CACHE="third-party/qbdi/ios"

# Validate prerequisites
if [[ ! -f "${QBDI_CACHE}/libQBDI.a" ]]; then
    echo "ERROR: ${QBDI_CACHE}/libQBDI.a not found." >&2
    echo "       Run: bash scripts/prepare-qbdi.sh ios" >&2
    exit 1
fi
if [[ ! -f "${QBDI_CACHE}/libqbdi-llvm.a" ]]; then
    echo "ERROR: ${QBDI_CACHE}/libqbdi-llvm.a not found." >&2
    echo "       Run: bash scripts/prepare-qbdi.sh ios" >&2
    exit 1
fi

# zstd sources: prefer dashcam's own FetchContent cache, fall back to the
# shared slowmo cache (either one is a pristine zstd checkout).
ZSTD_SRC=""
for cand in dashcam/_deps/zstd-src/lib slowmo/_deps/zstd-src/lib dashcam/build/_deps/zstd-src/lib; do
    if [[ -f "${cand}/zstd.h" ]]; then ZSTD_SRC="${cand}"; break; fi
done
if [[ -z "${ZSTD_SRC}" ]]; then
    echo "ERROR: zstd source not found (looked in dashcam/_deps and slowmo/_deps)." >&2
    echo "       Run a host cmake configure first: cd dashcam && mkdir -p build && cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF" >&2
    exit 1
fi

# Step 1: Cross-compile zstd for iOS arm64 (if not already built)
ZSTD_LIB="dashcam/build-ios/libzstd.a"
if [[ ! -f "${ZSTD_LIB}" ]]; then
    echo "==> Building libzstd.a for iOS arm64..."
    mkdir -p dashcam/build-ios
    ZSTD_TMP_DIR=$(mktemp -d)
    (cd "${ZSTD_TMP_DIR}" && for f in "${REPO_ROOT}/${ZSTD_SRC}"/common/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/compress/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/decompress/*.c; do
        xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -O3 -DNDEBUG \
            -I"${REPO_ROOT}/${ZSTD_SRC}" -I"${REPO_ROOT}/${ZSTD_SRC}/common" \
            -c "$f" || exit 1
    done)
    ar rcs "${ZSTD_LIB}" "${ZSTD_TMP_DIR}"/*.o
    rm -rf "${ZSTD_TMP_DIR}"
    echo "    -> ${ZSTD_LIB} ($(du -h "${ZSTD_LIB}" | cut -f1))"
else
    echo "==> Using cached ${ZSTD_LIB}"
fi

# Step 2: Build libqbditrace.dylib with zstd
echo "==> Building libqbditrace.dylib (with zstd compression)..."
xcrun --sdk iphoneos clang++ -arch arm64 -miphoneos-version-min=15.0 -std=c++17 -O3 -DNDEBUG -dynamiclib \
    -DQBDITRACE_HAVE_ZSTD=1 \
    -I"${QBDI_CACHE}/include" -I"${QBDI_CACHE}/build-include" \
    -Idashcam -I"${ZSTD_SRC}" \
    dashcam/QBDITrace.cpp \
    "${QBDI_CACHE}/libQBDI.a" "${QBDI_CACHE}/libqbdi-llvm.a" "${ZSTD_LIB}" \
    -framework Foundation -framework CoreFoundation \
    -o libqbditrace.dylib

echo "==> Done: libqbditrace.dylib ($(du -h libqbditrace.dylib | cut -f1))"
echo ""
echo "Deploy to device:"
echo "  scp libqbditrace.dylib vphone:/var/jb/usr/lib/libqbditrace.dylib"
echo "  ssh vphone 'ldid -S /var/jb/usr/lib/libqbditrace.dylib'"

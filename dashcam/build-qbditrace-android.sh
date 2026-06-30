#!/bin/bash
# build-qbditrace-android.sh — Build libqbditrace.so for Android arm64 with zstd
#
# Usage (from the QBDI repo root):
#   bash tools/qbditrace/build-qbditrace-android.sh
#
# Prerequisites:
#   - build-android/libQBDI.a already built (via cmake/config/config-android-aarch64.sh)
#   - NDK_PATH or ANDROID_SDK_ROOT environment variable set
#   - tools/tenet/_deps/zstd-src/ exists (shared FetchContent cache)
#
# Output: libqbditrace.so in the repo root (ready for deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
cd "${REPO_ROOT}"

# ---------------------------------------------------------------------------
# Resolve NDK path
# ---------------------------------------------------------------------------
if [[ -z "${NDK_PATH:-}" ]]; then
    if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
        # Try the versioned ndk/ directory first (modern SDK layout), then legacy ndk-bundle/
        if [[ -d "${ANDROID_SDK_ROOT}/ndk" ]]; then
            NDK_PATH="$(ls -d "${ANDROID_SDK_ROOT}/ndk/"* 2>/dev/null | sort -V | tail -n1)"
        fi
        if [[ -z "${NDK_PATH:-}" ]] && [[ -d "${ANDROID_SDK_ROOT}/ndk-bundle" ]]; then
            NDK_PATH="${ANDROID_SDK_ROOT}/ndk-bundle"
        fi
    fi
fi

if [[ -z "${NDK_PATH:-}" ]] || [[ ! -d "${NDK_PATH}" ]]; then
    echo "ERROR: NDK not found. Set NDK_PATH or ANDROID_SDK_ROOT." >&2
    exit 1
fi
echo "==> Using NDK: ${NDK_PATH}"

# Locate the NDK clang++ (aarch64-linux-android)
NDK_TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt"
HOST_TAG=""
for tag in darwin-x86_64 linux-x86_64 darwin-aarch64; do
    if [[ -d "${NDK_TOOLCHAIN}/${tag}" ]]; then
        HOST_TAG="${tag}"
        break
    fi
done
if [[ -z "${HOST_TAG}" ]]; then
    echo "ERROR: Cannot find NDK prebuilt toolchain in ${NDK_TOOLCHAIN}/" >&2
    exit 1
fi

# API level 24 is the minimum that supports QBDI on Android arm64
API_LEVEL="${ANDROID_API_LEVEL:-24}"
CC="${NDK_TOOLCHAIN}/${HOST_TAG}/bin/aarch64-linux-android${API_LEVEL}-clang"
CXX="${NDK_TOOLCHAIN}/${HOST_TAG}/bin/aarch64-linux-android${API_LEVEL}-clang++"
AR="${NDK_TOOLCHAIN}/${HOST_TAG}/bin/llvm-ar"

if [[ ! -x "${CXX}" ]]; then
    echo "ERROR: NDK clang++ not found at ${CXX}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate prerequisites
# ---------------------------------------------------------------------------
if [[ ! -f build-android/libQBDI.a ]]; then
    echo "ERROR: build-android/libQBDI.a not found." >&2
    echo "       Build QBDI for Android first:" >&2
    echo "         mkdir -p build-android && cd build-android" >&2
    echo "         bash ../cmake/config/config-android-aarch64.sh" >&2
    echo "         ninja" >&2
    exit 1
fi

ZSTD_SRC="tools/tenet/_deps/zstd-src/lib"
if [[ ! -f "${ZSTD_SRC}/zstd.h" ]]; then
    echo "ERROR: zstd source not found at ${ZSTD_SRC}. Run tenet cmake first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Cross-compile zstd for Android arm64 (if not already built)
# ---------------------------------------------------------------------------
ZSTD_LIB="build-android/libzstd.a"
if [[ ! -f "${ZSTD_LIB}" ]]; then
    echo "==> Building libzstd.a for Android arm64..."
    TMPDIR=$(mktemp -d)
    "${CC}" -O2 -DZSTD_MULTITHREAD=0 \
        -I"${ZSTD_SRC}" -I"${ZSTD_SRC}/common" \
        -c "${ZSTD_SRC}"/common/*.c "${ZSTD_SRC}"/compress/*.c "${ZSTD_SRC}"/decompress/*.c \
        -o "${TMPDIR}/" 2>/dev/null || \
    (cd "${TMPDIR}" && "${CC}" -O2 -DZSTD_MULTITHREAD=0 \
        -I"${REPO_ROOT}/${ZSTD_SRC}" -I"${REPO_ROOT}/${ZSTD_SRC}/common" \
        -c "${REPO_ROOT}/${ZSTD_SRC}"/common/*.c \
           "${REPO_ROOT}/${ZSTD_SRC}"/compress/*.c \
           "${REPO_ROOT}/${ZSTD_SRC}"/decompress/*.c)
    "${AR}" rcs "${ZSTD_LIB}" "${TMPDIR}"/*.o
    rm -rf "${TMPDIR}"
    echo "    -> ${ZSTD_LIB} ($(du -h "${ZSTD_LIB}" | cut -f1))"
else
    echo "==> Using cached ${ZSTD_LIB}"
fi

# ---------------------------------------------------------------------------
# Step 2: Build libqbditrace.so with zstd
# ---------------------------------------------------------------------------
echo "==> Building libqbditrace.so (with zstd compression)..."

LLVM_LIB=""
if [[ -f build-android/libqbdi-llvm.a ]]; then
    LLVM_LIB="build-android/libqbdi-llvm.a"
fi

"${CXX}" -std=c++17 -O2 -shared -fPIC \
    -DQBDITRACE_HAVE_ZSTD=1 \
    -Iinclude -Ibuild-android/include -Ibuild-android/include-static \
    -Itools/qbditrace -I"${ZSTD_SRC}" \
    tools/qbditrace/QBDITrace.cpp \
    build-android/libQBDI.a ${LLVM_LIB:+"${LLVM_LIB}"} "${ZSTD_LIB}" \
    -llog \
    -o libqbditrace.so

echo "==> Done: libqbditrace.so ($(du -h libqbditrace.so | cut -f1))"
echo ""
echo "Deploy to device:"
echo "  adb push libqbditrace.so /data/local/tmp/libqbditrace.so"
echo ""
echo "Then in your Frida script / qbditrace_runner.py:"
echo "  --dylib /data/local/tmp/libqbditrace.so"

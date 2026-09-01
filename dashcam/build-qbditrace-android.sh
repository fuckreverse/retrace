#!/bin/bash
# build-qbditrace-android.sh — Build libqbditrace.so for Android arm64 with zstd
#
# Usage (from the QBDI repo root):
#   bash tools/qbditrace/build-qbditrace-android.sh
#
# The script drives the standard CMake NDK toolchain into the fixed build
# directory tools/qbditrace/build-android/ (never create other build dirs —
# see CLAUDE.md). zstd is cross-compiled once with the NDK clang and cached
# at build-android/libzstd.a (source reused from tools/tenet/_deps/zstd-src/;
# it must NOT go through FetchContent — the shared <name>-build dir would
# clobber tenet's host-built zstd).
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

BUILD_DIR="tools/qbditrace/build-android"

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
    # Common Homebrew / standalone locations
    if [[ -z "${NDK_PATH:-}" ]]; then
        for candidate in /opt/homebrew/share/android-ndk /usr/local/share/android-ndk; do
            if [[ -d "${candidate}" ]]; then
                NDK_PATH="${candidate}"
                break
            fi
        done
    fi
fi

if [[ -z "${NDK_PATH:-}" ]] || [[ ! -d "${NDK_PATH}" ]]; then
    echo "ERROR: NDK not found. Set NDK_PATH or ANDROID_SDK_ROOT." >&2
    exit 1
fi
NDK_PATH="$(cd "${NDK_PATH}" && pwd -P)"
TOOLCHAIN_FILE="${NDK_PATH}/build/cmake/android.toolchain.cmake"
if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    echo "ERROR: NDK toolchain file not found at ${TOOLCHAIN_FILE}" >&2
    exit 1
fi
echo "==> Using NDK: ${NDK_PATH}"

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

# API level 24 is the minimum that supports QBDI on Android arm64
API_LEVEL="${ANDROID_API_LEVEL:-24}"

# Locate the NDK clang (aarch64-linux-android)
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
CC="${NDK_TOOLCHAIN}/${HOST_TAG}/bin/aarch64-linux-android${API_LEVEL}-clang"
AR="${NDK_TOOLCHAIN}/${HOST_TAG}/bin/llvm-ar"
if [[ ! -x "${CC}" ]]; then
    echo "ERROR: NDK clang not found at ${CC}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Cross-compile zstd for Android arm64 (cached at build-android/libzstd.a)
# ---------------------------------------------------------------------------
ZSTD_LIB="build-android/libzstd.a"
if [[ ! -f "${ZSTD_LIB}" ]]; then
    echo "==> Building libzstd.a for Android arm64..."
    TMPDIR=$(mktemp -d)
    "${CC}" -O3 -DNDEBUG -DZSTD_MULTITHREAD=0 -fPIC \
        -I"${ZSTD_SRC}" -I"${ZSTD_SRC}/common" \
        -c "${ZSTD_SRC}"/common/*.c "${ZSTD_SRC}"/compress/*.c "${ZSTD_SRC}"/decompress/*.c \
        -o "${TMPDIR}/" 2>/dev/null || \
    (cd "${TMPDIR}" && for f in "${REPO_ROOT}/${ZSTD_SRC}"/common/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/compress/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/decompress/*.c; do
        "${CC}" -O3 -DNDEBUG -DZSTD_MULTITHREAD=0 -fPIC \
            -I"${REPO_ROOT}/${ZSTD_SRC}" -I"${REPO_ROOT}/${ZSTD_SRC}/common" \
            -c "$f" || exit 1
    done)
    "${AR}" rcs "${ZSTD_LIB}" "${TMPDIR}"/*.o
    rm -rf "${TMPDIR}"
    echo "    -> ${ZSTD_LIB} ($(du -h "${ZSTD_LIB}" | cut -f1))"
else
    echo "==> Using cached ${ZSTD_LIB}"
fi

# ---------------------------------------------------------------------------
# Configure (CMake NDK toolchain) into the fixed build dir
# ---------------------------------------------------------------------------
# QBDI_BUILD_INCLUDE_DIR accepts a semicolon list; both layouts are produced
# by QBDI's own android configure.
QBDI_BUILD_INC="${REPO_ROOT}/build-android/include"
[[ -d "${REPO_ROOT}/build-android/include-static" ]] && \
    QBDI_BUILD_INC="${QBDI_BUILD_INC};${REPO_ROOT}/build-android/include-static"

echo "==> Configuring ${BUILD_DIR} (CMake NDK toolchain, API ${API_LEVEL})..."
cmake -S tools/qbditrace -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM="${API_LEVEL}" \
    -DQBDI_INCLUDE_DIR="${REPO_ROOT}/include" \
    -DQBDI_BUILD_INCLUDE_DIR="${QBDI_BUILD_INC}" \
    -DQBDI_STATIC_LIB="${REPO_ROOT}/build-android/libQBDI.a" \
    -DQBDITRACE_ZSTD_STATIC_LIB="${REPO_ROOT}/${ZSTD_LIB}" \
    -DQBDITRACE_ZSTD_INCLUDE_DIR="${REPO_ROOT}/${ZSTD_SRC}" \
    -DQBDITRACE_BUILD_DYLIB=ON \
    -DQBDITRACE_BUILD_TESTS=OFF \
    -DQBDITRACE_ENABLE_ZSTD=ON

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "==> Building libqbditrace.so (with zstd compression)..."
cmake --build "${BUILD_DIR}"

# ---------------------------------------------------------------------------
# Stage the artifact into the repo root (deployment convenience)
# ---------------------------------------------------------------------------
cp -f "${BUILD_DIR}/libqbditrace.so" libqbditrace.so

echo "==> Done: libqbditrace.so ($(du -h libqbditrace.so | cut -f1))"
echo ""
echo "Deploy to device:"
echo "  adb push libqbditrace.so /data/local/tmp/libqbditrace.so"
echo ""
echo "Then in your Frida script / qbditrace_runner.py:"
echo "  --dylib /data/local/tmp/libqbditrace.so"

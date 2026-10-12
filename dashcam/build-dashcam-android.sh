#!/bin/bash
# build-dashcam-android.sh — Build libqbditrace.so for Android arm64 with zstd
#
# Usage (from the Retrace repo root):
#   bash dashcam/build-dashcam-android.sh
#
# The script drives the standard CMake NDK toolchain into the fixed build
# directory dashcam/build-android/ (never create other build dirs —
# see CLAUDE.md). zstd is cross-compiled once with the NDK clang and cached
# at dashcam/build-android/libzstd.a (source reused from the shared
# FetchContent cache; it must NOT go through FetchContent — the shared
# <name>-build dir would clobber the host-built zstd).
#
# Prerequisites:
#   - scripts/prepare-qbdi.sh android has been run (patched QBDI static
#     libs cached under third-party/qbdi/android/)
#   - NDK_PATH or ANDROID_SDK_ROOT environment variable set
#   - zstd source cache exists (dashcam/_deps/ or slowmo/_deps/)
#
# Output: libqbditrace.so in the repo root (ready for deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

BUILD_DIR="dashcam/build-android"
QBDI_CACHE="third-party/qbdi/android"

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
if [[ ! -f "${QBDI_CACHE}/libQBDI.a" ]]; then
    echo "ERROR: ${QBDI_CACHE}/libQBDI.a not found." >&2
    echo "       Run: bash scripts/prepare-qbdi.sh android" >&2
    exit 1
fi
if [[ ! -f "${QBDI_CACHE}/libqbdi-llvm.a" ]]; then
    echo "ERROR: ${QBDI_CACHE}/libqbdi-llvm.a not found." >&2
    echo "       Run: bash scripts/prepare-qbdi.sh android" >&2
    exit 1
fi

# zstd sources: prefer dashcam's own FetchContent cache, fall back to the
# shared slowmo cache.
ZSTD_SRC=""
for cand in dashcam/_deps/zstd-src/lib slowmo/_deps/zstd-src/lib dashcam/build/_deps/zstd-src/lib; do
    if [[ -f "${cand}/zstd.h" ]]; then ZSTD_SRC="${cand}"; break; fi
done
if [[ -z "${ZSTD_SRC}" ]]; then
    echo "ERROR: zstd source not found (looked in dashcam/_deps and slowmo/_deps)." >&2
    echo "       Run a host cmake configure first: cd dashcam && mkdir -p build && cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF" >&2
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
ZSTD_LIB="dashcam/build-android/libzstd.a"
if [[ ! -f "${ZSTD_LIB}" ]]; then
    echo "==> Building libzstd.a for Android arm64..."
    mkdir -p "${BUILD_DIR}"
    ZSTD_TMP_DIR=$(mktemp -d)
    (cd "${ZSTD_TMP_DIR}" && for f in "${REPO_ROOT}/${ZSTD_SRC}"/common/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/compress/*.c \
                                  "${REPO_ROOT}/${ZSTD_SRC}"/decompress/*.c; do
        "${CC}" -O3 -DNDEBUG -fPIC \
            -I"${REPO_ROOT}/${ZSTD_SRC}" -I"${REPO_ROOT}/${ZSTD_SRC}/common" \
            -c "$f" || exit 1
    done)
    "${AR}" rcs "${ZSTD_LIB}" "${ZSTD_TMP_DIR}"/*.o
    rm -rf "${ZSTD_TMP_DIR}"
    echo "    -> ${ZSTD_LIB} ($(du -h "${ZSTD_LIB}" | cut -f1))"
else
    echo "==> Using cached ${ZSTD_LIB}"
fi

# ---------------------------------------------------------------------------
# Configure (CMake NDK toolchain) into the fixed build dir
# ---------------------------------------------------------------------------
# QBDI_BUILD_INCLUDE_DIR accepts a semicolon list; both layouts are produced
# by prepare-qbdi.sh's copy step.
QBDI_BUILD_INC="${REPO_ROOT}/${QBDI_CACHE}/build-include"

echo "==> Configuring ${BUILD_DIR} (CMake NDK toolchain, API ${API_LEVEL})..."
cmake -S dashcam -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_STL=c++_static \
    -DANDROID_PLATFORM="${API_LEVEL}" \
    -DQBDI_INCLUDE_DIR="${REPO_ROOT}/${QBDI_CACHE}/include" \
    -DQBDI_BUILD_INCLUDE_DIR="${QBDI_BUILD_INC}" \
    -DQBDI_STATIC_LIB="${REPO_ROOT}/${QBDI_CACHE}/libQBDI.a" \
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

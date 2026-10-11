#!/bin/bash
# prepare-qbdi.sh — Clone vanilla QBDI at the pinned commit, apply the Retrace
# patch series, and build the static libraries for the requested platform.
#
# Usage (from the Retrace repo root):
#   bash scripts/prepare-qbdi.sh ios       # libQBDI.a + libqbdi-llvm.a (arm64)
#   bash scripts/prepare-qbdi.sh android   # needs NDK_PATH / ANDROID_SDK_ROOT
#   bash scripts/prepare-qbdi.sh host      # macOS host build (for local dev)
#
# Output cache (gitignored):
#   third-party/qbdi/<platform>/libQBDI.a
#   third-party/qbdi/<platform>/libqbdi-llvm.a
#   third-party/qbdi/<platform>/include/       (QBDI public headers)
#   third-party/qbdi/<platform>/build-include/ (Version.h / Config.h)
#
# The per-platform QBDI build tree is kept at third-party/qbdi/<platform>/build/
# so incremental QBDI rebuilds don't re-clone or re-compile from scratch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
PATCH_DIR="${REPO_ROOT}/patches/qbdi"
CACHE_ROOT="${REPO_ROOT}/third-party/qbdi"

PLATFORM="${1:-}"
case "${PLATFORM}" in
    ios|android|host) ;;
    *) echo "Usage: $0 {ios|android|host}" >&2; exit 1 ;;
esac

PIN_SHA="$(head -1 "${PATCH_DIR}/PIN" | awk '{print $1}')"
if [[ ! "${PIN_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
    # PIN must hold the full 40-hex sha: a short sha cannot be resolved once
    # upstream has moved on.
    echo "ERROR: patches/qbdi/PIN must start with a full 40-hex commit sha (got: '${PIN_SHA}')" >&2
    exit 1
fi

SRC_DIR="${CACHE_ROOT}/src"        # patched QBDI source (shared by all platforms)
OUT_DIR="${CACHE_ROOT}/${PLATFORM}"

# ---------------------------------------------------------------------------
# 1. Clone vanilla QBDI once, check out the pinned commit
# ---------------------------------------------------------------------------
if [[ ! -d "${SRC_DIR}/.git" ]]; then
    echo "==> Cloning upstream QBDI into ${SRC_DIR} ..."
    mkdir -p "${CACHE_ROOT}"
    git clone https://github.com/QBDI/QBDI.git "${SRC_DIR}"
fi
cd "${SRC_DIR}"
CURRENT_SHA="$(git rev-parse HEAD)"
if [[ "${CURRENT_SHA}" != "${PIN_SHA}" ]]; then
    echo "==> Checking out pinned QBDI commit ${PIN_SHA} ..."
    git fetch origin dev-next --quiet || git fetch origin --quiet || true
    git checkout --detach "${PIN_SHA}"
fi

# ---------------------------------------------------------------------------
# 2. Apply the patch series (idempotent: skip if the retrace commit exists)
# ---------------------------------------------------------------------------
if ! git log --oneline -1 | grep -q "\[retrace\]"; then
    echo "==> Applying Retrace QBDI patches ..."
    for p in "${PATCH_DIR}"/*.patch; do
        echo "    -> $(basename "${p}")"
        git apply "$p"
    done
    git add -A
    git -c user.name="Retrace build" -c user.email="build@retrace.invalid" commit --quiet -m "[retrace] apply local patch series ($(ls "${PATCH_DIR}"/*.patch | xargs -n1 basename | tr '\n' ' '))"
else
    echo "==> Patches already applied (retrace commit on top of ${PIN_SHA})."
fi

# ---------------------------------------------------------------------------
# 3. Build static libraries for the platform
# ---------------------------------------------------------------------------
BUILD_DIR="${OUT_DIR}/build"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

case "${PLATFORM}" in
    ios)
        if ! command -v xcrun >/dev/null 2>&1; then
            echo "ERROR: iOS build requires Xcode/xcrun." >&2
            exit 1
        fi
        bash "${SRC_DIR}/cmake/config/config-ios-aarch64.sh"
        ;;
    android)
        if [[ -z "${NDK_PATH:-}" ]]; then
            if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
                echo "ERROR: set NDK_PATH or ANDROID_SDK_ROOT." >&2
                exit 1
            fi
            export NDK_PATH="${ANDROID_SDK_ROOT}/ndk-bundle/"
        fi
        if [[ ! -d "${NDK_PATH}" ]]; then
            echo "ERROR: NDK_PATH '${NDK_PATH}' is not a valid directory." >&2
            exit 1
        fi
        export NDK_PATH
        bash "${SRC_DIR}/cmake/config/config-android-aarch64.sh"
        ;;
    host)
        cmake "${SRC_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Release
        ;;
esac

echo "==> Building QBDI (${PLATFORM}) ..."
ninja QBDI_static 2>/dev/null || ninja

# Copy the outputs into a stable layout.
for f in libQBDI.a libqbdi-llvm.a; do
    found=""
    for d in "${BUILD_DIR}" "${BUILD_DIR}/src" "${BUILD_DIR}/package"; do
        if [[ -f "${d}/${f}" ]]; then found="${d}/${f}"; break; fi
    done
    if [[ -z "${found}" ]]; then
        echo "ERROR: ${f} not produced by the ${PLATFORM} build." >&2
        exit 1
    fi
    cp -f "${found}" "${OUT_DIR}/${f}"
done

# Headers: QBDI's cmake generates include/ (public) plus include-shared/ and
# include-static/ (Version.h, Config.h) inside the build dir.
mkdir -p "${OUT_DIR}/include" "${OUT_DIR}/build-include/QBDI"
cp -R "${SRC_DIR}/include/." "${OUT_DIR}/include/"
if [[ -d "${BUILD_DIR}/include-static" ]]; then
    cp -R "${BUILD_DIR}/include-static/." "${OUT_DIR}/build-include/"
fi
if [[ -f "${BUILD_DIR}/include-shared/QBDI/Version.h" ]]; then
    cp -f "${BUILD_DIR}/include-shared/QBDI/Version.h" "${OUT_DIR}/build-include/QBDI/"
fi

echo "==> QBDI ${PLATFORM} ready:"
ls "${OUT_DIR}"
echo ""
echo "dashcam build scripts consume this cache automatically:"
echo "  bash dashcam/build-dashcam-ios.sh"
echo "  bash dashcam/build-dashcam-android.sh"

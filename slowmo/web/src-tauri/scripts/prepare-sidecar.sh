#!/usr/bin/env bash
#
# prepare-sidecar.sh —— 为 Tauri 打包准备 tenet C++ 后端 sidecar 二进制。
#
# 做的事情：
#   1. 在 tools/tenet/build（固定目录，不新建）里以 Release 配置编译 tenet。
#   2. 递归解析 tenet 的动态库依赖，把所有「非系统」dylib（Triton/yara/lz4/
#      mimalloc 及其间接依赖 z3/capstone/openssl/libmagic/jansson 等）复制到
#      src-tauri/binaries/lib/ 下。
#   3. 用 install_name_tool 把 tenet 及每个被复制 dylib 的加载路径统一改写为
#      @rpath/<name>，并给最终二进制加两条 LC_RPATH，使其完全脱离本机
#      homebrew / ~/.local 路径，且同时兼容两种运行场景：
#        - `tauri dev`：直接执行 src-tauri/binaries/tenet-<triple>，此时
#          sidecar 和依赖库同在 binaries/ 目录下 → rpath "@executable_path/lib"
#        - 打包产物：sidecar 落在 .app/Contents/MacOS/，依赖库通过
#          bundle.resources 落在 .app/Contents/Resources/lib/（同级兄弟目录）
#          → rpath "@executable_path/../Resources/lib"
#      dyld 会按顺序依次尝试每条 rpath，找到第一个存在的文件即可，两个场景
#      互不影响。
#   4. 根据实际打包的 dylib、pnpm 锁定依赖和 Cargo.lock 生成第三方许可材料；
#      未登记的动态库或未批准许可证会直接阻断发布。
#   5. 把最终二进制以 Tauri sidecar 命名规则（<name>-<target-triple>）放到
#      src-tauri/binaries/tenet-<triple>，供 tauri.conf.json 的
#      bundle.externalBin 打包进 .app/Contents/MacOS/。
#
# 用法：
#   bash tools/tenet/web/src-tauri/scripts/prepare-sidecar.sh [--debug|--release]
#
# 默认构建类型为 RelWithDebInfo（与 tools/tenet/build 的默认配置一致，
# 增量编译快、运行性能约为 Debug 的 2-3×）。
#   --debug   切到 Debug（-O0 -g，最快编译，最慢运行）
#   --release 切到 Release（-O3 + ThinLTO + -mcpu，最慢编译，最快运行，发布用）
#
# 幂等：可重复运行；每次都会覆盖 binaries/ 下的产物。
#
# 仅支持 macOS（arm64/x86_64）。Windows/Linux sidecar 需要另行适配（见脚本末尾说明）。

set -euo pipefail

# ── 路径 ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_TAURI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TENET_DIR="$(cd "${SRC_TAURI_DIR}/../.." && pwd)"   # tools/tenet
BUILD_DIR="${TENET_DIR}/build"
BIN_OUT_DIR="${SRC_TAURI_DIR}/binaries"
LIB_OUT_DIR="${BIN_OUT_DIR}/lib"
LICENSE_OUT_DIR="${BIN_OUT_DIR}/licenses"
LICENSE_MANIFEST="${SRC_TAURI_DIR}/licenses/native-components.json"
LICENSE_COLLECTOR="${SCRIPT_DIR}/collect_licenses.py"
WEB_DIR="$(cd "${SRC_TAURI_DIR}/.." && pwd)"

BUILD_TYPE="RelWithDebInfo"
if [[ "${1:-}" == "--debug" ]]; then
  BUILD_TYPE="Debug"
elif [[ "${1:-}" == "--release" ]]; then
  BUILD_TYPE="Release"
fi

echo "==> tenet sidecar 准备脚本"
echo "    TENET_DIR   = ${TENET_DIR}"
echo "    BUILD_DIR   = ${BUILD_DIR}"
echo "    BUILD_TYPE  = ${BUILD_TYPE}"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "错误：本脚本目前仅支持 macOS。" >&2
  exit 1
fi

# ── 1. 编译 tenet（复用固定 build 目录，禁止新建）────────────────────────
if [[ ! -d "${BUILD_DIR}" ]]; then
  echo "错误：${BUILD_DIR} 不存在。请先按 CLAUDE.md 的说明初始化一次：" >&2
  echo "  cd ${TENET_DIR} && mkdir build && cd build && cmake .. && ninja" >&2
  exit 1
fi

echo "==> 切换 build 目录为 ${BUILD_TYPE} 并增量编译 tenet ..."
cmake -S "${TENET_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" >/dev/null
cmake --build "${BUILD_DIR}" --target tenet -j"$(sysctl -n hw.ncpu)"

TENET_BIN="${BUILD_DIR}/tenet"
if [[ ! -x "${TENET_BIN}" ]]; then
  echo "错误：编译后未找到可执行文件 ${TENET_BIN}" >&2
  exit 1
fi

# ── 2. 确定 target triple（sidecar 命名规则）──────────────────────────────
if command -v rustc >/dev/null 2>&1; then
  TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
else
  ARCH="$(uname -m)"
  if [[ "${ARCH}" == "arm64" ]]; then
    TARGET_TRIPLE="aarch64-apple-darwin"
  else
    TARGET_TRIPLE="x86_64-apple-darwin"
  fi
fi
echo "==> target triple: ${TARGET_TRIPLE}"

rm -rf "${BIN_OUT_DIR}"
mkdir -p "${LIB_OUT_DIR}"

FINAL_BIN="${BIN_OUT_DIR}/tenet-${TARGET_TRIPLE}"
cp "${TENET_BIN}" "${FINAL_BIN}"
chmod +x "${FINAL_BIN}"

# ── 3. 递归收集「非系统」dylib 依赖 ────────────────────────────────────────
#
# 系统路径（无需打包，运行环境总有）：/usr/lib/**, /System/**
# 其余（homebrew、~/.local、项目 _deps 构建产物等）一律视为需要打包的第三方库。

is_system_path() {
  case "$1" in
    /usr/lib/*|/System/*) return 0 ;;
    *) return 1 ;;
  esac
}

# 已处理集合（避免重复拷贝/死循环），用换行分隔的字符串模拟 set
declare -a PROCESSED_NAMES=()

already_processed() {
  local name="$1"
  local n
  for n in "${PROCESSED_NAMES[@]:-}"; do
    [[ "$n" == "$name" ]] && return 0
  done
  return 1
}

# 取出一个 Mach-O 文件的 LC_RPATH 列表（每行一个绝对路径）。
list_rpaths() {
  otool -l "$1" | awk '
    /^ *cmd LC_RPATH/ { want=1; next }
    want && /^ *path / { sub(/^ *path /, ""); sub(/ \(offset.*/, ""); print; want=0 }
  '
}

# 把 @rpath/xxx.dylib 解析为绝对路径：依次尝试 target 自身的 LC_RPATH 列表。
# $1 = 待解析的 @rpath/... 字符串   $2 = 引用它的文件（其 LC_RPATH 才有意义）
resolve_rpath() {
  local dep_path="$1" target="$2" rpath candidate
  local suffix="${dep_path#@rpath/}"
  while IFS= read -r rpath; do
    [[ -z "$rpath" ]] && continue
    candidate="${rpath}/${suffix}"
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done < <(list_rpaths "$target")
  return 1
}

# 收集一个 Mach-O 文件（可执行文件或 dylib）的「非系统」依赖，逐个拷贝+递归。
# $1 = 待扫描的文件路径（已经在其最终位置，即 FINAL_BIN 或 LIB_OUT_DIR 下的拷贝，
#      此时其 LC_RPATH 仍是从源文件原样继承来的，尚未被第 4 步清理）
collect_deps() {
  local target="$1"
  local target_name="$(basename "$target")"
  local line dep_path dep_name resolved

  while IFS= read -r line; do
    # otool -L 输出形如: "\t/path/to/lib.dylib (compatibility version ...)"
    dep_path="$(echo "$line" | sed -E 's/^[[:space:]]*([^[:space:]]+).*/\1/')"
    [[ -z "$dep_path" ]] && continue

    # dylib 的 otool -L 第一条依赖项固定是它自己的 LC_ID_DYLIB（自引用），
    # 例如 libtriton.dylib 被再次处理时会看到 "@rpath/libtriton.dylib" 指向自己，
    # 必须跳过，否则会被当成"找不到的依赖"报警。可执行文件没有 LC_ID_DYLIB，
    # 不受影响。
    if [[ "$(basename "$dep_path")" == "$target_name" ]]; then
      continue
    fi

    # 跳过 @loader_path / @executable_path 自引用（当前无需处理，指向自身或已处理路径）
    case "$dep_path" in
      @loader_path/*|@executable_path/*) continue ;;
      @rpath/*)
        # @rpath/xxx.dylib：需要用 target 自身的 LC_RPATH 解析出真实文件，
        # 不能直接跳过——很多第三方库（Triton/mimalloc）就是用 @rpath 形式引用的。
        resolved="$(resolve_rpath "$dep_path" "$target" || true)"
        if [[ -z "$resolved" ]]; then
          echo "    警告：无法用 LC_RPATH 解析 $dep_path（引用自 $(basename "$target")），跳过" >&2
          continue
        fi
        dep_path="$resolved"
        ;;
    esac

    if is_system_path "$dep_path"; then
      continue
    fi

    dep_name="$(basename "$dep_path")"

    # 改写引用方（target）里对这个依赖的加载路径 → @rpath/<name>（具体解析交给运行时的
    # 多条 LC_RPATH 完成，见下方第 4 步）。注意：对于原本就是 @rpath/xxx 的条目，
    # -change 的 old 参数必须是原始的 "@rpath/xxx" 字符串（而非我们解析出的绝对路径）。
    case "$line" in
      *@rpath/*)
        install_name_tool -change "@rpath/${dep_name}" "@rpath/${dep_name}" "$target" 2>/dev/null || true
        ;;
      *)
        install_name_tool -change "$dep_path" "@rpath/${dep_name}" "$target" 2>/dev/null || true
        ;;
    esac

    if already_processed "$dep_name"; then
      continue
    fi

    if [[ ! -f "$dep_path" ]]; then
      echo "    警告：找不到依赖库 $dep_path（引用自 $(basename "$target")），跳过" >&2
      continue
    fi

    echo "    收集依赖: $dep_name  <-  $dep_path"
    local dest="${LIB_OUT_DIR}/${dep_name}"
    cp -n "$dep_path" "$dest" 2>/dev/null || cp "$dep_path" "$dest"
    chmod u+w "$dest"

    # 修正被拷贝库自身的 install name（LC_ID_DYLIB）为 @rpath/<name>，否则其他库
    # 按名字找它时可能仍解析到旧的绝对路径。
    install_name_tool -id "@rpath/${dep_name}" "$dest" 2>/dev/null || true

    PROCESSED_NAMES+=("$dep_name")

    # 递归处理这个被拷贝库自己的依赖（此时 $dest 的 LC_RPATH 仍是源文件原有的，
    # 足够 resolve_rpath 继续解析它自己的 @rpath/ 依赖）
    collect_deps "$dest"
  done < <(otool -L "$target" | tail -n +2)
}

echo "==> 递归收集 tenet 的第三方动态库依赖 ..."
collect_deps "${FINAL_BIN}"

# ── 4. 重写 rpath：把所有开发机专属的 LC_RPATH 换成两条兼容 dev/打包两种场景的相对 rpath
# ──────────────────────────────────────────────────────────────────────────────
#
# @executable_path/lib                    —— `tauri dev` 场景：sidecar 与
#                                             lib/ 同在 src-tauri/binaries/ 下
# @executable_path/../Resources/lib       —— 打包场景：sidecar 在
#                                             Contents/MacOS/，lib/ 通过
#                                             bundle.resources 落在
#                                             Contents/Resources/lib/
#
# dyld 会按顺序依次尝试，找到第一个存在的文件即可；两条 rpath 同时挂在
# tenet 可执行文件与每个被拷贝的 dylib 上，确保无论是可执行文件直接加载，
# 还是 dylib 之间相互加载，都能正确解析 @rpath/<name>。
rewrite_rpaths() {
  local file="$1"
  while IFS= read -r rpath; do
    [[ -z "$rpath" ]] && continue
    install_name_tool -delete_rpath "$rpath" "$file" 2>/dev/null || true
  done < <(list_rpaths "$file")
  install_name_tool -add_rpath "@executable_path/lib" "$file" 2>/dev/null || true
  install_name_tool -add_rpath "@executable_path/../Resources/lib" "$file" 2>/dev/null || true
}

echo "==> 重写 rpath（同时兼容 dev 与打包两种布局）..."
rewrite_rpaths "${FINAL_BIN}"
while IFS= read -r -d '' dylib; do
  rewrite_rpaths "$dylib"
done < <(find "${LIB_OUT_DIR}" -type f -name '*.dylib' -print0)

# ── 5. 代码签名（ad-hoc，避免 macOS Gatekeeper 因改写 load command 而拒绝加载）
echo "==> 对 sidecar 二进制与依赖库做 ad-hoc 代码签名 ..."
find "${LIB_OUT_DIR}" -type f -name '*.dylib' -print0 | xargs -0 -I{} codesign --force --sign - {} 2>/dev/null || true
codesign --force --sign - "${FINAL_BIN}" 2>/dev/null || true

# ── 6. 生成第三方许可证资源 ─────────────────────────────────────────────────
# 以实际收集到的 dylib 为准核对原生清单，并从 pnpm/Cargo 锁定依赖生成声明。
# GraphGridLayout 的许可问题按产品决策单独跟踪，不在本清单中静默处理。
echo "==> 生成并校验第三方许可证材料 ..."
python3 "${LICENSE_COLLECTOR}" \
  --manifest "${LICENSE_MANIFEST}" \
  --lib-dir "${LIB_OUT_DIR}" \
  --web-dir "${WEB_DIR}" \
  --src-tauri-dir "${SRC_TAURI_DIR}" \
  --output "${LICENSE_OUT_DIR}"

echo "==> 完成。"
echo "    sidecar 二进制: ${FINAL_BIN}"
echo "    依赖库目录:     ${LIB_OUT_DIR} ($(find "${LIB_OUT_DIR}" -type f | wc -l | tr -d ' ') 个文件)"
echo "    许可证目录:     ${LICENSE_OUT_DIR} ($(find "${LICENSE_OUT_DIR}" -type f | wc -l | tr -d ' ') 个文件)"
echo
echo "校验（应仅剩系统库 / @executable_path 引用）："
otool -L "${FINAL_BIN}"

#!/usr/bin/env bash
#
# prepare-sidecar-linux.sh —— 为 Tauri Linux 打包准备 tenet C++ 后端 sidecar。
#
# 做的事情：
#   1. 在 slowmo/build（固定目录，不新建）里按指定配置增量编译 tenet。
#   2. 用 ldd 递归解析 ELF 依赖，把所有「非系统」共享库复制到
#      src-tauri/binaries/lib/ 下。
#   3. 用 patchelf 为 sidecar 和被复制的 .so 设置相对 RPATH，同时兼容
#      `tauri dev` 与常见 Linux bundle（AppImage/deb/rpm）目录布局。
#   4. 复用 collect_licenses.py 生成并校验第三方许可证材料。
#   5. 按 Tauri externalBin 规则输出 tenet-<target-triple>。
#
# 用法：
#   bash slowmo/web/src-tauri/scripts/prepare-sidecar-linux.sh [--debug|--release]
#
# 默认构建类型为 RelWithDebInfo；--debug 选择 Debug，--release 选择 Release。
# 幂等：每次运行都会重新生成 src-tauri/binaries/ 下的 sidecar、依赖和许可证。
# 仅支持 Linux（x86_64/aarch64）。Linux 不需要 macOS 的代码签名步骤。
#

set -euo pipefail

# ── 路径 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_TAURI_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TENET_DIR="$(cd "${SRC_TAURI_DIR}/../.." && pwd)"   # slowmo
BUILD_DIR="${TENET_DIR}/build"
BIN_OUT_DIR="${SRC_TAURI_DIR}/binaries"
LIB_OUT_DIR="${BIN_OUT_DIR}/lib"
LICENSE_OUT_DIR="${BIN_OUT_DIR}/licenses"
LICENSE_MANIFEST="${SRC_TAURI_DIR}/licenses/native-components.json"
LICENSE_COLLECTOR="${SCRIPT_DIR}/collect_licenses.py"
WEB_DIR="$(cd "${SRC_TAURI_DIR}/.." && pwd)"

BUILD_TYPE="RelWithDebInfo"
case "${1:-}" in
  "") ;;
  --debug) BUILD_TYPE="Debug" ;;
  --release) BUILD_TYPE="Release" ;;
  *)
    echo "错误：未知参数 '$1'。用法：$0 [--debug|--release]" >&2
    exit 1
    ;;
esac

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "错误：本脚本仅支持 Linux。当前系统：$(uname -s)" >&2
  exit 1
fi

for command_name in cmake ldd python3; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "错误：缺少必需命令 '${command_name}'，请先安装后重试。" >&2
    exit 1
  fi
done

if ! command -v patchelf >/dev/null 2>&1; then
  echo "错误：未找到 patchelf，无法重写 ELF RPATH。" >&2
  echo "请先安装，例如：" >&2
  echo "  Debian/Ubuntu: sudo apt install patchelf" >&2
  echo "  Fedora/RHEL:   sudo dnf install patchelf" >&2
  exit 1
fi

echo "==> tenet Linux sidecar 准备脚本"
echo "    TENET_DIR   = ${TENET_DIR}"
echo "    BUILD_DIR   = ${BUILD_DIR}"
echo "    BUILD_TYPE  = ${BUILD_TYPE}"

# ── 1. 编译 tenet（复用固定 build 目录，禁止新建其他 build 目录）─────────────
if [[ ! -d "${BUILD_DIR}" ]]; then
  echo "错误：固定构建目录 ${BUILD_DIR} 不存在。" >&2
  echo "请先按 CLAUDE.md 的说明初始化 slowmo/build，再重新运行本脚本；" >&2
  echo "本脚本不会创建 build-linux、build-release 等新目录。" >&2
  exit 1
fi

echo "==> 切换固定 build 目录为 ${BUILD_TYPE} 并增量编译 tenet ..."
cmake -S "${TENET_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" >/dev/null
cmake --build "${BUILD_DIR}" --target tenet -j"$(nproc)"

TENET_BIN="${BUILD_DIR}/tenet"
if [[ ! -x "${TENET_BIN}" ]]; then
  echo "错误：编译后未找到可执行文件 ${TENET_BIN}" >&2
  exit 1
fi

# ── 2. 确定 target triple（Tauri sidecar 命名规则）───────────────────────────
TARGET_TRIPLE=""
if command -v rustc >/dev/null 2>&1; then
  TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p' | head -n 1)"
  if [[ -z "${TARGET_TRIPLE}" ]]; then
    echo "警告：rustc 存在，但无法从 'rustc -vV' 解析 host triple；改用 uname。" >&2
  fi
fi

if [[ -z "${TARGET_TRIPLE}" ]]; then
  case "$(uname -m)" in
    x86_64) TARGET_TRIPLE="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) TARGET_TRIPLE="aarch64-unknown-linux-gnu" ;;
    *)
      echo "错误：无法为架构 '$(uname -m)' 推断 Linux target triple；请安装 rustc。" >&2
      exit 1
      ;;
  esac
fi

echo "==> target triple: ${TARGET_TRIPLE}"

rm -rf "${BIN_OUT_DIR}"
mkdir -p "${LIB_OUT_DIR}"

FINAL_BIN="${BIN_OUT_DIR}/tenet-${TARGET_TRIPLE}"
cp "${TENET_BIN}" "${FINAL_BIN}"
chmod +x "${FINAL_BIN}"

# ── 3. 递归收集「非系统」ELF 共享库依赖 ─────────────────────────────────────
#
# /lib、/lib64、/usr/lib、/usr/lib64（含其多架构子目录）以及动态加载器由目标
# Linux 系统提供，不随应用打包。/usr/local、项目 _deps、Conda/pyenv 和其他
# 自定义前缀下的库均视为第三方依赖并递归收集。
#
# 这里以 ldd 已解析出的绝对路径为准。遇到 "not found" 立即失败，避免产出一个
# 只能在构建机上运行、到用户机器才暴露缺库问题的 bundle。
is_system_dependency() {
  local dep_path="$1"
  local dep_name
  dep_name="$(basename "${dep_path}")"

  case "${dep_name}" in
    linux-vdso.so*|ld-linux*.so*|ld-musl-*.so*) return 0 ;;
  esac

  case "${dep_path}" in
    /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) return 0 ;;
    *) return 1 ;;
  esac
}

# 输出格式为 "依赖名<TAB>绝对路径"。直接加载器行（没有 "=>"）也会被识别；
# linux-vdso 等没有磁盘路径的伪依赖会被忽略。
#
# 注意：glibc 的 ldd 会执行目标 ELF 的动态加载器；本脚本只应处理本项目刚刚
# 编译出的可信 tenet 及其可信构建依赖，不能用于来源不明的二进制。
list_ldd_dependencies() {
  local target="$1"
  local output

  if ! output="$(ldd "${target}" 2>&1)"; then
    echo "错误：ldd 无法解析 ${target}：" >&2
    printf '%s\n' "${output}" >&2
    return 1
  fi

  awk '
    /=>[[:space:]]+not found/ {
      print "NOT_FOUND\t" $1
      next
    }
    /=>[[:space:]]+\// {
      print "FOUND\t" $1 "\t" $3
      next
    }
    /^[[:space:]]*\// {
      path = $1
      name = path
      sub(/^.*\//, "", name)
      print "FOUND\t" name "\t" path
    }
  ' <<<"${output}"
}

# basename -> 源文件 realpath。关联数组既防止递归环，也用于检测两个不同库意外
# 具有相同 SONAME/basename 的冲突，避免后收集的库静默覆盖先收集的库。
declare -A COLLECTED_SOURCES=()

collect_dependencies() {
  local target="$1"
  local dependencies status dep_name dep_path source_real dest

  # 不直接把函数放进进程替换：进程替换中的 ldd 失败不会被 set -e 捕获。
  dependencies="$(list_ldd_dependencies "${target}")"

  while IFS=$'\t' read -r status dep_name dep_path; do
    [[ -z "${status}" ]] && continue

    if [[ "${status}" == "NOT_FOUND" ]]; then
      echo "错误：依赖 '${dep_name}' 未找到（引用自 ${target}）。" >&2
      exit 1
    fi

    if [[ "${status}" != "FOUND" || -z "${dep_path}" ]]; then
      continue
    fi

    if is_system_dependency "${dep_path}"; then
      continue
    fi

    if [[ ! -f "${dep_path}" ]]; then
      echo "错误：ldd 返回的依赖路径不存在：${dep_path}（引用自 ${target}）" >&2
      exit 1
    fi

    source_real="$(readlink -f "${dep_path}")"
    if [[ -n "${COLLECTED_SOURCES[$dep_name]+present}" ]]; then
      if [[ "${COLLECTED_SOURCES[$dep_name]}" != "${source_real}" ]]; then
        echo "错误：发现同名但来源不同的共享库 '${dep_name}'：" >&2
        echo "  ${COLLECTED_SOURCES[$dep_name]}" >&2
        echo "  ${source_real}" >&2
        exit 1
      fi
      continue
    fi

    echo "    收集依赖: ${dep_name}  <-  ${dep_path}"
    dest="${LIB_OUT_DIR}/${dep_name}"
    cp -L "${dep_path}" "${dest}"
    chmod u+w "${dest}"
    COLLECTED_SOURCES["$dep_name"]="${source_real}"

    # 从原始路径递归扫描，确保依赖中使用 $ORIGIN 的 RUNPATH 仍以源库目录解析；
    # 依赖集合通过关联数组去重，因此循环依赖不会造成无限递归。
    collect_dependencies "${dep_path}"
  done <<<"${dependencies}"
}

echo "==> 递归收集 tenet 的第三方共享库依赖 ..."
collect_dependencies "${FINAL_BIN}"

# ── 4. 重写 RPATH/RUNPATH ────────────────────────────────────────────────────
#
# patchelf --set-rpath 接受冒号分隔的多个候选路径，动态链接器会依次尝试：
#   $ORIGIN/lib
#     `tauri dev`：sidecar 位于 src-tauri/binaries/，库位于其 lib/ 子目录。
#   $ORIGIN/../lib
#     常见 AppImage/deb/rpm：externalBin 位于 usr/bin，资源靠近 usr/lib。
#   $ORIGIN/../lib/Tenet/lib 与 $ORIGIN/../lib/tenet/lib
#     Tauri Linux bundle 常把 resources 放到 usr/lib/<product-name>/；配置又把
#     binaries/lib/* 映射到资源目录的 lib/，不同打包器可能保留或小写产品名。
#   $ORIGIN
#     对 lib/ 内的共享库本身，允许其解析同目录下的间接依赖。
#
# 以上是基于 Tauri v2 常见 Linux 布局的有界兼容假设；全部使用相对路径，不把
# 构建机上的 /usr/local、Conda 或 _deps 绝对路径泄漏进最终产物。
BUNDLE_RPATH='$ORIGIN/lib:$ORIGIN/../lib:$ORIGIN/../lib/Tenet/lib:$ORIGIN/../lib/tenet/lib:$ORIGIN'

rewrite_rpath() {
  local target="$1"
  patchelf --set-rpath "${BUNDLE_RPATH}" "${target}"
}

echo "==> 重写 RPATH（同时兼容 dev 与常见 Linux bundle 布局）..."
rewrite_rpath "${FINAL_BIN}"
while IFS= read -r -d '' shared_library; do
  rewrite_rpath "${shared_library}"
done < <(find "${LIB_OUT_DIR}" -type f \( -name '*.so' -o -name '*.so.*' \) -print0)

# Linux ELF 在 RPATH 改写后不需要执行 macOS 的 codesign 步骤。

# ── 5. 生成第三方许可证资源 ─────────────────────────────────────────────────
echo "==> 生成并校验第三方许可证材料 ..."
python3 "${LICENSE_COLLECTOR}" \
  --manifest "${LICENSE_MANIFEST}" \
  --lib-dir "${LIB_OUT_DIR}" \
  --web-dir "${WEB_DIR}" \
  --src-tauri-dir "${SRC_TAURI_DIR}" \
  --output "${LICENSE_OUT_DIR}"

LIBRARY_COUNT="$(find "${LIB_OUT_DIR}" -type f | wc -l | tr -d '[:space:]')"
LICENSE_COUNT="$(find "${LICENSE_OUT_DIR}" -type f | wc -l | tr -d '[:space:]')"

echo "==> 完成。"
echo "    sidecar 二进制: ${FINAL_BIN}"
echo "    依赖库目录:     ${LIB_OUT_DIR} (${LIBRARY_COUNT} 个文件)"
echo "    许可证目录:     ${LICENSE_OUT_DIR} (${LICENSE_COUNT} 个文件)"
echo
echo "校验（所有非系统依赖都应解析到打包目录，且不应出现 'not found'）："
FINAL_LDD_OUTPUT="$(ldd "${FINAL_BIN}" 2>&1)"
printf '%s\n' "${FINAL_LDD_OUTPUT}"
if grep -q '=>[[:space:]]*not found' <<<"${FINAL_LDD_OUTPUT}"; then
  echo "错误：最终 sidecar 仍有未解析的共享库依赖。" >&2
  exit 1
fi

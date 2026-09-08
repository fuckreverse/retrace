# USAGE — 从环境安装到完整分析

本文档覆盖完整的端到端工作流：

1. **环境安装**（宿主机 + 目标设备）
2. **编译** qbditrace + tenet
3. **录制** trace（iOS / Android）
4. **分析** trace（Tauri Web 前端 / TUI / CLI / RPC / MCP / WS）

---

## 一、环境安装

### 1.1 宿主机（Windows / Linux / macOS）

`tenet` 后端与 Tauri 前端以 Windows（x86_64/arm64）、Linux（x86_64/arm64）、macOS（x86_64/arm64）为构建运行目标。三平台 CI 已建立，但尚未在真实 Windows/Linux 物理机上完成完整人工验收。以下安装命令仍以 macOS 开发环境为例；其他平台请安装对应的 CMake、Ninja、C++ 工具链及所需可选依赖。

**基础工具链（macOS 示例）：**

```bash
# Xcode Command Line Tools
xcode-select --install

# Homebrew 包管理器（如未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Ninja 构建系统（tenet 和 qbditrace 均使用）
brew install ninja cmake

# Capstone（tenet 反汇编引擎，若需 --dump 模式）
brew install capstone
```

**Python 与 Frida（录制端需要）：**

```bash
# Python 3.9+
brew install python3

# Frida Python 绑定（必须与设备端 frida-server 版本匹配）
pip3 install frida frida-tools
```

> **重要**：Frida Python 版本必须与目标设备上的 `frida-server` / `frida-gadget` 版本兼容，推荐客户端与服务端使用完全相同的版本。不要照抄固定的大版本号；先在两端执行版本查询，再安装对应版本。

**tenet 可选依赖：**

```bash
# Triton 符号执行（精确语义污点分析，可选）
# 需要手动从源码构建或使用预编译包，见 Triton 官方文档

# YARA（模式规则匹配，可选）
brew install yara
```

**zstd（trace 压缩，通过 FetchContent 自动下载，通常无需手动安装）**

---

### 1.2 iOS 目标设备（越狱）

**Frida 安装（选其一）：**

- **通过越狱工具的包管理器**（Sileo/Cydia）安装 `frida` 包
- **手动安装 frida-server**：从 [GitHub Releases](https://github.com/frida/frida/releases) 下载对应版本的 `frida-server-ios-arm64`，推到设备并启动

```bash
# 验证 Frida 连接
frida-ps -H 127.0.0.1:27042   # USB 转发端口，或直接用 IP
```

**建议的 SSH 隧道设置（开发时更稳定）：**

```bash
# 把设备 22 端口转发到本机 2222
iproxy 2222 22 &
# 把 frida-server 端口转发到本机
iproxy 27042 27042 &
```

---

### 1.3 Android 目标设备

```bash
# 安装 Android 工具
brew install android-platform-tools  # adb

# 验证设备连接
adb devices

# 推送 frida-server
adb push frida-server-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# 端口转发
adb forward tcp:27042 tcp:27042
```

---

## 二、编译

> **⚠️ 禁止随意创建新 build 目录**——每次新建都会重新下载并编译所有第三方依赖（tenet 需 30 分钟以上）。严格使用下方的固定目录。

### 2.1 编译 qbditrace tracer dylib（iOS AArch64）

使用脚本（推荐，在仓库根目录执行）：

```bash
bash tools/qbditrace/build-qbditrace-ios.sh
```

产物：仓库根目录下的 `libqbditrace.dylib`

**推送到设备并签名：**

```bash
# 签名（无 entitlement）
ldid -S libqbditrace.dylib

# 推送到越狱设备
scp libqbditrace.dylib root@localhost:/var/jb/usr/lib/
# 或通过 USB
scp -P 2222 libqbditrace.dylib root@localhost:/var/jb/usr/lib/
```

---

### 2.2 编译 qbditrace tracer .so（Android AArch64）

```bash
export NDK_PATH=/path/to/android-ndk-rXXX
bash tools/qbditrace/build-qbditrace-android.sh
```

产物：仓库根目录下的 `libqbditrace.so`

**推送到设备：**

```bash
adb push libqbditrace.so /data/local/tmp/
adb shell chmod 644 /data/local/tmp/libqbditrace.so
```

---

### 2.3 编译 tenet 后端（Windows / Linux / macOS host）

**首次构建：**

```bash
cd tools/tenet
mkdir build && cd build
cmake ..                  # 默认 RelWithDebInfo，兼顾运行与增量编译速度
ninja -j$(nproc)
```

需要最快编译、可接受较慢运行时，可在同一固定目录显式切到 Debug：

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
ninja -j$(nproc)
```

**增量构建（日常开发）：**

```bash
cd tools/tenet/build
ninja -j$(nproc)          # 改单个 .cpp 通常 3-4 秒
```

**关键 CMake 选项速查：**

| 选项 | 默认 | 说明 |
|------|------|------|
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | `Debug`/`RelWithDebInfo`/`Release`；Release 启用 ThinLTO，Apple Silicon host 还启用 `-mcpu=apple-m1` |
| `TENET_ENABLE_TRITON` | Windows `OFF`，其他平台 `ON` | Triton 精确语义污点（需预装 libTriton） |
| `TENET_ENABLE_YARA` | Windows `OFF`，其他平台 `ON` | YARA 模式匹配（需预装 YARA） |
| `TENET_BUILD_TESTS` | `ON` | 单元测试 |
| `TENET_ENABLE_TBB` | `ON` | Intel TBB 并行排序、DAG 调度与 Scan Fusion |
| `TENET_ENABLE_RPC` | `ON` | TCP loopback JSON-RPC 服务 |
| `TENET_ENABLE_WS` | Windows `OFF`，Linux/macOS `ON` | uWebSockets + FlatBuffers 服务；Windows 支持仍待补齐 |
| `TENET_ENABLE_PROFILING` | `ON` | 仅 macOS 生效的 `os_signpost` 插桩 |
| `TENET_ENABLE_PYTHON` | `OFF` | pybind11 Python 绑定 |
| `TENET_PGO_MODE` | 空 | `generate` / `use` 两阶段 PGO |

跨平台兼容层位于 `src/common/platform_compat.h`、`platform_mmap.h`、`platform_paths.h`、`platform_file_lock.h`。`tenet` 可执行文件只包含 CLI / TUI / RPC / MCP / WS 等后端能力，不再包含 ImGui、Metal、SDL3 或其他原生窗口/渲染代码。

不带 Triton 的快速构建：

```bash
# 在 build-no-triton/ 目录（不要在 build/ 里关掉，避免重触依赖）
mkdir -p tools/tenet/build-no-triton && cd tools/tenet/build-no-triton
cmake .. -DTENET_ENABLE_TRITON=OFF
ninja -j$(nproc)
```

---

### 2.4 离线解码（tenet --dump）

独立的 `trace_decode` 已移除，其功能由 `tenet --dump` 接替：

```bash
# 人类可读文本格式
tenet --dump text trace.bin

# 机器可读 JSONL 格式
tenet --dump jsonl trace.bin
```

> `tenet --dump` 支持 v4/v5/v7 全格式（含默认分块压缩），无需单独构建。

---

## 三、录制 trace

### 3.1 基本用法（iOS）

```bash
# 录制主模块中某个函数（使用 IDA 静态偏移）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xEE91EC \
    --output /var/mobile/Documents/trace.bin

# 录制导出符号
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry _CCCrypt \
    --output /var/mobile/Documents/trace.bin

# 录制特定 framework 中的函数
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --module SomeFramework \
    --entry 0x1234 \
    --output /var/mobile/Documents/trace.bin
```

> **`--entry` 偏移怎么取**：IDA 中函数地址 `0x100A1B2C0`，镜像基址 `0x100000000`，则 `--entry 0xA1B2C0`。loader 自动加 ASLR slide。

### 3.2 基本用法（Android）

```bash
# Android native 库函数
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --android \
    --module libnative.so \
    --entry 0x1234 \
    --output /data/local/tmp/trace.bin

# Java 方法作为触发器：hook Java 层 native bridge，参数自动物化
# （int/long → 立即数，String → UTF-8 字符串，对象 → jobject handle）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --android \
    --module libnative.so \
    --entry 0x1234 \
    --java-entry com.example.NativeBridge.doWork \
    --output /data/local/tmp/trace.bin

# 录制完成后拉回宿主机
adb pull /data/local/tmp/trace.bin ./trace.bin
```

### 3.3 Attach 已运行进程

```bash
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --attach \
    --entry 0xABC \
    --output /var/mobile/Documents/trace.bin
```

### 3.4 捕获多次调用

```bash
# 捕获 5 次调用（生成 5 个 trace 文件）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-mode 5 \
    --output /var/mobile/Documents/trace.bin

# 无限捕获（Ctrl+C 停止）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-mode multi \
    --output /var/mobile/Documents/trace.bin
```

### 3.5 录制参数调优

```bash
# 启用 v5 PC-delta 模式（文件体积通常减少 40%–60%）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --entry 0xABC --pc-delta \
    --output /var/mobile/Documents/trace.bin

# 启用 v7 FPR/NEON 录制（密码学分析时有用）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --entry 0xABC --fpr \
    --output /var/mobile/Documents/trace.bin

# 调整 ring buffer（默认 64 MiB，大函数可能需要更大）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --ring-bytes $((256 * 1024 * 1024)) \
    --output /var/mobile/Documents/trace.bin

# 调整 ANCHOR 间隔（默认 1024 条指令，越小定位越快，文件越大）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --anchor-interval 512 \
    --output /var/mobile/Documents/trace.bin

# 排除噪声区间（静态偏移，格式 START-END 或 START:SIZE，最多 8 个）
# 排除区域原生执行不产生 trace 记录
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 0x1000-0x2000 --exclude-range 0x3000:0x400 \
    --output /var/mobile/Documents/trace.bin

# Pre-trace 内存 patch：清除缓存/标志以获取完整 trace
# +偏移 = 模块基址偏移，绝对地址也支持。trace 后自动恢复原始字节
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --patch +0x1abc:00000000 \
    --output /var/mobile/Documents/trace.bin
```

### 3.6 后台录制

```bash
nohup python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-mode multi \
    --timeout 300 \
    --output /var/mobile/Documents/trace.bin \
    > trace_log.txt 2>&1 &
```

### 3.7 把 trace 拉回宿主机

```bash
# iOS（iproxy 转发 22→2222）
scp -P 2222 root@localhost:/var/mobile/Documents/trace.bin ./trace.bin

# Android
adb pull /data/local/tmp/trace.bin ./trace.bin
```

---

## 四、验证 trace（可选）

用 `tenet --dump` 快速确认 trace 文件完整可读：

```bash
# 解码并打印前 100 条指令（含反汇编、寄存器差值、内存访问）
tenet --dump text trace.bin --limit 100

# 以 JSONL 格式输出（便于脚本处理）
tenet --dump jsonl trace.bin | head -20

# 查看统计摘要
tenet --stats trace.bin
```

> `tenet --dump` 支持 v4/v5/v7 全格式（含默认分块压缩），无需单独构建。

示例输出：

```
; tenet dump
; module        : /var/containers/.../TheApp
; arch          : aarch64
; module_slide  : 0x0000000004a30000
; inst_count    : 284671
; ----------------------------------------------------------
; --- thread 0x103 ---
; [seq_entry] @ 0x104a31b2c0 (static 0x1001b2c0)
0x0001001b2c0  sub sp, sp, #0x40          ; sp: 0x16d... -> 0x16d...
0x0001001b2c4  stp x29, x30, [sp, #0x30]  ; mem[W ] [0x16d...] (16B) = 0x...
0x0001001b2c8  add x0, x0, #1             ; x0: 0x29 -> 0x2a ; nzcv=----
; [objc_msgSend] cls="NSString" sel="length"
```

---

## 五、用 tenet 分析 trace

### 5.1 Tauri Web 前端（跨平台图形化入口）

图形化体验由 `tools/tenet/web/` 中独立的 Tauri 桌面应用提供。Tauri 的 Rust shell 以 `--ws-port <port> --progress-json <trace_path> --mcp-hub` 通过 sidecar 启动和管理 `tenet` 后端子进程（`--progress-json` 让索引构建等早期阶段以 `TENET-PROGRESS` 行上报进度，驱动 loading 页进度条，详见 `ui-layer.md`）；React/TypeScript 浏览器端仅连接 `ws://127.0.0.1:<port>`，使用 FlatBuffers 二进制协议。并行启动的 MCP Hub 面向 AI 工具、IDAPython 插件等外部客户端，与 Web UI 渲染路径无关，也不是其 fallback。

开发模式使用仓库中已有脚本：

```bash
cd tools/tenet/web
pnpm tauri:dev
```

Tauri 前端提供时间轴、指令、寄存器、内存/Hex Dump、函数与调用栈、CFG、字符串及分析结果等浏览和可视化能力。`tenet` 后端本身不会打开窗口；直接执行 `./tenet trace.bin` 应配合 CLI 选项、TUI 或服务模式使用。

> Windows 默认关闭 `TENET_ENABLE_WS`，而浏览器端 Web UI 仅实现 FlatBuffers WebSocket 通道，因此 Windows Web UI 暂时无法连接后端获取实时数据。这是待补齐 Windows WS 支持的已知限制，不存在 MCP HTTP 过渡方案。

---

### 5.2 TUI 模式（SSH / 无图形界面）

```bash
cd tools/tenet/build
./tenet --tui /path/to/trace.bin
```

TUI 提供终端内的多面板浏览体验，通过键盘操作，并与 Tauri 前端复用同一套后端 Core 和 Analysis。

---

### 5.3 CLI 批处理分析

**结构恢复：**

```bash
# 识别函数边界 + 交叉引用
./tenet trace.bin --xref

# 导出控制流图（Graphviz DOT 格式）
./tenet trace.bin --export-cfg function.dot

# 生成调用图
./tenet trace.bin --call-graph callgraph.dot

# 组合导出
./tenet trace.bin --export-cfg func.dot --call-graph cg.dot --symbol-annotation
```

**数据流与污点分析：**

```bash
# 从 x0 寄存器正向污点（从第 0 条指令开始）
./tenet trace.bin --taint 0

# 从指定指令 ID 开始正向污点
./tenet trace.bin --taint 0 --taint-inst 12345

# 反向污点：从指令 45678 回溯 x0 的来源
./tenet trace.bin --backward-taint 45678 0

# 反向污点 + 导出数据流图
./tenet trace.bin --backward-taint 45678 0 --backward-taint-graph dfg.json

# 关键路径（critical path）
./tenet trace.bin --backward-taint 45678 0 --critical-path
```

**算法与语义识别：**

```bash
# 密码学 / 反调试模式检测
./tenet trace.bin --pattern

# 常量物化分析（识别硬编码密钥常量）
./tenet trace.bin --constants

# 循环语义分析（识别 ARX/LFSR/Sbox 操作）
./tenet trace.bin --loop-semantics

# 算法自动摘要
./tenet trace.bin --algorithm-summary

# ObjC 消息分析
./tenet trace.bin --objc

# 系统调用分析
./tenet trace.bin --syscall-intercept

# 多线程：线程概要与切换
./tenet trace.bin --run-pass thread

# 多线程：只看指定线程的指令（可多个 tid）
./tenet trace.bin --thread-filter 4711,4712

# 多线程：共享内存跨线程交接（writer→reader）
./tenet trace.bin --cross-thread-dataflow

# 全部算法分析一次跑完
./tenet trace.bin --pattern --constants --loop-semantics --algorithm-summary

# VMP（虚拟机保护）执行抽象必须提供静态 hint
./tenet trace.bin --vm-abstract --vm-hints vm_hints.json

# 或直接给 dispatcher / indirect branch / handler PC
./tenet trace.bin --vm-abstract \
    --vm-dispatcher 0x100005000 \
    --vm-indirect-br 0x100005014 \
    --vm-handler 0x100006000 --vm-handler 0x100007000

# JSON hints 文件支持 anchor_pcs / mem_anchor_addr / VM context 等完整字段，推荐优先使用
```

**内存与字符串：**

```bash
# 所有运行时字符串
./tenet trace.bin --strings

# 从内存重建字符串
./tenet trace.bin --memory-strings

# 搜索字节模式
./tenet trace.bin --mem-search "DE AD BE EF"

# 内存快照（指定指令 ID）
./tenet trace.bin --memory-snapshot 50000
```

**统计与性能分析：**

```bash
# 基本统计（指令数、函数数、循环数等）
./tenet trace.bin --stats

# 窗口统计：当前 parser 要求两个保留参数，但执行范围仍是完整 trace
# 目前只有 --window-stats-size 会改变分析行为
./tenet trace.bin --window-stats 0 0 --window-stats-size 4096
```

**排除噪声区间（分析时过滤）：**

```bash
# 排除区间内的指令不传递给分析 pass（运行时地址，可重复）
# 不影响寄存器/内存状态重建
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --pattern
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --exclude-range 0x1003000 0x1003400 --xref
```

---

### 5.4 典型端到端工作流

#### 场景一：逆向一个未知加密函数

```bash
# Step 1：录制 trace
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --entry 0xABC \
    --output /var/mobile/Documents/crypt.bin

# Step 2：拉回宿主机
scp -P 2222 root@localhost:/var/mobile/Documents/crypt.bin ./crypt.bin

# Step 3：快速结构概览
./tenet crypt.bin --export-cfg func.dot --call-graph cg.dot

# Step 4：算法识别
./tenet crypt.bin --pattern --algorithm-summary --constants

# Step 5：如果发现密钥相关常量，做反向污点追溯来源
./tenet crypt.bin --backward-taint <inst_id_of_key_use> 0

# Step 6：交互式深入
# 在 Tauri 前端中打开 crypt.bin，浏览时间轴并触发污点等分析
```

#### 场景二：分析 ObjC App 的行为

```bash
# 录制（包含 ObjC 消息）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --entry 0xABC \
    --output /var/mobile/Documents/objc.bin

# ObjC 方法调用链分析
./tenet objc.bin --objc --call-graph cg.dot

# 在 Tauri 前端中打开 objc.bin，浏览 ObjC 调用边界
```

#### 场景三：比较两次 trace 的差异（trace diff）

```bash
# 第一次录制（正常输入）
python3 ... --trace-mode once --output run1.bin

# 第二次录制（不同输入）
python3 ... --trace-mode once --output run2.bin

# 在 tenet CLI 中对比两次 trace
tenet run1.bin --trace-diff-file run2.bin

# 也可在 Tauri 前端中打开 trace 后使用对应的可视化分析能力
```

---

### 5.5 服务模式（AI / 自动化接入）

**MCP stdio（AI 客户端通过子进程接入）：**

```bash
./tenet --mcp trace.bin
# AI 客户端通过 stdio 调用工具；实际工具数由构建和 Hub/session 模式决定，启动日志会打印
```

**MCP HTTP / Hub（AI 工具、远程客户端与 IDA 插件）：**

```bash
# 单实例 Streamable HTTP
./tenet --mcp-http 127.0.0.1:10444 trace.bin
# POST /mcp   Content-Type: application/json

# 多实例 Hub：首个进程监听 10444，后续进程作为 Worker 接入
./tenet --mcp-hub trace.bin
# MCP: POST http://127.0.0.1:10444/mcp
# JSON WebSocket: ws://127.0.0.1:10444/ws/<instance-id>
```

Hub WebSocket 使用 JSON-RPC/MCP 文本帧并按 URL 中的 `instance-id` 固定路由，供 IDAPython 等交互式客户端使用；仅接受本机回环连接。Web/Tauri 前端仍使用 `--ws-port` 提供的独立 FlatBuffers 二进制 WebSocket。

**IDAPython 插件：**

```bash
# 将入口脚本放入 IDA 用户插件目录；确保同级可导入 tenet Python 包
cp tools/tenet/python/tenet_ida.py ~/.idapro/plugins/

# 启动 Tauri 前端或 Hub 后，在 IDA 中执行：
# Edit → Plugins → Tenet Trace Bridge → Connect
```

插件会通过 `10444` 自动发现并匹配 trace 实例、同步 IDA image base，并提供双向导航与寄存器查询。完整包部署时需同时让 `tools/tenet/python/tenet/ida/` 位于 IDA 的 Python 搜索路径。

**JSON-RPC（本地脚本接入）：**

RPC 使用 JSON-RPC over TCP，默认绑定 `127.0.0.1`（loopback），也可通过 `--rpc [[host:]port]` 显式指定其他 host；省略端点时使用 `127.0.0.1:0`，其中端口 `0` 表示由 OS 自动分配空闲端口。

```bash
./tenet --rpc 127.0.0.1:10445 trace.bin &

# 示例调用（TCP）
echo '{"id":1,"method":"get_stats","params":{}}' | nc 127.0.0.1 10445
echo '{"id":2,"method":"get_reg","params":{"inst_id":1000,"reg":"x0"}}' | nc 127.0.0.1 10445

# 自动分配端口（实际监听端口见后端启动日志）
./tenet trace.bin --rpc
```

**边录边分析（streaming）：**

```bash
# 在录制过程中实时建索引，不需要等录制完成
./tenet --streaming /var/mobile/Documents/trace.bin
```

---

## 六、常见问题

### Frida 连接失败

```bash
# 检查 frida-server 是否在设备上运行
adb shell ps | grep frida   # Android
ssh root@device ps | grep frida  # iOS

# 检查版本匹配
frida --version
frida-ps -H 127.0.0.1:27042  # 远程
frida-ps -U                   # USB
```

### tenet 首次打开很慢（60s+）

这是正常现象——首次打开需要扫描整个 trace 文件建立 RocksDB 索引。索引会持久化到 trace 同目录下的 `<trace_stem>.tenet/`，后续打开可直接复用。

不要随意删除该 `.tenet/` 索引目录；其中还包含 pass blob 缓存与会话状态。

### trace 文件打不开（version error）

```
Error: Unsupported trace version 5, need == 4
```

如果遇到版本不兼容，请确认使用的 tenet 版本支持该格式。tenet 支持 v4/v5/v7：

```bash
./tenet trace.bin
```

### trace 太大，内存不足

```bash
# ring buffer 只影响内存占用和 chunk 轮转，不会截短 trace；控制体积应缩小追踪范围、
# 使用 --sampling 侦察后添加 --exclude-range，或缩短触发执行
python3 qbditrace_runner.py --sampling ...

# 默认已有分块 zstd；还可启用 PC-delta（v5，通常进一步减少 40%–60%）
python3 qbditrace_runner.py --pc-delta ...
```

### 录制时进程崩溃

检查 PC ring dump：

```bash
QBDI_LOG_FILE=/tmp/pcring.txt python3 qbditrace_runner.py ...
# 崩溃后查看最近执行的 2048 条 PC
cat /tmp/pcring.txt
```

---

## 七、进一步阅读

| 文档 | 主题 |
|------|------|
| [`qbditrace/README.md`](../../qbditrace/README.md) | tracer 详细设计、C ABI 参考、Benchmark 套件 |
| [`docs/capabilities.md`](capabilities.md) | tenet 全部能力按场景的导航地图 |
| [`docs/trace-format.md`](trace-format.md) | 二进制格式完整规范（v4/v5/v7/flags） |
| [`docs/analysis-layer.md`](analysis-layer.md) | 30 个 Pass 的分类、依赖和调度 |
| [`docs/ui-layer.md`](ui-layer.md) | Tauri Web 前端 / TUI / CLI / TCP RPC / MCP / WS 说明 |
| [`docs/pass-cookbook.md`](pass-cookbook.md) | 新增自定义 Pass 的开发指南 |
| [`docs/profiling.md`](profiling.md) | 性能调优与 Instruments 使用 |

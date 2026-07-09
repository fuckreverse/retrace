# USAGE — 从环境安装到完整分析

本文档覆盖完整的端到端工作流：

1. **环境安装**（宿主机 + 目标设备）
2. **编译** qbditrace + tenet
3. **录制** trace（iOS / Android）
4. **分析** trace（GUI / TUI / CLI / MCP）

---

## 一、环境安装

### 1.1 宿主机（macOS arm64，开发端）

**基础工具链：**

```bash
# Xcode Command Line Tools
xcode-select --install

# Homebrew 包管理器（如未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Ninja 构建系统（tenet 和 qbditrace 均使用）
brew install ninja cmake

# Capstone（trace_decode 离线解码器的反汇编引擎）
brew install capstone
```

**Python 与 Frida（录制端需要）：**

```bash
# Python 3.9+
brew install python3

# Frida Python 绑定（必须与设备端 frida-server 版本匹配）
pip3 install frida frida-tools
```

> **重要**：Frida Python 版本必须与目标设备上的 `frida-server` / `frida-gadget` 版本完全一致。  
> 建议固定安装：`pip3 install frida==16.x.x`

**tenet 可选依赖：**

```bash
# Triton 符号执行（精确语义污点分析，可选）
# 需要手动从源码构建或使用预编译包，见 Triton 官方文档

# YARA（模式规则匹配，可选）
brew install yara

# SDL3（GUI 渲染，tenet GUI 模式必须）
brew install sdl3
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

产物：`tools/qbditrace/build-ios/libqbditrace.dylib`

**推送到设备并签名：**

```bash
# 签名（无 entitlement）
ldid -S tools/qbditrace/build-ios/libqbditrace.dylib

# 推送到越狱设备
scp tools/qbditrace/build-ios/libqbditrace.dylib root@localhost:/var/jb/usr/lib/
# 或通过 USB
scp -P 2222 tools/qbditrace/build-ios/libqbditrace.dylib root@localhost:/var/jb/usr/lib/
```

---

### 2.2 编译 qbditrace tracer .so（Android AArch64）

```bash
export NDK_PATH=/path/to/android-ndk-rXXX
bash tools/qbditrace/build-qbditrace-android.sh
```

产物：`tools/qbditrace/build-android/libqbditrace.so`

**推送到设备：**

```bash
adb push tools/qbditrace/build-android/libqbditrace.so /data/local/tmp/
adb shell chmod 644 /data/local/tmp/libqbditrace.so
```

---

### 2.3 编译 tenet 分析器（macOS host）

**首次构建：**

```bash
cd tools/tenet
mkdir build && cd build
cmake ..                  # 默认 Debug，适合开发迭代
ninja -j$(nproc)
```

或构建 RelWithDebInfo 版本（速度约 Debug 的 2-3x，保留调试信息）：

```bash
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
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
| `CMAKE_BUILD_TYPE` | `Debug` | `Debug`/`RelWithDebInfo`/`Release` |
| `TENET_ENABLE_TRITON` | `ON` | Triton 精确语义污点（需预装 libTriton） |
| `TENET_ENABLE_YARA` | `ON` | YARA 模式匹配（需 `brew install yara`） |
| `TENET_ENABLE_GUI` | `ON` | ImGui + SDL3 GUI（macOS 默认开） |
| `TENET_BUILD_TESTS` | `ON` | 单元测试 |
| `TENET_ENABLE_TBB` | `ON` | Intel TBB 并行加速 |

不带 Triton 的快速构建：

```bash
# 在 build-no-triton/ 目录（不要在 build/ 里关掉，避免重触依赖）
mkdir -p tools/tenet/build-no-triton && cd tools/tenet/build-no-triton
cmake .. -DTENET_ENABLE_TRITON=OFF
ninja -j$(nproc)
```

---

### 2.4 编译 trace_decode 离线解码器（可选）

```bash
cd tools/qbditrace
mkdir build && cd build
cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF \
    -DFETCHCONTENT_BASE_DIR=$(pwd)/../../tenet/_deps  # 复用 tenet 的依赖缓存
ninja -j$(nproc)
# 产物：tools/qbditrace/build/trace_decode
```

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
# 启用 v5 PC-delta 模式（文件体积减少约 60%）
# 在 qbditrace_runner.py 末尾或通过 Frida 脚本的 config 设置：
# enable_pc_delta: 1

# 启用 v7 FPR 录制（NEON 寄存器，密码学分析时有用）
# enable_fpr: 1

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

用 trace_decode 快速确认 trace 文件完整可读：

```bash
# 解码并打印前 100 条指令（含反汇编、寄存器差值、内存访问）
./tools/qbditrace/build/trace_decode trace.bin --limit 100

# 以 JSONL 格式输出（便于脚本处理）
./tools/qbditrace/build/trace_decode trace.bin --format jsonl | head -20

# 查看统计摘要
./tools/qbditrace/build/trace_decode trace.bin 2>&1 | tail -20
```

> **注**：`trace_decode` 仅支持 v4 格式。若录制时启用了 `enable_pc_delta`（v5）或 `enable_fpr`（v7），请直接用 tenet 打开。

示例输出：

```
; qbditrace decode
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

### 5.1 交互式 GUI（macOS，推荐入手方式）

```bash
cd tools/tenet/build
./tenet /path/to/trace.bin
```

**GUI 主要面板：**

| 面板 | 快捷键/位置 | 用途 |
|------|------------|------|
| 指令视图 | 主面板 | 时间轴浏览，上下导航指令 |
| 寄存器 | 右侧面板 | 查看任意指令点的寄存器值 |
| 内存 / Hex Dump | 下方面板 | 查看任意时刻的内存内容 |
| 函数列表 | View → Functions | 已识别函数、跳转、过滤 |
| 调用栈 | View → Call Stack | 当前位置的调用链 |
| CFG | 右键 → Show CFG | 当前函数控制流图 |
| 字符串 | View → Strings | 所有运行时字符串 |
| 分析结果 | Analysis 菜单 | 触发各类 pass 并查看结果 |

**基本导航：**

- `↑` / `↓`：逐条指令移动
- `PgUp` / `PgDn`：快速滚动
- 双击函数名：跳转到函数入口
- 右键指令：触发污点、切片、跳转等操作

---

### 5.2 TUI 模式（SSH / 无图形界面）

```bash
cd tools/tenet/build
./tenet --tui /path/to/trace.bin
```

TUI 提供与 GUI 类似的多面板浏览体验，通过键盘操作。

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
./tenet trace.bin --syscall

# 全部算法分析一次跑完
./tenet trace.bin --pattern --constants --loop-semantics --algorithm-summary

# VMP（虚拟机保护）执行抽象
./tenet trace.bin --vm-abstract

# 带静态 hint（anchor PC + VM-PC 寄存器 + handler 地址）
./tenet trace.bin --vm-abstract \
    --vm-dispatcher-pc 0x100005000 \
    --vm-indirect-br-pc 0x100005014 \
    --vm-pc-reg 19 \
    --vm-handler-pc 0x100006000 --vm-handler-pc 0x100007000

# 用 JSON hints 文件（推荐，支持 anchor_pcs / mem_anchor_addr 等完整字段）
./tenet trace.bin --vm-abstract --vm-hints vm_hints.json
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

# 窗口统计（热点函数、执行频率）
./tenet trace.bin --window-stats
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
./tenet crypt.bin   # GUI 打开，右键污点/切片
```

#### 场景二：分析 ObjC App 的行为

```bash
# 录制（包含 ObjC 消息）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --entry 0xABC \
    --output /var/mobile/Documents/objc.bin

# ObjC 方法调用链分析
./tenet objc.bin --objc --call-graph cg.dot

# GUI 浏览 ObjC 调用边界
./tenet objc.bin
```

#### 场景三：比较两次 trace 的差异（trace diff）

```bash
# 第一次录制（正常输入）
python3 ... --trace-mode once --output run1.bin

# 第二次录制（不同输入）
python3 ... --trace-mode once --output run2.bin

# 用 trace_decode diff（v4 格式，自动归一化栈/堆地址）
./trace_decode run1.bin --diff run2.bin

# 或在 tenet GUI 中打开 trace diff 面板
./tenet run1.bin   # File → Compare Trace → run2.bin
```

---

### 5.5 服务模式（AI / 自动化接入）

**MCP stdio（AI 客户端通过子进程接入）：**

```bash
./tenet --mcp trace.bin
# AI 客户端（如 Claude Desktop）通过 stdio 调用 47 个 MCP 工具
```

**MCP HTTP（远程或 GUI 宿主）：**

```bash
./tenet --mcp-http 127.0.0.1:7080 trace.bin
# POST /mcp   Content-Type: application/json
```

**JSON-RPC（本地脚本接入）：**

```bash
./tenet --rpc /tmp/tenet.sock trace.bin &

# 示例调用
echo '{"id":1,"method":"get_stats","params":{}}' | nc -U /tmp/tenet.sock
echo '{"id":2,"method":"get_reg","params":{"inst_id":1000,"reg":"x0"}}' | nc -U /tmp/tenet.sock
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

这是正常现象——首次打开需要扫描整个 trace 文件建立 RocksDB 索引。索引建完后会持久化到 `.tenet-index/` 目录，后续打开同一 trace 几乎秒开。

不要删除 `.tenet-index/` 目录。

### trace 文件打不开（version error）

```
Error: Unsupported trace version 5, need == 4
```

这是 `trace_decode` 的限制——它只支持 v4。改用 tenet 打开：

```bash
./tenet trace.bin   # tenet 支持 v4/v5/v7
```

### trace 太大，内存不足

```bash
# 减少 ring buffer，录制更短的执行片段
python3 qbditrace_runner.py --ring-bytes $((32 * 1024 * 1024)) ...

# 启用 PC-delta 压缩（v5 格式，体积减少 ~60%）
# 在 qbditrace_runner.py 配置中设置 enable_pc_delta=1
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
| [`docs/ui-layer.md`](ui-layer.md) | GUI / TUI / CLI / RPC / MCP 详细说明 |
| [`docs/pass-cookbook.md`](pass-cookbook.md) | 新增自定义 Pass 的开发指南 |
| [`docs/profiling.md`](profiling.md) | 性能调优与 Instruments 使用 |

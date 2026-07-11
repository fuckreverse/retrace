# qbditrace — 基于 QBDI 的高性能指令级 trace 工具

面向 iOS / Android AArch64 逆向场景的逐指令 trace 工具。在指定模块内，记录每条
指令执行后的**写入寄存器 diff（改前→改后）、NZCV 标志、内存访问（含 store
value，支持 9-16 字节宽 store）、SVC 系统调用、平台 API 调用，以及跨模块调用/
返回的目标地址**；iOS 还可记录 `objc_msgSend` 类/方法派发（含运行时类名）。模块
之外的代码以原生速度运行，仅保留 transfer 事件。运行期只写裸二进制，反汇编与
符号化交给离线分析端，因此热路径开销可控。

针对 iOS/arm64e 真机做了专门处理：VM 开启 `OPT_BYPASS_PAUTH` 绕过指针认证，
因此 `braa/blraa` 这类带认证的间接跳转（例如 `objc_msgSend` 尾部的 `braa x17`、
PAC 化的 `br x16`）不会导致崩溃，控制流可以被正确跟踪。

## 设计要点

整体分三层，把开销尽量推离运行期热路径：

1. **运行期（注入进目标进程的 dylib）**：逐指令回调里只做最小动作——读 NZCV、
   按 PC 查缓存好的"写哪些寄存器"列表并读新值、按需取内存访问、把一条变长记录
   追加到 thread-local 无锁缓冲区。没有任何反汇编、符号化、加锁或同步 I/O。
2. **异步落盘**：每个线程独立 chunk buffer，单个后台 writer 线程统一刷盘。启用
   zstd 时默认写成 1 MiB 独立 frame 的**分块压缩格式**，并在文件尾写块索引，兼顾
   体积和随机访问；`bytes_written` 统计的是提交给 writer 的原始字节数，不是物理文件大小。
3. **离线后处理**：tenet 是完整分析端，支持默认分块压缩及 v4/v5/v7；轻量
   `trace_decode` 仅用于未压缩 v4 兼容文件。两者都可利用 trace **自带的内嵌码表**
   反汇编，并把运行期地址按 slide 归一化为静态地址，无需外部镜像。

此外解码器内置若干逆向增强：调用点的参数/返回值聚合（e1）、adrp/adr 目标与静态
字符串标注（e2）、调用深度缩进（e3）、以及两条 trace 的指令级 diff（e4，自动归一
栈/堆地址只显示真实差异）。各项均可用 `--no-*` / `--diff` 控制（见第 3 节）。

### 内嵌码表（自带反汇编）

为了让 trace 文件**开箱即用地离线反汇编**，运行期在某条 PC **首次执行**时，把这条
指令的原始字节（AArch64 定长 4 字节）作为一条 `CODE` 记录随流落盘。由于按 PC 去重
（每线程一个 `seen` 集合），循环/递归等稳态热路径**零额外开销**，文件体积增量也很小
（只与"执行过的不同指令条数"成正比，而非指令执行次数）。解码器读这些 `CODE` 记录
建立 `静态PC → 字节` 的码表，反汇编时优先查码表，因此**不依赖外部 `--image`**。该
特性默认开启，可在引导脚本里关闭。

寄存器重建用的是**折中方案 A**：在序列入口（以及可选的每 N 条指令）打一个全量
寄存器快照（anchor），其后每条指令只记录变化的寄存器。解码器从最近的 anchor
出发回放 diff，即可在任意点得到准确的完整寄存器状态。

### 容错内存读取（Fault-tolerant Memory Probe）

目标进程可能有 guard page、已释放/未映射区域、MMIO 等危险地址。tracer 使用
`vm_read_overwrite`（mach VM 接口）实现容错读取：对不可读的地址返回错误（而非
触发 SIGSEGV 崩溃），保证 store value 补读、ObjC 接收者类名解析、以及内嵌码表
的字节抓取均不会导致 tracer 崩溃。不可读的地址会被标记为 unknown 而非触发异常。

### 宽 store 补读

write 指令的 value QBDI 有时拿不到（标记 `MEMORY_UNKNOWN_VALUE`）。此时在
POSTINST 阶段（store 已执行）从目标地址重新读回字节补齐，并清掉 unknown 标记。
支持 1-16 字节的标量和 NEON 宽 store（`stp x,x` / 128-bit 向量）：低 8 字节
存入 `value`，高 8 字节存入 `value_hi`。更宽的 store（>16B，极罕见）仍保留
unknown 标记。

### 整模块插桩

当前版本默认使用 `addInstrumentedModuleFromAddr` 对**目标函数所在模块的整个可执行
段**进行插桩（而非仅限于 `[trace_start, trace_end)` 固定窗口）。这解决了以下问题：
目标函数体超过原始固定窗口大小或尾调用相邻 helper 时，PC 离开窗口会触发非预期的
ExecBroker 行为（甚至死锁）。整模块插桩覆盖所有模块内子调用，而系统库调用自然
落在模块外、通过 transfer 事件原生执行。如果模块解析失败（匿名映射），自动退化为
固定窗口。

### Safe Return Address（ARC 兼容）

QBDI 默认的 `FAKE_RET_ADDR == 42 (0x2a)` 会导致含 ARC 返回值优化路径（如
`objc_autoreleaseReturnValue`）的函数崩溃——该 helper 会解引用 LR 查找 ARC
elision marker。tracer 分配了一个独立的 RX 页（首字节为 AArch64 `ret` 指令），
用作 safe return address，使 ARC probe 读到合法内存而非 fault。对含 ObjC ARC
代码的 iOS 目标至关重要。

### iOS 流跟踪与调用信息

- **跨区间 call/return 目标地址**：执行流离开插桩区间（进入系统库 / IMP）时，
  QBDI 通过 ExecBroker 原生执行并触发 `EXEC_TRANSFER_CALL/RETURN` 事件。记录里
  既保存**调用点 PC（site，区间内的那条 `br/blr`）**，又保存**转移目标地址
  （target，跳到哪去了）**，便于还原 `br x16`、OC 之间跳转、`objc_msgSend` 等
  原本"跟丢"的控制流。
- **objc_msgSend 派发**：由引导脚本解析 `objc_msgSend / objc_msgSendSuper /
  objc_msgSendSuper2 / objc_msgSend_stret` 的运行期地址传入。当某次跨区间调用的
  目标命中其中之一时，在调用点抓取 `x0`（self / 接收者）与选择子寄存器（普通变体
  是 `x1=SEL`，stret 变体接收者在 `x1`、SEL 在 `x2`）。此外，**运行时通过
  `object_getClassName` 捕获接收者的类名**（存入 `OBJC` 记录的 `cls[48]` 字段），
  tagged pointer 和 arm64e isa packing 均可正确处理。对 `*Super` 变体（接收者为
  `objc_super` 结构体指针，非对象）跳过类名解析。只有通过 `looksLikeObjcObject`
  验证（对齐、非空、isa 可读）的接收者才会尝试类名解析，避免对野指针的解引用。
- **SVC 系统调用**：用 mnemonic 回调只在 `svc` 指令上触发（对普通指令零开销），
  记录 Darwin 系统调用号（`x16`）与参数 `x0..x5`，离线映射成 syscall 名。

### 寄存器 diff 的前后值

每条变化的寄存器记录其**改后值**（绝对值）。解码器通过 anchor + diff 链维护一份
running register file，因此能在输出时同时给出改前值，以 `reg: 0xOLD -> 0xNEW`
形式打印，完全无损。diff 存储绝对值（而非 delta），因此即使跨 sequence/transfer
边界也能正确重建，不依赖连续的 anchor。

多线程：每个线程有独立的 `ThreadCtx` + ring buffer，记录流里带 thread id 标记，
解码器按线程分别重建。

### 崩溃定位 PC ring window（诊断）

tracer 维护一个大小为 2048 的内存环形缓冲（`g_pc_ring`），PREINST 回调里
每条指令只做一次 cheap 的环写入（PC + opcode 字节），零 IO 开销。当进程发生
SIGSEGV/SIGBUS 时，内置的 fault handler 将最近 2048 条 PC（连同指令编码）
dump 到 `QBDI_LOG_FILE` 环境变量指定的文件（或 stderr），然后 re-raise 让进程
自然崩溃。

此外，导出函数 `qbditrace_dump_pcring(path)` 允许 Frida 端在自己的异常处理中
主动读取 ring（Frida 的 exceptor 会在 NativeFunction trampoline 内截获 fault，
此时 native signal handler 不会运行；调用此导出后可从 ring 中恢复崩溃前 PC 序列）。

### 关于 GCD / 多线程的语义边界

QBDI 的 VM 是**单线程**的：`qbditrace_run_call` / `qbditrace_run_at` 只接管发起
调用的线程。默认情况下，`dispatch_async` / `dispatch_after` 派发到其它线程的
block 不在当前 VM 的接管范围内，只能看到 dispatcher 的跨模块调用。

`--trace-gcd` 是一个显式的侦察模式：Frida agent hook `dispatch_async`、
`dispatch_after` 和 `dispatch_barrier_async`，在提交点读取 block invoke 指针，并在
当前线程中额外调用一次 `qbditrace_run_call`，每个 block 生成独立 trace 文件。它并非
跟踪 GCD 工作线程上的原始那次执行，因此要注意：

- block 会被 agent **同步额外执行一次**，随后仍会被系统正常调度；有副作用、时序依赖、
  queue-specific data 或必须运行在特定线程上的 block 不适合此模式。
- 默认只捕获 invoke 指针位于目标模块内的 block；`--gcd-no-filter` 可关闭过滤，
  `--gcd-max` 可限制额外执行次数。
- 真正的多线程并发 trace 仍不支持。正式录制应尽量串行化，避免多个线程同时进入 tracer。

## 文件结构

```
tools/qbditrace/
├── TraceFormat.h           二进制格式契约（writer 与 decoder 共用）
├── QBDITrace.h            公共 C ABI、配置结构与实时统计页契约
├── RingBuffer.h           thread-local 缓冲 + 后台 writer 线程
├── QBDITrace.cpp          核心 tracer（QBDI 回调、热路径、VM 接管、fault handler、safe ret addr）
├── qbditrace_runner.py    ★ Python loader（唯一入口，管理参数/连接/生命周期）
├── qbditrace.js           Frida agent 引擎（纯逻辑，配置由 Python 注入）
├── decoder/
│   └── trace_decode.cpp   离线解码器（Capstone 反汇编 + 状态重建 + diff）
├── benchmark/
│   ├── bench_harness.c    基础 benchmark harness
│   ├── run_benchmark.sh   一键运行基础 benchmark
│   ├── targets.c/h        7 类 target
│   └── advanced/          高级 benchmark 套件（22 target，真实加密+OLLVM 混淆）
│       ├── run_advanced.sh
│       └── README.md
└── CMakeLists.txt         tracer（iOS dylib / Android so）、decoder 与 host tests
```

## 1. 编译

### 1.1 编译 tracer（iOS arm64）

依赖仓库固定目录中的 QBDI 静态库 `build-ios/libQBDI.a` 和
`build-ios/libqbdi-llvm.a`。从仓库根目录执行：

```sh
bash tools/qbditrace/build-qbditrace-ios.sh
```

脚本会复用 `tools/tenet/_deps/zstd-src/`，按需生成 `build-ios/libzstd.a`，并在
仓库根目录输出带分块 zstd 压缩能力的 `libqbditrace.dylib`。部署到越狱设备：

```sh
scp libqbditrace.dylib vphone:/var/jb/usr/lib/libqbditrace.dylib
ssh vphone 'ldid -S /var/jb/usr/lib/libqbditrace.dylib'
```

### 1.2 编译 tracer（Android arm64）

先按 `cmake/config/config-android-aarch64.sh` 构建 QBDI，确保
`build-android/libQBDI.a` 已存在，再设置 NDK 路径并执行：

```sh
export NDK_PATH=/path/to/android-ndk
bash tools/qbditrace/build-qbditrace-android.sh
adb push libqbditrace.so /data/local/tmp/libqbditrace.so
```

脚本默认使用 Android API 24（可通过 `ANDROID_API_LEVEL` 覆盖），并输出仓库根目录下的
`libqbditrace.so`。运行 loader 时加 `--android`；默认 dylib 路径会切换为
`/data/local/tmp/libqbditrace.so`。

### 1.3 编译 host tests 与 v4 离线解码器

固定 host 构建目录为 `tools/qbditrace/build/`，不要另建 build 目录：

```sh
cd tools/qbditrace/build
cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF
ninja
ctest --output-on-failure
```

`build/trace_decode` 是轻量兼容工具，**当前只接受未压缩 v4 trace**。默认录制启用了
分块压缩，`--pc-delta` / `--sampling` 会生成 v5，`--fpr` 会生成 v7；这些 trace
应使用 tenet 打开。需要给 `trace_decode` 生成兼容输入时，同时使用 `--no-compress`，
且不要启用 `--pc-delta`、`--sampling` 或 `--fpr`。

## 2. 用 Frida 注入并 trace

> **⚠️ 重要：必须使用 Python loader 加载。禁止直接 `frida -l qbditrace.js`。**
>
> `qbditrace.js` 是纯引擎脚本，不含任何内嵌配置。所有参数由 Python loader
> (`qbditrace_runner.py`) 通过 `script.post()` 注入。直接用 Frida CLI 加载会
> 因缺少配置而挂起不动。

Frida 只做引导，核心 trace 逻辑全在 native，与 Frida 无关。

### 2.1 Trace 语义

qbditrace 的 trace 语义是**模块级**的：

- **`--entry`**：指定触发 trace 的入口函数（偏移或符号名）。trace 从该函数被调用
  时开始，到它返回时结束。
- **`--module`**：指定要 trace 的模块（默认主可执行文件）。入口函数执行期间，
  **所有落在该模块内的代码**都会被记录。模块外的调用（系统库、runtime 等）原生
  透传执行，不 trace，仅记录 transfer 事件。

不需要指定函数大小或地址范围——tracer 自动对整个模块插桩
（`addInstrumentedModuleFromAddr`）。

### 2.2 Python loader 使用方法

```sh
# 基本用法：trace 主模块内某个函数（按 IDA 偏移）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xEE91EC \
    --output /var/mobile/Documents/trace.bin

# 按导出符号名 trace
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry _CCCrypt \
    --output /var/mobile/Documents/cccrypt.bin

# trace 某个 framework 模块内的函数
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --module SomeFramework \
    --entry 0x1234 \
    --output /var/mobile/Documents/trace.bin

# attach 已运行进程
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --attach \
    --entry 0xABC \
    --output /var/mobile/Documents/trace.bin

# 多次 trace（捕获 5 次调用）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-mode 5 \
    --output /var/mobile/Documents/trace.bin

# 启用 GCD block tracing
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-gcd \
    --output /var/mobile/Documents/trace.bin

# 设置超时（30 秒后自动退出）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --timeout 30 \
    --output /var/mobile/Documents/trace.bin

# 排除内存校验循环（静态偏移 0x12000-0x13500），大幅减少 trace 体积
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 12000-13500 \
    --output /var/mobile/Documents/trace.bin

# 排除多个区域（最多 8 个）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 12000-13500 \
    --exclude-range A0000:200 \
    --output /var/mobile/Documents/trace.bin

# ── 采样侦察模式（先摸清执行情况，再决定排除哪些区域） ──────
# 步骤 1：先跑一次 --sampling，产出一个体积小得多的裸 PC 流 trace
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --sampling \
    --output /var/mobile/Documents/sampling.bin

# 步骤 2：用 tenet 分析这个 sampling trace，找出占比最大的循环
#         （--suggest-excludes 直接给出建议的 --exclude-range 参数）
./tenet --suggest-excludes /var/mobile/Documents/sampling.bin
# 或人工看 loop 明细：
./tenet --run-pass loop /var/mobile/Documents/sampling.bin

# 步骤 3：静态确认建议的地址范围确实是无关代码（如 memset/CRC/反调试延时），
#         然后把确认过的范围传给正式的完整 trace
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 100292230-100292268 \
    --output /var/mobile/Documents/trace.bin

# ── Pre-trace 内存 patch ──────────────────────────────────
# 在 trace 开始前修改目标进程内存（清除缓存/标志/修改常量），trace 完成后自动恢复

# 用偏移地址（+前缀）清零 4 字节缓存标志，确保 trace 走完整计算路径
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --patch +0x1abc:00000000 \
    --output /var/mobile/Documents/trace.bin

# 多个 patch 叠加使用（绝对地址 + 偏移地址混用）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry 0xABC \
    --patch +0x1abc:00000000 \
    --patch +0x2def:01 \
    --output /var/mobile/Documents/trace.bin

# ── Invoke 模式（主动调用） ──────────────────────────────
# 直接调用目标函数并 trace，无需等待 App 触发

# 传入 buffer + length，主动调用加密函数
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry 0xEE91EC \
    --invoke \
    --args "bytes:aabbccdd0011" "int:6" "buf:64" \
    --output /var/mobile/Documents/trace.bin

# 用导出符号名 + 完整参数调用 CCCrypt
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry _CCCrypt \
    --invoke \
    --args "int:0" "int:0" "str:mykey" "int:5" \
           "str:plaintext" "int:9" "buf:64" "buf:8" \
    --output /var/mobile/Documents/cccrypt.bin

# ObjC 类型参数（iOS）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry 0x1234 \
    --invoke \
    --args "nsstr:hello" "nsdata:aabbccdd" "int:0" \
    --output /var/mobile/Documents/trace.bin
```

### 2.3 完整参数列表

**连接参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `127.0.0.1:27042` | Frida remote 设备地址 |
| `--usb` | off | 使用 USB 连接而非远程 |
| `--android` | off | 使用 Android 默认路径与平台行为；默认 dylib 切换为 `/data/local/tmp/libqbditrace.so` |

**目标参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--target` / `-t` | (必填) | Bundle ID（spawn）或进程名（attach） |
| `--attach` / `-a` | off | attach 已运行进程而非 spawn |

**Trace 范围：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--module` / `-m` | 主可执行文件 | 要 trace 的模块。该模块内的所有执行都会被记录 |
| `--entry` / `-e` | (必填) | 入口点：hex 偏移（如 `0xEE91EC`）或导出符号名（如 `_CCCrypt`）。trace 从此函数调用开始，到返回结束 |
| `--arg-count` | 1 | 入口函数的整型参数个数（x0..x7，最大 8） |
| `--range-size` | 自动(整模块) | [高级] 模块解析失败时的回退范围（hex）。正常情况无需指定 |

**录制参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--record` | 127 (全部) | 位掩码：1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC, 32=CAPI, 64=SEQEVENTS |
| `--no-objc` | off | 关闭 ObjC msgSend 解析 |
| `--anchor-interval` | 0 (默认1024) | 每 N 条指令打全量快照 |
| `--ring-bytes` | 0 (默认64MiB) | 每线程 ring buffer 大小 |
| `--no-embed-code` | off | 关闭内嵌码表；tenet 的 CFG/loop 等依赖反汇编的能力会降级，除非另有外部镜像 |
| `--pc-delta` | off | 启用 v5 PC-delta，INST 使用 2 字节有符号差值，通常缩小 40%–60% |
| `--fpr` | off | 启用 v7 FPR/NEON 记录：每条指令写 FPR diff，ANCHOR 增加 512B 快照 |
| `--no-compress` | off | 关闭默认分块 zstd 压缩，写未压缩记录流 |
| `--exclude-range` | 无 | 排除地址范围（格式：`START-END` 或 `START:SIZE`，hex 静态偏移）。可多次指定，最多 8 个。该区间内代码以原生速度执行，不产生 trace 记录。适用于排除大循环（如内存校验） |
| `--sampling` | off | **采样侦察模式**：只记录裸 PC 流（`REC_INST` + `REC_CODE` + `REC_ANCHOR`，不含寄存器/内存/SEQ_ENTRY-EXIT），体积通常缩小 80%+，但仍逐指令执行、循环次数与回边完全精确。用于在做完整 trace 前先摸清执行情况，找出可 `--exclude-range` 排除的大循环。隐含开启 `--pc-delta` 并把 `--anchor-interval` 设为一个较大值（除非显式指定）；此时 `--record` 会被忽略。见下方「采样侦察工作流」 |

**Pre-trace 内存 patch：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--patch` | 无 | trace 前向目标进程内存写入指定字节。格式：`ADDR:HEXBYTES`（绝对运行时地址）或 `+OFFSET:HEXBYTES`（模块基址偏移）。可多次指定。trace 完成后自动恢复原始字节。适用于清除缓存标志、修改分支条件等场景 |

**Invoke 模式（主动调用）：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--invoke` | off | 主动调用入口函数并 trace，而非 hook 等待被动触发。需配合 `--args` 提供参数 |
| `--args` | 无 | 类型化参数列表（最多 8 个），语法为 `TYPE:VALUE`。支持的类型见下表 |

`--args` 支持的参数类型：

| 类型 | 语法 | 说明 | 平台 |
|------|------|------|------|
| `int` | `int:42` 或 `int:0x1234` | 整数/指针立即数 | 全平台 |
| `str` | `str:hello` | UTF-8 C 字符串（自动分配内存，传指针） | 全平台 |
| `bytes` | `bytes:aabbccdd` | 原始字节 buffer（hex 编码，自动分配） | 全平台 |
| `buf` | `buf:64` 或 `buf:0x100` | 零填充输出 buffer（指定大小），调用后自动 dump 前 64 字节 | 全平台 |
| `nullptr` | `nullptr` | 空指针（无需值） | 全平台 |
| `nsstr` | `nsstr:hello` | ObjC `NSString`（自动创建，传 handle） | iOS |
| `nsdata` | `nsdata:aabbccdd` | ObjC `NSData`（从 hex 创建，传 handle） | iOS |
| `nsnum` | `nsnum:42` | ObjC `NSNumber`（自动创建，传 handle） | iOS |
| (裸整数) | `0x1234` 或 `42` | 不带前缀的数字自动当作 `int` | 全平台 |

使用 `--invoke` 时，`--arg-count` 会从 `--args` 数量自动推断，`--trace-mode` 强制为 `once`。

**Trace 模式（hook 被动模式）：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-mode` | `once` | `once` / `multi`（无限）/ 正整数 N |
| `--no-rehook` | off | 多次模式下不重装 hook |

**GCD 参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-gcd` | off | hook GCD dispatcher，并在提交点同步额外执行、单独 trace block invoke；不是跟踪原工作线程 |
| `--gcd-no-filter` | off | trace 所有 block（不限 invoke 是否位于目标模块） |
| `--gcd-max` | 0 (无限) | 最大额外执行/捕获的 block 数 |

**运行控制：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--timeout` | 0 (无限) | N 秒后自动退出 |
| `--wait-for-done` | off (once 模式自动开启) | trace 完成后自动退出 |
| `--output` / `-o` | (必填) | 设备上 trace 文件输出路径 |
| `--dylib` | 按平台 | iOS 默认 `/var/jb/usr/lib/libqbditrace.dylib`；Android 默认 `/data/local/tmp/libqbditrace.so` |

### 2.4 工作原理

Python loader 的执行流程：

1. 解析命令行参数，构建 CONFIG 字典
2. 连接 Frida 设备（远程或 USB）
3. Spawn 或 attach 目标进程
4. 加载 `qbditrace.js` agent 脚本
5. 通过 `script.post({'type': 'config', 'payload': CONFIG})` 注入配置
6. Resume 进程（spawn 模式）
7. 等待 trace 完成或超时
8. 清理退出

JS agent 收到配置后，根据模式走不同路径：

**Hook 模式**（默认）：加载 dylib → 解析模块信息 → 对整个模块插桩 →
`Interceptor.replace` 接管入口函数。当入口函数被 App 调用时，agent 先
`Interceptor.revert` 还原原始字节（确保 QBDI 读到真实指令而非 Frida 跳板），
再用 QBDI 接管执行并 trace。执行期间，模块内的所有子调用、分支、循环全部被记录；
模块外的系统库调用原生透传。入口函数返回后 `qbditrace_stop` 把 trace 刷盘。

> 为什么先 revert：`Interceptor.replace` 会在函数入口写跳板，而 QBDI 直接从内存
> 读指令执行。若不还原，QBDI 会 trace 到 Frida 跳板。

**Invoke 模式**（`--invoke`）：加载 dylib → 解析模块信息 → 配置 tracer →
apply patches（如有）→ `materializeArgs()` 将类型化参数描述符转换为 Frida
`NativePointer`（分配内存、创建 ObjC 对象等）→ 直接调用
`qbditrace_run_call(retOut, func, argc, argv)` → `qbditrace_stop()` 刷盘 →
restore patches（恢复原始字节）。不走 `Interceptor.replace`，不需要等待 App 触发。
调用完成后自动 dump `buf` 类型参数的前 64 字节，方便快速查看输出结果。

**Pre-trace patch 机制**：`--patch` 指定的内存修改在 `qbditrace_configure()` 之后、
`qbditrace_run_call()` 之前通过 Frida 的 `Memory.writeByteArray()` 执行。apply 前
先读取并保存原始字节，trace 完成后写回恢复。hook 多次 trace 模式下，每次 trace 都会
重新 apply patch，确保每次从预期状态开始。该功能完全在 Frida JS 层实现，不涉及
`qbditrace_config_t` 结构体变更，也不需要重新编译 dylib。

### 2.5 --entry 偏移怎么取

在 IDA 里看到函数地址例如 `0x100A1B2C0`，镜像基址 `0x100000000`，则
`--entry 0xA1B2C0`。loader 会自动加上运行期的 ASLR slide。

如果目标是导出函数，直接用符号名更方便：`--entry _CCCrypt`。

### 2.6 后台运行

Python loader 天然支持后台运行（不依赖 TTY）：

```sh
# 配合 nohup 后台运行
nohup python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --trace-mode multi \
    --timeout 300 \
    --output /var/mobile/Documents/trace.bin \
    > trace_log.txt 2>&1 &

# 或在 tmux/screen 中运行
```

### 2.7 为什么禁止直接用 Frida CLI

1. **console.log 丢失**：Python API 的 `set_log_handler` 能正确捕获所有日志；
   Frida CLI 在某些场景下会丢失输出。
2. **后台运行**：Frida CLI 依赖 TTY，SSH 断开即退出；Python 可 nohup/tmux。
3. **参数集中管理**：所有配置通过命令行参数传入，无需手动编辑 JS 文件。
4. **状态回调**：Python 能接收结构化的 status 事件（trace 开始/完成/错误），
   便于自动化流水线集成。
5. **超时控制**：内置 `--timeout` 参数，避免 Frida 无限挂起。

把设备上的输出文件（如 `/var/mobile/Documents/trace.bin`）拷回 host。

## 3. 离线解码与 IDA 对照

> `trace_decode` 仅用于未压缩 v4 兼容 trace；默认分块压缩 trace 以及 v5/v7 trace
> 请使用 tenet。录制兼容文件时需加 `--no-compress`，且不要启用 `--pc-delta`、
> `--sampling` 或 `--fpr`。

```sh
# v4 兼容 trace 自带去重码表，无需任何外部输入
./tools/qbditrace/build/trace_decode qbditrace.bin

# 输出 JSONL（每条记录一行 JSON，便于脚本后处理）
./tools/qbditrace/build/trace_decode qbditrace.bin --format jsonl

# 两条 trace 做指令级 diff（自动归一化栈/堆地址，只显示真实值差异）
./tools/qbditrace/build/trace_decode qbditrace.bin --diff qbditrace_run2.bin

# 其他选项
#   --image <f> --image-base <hex>  [已废弃] 外部裸代码 dump 兜底
#   --no-regs            不打印寄存器变化
#   --no-mem             不打印内存访问
#   --no-symbols         关闭 adrp/adr 目标 + 静态字符串标注（e2）
#   --no-call-summary    关闭调用点 参数/返回值 聚合（e1）
#   --no-depth           关闭调用深度缩进（e3）
#   --limit N            只解码前 N 条指令
```

**内嵌码表（默认开）**：trace 写入时会把每条**执行过的不同指令**的原始字节随流
落盘（去重，循环/递归稳态零额外开销），解码器据此自带反汇编，**不再需要 `--image`**。

`--image` 现已**废弃（deprecated）**：内嵌码表已让离线反汇编自包含。它目前仅作为
旧 trace 的兜底保留，**后续版本可能直接移除**。

> 关闭内嵌码表：使用 `--no-embed-code` 参数。

输出里每条指令的地址都是**静态地址**（已减去 module_slide），可直接和 IDA 里看到
的地址对照。示例：

```
; qbditrace decode
; module        : /var/containers/.../TheApp
; arch          : aarch64
; module_slide  : 0x0000000004a30000
; ----------------------------------------------------------
; --- thread 0x103 ---
; [seq_entry] @ 0x104a31b2c0 (static 0x1001b2c0)
0x0001001b2c0  sub sp, sp, #0x40                 ; sp: 0x16d... -> 0x16d...
0x0001001b2c4  stp x29, x30, [sp, #0x30]         ; mem[W ] [0x16d...] (16B) = 0x...
0x0001001b2c8  add x0, x0, #1                    ; x0: 0x29 -> 0x2a ; nzcv=----
; [objc_msgSend] @ 0x1001b2d0 (static 0x1001b2d0) cls="NSString" sel="length"
; [xfer_call] 0x1001b2d0 (static 0x1001b2d0) -> target 0x1c0a... (static 0x...)
; [svc] @ 0x1001b3e0 (static 0x1001b3e0) syscall=4 (write) args=0x1,0x16d...,0x10,...
```

## 4. C ABI 参考

`QBDITrace.h` 定义了 tracer dylib 导出的公共 C 接口：

```c
int  qbditrace_configure(const qbditrace_config_t *cfg);
int  qbditrace_run_call(uint64_t *ret_out, uint64_t function,
                        uint32_t argc, const uint64_t *argv);
int  qbditrace_run_at(uint64_t *ret_out, uint64_t start_pc,
                      const uint64_t *gpr, uint64_t sp, uint64_t lr);
void qbditrace_stop(void);
int  qbditrace_force_anchor(void);
const char *qbditrace_output_path(void);
int  qbditrace_dump_pcring(const char *path);
const qbditrace_stats_t *qbditrace_stats_page(void);
```

### qbditrace_configure

配置 tracer，必须在任何 `run_*` 之前调用。会拷贝 config（字符串也会 dup），
调用方无需保持 struct 存活。成功返回 0，失败返回负值。

### qbditrace_run_call

用 QBDI VM 接管目标函数执行，trace 落在配置区间内的一切。在隔离的假栈上执行。
argc 可为 0..8（AArch64 整型参数）。返回值写入 `*ret_out`。

这是**推荐入口**：Frida hook 目标函数后在回调中调用此函数转发原始参数。

内部使用 safe return address（映射 RX 页，含 `ret` 指令）替代 QBDI 默认的
`FAKE_RET_ADDR == 42`，修复 ARC `objc_autoreleaseReturnValue` 解引用 LR
导致的 fault。

### qbditrace_run_at

原地 trace：以捕获的寄存器上下文重放一次真实调用。**不分配假栈**——使用调用者的
真实 SP 和完整寄存器状态，trace 代码看到的环境与真实调用完全一致。

适用场景：非可重入的薄 wrapper（行为依赖调用者已准备好的栈帧/全局状态，如
VM dispatch 入口），它们不能在隔离环境下正确执行。

参数含义：

- `start_pc`：函数入口运行时 PC（被 hook 的地址）
- `gpr`：30 个值的数组 = x0..x28 (idx 0..28) + x29/FP (idx 29)
- `sp`：入口时捕获的真实栈指针
- `lr`：入口时捕获的真实返回地址；VM 运行到此地址时停止

### qbditrace_stop

刷盘并关闭 trace 文件。可重复调用。显式调用可保证 trace 完整且立即可读。

### qbditrace_force_anchor

请求在下一条指令前写入全量寄存器 ANCHOR。tracer 未配置时返回负值，已配置时返回
0。该调用只设置**调用线程**已有 `ThreadCtx` 的 `need_anchor`；若该线程尚无上下文，
首次创建上下文本来也会先写 ANCHOR。它不是“从任意 Frida 控制线程给另一 VM 线程
打快照”的跨线程命令。

### qbditrace_output_path

返回当前正在写入的 trace 文件路径。返回指针由库管理。

### qbditrace_dump_pcring

诊断用途：将崩溃定位 PC ring window（最后 2048 条执行的 PC + opcode）写入指定
文件（追加模式），`path` 为 NULL 时写 stderr。供 Frida 端在自己的异常处理中调用
（Frida 的 exceptor 会在 NativeFunction trampoline 内拦截 fault，此时 native
signal handler 不会运行）。返回写出的 PC 条目数。

### qbditrace_stats_page

返回进程生命周期内稳定的只读统计页指针。Frida agent 默认每 500 ms 直接读取该页，
显示指令数、ANCHOR、内存访问、EVENT、SVC、OBJC、CODE、CAPICALL、提交给 writer 的
原始字节数和运行时间。计数器使用 relaxed atomic，允许轻微滞后；`bytes_written` 不是
压缩后文件大小。

### qbditrace_config_t 结构体

| 字段 | 类型 | 说明 |
|------|------|------|
| `trace_start` | `uint64_t` | 运行时起始地址（含 ASLR） |
| `trace_end` | `uint64_t` | 运行时结束地址（不含） |
| `module_base` | `uint64_t` | 模块运行期基址 |
| `module_slide` | `uint64_t` | ASLR slide；静态地址 = 运行时 - slide |
| `module_name` | `const char*` | 模块路径（可为 NULL） |
| `output_path` | `const char*` | 输出文件路径（NULL => 默认路径） |
| `record` | `uint32_t` | 位掩码：1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC, 32=CAPI, 64=SEQEVENTS。特殊哨兵值 `QBDITRACE_REC_SAMPLING`（`1u<<31`）用于"采样侦察"模式——见下方说明 |
| `anchor_interval` | `uint32_t` | 每 N 条指令打一次全量快照（0 = 默认 1024） |
| `ring_bytes` | `uint64_t` | 每线程 ring buffer 字节数（0 = 默认 64 MiB） |
| `objc_msgSend` | `uint64_t` | 运行期 objc_msgSend 地址（0 = 不捕获） |
|`objc_msgSendSuper` | `uint64_t` | 运行期 objc_msgSendSuper 地址 |
| `objc_msgSendSuper2` | `uint64_t` | 运行期 objc_msgSendSuper2 地址 |
| `objc_msgSend_stret` | `uint64_t` | 运行期 objc_msgSend_stret 地址 |
| `extra_range_start` | `uint64_t` | 第二插桩区间起始（0 = 未用） |
| `extra_range_end` | `uint64_t` | 第二插桩区间结束 |
| `disable_embed_code` | `uint32_t` | 非零关闭内嵌码表（默认 0 = 开启，反转语义） |
| `enable_pc_delta` | `uint32_t` | 非零启用 v5 PC-delta；INST 头由 16B 缩为 6B（与 FPR 同开时为 8B） |
| `_reserved_old_value` | `uint32_t` | 已弃用的 v6 写前值开关，保留 ABI 布局，writer 忽略该值 |
| `enable_fpr` | `uint32_t` | 非零启用 v7 FPR/NEON diff 与 ANCHOR 快照 |
| `disable_compress` | `uint32_t` | 非零关闭压缩；0 默认启用分块 zstd（需构建时包含 zstd） |
| `disable_branch_hint` | `uint32_t` | 非零关闭 nzcv 高 4 位的 CALL/RET/BRANCH hint；0 默认开启 |
| `n_exclude_ranges` | `uint32_t` | 排除区间数量（0..8） |
| `exclude_ranges[8]` | `struct{u64,u64}` | 排除区间数组，每项 {start, end}（运行时地址）。区间内代码以原生速度执行，不产生 trace 记录。最多 8 个 |
| `enable_capi_intercept` | `uint32_t` | 非零启用 C API 拦截（仍需 `record` 含 `QBDITRACE_REC_CAPI`）；官方 Frida agent 默认启用 |
| `n_capi_funcs` | `uint32_t` | `capi_funcs[]` 中有效项数（0..128）。为 0 时 native 在 configure 阶段用 `dlsym` 自动解析标准 C/平台 API |
| `capi_funcs[128]` | `struct{addr,api_id,n_args,str_args}` | 可选的显式函数表。每项含运行时地址、api_id、参数数量、指针参数捕获位掩码。Frida agent 主要用它传入无法由 `dlsym` 获取的 Android JNI vtable 地址 |

**`run_call` vs `run_at` 的选择**：`run_call` 创建隔离假栈，适合大多数场景。
`run_at` 使用真实栈帧和完整寄存器上下文，适合行为依赖调用者栈帧的薄包装函数。

**采样侦察模式（`QBDITRACE_REC_SAMPLING`）**：`record` 字段为 0 时会被 ABI 兼容层
静默替换为 `QBDITRACE_REC_DEFAULT`（历史上 0 代表"调用方未设置该字段"），因此无法用
`record = 0` 得到"什么都不记录"的效果。若确实只想要一份最小体积的裸 PC 流 trace（用于
先摸清执行情况、找出可排除的大循环，而不是做完整分析），设置：

```c
cfg.record = QBDITRACE_REC_SAMPLING;   // 只产出 REC_INST + REC_CODE + REC_ANCHOR
cfg.enable_pc_delta = 1;               // v5 格式，INST 头 16B -> 6B
cfg.anchor_interval = 1 << 20;         // 放大 ANCHOR 间隔（不需要精确寄存器状态）
```

`QBDITRACE_REC_SAMPLING` 是一个不参与任何记录内容判断的哨兵位，只用来让 `record` 非零、
避免被替换为默认值；效果等价于关闭 NZCV/REGDIFF/MEM/SYSCALL/OBJC/CAPI/SEQEVENTS 全部内容位。
产出的 trace 仍是逐指令完整执行（不是跳采样），因此 tenet 的 `cfg`/`loop`/`window_stats`
等只依赖 PC 流 + 反汇编的 pass 可以在这份 trace 上得到与完整 trace 完全一致的循环次数和
基本块边计数。Python loader 用户直接用 `qbditrace_runner.py --sampling` 即可，无需手填这三个字段。

## 5. Benchmark 套件

`benchmark/` 目录提供两层测试集，覆盖从基础功能验证到复杂逆向场景的全链路压力测试。

### 5.1 基础 benchmark

```sh
sh tools/qbditrace/benchmark/run_benchmark.sh           # 全量运行
sh tools/qbditrace/benchmark/run_benchmark.sh --filter tea  # 只跑 TEA 相关
```

基础集包含 7 类 target（Simple / Branchy / Loopy / Recursive / CFF-like / Crypto /
Large），主要验证 tracer 的正确性、性能 overhead 和格式完整性。详见
`benchmark/targets.h`。

### 5.2 高级 benchmark（advanced）

高级集面向 **tenet 离线分析器**的能力验证，使用真实加密算法 + 真实 OLLVM 混淆模式，
共 22 个 target 分 4 组：

| 分组 | 含义 | target 数 | trace 范围 | 主要验证的 tenet Pass |
|------|------|-----------|-----------|----------------------|
| A | 真实加密算法 | 7 | 24KB–531KB | PatternPass (S-Box/QR), TaintPass (key→output) |
| B | OLLVM 混淆变体 | 5 | 40KB–673KB | CFGPass (CFF dispatcher), PatternPass (MBA) |
| C | 综合实战场景 | 6 | 25KB–51MB | FunctionPass, CallGraphPass, 全 Pass |
| D | 边界压力 | 4 | 5KB–281KB | SlicePass (分支爆炸), XRefPass (深调用) |

```sh
# 一键全量：build → trace → decode → 可选 tenet 分析
sh tools/qbditrace/benchmark/advanced/run_advanced.sh

# 只跑 Group B（混淆），并启用 tenet 分析
sh tools/qbditrace/benchmark/advanced/run_advanced.sh --group B --tenet /path/to/tenet

# 单个 target + 完整解码
sh tools/qbditrace/benchmark/advanced/run_advanced.sh --filter aes_cff_mba --decode-all
```

高级集的设计细节见 [`benchmark/advanced/README.md`](benchmark/advanced/README.md)。

**编译注意**：target 源码必须用 `-march=armv8-a+nosha3+nocrypto+noaes+nosha2
-fno-vectorize -fno-slp-vectorize` 编译，以防编译器生成 ARMv8.2 SHA3/Crypto NEON
指令（如 `eor3.16b`），这些指令超出 QBDI 内置 LLVM 反汇编器的支持范围。

### 5.3 可选：真实 OLLVM 编译

```sh
sh tools/qbditrace/benchmark/advanced/build_ollvm.sh
```

## 二进制格式速览

`TraceFormat.h` 是唯一的格式契约（writer 与 decoder 共用，保证 ABI 一致）。

- 536 字节文件头：magic `"QBDT"`、version、arch、num_gpr、module_base、
  module_slide、trace 区间、flags、module_name。flags 标记内容特性：
  `HAS_MEM`、`HAS_NZCV`、`REG_DIFF`、`HAS_CODE`（内嵌码表存在）。
- 记录流由变长记录组成，首字节为 `kind`：
  - `INST (0)`：`{kind,nzcv,n_regdiff,n_mem,pc}` +
    n_regdiff × `{reg_index,value}` + n_mem × `{mem_type,mem_flags,size,addr,value,value_hi}`
  - `ANCHOR (1)`：全量寄存器快照（重建检查点）
  - `THREAD (2)`：线程标记（thread id）
  - `EVENT (3)`：VM 事件（SEQ_ENTRY/SEQ_EXIT/XFER_CALL/XFER_RETURN）。
    XFER_CALL 的 `addr` 是转移目标，`site` 是调用点 PC
  - `SVC (4)`：`{pc, syscall_no(x16), args[6]=x0..x5}`
  - `OBJC (5)`：`{variant, pc, recv(self), sel, cls[48]}`（cls 为运行时类名，
    最多 47 字符，NUL 结尾；tagged pointer / normal object 均可解析）
  - `CODE (6)`：`{kind,size,pc}` + size 个原始指令字节（AArch64 = 4B）
  - `CAPICALL (7)`：`{api_id, arg_count, str_count, pc, target, args[8]}` +
    str_count 个可变长字符串捕获（88 字节固定头 + 可变尾）。当 `enable_capi_intercept != 0`
    且 XFER_CALL 目标命中 `capi_funcs[]` 时发射；携带调用点的参数寄存器与指针参数的
    内联字符串内容（最多 4 个，每个最多 255 字节）。完整枚举见 `TraceFormat.h` 的
    `qbditrace_capi_id_t`；当前磁盘字段仍为 `uint8_t`，所以 **api_id >= 256 会截断**，
    Android 扩展 BoringSSL/JNI ID 暂不能可靠 round-trip。
- 寄存器索引采用 QBDI GPR 顺序：0..28=x0..x28，29=fp，30=lr，31=sp，
  32=nzcv，33=pc。
- 内存访问含 `value`（低 8B）+ `value_hi`（高 8B，用于 stp/NEON 9-16B store）。
- writer 基线为 **v4**；`enable_pc_delta` 生成 v5，`enable_fpr` 生成 v7（可与
  PC-delta 组合）。v6 OLD_VALUE 只保留读取契约，writer 已移除。
- zstd 构建下默认设置 `HF_BLOCK_COMPRESSED`，记录按 1 MiB 独立 frame 压缩并带尾部
  索引；`HF_COMPRESSED` 单流格式仅为历史读取兼容，当前 writer 不产生。
- 完整字段、结构大小和兼容策略见 `tools/tenet/docs/trace-format.md`；若与本文冲突，
  以 `TraceFormat.h` 为准。

## 诊断与环境变量

| 变量 | 说明 |
|------|------|
| `QBDI_LOG_FILE` | 设为文件路径后，fault handler 自动把 PC ring dump 到此文件（追加）。不设置则写 stderr |
| `QBDITRACE_OUT` | 默认 trace 输出路径的环境变量覆盖（未通过 config 指定 output_path 时生效） |

## 已知限制

- write value 补读覆盖 `size <= 16` 的 store（使用 `vm_read_overwrite` 容错读取）；
  更宽的向量 store 的 value 保留 unknown 标记。
- 默认 `--trace-mode once` 只 trace 首次调用。使用 `--trace-mode multi` 或
  `--trace-mode N` 可捕获多次调用。
- 主路径支持 iOS / Android AArch64；x86_64 写入路径未做完整适配。
- `trace_decode` 只接受未压缩 v4；默认分块压缩、v5 PC-delta 和 v7 FPR trace 使用 tenet。
- objc 记录的 cls 字段容量 48 字节；`*Super` 变体跳过类名解析（接收者为 objc_super
  结构体指针）。选择子通常可离线还原为方法名字符串。
- syscall 名表只覆盖常见子集，未命中的号码按原始数字显示；Mach trap 不在此表内。
- GCD / 跨线程派发的原始执行不在当前 VM 内；`--trace-gcd` 通过在提交点同步额外执行
  block 来生成独立 trace，可能重复副作用，不能等同于真实工作线程跟踪。
- `addInstrumentedModuleFromAddr` 整模块插桩；模块解析失败时退化为固定窗口。

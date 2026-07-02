# qbditrace — 基于 QBDI 的高性能指令级 trace 工具

面向 iOS AArch64（越狱真机）逆向场景的逐指令 trace 工具。在指定地址区间内，
记录每条指令执行后的**写入寄存器 diff（改前→改后）、NZCV 标志、内存访问（含
store value，支持 9-16 字节宽 store）、SVC 系统调用、objc_msgSend 类/方法派发
（含运行时类名）、以及跨区间调用/返回的目标地址**；区间之外的代码以原生速度
运行、零 trace 开销。运行期只写裸二进制，反汇编与符号化全部交给离线解码器，
因此热路径极快。

针对 iOS/arm64e 真机做了专门处理：VM 开启 `OPT_BYPASS_PAUTH` 绕过指针认证，
因此 `braa/blraa` 这类带认证的间接跳转（例如 `objc_msgSend` 尾部的 `braa x17`、
PAC 化的 `br x16`）不会导致崩溃，控制流可以被正确跟踪。

## 设计要点

整体分三层，把开销尽量推离运行期热路径：

1. **运行期（注入进目标进程的 dylib）**：逐指令回调里只做最小动作——读 NZCV、
   按 PC 查缓存好的"写哪些寄存器"列表并读新值、按需取内存访问、把一条变长记录
   追加到 thread-local 无锁缓冲区。没有任何反汇编、符号化、加锁或同步 I/O。
2. **异步落盘**：每个线程独立 ring buffer，单个后台 writer 线程统一刷盘。缓冲区
   满时采用**全量落盘**（不丢数据）。
3. **离线后处理（host 工具）**：`trace_decode` 用 Capstone 反汇编，按线程从
   anchor 快照 + diff 链重建完整寄存器状态，并把运行期地址归一化为 IDA 里的静态
   地址。反汇编默认直接用 trace **自带的内嵌码表**，无需任何外部镜像。

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
调用的那个线程，并在该线程的栈上用 QBDI 执行目标函数。这带来两点限制：

- **dispatch_async / GCD 派发出去的 block 跟不到**。当目标代码调用
  `dispatch_async` 把一个 block 丢到其它队列/线程执行时，那段 block 在**另一个
  原生线程**上运行，并不在当前 VM 的接管范围内，因此不会被 trace。能看到的只是
  "调用了 dispatch_async"这一跨区间 call 事件本身。
- **同步派发（dispatch_sync）/ 普通函数调用**只要最终在当前线程、且落在插桩
  区间内执行，就能正常 trace；落在区间外则原生执行并以 transfer 事件记录目标。

本版本**不做多线程并发 trace**。如果需要覆盖多线程，推荐**串行化**（一次只让一个
线程进入被 trace 的函数），而非真并发。

## 文件结构

```
tools/qbditrace/
├── TraceFormat.h           二进制格式契约（writer 与 decoder 共用）
├── QBDITrace.h            公共 C ABI（configure / run_call / run_at / stop / output_path / dump_pcring）
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
└── CMakeLists.txt         两个目标：dylib（iOS）+ decoder（host）
```

## 1. 编译

### 1.1 编译 tracer dylib（iOS arm64）

依赖已经编译好的 QBDI 静态库（仓库内 `build-ios/libQBDI.a`、`build-ios/libqbdi-llvm.a`）。

最简单、已验证可链接的方式是直接用一条命令（在仓库根目录执行）：

```sh
xcrun --sdk iphoneos clang++ -arch arm64 -std=c++17 -O2 -dynamiclib \
    -Iinclude -Ibuild-ios/include -Ibuild-ios/include-static -Itools/qbditrace \
    tools/qbditrace/QBDITrace.cpp \
    build-ios/libQBDI.a build-ios/libqbdi-llvm.a \
    -framework Foundation -framework CoreFoundation \
    -o libqbditrace.dylib
```

> 注意头文件分布：`Version.h` 在 `build-ios/include`，而**静态库版本**的
> `Config.h` 在 `build-ios/include-static`，两个目录都要 `-I`。

或者用 CMake（详见 `CMakeLists.txt` 头部注释）：

```sh
cmake -S tools/qbditrace -B build-trace-ios \
    -DCMAKE_TOOLCHAIN_FILE=cmake/config/ios.toolchain.cmake -DPLATFORM=OS64 \
    -DQBDI_INCLUDE_DIR=$PWD/include \
    -DQBDI_BUILD_INCLUDE_DIR="$PWD/build-ios/include;$PWD/build-ios/include-static" \
    -DQBDI_STATIC_LIB=$PWD/build-ios/libQBDI.a \
    -DQBDITRACE_BUILD_DYLIB=ON -DQBDITRACE_BUILD_DECODER=OFF
cmake --build build-trace-ios
```

产物 `libqbditrace.dylib` 需要正确签名后推到越狱设备（例如 `/var/jb/usr/lib/`）。

### 1.2 编译离线解码器（host，macOS arm64）

```sh
brew install capstone          # 提供反汇编能力；缺失时仅打印原始 opcode

cmake -S tools/qbditrace -B build-trace-host \
    -DQBDITRACE_BUILD_DYLIB=OFF -DQBDITRACE_BUILD_DECODER=ON
cmake --build build-trace-host
# 产物：build-trace-host/trace_decode
```

或直接编译：

```sh
c++ -std=c++17 -O2 -DQBDITRACE_HAVE_CAPSTONE=1 \
    tools/qbditrace/decoder/trace_decode.cpp \
    -I$(brew --prefix capstone)/include -L$(brew --prefix capstone)/lib -lcapstone \
    -o trace_decode
```

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
| `--record` | 31 (全部) | 位掩码：1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC |
| `--no-objc` | off | 关闭 ObjC msgSend 解析 |
| `--anchor-interval` | 0 (默认1024) | 每 N 条指令打全量快照 |
| `--ring-bytes` | 0 (默认64MiB) | 每线程 ring buffer 大小 |
| `--no-embed-code` | off | 关闭内嵌码表 |
| `--exclude-range` | 无 | 排除地址范围（格式：`START-END` 或 `START:SIZE`，hex 静态偏移）。可多次指定，最多 8 个。该区间内代码以原生速度执行，不产生 trace 记录。适用于排除大循环（如内存校验） |

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
| `--trace-gcd` | off | 启用 GCD block tracing |
| `--gcd-no-filter` | off | trace 所有 block（不限模块内） |
| `--gcd-max` | 0 (无限) | 最大 GCD block 捕获数 |

**运行控制：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--timeout` | 0 (无限) | N 秒后自动退出 |
| `--wait-for-done` | off (once 模式自动开启) | trace 完成后自动退出 |
| `--output` / `-o` | (必填) | 设备上 trace 文件输出路径 |
| `--dylib` | `/var/jb/usr/lib/libqbditrace.dylib` | 设备上 dylib 路径 |

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
`materializeArgs()` 将类型化参数描述符转换为 Frida `NativePointer`（分配内存、
创建 ObjC 对象等）→ 直接调用 `qbditrace_run_call(retOut, func, argc, argv)`
→ `qbditrace_stop()` 刷盘。不走 `Interceptor.replace`，不需要等待 App 触发。
调用完成后自动 dump `buf` 类型参数的前 64 字节，方便快速查看输出结果。

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

```sh
# 默认即带反汇编：trace 自带去重码表，无需任何外部输入
./trace_decode qbditrace.bin

# 输出 JSONL（每条记录一行 JSON，便于脚本后处理）
./trace_decode qbditrace.bin --format jsonl

# 两条 trace 做指令级 diff（自动归一化栈/堆地址，只显示真实值差异）
./trace_decode qbditrace.bin --diff qbditrace_run2.bin

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
const char *qbditrace_output_path(void);
int  qbditrace_dump_pcring(const char *path);
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

### qbditrace_output_path

返回当前正在写入的 trace 文件路径。返回指针由库管理。

### qbditrace_dump_pcring

诊断用途：将崩溃定位 PC ring window（最后 2048 条执行的 PC + opcode）写入指定
文件（追加模式），`path` 为 NULL 时写 stderr。供 Frida 端在自己的异常处理中调用
（Frida 的 exceptor 会在 NativeFunction trampoline 内拦截 fault，此时 native
signal handler 不会运行）。返回写出的 PC 条目数。

### qbditrace_config_t 结构体

| 字段 | 类型 | 说明 |
|------|------|------|
| `trace_start` | `uint64_t` | 运行时起始地址（含 ASLR） |
| `trace_end` | `uint64_t` | 运行时结束地址（不含） |
| `module_base` | `uint64_t` | 模块运行期基址 |
| `module_slide` | `uint64_t` | ASLR slide；静态地址 = 运行时 - slide |
| `module_name` | `const char*` | 模块路径（可为 NULL） |
| `output_path` | `const char*` | 输出文件路径（NULL => 默认路径） |
| `record` | `uint32_t` | 位掩码：1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC |
| `anchor_interval` | `uint32_t` | 每 N 条指令打一次全量快照（0 = 默认 1024） |
| `ring_bytes` | `uint64_t` | 每线程 ring buffer 字节数（0 = 默认 64 MiB） |
| `objc_msgSend` | `uint64_t` | 运行期 objc_msgSend 地址（0 = 不捕获） |
|`objc_msgSendSuper` | `uint64_t` | 运行期 objc_msgSendSuper 地址 |
| `objc_msgSendSuper2` | `uint64_t` | 运行期 objc_msgSendSuper2 地址 |
| `objc_msgSend_stret` | `uint64_t` | 运行期 objc_msgSend_stret 地址 |
| `extra_range_start` | `uint64_t` | 第二插桩区间起始（0 = 未用） |
| `extra_range_end` | `uint64_t` | 第二插桩区间结束 |
| `disable_embed_code` | `uint32_t` | 非零关闭内嵌码表（默认 0 = 开启，反转语义） |
| `n_exclude_ranges` | `uint32_t` | 排除区间数量（0..8） |
| `exclude_ranges[8]` | `struct{u64,u64}` | 排除区间数组，每项 {start, end}（运行时地址）。区间内代码以原生速度执行，不产生 trace 记录。最多 8 个 |

**`run_call` vs `run_at` 的选择**：`run_call` 创建隔离假栈，适合大多数场景。
`run_at` 使用真实栈帧和完整寄存器上下文，适合行为依赖调用者栈帧的薄包装函数。

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
- 寄存器索引采用 QBDI GPR 顺序：0..28=x0..x28，29=fp，30=lr，31=sp，
  32=nzcv，33=pc。
- 内存访问含 `value`（低 8B）+ `value_hi`（高 8B，用于 stp/NEON 9-16B store）。
- 格式版本当前为 **v4**（v3: 去掉 diff prev_value 改为绝对值 + 新增 value_hi；
  v4: 新增 CODE 记录 + OBJC cls 字段）。解码器只接受与自身一致的版本。

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
- 仅在 iOS AArch64 上验证；x86_64 写入路径未做完整适配。
- objc 记录的 cls 字段容量 48 字节；`*Super` 变体跳过类名解析（接收者为 objc_super
  结构体指针）。选择子通常可离线还原为方法名字符串。
- syscall 名表只覆盖常见子集，未命中的号码按原始数字显示；Mach trap 不在此表内。
- GCD / 跨线程派发出去的 block 无法被 trace（不在当前 VM 线程内执行）。
- `addInstrumentedModuleFromAddr` 整模块插桩；模块解析失败时退化为固定窗口。

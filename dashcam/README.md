# qbditrace — 基于 QBDI 的高性能指令级 trace 工具

面向 iOS AArch64（越狱真机）逆向场景的逐指令 trace 工具。在指定地址区间内，
记录每条指令执行后的**写入寄存器 diff（改前→改后）、NZCV 标志、内存访问（含
store value）、SVC 系统调用、objc_msgSend 类/方法派发、以及跨区间调用/返回的
目标地址**；区间之外的代码以原生速度运行、零 trace 开销。运行期只写裸二进制，
反汇编与符号化全部交给离线解码器，因此热路径极快。

针对 iOS/arm64e 真机做了专门处理：VM 开启 `OPT_BYPASS_PAUTH` 绕过指针认证，
因此 `braa/blraa` 这类带认证的间接跳转（例如 `objc_msgSend` 尾部的 `braa x17`、
PAC 化的 `br x16`）不会导致崩溃，控制流可以被正确跟踪。

## 设计要点

整体分三层，把开销尽量推离运行期热路径：

1. **运行期（注入进目标进程的 dylib）**：逐指令回调里只做最小动作——读 NZCV、
   按 PC 查缓存好的“写哪些寄存器”列表并读新值、按需取内存访问、把一条变长记录
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
（只与“执行过的不同指令条数”成正比，而非指令执行次数）。解码器读这些 `CODE` 记录
建立 `静态PC → 字节` 的码表，反汇编时优先查码表，因此**不依赖外部 `--image`**。该
特性默认开启，可在引导脚本里关闭。

寄存器重建用的是**折中方案 A**：在序列入口（以及可选的每 N 条指令）打一个全量
寄存器快照（anchor），其后每条指令只记录变化的寄存器。解码器从最近的 anchor
出发回放 diff，即可在任意点得到准确的完整寄存器状态。

write 指令的 value QBDI 有时拿不到（标记 `MEMORY_UNKNOWN_VALUE`）。此时在
POSTINST 阶段（store 已执行）从目标地址重新读回字节补齐，并清掉 unknown 标记。

### iOS 流跟踪与调用信息

- **跨区间 call/return 目标地址**：执行流离开插桩区间（进入系统库 / IMP）时，
  QBDI 通过 ExecBroker 原生执行并触发 `EXEC_TRANSFER_CALL/RETURN` 事件。记录里
  既保存**调用点 PC（site，区间内的那条 `br/blr`）**，又保存**转移目标地址
  （target，跳到哪去了）**，便于还原 `br x16`、OC 之间跳转、`objc_msgSend` 等
  原本“跟丢”的控制流。
- **objc_msgSend 派发**：由引导脚本解析 `objc_msgSend / objc_msgSendSuper /
  objc_msgSendSuper2 / objc_msgSend_stret` 的运行期地址传入。当某次跨区间调用的
  目标命中其中之一时，在调用点抓取 `x0`（self / 接收者）与选择子寄存器（普通变体
  是 `x1=SEL`，stret 变体接收者在 `x1`、SEL 在 `x2`），离线由选择子指针解析出
  方法名字符串。
- **SVC 系统调用**：用 mnemonic 回调只在 `svc` 指令上触发（对普通指令零开销），
  记录 Darwin 系统调用号（`x16`）与参数 `x0..x5`，离线映射成 syscall 名。

### 寄存器 diff 的前后值

每条变化的寄存器同时记录**改前值与改后值**，解码器以 `reg: 0xOLD -> 0xNEW`
形式打印，无需依赖 anchor 回放也能直观看出单条指令对寄存器的影响。

多线程：每个线程有独立的 `ThreadCtx` + ring buffer，记录流里带 thread id 标记，
解码器按线程分别重建。

### 关于 GCD / 多线程的语义边界

QBDI 的 VM 是**单线程**的：`qbditrace_run_call` 只接管发起调用的那个线程，并
在该线程的栈上用 QBDI 执行目标函数。这带来两点必须明确的限制：

- **dispatch_async / GCD 派发出去的 block 跟不到**。当目标代码调用
  `dispatch_async` 把一个 block 丢到其它队列/线程执行时，那段 block 在**另一个
  原生线程**上运行，并不在当前 VM 的接管范围内，因此不会被 trace。能看到的只是
  “调用了 dispatch_async”这一跨区间 call 事件本身。
- **同步派发（dispatch_sync）/ 普通函数调用**只要最终在当前线程、且落在插桩
  区间内执行，就能正常 trace；落在区间外则原生执行并以 transfer 事件记录目标。

本版本**不做多线程并发 trace**：让多个线程同时用各自 VM 去 trace **同一个函数**
存在内存/状态冲突的本质矛盾，且会显著放大复杂度。如果确实需要覆盖多线程，推荐的
方向是**串行化**（一次只让一个线程进入被 trace 的函数），而非真并发。

## 文件结构

```
tools/qbditrace/
├── TraceFormat.h        二进制格式契约（writer 与 decoder 共用）
├── QBDITrace.h          公共 C ABI（configure / run_call / stop / output_path）
├── RingBuffer.h         thread-local 缓冲 + 后台 writer 线程
├── QBDITrace.cpp        核心 tracer（QBDI 回调、热路径、VM 接管）
├── qbditrace.js         Frida 引导脚本（仅负责加载与一次性接管，与热路径无关）
├── decoder/
│   └── trace_decode.cpp 离线解码器（Capstone 反汇编 + 状态重建）
├── test/                Apple Silicon 上的自包含闭环测试（见第 4 节）
│   ├── test_target.c    覆盖 5 类特性的目标函数（控制流/内存/调用/objc/SVC）
│   ├── test_harness.c   standalone harness：直接调 configure/run_call/stop
│   └── run_macos.sh     一键构建并运行测试 + 解码
└── CMakeLists.txt       两个目标：dylib（iOS）+ decoder（host）
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

Frida 只做引导，核心 trace 逻辑全在 native，与 Frida 无关。

编辑 `qbditrace.js` 顶部的 `CONFIG`：

| 字段           | 含义 |
|----------------|------|
| `dylibPath`    | 设备上 `libqbditrace.dylib` 的绝对路径 |
| `moduleName`   | 目标函数所在模块名；`null` 表示主可执行文件 |
| `funcOffset`   | 目标函数相对模块基址的**静态偏移**（= IDA 中地址 − 镜像基址） |
| `rangeSize`    | trace 区间长度（字节），区间 = `[start, start+rangeSize)` |
| `outputPath`   | 设备上 trace 二进制的输出路径 |
| `record`       | 位掩码：1=NZCV，2=寄存器 diff，4=内存访问，8=SVC，16=objc_msgSend；31=全部 |
| `resolveObjc`  | 是否解析 `objc_msgSend` 家族地址以捕获 self/SEL（非 OC 目标可设 false） |
| `anchorInterval` | 每 N 条指令打一次全量寄存器重同步快照（0 = 默认 1024）。anchor 只是 seek/部分读的重同步检查点，diff 存的是绝对值，跨序列/transfer 边界也能重建，无需每次都打 |
| `ringBytes`    | 每线程 ring buffer 字节数（0 = 默认 64 MiB） |
| `embedCode`    | 是否在 trace 里内嵌去重码表以支持离线自带反汇编（默认 `true`；设 `false` 关闭） |
| `argCount`     | 目标函数的整型参数个数（转发给 QBDI 的 x0..x7） |

`funcOffset` 怎么取：在 IDA 里看到函数地址例如 `0x100A1B2C0`，镜像基址
`0x100000000`，则 `funcOffset = 0xA1B2C0`。脚本会自动加上运行期的 ASLR slide。

运行：

```sh
# attach 已运行进程
frida -H 127.0.0.1:27042 -n "<AppName>" -l tools/qbditrace/qbditrace.js
# 或 spawn 启动
frida -H 127.0.0.1:27042 -f <bundle.id> -l tools/qbditrace/qbditrace.js --no-pause
```

脚本会：加载 dylib → 解析模块基址与 slide → `qbditrace_configure` 设定区间 →
`Interceptor.replace` 接管目标函数入口。当目标函数**第一次被调用**时，脚本会先
`Interceptor.revert` 还原原始字节（确保 QBDI 读到真实指令而非 Frida 跳板），
再用 QBDI 接管执行并 trace，结束后 `qbditrace_stop` 把 trace 刷盘。

> 为什么先 revert：`Interceptor.replace` 会在函数入口写跳板，而 QBDI 直接从内存
> 读指令执行。若不还原，QBDI 会 trace 到 Frida 跳板。一次性 trace 是逆向最常见
> 的需求，因此回调里直接 revert 后不再重装；之后的调用原生运行、不再 trace。

把设备上的 `outputPath`（如 `/var/mobile/Documents/qbditrace.bin`）拷回 host。

## 3. 离线解码与 IDA 对照

```sh
# 默认即带反汇编：trace 自带去重码表，无需任何外部输入
./trace_decode qbditrace.bin

# 输出 JSONL（每条记录一行 JSON，便于脚本后处理）
./trace_decode qbditrace.bin --format jsonl

# 两条 trace 做指令级 diff（自动归一化栈/堆地址，只显示真实值差异）
./trace_decode qbditrace.bin --diff qbditrace_run2.bin

# 其他选项
#   --image <f> --image-base <hex>  [已废弃] 外部裸代码 dump 兜底（见下）
#   --no-regs            不打印寄存器变化
#   --no-mem             不打印内存访问
#   --no-symbols         关闭 adrp/adr 目标 + 静态字符串标注（e2）
#   --no-call-summary    关闭调用点 参数/返回值 聚合（e1）
#   --no-depth           关闭调用深度缩进（e3）
#   --limit N            只解码前 N 条指令
```

**内嵌码表（默认开）**：trace 写入时会把每条**执行过的不同指令**的原始字节随流
落盘（去重，循环/递归稳态零额外开销），解码器据此自带反汇编，**不再需要 `--image`**。
解码头部的 `code=1` 与 `; code : embedded ...` 即表示该 trace 自包含。

`--image` 现已**废弃（deprecated）**：内嵌码表已让离线反汇编自包含，几乎不存在它
能比码表多救出指令的场景（缺失的 PC 往往是 guard page / 已 unmap，磁盘镜像同样读
不到；旧版本 trace 又会被版本校验直接拒绝）。它目前仅作为旧 trace 的兜底保留，**后续
版本可能直接移除**。若仍要使用：提供代码段裸 dump，其首字节对应 `--image-base` 指定
的静态地址，解码器按 `static_pc - image_base` 取字节;注意它只认**裸代码 dump**，不
解析磁盘 Mach-O 段布局。

> 关闭内嵌码表：在 `qbditrace.js` 的 `CONFIG` 里设 `embedCode: false`（默认开）。
> 一般无需关闭——去重后体积增量很小，换来开箱即用的离线反汇编。

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
; [objc_msgSend] @ 0x1001b2d0 (static 0x1001b2d0) self=0x283f... sel="length"
; [xfer_call] 0x1001b2d0 (static 0x1001b2d0) -> target 0x1c0a... (static 0x...)
; [svc] @ 0x1001b3e0 (static 0x1001b3e0) syscall=4 (write) args=0x1,0x16d...,0x10,...
```

## 4. 在 Apple Silicon（macOS arm64）上做初步测试

在没有真机的情况下，可以先在 Apple Silicon Mac 上跑一个**自包含闭环**，验证 tracer
的五类记录都能正确工作。这一步既能确认工具链可用，也能评估在真机上的通用性。

### 4.1 思路

macOS arm64 和 iOS arm64e 都是 AArch64，QBDI 的指令级语义完全一致，差别只在：

- iOS A12+ 是 **arm64e（带指针认证 PAC）**，需要 `OPT_BYPASS_PAUTH`；macOS 是
  **普通 arm64（无 PAC）**，该选项无害。tracer 已用 `#if !defined(__x86_64__)`
  自动走对应分支，源码无需改动。
- 注入方式不同：真机用 Frida 注入 dylib，初测时直接把 tracer 编进一个
  **standalone harness**，在 `main` 里调用 `qbditrace_configure` / `qbditrace_run_call`
  / `qbditrace_stop`，跑完用 decoder 看输出。

因此只需要把 QBDI 的库编成 macOS arm64 版本，就能把同一套 tracer 代码直接跑起来。

### 4.2 构建 macOS arm64 版 QBDI

```sh
# 在 QBDI 仓库根目录
sh cmake/config/config-macOS-AARCH64.sh   # 约 2 分钟
ninja QBDI_static qbdi-llvm               # 编译 LLVM 子集，数分钟
lipo -info build-macos/libQBDI.a          # 应显示 architecture: arm64
```

### 4.3 一键运行测试

```sh
sh tools/qbditrace/test/run_macos.sh        # 用默认 seed
sh tools/qbditrace/test/run_macos.sh 0x42   # 自定义 seed
```

脚本做三件事：编译 `tracer + test_target + test_harness` 成可执行文件、运行它生成
trace、再编译 decoder 并解码输出。

测试目标 `trace_target()` 故意把五类特性都覆盖到：写一个数组（**内存写**）、按
seed 奇偶分支（**控制流**）、调用 `helper_sum` 和递归 `fib`（**跨函数调用 + 控制流**）、
调 `objc_msgSend`（**objc**）、以及一条 inline `svc #0x80`（**SVC**）。harness 会把
插桩结果 `ret` 和不插桩的 native 结果对比，确认插桩不改变语义。

### 4.4 验证结果（五类记录全部命中）

```
; [seq_entry]  @ ...                     ; 控制流：序列入口/出口、fib 递归跳转
0x...  str x8, [x9]    ; mem[W ] [0x...] = 0x1234   ; 内存写（数组等差 3）
0x...  ldr x8, [x9]    ; mem[R ] [0x...]            ; 内存读（helper_sum 求和）
; [xfer_call]   site -> target 0x183a11800          ; 跨函数调用，target=真实库函数
; [xfer_return] ...
; [objc_msgSend] @ ... self=0x1f0d76918 sel=0x1feda6050
; [svc]         @ ... syscall=20 (getpid) args=...
```

最后 harness 打印 `instrumented ret == native result`，两值一致（例如
`0x8f5bf4300367ab67`），说明插桩没有改变程序语义。

### 4.5 两个真机逆向中也会遇到的关键点

测试过程中暴露并解决了两个在真机上同样存在的难点：

**stub 链导致 xfer target 落在 stub 而非真实函数。** macOS/iOS 上目标函数调用外部库
函数（如 `objc_msgSend`）时，先 `bl` 到本模块的 `__stubs` / `__auth_stubs`
（`adrp x16; ldr x16; br x16`），stub 再跳到 dyld 共享缓存里的真实函数。如果只插桩
目标函数本身，QBDI 在执行流离开插桩区（即到达 stub）时就触发 `EXEC_TRANSFER_CALL`，
此时 target 是 **stub 地址而不是真实 objc_msgSend**，导致 objc 等值匹配失败。

解决办法是把 `__stubs` / `__auth_stubs` section 也纳入插桩范围，让 QBDI trace 进
stub，等 stub 的 `br x16` 真正跳到库函数时才触发 transfer，此时 target 就是真实地址。
为此 tracer 的 config 新增了一个**第二插桩区间** `extra_range_start/end`
（`QBDITrace.h`/`.cpp` 已支持，JS 也已透传）。harness 用
`getsectiondata(__TEXT,__auth_stubs)` 定位该区间并填入 config。加上 stubs 后，四个
xfer target 全部命中真实的 dyld 缓存地址（getpid / objc_getClass / sel_registerName /
objc_msgSend），与 harness `dlsym` 解析的结果完全一致。

**SVC 必须在插桩区内才能捕获。** `getpid()` 的 svc 指令在 libsystem（dyld 缓存、
插桩区外）里执行，不会触发 SVC 回调，只表现为一次 transfer。要捕获 SVC，svc 指令本身
必须落在插桩区内 —— 这正是混淆 / 反调试 iOS 代码常用的 **inline syscall** 模式。
测试用一条 inline `svc #0x80`（getpid，选择子 x16=20）在 `trace_target` 内验证，成功
被 SVC 回调捕获并记录参数。

### 4.6 通用性结论

同一套 tracer 源码在 macOS arm64 上闭环验证通过，五类记录全部正确、语义一致。迁移到
iOS arm64e 真机时只需：换用 iOS dylib（已有 `1.1` 的编译命令）、保留
`OPT_BYPASS_PAUTH`、用 Frida 注入并把目标函数 + 其 `__auth_stubs` 区间填入 config。
PAC 差异已被 tracer 自动适配，无需改动逻辑。

## 二进制格式速览

`TraceFormat.h` 是唯一的格式契约（writer 与 decoder 共用，保证 ABI 一致）。

- 512 字节文件头：magic `"QBDT"`、version、arch、num_gpr、module_base、
  module_slide、trace 区间、flags、module_name。flags 标记内容特性：
  `HAS_MEM`、`HAS_NZCV`、`REG_DIFF`、`HAS_CODE`（内嵌码表存在）。
- 记录流由变长记录组成，首字节为 `kind`：
  - `INST`：`{kind,nzcv,n_regdiff,n_mem,pc}` +
    n_regdiff×`{reg_index,value}` + n_mem×`{mem_type,mem_flags,size,addr,value}`。
    （diff 只存改后值；解码器从 running register file 回放得到改前值，因此不再
    冗余存 prev_value。）
  - `ANCHOR`：全量寄存器快照（重建检查点）
  - `THREAD`：线程标记（thread id）
  - `EVENT`：VM 事件（序列入口/出口、跨区间 call/return）。XFER_CALL 的
    `addr` 是转移目标，`site` 是区间内的调用点 PC
  - `SVC`：`{pc, syscall_no(x16), args[6]=x0..x5}`
  - `OBJC`：`{variant, pc, recv(self), sel}`
  - `CODE`：`{kind,size,pc}` + size 个原始指令字节。某 PC 首次执行时写入一条，
    供解码器自带反汇编（AArch64 定长 4 字节）。去重后稳态零开销。
- 寄存器索引采用 QBDI GPR 顺序：0..28=x0..x28，29=fp，30=lr，31=sp，
  32=nzcv，33=pc。
- 格式版本随不兼容变更递增，当前为 **v4**（v3 去掉 diff 的 prev_value，v4 新增
  内嵌码表 `CODE` 记录）；解码器只接受与自身一致的版本。

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

高级集的设计细节、各 target 说明和编译注意事项见
[`benchmark/advanced/README.md`](benchmark/advanced/README.md)。

**编译注意**：target 源码必须用 `-march=armv8-a+nosha3+nocrypto+noaes+nosha2
-fno-vectorize -fno-slp-vectorize` 编译，以防编译器生成 ARMv8.2 SHA3/Crypto NEON
指令（如 `eor3.16b`），这些指令超出 QBDI 内置 LLVM 反汇编器的支持范围。

### 5.3 可选：真实 OLLVM 编译

如果需要用 Pluto-Obfuscator（LLVM 14.0.6）编译真正的 OLLVM 混淆版本做对比：

```sh
sh tools/qbditrace/benchmark/advanced/build_ollvm.sh
```

该脚本会从 GitHub 克隆 Pluto-Obfuscator 源码、编译 clang，并对各 crypto target 分别
应用 CFF/BCF/SUB/ALL 四种混淆组合。编译时间约 30 分钟。

## 已知限制

- write value 补读仅覆盖 `size <= 8` 的标量 store；更宽的向量 store 的 value
  保留 unknown 标记。
- Frida 引导默认**只 trace 目标函数的首次调用**（逆向常见需求）。如需每次都 trace，
  需要改造为带原始字节 save/restore 的重装逻辑（注意线程安全）。
- 仅在 iOS AArch64 上验证；`TraceFormat.h` 预留了 x86_64 的 arch 标记，但 x86_64
  写入路径未做完整适配（SVC/objc/PAuth 等增强均为 AArch64 专属）。
- objc 记录里的 **self（接收者）是运行期对象指针**，其类名需运行期对象布局才能
  解析，离线解码器只打印指针；选择子（SEL）通常指向镜像内 `__objc_methname`，
  能离线还原成方法名字符串。
- syscall 名表只覆盖常见子集，未命中的号码按原始数字显示；Mach trap（负号选择子）
  不在此表内。
- GCD / 跨线程派发出去的 block 不在当前 VM 线程内执行，无法被 trace（详见上文
  “GCD / 多线程的语义边界”）。

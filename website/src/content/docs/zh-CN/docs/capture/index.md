---
title: 捕获（Capture）
sidebar:
  order: 1
---

Tenet 消费符合[二进制 Trace 格式](/zh-CN/docs/reference/)的 Trace 文件。任何能生成合规 `.bin` 文件的工具都可以作为分析管道的数据源。

## 官方捕获引擎：QBDITrace

QBDITrace 是面向 iOS / Android AArch64 的参考捕获引擎。它在目标进程内运行，写入紧凑的二进制流，将反汇编、符号处理与分析留在离线端。

### iOS

```bash
bash tools/qbditrace/build-qbditrace-ios.sh
ldid -S tools/qbditrace/build-ios/libqbditrace.dylib
scp -P 2222 tools/qbditrace/build-ios/libqbditrace.dylib root@localhost:/var/jb/usr/lib/
```

### Android

```bash
export NDK_PATH=/path/to/android-ndk
bash tools/qbditrace/build-qbditrace-android.sh
adb push tools/qbditrace/build-android/libqbditrace.so /data/local/tmp/
```

### Hook 模式与 Invoke 模式

**Hook 模式**等待应用自然触发目标函数——适合依赖应用状态的执行路径。**Invoke 模式**构造类型化参数，通过 `qbditrace_run_call` 主动执行——适合可重复的隔离调用。

### QBDITrace 记录内容

| 类别 | 详情 |
|------|------|
| 指令 | 逐指令 PC、NZCV 标志、写入寄存器差值（绝对值） |
| 内存 | 读/写地址、大小与值——包括 9–16 字节宽 store |
| 内嵌码表 | 每条首次执行的指令的原始字节（按 PC 去重），离线反汇编无需外部镜像 |
| ObjC 派发 | `objc_msgSend` 系列：接收者、选择子与运行时类名 |
| 系统调用 | `svc` 指令位置、系统调用号与参数 |
| C API 调用 | 拦截 `memcpy`、`strcmp`、`strlen`、CommonCrypto、BoringSSL、JNI 等，含参数快照与字符串捕获 |
| 跨区间转移 | 执行离开或重新进入插桩模块时的调用点 PC 与目标地址 |
| FPR / NEON (v7) | 128 位向量寄存器差值与锚点快照（可选开启） |

### 设计要点

- **模块级插桩**：对目标模块整个可执行段插桩；模块外代码原生执行，仅记录转移事件。
- **锚点 + 差值重建**：周期性全量寄存器锚点让解码器在任意指令重建精确状态；其余流只存储变化。
- **容错内存读取**：使用 `vm_read_overwrite` 安全探测 store 值、ObjC 类名与内嵌码表字节——非法地址返回错误而非崩溃。
- **arm64e 指针认证**：QBDI 绕过 PAC，`braa`/`blraa` 间接跳转（包括 `objc_msgSend` 尾调用）可正确追踪。
- **ARC 安全返回地址**：独立 RX 页替代 QBDI 默认假返回值，`objc_autoreleaseReturnValue` 探测不会触发异常。
- **1 MiB 分块压缩**带尾部索引支持随机访问；PC-delta 编码（v5）将 INST 头从 16 字节缩至 6 字节。
- **崩溃 PC 环**：始终捕获最近 2048 条执行 PC；SIGSEGV/SIGBUS 时自动 dump，或通过 Frida 异常处理调用 `qbditrace_dump_pcring`。

### 线程与 GCD

QBDI VM 只接管发起调用的线程。转移到其他线程的工作有两种捕获方式：

- **Android —— `--trace-threads`：** 拦截 `pthread_create`，将 start routine 位于被追踪模块内的子线程重定向到 `qbditrace_run_thread()`——routine 在子线程自己的 QBDI VM 中执行。所有线程记录进**同一个 trace 文件**，以 `THREAD` 标记区分——这是真正的多线程 trace。Tenet 可按线程切分（`--run-pass thread`、`--thread-filter`）。
- **iOS —— `--trace-gcd`：** hook GCD dispatcher，在提交点同步额外执行发现的 block invoke 指针——每个 block 生成独立 trace 文件。这**不是**真正的多线程 trace：block 在调用线程上额外执行一次，有副作用或依赖特定队列的 block 可能表现不同。尽量串行化捕获。

## 自定义采集器

Tenet 不要求 QBDITrace。任何能生成合规二进制 Trace 格式的运行时都可以作为数据源。常见替代方案：

- **Frida Stalker**：通过 `Stalker.follow` 插桩线程，写入 `REC_INST` + `REC_ANCHOR` + `REC_CODE` 记录。
- **其他 DBI 框架**：DynamoRIO、Pin 或自定义引擎生成合规 `.bin` 文件。
- **模拟器**：Unicorn 或 QEMU 插桩后逐指令记录状态到该格式。
- **静态分析输出**：用于测试与验证的合成 Trace。

Tenet 打开 Trace 的最低要求：合法 `QBDT` magic、版本 ≥ 4、完整的逐指令 PC 流。额外记录类型如何解锁更丰富分析见[兼容性分层](/zh-CN/docs/reference/#兼容性分层)。

### 记录类型选择

| 层级 | 所需记录 | 解锁的分析能力 |
|------|---------|---------------|
| **最低** | `REC_INST`（仅 PC）、`REC_ANCHOR` | 基础指令列表、地址归一化 |
| **结构** | + `REC_CODE`、branch hints、`REC_EVENT`（XFER_CALL/RETURN） | CFG 恢复、函数边界、调用图、循环检测 |
| **状态** | + GPR 差值、`REC_INST` NZCV、内存访问 | 寄存器重建、内存模型、污点分析、数据流切片 |
| **平台** | + `REC_SVC`、`REC_OBJC`、`REC_CAPICALL` | 系统调用命名、ObjC 消息解析、C API 参数捕获 |
| **向量** | + `REC_INST` FPR 差值、`REC_ANCHOR` FPR 快照 (v7) | NEON/向量寄存器重建、密码学算法识别 |

缺失记录会优雅降级：Tenet 照常打开 Trace，仅运行输入满足的 Pass。

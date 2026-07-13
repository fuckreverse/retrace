---
title: ObjC、系统调用与平台 API
sidebar:
  order: 6
---

平台相关 Pass 把底层 Trace 事件翻译为高层 API 语义。它们回答"发生了什么系统或框架调用、参数是什么、哪个高层方法触发了它"。

## target_os 判定与回退

Tenet 从 Trace 头读取 `target_os`（`TraceFormat.h`，偏移 `0x138`，4 字节）：

| 值 | 含义 |
|---|---|
| 0 | Unknown（旧版 Trace，该字段尚未引入） |
| 1 | iOS / Darwin |
| 2 | Android |
| 3 | Linux |

`target_os = 0` 时，Tenet 根据 `module_name` 路径启发式回退：以 `/data/`、`/system/` 开头或含 `.so` 的模块推断为 Android；以 `/var/`、`/private/` 开头或含 `/Library/`、`.dylib`、`.app/` 的模块推断为 iOS；其余保持 Unknown。这种回退是尽力而为的 —— 如果需要准确的平台 API 分类，请确保 qbditrace 录制时写入了正确的 `target_os`。

:::note[旧版 Trace 与 target_os]
旧版 qbditrace 录制的 Trace 写 `target_os = 0`。`objc` 与 `objc_crypto` 对明确的 Android/Linux 目标直接返回空结果，但允许 Unknown 继续尝试；`syscall_intercept` 在 Unknown 下同时使用兼容表。若启发式判断错误，优先用新版 qbditrace 重新录制。
:::

## Objective-C 消息

`objc` 解析 `REC_OBJC`（=5）记录种类。它对每条消息发送提取：

- **receiver**（`objc_msgSend` 调用时的 x0）—— 消息接收者对象；
- **selector**（x1）—— SEL 指针，从二进制的 selector 引用或 Trace 内存中解析出名字；
- **class name** —— 由 receiver 的 isa 指针推导（ObjC runtime 类查找，通过 Trace 内存）；
- **arguments**（x2–x7，最多 6 个）—— 每个参数原始值都被记录，当它看起来像用户空间指针时，`objc` 会尝试解引用为 C 字符串；
- **return value**（下一条 OBJC 记录或 Trace 结束时的 x0）—— 同样在可能时解引用为字符串。

仅解析四种 msgSend 变体（`objc_msgSend`、`objc_msgSendSuper`、`objc_msgSendSuper2`、`objc_msgSend_stret`），对应录制时传入 `qbditrace_config_t` 的地址。`ObjcMessage` 上的 `variant` 字段区分具体变体（0 = msgSend，1 = stret，2 = super/super2）。

`objc` 仅在 Darwin 目标上工作。Android 和 Linux Trace 上该 Pass 直接返回空结果。

```bash
./tenet [options] trace.bin --objc
./tenet [options] trace.bin --objc --objc-class NSString
```

`--objc-class <name>` 按类名精确过滤输出。

### ObjC × 密码学关联

`objc_crypto` 把 `pattern`（密码学原语检测）与 `objc`（围绕每条检测的 ObjC 调用）结合起来。对每个密码学命中，找到最近的包围它的 ObjC 调用栈，回答"哪个用户可见方法（例如 `-[NSURLConnection delegate]` → `-[MyManager connectionDidFinish:]`）触发了这次 CCCrypt 调用？"

```bash
./tenet [options] trace.bin --objc --pattern --objc-crypto
```

该 Pass 也会高亮没有 ObjC 帧包围的密码学调用 —— 那些通常是底层或 C API 路径。

## 系统调用与 C API 拦截

`syscall_intercept` 用三个数据源按严格优先级重建高层 API 调用：

| 优先级 | 数据源 | 精度 | 说明 |
|---|---|---|---|
| 1 | `REC_CAPICALL` | 最高 | Tracer 侧解析：符号名、参数、内联字符串捕获。录制时需开启 `enable_capi_intercept` |
| 2 | `REC_SVC` | 中 | 原始 syscall 编号 + 参数，按平台 syscall 表分类 |
| 3 | `XFER_CALL` 启发式 | 最低 | 跨模块调用/返回对（`REC_EVENT` 记录标记离开与返回），无符号，可能误归 |

### 数据源详解

**`REC_CAPICALL`** 在录制时设置 `qbditrace_config_t::enable_capi_intercept` 且显式提供了 `capi_funcs[]`（或依赖 native dlsym 自动解析、Frida 补充 JNI 条目）时产生。每条记录携带：
- 运行时目标地址；
- `api_id`（已知 API 表索引）；
- 参数值（最多 8 个）；
- `str_args` 位掩码 —— 标记哪些参数是已知字符串指针，tracer 侧直接内联捕获，tenet 无需重建内存。

这是最佳数据源：符号、类型化参数、解引用字符串全部预打包。

**`REC_SVC`**（系统调用记录）捕获 supervisor-call 事件。Darwin 上包括 `mach_msg`、`mach_vm_map`、`read`、`write` 等；Linux/Android 上包括 `ioctl`、`mmap`、`mprotect` 等。Tenet 按 `target_os` 选择的 syscall 表分类。

**`XFER_CALL` 启发式** 基于 `REC_EVENT` 记录中标记跨模块离开与返回的事件工作。当被追踪代码转移到录制范围外再返回时，tenet 重建一次合成调用。无符号解析，按目标 PC 标记。

### 拦截的 API 表

| 平台 | 分类的 API |
|---|---|
| Darwin (iOS) | **CommonCrypto：** `CCCrypt`、`CCCryptorCreate`、`CCCryptorCreateWithMode`、`CCHmac`、摘要/PBKDF 系列  **Security.framework：** `SecKeyCreateSignature`、`SecKeyRawSign`、`SecKeyRawVerify`、`SecKeyEncrypt`、`SecKeyDecrypt`、`SecKeyCreateWithData`  **BoringSSL / OpenSSL：** EVP cipher 与 digest 系列 |
| Android | **BoringSSL：** 同上 EVP/SSL 接口  **JNI：** `RegisterNatives`、`FindClass`、`CallVoidMethod`、`GetMethodID` 等 |
| Linux | **OpenSSL：** EVP_* 系列  **系统调用：** `mmap`、`mprotect`、`write`、`open`、`ioctl` 等（需要 `REC_SVC` 记录） |
| Unknown | 启发式 —— 同时尝试 iOS 与 Android 表；质量取决于 Trace 中出现的模块 |

```bash
./tenet [options] trace.bin --syscall-intercept
./tenet [options] trace.bin --syscall-intercept --syscall-intercept-bytes 128
```

`--syscall-intercept-bytes <N>` 控制每个指针参数读取的字节数（默认 64）。更大值能捕获更长缓冲区，但增加内存和处理时间。

### 解读平台 API 结果

每个拦截的调用报告：
- API 名与分类；
- 所有参数值，指针参数在可能时解引用为字符串；
- 调用点 PC 与 inst_id；
- 返回值；
- 解析所用的数据源（`REC_CAPICALL` / `REC_SVC` / `XFER_CALL`）。

多个数据源覆盖同一调用时，只有优先级最高的产生输出 —— tenet 不会跨源重复。

## 真实接口面

### CLI（批处理模式）

上述每个 Pass 都既有独立 CLI 标志又有 `--run-pass` 名称，可从脚本驱动：

```bash
./tenet [options] trace.bin --objc --objc-class NSString
./tenet [options] trace.bin --objc --pattern --objc-crypto
./tenet [options] trace.bin --syscall-intercept --syscall-intercept-bytes 128

# 等价地通过通用 runner
./tenet [options] trace.bin --run-pass objc
./tenet [options] trace.bin --run-pass objc_crypto
./tenet [options] trace.bin --run-pass syscall_intercept
```

批处理模式（`-c`，或选择非交互执行的分析/查询参数）向 stdout 写 JSON。

### GUI

`--objc` 与 `--syscall-intercept` 都在 Pass 运行后的 GUI **Platform** 分组注册面板。ObjC 结果按类显示消息频率；syscall 结果按 API 显示频率。`--objc-class` 过滤会让 GUI 表格收窄。

### TUI

同样的标志配合 `--tui` 使用。TUI 以可浏览列表显示 ObjC 消息表和 syscall 拦截表。

### MCP

MCP 将平台分析暴露为 `objc_messages`、`syscall_intercept`、`objc_crypto`。`objc_messages` 对 class 使用精确匹配、对 selector 使用子串匹配；`syscall_intercept` 用 `capture_bytes` 控制捕获大小。具体分页字段以 [MCP 工具目录](/zh-CN/docs/automate/mcp/#tool-catalog) 为准。

## 平台限制

| 功能 | iOS / Darwin | Android | Linux | Unknown |
|---|---|---|---|---|
| ObjC 消息 | 完整 | 跳过 | 跳过 | 继续尝试（兼容旧 iOS Trace） |
| CommonCrypto / Security / CryptoKit 分类 | 仅分类（需要 `REC_CAPICALL`） | N/A | N/A | 启发式 |
| 加密原语检测 | 基于模式（`pattern` Pass） | 基于模式 | 基于模式 | 基于模式 |
| 跨源关联（`objc_crypto`） | 可用 | N/A | N/A | N/A |

**录制前置条件：**
- ObjC：Trace 必须含 `REC_OBJC` 记录（录制时 `record |= QBDITRACE_REC_MSGSEND`；在 `qbditrace_config_t` 中配置 `objc_msgSend` 地址）；
- `REC_CAPICALL`：设置 `enable_capi_intercept = 1` 且 `n_capi_funcs > 0`（或依赖 native dlsym 自动解析）；否则仅 `REC_SVC` 与 `XFER_CALL` 可用；
- `REC_SVC`：默认在 `QBDITRACE_REC_DEFAULT`（127）中启用；显式 `record &= ~QBDITRACE_REC_SYSCALL` 可减小 Trace 体积。

## 推荐工作流

1. **判断平台来源** —— 先在 GUI 打开 Trace 或运行 `--stats`，确认 `target_os`、模块名、记录 flags。
2. **iOS Trace** —— 先 `--objc` 映射用户可见行为，再 `--pattern` 定位密码学原语；配合 `--objc-crypto` 把每个原语链接到触发它的 ObjC 方法。
3. **提取密码学素材** —— `--syscall-intercept` 从 CommonCrypto / BoringSSL / JNI 调用中恢复密钥、IV、明文缓冲区。缓冲区超过 64 B 时增大 `--syscall-intercept-bytes`。
4. **评估分类可信度** —— 如果 Trace 没有 `REC_CAPICALL`，结果依赖 `REC_SVC` + `XFER_CALL`，可能误归或遗漏；查看结果中 `source` 字段。

## 排查

### `objc` 未返回任何消息

- 明确的 Android/Linux 目标会被跳过；Unknown 会继续尝试解析。若旧 Trace 的 `module_name` 启发式不可靠，请用新版 qbditrace 重新录制。
- 确认 Trace 含 `REC_OBJC` 记录 —— 如果 `record` 没含 `QBDITRACE_REC_MSGSEND`，ObjC 记录不会被发射。
- 确认 `objc_msgSend`（及其 super/stret 变体）已在 `qbditrace_config_t` 中配置；tenet 的 Pass 只解析这四个符号。

### `syscall_intercept` 未找到任何 API 调用

- Trace 可能缺少 `REC_CAPICALL` 与 `REC_SVC`，检查 Trace header 中的 `record`。
- 录制时可能未开启 `enable_capi_intercept`；不开启则只有 syscall 级拦截生效。
- Unknown 目标 Trace 上 API 表可能不匹配 —— 用正确的 `target_os` 重新录制。

### CLI 与 GUI 结果不一致

两者不应有差异 —— 都走同一 Pass 管线。如果输出不符，确认 GUI 没有从之前不同参数的 Pass 缓存中加载结果 —— 用 `--cache-delete` 清除。

---
title: QBDITrace 参数与配置
sidebar:
  order: 2
---

## Python loader

QBDITrace 唯一支持的使用方式是通过 `qbditrace_runner.py`。**禁止**直接用 Frida 加载 `qbditrace.js`——agent 需要通过 `script.post()` 注入配置。

```bash
# 按偏移 trace 主模块内某个函数
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
```

## 连接参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `127.0.0.1:27042` | Frida 远程设备地址 |
| `--usb` | off | 使用 USB 连接 |
| `--device-id` | (第一个 USB 设备) | 显式指定 Frida 设备 id（如 Android 序列号）。**多台 USB 设备并存时必填**——否则默认取第一个，可能选错手机 |
| `--android` | off | 使用 Android 默认路径；dylib 切换为 `/data/local/tmp/libqbditrace.so` |

## 目标参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--target` / `-t` | (必填) | Bundle ID（spawn）或进程名（attach） |
| `--attach` / `-a` | off | attach 已运行进程而非 spawn |

## Trace 范围

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--module` / `-m` | 主可执行文件 | 要 trace 的模块。模块内所有代码都会被记录，模块外原生执行 |
| `--entry` / `-e` | (必填) | 入口点：hex 偏移（如 `0xEE91EC`）或导出符号名。trace 从此函数调用开始，到返回结束 |
| `--arg-count` | 1 | 入口函数的整型参数个数（x0–x7，最大 8） |
| `--range-size` | 自动(整模块) | 模块解析失败时的回退范围。正常情况无需指定 |

## 录制参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--record` | 127 (全部) | 位掩码：1=NZCV, 2=REGDIFF, 4=MEM, 8=SVC, 16=OBJC, 32=CAPI, 64=SEQEVENTS |
| `--no-objc` | off | 关闭 ObjC msgSend 解析 |
| `--anchor-interval` | 0 (默认1024) | 每 N 条指令打全量快照 |
| `--ring-bytes` | 0 (默认64 MiB) | 每线程 ring buffer 大小 |
| `--no-embed-code` | off | 关闭内嵌码表；Tenet 的 CFG/loop 等依赖反汇编的能力会降级，除非另有外部镜像 |
| `--pc-delta` | off | 启用 v5 PC-delta 编码：2 字节有符号差值将 INST 头缩小约 60% |
| `--fpr` | off | 启用 v7 FPR/NEON 记录：每条指令写 FPR diff + 每个锚点增加 512B FPR 快照 |
| `--no-compress` | off | 关闭默认 1 MiB 分块 zstd 压缩 |
| `--exclude-range` | 无 | 排除地址范围（格式：`START-END` 或 `START:SIZE`，hex 静态偏移）。最多 8 个。区间内代码原生执行，零 trace 开销 |
| `--snapshot-range` | 无 | 可选内存快照：对绝对运行时范围 `START END`（十进制或 0x 十六进制）在 configure 时做一次快照（v9 `REC_MEMIMG`）。可重复，最多 8 个。目标应为模块可写数据段（`__DATA`/`__bss`）——不要 dump rodata（Tenet 的 `--image` 回退已覆盖）、heap 或 stack。Tenet 解析字节时优先写/读日志，快照只作为显式标注的基底层 |
| `--sampling` | off | **侦察模式**：只记录裸 PC 流（不含寄存器/内存/序列事件），体积缩小 ≈80%+，但循环次数与回边完全精确。隐含开启 `--pc-delta` 与大 anchor interval。见下方*侦察工作流* |

```bash
# 在 trace 前快照模块的可写数据段
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --snapshot-range 0x100010000 0x100012000 \
    --output /var/mobile/Documents/trace.bin
```

## Pre-trace 内存 patch

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--patch` | 无 | trace 前向目标进程内存写入指定字节。格式：`ADDR:HEXBYTES`（绝对运行时地址）或 `+OFFSET:HEXBYTES`（模块基址偏移）。可多次指定。trace 完成后自动恢复原始字节。适用于清除缓存标志、修改分支条件等场景 |

```bash
# 清零模块偏移 +0x1abc 处的 4 字节缓存标志
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --patch +0x1abc:00000000 \
    --output /var/mobile/Documents/trace.bin
```

## Invoke 模式

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--invoke` | off | 主动调用入口函数而非 hook 等待。需配合 `--args` |
| `--args` | 无 | 类型化参数列表（最多 8 个），语法为 `TYPE:VALUE` |

支持的参数类型：

| 类型 | 语法 | 说明 | 平台 |
|------|------|------|------|
| `int` | `int:42` 或 `int:0x1234` | 整数/指针立即数 | 全平台 |
| `str` | `str:hello` | UTF-8 C 字符串（自动分配内存，传指针） | 全平台 |
| `bytes` | `bytes:aabbccdd` | 原始字节 buffer（hex 编码，自动分配） | 全平台 |
| `buf` | `buf:64` 或 `buf:0x100` | 零填充输出 buffer（指定大小），调用后自动 dump 前 64 字节 | 全平台 |
| `nullptr` | `nullptr` | 空指针 | 全平台 |
| `nsstr` | `nsstr:hello` | ObjC `NSString`（自动创建，传 handle） | iOS |
| `nsdata` | `nsdata:aabbccdd` | ObjC `NSData`（从 hex 创建，传 handle） | iOS |
| `nsnum` | `nsnum:42` | ObjC `NSNumber`（自动创建，传 handle） | iOS |
| (裸整数) | `0x1234` 或 `42` | 不带前缀的数字自动当作 `int` | 全平台 |

使用 `--invoke` 时，`--arg-count` 从 `--args` 数量自动推断，`--trace-mode` 强制为 `once`。

```bash
# 主动调用 CCCrypt 并传入完整参数
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app --attach \
    --entry _CCCrypt \
    --invoke \
    --args "int:0" "int:0" "str:mykey" "int:5" \
           "str:plaintext" "int:9" "buf:64" "buf:8" \
    --output /var/mobile/Documents/cccrypt.bin
```

## Hook 模式选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-mode` | `once` | `once` / `multi`（无限）/ 正整数 N |
| `--no-rehook` | off | 多次模式下不重装 hook |

## 多线程参数（Android）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-threads` | off | 拦截 `pthread_create`，录制 start routine 位于被追踪模块内的子线程。每个子线程经 `qbditrace_run_thread()` 在自己的 QBDI VM 中执行，记录进同一 trace 文件，以 `THREAD` 标记区分 |
| `--threads-no-filter` | off | 不限 start routine 是否在目标模块内，trace 所有子线程 |
| `--threads-max` | 0 (无限) | 最大捕获的子线程数 |

## Java 入口（Android）

`--java-entry fully.qualified.Class.method` 以 Java 方法作为 trace 触发器，替代 hook native 入口。agent 通过 `Java.perform` hook 该 Java 方法；App 调用时自动物化参数并在 VM 内调用 native 入口。Java `int`/`long` 转立即数，`String` 转 UTF-8 缓冲，其余对象以 jobject handle 传递。需要 `--android`；与 `--invoke` 互斥。

```bash
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --android \
    --module libnative.so \
    --entry 0x1234 \
    --java-entry com.example.NativeBridge.doWork \
    --output /data/local/tmp/trace.bin
```

## GCD 参数（iOS）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-gcd` | off | hook GCD dispatcher，在提交点同步额外执行发现的 block invoke 指针（每个独立 trace 文件）。非真正多线程 trace——Android 上请用 `--trace-threads` 获得真多线程捕获 |
| `--gcd-no-filter` | off | 不限 invoke 是否在目标模块内，trace 所有 block |
| `--gcd-max` | 0 (无限) | 最大额外执行/捕获的 block 数 |

## 运行控制

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--timeout` | 0 (无限) | N 秒后自动退出 |
| `--wait-for-done` | off (once 模式自动开启) | trace 完成后自动退出 |
| `--output` / `-o` | (必填) | 设备上 trace 文件输出路径 |
| `--dylib` | 按平台 | iOS 默认 `/var/jb/usr/lib/libqbditrace.dylib`；Android 默认 `/data/local/tmp/libqbditrace.so` |

## 侦察工作流

使用两阶段侦察工作流减小目标含大循环时的 trace 体积：

```bash
# 阶段 1：运行轻量侦察 trace（裸 PC 流）
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --sampling \
    --output /var/mobile/Documents/scout.bin

# 阶段 2：用 tenet 分析侦察 trace，找出占比最大的循环
./tenet --suggest-excludes /var/mobile/Documents/scout.bin

# 阶段 3：确认排除范围后运行完整 trace
python3 tools/qbditrace/qbditrace_runner.py \
    --target com.example.app \
    --entry 0xABC \
    --exclude-range 12000-13500 \
    --output /var/mobile/Documents/trace.bin
```

## 排障

- **没有指令记录：** 确认运行时地址已包含 ASLR slide，且代码在 VM 接管线程运行。
- **Frida 无法连接：** Python 绑定与设备端服务版本必须完全一致。
- **Trace 被 Tenet 拒绝：** 检查 magic number 是否有效、格式版本与布局 flags 是否受支持且一致（包括版本低于 v4），以及文件是否损坏或记录不完整。
- **缺少寄存器差值（`REG_DIFF`）：** Trace 仍可正常打开和索引，但寄存器查询、污点传播等依赖寄存器状态的分析会降级或不可用。
- **缺少内嵌代码表（`HAS_CODE`）：** Trace 仍可正常打开；CFG、模式识别等依赖反汇编的分析需要通过 `--image` 提供外部镜像。
- **异步工作缺失：** 单独捕获 worker 入口、改为同步路径，或使用 `--trace-threads`（Android）/ `--trace-gcd`（iOS）。
- **Android App 无法写输出：** App 不能在 `/data/local/tmp` 下创建文件（目录 DAC 拒绝 app uid）。改写到 App 数据目录（`/data/data/<package>/…`）并用 `su` 拉取。同理 App 不能 `dlopen` `/data/local/tmp` 的 `.so`——native 库需打包进 APK。
- **连接多台手机：** 传 `--device-id` 显式指定序列号，否则 loader 可能选错 USB 设备。
- **目标附近崩溃：** agent 会自动把最近 2048 条 PC 环 dump 到 `<output>.pcring`，并刷盘崩溃前已录制的指令——部分 trace 仍可分析。也可手动调用 `qbditrace_dump_pcring`。

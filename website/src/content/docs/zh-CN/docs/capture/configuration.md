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
| `--sampling` | off | **侦察模式**：只记录裸 PC 流（不含寄存器/内存/序列事件），体积缩小 ≈80%+，但循环次数与回边完全精确。隐含开启 `--pc-delta` 与大 anchor interval。见下方*侦察工作流* |

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

## GCD 参数（iOS）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--trace-gcd` | off | hook GCD dispatcher，在提交点同步额外执行发现的 block invoke 指针（每个独立 trace 文件）。非真正多线程 trace |
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
- **Trace 被 Tenet 拒绝：** 确认格式 v4+，且含寄存器差值与内嵌码表 flags。
- **异步工作缺失：** 单独捕获 worker 入口，或改为同步路径。
- **目标附近崩溃：** 使用 `qbditrace_dump_pcring` 导出最近 2048 个 PC。

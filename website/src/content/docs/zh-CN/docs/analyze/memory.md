---
title: 内存、字符串与值搜索
sidebar:
  order: 4
---

Tenet 在选定时刻重建内存、发现字符串、捕获快照、搜索模式和值、测量熵并运行 YARA 规则。所有结果都与指令 ID 绑定。

## 时间感知内存读取

`memread` 在时间轴某点读取内存区域，未知字节显示为 `??`。`mem_history` 列出与地址区间重叠的全部已记录写入。它们是查询，不是 Pass。

```bash
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
```

## 字符串

| Pass | 方法 | 适用场景 |
|---|---|---|
| `strings` | 最终快照扫描 | 已知字符串、ObjC selector、符号名 |
| `memory_strings` | 调用点时间感知扫描 | 瞬时解密/解码字符串 |

`memory_strings` 在调用点检查寄存器与栈上的活跃指针，能发现只在调用期间存在、之后被覆盖的字符串。

```bash
./tenet trace.bin --strings
./tenet trace.bin --memory-strings --memory-strings-scan-size 512
```

## 内存快照

`memory_snapshot` 在指定指令 ID 处捕获内存区域。使用 `--memory-snapshot-size` 控制每区域字节数。

```bash
./tenet trace.bin --memory-snapshot 5000 --memory-snapshot-size 128
```

## 值与模式搜索

`mem_search` 搜索字节模式、精确值、寄存器值和立即数：

```bash
./tenet trace.bin --run-pass mem_search
```

通过 GUI 或 MCP 配置：支持 `??` 通配符字节模式、精确 8/16/32/64 位值、选定时刻寄存器值和立即数扫描。`literal_search` 是弃用别名。

## 熵

`entropy` 在选定指令 ID 处测量内存区域的 Shannon 熵。高熵只是分类信号之一，不能独立证明加密。精确地址/大小控制请使用 GUI 或 MCP `entropy_analysis`，不要依赖 CLI 兼容参数。

## YARA 内存扫描

`yara_mem_scan` 对内存页运行 YARA 规则。通过 `--yara-rules` 添加自定义规则文件，用 `--yara-min-entropy` 跳过低熵页，`--yara-scan-code` 同时扫描代码 buffer。

```bash
./tenet trace.bin --yara-mem-scan --yara-rules custom.yar --yara-min-entropy 3.0
```

YARA 支持需要可选构建依赖，并非所有安装都可用。

## 证据与限制

- 所有内存结果依赖已记录的写入与读取。未访问页保持未知。
- 已记录 read 可恢复未插桩代码准备的数据；完全未被观察的数据不可恢复。
- 最终快照字符串仅反映最后一次写入。瞬态值请使用 `memory_strings`。
- GUI/MCP 熵查询支持精确地址/大小；CLI 兼容参数不完全暴露此控制。
- YARA 扫描的是重建后的真实内存，不是近似。

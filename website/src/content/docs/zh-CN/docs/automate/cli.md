---
title: 命令行界面
sidebar:
  order: 2
---

CLI 运行分析、导出数据和生成报告，无需交互会话。所有批处理模式与终端 TUI 及 Tauri sidecar/后端使用相同的 Pass 实现。

## 批量分析

```bash
# 结构
./tenet trace.bin --export-cfg func.dot
./tenet trace.bin --call-graph cg.dot
./tenet trace.bin --symbol-annotation

# 污点
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --critical-path --taint 0 --backward-taint 58000 0

# 算法
./tenet trace.bin --pattern
./tenet trace.bin --constants
./tenet trace.bin --algorithm-summary
./tenet trace.bin --loop-semantics

# 内存与字符串
./tenet trace.bin --strings
./tenet trace.bin --memory-strings
./tenet trace.bin --memread 0x16fdff200 32 50000
./tenet trace.bin --mem-history 0x16fdff200 32
./tenet trace.bin --memory-snapshot 5000

# 平台
./tenet trace.bin --objc
./tenet trace.bin --objc --objc-class NSString
./tenet trace.bin --syscall-intercept

# VM 分析（--vm-abstract 至少需要一个静态 hint）
./tenet trace.bin --vm-abstract --vm-hints hints.json
./tenet trace.bin --backward-taint 10000 0 --taint-source-annotation

# Trace 工具（参数为 instruction ID 区间）
./tenet trace.bin --trace-fold 10000 50000 --trace-fold-min-iter 3
./tenet trace.bin --trace-diff 10000 20000 30000 40000 --trace-diff-file other.bin
./tenet trace.bin --window-stats 0 100000 --window-stats-size 10000
./tenet trace.bin --reg-timeline 0 --reg-timeline-range 10000 50000
```

## 显式选择 Pass

```bash
./tenet trace.bin --run-pass function --run-pass xref --run-pass cfg
```

当便利标志不映射到所需 Pass 集时，使用 `--run-pass` 进行精细控制。

## 多线程分析

```bash
# 线程概要与切换事件
./tenet trace.bin --run-pass thread

# 只看指定线程的指令（逗号分隔多个 tid）
./tenet trace.bin --thread-filter 4711,4712

# 共享内存跨线程交接（writer → reader 边）
./tenet trace.bin --cross-thread-dataflow
```

`--thread-filter` 构建每线程指令 bitmap；省略 tid 列表则先构建全部线程 bitmap，之后再过滤。`--cross-thread-dataflow` 扫描内存写历史，报告每对「线程 A 写地址 X → 线程 B 读地址 X（中间无其它写）」，按地址聚合成 channel 并给出 producer→consumer 统计。

## 排除区间

```bash
./tenet trace.bin --exclude-range 0x1001000 0x1002000 --exclude-range 0x2001000 0x2002000
```

排除区间在分析时过滤指令，不会修改 Trace 文件。

## 外部镜像

```bash
./tenet trace.bin --image /path/to/binary
```

## 交互与服务入口

当前没有 `--tui` 参数。不带分析或服务参数运行 `./tenet trace.bin` 时，默认进入终端 TUI。

| 参数 | 行为 |
|---|---|
| `--rpc [[host:]port]` | 启动 TCP JSON-RPC；裸 `--rpc` 默认为 `127.0.0.1:0`（自动端口） |
| `--mcp` | 通过 stdin/stdout 启动 MCP JSON-RPC，直到 stdin 关闭 |
| `--mcp-http [host:port]` | 启动 MCP Streamable HTTP，默认 `127.0.0.1:10444`；可配合 `--mcp-host`、`--mcp-port`、`--mcp-auth` |
| `--mcp-hub [host:port]` | 启动多实例 Hub/Worker 协调，默认 `127.0.0.1:10444` |
| `--ws-port <port>` | 启动固定绑定 `127.0.0.1` 的 FlatBuffers WebSocket 服务；Windows 当前不可用 |
| `--streaming` | tail 正在增长的 Trace 并实时构建索引 |
| `--stats` | 以 JSON 输出 Trace 统计信息 |

Tauri 桌面应用会以 sidecar 方式启动 `tenet --ws-port <port> <trace> --mcp-hub`。Windows 构建当前不支持 `--ws-port`，但 CLI、TUI、RPC 和 MCP 不受影响。

## 输出与报告

大多数 CLI 模式向 stdout 输出结构化文本。图导出（CFG、调用图、数据流图）写入 Graphviz DOT 文件。Profile 支持 JSON 和 CSV。Diff 写入 JSON。`--backward-taint-graph <file>` 按扩展名导出 `.dot` 或 `.json`。

## 无界面注意事项

- CLI、终端 TUI 与 Tauri sidecar/后端读写相同的 `.tenet/` 索引，并遵守相同的会话锁。
- 长时间批处理不渲染 UI，比 TUI 更快。
- Pass 结果会被缓存；相同参数重复运行完成很快。

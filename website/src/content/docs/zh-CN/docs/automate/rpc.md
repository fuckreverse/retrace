---
title: JSON-RPC 服务
sidebar:
  order: 3
---

JSON-RPC 服务是面向本地脚本和工具集成的精简查询接口。Tenet 在进程启动时通过 CLI 打开一份 Trace，RPC 客户端连接后查询这份已打开的 Trace。

## 启动

`--rpc` 接受 `[[host:]port]`。默认监听 `127.0.0.1:0`；端口为 `0` 时由操作系统自动分配，实际端点会输出到标准错误流。

```bash
./tenet trace.bin --rpc 4321
./tenet trace.bin --rpc 127.0.0.1:4321
./tenet trace.bin --rpc
```

RPC 模式会保持进程运行，直到收到 `SIGINT` 或 `SIGTERM`。服务使用 IPv4 TCP，通常应保持在 loopback 地址上，不应暴露到不受信任的网络。

## 协议

服务使用 JSON-RPC 2.0 over TCP。每条请求和响应都是一行 JSON，并以换行符 `\n` 结束。请求的 `id` 可以是整数或字符串；`params` 省略时按空对象处理。服务按顺序处理客户端连接和请求，不会推送进度 Notification。

请求：

```json
{"jsonrpc":"2.0","id":1,"method":"get_reg","params":{"inst_id":42,"reg_name":"x0"}}
```

响应：

```json
{"jsonrpc":"2.0","id":1,"result":{"inst_id":42,"reg_name":"x0","value":"0x1234"}}
```

数值参数既可以使用 JSON number，也可以使用十进制字符串或带 `0x` 前缀的十六进制字符串。地址和值等结果字段通常以十六进制字符串返回。

## 可用方法

| 方法 | 参数 | 返回与行为 |
|---|---|---|
| `ping` | 无 | 返回 `{"pong": true}`。 |
| `get_progress` | `kind?: string` | 返回 `tasks` 快照，可按 `kind` 过滤。每项包含 `id`、`kind`、`label`、`phase`、`state`、`progress`、`completed`、`total`、`message`、`error`、`revision`。 |
| `get_stats` | 无 | 返回 `inst_count`、`anchor_count`、`code_count`、`build_seconds`、`module_name`、`module_base`、`module_slide`、`file_size`。模块基址和 slide 是十六进制字符串。 |
| `get_reg` | `inst_id`, `reg_name?` | 返回指定指令执行前的 `inst_id`、`reg_name` 和 `value`。`reg_name` 默认为 `x0`；支持 `x0`–`x28`、`fp`/`x29`、`lr`/`x30`、`sp`、`nzcv`、`pc`。未知寄存器返回 `-32602`。 |
| `get_regs` | `inst_id` | 返回 `inst_id` 和 `regs`，后者包含指定指令执行前的 34 个 AArch64 GPR 状态，键使用规范名称 `x0`–`x28`、`fp`、`lr`、`sp`、`nzcv`、`pc`。 |
| `read_mem` | `addr`, `size?`, `inst_id?` | 时间感知内存读取。`size` 默认 16，最大 4096；`inst_id` 默认 Trace 指令总数。返回 `addr`、`size`、`inst_id`、字节数组 `data`、逐字节有效性数组 `known` 和 `known_count`。 |
| `get_range` | `start?`, `end?` | 返回 `[start,end)` 内的指令行；`start` 默认 0，`end` 默认 `start + 100`，最多返回 1000 个 ID 范围。结果含 `rows`、`start`、`end`；每行含 `inst_id`、`pc`、`reg_diffs` 和 `mem_accesses`。 |
| `get_xref` | `pc` | 获取/运行 `xref` Pass，并返回 `pc`、`inst_ids` 和完整的 `exec_count`；`inst_ids` 最多 10000 项。Pass 不可用时返回空数组、计数 0 和 `warning`。 |
| `get_cfg` | 无 | 需要 `PassManager`；获取/运行 `cfg_layout` Pass，返回带注释的 Graphviz `dot`。不可用或失败时返回 `-32603`。 |
| `get_call_graph` | 无 | 需要 `PassManager`；获取/运行调用图 Pass，返回 `nodes` 和 `edges`。节点含 `pc`、`name`、`is_root`、`calls_made`、`calls_received`；边含 `caller`、`callee`、`call_count`。 |
| `get_taint` | `inst_id?` | 需要 `PassManager` 和可取得的 `taint` Pass 结果。返回 `instructions_processed`、最终 `tainted_regs`、完整 `step_count` 及最多 500 个 `steps`；截断时附带 `steps_truncated: true`。每个 step 含 `inst_id`、`pc`、`dst_reg`。当前实现接受 `inst_id`（默认 0），但不会用它重新配置污点源。 |

## 进度与分析范围

服务不会主动发送进度事件。客户端可以轮询 `get_progress`，获取当前任务的状态快照。

RPC 只提供基础状态、寄存器、内存、指令范围、XRef、污点结果和图查询等有限接口。进程启动时已经打开 Trace；RPC 客户端不能切换或关闭 Trace。需要主动运行更完整的分析工作流（包括更多污点分析、CFG 导出、算法识别等）时，请使用 [MCP 服务](./mcp/)。

## 集成模式

- 使用支持 newline-delimited JSON 的 TCP 客户端或 Python JSON-RPC 客户端连接。
- 对已打开 Trace 执行轻量、结构化的本地查询。
- 将寄存器、内存、XRef 和图结果桥接到其他工具。
- 完整分析自动化交给 MCP，RPC 保持为小型查询面。

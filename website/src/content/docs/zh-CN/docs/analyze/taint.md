---
title: 污点与数据流
sidebar:
  order: 3
---

污点分析连接执行时间轴上的值。前向污点回答 source 流向哪里，反向污点回答哪些值对 sink 有贡献。

## Source 与 sink 选择

- **前向 source**：某次指令执行中的一个寄存器索引。该寄存器在该时刻的值成为初始污点种子。
- **反向 sink**：某条指令 (`inst_id`) 中的一个寄存器索引。分析向后回溯所有对该值有贡献的指令。

两者都使用**寄存器数字索引**（0–28 对应 x0–x28，29 = fp，30 = lr，31 = sp，32 = nzcv，33 = pc）。前向分析还通过 `--taint-mem` 支持内存 source。

## 前向污点配置

选择寄存器，可选指定指令执行和内存 source：

```bash
./tenet [options] trace.bin --taint 0 --taint-inst 12000
./tenet [options] trace.bin --taint 0 --taint-mem 0x16fdff200 \
  --taint-stop-pc 0x100123456 --taint-max-width 16
```

控制项：

- `--taint-inst <inst_id>` — 从特定执行开始（不只是该寄存器的首次写入）。
- `--taint-mem <addr>` — 添加内存地址作为额外污点源（可重复）。
- `--taint-stop-pc <addr>` — 执行到该 PC 时停止传播（可重复，用于在已知 sink 处限制调查）。
- `--taint-max-width <N>` — 当同时污点的寄存器数超过 N 时停止（防止无控制扩散）。
- `--taint-no-calls` — 不跨函数调用传播污点。
- `--taint-no-xref` — 关闭 XRef 加速（更慢但便于诊断传播问题）。
- `--taint-no-kills` — 不在输出中输出 kill 事件。

前向污点默认启用 XRef 加速；需要 `xref` pass 已注册。

## 反向污点：writer 与 overlap

`--backward-taint` 跟踪最近寄存器 writer 链和重叠内存写：

```bash
./tenet [options] trace.bin --backward-taint 58000 0
./tenet [options] trace.bin --backward-taint 58000 0 \
  --backward-taint-max-steps 5000 \
  --backward-taint-graph graph.json
```

- `--backward-taint <inst_id> <reg>` — 必填：sink 指令和寄存器索引。
- `--backward-taint-max-steps <N>` — 限制向后回溯的步数（默认无限制，仅受 trace 起点约束）。
- `--backward-taint-graph <file>` — 导出反向 walk 过程中构建的数据流依赖图（`.dot` 或 `.json`）。这是**反向污点自身的**依赖图；与独立的 `--dataflow-graph` Pass 不同。

Pass 同时跟踪寄存器 writer (reg_diff) 和内存 load←store 链。内存匹配支持**重叠感知**：跟踪部分重叠和非对齐访问，因此对 `0x1000` 的写入会贡献到对 `0x1004` 的读取（如果地址范围相交）。

## `--critical-path`：必须搭配反向污点

`--critical-path` 计算前向可达（source → 所有到达处）与反向贡献（所有流入 sink 的指令）的交集。结果是实际将 source 数据转换为 sink 值的指令序列。

**CLI 语义**：`--critical-path` **必须**与 `--backward-taint <inst_id> <reg>` 搭配使用。它还需要前向污点；如果未指定 `--taint`，会自动使用反向 sink 的寄存器作为前向 source；起点取 `--taint-inst`，未提供时从 Trace 开头开始。

```bash
./tenet [options] trace.bin \
  --taint 0 --taint-inst 10000 \
  --backward-taint 58000 0 \
  --critical-path
```

输出包括 `critical_path_count`（交集大小）、`backward_count`、`forward_count`，以及前 200 条关键路径指令 ID。

MCP 等价工具：单次调用 `critical_path`，同时传入 `source_reg`、`source_inst_id`、`sink_reg` 与 `sink_inst_id`；工具会在内部运行双向分析。

## `--backward-taint-graph` 与 `--dataflow-graph` 的区别

这是两种不同的分析：

| | `--backward-taint-graph` | `--dataflow-graph` |
|---|---|---|
| 范围 | 从 sink 反向 walk 发现的所有贡献指令 | 用户指定的指令范围 `[start, end)` |
| 触发标志 | `--backward-taint-graph <file>`（与 `--backward-taint` 搭配） | `--dataflow-graph <start> <end>` |
| 输出路径 | 同一标志 | `--dataflow-graph-output <file>` |
| Pass 名称 | 内建于 `backward_taint` | `dataflow_graph` |
| 节点上限 | 所有贡献指令 | 默认 5000 节点 |

```bash
# 反向污点自身的依赖图（沿 sink 贡献链）
./tenet [options] trace.bin --backward-taint 58000 0 \
  --backward-taint-graph bt-graph.json

# 任意范围的独立数据流图
./tenet [options] trace.bin --dataflow-graph 20000 24000 \
  --dataflow-graph-output dfg.dot
```

## 来源标注

`taint_source_annotation` 为反向污点叶子补充上下文分类：

```bash
./tenet [options] trace.bin --backward-taint 58000 0 --taint-source-annotation
```

每个叶子（无法再向前追溯的端点）被分类为：

- `ObjcGetter` / `ObjcArg` / `ObjcReturn` — 值来自 Objective-C 方法（仅 iOS/macOS）。
- `MemoryLoad` — 值来自内存读取，且贡献集中没有更早的写入。
- `Constant` — 值由立即数加载指令（MOVZ/MOVK 链、ADRP+ADD）物化。
- `FunctionReturn` — 值由函数调用返回。

**依赖**：需要 `backward_taint`（硬依赖）和 `objc`（硬依赖）。`function` 是软依赖，用于将 `FunctionReturn` 来源归因到具体 callee。Android/Linux Trace 无法获得 ObjC 标注（无 ObjC 运行时）。

## Triton 与回退语义

当 Tenet 使用 Triton 构建（`TENET_ENABLE_TRITON=ON`）且 Triton bridge 可用时，前向和反向污点都使用 Triton 的符号引擎获取精确的逐指令语义。这能捕获标志级依赖和复杂 AArch64 寻址模式。

当 Triton 不可用（构建时未启用，或运行时缺失）时，两个 Pass 都回退到**启发式引擎**：

- 寄存器污染从 `reg_diff` 条目推断（有 diff 的寄存器即视为被写入）。
- 应用 kill 语义：如果寄存器被完全覆盖（不依赖其先前值），旧污点被杀死。
- 内存传播通过内存模型的 store←load 重叠匹配进行。
- NZCV 和 SP 不作为普通值污点传播。

启发式对具有部分寄存器更新或标志依赖操作的指令精度较低，但覆盖绝大多数 AArch64 整数代码。

## Tauri 前端、TUI 与 MCP

- **Tauri 前端**：污点指令在指令列表中高亮；Producer Chain 面板显示 `backward_taint` 结果的受限预览（不是独立分析）。"Taint" 模式显示前向污点事件。
- **TUI**：按 `t` 运行前向污点，按 `B`（Shift+b）运行反向污点；污点指令会在列表中标注。
- **MCP**：`taint_forward` 必填 `reg_index`，并支持 `inst_id`、`mem_addrs`、`stop_pcs`、`max_width` 与步骤分页；`taint_backward` 使用 `sink_inst_id` / `sink_reg`，支持步数限制和事件分页；`critical_path` 在一次调用中同时接收 source 与 sink；`dataflow_graph` 使用 `start_inst_id` / `end_inst_id`，可选 `max_nodes`、`format`。

## 结果解释

- 污点证明的是**特定执行中记录到的数据依赖**——不一定暗示语义意图或密码学相关性。
- 污点路径不保证 source 值在位级别上原样出现在 sink 处（中间转换可能已改变它）。
- 缺失或未插桩的操作（未录制的调用、排除范围）会中断链路，在传播中产生缺口。
- 前向污点会过近似：如果寄存器的新值实际上不依赖其先前值但 Pass 无法证明，旧污点可能存活（仅启发式模式；Triton 更精确）。

## 性能与缓存

- 前向污点默认使用 XRef 加速——快速跳过不接触污点集的指令。仅在诊断时用 `--taint-no-xref` 禁用。
- 反向污点通过 `--backward-taint-max-steps` 限制 walk 时间，对大 trace 保持可预测。
- 前向 Pass 从 source 到结尾是单流；其成本随污点集触及的指令数扩展，而非总 trace 大小。
- 结果不在运行间缓存；重新运行污点会重新运行 Pass。底层 `xref` Pass 在 trace 范围不变时可能作为 RocksDB blob 缓存。

## 排查

### 前向污点几乎到达所有地方

污点集在无节制地扩散。添加 `--taint-max-width` 限制寄存器集，`--taint-stop-pc` 按位置限制，或 `--taint-no-calls` 阻止跨函数传播。

### 反向污点找不到上游来源

sink 寄存器可能由未插桩操作设置（trace 中的间隙），或 trace 缺少识别 writer 所需的 `reg_diff` 数据。确认 trace 录制时启用了 `QBDITRACE_REC_REGDIFF`，且 sink 指令在插桩范围内。

### `--critical-path` 产生空结果

前向与反向污点集没有交集。先运行前向污点检查它到达哪里，再从疑似 sink 运行反向污点，确认贡献集有交集。

### 污点链路在调用边界出现缺口

使用 C API 记录 (`REC_CAPICALL`) 或 read 观察来检查跨未录制调用的参数传递。来源标注也可以识别值是否来自未插桩的函数返回。

### Triton 与启发式结果不一致

Triton 对更多 AArch64 指令有精确语义；启发式在边角情况下可能过污点。需要精确精度时优先使用 Triton 构建。

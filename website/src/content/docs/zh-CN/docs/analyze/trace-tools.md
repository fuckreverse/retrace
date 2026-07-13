---
title: Trace 工具
sidebar:
  order: 7
---

Trace 工具对整个执行历史进行操作：压缩重复循环、比较 Trace 区域、追踪寄存器变化、统计指令窗口。它们不衍生关于单条 Trace 的新语义事实，而是帮你选择、压缩和比较时间轴。

## Trace 折叠

`trace_fold` 检测重复的循环迭代，把它们压缩为摘要。不再展示每一次迭代，而是保留少量代表性迭代（首次末 N 次），并报告折叠区域中发生的寄存器 / NEON 状态变化。

必要的 Pass 依赖是 `loop`（循环发现）与 `xref`（PC 交叉引用）；MCP 包装层还会调度 `function` 以提供周边上下文。

```bash
./tenet [options] trace.bin --trace-fold <start> <end>
./tenet [options] trace.bin --trace-fold <start> <end> --trace-fold-min-iter 5
./tenet [options] trace.bin --trace-fold <start> <end> --trace-fold-keep-iter 3
```

所有参数都是 **instruction ID**（不是 PC）—— 要折叠的连续 inst_id 区间。

### 附加参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--trace-fold-min-iter <N>` | 3 | 折叠一个循环所需的最小连续迭代次数 |
| `--trace-fold-keep-iter <N>` | 2 | 保留的代表性迭代数（前 N + 后 N） |
| `--trace-fold-samples <N>` | 6 | 内部采样点数，用于分类每个寄存器的变化模式（单调 / 振荡 / 常量） |
| `--trace-fold-no-fpr` | 关闭 | 即使 Trace 携带 v7 FPR 数据，也禁用 FPR（NEON v0–v31）差异摘要 |

### 折叠报告内容

每个折叠区域报告：

- **header PC**：循环的分支回跳目标；
- **total iterations / instructions folded**：移除了多少；
- **kept iterations**：保留在简化视图中的代表性首次/末次迭代的 inst_id 区间；
- **GPR 变化**：每个被修改的寄存器的首次值、末次值、推断模式（`constant` / `monotonic` / `oscillating`）—— 快速启发式，暗示计数器/累加器还是临时复用；
- **FPR 变化**（仅 v7 FPR 启用 Trace，除非 `--trace-fold-no-fpr`）：每个被修改的 NEON 寄存器的首次/末次 128 位值；
- **compression ratio**：`original / folded`。

### 如何解读折叠结果

模式分类是有意轻量级的 —— 它**不是** `loop_semantics` 的替代品。用它来：

- 压缩寄存器呈 `monotonic` 寻址的 `memset` 风格字节循环；
- 发现除 PC 外不改任何 GPR 的循环（全部 `constant` = 大概率 busy-wait 或延迟）；
- 识别累加器风格循环（某 xN 呈 `monotonic` 意味着运行累加和）。

要对循环做严格分类（Feistel、SPN、ARX、memcpy 等），在未折叠的 Trace 或对保留迭代上运行 `--loop-semantics`。

### 状态摘要

`trace_fold` 在采样前用 `regfile.warm_range()` 批量预热折叠区域的所有 anchor 缓存，避免逐迭代冷 replay。首次/末次 + 内部采样点取自均匀间隔的迭代，再加上半周期伴随点，防止周期信号（如 `+delta / -delta` 交替的临时寄存器）被误判为 `monotonic`（抗混叠）。

## Trace 差异

`trace_diff` 比较两个指令区间，找出它们在哪里分叉。支持同 Trace 区域比较与跨文件比较（差分密码分析 / 白盒分析）。

```bash
# 同 Trace 区域比较
./tenet [options] trace.bin --trace-diff <a_start> <a_end> <b_start> <b_end>

# 跨文件：与第二条 Trace 比较
./tenet [options] trace.bin --trace-diff <a_start> <a_end> <b_start> <b_end> --trace-diff-file other.bin
```

所有参数都是 **instruction ID**。区间为半开：`[start, end)`。

### 附加参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--trace-diff-file <path>` |（同 Trace）| 跨文件比较时 Trace B 的路径 |
| `--trace-diff-window <n>` | 16384 | 重同步前向搜索窗口 —— 分叉前向后搜索多少条指令以找到匹配的 PC |
| `--trace-diff-max-diffs <n>` | 100000 | 最大记录的分歧段数；超过此值结果被截断 |

### 对齐与重同步

差异按 inst_id 顺序双向遍历。差异分为三种类型：

| 类型 | 含义 | 重同步行为 |
|---|---|---|
| `ControlFlow` | PC 不同 | 触发重同步搜索：在两个区间内前向扫描最多 `resync_window` 条指令，寻找匹配的 PC 对（优先以 CALL/RET 边界作为锚点） |
| `RegisterValue` | PC 相同但输出寄存器值不同 | 内联报告；两个区间继续同步推进 |
| `MemoryValue` | PC 相同但内存访问值不同 | 内联报告；两个区间继续同步推进 |

重同步成功时，段标记 `resynced = true` 并记录两侧的重同步点。失败时（永久性分歧），`resynced = false`。

每个 `DivergeSegment` 记录：
- 分歧起点（A 的 inst_id、B 的 inst_id、分叉处 PC、类型）；
- 两侧的分歧长度（`skip_a`、`skip_b`）；
- 成功时的重同步点。

### 同文件 vs 跨文件

- **同文件**（无 `--trace-diff-file`）：适用于同一 Trace 中某函数被调用两次的场景（如同一原语两种输入）。Tenet 用两个独立 reader 两次打开同一 Trace。
- **跨文件**：Tenet 分别减去两条 Trace 的 `module_slide`，按归一化 PC 比较；架构与 GPR 数必须一致，模块名不同时会给出可靠性警告。格式版本必须兼容。区间不匹配或模块布局不同会产生难读的差异 —— 先分别确认两条 Trace 都能在 tenet 中正常打开再做差异比较。

### 结果解读

结果摘要字段：
- `matched_count`：完美匹配的指令数（PC + 数据完全一致）；
- `total_diverged`：分歧区间的总指令数；
- `resync_count`：成功重同步次数；
- `permanent_divergence_count`：从未重同步的段数；
- `truncated`：`true` 表示达到 `max_diffs`。

对同一函数两种输入的健康差分分析会呈现：早期匹配 → 输入依赖分支处的分歧段 → 共同汇聚点（函数 epilogue）处的成功重同步。

## 窗口统计

`window_stats` 对连续 inst_id 区间计算逐窗口指标：指令混合（助记符分布）、寄存器写活跃度、内存访问密度、唯一 PC、分支密度、助记符熵。用于剖析哪个执行阶段最活跃。

```bash
./tenet [options] trace.bin --window-stats <start> <end>
./tenet [options] trace.bin --window-stats <start> <end> --window-stats-size 2048
```

### 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--window-stats <start> <end>` | —— | 要扫描的 inst_id 区间（必填） |
| `--window-stats-size <n>` | 1024 | 每个窗口的指令数（MCP 默认 1000） |

### 窗口统计报告

每个 `WindowSnapshot` 包含：
- 指令数；
- 按计数降序的 top-N 助记符；
- 每个 GPR（共 34 个）的写计数；
- 读/写次数与唯一内存地址数；
- 唯一 PC（指令多样性）；
- 指令混合的助记符熵；
- 分支密度。

聚合结果高亮：最热内存窗口、最最多样窗口（最高熵）、最密分支窗口。

用 `--window-stats-size` 调节粒度：更小窗口更精确定位热点；更大窗口平滑噪声但可能合并不同阶段。

## 寄存器时间线

`reg_timeline` 在某个 inst_id 区间为一个 GPR 建立逐写历史：每条写事件记录 PC、旧值、新值。

```bash
./tenet [options] trace.bin --reg-timeline <reg_index>
./tenet [options] trace.bin --reg-timeline <reg_index> --reg-timeline-range <start> <end>
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--reg-timeline <reg_index>` | —— | 寄存器索引（0–28 = x0–x28，29=fp，30=lr，31=sp，32=nzcv，33=pc） |
| `--reg-timeline-range <start> <end>` | 整个 Trace | 要扫描的 inst_id 区间 |

### GUI / MCP 入口

GUI 在 Profile 分组中提供"Register Timeline"面板：在寄存器视图中选择寄存器即可填充时间线。MCP 暴露 `reg_timeline` 工具，参数与 CLI 一致。

## 调用上下文

`call_context` 对单条指令重建调用栈（通过 `FunctionResult::call_stack_at()`）、循环上下文（哪些循环包含该目标、嵌套深度、迭代数）、目标前后的相邻指令。

```bash
./tenet [options] trace.bin --call-context <inst_id>
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--call-context <inst_id>` | —— | 目标 instruction ID |

### 结果结构

- `call_stack`：由外到内的 `CallStackFrame` 列表（调用点 PC、被调用方 PC、call/ret inst_id、尾调用标记）；
- `loop_contexts`：包含目标的循环，含 header PC、嵌套深度、观察到的总迭代数；
- `instructions`：周围指令（默认前 10 / 后 10），每条标注循环深度以及是否为目标。

### GUI / MCP 入口

GUI 中在时间线中选择指令会自动填充 Call Context 面板。MCP 的 `call_context` 可传精确 `inst_id` 或 `pc`；PC 形式通过 XRef 选择一次已观察的指令执行。

## 性能剖析入口

Tenet **没有** `--profile` CLI 标志。性能分析走 macOS Instruments 工具链：

- **Time Profiler** —— 函数级 CPU 采样，定位最慢的 Pass 或函数；
- **System Trace** —— 可视化线程调度与上下文切换；
- **CPU Counters** —— 暴露 IPC、cache miss 率、分支预测失败率；
- **os_signpost** —— `TENET_ZONE_NAMED(...)` 打在 Instruments 中以 "Points of Interest" 出现，按 Pass 名标记。

命令与方法论见随产品提供的 `tools/tenet/docs/profiling.md` 指南（Instruments、signpost 标记、基准测试套件）。

## 推荐工作流

1. **初步浏览** —— 在 GUI 打开 Trace 或 `--stats`，确认总指令数与索引状态。
2. **定位热区** —— 跑 `--window-stats 0 <end>` 找出最活跃的指令段。
3. **折叠噪声循环** —— 如果窗口统计暴露了高密度高迭代区域（memset 风格），对该 inst_id 区间跑 `--trace-fold`，在深入分析前先压缩。
4. **差异对比** —— 对同函数/不同输入的 Trace，使用 `--trace-diff`（或 `--trace-diff-file`）定位数据依赖引发的分歧。
5. **寄存器级下钻** —— 一旦锁定感兴趣的 PC，用 `--reg-timeline <reg>` 看该区间寄存器变化，用 `--call-context <inst>` 重建控制流上下文。

## 限制与排查

- **折叠基于 inst_id 区间**，不是 PC。如果想折叠特定循环，先在 GUI 或 `--search-pc <header_pc>` 中定位其 inst_id 范围。
- **差异要求格式/版本兼容**。两条 Trace（或同一 Trace 的两个区间）都能在 tenet 中正常打开。Delta 编码（v5）和 FPR（v7）Trace 在 tenet 内完全支持。
- **离线解码**通过 `tenet --dump text` 或 `tenet --dump jsonl` 进行，支持 v4/v5/v7（含分块压缩）。独立的 `trace_decode` 已移除。
- **寄存器时间线和调用上下文都有 GUI 面板**，也可通过 CLI/MCP 访问。没有 `--profile` / `--hotspot` CLI 标志 —— 性能剖析用 Instruments，不是内置采样器。
- **折叠保留代表性迭代**；并不从底层 Trace 数据中移除。折叠后运行的 Pass 仍看到原始指令流。
- **窗口统计步长 = 窗口大小**（不重叠）；当前 CLI 不暴露重叠窗口。

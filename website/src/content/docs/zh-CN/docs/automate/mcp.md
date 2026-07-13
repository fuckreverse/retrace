---
title: MCP 服务
sidebar:
  order: 4
---

Tenet 的 Model Context Protocol (MCP) 服务让 LLM 代理和 IDE 通过结构化工具直接查询 Trace、重建状态、运行分析并验证结论。所有入口都复用同一个 `TraceReader`、索引、Pass 管线和结果缓存。

Tenet 提供两种推荐入口：

| 模式 | 启动方式 | 适用场景 |
|---|---|---|
| stdio | `--mcp` | 一个客户端直接拉起一个 Tenet 进程和一份 Trace |
| MCP Hub | `--mcp-hub` | GUI 自动接入、同时打开多份 Trace、固定端口连接 |

## stdio：单 Trace

```bash
./tenet trace.bin --mcp
```

Tenet 通过 stdin/stdout 收发 JSON-RPC 消息，日志写入 stderr；进程持续运行直到客户端关闭 stdin。

客户端配置示例：

```json
{
  "mcpServers": {
    "tenet": {
      "command": "/absolute/path/to/tenet",
      "args": [
        "/absolute/path/to/trace.bin",
        "--mcp"
      ]
    }
  }
}
```

使用绝对路径，避免 MCP 客户端的工作目录与终端不同。stdio 模式绑定单个 Trace，不需要 `instance` 参数。

## MCP Hub：固定端口与多实例

```bash
./tenet trace.bin --mcp-hub
```

默认监听：

```text
http://127.0.0.1:10444/mcp
```

可显式指定监听地址和实例名：

```bash
./tenet trace.bin \
  --mcp-hub 127.0.0.1:10444 \
  --mcp-hub-name signing-trace
```

客户端配置示例：

```json
{
  "mcpServers": {
    "tenet": {
      "url": "http://127.0.0.1:10444/mcp"
    }
  }
}
```

:::note[端口约定]
MCP Hub 和 GUI 使用的默认端口是 **10444**。无需为每一份 Trace 分配单独端口。
:::

### Hub 如何组织多份 Trace

第一个成功获取 `~/.tenet/mcp-hub.lock` 的 Tenet 进程成为 Hub，并监听 `10444`。随后打开的 Tenet 进程作为 Worker 反向连接 Hub，不再对外监听端口。Hub 同时负责：

- 提供自身 Trace 的工具；
- 维护所有实例的 ID、PID、Trace 路径和模块名；
- 将工具调用路由到目标实例；
- 在进程退出后依靠 `flock` 自动释放选举锁。

先发现实例：

```text
list_instances()
```

默认是 **sessionless** 模式，因此每次普通工具调用都必须携带 `instance`：

```text
trace_info(instance="signing-trace")
get_regs(instance="signing-trace", inst_id=1200)
```

这避免并发代理或多个会话共享 Hub 时把请求错误路由到另一份 Trace。

### Session 模式

如果客户端更适合保持一个默认实例：

```bash
./tenet trace.bin --mcp-hub --mcp-hub-session
```

先调用：

```text
select_instance(instance="signing-trace")
```

之后可以省略普通工具的 `instance`。`list_instances` 在两种模式下都可用；`select_instance` 只在 session 模式下注册。

### GUI 行为

GUI 打开 Trace 后会自动尝试加入 MCP Hub：首个 GUI 会话成为 Hub，后续会话成为 Worker。默认地址同样是 `127.0.0.1:10444`，默认使用 sessionless 路由。通常只需让客户端连接一次 `10444`，无需为每个 GUI 窗口重复配置。

## 从三个工具开始

连接后建议按以下顺序建立上下文：

1. `list_instances`（Hub）— 选择目标 Trace；
2. `trace_info` — 确认模块、Trace 版本、指令数、slide 和地址范围；
3. `disasm` / `search_pc` / `get_regs` — 将问题落到具体执行位置和状态。

不要让代理一开始就运行所有昂贵分析。先缩小 PC 或 `inst_id` 范围，再运行污点、图分析或 VM 查询。

## 工具目录

工具 schema 是权威参数说明；客户端应通过 MCP 的 `tools/list` 获取当前构建实际提供的工具。下面按用途列出当前接口。

### Trace、指令与状态

| 工具 | 用途 |
|---|---|
| `trace_info` | Trace 格式、模块、地址、flags 与指令统计 |
| `disasm` | 分页读取已执行指令、寄存器差值和内存访问 |
| `get_regs` | 按 `inst_id` 或 PC 重建 34 个 AArch64 GPR |
| `memread` | 指定时刻的 time-travel 内存读取 |
| `mem_write_history` | 查询地址范围的历史写入 |
| `search_pc` | O(1) 查询某 PC 的执行实例 |
| `reg_timeline` | 寄存器值变化时间线 |
| `call_context` | 指令处的动态调用上下文 |

### 数据流与图

| 工具 | 用途 |
|---|---|
| `taint_forward` | 前向污点；Triton 可用时使用精确语义，否则启发式回退 |
| `taint_backward` | 从 sink 回溯贡献源 |
| `critical_path` | 前向与反向污点交集 |
| `cfg_export` | 导出执行 CFG（JSON/DOT） |
| `call_graph` | 导出动态调用图（JSON/DOT） |
| `dataflow_graph` | 导出限定指令区间的数据流图 |

### 结构、模式与平台语义

| 工具 | 用途 |
|---|---|
| `functions` / `find_function` | 枚举或定位执行支撑的函数 |
| `loops` / `loop_semantics` | 循环结构与算法语义分类 |
| `xref` | PC 交叉引用和热点统计 |
| `pattern_scan` / `constants_scan` | 加密、反分析、混淆模式和物化常量 |
| `algorithm_summary` | 汇总算法候选及证据 |
| `strings_scan` / `memory_strings` | 扫描写入历史或指定时刻内存中的字符串 |
| `mem_search` / `yara_mem_scan` | 值、字节模式和 YARA 内存搜索 |
| `memory_snapshot` / `entropy_analysis` | 内存快照和熵测量 |
| `objc_messages` / `objc_crypto` | ObjC 消息及其密码学上下文 |
| `syscall_intercept` | CommonCrypto、BoringSSL、JNI 等边界调用 |
| `symbol_annotation` | 为 PC 聚合函数、循环、常量和模式标签 |
| `taint_source_annotation` | 为反向污点叶节点补充来源语义 |
| `trace_fold` / `trace_diff` | 折叠重复执行或比较两个区间/Trace |
| `window_stats` | 分页统计指令窗口特征 |

### VM 分析

| 工具 | 用途 |
|---|---|
| `vm_abstract` | 使用 IDA/Ghidra hints 构建 VM 抽象 |
| `vm_summary` | dispatcher、架构、handler 热度概览；要求已有 `vm_abstract` 结果 |
| `vm_steps_query` | 按 opcode、VM-PC、label 或寄存器变化过滤 VM steps；要求已有 `vm_abstract` 结果 |
| `vm_reg_timeline` | 虚拟寄存器值变化时间线；要求已有 `vm_abstract` 结果 |
| `vm_backward_slice` | 虚拟寄存器的 step 级反向切片；要求已有 `vm_abstract` 结果 |

`vm_abstract` 不会无 hint 检测 VM。完整输入约定见[虚拟机与代码虚拟化](/zh-CN/docs/analyze/vmp/)。

### 面向代理的证据与假设

| 工具 | 用途 |
|---|---|
| `batch_query` | 一次执行最多 20 个独立查询，减少往返 |
| `verify_evidence` | 验证代理引用的 PC、指令、寄存器或内存证据 |
| `hypothesis_add` | 建立待验证假设 |
| `hypothesis_evidence` | 添加支持或反对证据及验证状态 |
| `hypothesis_conclude` | 在有已验证证据时确认假设 |
| `hypothesis_abandon` | 放弃不成立的假设 |
| `hypothesis_list` / `hypothesis_get` | 枚举或读取假设账本 |
| `hypothesis_mark_reviewed` | 标记人工复核状态 |

推荐把推理过程写成“假设 → 查询 → `verify_evidence` → 结论”，而不是把分析工具的候选结果直接当成事实。

## 地址空间与 IDA 协作

MCP 默认把 PC 转为 IDA 对 AArch64 Mach-O 常用的显示地址：

```text
displayed_pc = runtime_pc - module_slide + image_base
image_base = 0x100000000
```

因此 IDA 中的 `0x10001A2E4` 通常可以直接传给 `search_pc`，Tenet 返回的 PC 也可直接带回 IDA。

需要其他地址风格时调用：

```text
set_image_base(image_base="0x0")
```

- `0x100000000`：默认 IDA 显示地址；
- `0x0`：slide-relative 静态偏移；
- `module_slide`：原始运行时地址。

`set_image_base` 会影响后续所有 PC 输入和输出。修改后不要继续传旧地址空间的 PC。

典型协作流程：

1. IDA 中定位静态函数、dispatcher 或可疑调用点；
2. `search_pc` 确认该 PC 是否真实执行；
3. 从命中的 `inst_id` 调用 `disasm`、`get_regs`、`memread` 或污点工具；
4. 用 Tenet 的动态证据验证 IDA 中的静态假设；
5. 对 VM 分析，将 IDA 地址写入 hints JSON，再调用 `vm_abstract`。

## 性能、能力与安全边界

- 长结果均有分页参数；优先限制范围，不要反复请求完整 Trace。
- `batch_query` 最多组合 20 个查询，适合并行读取，不应用来无边界启动昂贵分析。
- `taint_forward`、`taint_backward` 和 `critical_path` 在启用 Triton 时使用精确语义，否则使用启发式回退。
- `yara_mem_scan` 需要构建时启用 YARA。
- Tenet 当前按单线程 Trace 语义分析。
- Hub Worker 请求有超时；超长任务应缩小范围后重试。
- Hub 默认仅绑定 `127.0.0.1`，没有认证或 TLS。不要将 `0.0.0.0:10444` 暴露到不可信网络；远程使用时应通过受控隧道或访问层保护。
- MCP 服务依赖活跃 Tenet 进程和已打开 Trace；进程退出后客户端应重新发现实例。

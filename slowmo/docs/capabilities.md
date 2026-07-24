# tenet 能力地图

这份文档不按源码目录，而是按“你要完成什么事”来组织 tenet 的能力。

```mermaid
mindmap
  root((tenet capabilities))
    交互浏览
      GUI
      TUI
      导航历史
      书签与搜索
    结构恢复
      function
      xref
      cfg
      call_graph
      loop
    数据流分析
      taint
      backward_taint
      dataflow_graph
    内存与字符串
      memread
      mem_write_history
      memory_snapshot
      strings
      memory_strings
      mem_search（含精确值检索）
    算法识别
      pattern（内嵌 constant_materialization）
      loop_semantics
      algorithm_summary
      objc_crypto
    混淆/VM保护
      vm_abstract
    自动化接入
      CLI
      RPC
      MCP stdio
      MCP HTTP
      batch_query
    流式与性能
streaming
stats
window_stats
profiling
```

## 1. 交互浏览

### GUI

- 默认入口，适合大 trace 的可视化浏览。
- 主要能力：指令列表、寄存器、内存、调用栈、函数列表、Hex Dump、CFG、分析结果面板。
- 典型命令：

```bash
./tenet trace.bin
```

### TUI

- 适合远程终端、SSH、无图形环境。
- 与 GUI 共用同一套 Core 和 Analysis，对等支持导航、断点、Goto、搜索、分析触发。
- 典型命令：

```bash
./tenet --tui trace.bin
```

### 你会用到的交互动作

- 时间轴导航：按 `inst_id` 跳转、前进/后退历史。
- 搜索：按 PC、指令文本、函数名定位。
- XRef 导航：在同一 PC 的多次执行之间跳转。
- 污点跳转：在 tainted 指令之间快速跳转。
- 断点：PC 断点、内存写观察点、条件断点。

参考：[`ui-layer.md`](ui-layer.md)

## 2. 结构恢复

这一组能力回答“代码结构长什么样”。

| 能力 | 入口 | 输出 | 典型用途 |
|------|------|------|----------|
| 函数识别 | `function` pass / `functions` MCP tool | `FunctionResult` | 找函数边界、调用关系、调用栈 |
| XRef | `xref` pass / `xref` MCP tool | `XrefResult` | 查某个 PC 执行过多少次、在哪些 inst_id 出现 |
| CFG | `cfg` / `cfg_layout` / `cfg_export` | `CFGResult`, DOT | 恢复基本块、边、布局、热度 |
| 调用图 | `call_graph` / `--call-graph` | DOT / JSON | 看函数间高层关系 |
| 循环 | `loop` / `loops` | loop 列表 | 找热点循环、准备做 loop semantics |

典型命令：

```bash
./tenet trace.bin --export-cfg func.dot --call-graph cg.json
./tenet trace.bin --symbol-annotation
```

对应 pass：`function`, `xref`, `cfg`, `cfg_layout`, `call_graph`, `loop`
（`--symbol-annotation` 不是独立 pass，而是聚合以上结果的辅助函数 `build_annotation_view()`）

参考：[`analysis-layer.md`](analysis-layer.md)

## 3. 数据流分析

这一组能力回答“值从哪里来、往哪里去”。

| 能力 | 入口 | 说明 |
|------|------|------|
| 前向污点 | `--taint`, `taint_forward` | 从 source 寄存器或内存向后传播 |
| 反向污点 | `--backward-taint`, `taint_backward` | 从 sink 反推贡献源 |
| 关键路径 | `--critical-path`, `critical_path` | 前向与反向污点交集 |
| 数据流图 | `--dataflow-graph`, `dataflow_graph` | 指令范围内寄存器级图结构 |
| taint source annotation | `--taint-source-annotation` | 给反向叶子源加 ObjC / 内存上下文 |

典型命令：

```bash
./tenet trace.bin --taint 0 --taint-inst 12000 --taint-stop-pc 0x100123456
./tenet trace.bin --backward-taint 58000 0 --backward-taint-graph graph.json
./tenet trace.bin --critical-path --backward-taint 58000 0
./tenet trace.bin --dataflow-graph 20000 24000 --dataflow-graph-output dfg.dot
```

对应 pass：`taint`, `backward_taint`, `dataflow_graph`, `taint_source_annotation`

> `slice`、`producer_chain` 已被 `backward_taint` 取代（不再是独立 pass/CLI 选项/MCP 工具）；GUI 里的 “Producer Chain” 快捷入口现在内部调用的是 `BackwardTaintPass` 的一个小步数预览模式。

参考：[`analysis-layer.md`](analysis-layer.md), [`core-layer.md`](core-layer.md)

## 4. 内存与字符串

这一组能力回答“某一时刻内存里是什么、谁写过它、它是不是字符串”。

| 能力 | 入口 | 说明 |
|------|------|------|
| 时间感知内存读取 | `--memread`, `memread` | 读取某地址在某个 `inst_id` 时刻的内容 |
| 写历史 | `--mem-history`, `mem_write_history` | 看某段地址被哪些指令写过 |
| 内存快照 | `--memory-snapshot`, `memory_snapshot` | 在指定调用点或 inst_id 抓区域快照 |
| 字符串扫描 | `--strings`, `strings_scan` | 从最终快照中恢复字符串 |
| 调用点字符串 | `--memory-strings`, `memory_strings` | 用时间感知重建调用瞬间的参数字符串 |
| 模式/精确值搜索 | `--mem-search`, `--mem-search-value`（兼容旧参数名 `--literal-search`）, `mem_search` | 按字节模式、精确数值或立即数搜索内存写入/寄存器值 |
| 熵分析 | `--entropy`, `entropy_analysis` | 判断高熵区、密文区 |
| YARA 扫描 | `--yara-mem-scan` | 在内存页上跑 YARA 规则 |

典型命令：

```bash
./tenet trace.bin --memread 0x16fdff200 64 32000
./tenet trace.bin --memory-snapshot 40000 --memory-snapshot-size 128
./tenet trace.bin --strings --memory-strings
./tenet trace.bin --mem-search-value 0x9E3779B97F4A7C15
```

对应 pass：`strings`, `memory_strings`, `memory_snapshot`, `mem_search`, `entropy`, `yara_mem_scan`

> `literal_search` 已不是独立 pass：精确数值搜索现在是 `MemSearchPass` 的一个模式。`--literal-search`/`--literal-search-range` 仍保留为 `--mem-search-value`/`--mem-search-range` 的弃用别名（仅 CLI 层面，不影响 MCP/GUI）。

参考：[`core-layer.md`](core-layer.md), [`analysis-layer.md`](analysis-layer.md)

## 5. 算法与高层语义识别

这一组能力回答“这段代码像什么算法、是不是加密、有没有 ObjC 触发点”。

| 能力 | 入口 | 说明 |
|------|------|------|
| 模式检测 | `--pattern`, `pattern_scan` | 检测 crypto / anti-debug / obfuscation / networking / key schedule |
| 常量物化 | `--constants`, `constants_scan` | 找 movz+movk 构造的算法常量 |
| 循环语义 | `--loop-semantics`, `loop_semantics` | 识别 Feistel / SPN / ARX / memcpy-like |
| 算法摘要 | `--algorithm-summary`, `algorithm_summary` | 汇总 pattern + constants + loop + call graph |
| ObjC 消息 | `--objc`, `objc_messages` | 提取类名、selector、调用点（仅 Darwin 目标） |
| ObjC × Crypto | `--objc-crypto`, `objc_crypto` | 关联高层调用栈与密码学逻辑（仅 Darwin 目标） |
| 系统调用拦截 | `--syscall-intercept`, `syscall_intercept` | 按平台自动选择 API 表（CommonCrypto/BoringSSL）；Darwin `REC_SVC` 支持 BSD syscall、负号 Mach trap 与发送 Mach 消息的常用 MIG routine 解析 |
| VMP 抽象 | `--vm-abstract`, `vm_abstract` | **需静态分析 hint**（anchor PC/PC集/内存写，来自 IDA/Ghidra）：在每条 VM 指令的 anchor 命中点快照 VM 上下文，派生 handler 执行次数、解码 opcode、读取 VM context/寄存器文件/栈快照 |

典型命令：

```bash
./tenet trace.bin --pattern --constants --loop-semantics --algorithm-summary
./tenet trace.bin --objc --objc-class NSData
./tenet trace.bin --objc-crypto --syscall-intercept
```

对应 pass：`pattern`（内嵌 constant_materialization）, `loop_semantics`, `algorithm_summary`, `objc`, `objc_crypto`, `syscall_intercept`

参考：[`analysis-layer.md`](analysis-layer.md)

## 6. 批处理与自动化接入

### CLI 批处理

- 适合 shell pipeline、一次性批量分析、JSON / DOT 导出。
- 入口在 `src/cli_options.cpp` + `src/batch_analysis.cpp`。
- 特点：多个选项可以组合，按声明顺序执行。

### RPC

- Unix socket JSON-RPC。
- 适合本地脚本或工具接入，不适合直接暴露到远程网络。

```bash
./tenet trace.bin --rpc /tmp/tenet.sock
```

### MCP stdio

- 适合本地 AI 客户端直接拉起 tenet 子进程。
- 所有工具共享同一组 in-memory 对象，避免每次调用重新打开 trace。

```bash
./tenet trace.bin --mcp
```

### MCP Streamable HTTP

- 适合 GUI 宿主、远程接入、没有 stdio 的运行环境。
- 单入口 `POST /mcp`，附带 `GET /health`。
- 支持 Basic Auth 和会话 ID。

```bash
./tenet trace.bin --mcp-http 127.0.0.1:10444
```

### MCP Hub 与 IDA Bridge

`--mcp-hub` 在默认 `127.0.0.1:10444` 上统一提供 `/mcp` Streamable HTTP、多实例 Worker 路由和 `/ws/<instance-id>` JSON WebSocket。IDAPython 插件通过 Hub 自动发现当前 IDB 对应模块，连接目标实例，并在 IDA 与 Tenet 之间双向同步导航；同一 PC 多次执行时，后端会选择距当前 Trace 光标最近的 `inst_id`。Hub JSON WebSocket 仅接受回环连接，与 `--ws-port` 的 FlatBuffers 二进制服务相互独立。

### MCP 工具分组

工具由 `register_all_tools()` 按组注册，VM query 位于独立的 `mcp_tools_vm.cpp`，Hub/session 模式还会增加协调工具；准确数量以启动日志为准。能力分为：

- Core / trace / query / taint / graph：基础 trace 查询与图分析
- Analysis / search / pass：高层分析与 pass 封装
- AI tools：`verify_evidence`, `batch_query`, 假设账本工具

参考：[`ui-layer.md`](ui-layer.md)

## 7. 流式与实时能力

### 实时增量索引

- `StreamingIndex` 会 tail 一个增长中的 trace 文件。
- 适合“边录制边看”的场景。
- 提供最终统计输出。

```bash
./tenet trace.bin --streaming
```

### 统计与健康检查

- `--stats`：输出 trace 基础统计 JSON。
- `GET /health`：MCP HTTP 活性探针。

## 8. 性能分析与优化

适合回答：

- 哪个 pass 最慢？
- 是 CPU 热点、内存分配，还是索引命中问题？
- Scan Fusion、并行分片和缓存有没有起作用？

入口文档：[`profiling.md`](profiling.md)

## 9. 从问题到能力的映射

| 你遇到的问题 | 优先使用 |
|--------------|----------|
| 我想知道某个输出是怎么来的 | `backward_taint`（含 GUI 内快速预览 “Producer Chain” 步数受限模式）, `mem_write_history` |
| 我想知道输入往哪流了 | `taint`, `critical_path`, `dataflow_graph` |
| 我想知道代码结构 | `function`, `xref`, `cfg`, `call_graph`, `loops` |
| 我想知道是不是某个算法 | `pattern`, `constants`, `loop_semantics`, `algorithm_summary` |
| 我想知道代码是不是被 VM 保护了 | 先用 IDA/Ghidra 静态分析定位 dispatcher，再用 `vm_abstract`（hint 驱动，不做启发式扫描）验证并跑执行统计 |
| 我想知道某段内存当时的值 | `memread`, `memory_snapshot`, `memory_strings` |
| 我想让 AI 自动分析 | 单实例用 `--mcp`，多 Trace 固定入口用 `--mcp-hub`（默认 `10444`） |
| 我想在 IDA 与 Trace 间双向跳转 | 启动 GUI/`--mcp-hub`，加载 `python/tenet_ida.py`，通过 Hub JSON WebSocket 同步 |
| 我想边录边看 | `--streaming` |
| 我在分析 Android trace | `syscall_intercept`（BoringSSL）, `pattern`, `taint` — ObjC 相关 pass 自动跳过 |
| 我想排除噪声代码区间 | qbditrace `--exclude-range`（录制时排除），tenet `--exclude-range`（分析时过滤） |
| 我想优化 tenet 本身 | `profiling.md` |

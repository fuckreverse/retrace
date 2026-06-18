# tenet MCP Server

通过 Model Context Protocol (MCP) 将 tenet trace 分析能力暴露给 AI 工具（Claude Desktop、CatDesk、Cursor、algokiller-plugin 等）。

## 架构

```
AI Client / algokiller-plugin
        │ JSON-RPC 2.0 over stdio
        ▼
mcp/ package (Python 3.9+, 36 tools)
├── server.py          — MCP dispatch + discipline injection
├── tools/             — 28 analysis tools (by category)
├── hypothesis/        — anti-hallucination ledger (8 tools)
└── discipline/        — LLM drift prevention
        │ subprocess
        ▼
tenet CLI binary  (C++17, Triton, RocksDB)
        │ mmap zero-copy
        ▼
QBDI trace file (.bin)
```

## 快速开始

### 1. 编译 tenet

```bash
cd tools/tenet/build
ninja -j$(nproc)
```

### 2. 配置 MCP client

**CatDesk / Claude Desktop** — 编辑 MCP 配置文件：

```json
{
  "mcpServers": {
    "tenet": {
      "command": "python3",
      "args": ["-m", "mcp"],
      "cwd": "/path/to/QBDI/tools/tenet",
      "env": {
        "TENET_BIN": "/path/to/tenet/build/tenet"
      }
    }
  }
}
```

### 3. 使用

配置完成后，AI 对话中直接自然语言指示即可：

> "打开 /tmp/trace.bin，帮我看看有哪些加密算法"
>
> "从 x0 在 #1000 开始做前向 taint，看数据流到哪里"
>
> "搜索 PC 0x100abc000 执行了几次"

## 工具列表 (36 个)

### 核心分析 (22 个，原有)

| 工具 | 说明 |
|------|------|
| `trace_open` | 加载 .bin trace 文件，返回元数据 |
| `trace_info` | 获取已加载 trace 的信息 |
| `disasm` | 反汇编指定范围的指令 |
| `taint_forward` | 基于 Triton 的精确前向污点分析 |
| `taint_backward` | 反向数据流追踪（value 从哪来） |
| `critical_path` | 前向+反向 taint 交集，提取关键路径 |
| `cfg_export` | 导出控制流图 (DOT/JSON) |
| `call_graph` | 构建调用图 |
| `dataflow_graph` | 数据流图（指令范围内的依赖关系） |
| `pattern_scan` | 扫描加密/反调试/混淆模式 |
| `strings_scan` | 提取 trace 中的字符串 |
| `constants_scan` | 提取 movz+movk 常量，识别加密常数 |
| `loop_semantics` | 循环语义分析（Feistel/SPN/ARX 检测） |
| `algorithm_summary` | 综合算法识别报告 |
| `symbol_annotation` | 统一符号注解层 |
| `regstate` | 查询某条指令处的寄存器状态 |
| `memread` | 时间感知的内存读取 |
| `mem_write_history` | 查某地址的所有写入历史 |
| `memory_snapshot` | 批量内存快照 |
| `search_pc` | 搜索某 PC 在 trace 中出现的所有位置 |
| `trace_diff` | 两段 trace 范围的差分比较 |
| `objc_messages` | ObjC 消息分析 |

### 新增分析 (6 个)

| 工具 | 说明 |
|------|------|
| `verify_evidence` | 验证 AI 引用的数据确实存在于 trace 中（反幻觉） |
| `trace_fold` | 循环折叠/压缩视图（快速理解重复结构） |
| `reg_timeline` | 寄存器值时间线（追踪值随时间变化） |
| `call_context` | 函数上下文 + 调用栈查询 |
| `batch_query` | 批量查询（减少 MCP 往返延迟） |
| `mem_pattern_search` | 内存字节模式搜索（定位密钥/IV/密文） |

### Hypothesis Ledger (8 个，反幻觉框架)

| 工具 | 说明 |
|------|------|
| `hypothesis_add` | 提出新假设（必须在下结论前使用） |
| `hypothesis_activate` | 激活假设（开始收集证据） |
| `hypothesis_evidence` | 添加证据（支持或反对） |
| `hypothesis_conclude` | 结论确认（需已验证证据） |
| `hypothesis_abandon` | 放弃假设（证据否定） |
| `hypothesis_list` | 列出所有假设及状态 |
| `hypothesis_get` | 获取假设详情含所有证据 |
| `hypothesis_mark_reviewed` | 标记假设已审核 |

## 反幻觉机制

### Hypothesis Ledger

强制 AI 走科学方法流程：

1. `hypothesis_add` — 提出假设
2. 使用分析 tools 搜索证据
3. `verify_evidence` — 验证引用的数据确实存在
4. `hypothesis_evidence(verified=true)` — 记录已验证证据
5. `hypothesis_conclude` — 有足够证据时下结论

**关键约束**：
- 没有 verified evidence 就不能 conclude
- 冲突的假设不能同时 conclude
- 所有证据引用必须在 trace 中可验证

### Discipline Injection

防止 AI 在长对话中"遗忘"分析规则：
- 每 5 次 tool call 注入短提醒
- 每 20 次 tool call 注入完整规则块
- hypothesis_* 类工具自带纪律性，不重复注入

## 模块结构

```
mcp/
├── __init__.py          # 包标识
├── __main__.py          # 入口 (python -m mcp)
├── server.py            # MCP server 主逻辑
├── config.py            # 配置常量
├── session.py           # Session 状态 + tenet CLI 调用
├── transport.py         # JSON-RPC stdio 传输
├── parsers.py           # CLI 输出解析器
├── tools/
│   ├── __init__.py      # tool registry (自动收集)
│   ├── trace.py         # trace_open, trace_info, disasm
│   ├── taint.py         # taint_forward, taint_backward, critical_path
│   ├── graph.py         # cfg_export, call_graph, dataflow_graph
│   ├── memory.py        # regstate, memread, mem_write_history, memory_snapshot
│   ├── analysis.py      # pattern/strings/constants/loop/algorithm/symbol
│   ├── search.py        # search_pc, trace_diff, objc_messages
│   ├── evidence.py      # verify_evidence
│   ├── fold.py          # trace_fold, reg_timeline
│   ├── context.py       # call_context
│   ├── batch.py         # batch_query
│   └── mem_search.py    # mem_pattern_search
├── hypothesis/
│   ├── __init__.py
│   ├── ledger.py        # HypothesisLedger 核心状态机
│   └── tools.py         # hypothesis_* MCP tools
└── discipline/
    ├── __init__.py
    └── injector.py      # DisciplineInjector
```

## 协议细节

- **MCP 版本**: 2024-11-05
- **传输**: JSON-RPC 2.0 over stdio (newline-delimited)
- **依赖**: Python 3.9+ 标准库（零外部依赖）
- **超时**: 普通查询 120s，taint/CFG 300s，critical_path/算法 600s

## 与 algokiller-plugin 协作

本 MCP server 设计为可被 algokiller-plugin 驱动：

```
algokiller-plugin (驱动层: skill方法论 + sub-agent协调)
        │ MCP protocol
        ▼
tenet MCP server (能力层: 36 tools + hypothesis + discipline)
        │ subprocess
        ▼
tenet CLI (计算层: 22 passes, Triton, RocksDB)
```

algokiller-plugin 负责"思考"（分析策略、假设推理），tenet 负责"计算"（精确数据流分析、符号执行）。

## 手动测试

```bash
cd tools/tenet
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
  python -m mcp --tenet-bin ./build/tenet
```

期望返回：
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"tenet-trace-analyzer","version":"0.2.0"}}}
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TENET_BIN` | tenet 二进制路径 | `tenet` (从 PATH 查找) |

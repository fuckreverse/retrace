---
title: 分析 Trace
sidebar:
  order: 1
---

Tenet 在四种入口背后暴露相同的核心、Pass 与结果缓存。本页面向你呈现完整分析能力全貌，按问题类型引导你选择起始章节，并列出推荐的调查顺序。

## 分析能力地图

| 区域 | 能做什么 | 主要工具 |
|---|---|---|
| 结构恢复 | 恢复函数、CFG、XRef、循环、调用图 | `function`、`xref`、`cfg`、`loop`、`call_graph`、`cfg_layout` |
| 污点与数据流 | 前向/反向污点、关键路径、数据流图 | `taint`、`backward_taint`、`taint_source_annotation`、`dataflow_graph` |
| 内存与字符串 | 快照、值搜索、熵、YARA、字符串发现 | `memory_snapshot`、`memory_strings`、`mem_search`、`entropy`、`yara_mem_scan`、`strings` |
| 算法与模式 | 模式扫描、物化常量、循环语义、算法摘要 | `pattern`、`loop_semantics`、`algorithm_summary` |
| 平台 API | ObjC 消息、系统调用、C API 拦截（CommonCrypto / BoringSSL / JNI） | `objc`、`syscall_intercept`、`objc_crypto` |
| Trace 对比 | 折叠重复迭代、差异比较、窗口统计、寄存器时间线 | `trace_fold`、`trace_diff`、`window_stats`、`reg_timeline`、`call_context` |
| VM 分析 | handler 识别、派发恢复、状态映射、反向切片 | `vm_abstract` + MCP `vm_summary` / `vm_steps_query` / `vm_reg_timeline` / `vm_backward_slice` |

所有 MCP 工具详见 [MCP 服务指南](/zh-CN/docs/automate/mcp/#tool-catalog)；所有 Pass 及其 CLI 标志详见 [Pass 目录](/zh-CN/docs/reference/pass-catalog/)。

## 按问题选择

从匹配你问题的章节开始：

| 我想要… | 从这里开始 |
|---|---|
| 识别感兴趣的函数 / 理解整体流程 | [恢复程序结构](./structure/) |
| 把关键值反向追蹤到源头，或正向追蹤到去向 | [污点与数据流](./taint/) |
| 在内存中查找字符串、结构体或加密材料 | [内存、字符串与值搜索](./memory/) |
| 确定一组循环实现的是哪类算法 | [算法与模式识别](./algorithms/) |
| 检查 ObjC 消息、系统调用或边界 API 的输入输出 | [ObjC、系统调用与平台 API](./platform/) |
| 比较两份录制或总结热点循环 | [Trace 工具](./trace-tools/) |
| 分析 VMP 风格虚拟化代码 | [虚拟机分析](./vmp/) |

## 推荐调查顺序

Trace 是指令的扁平流；分析在其上逐层构建视图。建议从廉价、全局走向昂贵、精确：

```
1.  trace_info / 结构          → 函数、CFG、XRef、循环
2.  污点 / 数据流               → 前向污点、反向污点、关键路径
3.  内存 / 字符串               → 快照、值搜索、熵、YARA
4.  算法 / 模式                 → 模式扫描、常量、loop_semantics、algorithm_summary
5.  平台 API                    → objc、syscall_intercept、objc_crypto
6.  Trace 对比                 → trace_fold、trace_diff、window_stats、reg_timeline
7.  VM 分析                    → vm_abstract（需 IDA/Ghidra 提供静态 hints）
```

这是推荐顺序而非强制约束。每一步都独立，可以任意顺序重跑，但结果会相互叠加：例如 `algorithm_summary` 会交叉引用 `pattern` 和 `loop_semantics`，所以应在两者之后运行。

## 证据层级

Tenet 各分析在不同置信度上产出结果。下结论时应区别对待：

| 层级 | 声明类型 | 典型来源 |
|---|---|---|
| 记录事实 | 在 Trace 中直接观察到 | GPR/FPR 快照、内存访问、已执行指令、PC |
| 重建状态 | 通过重放记录的写入推导 | 任意 `inst_id` 处的 `RegisterFile`、`MemoryModel` 写入历史、`get_regs`、`memread` |
| 结构推断 | 从执行结构推断 | 函数、CFG、循环、XRef、VM handler 切分、调用图 |
| 候选解释 | 多信号启发式综合 | `algorithm_summary`、`loop_semantics` 标签、`pattern` 签名 |

不要把候选解释当作记录事实。使用 `verify_evidence`（MCP）或重新检查相关 `inst_id` / 寄存器时间线，把假设升级为经过验证的证据。

## 入口选择

| 入口 | 启动方式 | 适用场景 |
|---|---|---|
| GUI | `./tenet trace.bin` | 探索性浏览、VM Workspace、拖入 hints JSON |
| TUI | `./tenet --tui trace.bin` | 纯终端环境、快速键盘驱动检查 |
| CLI | `./tenet --taint 0 trace.bin`（或 `--pattern`、`--call-graph`、`--export-cfg` 等） | 脚本或 CI 一次性批处理分析 |
| MCP | `./tenet trace.bin --mcp` 或 `--mcp-hub` | Agent 驱动、IDE 集成或多 Trace 工作流 |

四种入口共享同一个 reader、索引、Pass 管线和结果缓存——无论走哪条入口，分析结果完全一致。

## 最小快速流程

```bash
# 1. 确认 Trace 可读
tenet --dump text trace.bin --limit 100

# 2. 交互式打开，等待默认 Pass 完成
./tenet trace.bin                         # 或：./tenet --tui trace.bin

# 3. 一次性 CLI 分析
./tenet --pattern trace.bin
./tenet --algorithm-summary trace.bin
./tenet --call-graph cg.dot trace.bin
./tenet --export-cfg func.dot trace.bin

# 4. 从 x0 开始目标污点
./tenet --taint 0 trace.bin
# 或在 inst_id 1200 处反向污点寄存器 x4（寄存器索引 4）：
./tenet --backward-taint 1200 4 trace.bin
```

`tenet --dump` 支持 v4/v5/v7（含分块压缩），无需单独构建。

## 前置检查

### 录制质量检查

| 检查项 | 为什么重要 | 关注什么 |
|---|---|---|
| 格式版本 | Tenet 要求 `version >= 4` | `trace_info` 显示版本；旧版本会被拒绝 |
| 代码嵌入 | 需要反汇编的分析在没有代码嵌入时会退化 | 检查 Header 标志 `HAS_CODE`；缺少已录制代码时，指令语义分析可能不可用或精度下降 |
| GPR / MEM diff | 缺失寄存器或内存 diff 会降低状态恢复精度 | 采样录制可能省略 `REG_DIFF`、`HAS_MEM` 或 `HAS_NZCV`；应把结果视为有意稀疏的证据 |
| 分块压缩 | 默认录制使用 1 MiB zstd 分块 | `tenet --dump` 及所有 tenet 分析模式均支持压缩 Trace（v4/v5/v7） |
| 地址一致性 | Trace 记录包含 ASLR slide 的运行时地址 | 各 CLI 命令的地址约定不同；MCP 的 PC 参数通过 `image_base` 与 `module_slide` 重基，而 VM `mem_anchor_addr` 等内存地址字段仍使用运行时地址 |

### 可选依赖

| 功能 | 依赖 | 启用条件 |
|---|---|---|
| Triton 驱动的精确污点语义 | Triton | 构建时 `TENET_ENABLE_TRITON=ON`；否则污点工具使用启发式回退 |
| YARA 内存扫描（`yara_mem_scan`） | libyara | 构建时 `TENET_ENABLE_YARA=ON` |
| GUI（交互式视口） | SDL3 + Metal | `TENET_ENABLE_GUI=ON`，macOS 默认启用 |
| Trace 压缩（现代默认） | zstd | qbditrace 中 `QBDITRACE_ENABLE_ZSTD=ON` |
| 并行索引 / 任务调度 | Intel oneTBB | `TENET_ENABLE_TBB=ON`，默认启用 |

没有 Triton 或 YARA 的构建仍支持结构分析及大多数其他能力，但明确依赖这些库的工具会不可用，或按当前构建能力降级。

## 下一步

以下章节各自深入一个分析区域，包含概念、入口与排查：

| 章节 | 交叉链接 |
|---|---|
| [恢复程序结构](./structure/) | `function`、`xref`、`cfg`、`loop`、`call_graph` |
| [污点与数据流](./taint/) | `taint`、`backward_taint`、`taint_source_annotation`、`dataflow_graph` |
| [内存、字符串与值搜索](./memory/) | `mem_search`、`memory_strings`、`memory_snapshot`、`entropy`、`yara_mem_scan` |
| [算法与模式识别](./algorithms/) | `pattern`、`loop_semantics`、`algorithm_summary` |
| [ObjC、系统调用与平台 API](./platform/) | `objc`、`syscall_intercept`、`objc_crypto` |
| [Trace 工具](./trace-tools/) | `trace_fold`、`trace_diff`、`window_stats`、`reg_timeline` |
| [虚拟机分析](./vmp/) | `vm_abstract` + MCP VM 工具 |

完整 Pass 列表含 CLI 标志与依赖图见 [Pass 目录](/zh-CN/docs/reference/pass-catalog/)。所有 MCP 工具见 [MCP 服务指南](/zh-CN/docs/automate/mcp/)。

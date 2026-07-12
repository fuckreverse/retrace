---
title: Pass 目录
sidebar:
  order: 1
---

Tenet 中的每项分析都是一个 Pass。本页列出目录中全部 Pass，按类别分组。默认开启的 Pass 在 GUI 或 TUI 打开 Trace 时自动运行；其余按需启动。

## Structure

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `function` | `--run-pass function` | 是 | 发现 call/return 对，构建函数列表 |
| `xref` | `--run-pass xref` | 是 | PC→inst_ids 交叉引用索引 |
| `cfg` | `--run-pass cfg` | 是 | 控制流图（基本块 + 边） |
| `cfg_layout` | `--run-pass cfg_layout` | 否 | CFG 视图的图布局坐标 |
| `call_graph` | `--run-pass call_graph` | 是 | 函数间调用图 |
| `loop` | `--run-pass loop` | 是 | 通过 CFG 回边检测循环 |
| `vm_abstract` | `--vm-abstract` | 否 | VM 派发器检测与 handler 提取 |

## Taint

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `taint` | `--taint` | 否 | 从当前寄存器做前向污点 |
| `backward_taint` | `--backward-taint` | 否 | 从当前指令做反向污点 |
| `taint_source_annotation` | `--taint-source-annotation` | 否 | 标注反向污点端点（ObjC/内存/常量） |

## Crypto / Pattern

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `pattern` | `--pattern` | 是 | 密码学/反调试模式 + 物化常量（`constant_materialization` 已合并至 pattern） |
| `loop_semantics` | `--loop-semantics` | 是 | 分类循环（Feistel/SPN/ARX/memcpy…） |
| `algorithm_summary` | `--algorithm-summary` | 是 | 交叉引用常量+模式→算法标识 |
| `objc_crypto` | `--objc-crypto` | 否 | 关联密码学模式与 ObjC 调用栈 |

## Memory / String

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `strings` | `--strings` | 是 | Trace 中的字符串访问 |
| `memory_strings` | `--memory-strings` | 否 | 通过内存重建的时间感知字符串发现 |
| `memory_snapshot` | `--memory-snapshot` | 否 | 在调用点/inst_id 处捕获内存快照 |
| `mem_search` | `--run-pass mem_search` | 否 | 多模式+精确值/立即数搜索（`literal_search` 已弃用别名） |
| `entropy` | `--entropy` | 否 | 内存区域的 Shannon 熵 |
| `yara_mem_scan` | `--yara-mem-scan` | 否 | 对堆/栈内存运行 YARA |

## Platform API

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `objc` | `--objc` | 否 | Objective-C 消息发送分析 |
| `syscall_intercept` | `--syscall-intercept` | 否 | 拦截密码学/系统 API 调用（平台感知） |

## Profile / Trace

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `trace_fold` | `--trace-fold` | 否 | 将重复循环迭代折叠为摘要 |
| `reg_timeline` | `--reg-timeline` | 否 | 寄存器全部写入时间线 |
| `call_context` | `--call-context` | 否 | 指令处的调用栈+循环位置+邻居 |
| `window_stats` | `--window-stats` | 否 | 滑动窗口统计（热区、熵…） |
| `trace_diff` | `--diff-trace` | 否 | 比较两个 Trace 区域的差异 |
| `dataflow_graph` | `--dataflow-graph` | 否 | 区域的寄存器级数据流图 |

## Misc

| Pass | CLI 标志 | 默认 | 摘要 |
|---|---|---|---|
| `thread` | `--run-pass thread` | 是 | 线程时间线/切换 |
| `thread_filter` | `--run-pass thread_filter` | 否 | 每线程指令位图用于过滤 |

## 依赖图

```text
function ──> call_graph
xref ──> cfg ──> cfg_layout
              └──> loop ──> loop_semantics
                           └──> algorithm_summary
pattern ──> algorithm_summary
            └──> objc_crypto
objc ──> objc_crypto
backward_taint ──> taint_source_annotation
cfg ──> vm_abstract
loop ──> vm_abstract
```

未列在依赖图中的 Pass 无前置条件，可独立运行。

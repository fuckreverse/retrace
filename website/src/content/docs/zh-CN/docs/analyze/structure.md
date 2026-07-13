---
title: 恢复程序结构
sidebar:
  order: 2
---

结构恢复把执行时间轴组织为代码位置、函数、基本块、边、调用和循环。它通常是分析第一步，因为后续 Pass 会复用这些结果。

## 能力链与依赖

```text
xref ──> cfg ──> cfg_layout
            └──> loop
function ──> call_graph
```

| Pass | 依赖 | 回答的问题 | 主要结果 |
|---|---|---|---|
| `function` | 无 | 观察到了哪些 call/return 和函数调用？ | 调用事件、动态调用栈、函数表 |
| `xref` | 无 | 某 PC 在哪里执行、执行几次？ | PC→`inst_id` 出现位置与计数 |
| `cfg` | `xref` | 已执行基本块如何连接？ | 块、边、执行热度、终结指令 |
| `cfg_layout` | `cfg` | CFG 节点如何布局？ | 可视化坐标、annotated DOT |
| `call_graph` | `function` | 已观察函数互相调用？ | caller→callee 边、调用点、次数 |
| `loop` | `cfg` | 哪些 CFG 回边构成循环？ | header、body、迭代数与嵌套 |

依赖图由 PassManager 自动解析：请求 `--export-cfg` 会自动注册 `xref`、`cfg`、`cfg_layout`；请求 `--call-graph` 自动注册 `function` 和 `call_graph`。

## 动态函数与 call/return 语义

`function` 通过配对 BL/BLR (call) 与 RET 来识别函数边界，使用模拟调用栈。这是**动态**重建：

- 只有当本次运行观察到对其入口 PC 的调用时，函数才会出现。
- 间接调用 (BLR) 和运行时派发会解析到实际观察目标 PC。
- 尾调用（重用调用者栈帧的无条件 B/BR）通过 SP 跟踪检测，标记为 `is_tail_call`。
- 每个 `CallEvent` 记录 `call_inst_id`、`target_pc`、`return_inst_id`（未返回时为 0）以及调用栈深度。
- 函数名来自二进制符号表；无名条目显示为 `sub_<hex>`。

默认情况下内存使用有上限（call events 上限 2000 万，单个函数的 indices 上限 1000）。仅在小 trace 需要完整逐调用导航时使用 `FunctionConfig::full_mode`。

## XRef

`xref` 在所有已执行指令上建立 PC→inst_id 索引。它驱动：

- CFG 面板中的执行计数热力图。
- 同一块或 PC 各次出现的 首/上/下/末 导航。
- 前向污点加速（默认启用；用 `--taint-no-xref` 禁用）。

## CFG 与全量 `--export-cfg`

`cfg` 从已执行基本块构建控制流图。`--export-cfg` 将当前 Trace 恢复出的全量 CFG 导出为一个 Graphviz DOT 文件，而不是只导出某个函数：

```bash
./tenet [options] trace.bin --export-cfg all.dot
```

输出是 `cfg_layout` 的 annotated DOT（`CFGLayoutResult::dot_annotated`）。用 `dot -Tsvg all.dot -o all.svg` 或任意 Graphviz 渲染器打开。块颜色反映执行热度；边显示观察到的控制流。

:::note[块数阈值]
仅当 CFG 块数 ≤ 500 时，完整反汇编才会嵌入每个节点。更大图的输出会包含占位文本；请使用 GUI 或 MCP `cfg_export`（JSON 格式）按需浏览单个块。
:::

## Layout

`cfg_layout` 使用层级网格算法（类似 Ghidra decompiler 布局）为 CFG 节点计算可视化坐标。`--export-cfg` 会自动注册它；其他布局视图按需请求时再运行。独立 CLI 使用较少；大多数用户通过 GUI 或生成的 DOT 消费布局。

## Loops

`loop` 通过 CFG 上的 dominator tree 分析检测自然循环（LLVM 风格 Semi-NCA 算法）。每个循环报告：

- `header_pc` 和 `back_edge_pc`
- `iteration_count`（回边被执行的次数）
- `nesting_depth`（0 = 最外层）
- `body_pcs`（循环体内所有 PC）

循环结果为 Loop Semantics、Trace Fold 和热点分析提供输入。

## Call graph

`call_graph` 将 `function` 结果聚合为过程间调用图。`--call-graph` 导出为 Graphviz DOT：

```bash
./tenet [options] trace.bin --call-graph cg.dot
```

每个节点是一个函数（按入口 PC）；边携带调用次数和调用点 PC。

## 推荐工作流

1. 在 GUI/TUI 中打开 trace——结构相关的 `function`、`xref`、`cfg`、`call_graph`、`loop` 属于默认启动集合。
2. 浏览 Functions 面板定位目标函数。
3. 使用 Call Stack 面板跟随 call/return 导航。
4. 打开 CFG 面板检查热块和边缘；使用 上/下 访问 在多次执行间步进。
5. 在 Loops 面板查看迭代次数和嵌套。
6. 如需持久产物，使用 CLI `--export-cfg` 或 `--call-graph`。

## 交互入口

- **Functions 面板** (`show_functions_`)：按调用次数、指令数或名称排序/过滤。右键函数可跳转到其入口、运行 Xref，或查看 caller/callee。
- **Call Stack 面板** (`show_callstack_`)：列出当前指令处的栈帧。右键帧可跳转到调用点或函数入口。
- **CFG 面板** (`show_cfg_`)：渲染 CFG 布局。点击块选中；使用 首/上/下/末 在多次访问间导航（由 Xref 驱动）。右键块可跳转到特定执行。
- **Call Graph 面板** (`show_call_graph_`)：热 callee 排名和完整边列表。点击节点跳转到其入口。
- **XRef 导航**：在 Call Stack 面板中，PC xref 控制（Prev/Next）在当前 PC 的每次出现间步进。在 GUI 中，按 `X` 在未运行 Xref 时启动它，然后在各次访问间循环。
- **TUI**：`:pass function`、`:pass xref`、`:pass cfg`、`:pass loop`、`:pass call_graph` 运行单个 Pass。`:analyze` 运行默认集。

## MCP 调用顺序

1. `functions`——列出已观察函数（入口 PC、名称、调用次数、指令数）。
2. `find_function`——按 PC 定位函数。
3. `xref`——查询 PC→inst_id 出现。
4. `cfg_export`——以 DOT 或 JSON 格式导出 CFG（自动运行 `xref`、`cfg`、`cfg_layout`）。
5. `call_graph`——以 DOT 或 JSON 格式导出调用图（自动运行 `function`、`call_graph`）。
6. `loops`——查询检测到的循环（header、body、迭代数、嵌套）。

MCP 工具返回的 PC 使用当前 `image_base`（默认 `0x100000000`，与 AArch64 Mach-O 的 IDA 地址一致）。如果静态工具使用不同 base，用 `set_image_base` 调整。

## 结果解释

- **动态覆盖**：仅当本次运行执行过相应证据时，边、函数或循环才会出现。未执行错误路径、其他 switch 分支和 callback 不会出现。
- **间接调用**：解析到观察目标；如果函数指针在运行期间有多个 callee，每条边单独出现。
- **执行次数**：只描述这次输入与运行，不代表一般概率。
- **函数边界**：来自观察到的 call/return 对，不是二进制元数据。即使没有被观察到的调用者，只要函数是 trace 起点仍会出现。

## Sampling、branch hint 与缺码边界

- **Branch hint** (`HF_BRANCH_HINT`)：Trace 中存在时，tracer 在录制时将 call/ret/branch 类别编码到 NZCV 高 4 位。`function` 使用这条 O(1) 路径即时分类 ~95% 的指令。没有 branch hint 时，回退到对 code table 的二进制搜索表（仍正确，略慢）。
- **Sampling**：如果 trace 使用指令采样，某些 call/return 对可能丢失，导致不完整的调用栈或幽灵尾调用。`FunctionResult::non_local_unwinds_` 统计检测到的异常数。
- **缺码**（`REC_CODE` 禁用）：没有嵌入 opcode 时 code table 为空，`function` 无法分类 branch-class PC。call/return 配对会降级或失败。请用启用 code embedding 重新录制，或提供外部镜像用于反汇编。

## 排查

### 调用栈显示异常深度或非局部展开

Trace 可能缺失 RET 事件（采样、插桩间隙）或存在非标准控制流（longjmp、异常展开）。检查 `FunctionResult::non_local_unwinds_` 获取检测到的异常计数。

### 预期的函数不存在

该函数在追踪执行期间未被调用，或其调用使用了间接分支且目标未被观察。确认 trace 范围覆盖该代码路径，并在 Xref 中检查预期入口 PC。

### `--export-cfg` 输出为空或过于简单

确认 trace 包含足够多的已形成基本块的执行指令。非常短的 trace 或重度采样的 trace 可能只产生单块图。同时确认 `REC_CODE` 或外部镜像可用，以便解析块边界。

### 循环迭代次数看起来不对

循环检测依赖 CFG 准确性。如果采样遗漏了回边，迭代数会被少算。使用未采样的 trace 录制以获得准确循环指标。

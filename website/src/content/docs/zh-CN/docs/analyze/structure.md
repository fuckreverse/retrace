---
title: 恢复程序结构
sidebar:
  order: 2
---

结构恢复把执行时间轴组织为代码位置、函数、基本块、边、调用和循环。它通常是分析第一步，因为后续 Pass 会复用这些结果。

## 能力链

```text
xref ──> cfg ──> cfg_layout
            └──> loop
function ──> call_graph
```

| Pass | 回答的问题 | 主要结果 |
|---|---|---|
| `function` | 观察到了哪些 call/return 和函数调用？ | 函数、调用事件、动态调用栈 |
| `xref` | 某 PC 在哪里执行、执行几次？ | PC→`inst_id` 出现位置与计数 |
| `cfg` | 已执行基本块如何连接？ | 块、边、执行热度、终结指令 |
| `cfg_layout` | CFG 节点如何布局？ | 可视化坐标 / DOT 布局 |
| `call_graph` | 哪些已观察函数互相调用？ | caller→callee 边、调用点、次数 |
| `loop` | 哪些 CFG 回边构成循环？ | header、body、迭代与嵌套 |

## CLI

```bash
./tenet trace.bin --export-cfg function.dot
./tenet trace.bin --call-graph callgraph.dot
./tenet trace.bin --symbol-annotation
./tenet trace.bin --run-pass function --run-pass xref --run-pass loop
```

`--symbol-annotation` 聚合已有 function、loop 和 pattern 证据，不是独立 Pass。

## 交互使用

- **Functions：** 过滤/排序已观察函数，检查调用次数和 caller/callee。
- **Call Stack：** 选择栈帧，跳转调用点/入口，跟随 call 与 return。
- **CFG：** 选择函数，检查热块/热边，点击节点导航。
- **XRef：** 在同一 PC 的每次出现之间移动。
- **Loops：** 为 Loop Semantics、Trace Fold 和热点分析提供输入。

MCP 对应工具包括 `functions`、`find_function`、`xref`、`cfg_export`、`call_graph` 和 `loops`。

## 解释边界

这是**动态**结构：

- 仅当本次运行执行过相应证据时，边或函数才会出现。
- 间接调用和运行时派发会解析到实际观察目标。
- 未执行错误路径、其他 switch 分支和 callback 不会出现。
- 函数边界依赖分支/代码证据；sampling 或缺码会降低精度。
- 执行次数只描述这次输入与运行，不代表一般概率。

用结构恢复选择精确 source 或 sink，然后继续[污点与数据流](./taint/)。

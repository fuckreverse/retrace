---
title: 虚拟机与代码虚拟化
sidebar:
  order: 8
---

VMP 风格保护将原生代码替换为自定义字节码解释器。Tenet 的 VM 分析框架从已观察执行中恢复 handler 结构、数据流、派发模式和提升语义——无需原始编译器或字节码规范。

## VM 分析分类体系

| 类别 | 分析目标 | 相关 Pass |
|---|---|---|
| Handler 识别 | 定位派发器和 handler 边界 | `xref`、`cfg`、`loop`、`vm_abstract` |
| 派发模式 | 分类直接/间接/线程化派发 | `vm_abstract`、`cfg` |
| Handler 语义 | 将操作提升为类原生 IR | `vm_abstract`、`backward_taint`、`dataflow_graph` |
| 状态映射 | 将虚拟寄存器映射到物理位置 | `backward_taint`、`taint_source_annotation` |
| 控制流 | 重建虚拟分支和循环 | `cfg`、`loop`、`loop_semantics` |

## vm_abstract

`vm_abstract` 是主要入口。它：

1. 使用循环分析和 CFG 结构定位派发循环。
2. 从派发目标识别 handler 入口点。
3. 分类派发模式（直接、间接、线程化）。
4. 提取每个 handler 的指令数和边频率。

```bash
./tenet trace.bin --vm-abstract
```

## 辅助 Pass

将 `vm_abstract` 结果与其他 Pass 结合以深入分析：

- **`backward_taint`** 对虚拟寄存器或栈 slot 揭示物理映射与 producer 链。
- **`dataflow_graph`** 在 handler 内展示寄存器/内存变换。
- **`loop_semantics`** 分类派发循环本身（常为 ARX 或 Counter Loop）。
- **`cfg`** 与 **`function`** 定位包含解释器及其边界。
- **`pattern`** 可识别 handler 内的反调试或混淆技术。

## VM Workspace（GUI）

Desktop GUI 包含 VM Workspace 窗口，展示 handler 摘要、派发可视化、handler→指令映射和污点结果集成。推荐在多步 VM 分析中使用此界面。

## 限制

- VM 分析依赖派发器在 Trace 中执行。无循环的内联或扁平化派发可能需要手工 handler 识别。
- Handler 提升有界：含大量内存间接的复杂 handler 可能无法完全解析。
- 分析只观察一次执行；未执行的 handler 和派发目标不会被报告。
- 状态映射精度依赖已记录的 GPR diff 和内存访问。Sampling 或缺失证据会降低准确性。
- `vm_abstract` 不做去虚拟化或重编译；它生成供下游工具使用的结构分析。

---
title: 污点与数据流
sidebar:
  order: 3
---

污点分析连接执行时间轴上的值。前向污点回答 source 流向哪里，反向污点回答哪些值对 sink 有贡献。

## 前向污点

选择 source 寄存器和一次指令执行，可附加内存 source，然后向后续消费者传播：

```bash
./tenet trace.bin --taint 0 --taint-inst 12000
./tenet trace.bin --taint 0 --taint-mem 0x16fdff200 \
  --taint-stop-pc 0x100123456 --taint-max-width 16
```

常用控制：

- `--taint-stop-pc` 在已知 sink 处限制调查。
- `--taint-max-width` 阻止无控制扩散。
- `--taint-no-calls` 禁止跨函数调用传播。
- `--taint-no-xref` 关闭 XRef 加速以便诊断。

GUI/TUI 会高亮污点指令，`[` 与 `]` 遍历传播事件；MCP 使用 `taint_forward`。

## 反向污点

从 sink 指令与寄存器开始：

```bash
./tenet trace.bin --backward-taint 58000 0
./tenet trace.bin --backward-taint 58000 0 \
  --backward-taint-max-steps 5000 \
  --backward-taint-graph graph.json
```

Pass 会跟踪最近寄存器 writer 与重叠内存写。GUI 的 **Producer Chain** 只是 `backward_taint` 的受限预览，不是独立分析。MCP 使用 `taint_backward`。

## 关键路径与数据流图

`--critical-path` 取前向可达与反向贡献的交集，把宽泛传播缩小为连接 source/sink 的证据。`dataflow_graph` 在明确指令范围内构建寄存器/内存 producer-consumer 图：

```bash
./tenet trace.bin --dataflow-graph 20000 24000 \
  --dataflow-graph-output dfg.dot
```

图上限为 5000 节点；更大区域需缩小范围。

## 来源标注

`taint_source_annotation` 为反向叶子补充 ObjC getter/参数/返回值、内存 load、常量或函数返回等上下文。它依赖 `backward_taint` 与 `objc`；Android/Linux Trace 无法获得 ObjC 标注。

```bash
./tenet trace.bin --backward-taint 58000 0 --taint-source-annotation
```

## 精度与证据

- 有效传播需要 GPR ANCHOR/diff 与内存访问。
- 内存匹配支持部分重叠和非对齐访问。
- NZCV、SP、PC 默认不作为普通值污点传播。
- Triton 可用时提供局部指令精确语义；无 Triton 构建降级到已支持的回退语义。
- 污点证明记录到的数据依赖，不等于语义意图或密码学相关性。
- 缺失/未插桩操作会中断链路；可结合 C API 记录、read 观察和来源标注解释缺口。

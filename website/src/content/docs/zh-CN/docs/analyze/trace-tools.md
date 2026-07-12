---
title: Trace 工具
sidebar:
  order: 7
---

Trace 工具对整个执行历史进行操作：比较、折叠、剖析和差异分析。它们不衍生关于单条 Trace 的新语义事实，而是帮助选择、比较和总结时间轴。

## Trace 折叠

`trace_fold` 将匹配函数或循环的 Trace 区域压缩为单个代表性块。结果是一条简化时间轴，保留全部未折叠执行，而对折叠区域仅显示一次入口/出口。

适用场景：

- 从时间轴中移除库模板代码，但保留入口/出口。
- 折叠已知循环以更清晰地看到周围上下文。
- 聚焦于特定函数范围，折叠范围外的一切。

```bash
./tenet trace.bin --trace-fold --fold-function 0x100123456
./tenet trace.bin --trace-fold --fold-loop
```

折叠可逆：原始时间轴被保留，可随时切换折叠/展开而无需重新处理。

## Trace 差异

`trace_diff` 逐条指令比较两条 Trace。提供第二条 Trace 以找出执行分歧点：

```bash
./tenet trace.bin --diff-trace other.bin --diff-output diff.json
```

差异包括 PC 不匹配、寄存器值差异和内存访问差异。结果为结构化 JSON 报告。

典型用途：

- 比较同一函数的两种输入。
- 验证补丁只改变了预期行为。
- 检测环境依赖的执行差异。

## 窗口统计

`window_stats` 计算每窗口的指令数、内存访问数和基本块覆盖率。用于剖析执行阶段活跃度：

```bash
./tenet trace.bin --window-stats --window-size 10000
```

## 剖析与热点

`profile` 计算每函数和每基本块的执行统计。它用定量数据补充结构恢复：

```bash
./tenet trace.bin --profile --profile-format json
./tenet trace.bin --profile --profile-format csv
```

热点分析识别最高频执行的函数和块。与 Trace 折叠结合使用，压缩不关心的热区域，暴露周围冷代码。

## 限制

- 折叠和差异以指令粒度工作。语义差异（如同 PC 但不同数据）会被报告但不解释。
- 窗口统计均匀采样；指令密度不均时可能需要更小窗口。
- 剖析数据仅反映已记录的执行，不是通用性能模型。
- 差异分析要求两条 Trace 的格式版本和模块配置兼容。

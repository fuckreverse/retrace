---
title: 核心概念
sidebar:
  order: 4
---

Tenet 将一次真实执行转化为可反复导航和查询的本地数据库。它解释的是**这次运行发生了什么**，不会枚举从未执行的路径。

## 指令时间轴

每条执行过的指令都有单调递增的 `inst_id`。同一个 PC 可以出现多次，而 `inst_id` 精确标识其中一次执行。讨论代码位置时使用 PC，讨论时间时使用指令 ID。

Trace 中地址均为运行时地址。与静态镜像对应时使用：

```text
static_address = runtime_address - module_slide
```

## 执行前与执行后状态

`state_before(N)` 表示第 N 条指令执行前的寄存器，`state_after(N)` 则应用该指令记录的差值。Tenet 通过周期性全量 ANCHOR 和逐指令 diff 重建状态；打开 Trace 时还会构建稠密内存 checkpoint，使随机查询只需回放很短的窗口。

## 时间感知内存

Tenet 不只展示最终内存快照。它按地址和指令 ID 索引写入，然后重建选定时刻的内存区域。指令 N 的写入在 N 执行后可见；记录到的 read 还能补全由未插桩代码准备的数据。

缺失字节保持未知（`??`），Tenet 不会猜测数据。

## 已执行结构

函数、XRef、CFG 边、调用和循环均来自实际执行。它能很好处理间接跳转、运行时派发和动态解密代码，但缺少某条边只表示“未观察到”，不表示“不可能”。

## 分析 Pass

每项分析都是声明依赖、结果可缓存的独立 Pass。独立的 Tauri 桌面应用通过 WebSocket 调用 Tenet 后端，与 TUI、CLI、RPC 和 MCP 使用同一套 Pass 实现；多个扫描型 Pass 可以共享一次 Trace 遍历。

## 能力取决于证据

| Trace 证据 | 可用能力 |
|---|---|
| PC 流 | 时间轴、计数、基础 XRef |
| 内嵌代码或外部镜像 | 反汇编、CFG、分支分类 |
| GPR diff 与 ANCHOR | 寄存器状态、污点和数据流 |
| 内存访问 | 时间感知内存、字符串、写历史 |
| Event 与 branch hint | 调用、返回、函数和循环 |
| SVC / ObjC / C API 记录 | 平台语义 |
| FPR diff（v7） | NEON/向量状态重建 |

精确降级规则见[兼容性与限制](/zh-CN/docs/reference/compatibility/)。

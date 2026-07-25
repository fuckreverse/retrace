---
title: 导航与断点
sidebar:
  order: 4
---

Tenet 导航的是已完成的执行历史。Continue、Step 和 Break 都是在已有时间轴中搜索，不会恢复目标进程执行。Tauri 桌面应用（Desktop）和 TUI 使用同一套后端状态语义，但交互入口并不完全相同。

## 直接导航

- **指令 ID：** 跳到一次精确执行。
- **运行时 PC：** 跳到执行过的代码位置。
- **函数：** 跳到已观察到的调用或入口。
- **搜索：** 定位指令文本、符号或已知字符串。
- **历史：** 在之前的导航决策间前进/后退。
- **书签：** 保存在 Trace 索引中，供之后的会话恢复调查地标。

## 重复执行与 XRef

`xref` Pass 将每个 PC 映射到全部对应的指令 ID。执行次数是观察频率，不是静态可达性估计。

- **TUI：** `x` / `X` 是直接的下一个/上一个 XRef 操作，可在循环迭代、重复调用或共享 handler 的各次执行间移动，并恢复每次出现时的精确状态。
- **Desktop：** Goto 对话框用 XRef 索引解析地址或函数，并跳到第一次匹配的执行；当前 Web 前端没有与 TUI 上一个/下一个 XRef 对等的直接控件或 XRef 结果列表。

## 调用与返回

Function Pass 负责配对 Trace 中观察到的 call 和 return，并重建动态调用栈。

- **TUI：** 提供直接的 **Follow Call** / **Follow Return** 快捷操作，分别跳到动态被调函数的首条指令和对应调用点。
- **Desktop：** Call Stack 面板中的栈帧可点击并跳到相应 call site；Functions 面板用于浏览已发现函数。当前 Web 前端不提供与 TUI 对等的 Follow Call/Return 快捷操作。

## 静态时间轴上的断点（TUI）

以下能力由 TUI 接入的静态时间轴 `BreakpointEngine` 提供；Desktop 当前的指令右键菜单不能设置断点或观察点。

| 类型 | 匹配来源 | 适用场景 |
|---|---|---|
| PC 断点 | XRef PC→指令 ID | 查找代码下一次/上一次执行 |
| 写观察点 | 内存写索引 | 定位 buffer 或字段何时变化 |
| 条件断点 | 扫描时计算 predicate | 在状态相关事件处停止 |

TUI 的正向/反向 continue 选择下一次/上一次命中。由于程序没有重新执行，反向继续不需要恢复 checkpoint 或 replay 目标。

## 按值导航

- **Register Timeline：** 后端 `reg_timeline` Pass 记录寄存器写入的指令位置以及写入前/后的值；TUI 的结果视图可显示这些 old/new 字段。Desktop 当前的 RegTimeline 面板以折线和样本表展示每个采样点的当前值，并可点击样本跳转，不显示逐项的新旧值对比。
- **Memory Write History：** 与地址区间重叠的全部写入。
- **Last Writer：** 对当前字节/区域有贡献的最近写入。
- **Backward Taint：** 从寄存器 sink 回溯传递性的 producer 链。
- **污点导航：** 分析后在传播事件之间移动；具体入口取决于所用前端。

## 运行时地址与静态地址

界面导航使用运行时地址。带到 IDA/Ghidra 时减去 `module_slide`，把静态地址带回 Tenet 时再加上。

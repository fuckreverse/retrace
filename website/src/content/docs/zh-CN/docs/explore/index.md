---
title: 浏览执行历史
sidebar:
  order: 1
---

交互浏览回答的问题不同于批处理分析：不仅是“检测到了什么”，更是“这个精确时刻的状态是什么”。独立的 Tauri 桌面应用（Desktop）与 TUI 使用相同的后端时间轴、状态模型和持久化格式；书签和最后光标保存在 Trace 旁的索引目录中，可由之后的另一前端会话恢复。同一 Trace 受独占会话锁保护，因此 Desktop 与 TUI 不能同时打开它并实时联动光标。

## 从时间轴开始

通过 `inst_id` 选择一次具体执行。Desktop 的主指令行显示运行时 PC 和反汇编，内存读写显示在独立的 **Mem Access** 面板；寄存器、Mem Access 与 Hex Dump 等面板随光标更新。TUI 同样以指令时间轴为中心，并在独立面板中检查寄存器和内存状态。两者展示的都是该次执行对应的 Trace 状态，而不是静态近似。

## 按证据移动

| 目标 | 导航动作 | 适用前端 |
|---|---|---|
| 重访位置 | Goto PC 或指令 ID | Desktop、TUI |
| 在同一 PC 的多次执行间移动 | 上一个/下一个 XRef | TUI 直接操作；Desktop Goto 仅跳到首次匹配 |
| 跟踪动态调用 | 调用栈；Follow Call、Follow Return | Desktop 可点击调用栈帧；直接 Follow 快捷操作为 TUI |
| 定位值变化 | Register Timeline 或内存写历史 | 后端分析；Desktop RegTimeline 显示采样值，TUI 结果可显示 old/new |
| 在事件处停下 | PC 断点、写观察点、条件断点 | TUI `BreakpointEngine` |
| 回顾调查过程 | 前进/后退历史与书签 | Desktop、TUI；跨会话恢复而非同时联动 |
| 遍历污点证据 | 上一条/下一条污点指令 | TUI 直接操作 |

## 检查状态

- **Registers：** 选中指令时的 GPR 状态；具体的前后值与读写高亮呈现取决于前端。
- **Memory / Mem Access：** 当前指令记录的读写访问；Desktop 在独立的 Mem Access 面板显示地址、大小和值。
- **Hex Dump：** 选定地址和时刻的已知/未知字节。
- **Call Stack：** 动态重建的栈帧；Desktop 可点击栈帧跳到 call site。
- **Functions 与 CFG：** 从真实执行控制流恢复的结构，通过各自面板浏览。

## 在上下文中触发分析

Desktop 的指令右键菜单当前只提供：导航到该指令、添加/移除书签、以固定的 `x0` 为源启动前向污点、在 Hex Dump 中打开 PC，以及复制地址或反汇编。反向污点、XRef、CFG、断点/观察点和 Memory Snapshot 不是该菜单的直接选项；需要通过 Analysis 面板等对应入口运行可用的 Pass。分析结果由后端缓存，可在后续会话中重访。

视觉多面板工作请看独立的 [Tauri Desktop](./desktop/)，终端环境请看 [TUI](./tui/)，精确移动方式及各前端边界见[导航与断点](./navigation/)。

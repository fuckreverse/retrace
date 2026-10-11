---
title: Desktop GUI
sidebar:
  order: 2
---

Tenet Desktop 是位于 `slowmo/web/` 的独立 Tauri 桌面应用，而不是 `tenet` 可执行文件中的原生 GUI。打开 trace 时，应用会拉起纯后端 `tenet` 作为 sidecar，实际参数包含 `--ws-port <port> <trace> --mcp-hub`。React 前端通过 WebSocket 使用 FlatBuffers 二进制协议访问后端；MCP Hub 则同时为外部工具提供实例协调能力。

Desktop 当前支持 macOS 和 Linux。Windows 版后端默认关闭 `TENET_ENABLE_WS`，因为所用 uSockets 事件循环尚未接入 IOCP；因此 Tauri Desktop 目前无法连接 Windows 版 `tenet` 后端。

## 主工作区

界面由 `SidebarLeft`、`CenterArea` 和 `SidebarRight` 三部分组成，底部另有共享时间线和状态栏。

| 区域 | 当前视图 | 内容 |
|---|---|---|
| 左侧栏 | Functions、Strings | 已发现函数的过滤与排序，以及字符串分析结果 |
| 中央上部 | Instructions、CFG、Strings、Reg Timeline、Dataflow | 指令时间线与搜索、控制流图、字符串、寄存器时间线和数据流图 |
| 中央下部 | Analysis、Call Stack 及分析结果标签页 | Pass 控制台、当前调用栈，以及 Patterns、Algorithms、Constants、Loops、API Intercepts、ObjC、Call Graph、污点、内存搜索、Entropy、YARA、Trace Fold/Diff、Snapshots、Threads / XThread Data（多线程）、DWARF、VM Workspace、Cache、Log 和 Settings 等视图 |
| 右侧栏 | Registers、Hex Dump、Mem Access | 当前指令执行前的 GPR/NZCV、可定位的十六进制内存视图，以及当前指令记录的内存读写 |

导航位置由前端 store 共享。选择指令、调用栈帧或带指令位置的分析结果时，相关面板会围绕同一个 `inst_id` 更新。工具栏、时间线和 Navigate 菜单还提供前进/后退、首尾跳转、Go to、搜索与书签。

## 导航流程

1. 在 **Instructions** 中选择指令，查看运行时 PC、反汇编和搜索结果。
2. 在 **Registers** 中比较当前值、写入和相邻指令间的变化。
3. 在 **Mem Access** 中检查已记录的读写，并将地址或寄存器值送到 **Hex Dump**。
4. 使用 **Call Stack**、**Functions**、**CFG** 和分析结果标签页补充行为上下文。
5. 为重要的 source、变换和 sink 添加书签；需要 XRef 前后跳转、Follow Call/Return、断点或观察点时，使用 TUI。

## Analysis 控制台

**Analysis** 是中央下部的一个标签页。它按 Structure、Taint、Crypto-Pattern、Memory-String、ObjC-Platform、Profile-Trace 和 Misc 分类展示后端 Pass 目录，并显示 Not Run、Running、Completed 或 Failed 状态。

运行中的 Pass 会显示阶段消息和百分比进度。未运行或已结束的 Pass 可通过播放/重跑按钮执行；已完成项显示重跑按钮。**Clear All** 会清除分析状态与结果。当前面板没有单任务取消操作，因此不要把进度显示理解为可取消任务。

需要参数或专门展示的能力位于对应标签页，例如 Memory Search、YARA、Entropy、Register Timeline、Dataflow、Backward Taint、Trace Fold、Trace Diff 和 VM Workspace。Patterns、Constants、Loops、Algorithms、ObjC、ObjC×Crypto、API Intercepts、Call Graph 等结果也在标签页面板中展示，而不是默认作为独立弹出窗口。当前只有菜单中的 **VM Workspace** 明确提供 “Open in New Window”。

多线程 trace 中，**Threads** 标签页列出每个线程的指令数与切换事件——选中线程后指令视图经 `thread_filter` pass 过滤。**XThread Data** 标签页展示跨线程数据流：写者线程与读者线程之间经共享内存的交接，按地址聚合为 channel 并附 producer→consumer 统计。

## 上下文操作

当前 **Instructions** 右键菜单只提供：

- Navigate Here
- Add Bookmark / Remove Bookmark
- Taint Forward (x0)
- Open PC in Hex Dump
- Copy Address
- Copy Disassembly

**Registers** 的右键菜单可将寄存器值送到 Hex Dump，或复制该值。XRef、反向污点和其他分析应从 **Analysis** 或相应结果标签页进入；XRef prev/next、Follow Call/Return、断点和写观察点等交互目前主要由 TUI 提供，不能假定 Desktop 的指令右键菜单也具备这些操作。

## 符号与缺码

**DWARF / Symbol Info** 标签页用于展示后端返回的文件、行号、函数和变量信息。

如果 trace 没有嵌入所需代码字节，后端 CLI 支持通过 `--image <path>` 加载匹配镜像，供反汇编和依赖代码的分析回填。`--image` 是启动 `tenet` 后端时的命令行参数；当前 Tauri 的打开 trace 流程只为 sidecar 传入 WebSocket、trace 和 MCP Hub 参数，没有在 Desktop 界面中提供选择镜像或用 `--image` 重新打开的交互。需要该能力时，请在 CLI 工作流中显式启动带 `--image` 的后端分析。

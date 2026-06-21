# UI 层

> 职责：用户交互与结果展示。UI 是**纯消费者**——所有数据来自 Core + Pass Pipeline，UI 只负责展示、导航、触发分析。
> 源码：`src/gui/`、`src/tui/`、`src/main.cpp`（CLI）、`mcp/`（MCP）。

## 设计原则

1. **UI 不持有逻辑**：分析全走 `PassManager::require()`，UI 只取结果引用渲染。
2. **三前端对等**：GUI / TUI / CLI 共享同一套 IO+Core+Analysis，功能对等（差异在交互粒度）。
3. **异步分析**：长耗时操作（污点/CFG）后台线程执行，UI 不阻塞，进度通过原子标志/状态串回传。
4. **共享显示模型**：`InstructionRow`（common/instruction_row.h）是 TUI/GUI 共用的指令行视图模型。

## 前端清单

| 前端 | 源码 | 后端 | 触发 |
|------|------|------|------|
| GUI | `src/gui/` | Dear ImGui(Docking) + SDL3 + Metal | 默认（macOS，`TENET_ENABLE_GUI`） |
| TUI | `src/tui/` | FTXUI | `--tui` 或无 GUI 时 |
| CLI | `src/main.cpp` | 无（批处理） | `-c` 或任意 `--xxx` 分析选项 |
| RPC | `src/io/rpc_server.cpp` | JSON-RPC over Unix socket | `--rpc [path]` |
| MCP | `mcp/` | MCP 2024-11-05 over stdio | 外部 AI 客户端启动 |

## GuiApp — ImGui + SDL3 + Metal

**渲染**：SDL3 建窗 + Metal 命令队列做原生 GPU 渲染（macOS）。`render_frame()` 每帧调 `render_menu_bar()/render_toolbar()/render_status_bar()` + 各 `render_xxx_panel()`。

**面板**（`gui/panels_*.cpp` 分文件实现）：

| 面板 | 文件 | 功能 |
|------|------|------|
| 指令列表 | panels_instruction.cpp | 汇编 + 语法高亮 + 污点/切片/循环高亮 + 书签 |
| 寄存器 | panels_registers.cpp | 当前 inst_id 的 34 GPR，读/写/读写三色 |
| 内存 | panels_memory.cpp | 内存访问列表，点击地址开 Hex Dump |
| 调用栈 | panels_callstack_funcs.cpp | 当前调用栈，Enter 跟随调用/返回 |
| 函数列表 | panels_callstack_funcs.cpp | 排序（调用数/名/地址）+ 过滤 + Goto 补全 |
| Hex Dump | panels_misc.cpp | 十六进制 + ASCII，时间感知 |
| 字符串 | panels_misc.cpp | 字符串列表 + 过滤 + 长度区间 |
| 线程 | panels_misc.cpp | 线程时间线/切换 |
| Minimap | panels_misc.cpp | 鸟瞰纵向条（执行密度/循环/线程着色） |
| CFG | panels_cfg.cpp | 图形 CFG：缩放/平移/热力图/块选择/边宽度 |
| 分析 | panels_analysis.cpp | 污点/切片/反向污点结果列表 |
| 寄存器时间线 | panels_reg_timeline.cpp | 寄存器值 sparkline（P2-12） |
| DWARF | panels_dwarf.cpp | nm/JSON 符号信息（P2-13） |
| Trace Diff | panels_trace_diff.cpp | 多 trace 区域差异视图（P2-14） |
| 断点 | panels_misc.cpp | 断点列表管理 |

**导航**：
- `navigate_to(inst_id)` + `nav_push/nav_back/nav_forward` 浏览器式历史（ring buffer 64 条）。
- Goto 弹窗：函数名自动补全（`rebuild_goto_candidates()` 从 function_result）。
- 搜索：PC/inst_id/反汇编文本。
- 书签：存 TraceIndex meta CF，跨会话恢复。
- XRef 导航：`goto_xref_next/prev` 跳同一 PC 的下次/上次执行。
- 污点跳转：`jump_taint_next/prev` 在污染指令间跳。

**交互**：
- 右键上下文菜单（`render_xxx_context_menu()`）：寄存器→设污点源/复制值；内存→开 Hex Dump/设观察点；指令→反向污点/切片/设断点；函数→Goto/导出 CFG。
- 命令模式：`:` 前缀命令（`b 0x1234` 设 PC 断点、`w 0xaddr 8` 设观察点）。
- 断点引擎（BreakpointEngine）：PC 断点 O(1)、内存写观察点 O(log N)、条件断点 O(N)，前向+后向 continue。

**异步分析**：`run_startup_analysis()` 在后台线程跑核心 Pass（xref/function/cfg/strings/pattern/constant/loop_semantics/algorithm_summary/symbol_annotation），`analysis_running_` 原子标志 + `analysis_status_` 状态串，UI 不阻塞。`ensure_pass_manager()` 懒建 PassManager 并注入 IO/Core 引用。

**设置**：`gui_settings.{h,cpp}` 持久化字体/主题/颜色到 imgui.ini。Docking 布局由 ImGui 自动持久化。

**缓存**：`row_cache_`（LRUCache 4096）缓存 InstructionRow，避免每帧重算。

## TuiApp — FTXUI 终端界面

**布局**：`make_main_component()` 组装 FTXUI 组件树。左主面板（指令列表）+ 右侧（寄存器/内存）+ 底部状态栏 + 可切换面板（调用栈/函数/字符串/线程/Hex Dump/断点）。Tab 切焦点面板。

**功能对等**：导航历史、书签、Goto 对话框、搜索、面板焦点切换、断点引擎、污点/切片/反向污点/函数/XRef 分析触发、XRef 跳转、污点跳转、调用栈跟随、函数列表排序过滤、字符串搜索、线程跳转、循环高亮、Minimap 纵向条。

**特有**：`hex_dump_view.{h,cpp}` 终端 Hex Dump 视图；命令模式对话框（`:` 前缀）。

**缓存**：`row_cache_`（LRUCache 1024）。

**batch_mode(start, count, show_regs, show_mem)**：非交互 dump，给 `-c` 用。

## CLI — 批处理管线

`main.cpp` 解析参数后，按选项触发对应 Pass，输出 JSON/DOT/文本到 stdout/文件。**多选项可组合**，按声明顺序执行。

**选项分组**（详见 `print_usage()`）：
- 通用：`--tui/-c/-n/-s/-r/-m/-i/-h`
- 污点：`--taint <reg>/--taint-inst/--taint-mem/--taint-stop-pc/--taint-max-width/--taint-no-calls/--taint-no-xref/--taint-no-kills`
- 反向：`--backward-taint <inst> <reg>/--backward-taint-max-steps/--backward-taint-graph/--critical-path`
- CFG/调用图：`--export-cfg/--call-graph`
- 模式/算法：`--pattern/--constants/--constants-min-parts/--loop-semantics/--algorithm-summary`
- 字符串/内存：`--strings/--memory-strings/--memory-snapshot/--memory-snapshot-size`
- ObjC/iOS：`--objc/--objc-class/--objc-crypto/--syscall-intercept/--syscall-intercept-bytes/--taint-source-annotation`
- 数据流：`--dataflow-graph/--dataflow-graph-output`
- 差异：`--trace-diff`
- 符号：`--symbol-annotation/--image`
- 查询（JSON）：`--memread <addr> <size> <inst>/--mem-history <addr> <size>/--search-pc <addr> [limit]`
- 调试：`--dump-memaccess <start> <count>/--dump-ma-strings`
- P3 高级：`--cache-sim*/--yara-mem-scan*/--thread-filter/--rpc/--streaming/--stats`
- 抑制并行扫描：`--no-parallel-scan`

**输出格式**：分析结果走 **stdout**（JSON/DOT/文本），日志走 stderr（`TENET_LOG` 控制）。脚本友好。

## RPC — JSON-RPC over Unix socket

`TenetRpcService` 把 reader/index/regfile/memory/pm 引用注入，`start(socket_path)` 后阻塞监听。单连接串行处理（mutex 序列化并发客户端）。标准方法：`ping/get_stats/get_reg/get_regs/read_mem/get_inst/get_range/get_xref/get_cfg/get_call_graph`。详见 [io-layer.md](io-layer.md#rpcserver--json-rpc-over-unix-socket)。

## MCP — AI 驱动分析

`mcp/tenet_mcp_server.py` 实现 MCP 2024-11-05 协议，JSON-RPC 2.0 over stdio 与 AI 客户端通信。**零外部 Python 依赖**（3.9+）。

**21 工具**：`trace_open/trace_info/disasm/taint_forward/taint_backward/cfg_export/call_graph/pattern_scan/strings_scan/constants_scan/regstate/memread/mem_write_history/critical_path/search_pc/trace_diff/loop_semantics/symbol_annotation/memory_snapshot/dataflow_graph/algorithm_summary/objc_messages`。

底层通过启动 `tenet --rpc <socket>` 子进程 + JSON-RPC 通信实现。配置见 `mcp/mcp_config_example.json`。

## 数据流（UI 视角）

```
用户操作（点击/Goto/快捷键）
        │
        ▼
navigate_to(inst_id)  ← 更新 current_inst_ + nav_push
        │
        ├─ 即时渲染：fetch_row(inst_id) → row_cache_ LRU → InstructionRow
        │   └─ regfile.state_before + decoder.decode + memory.read
        │
        └─ 触发分析（按需）：pm.require("taint") / pm.require("cfg_layout") ...
            └─ 后台线程执行（GUI: analysis_running_ 原子标志）
                └─ 完成后存 PassEntry，UI 取 const T* 引用渲染
```

**关键**：UI 永远通过 `PassManager::require()` 取分析结果，不直接调 Core 做分析。即时状态（寄存器/内存）才直接调 Core（regfile/memory/decoder）。

## 关键设计决策

1. **三前端共享 Core**：避免逻辑重复。GUI/TUI 只差渲染层，CLI 只差无渲染。
2. **InstructionRow 统一模型**：TUI/GUI 共用，减少分歧。
3. **异步分析不阻塞**：GUI 用 `startup_analysis_thread_`，CLI 串行但输出友好。长 trace 首次打开立即可交互，核心分析后台跑。
4. **LRU row_cache**：滚动浏览时复用相邻行，避免每帧重算寄存器/解码。
5. **断点引擎复用索引**：PC/内存断点不扫 trace，秒级定位，支撑「时空调试」体验。
6. **MCP 复用 RPC**：AI 工具不重写分析逻辑，通过 RPC 复用 tenet 二进制的全部能力。

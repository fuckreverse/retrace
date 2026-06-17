# tenet — Offline Trace Analyzer

基于 qbditrace 录制的 `.bin` trace 进行离线全量分析。实现「时间无关调试」
（Timeless Debugging）的分析端——在完整的执行历史上自由导航，执行双向污点追踪、
交叉引用、CFG 恢复等高级逆向分析。

## 核心特性

**极致性能**：mmap 零拷贝读取 + RocksDB 持久化索引 + Roaring Bitmap 亿级集合运算。1.5GB trace（1 亿条指令）首次索引 ~60s，之后秒开。随机跳转 < 500μs。

**Triton 驱动的精确分析**：利用 Quarkslab Triton 库的 AArch64 指令语义引擎做精确的污点传播和数据流分析——自动处理条件执行、隐式操作数、子寄存器别名等 500+ 种指令的语义细节，无需手写特例表。

**Pass Pipeline 架构**：LLVM 风格的可扩展分析框架。每个分析能力是独立 Pass，声明依赖后由 PassManager 自动调度和并行执行（拓扑排序 + 原子状态 + 条件变量实现真并行）。新增分析能力只需实现一个 Pass 类。

**三前端支持**：GUI（Dear ImGui + SDL3 + Metal，macOS 原生 GPU 渲染）、TUI（FTXUI 终端界面）、CLI（批量分析管线）三种使用模式。

**MCP 集成**：内置 MCP 服务器（21 个工具），让 AI 直接驱动 tenet 的全部分析能力。

## 技术栈

| 组件 | 选型 | 版本 | 许可证 |
|------|------|------|--------|
| 语义/污点/符号 | Triton (libTriton) | 系统安装 | Apache 2.0 |
| 反汇编 | Capstone | 5.0.1 | BSD-3 |
| 文件访问 | POSIX mmap | — | — |
| 索引存储 | RocksDB | v9.4.0 | Apache 2.0 |
| 位图集合 | CRoaring | v4.1.1 | Apache 2.0 |
| GUI 框架 | Dear ImGui (Docking) | v1.91.6 | MIT |
| 窗口/渲染 | SDL3 + Metal | 3.2.0 | zlib |
| 节点编辑器 | imgui-node-editor | v0.9.3 | MIT |
| TUI | FTXUI | v5.0.0 | MIT |
| 格式化 | fmt | 10.2.1 | MIT |
| JSON | nlohmann/json | v3.11.3 | MIT |
| 哈希表 | ankerl::unordered_dense | v4.4.0 | MIT |
| 模式匹配 | YARA | 系统安装 | BSD-3 |
| 测试 | Catch2 | v3.5.4 | BSL-1.0 |
| 语言 | C++17 | — | — |

## 快速开始

```bash
cd tools/tenet/build
ninja -j$(nproc)

# GUI 模式（macOS 默认）
./tenet /path/to/trace.bin

# TUI 模式
./tenet --tui /path/to/trace.bin

# CLI 批量分析
./tenet -c --taint 0 trace.bin
./tenet -c --export-cfg func.dot trace.bin
./tenet -c --pattern trace.bin
./tenet -c --algorithm-summary trace.bin
```

## CLI 完整参数

### 通用选项

| 参数 | 说明 |
|------|------|
| `--tui` | 使用终端 UI（当 GUI 可用时默认使用 GUI） |
| `-c` | Batch 模式（非交互，用于脚本/管线） |
| `-n <count>` | 显示指令数量（默认 100） |
| `-s <inst_id>` | 从指定指令 ID 开始（默认 0） |
| `-r` | 显示寄存器状态 |
| `-m` | 显示内存访问 |
| `-i` | 显示索引构建统计 |
| `-h` | 显示帮助 |

### 分析选项（需 `-c` 或自动抑制交互）

| 参数 | 说明 |
|------|------|
| `--export-cfg <file.dot>` | 导出带注释的 CFG（Graphviz DOT） |
| `--taint <reg_index>` | 从寄存器索引运行前向污点 |
| `--taint-inst <inst_id>` | 从指定指令开始污点 |
| `--taint-mem <addr>` | 添加内存地址为污点源（十六进制） |
| `--taint-stop-pc <addr>` | 到达此 PC 停止污点（可重复使用） |
| `--taint-max-width <N>` | 污染宽度超 N 个寄存器时停止 |
| `--taint-no-calls` | 不跨函数传播污点 |
| `--taint-no-xref` | 禁用 XRef 加速 |
| `--taint-no-kills` | 不输出 kill 事件 |
| `--backward-taint <inst_id> <reg>` | 从 sink 指令反向污点 |
| `--backward-taint-max-steps <N>` | 限制反向步数 |
| `--backward-taint-graph <file>` | 导出数据流图（.dot 或 .json） |
| `--critical-path` | 计算前向+反向交集 |
| `--strings` | 发现已追踪内存中的可打印字符串 |
| `--pattern` | 检测加密/反调试/混淆模式 |
| `--constants` | 提取通过 movz+movk 物化的常量 |
| `--constants-min-parts <N>` | 最少 movz+movk 部件数（默认 2） |
| `--call-graph <file.dot>` | 导出调用图（DOT 或 JSON） |
| `--loop-semantics` | 识别轮函数/加密循环语义 |
| `--trace-diff <a_start> <a_end> <b_start> <b_end>` | 差异化 trace 分析 |
| `--dataflow-graph <start> <end>` | 构建指令范围数据流图 |
| `--dataflow-graph-output <file>` | 导出数据流图 |
| `--algorithm-summary` | 生成算法综合摘要报告 |
| `--objc` | 分析 Objective-C 消息发送 |
| `--symbol-annotation` | 为所有 PC 生成符号注释 |
| `--memory-snapshot <inst_id>` | 捕获内存快照（可重复使用） |
| `--memory-snapshot-size <N>` | 快照中每区域字节数（默认 64） |

### 查询选项（JSON 输出）

| 参数 | 说明 |
|------|------|
| `--memread <addr> <size> <inst_id>` | 时间感知的内存读取 |
| `--mem-history <addr> <size>` | 列出对地址的所有写入历史 |
| `--search-pc <addr> [limit]` | 查找所有执行过某 PC 的指令 |

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│            Frontend (GUI / TUI / CLI / MCP Server)               │
├─────────────────────────────────────────────────────────────────┤
│   Pass Pipeline (22 Passes, PassManager 拓扑排序 + 并行调度)     │
│   XRef · Taint · BackwardTaint · CFG · CFGLayout · Slice ·      │
│   Function · CallGraph · String · Pattern · Loop · LoopSem ·    │
│   TraceDiff · DataflowGraph · AlgorithmSummary · ObjC · ...     │
├─────────────────────────────────────────────────────────────────┤
│   Core (RegisterFile + MemoryModel + TritonBridge/TritonPool)   │
├─────────────────────────────────────────────────────────────────┤
│   IO (TraceReader mmap + CodeTable + IndexBuilder + RocksDB)    │
└─────────────────────────────────────────────────────────────────┘
```

## 分析 Pass 列表

tenet 当前包含 22 个分析 Pass：

| Pass | 说明 |
|------|------|
| `index_build` | 索引构建（首次加载时运行） |
| `disassembly` | AArch64 反汇编（Capstone） |
| `xref` | 交叉引用分析 |
| `cfg` | 控制流图构建 |
| `cfg_layout` | CFG 布局（Sugiyama 分层算法，与 IDA 同源） |
| `taint` | 前向污点分析（Triton 精确语义） |
| `backward_taint` | 反向污点 / 数据流追踪 |
| `slice` | 程序切片 |
| `function` | 函数识别（含 tail call 检测） |
| `call_graph` | 调用图构建 |
| `strings` | 字符串发现（ASCII/UTF-8/UTF-16） |
| `pattern` | 模式检测（加密/反调试/混淆/网络/密钥调度） |
| `constant_materialization` | movz+movk 常量提取 + 已知算法常量匹配 |
| `loop` | 循环检测 |
| `loop_semantics` | 循环语义识别（Feistel/SPN/轮函数） |
| `trace_diff` | 差异化 trace 分析 |
| `symbol_annotation` | 符号注释生成 |
| `memory_snapshot` | 内存快照捕获 |
| `dataflow_graph` | 数据流图构建 |
| `algorithm_summary` | 算法综合摘要报告 |
| `objc` | Objective-C 消息分析 |
| `thread` | 线程分析 |

## GUI 前端（macOS）

基于 Dear ImGui (Docking) + SDL3 + Metal 的原生 GPU 渲染 GUI：

**面板**：指令列表（语法高亮）、寄存器面板（读/写/读写三色）、内存访问、调用栈、函数列表（排序/过滤）、Hex Dump、字符串、线程、Minimap 鸟瞰图、CFG 图形面板（缩放/平移/热力图着色/块选择）、分析面板、进度覆盖层。

**交互**：导航历史（Back/Forward）、书签系统、Goto 弹窗（函数名自动补全）、搜索、右键上下文菜单、快捷键系统、Docking 布局持久化。

**分析集成**：异步后台分析（不阻塞 UI）、启动自动运行核心分析、前向/反向污点可视化、程序切片可视化、XRef 导航、污点跳转。

## TUI 前端

基于 FTXUI 的终端界面，功能与 GUI 对等：指令列表（语法高亮）、寄存器面板（差异高亮）、内存面板、Hex Dump、调用栈、函数列表、字符串面板、线程面板、Minimap 纵向条。支持导航历史、书签、Goto 对话框、搜索、面板焦点切换。

## MCP 服务器

`mcp/tenet_mcp_server.py` 提供 MCP 2024-11-05 协议的服务器，通过 JSON-RPC 2.0 over stdio 与 AI 客户端通信。零外部 Python 依赖（Python 3.9+）。

提供 21 个工具：`trace_open`, `trace_info`, `disasm`, `taint_forward`, `taint_backward`, `cfg_export`, `call_graph`, `pattern_scan`, `strings_scan`, `constants_scan`, `regstate`, `memread`, `mem_write_history`, `critical_path`, `search_pc`, `trace_diff`, `loop_semantics`, `symbol_annotation`, `memory_snapshot`, `dataflow_graph`, `algorithm_summary`, `objc_messages`。

配置示例见 `mcp/mcp_config_example.json`。

## YARA 规则

`rules/` 目录包含 6 组 YARA 规则用于 PatternPass 模式检测：

| 规则文件 | 检测类别 |
|----------|----------|
| `crypto.yar` | 加密算法特征 |
| `anti_debug.yar` | 反调试技术 |
| `obfuscation.yar` | 代码混淆 |
| `encoding.yar` | 编码/压缩 |
| `key_schedule.yar` | 密钥调度 |
| `networking.yar` | 网络操作 |

## 目录结构

```
tools/tenet/
├── CMakeLists.txt              ← CMake 构建（C++17, LTO, Apple M1+ 优化）
├── DESIGN.md                   ← 总体架构设计
├── README.md                   ← 本文件
├── imgui.ini                   ← ImGui Docking 布局持久化
├── _deps/                      ← FetchContent 共享缓存（勿删！~2G）
│   ├── capstone-src/
│   ├── catch2-src/
│   ├── fmt-src/
│   ├── ftxui-src/
│   ├── imgui-src/
│   ├── imgui_node_editor-src/
│   ├── nlohmann_json-src/
│   ├── roaring-src/
│   ├── rocksdb-src/
│   ├── sdl3-src/
│   └── unordered_dense-src/
├── bench/                      ← 性能基准测试
│   ├── bench_tenet.cpp
│   ├── bench_all_passes.cpp
│   └── bench_loop_only.cpp
├── demo/                       ← 演示 trace + 生成器
│   ├── demo_trace.bin
│   └── gen_trace.cpp
├── docs/                       ← 设计文档
│   ├── io-layer.md
│   ├── core-layer.md
│   ├── analysis-layer.md
│   ├── ui-layer.md
│   └── trace-format.md
├── mcp/                        ← MCP 服务器（AI 驱动分析）
│   ├── tenet_mcp_server.py
│   ├── mcp_config_example.json
│   └── README.md
├── rules/                      ← YARA 模式规则
│   ├── crypto.yar
│   ├── anti_debug.yar
│   ├── obfuscation.yar
│   ├── encoding.yar
│   ├── key_schedule.yar
│   └── networking.yar
└── src/
    ├── main.cpp                ← 入口 + CLI 参数解析
    ├── analysis/
    │   ├── pass_manager.{h,cpp}    ← PassManager 并行调度
    │   ├── trace_collector.{h,cpp} ← TraceScanEngine 广播
    │   ├── passes/                 ← 22 个分析 Pass
    │   └── results/                ← Pass 结果类型
    ├── common/
    │   ├── BinaryTrees.h           ← 红黑树/AVL
    │   ├── LinkedListPool.h        ← 池化链表
    │   ├── instruction_row.h       ← 指令行视图
    │   ├── logger.h                ← 日志
    │   └── types.h                 ← Result<T>, RegState 等
    ├── core/
    │   ├── register_file.{h,cpp}   ← ANCHOR 基寄存器重建
    │   ├── memory_model.{h,cpp}    ← 写历史 + RocksDB 持久化
    │   ├── instruction_decoder.{h,cpp} ← 指令解码
    │   └── triton_bridge.{h,cpp}   ← Triton 桥接 + TritonPool
    ├── gui/
    │   ├── gui_app.{h,mm}          ← ImGui + Metal GUI
    │   └── gui_settings.{h,cpp}    ← 设置持久化
    ├── io/
    │   ├── trace_reader.{h,cpp}    ← mmap 零拷贝读取
    │   ├── code_table.{h,cpp}      ← 代码段管理
    │   └── index_builder.{h,cpp}   ← RocksDB 索引构建
    ├── tui/
    │   ├── tui_app.{h,cpp}         ← FTXUI 终端界面
    │   └── hex_dump_view.{h,cpp}   ← Hex Dump 视图
    └── ui/                         ← 预留
```

## 构建

详见仓库根目录 `CLAUDE.md` 的构建说明。关键要点：

```bash
# 日常增量构建（< 30s）
cd tools/tenet/build
ninja -j$(nproc)

# 首次构建
cd tools/tenet && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
ninja -j$(nproc)
```

**CMake 选项**：

| 选项 | 默认 | 说明 |
|------|------|------|
| `TENET_ENABLE_TRITON` | ON | Triton 精确污点（需预装 libTriton） |
| `TENET_ENABLE_YARA` | ON | YARA 模式匹配（需系统 yara） |
| `TENET_ENABLE_GUI` | ON | ImGui GUI（需 SDL3 + Metal，macOS） |
| `TENET_BUILD_TESTS` | ON | 单元测试（Catch2） |
| `TENET_USE_SYSTEM_ROCKSDB` | OFF | 使用系统 RocksDB 而非 FetchContent |
| `TENET_USE_SYSTEM_CAPSTONE` | OFF | 使用系统 Capstone 而非 FetchContent |

> ⚠️ `_deps/` 目录是所有 build 目录的共享缓存（通过 `FETCHCONTENT_BASE_DIR`），**禁止删除**。禁止新建 build 目录。

## 与 qbditrace 的关系

tenet 读取 qbditrace 生成的 `.bin` trace 文件（TraceFormat.h v4）。
两者通过二进制格式通信，tenet 是纯只读消费者。
格式契约详见 [docs/trace-format.md](docs/trace-format.md)。

### 测试数据：Advanced Benchmark

qbditrace 的 [advanced benchmark](../qbditrace/benchmark/advanced/README.md) 提供了
22 个专门为验证 tenet 各 Pass 能力而设计的 trace 样本，涵盖：

- **Group A**（7 个真实加密算法）→ 验证 PatternPass / TaintPass
- **Group B**（5 个 OLLVM 混淆变体）→ 验证 CFGPass（CFF 还原）/ PatternPass（MBA 识别）
- **Group C**（6 个综合场景）→ 验证 FunctionPass / CallGraphPass / 全 Pass 协同
- **Group D**（4 个边界压力）→ 验证 SlicePass 路径爆炸抗性 / XRefPass

每个 target 在注册表中显式标注了期望触发的 tenet Pass（`caps` 字段），可直接用于
回归测试。一键生成全部 trace：

```sh
sh tools/qbditrace/benchmark/advanced/run_advanced.sh --tenet ./build/tenet
```

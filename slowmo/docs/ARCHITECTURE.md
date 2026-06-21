# tenet 架构总览

> 本文档是 tenet 项目的**压缩导航图**，面向 AI 与人类读者。每个模块的细节见同目录下的分层文档。
> 设计原则：代码是权威，文档只描述「在哪、做什么、为什么」，不重复代码。

## 一句话定位

tenet 是 qbditrace 录制的 `.bin` 执行 trace 的**离线全量分析端**，实现「时间无关调试」——在完整执行历史上自由导航、双向污点、CFG 恢复、算法识别。

## 四层架构

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend   GUI(ImGui+SDL3+Metal) · TUI(FTXUI) · CLI · RPC · MCP │
├─────────────────────────────────────────────────────────────┤
│  Analysis   PassManager (DAG 拓扑 + 原子状态 + 真并行)            │
│             30+ Pass：xref·taint·cfg·function·pattern·loop…     │
│             TraceScanEngine 单遍广播 + 并行分片                   │
├─────────────────────────────────────────────────────────────┤
│  Core       RegisterFile(Anchor+Diff+LRU) · MemoryModel(RocksDB) │
│             InstructionDecoder(Capstone+缓存) · TritonBridge      │
│             BreakpointEngine(时空断点)                            │
├─────────────────────────────────────────────────────────────┤
│  IO         TraceReader(mmap 零拷贝) · TraceIndex(RocksDB 倒排)   │
│             CodeTable + ImageFallback · StreamingIndex · RpcServer│
└─────────────────────────────────────────────────────────────┘
```

**依赖方向**：上层依赖下层，绝不上调。Frontend → Analysis → Core → IO。Core/IO 层是线程安全（只读 mmap + RocksDB MVCC），Core 的可变缓存（LRU）由调用方保证单线程或自带锁。

## 启动与数据流（main.cpp）

`main.cpp` 是唯一的装配点，串联四层。读 `main.cpp` 即可理解整个生命周期：

1. **打开 trace**：`TraceReader::open(path)` → mmap 映射 + 解析 536B 文件头。
2. **建/载索引**：`TraceIndex::open_or_build(reader)` → 首次顺序扫描建 RocksDB（多 CF 倒排），之后秒开。自适应稀疏度 + ANCHOR 边界并行分片。
3. **建 CodeTable**：`index.load_code_table(code_table)` 从 `CODE_BYTES` CF 装载（避免二次扫文件）；可选 `--image` 加载二进制做 LDXR/STXR 缺码回填。
4. **建 Core**：`RegisterFile`、`MemoryModel`（`build()` 持久化 mem_write CF）、`InstructionDecoder`（Capstone 初始化）、`TritonPool`（可选）。
5. **建 PassManager**：`set_reader/index/...` 注入依赖，`register_pass(...)` 注册所需 Pass。每个 Pass 声明 `dependencies()`，PassManager 拓扑排序 + CAS 状态机实现真并行。
6. **分发前端**：无分析选项 → GUI/TUI 交互；有分析选项 → CLI 批量执行 `pm.require("pass_name")`，输出 JSON/DOT 到 stdout/文件；`--rpc` → `TenetRpcService` 阻塞式 JSON-RPC over Unix socket。

## 关键不变量

| 不变量 | 含义 | 守护位置 |
|--------|------|----------|
| **inst_id 单调递增** | 每条 INST 记录全局唯一递增编号，是所有分析的「时间轴」 | qbditrace 写入端 |
| **运行时地址** | 所有 PC/地址含 ASLR slide；静态地址 = runtime − slide | FileHeader.module_slide |
| **Anchor 周期重建** | 每 ~4096 条 INST 一个 ANCHOR 全量快照，diff 链衔接 | qbditrace + RegisterFile |
| **零拷贝** | TraceReader 返回指向 mmap 的视图指针，不复制 | RecordView/InstView |
| **索引可持久化** | RocksDB 缓存按 trace 内容指纹校验，文件未变则秒开 | TraceIndex::is_valid_for |
| **v4/v5/v6 兼容** | trace 格式有 3 种 INST 内存布局变体，Reader 按 header flags 分派 | InstView.is_v5/is_v6 |
| **Pass 幂等** | 同一 Pass 同一 range 只跑一次，结果缓存于 PassEntry | PassManager CAS 状态机 |

## 核心数据结构（common/types.h）

- `Result<T>`：C++17 兼容的预期类型（无 std::expected），成功持 T，失败持 `Error{code,message}`。
- `RegState`：34 个 AArch64 GPR 的定长数组（272B），索引：x0-x28(0-28)、fp(29)、lr(30)、sp(31)、nzcv(32)、pc(33)。
- `LRUCache<K,V>`：**零堆分配** LRU——预分配 Node 数组 + 侵入式双向链表（prev/next 用数组下标）+ ankerl flat_map。热路径（解码、寄存器重建）零 malloc。
- `RecordKind`：Inst/Anchor/Thread/Event/Svc/Objc/Code 共 7 种记录。

## AArch64 指令分类（common/aarch64_classify.h）

纯 opcode 位运算分类，**无 Capstone 依赖**，适合热循环。提供 `is_b/is_bl/is_blr/is_br/is_ret/is_b_cond/is_movz/is_movk` 等。CFG/Function/Taint 等 Pass 在扫描时用它快速判断指令类别，避免每条都调 Capstone。

## 日志与计时（common/logger.h）

纯头文件日志：`TENET_LOG` 环境变量控级别（0-5 或 INFO/DEBUG/TRACE），输出到 **stderr**（不干扰 stdout 的 JSON/分析结果）。`TENET_SCOPE_TIMER("name")` RAII 自动打印作用域耗时 + RSS 增量。`log::rss_mb()` 获取进程 RSS。

## 性能基线（1 亿指令 / 1.5GB trace）

| 操作 | 耗时 | 备注 |
|------|------|------|
| 首次索引构建 | ~60s | 并行分片，RocksDB batch write |
| 再次打开 | <1s | 缓存命中 |
| 随机跳转 inst_id | <500μs | 稀疏 offset + 256 条线性扫描 |
| state_before（cache miss） | ~500μs | 加载 anchor + apply ≤4096 diffs |
| state_before（cache hit） | <1μs | LRU 命中 |
| 前向污点（10K 步） | ~50ms | Triton replay |

## 分层文档索引

| 文档 | 范围 |
|------|------|
| [io-layer.md](io-layer.md) | TraceReader / TraceIndex / CodeTable / StreamingIndex / RpcServer |
| [core-layer.md](core-layer.md) | RegisterFile / MemoryModel / InstructionDecoder / TritonBridge / BreakpointEngine |
| [analysis-layer.md](analysis-layer.md) | PassManager / TraceScanEngine / 30+ Pass 全目录 |
| [ui-layer.md](ui-layer.md) | GuiApp / TuiApp / CLI / RPC / MCP |
| [trace-format.md](trace-format.md) | tenet 与 qbditrace 的二进制格式契约 |

## 源码地图（src/）

```
src/
├── main.cpp                    入口 + CLI 解析 + 四层装配（2538 行，读它理解全局）
├── common/                     types.h(Result/RegState/LRUCache) · aarch64_classify.h
│                               dataflow_types.h · instruction_row.h · logger.h · BinaryTrees.h
├── io/                         trace_reader · index_builder · code_table · streaming_index · rpc_server · recent_files
├── core/                       register_file · memory_model · instruction_decoder · triton_bridge · breakpoint_engine
├── analysis/
│   ├── pass_manager.{h,cpp}    PassManager + PassContext + AnalysisPass 基类
│   ├── trace_collector.{h,cpp} TraceCollector 接口 + TraceScanEngine 广播引擎
│   └── passes/                 30+ 个 Pass（每个 pass 一对 .h/.cpp）
├── gui/                        gui_app(.h/.mm) + panels_*.cpp + gui_settings + navigation + popups
├── tui/                        tui_app + hex_dump_view
└── python/                     tenet_bindings.cpp（Python 绑定，可选）
```

## 扩展指南

- **加新分析**：在 `passes/` 下新建 `my_pass.{h,cpp}`，继承 `AnalysisPass`，实现 `name()/dependencies()/run()`，在 `main.cpp` 注册。PassManager 自动调度。参考最简单的 `literal_search_pass`。
- **加新前端命令**：在 `main.cpp` 的参数解析循环加 `else if`，调用 `pm.require("...")` 取结果，格式化输出。
- **加新 RPC 方法**：在 `TenetRpcService::register_methods()`（rpc_server.cpp）加 handler。
- **加新 GUI 面板**：在 `gui/panels_*.cpp` 加 `render_xxx_panel()`，在 `gui_app.h` 声明，在 `render_frame()` 调用。

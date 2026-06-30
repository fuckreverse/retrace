# tenet 架构总览

这份文档从“程序如何启动、对象如何装配、模式如何分流”三个角度解释 tenet 的整体架构。想看单层细节时，再跳转到对应分层文档。

## 一句话定位

`tenet` 是 `qbditrace` 的离线分析端：它读取一次真实执行形成的 trace，把它重建成可查询、可导航、可导出、可服务化接入的执行历史。

## 四层结构

```mermaid
flowchart TB
    UI[Frontend / Service Layer\nGUI · TUI · CLI · RPC · MCP · MCP HTTP] --> ANA[Analysis Layer\nPassManager · Pass Registry · TraceScanEngine]
    ANA --> CORE[Core Layer\nRegisterFile · MemoryModel · InstructionDecoder · TritonBridge]
    CORE --> IO[IO Layer\nTraceReader · TraceIndex · CodeTable · StreamingIndex]
```

- **IO 层**负责把 trace 暴露成零拷贝记录流，并建立持久化索引。
- **Core 层**负责把记录流还原成“任意时刻的程序状态”。
- **Analysis 层**负责把状态和索引组织成可复用的分析 pass。
- **UI / Service 层**负责交互、导出和对外服务，不承担核心分析逻辑。

## 启动装配流程

`src/main.cpp` 是唯一装配点。它不会在各层之间写业务逻辑，只负责把固定对象顺序接起来。

```mermaid
flowchart TD
    A[parse_args] --> B[TraceReader::open]
    B --> C[TraceIndex::open_or_build]
    C --> D[index.load_code_table]
    D --> E{--image?}
    E -- yes --> F[ImageFallback]
    E -- no --> G[InstructionDecoder::init]
    F --> G
    G --> H[RegisterFile]
    H --> I[MemoryModel]
    I --> J{has_analysis_option?}
    J -- yes --> K[run_batch_analysis]
    J -- no --> L{--tui? GUI available?}
    L -- GUI --> M[GuiApp]
    L -- TUI --> N[TuiApp]
```

### 启动阶段细分

| 阶段 | 主要对象 | 作用 |
|------|----------|------|
| 参数解析 | `CliOptions` | 决定交互模式、批处理能力、服务模式 |
| 打开 trace | `TraceReader` | `mmap` 整个 trace，解析头，提供顺序/随机记录访问 |
| 载入或构建索引 | `TraceIndex` | 建立 offset / anchor / mem / reg / code 等 RocksDB CF |
| 载入代码字节 | `CodeTable` | 从索引或 trace 提取 opcode，供反汇编和 CFG 使用 |
| 可选镜像回填 | `ImageFallback` | 处理 trace 内缺失 code bytes 的 PC |
| 初始化 Core | `InstructionDecoder`, `RegisterFile`, `MemoryModel` | 构造任意时刻寄存器、内存和指令语义 |
| 分流到入口 | `run_batch_analysis`, `GuiApp`, `TuiApp` | 批处理、交互或服务化 |

## 运行时对象模型

tenet 的核心不是“一个大上下文对象”，而是一组职责稳定的长生命周期对象：

| 对象 | 生命周期 | 线程模型 | 备注 |
|------|----------|----------|------|
| `TraceReader` | 进程级 / 单 trace | 只读并发安全 | mmap 零拷贝底座 |
| `TraceIndex` | 进程级 / 单 trace | RocksDB 并发安全 | 持久化索引与元信息 |
| `CodeTable` | 进程级 / 单 trace | 读多写少 | 缓存 PC→opcode 映射 |
| `InstructionDecoder` | 进程级 | 内部互斥 | Capstone 句柄包装 |
| `RegisterFile` | 进程级或 pass 私有 | 缓存偏向单线程 | ANCHOR+diff 状态重建 |
| `MemoryModel` | 进程级 | 并发安全 | 时间感知内存读取与写历史 |
| `PassManager` | 入口级 / 会话级 | 内部同步 | 调度、缓存、依赖解析 |

## 模式分流

### 交互模式

- **GUI**：macOS 默认图形入口，强调浏览体验与多面板可视化。
- **TUI**：终端环境入口，适合 SSH 和远程分析。

### 批处理模式

- `run_batch_analysis()` 负责“注册 pass → 执行 → 格式化输出”。
- 多个 CLI 能力可以组合，输出 JSON / DOT / 文本。

### 服务模式

| 模式 | 入口 | 说明 |
|------|------|------|
| RPC | `--rpc` | Unix socket JSON-RPC，适合本地工具接入 |
| MCP stdio | `--mcp` | AI 客户端拉起 tenet 子进程时使用 |
| MCP HTTP | `--mcp-http` | 远程或无 stdio 场景，使用 Streamable HTTP |
| Streaming | `--streaming` | tail 正在增长的 trace，做实时增量索引 |

## 关键不变量

| 不变量 | 含义 |
|--------|------|
| `inst_id` 单调递增 | 所有分析共享同一条时间轴 |
| 地址是运行时地址 | 默认含 slide；静态地址需自行减 `module_slide` |
| 寄存器重建基于 ANCHOR | `RegisterFile` 的正确性依赖 trace 中周期性快照 |
| 内存读取是时间感知的 | `MemoryModel` 不读“最终值”，而读某时刻值 |
| pass 结果可缓存且幂等 | 同一个 pass 在同一上下文里不会重复执行 |
| 上层只依赖下层 | UI 不直接持有分析实现，Analysis 不直接改写 IO |

## 典型数据流

### 从“打开 trace”到“看见一条指令”

1. `TraceReader` 通过 `mmap` 让记录可顺序遍历。
2. `TraceIndex` 用稀疏 offset + anchor 建立快速定位。
3. `RegisterFile::state_before(inst_id)` 找到最近 anchor 并回放 diff。
4. `CodeTable::opcode_at(pc)` 取 opcode，必要时走 `ImageFallback`。
5. `InstructionDecoder` 把 opcode 反汇编成 mnemonic / operands。
6. GUI/TUI 把这些信息封装成 `InstructionRow` 渲染。

### 从“点击分析按钮”到“拿到结果”

1. UI 或 CLI 请求某个能力，例如 `cfg_layout`。
2. `PassManager::require("cfg_layout")` 自动解析依赖链。
3. 依赖 pass 先执行，结果缓存进 `PassEntry`。
4. 当前 pass 消费 `PassContext` 与上游结果，生成 `PassResult`。
5. UI / CLI / MCP 读取 typed result 并做展示或序列化。

## 当前实现规模

- `src/analysis/pass_registry.cpp` 当前维护 **36 个 pass**。
- `src/io/mcp/` 当前维护 **46 个 MCP 工具**。
- CLI 参数集中在 `src/cli_options.cpp`，批处理执行集中在 `src/batch_analysis.cpp`。

## 扩展点

### 新增一个分析能力

1. 在 `src/analysis/passes/` 新增 pass。
2. 在 `pass_registry.cpp` 把它加入 catalog 和工厂。
3. 如需 CLI 入口，在 `cli_options.*` 与 `batch_analysis.cpp` 加参数和输出。
4. 如需 AI 调用，在 `src/io/mcp/` 注册工具。

### 新增一个前端能力

- **GUI**：在 `gui/panels_*.cpp` 增加面板或上下文菜单。
- **TUI**：在 `tui/panels/` 或 `tui_app.cpp` 增加面板或命令。
- **CLI**：在 `batch_analysis.cpp` 追加结果序列化逻辑。
- **服务模式**：在 `rpc_server.cpp` 或 `src/io/mcp/` 加新接口。

## 文档地图

| 文档 | 关注点 |
|------|--------|
| [`docs/README.md`](README.md) | 文档导航与阅读路径 |
| [`USAGE.md`](USAGE.md) | **端到端入门**：环境安装 → 编译 → 录制 → 分析 |
| [`../README.md`](../README.md) | 项目入口与快速开始 |
| [`capabilities.md`](capabilities.md) | 按能力看 tenet 能做什么 |
| [`io-layer.md`](io-layer.md) | trace / index / code / streaming |
| [`core-layer.md`](core-layer.md) | 寄存器 / 内存 / 解码 / Triton |
| [`analysis-layer.md`](analysis-layer.md) | pass 分类、依赖、调度、融合 |
| [`pass-cookbook.md`](pass-cookbook.md) | 新增 pass 的实操开发指南 |
| [`ui-layer.md`](ui-layer.md) | GUI / TUI / CLI / RPC / MCP |
| [`trace-format.md`](trace-format.md) | 与 qbditrace 的格式契约 |
| [`profiling.md`](profiling.md) | 性能分析、Instruments、优化方法论 |

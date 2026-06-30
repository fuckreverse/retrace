# tenet — Offline Trace Analyzer

`tenet` 是 `qbditrace` 的离线分析端，用来读取 `.bin` trace 并做时间无关调试（Timeless Debugging）。它把一次真实执行过程重建成可导航、可查询、可自动化分析的时间轴，适合逆向分析、算法识别、污点传播、结构恢复和 AI 驱动分析。

## 你能用 tenet 做什么

- 交互浏览 trace：GUI / TUI 双前端，支持时间轴导航、书签、搜索、断点、Hex Dump。
- 恢复程序结构：函数识别、XRef、CFG、调用图、循环与循环语义。
- 追踪数据流：前向污点、反向污点、程序切片、producer chain、数据流图。
- 重建运行时状态：任意指令点寄存器状态、时间感知内存读取、写历史、内存快照、字符串恢复。
- 识别高层语义：常量物化、模式检测、算法摘要、ObjC 消息分析、系统调用参数提取。
- 做自动化与 AI 集成：CLI 批处理、JSON-RPC、MCP stdio、MCP Streamable HTTP、实时 streaming index。

## 文档入口

| 文档 | 适合场景 | 内容 |
|------|----------|------|
| [`docs/USAGE.md`](docs/USAGE.md) | **从零开始** | 环境安装、编译、录制 trace、分析全流程 |
| [`docs/README.md`](docs/README.md) | 先找入口 | 文档地图、按模块/按能力索引 |
| [`docs/capabilities.md`](docs/capabilities.md) | 按能力使用 | 交互、批处理、自动化、AI、流式分析能力总览 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 看整体设计 | 启动流程、层次边界、运行时装配、扩展点 |
| [`docs/io-layer.md`](docs/io-layer.md) | 看底层数据访问 | `TraceReader`、`TraceIndex`、`CodeTable`、`StreamingIndex` |
| [`docs/core-layer.md`](docs/core-layer.md) | 看状态重建 | `RegisterFile`、`MemoryModel`、`InstructionDecoder`、Triton 桥接 |
| [`docs/analysis-layer.md`](docs/analysis-layer.md) | 看 Pass 框架 | `PassManager`、`TraceScanEngine`、36 个 pass 的分类与依赖 |
| [`docs/ui-layer.md`](docs/ui-layer.md) | 看入口与服务 | GUI、TUI、CLI、RPC、MCP、MCP HTTP |
| [`docs/trace-format.md`](docs/trace-format.md) | 看格式契约 | tenet 与 qbditrace 的 trace 二进制接口 |
| [`docs/profiling.md`](docs/profiling.md) | 看性能优化 | Instruments、os_signpost、bench、优化方法论 |
| [`docs/pass-cookbook.md`](docs/pass-cookbook.md) | 看开发实操 | 新增 pass、接 CLI、接 MCP 的具体步骤 |
| [`DESIGN.md`](DESIGN.md) | 看设计理由 | 当前设计原则、关键取舍与演进说明 |

## 当前实现速览

- 主入口在 `src/main.cpp`：解析参数、打开 trace、构建/加载索引、初始化 Core、再分发到 GUI/TUI/CLI/服务模式。
- `src/analysis/pass_registry.cpp` 当前注册了 **36 个 pass**，按结构、污点、密码学、内存、ObjC/系统调用、性能、线程等类别组织。
- `src/io/mcp/` 当前注册了 **46 个 MCP 工具**，覆盖 trace 查询、分析触发、搜索、批量调用、证据验证和假设管理。
- 常驻对象模型是：`TraceReader` + `TraceIndex` + `CodeTable` + `RegisterFile` + `MemoryModel` + `InstructionDecoder` + `PassManager`。

## 固定构建目录

> tenet 必须使用固定构建目录。不要创建 `build-xxx`，也不要删除 `_deps/`。

- 默认构建目录：`tools/tenet/build/`
- 无 Triton 构建目录：`tools/tenet/build-no-triton/`
- 如果 `build/` 被误删，只重建这个固定目录，不要再新开别的 build 树。

```bash
cd tools/tenet/build
cmake ..
ninja -j$(nproc)
```

常用 CMake 选项：

| 选项 | 默认 | 说明 |
|------|------|------|
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | 日常开发推荐；`Release` 用于最终性能测试 |
| `TENET_ENABLE_TRITON` | `ON` | 启用 Triton 精确语义/污点 |
| `TENET_ENABLE_YARA` | `ON` | 启用 YARA 模式匹配 |
| `TENET_ENABLE_GUI` | `ON` | 启用 ImGui + SDL3 + Metal GUI |
| `TENET_BUILD_TESTS` | `ON` | 构建单元测试 |
| `TENET_ENABLE_RPC` | `ON` | 启用 Unix socket JSON-RPC 服务 |
| `TENET_ENABLE_PROFILING` | `ON` | 启用 macOS `os_signpost` 标记 |
| `TENET_ENABLE_PYTHON` | `OFF` | 构建 Python 绑定 |

## 快速开始

```bash
cd tools/tenet/build
ninja -j$(nproc)

# 交互浏览（macOS 默认 GUI）
./tenet /path/to/trace.bin

# 强制 TUI
./tenet --tui /path/to/trace.bin

# 结构恢复
./tenet trace.bin --export-cfg func.dot --call-graph cg.dot

# 数据流分析
./tenet trace.bin --taint 0 --taint-inst 12345
./tenet trace.bin --backward-taint 45678 0 --backward-taint-graph dfg.json

# 算法与模式识别
./tenet trace.bin --pattern --constants --loop-semantics --algorithm-summary

# 自动化服务
./tenet trace.bin --rpc /tmp/tenet.sock
./tenet trace.bin --mcp
./tenet trace.bin --mcp-http 127.0.0.1:7080
```

## 常见工作流

### 1. 先看结构

```bash
./tenet trace.bin --export-cfg func.dot --call-graph cg.dot --symbol-annotation
```

适合快速回答：函数边界在哪、谁调用了谁、热点循环在哪。

### 2. 再看数据流

```bash
./tenet trace.bin --taint 0 --taint-inst 12000 --taint-stop-pc 0x100123456
./tenet trace.bin --backward-taint 58000 0 --critical-path
```

适合回答：输入如何流到输出、某个 sink 由谁产生、关键路径是什么。

### 3. 最后看算法与语义

```bash
./tenet trace.bin --pattern --constants --loop-semantics --algorithm-summary --objc-crypto
```

适合回答：是不是 AES/SHA/ARX、哪些 ObjC 调用触发了密码学逻辑、是否存在反调试或混淆。

### 4. 做服务化接入

- `--rpc`：适合脚本或本地工具走 Unix socket JSON-RPC。
- `--mcp`：适合本地 AI 客户端通过 stdio 直接驱动 tenet。
- `--mcp-http`：适合 GUI 宿主、远程接入或没有 stdio 的场景，走 `POST /mcp`。
- `--streaming`：适合边录制边分析增长中的 trace。

## 目录结构

```text
tools/tenet/
├── CMakeLists.txt
├── README.md
├── DESIGN.md
├── docs/
│   ├── README.md
│   ├── capabilities.md
│   ├── ARCHITECTURE.md
│   ├── io-layer.md
│   ├── core-layer.md
│   ├── analysis-layer.md
│   ├── ui-layer.md
│   ├── trace-format.md
│   ├── profiling.md
│   └── pass-cookbook.md
├── rules/                    # YARA 规则
├── bench/                    # 性能基准
├── demo/                     # demo trace 与生成器
├── src/
│   ├── main.cpp
│   ├── batch_analysis.cpp
│   ├── cli_options.cpp
│   ├── io/
│   ├── core/
│   ├── analysis/
│   ├── gui/
│   ├── tui/
│   └── python/
└── tests/
```

## 与 qbditrace 的关系

- `qbditrace` 负责录制 trace，`tenet` 负责离线读取和分析。
- 两者通过 `tools/qbditrace/TraceFormat.h` 约定的二进制格式协作。
- tenet 当前要求 trace 版本 `>= 4`，并依赖 `REG_DIFF | HAS_CODE` 标志。
- 详细格式见 [`docs/trace-format.md`](docs/trace-format.md)。

## 进一步阅读

- 想按场景选择能力：看 [`docs/capabilities.md`](docs/capabilities.md)
- 想理解四层边界：看 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 想扩展 pass：先看 [`docs/pass-cookbook.md`](docs/pass-cookbook.md)，再看 [`docs/analysis-layer.md`](docs/analysis-layer.md)
- 想接 AI 或远程服务：看 [`docs/ui-layer.md`](docs/ui-layer.md)
- 想做性能优化：看 [`docs/profiling.md`](docs/profiling.md)

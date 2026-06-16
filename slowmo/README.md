# tenet — Offline Trace Analyzer

基于 qbditrace 录制的 `.bin` trace 进行离线全量分析。实现「时间无关调试」
（Timeless Debugging）的分析端——在完整的执行历史上自由导航，执行双向污点追踪、
交叉引用、CFG 恢复等高级逆向分析。

## 核心特性

**极致性能**：mmap 零拷贝读取 + RocksDB 持久化索引 + Roaring Bitmap 亿级集合运算。1.5GB trace（1 亿条指令）首次索引 ~60s，之后秒开。随机跳转 < 500μs。

**Triton 驱动的精确分析**：利用 Quarkslab Triton 库的 AArch64 指令语义引擎做精确的污点传播和数据流分析——自动处理条件执行、隐式操作数、子寄存器别名等 500+ 种指令的语义细节，无需手写特例表。

**Pass Pipeline 架构**：LLVM 风格的可扩展分析框架。每个分析能力（XRef、Taint、CFG、String、Pattern...）是独立 Pass，声明依赖后由 PassManager 自动调度和并行执行。新增分析能力只需实现一个 Pass 类。

**工业级 CFG 布局**：使用 Graphviz dot 引擎（与 IDA 同源的 Sugiyama 分层算法）生成 CFG 布局，开箱即得出版级质量。

## 技术栈

| 组件 | 选型 | 许可证 |
|------|------|--------|
| 语义/污点/符号 | Triton (libTriton) | Apache 2.0 |
| 反汇编 | Capstone | BSD-3 |
| 文件访问 | POSIX mmap | — |
| 索引存储 | RocksDB | Apache 2.0 |
| CFG 布局 | Graphviz (libcgraph/libgvc) | EPL-1.0 |
| 位图集合 | Roaring Bitmap | Apache 2.0 |
| 压缩 | Zstd (可选) | BSD-3 |
| TUI | FTXUI | MIT |
| 语言 | C++17 | — |

## 快速开始

```bash
cd tools/tenet
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# 分析 trace
./tenet /path/to/trace.bin

# CLI 模式：导出 CFG
./tenet --export-cfg 0x750bd5400 --format dot -o func.dot trace.bin

# CLI 模式：污点追踪
./tenet --taint '{"reg": "x0", "inst_id": 162718, "direction": "forward"}' trace.bin
```

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                   Frontend (TUI / CLI / API)                      │
├─────────────────────────────────────────────────────────────────┤
│              Pass Pipeline (XRef, Taint, CFG, String, ...)       │
│                      ↕ PassManager 调度                          │
├─────────────────────────────────────────────────────────────────┤
│       Core (RegisterFile + MemoryModel + TritonBridge)           │
├─────────────────────────────────────────────────────────────────┤
│           IO (TraceReader mmap + RocksDB Index)                  │
└─────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
tools/tenet/
├── DESIGN.md               ← 总体架构设计
├── README.md               ← 本文件
├── CMakeLists.txt          ← (TODO)
├── docs/
│   ├── io-layer.md         ← IO 层：mmap + RocksDB
│   ├── core-layer.md       ← Core 层：状态重建 + Triton 桥接
│   ├── analysis-layer.md   ← Analysis：Pass Pipeline 框架
│   ├── ui-layer.md         ← UI：视图接口
│   └── trace-format.md     ← 与 qbditrace 的格式契约
├── src/                    ← (TODO)
├── include/tenet/          ← (TODO)
├── tests/                  ← (TODO)
└── third_party/            ← 子模块
    ├── triton/
    ├── capstone/
    ├── rocksdb/
    ├── roaring/
    └── ftxui/
```

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

## 里程碑

| 阶段 | 目标 | 预计 |
|------|------|------|
| M1 | IO + 基础 Core（TraceReader, RocksDB, RegisterFile） | 2-3 周 |
| M2 | Triton 集成 + MemoryModel | 2 周 |
| M3 | Pass Pipeline + XRef + Taint | 3 周 |
| M4 | CFG + Graphviz 布局 | 2 周 |
| M5 | TUI 交互界面 | 2 周 |
| M6 | 性能调优（100M trace 验证） | 2 周 |
| M7 | 扩展 Pass + 脚本接口 | 持续 |

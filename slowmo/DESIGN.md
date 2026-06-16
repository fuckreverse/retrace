# Tenet — 离线 Trace 分析器 总体架构设计 (v2)

## 设计哲学

1. **不重新发明轮子**：指令语义、污点传播、符号执行交给 Triton；图布局交给 Graphviz；KV 索引交给 RocksDB。只自研真正独特的部分（trace 重建、Pass 编排）。
2. **极致性能**：mmap 零拷贝、列式二级索引、Anchor+Diff O(1) 状态重建、Pass 级并行。
3. **可扩展分析**：LLVM 风格 Pass Pipeline，每个分析能力是一个独立 Pass，支持依赖声明、缓存、按需触发。

## 技术栈

| 组件 | 选型 | 许可证 | 作用 |
|------|------|--------|------|
| 指令语义/污点/符号 | **Triton** (libTriton) | Apache 2.0 | 核心分析引擎 |
| 反汇编 | **Capstone** | BSD-3 | 指令解码与显示 |
| Trace 存储 | **mmap** (POSIX) | — | 零拷贝原始流访问 |
| 二级索引 | **RocksDB** | Apache 2.0 | PC→时间戳、地址→访问点等倒排索引 |
| CFG 布局 | **Graphviz** (libcgraph + libgvc) | EPL-1.0 | Sugiyama 分层布局 |
| 压缩 | **Zstd** (seekable format) | BSD-3 | 可选的 trace 压缩与随机访问 |
| Bitmap | **Roaring Bitmap** | Apache 2.0 | 大规模 inst_id 集合（污点结果等） |
| TUI | **FTXUI** | MIT | 终端交互界面 |
| 构建 | **CMake** 3.20+ | — | — |
| 测试 | **Catch2** | BSL-1.0 | 单元测试 |
| 语言 | **C++17** | — | 与 Triton/Capstone/RocksDB 原生兼容 |

## 架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Frontend (UI / CLI / API)                     │
├─────────────────────────────────────────────────────────────────────┤
│                        Pass Pipeline (Analysis)                      │
│  ┌────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │
│  │ TaintPass  │ │ XRefPass     │ │ CFGPass      │ │ UserPass…  │  │
│  └─────┬──────┘ └──────┬───────┘ └──────┬───────┘ └─────┬──────┘  │
│        └───────────┬────┴───────────┬────┴───────────────┘         │
│                    ▼                ▼                                │
│              PassManager (依赖解析 + 缓存 + 调度)                     │
├─────────────────────────────────────────────────────────────────────┤
│                        Core (State Reconstruction)                   │
│  ┌───────────────┐ ┌────────────────┐ ┌────────────────────────┐   │
│  │ RegisterFile   │ │ MemoryModel    │ │TritonContext (per-inst)│   │
│  │ (Anchor+Diff)  │ │ (Temporal KV)  │ │(语义/污点/符号 delegate)│   │
│  └───────────────┘ └────────────────┘ └────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                        IO (Storage + Index)                          │
│  ┌────────────┐ ┌────────────────┐ ┌──────────┐ ┌──────────────┐  │
│  │TraceReader │ │ RocksDB Index  │ │CodeTable │ │ SymbolTable  │  │
│  │(mmap zero  │ │ (倒排索引)     │ │(代码缓存)│ │ (符号加载)   │  │
│  │  copy)     │ │                │ │          │ │              │  │
│  └────────────┘ └────────────────┘ └──────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Pass Pipeline 设计

### 核心概念

```cpp
// 每个 Pass 是一个独立的分析单元
class AnalysisPass {
public:
    virtual ~AnalysisPass() = default;

    // Pass 元信息
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;

    // 依赖声明：本 pass 需要哪些其他 pass 的结果
    virtual std::vector<std::string> dependencies() const { return {}; }

    // 执行入口
    virtual PassResult run(PassContext& ctx) = 0;

    // 可选：增量更新（当 trace 范围变化时，无需完全重跑）
    virtual bool supports_incremental() const { return false; }
    virtual PassResult update(PassContext& ctx, const Range& changed) {
        return run(ctx);
    }
};

// PassContext 提供对 Core 层和其他 Pass 结果的访问
class PassContext {
public:
    // Core 层访问
    TraceReader& reader();
    RegisterFile& regfile();
    MemoryModel& memory();
    triton::API& triton();       // Triton 实例
    RocksDBIndex& index();

    // 获取已运行 Pass 的结果
    template<typename T>
    const T& result(const std::string& pass_name);

    // 查询范围（可能是全 trace，也可能是子范围）
    Range analysis_range() const;

    // 进度回调
    void report_progress(float pct, const std::string& msg);
};

// PassManager：注册、依赖解析、缓存、调度
class PassManager {
public:
    void register_pass(std::unique_ptr<AnalysisPass> pass);

    // 按需执行：自动解析依赖链
    template<typename ResultT>
    const ResultT& require(const std::string& pass_name);

    // 并行执行所有无依赖冲突的 pass
    void run_all();

    // 使某个 pass 的缓存失效
    void invalidate(const std::string& pass_name);
};
```

### 内置 Pass 列表

| Pass 名 | 依赖 | 输出 | 说明 |
|----------|------|------|------|
| `IndexBuildPass` | — | RocksDB 倒排索引 | 首次打开时构建，之后缓存 |
| `XRefPass` | IndexBuildPass | `XRefResult` | Use-Def / Def-Use 链 |
| `TaintPass` | XRefPass | `TaintResult` (Roaring Bitmap) | 正/逆向污点，Triton 语义驱动 |
| `CFGPass` | IndexBuildPass | `CFGResult` | 函数级 CFG + 循环识别 |
| `CFGLayoutPass` | CFGPass | `LayoutResult` | Graphviz 分层布局坐标 |
| `StringPass` | — | `StringResult` | 字符串扫描 |
| `PatternPass` | StringPass | `PatternResult` | 密码学/反调试模式匹配 |
| `CallGraphPass` | CFGPass | `CallGraphResult` | 全局调用图 |
| `SlicePass` | XRefPass, TaintPass | `SliceResult` | 程序切片 |

### Pass 并行策略

```
                 IndexBuildPass
                /      |       \
        XRefPass    CFGPass    StringPass
        /    \         |          |
  TaintPass  SlicePass CFGLayoutPass  PatternPass
```

无依赖的 Pass 可并行执行（通过线程池）。PassManager 基于 DAG 拓扑序调度。

## Triton 集成方案

### 角色

Triton 在 tenet 中担任**语义预言机 (Semantic Oracle)**：

1. **精确的 read/write set**：给定一条指令的字节码，Triton 返回它读写了哪些寄存器和内存。比 Capstone 的 `detail->regs_read/regs_write` 精确得多（处理条件执行、隐式操作数、STP/LDP 等复杂指令）。
2. **污点传播**：Triton 内置 TaintEngine，逐条指令处理 `taintAssignment / taintUnion`，自动处理子寄存器、内存别名、条件传播。
3. **符号执行**：可选——对关键路径做约束求解（如验证路径可达性、提取常量）。

### 使用模式：Trace Replay on Triton

```cpp
// 不是让 Triton "执行"指令，而是 "replay" trace 上的每条指令
void replay_instruction(triton::API& triton, const InstRecord& rec) {
    // 1. 设置 concrete 寄存器值（来自 RegisterFile 重建）
    for (auto& [reg_id, val] : rec.reg_state_before)
        triton.setConcreteRegisterValue(reg_id, val);

    // 2. 设置 concrete 内存值（来自 MemoryModel）
    for (auto& acc : rec.mem_reads)
        triton.setConcreteMemoryAreaValue(acc.addr, acc.data);

    // 3. 让 Triton "处理"这条指令（更新内部语义/污点/符号状态）
    triton::arch::Instruction inst;
    inst.setAddress(rec.pc);
    inst.setOpcode(rec.opcode, rec.opcode_size);
    triton.processing(inst);

    // 4. 现在可以查询：
    //    - inst.getReadRegisters() / getWrittenRegisters()
    //    - inst.getLoadAccess() / getStoreAccess()
    //    - triton.isRegisterTainted(reg) / isMemoryTainted(addr)
    //    - inst.getSymbolicExpressions() (符号表达式)
}
```

### 性能考量

- Triton `processing()` 每条指令约 **2-5 μs**（AArch64）。
- 对 1 亿条指令做全量 replay 需 200-500s —— **不可接受作为启动成本**。
- 解决方案：**按需 replay**。只在用户请求污点/XRef 时，对相关子范围（由 RocksDB 索引加速定位）做 Triton replay。
- TaintPass 的典型工作量：从一个 source 出发传播 ~10K-100K 步，耗时 20ms-500ms。

## 性能目标（修订版）

| 操作 | 目标 | 实现路径 |
|------|------|----------|
| 打开 1.5GB trace | < 2s（有缓存 < 50ms） | mmap + RocksDB 缓存持久化 |
| 随机跳转 inst_id | < 500μs | 分页索引 + Anchor LRU |
| 全量索引构建 | < 60s (100M inst) | 顺序扫描 + RocksDB batch write |
| 正向污点 10K 步 | < 50ms | XRef 跳跃 + Triton 语义 |
| 逆向污点 10K 步 | < 100ms | 逆向 XRef + Triton |
| CFG 构建（单函数） | < 200ms | PC 索引直接获取 transitions |
| CFG 布局 | < 500ms | Graphviz dot 算法 |
| 字符串扫描 | < 30s | 内存最终快照扫描 |
| 内存预算 | < 2GB RSS | mmap 不计入；RocksDB block cache 可配 |

## 目录结构

```
tools/tenet/
├── CMakeLists.txt
├── README.md
├── DESIGN.md                    ← 本文件
├── docs/
│   ├── io-layer.md              ← IO 层设计
│   ├── core-layer.md            ← Core 层 + Triton 集成
│   ├── analysis-layer.md        ← Pass Pipeline 设计
│   ├── ui-layer.md              ← UI 接口设计
│   └── trace-format.md          ← 与 qbditrace 的格式契约
├── src/
│   ├── io/                      ← TraceReader, RocksDB 索引
│   ├── core/                    ← RegisterFile, MemoryModel, Triton 桥接
│   ├── analysis/
│   │   ├── pass_manager.h/cpp   ← PassManager 框架
│   │   ├── passes/              ← 各内置 Pass
│   │   └── results/             ← Pass 输出类型定义
│   ├── ui/                      ← 视图层
│   └── main.cpp
├── include/tenet/               ← 公共 API 头文件
├── tests/
│   ├── unit/
│   └── integration/
└── third_party/                 ← 子模块或 vendored 依赖
    ├── triton/
    ├── capstone/
    ├── rocksdb/
    ├── roaring/
    └── ftxui/
```

## 里程碑（修订版）

| 阶段 | 目标 | 预计周期 | 关键交付 |
|------|------|----------|----------|
| **M1** | IO 层 + 基础 Core | 2-3 周 | TraceReader, RocksDB 索引, RegisterFile, 能遍历 trace |
| **M2** | Triton 集成 + MemoryModel | 2 周 | Triton replay 管线, 时间内存模型 |
| **M3** | Pass Pipeline 框架 + XRef/Taint | 3 周 | PassManager, XRefPass, TaintPass |
| **M4** | CFG + Graphviz 布局 | 2 周 | CFGPass, CFGLayoutPass, DOT/SVG 导出 |
| **M5** | TUI 交互 | 2 周 | FTXUI 界面, 全功能交互 |
| **M6** | 性能调优 + 100M trace 验证 | 2 周 | 基准测试, 内存优化, 并行 Pass |
| **M7** | 扩展 Pass + 脚本接口 | 持续 | PatternPass, SlicePass, Python 绑定 |

## 与上一版设计的关键变化

| 项目 | v1 (旧) | v2 (新) | 原因 |
|------|---------|---------|------|
| 污点引擎 | 自研（基于 Capstone detail） | Triton TaintEngine | 精度与正确性，免维护 |
| 指令语义 | 手写特例表 | Triton 自动解析 | AArch64 500+ 指令无法穷举 |
| 二级索引 | 自研分页内存结构 | RocksDB | 持久化、复杂查询、久经考验 |
| CFG 布局 | 自研 8 步算法 | Graphviz libgvc | 工业级质量，开发成本 → 0 |
| 分析扩展 | 硬编码层次调用 | Pass Pipeline | 可插拔、可并行、依赖自动解析 |
| taint 集合 | `std::set<uint64_t>` | Roaring Bitmap | 亿级集合内存 1/10，交集/并集 100x 快 |
| TUI | ncurses (undecided) | FTXUI | 现代 C++、声明式布局、零全局状态 |

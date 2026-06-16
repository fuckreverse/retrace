# Analysis Layer 详细设计 (v2)

## 概述

Analysis Layer 采用 **LLVM 风格 Pass Pipeline** 架构。每个分析能力是一个独立的 `AnalysisPass`，通过 `PassManager` 统一调度。Pass 之间通过**声明式依赖 + 类型安全结果获取**解耦。

核心优势：
- 新分析能力只需实现一个 Pass 类，注册即可用
- 依赖自动解析，无需手动编排执行顺序
- 无依赖冲突的 Pass 自动并行
- 结果缓存，同一 Pass 不重复运行
- 增量更新：trace 子范围变化时只重跑受影响的 Pass

---

## PassManager 框架

### 核心类

```cpp
// Pass 运行结果的类型擦除容器
class PassResult {
public:
    enum Status { Success, Failed, Skipped };
    Status status;
    std::string error_message;  // 仅 Failed 时有值
    std::any data;              // 类型安全的结果数据

    template<typename T>
    static PassResult success(T&& result) {
        return {Success, {}, std::make_any<T>(std::forward<T>(result))};
    }
    static PassResult failed(std::string msg) {
        return {Failed, std::move(msg), {}};
    }
};

// Pass 执行上下文
class PassContext {
public:
    // === IO 层访问 ===
    TraceReader& reader();
    RocksDBIndex& index();
    CodeTable& code_table();
    SymbolTable& symbols();

    // === Core 层访问 ===
    RegisterFile& regfile();
    MemoryModel& memory();
    TritonBridge& triton();
    InstructionDecoder& decoder();

    // === Pass 间结果获取 ===
    // 获取已完成 Pass 的结果（类型安全）
    template<typename T>
    const T& require(const std::string& pass_name) {
        // PassManager 保证该 pass 已运行完毕（否则会先触发运行）
        return std::any_cast<const T&>(manager_.get_result(pass_name).data);
    }

    // === 分析范围 ===
    struct Range {
        uint64_t start_inst_id;
        uint64_t end_inst_id;
        bool is_full_trace() const;
    };
    Range range() const;

    // === 进度报告 ===
    void progress(float pct);  // 0.0 - 1.0
    void progress(float pct, std::string_view msg);
    bool cancelled() const;  // 用户取消

private:
    PassManager& manager_;
    Range range_;
};

// Pass 基类
class AnalysisPass {
public:
    virtual ~AnalysisPass() = default;

    // === 元信息（编译期确定）===
    virtual std::string_view name() const = 0;
    virtual std::string_view description() const = 0;
    virtual std::vector<std::string_view> dependencies() const { return {}; }

    // === 执行 ===
    virtual PassResult run(PassContext& ctx) = 0;

    // === 可选：增量更新 ===
    virtual bool supports_incremental() const { return false; }
    virtual PassResult update(PassContext& ctx,
                             const PassContext::Range& changed_range) {
        return run(ctx);  // 默认：全量重跑
    }

    // === 可选：估算开销（用于调度优先级）===
    virtual float estimated_cost(const PassContext& ctx) const { return 1.0f; }
};

// PassManager：注册 + 调度 + 缓存
class PassManager {
public:
    // 注册 Pass（通常在 main() 中完成）
    void register_pass(std::unique_ptr<AnalysisPass> pass);

    // 按需执行：如果未运行则运行（递归解析依赖链）
    const PassResult& require(const std::string_view pass_name);

    // 并行执行所有已注册的 Pass（按 DAG 拓扑序 + 线程池）
    void run_all(size_t num_threads = std::thread::hardware_concurrency());

    // 使缓存失效（触发下次 require 时重跑）
    void invalidate(const std::string_view pass_name);
    void invalidate_all();

    // 设置分析范围（影响所有 Pass 的 ctx.range()）
    void set_range(uint64_t start, uint64_t end);

    // 查询状态
    enum PassState { NotRun, Running, Completed, Failed };
    PassState state(const std::string_view pass_name) const;
    std::vector<std::string_view> all_passes() const;

private:
    struct PassEntry {
        std::unique_ptr<AnalysisPass> pass;
        PassResult result;
        PassState state = NotRun;
    };
    std::unordered_map<std::string_view, PassEntry> passes_;

    // DAG 调度
    std::vector<std::vector<std::string_view>> topological_levels();
    void execute_level(std::vector<std::string_view>& level, size_t num_threads);
};
```

### Pass 注册示例

```cpp
int main(int argc, char** argv) {
    // ... 初始化 IO 和 Core ...

    PassManager pm;

    // 注册内置 Pass
    pm.register_pass(std::make_unique<IndexBuildPass>());
    pm.register_pass(std::make_unique<XRefPass>());
    pm.register_pass(std::make_unique<TaintPass>());
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<CFGLayoutPass>());
    pm.register_pass(std::make_unique<StringPass>());
    pm.register_pass(std::make_unique<PatternPass>());
    pm.register_pass(std::make_unique<CallGraphPass>());
    pm.register_pass(std::make_unique<SlicePass>());

    // 用户自定义 Pass（未来：从 .so 动态加载）
    // pm.register_pass(load_plugin("my_analysis.so"));

    // 按需执行
    const auto& taint = pm.require<TaintResult>("taint");
    // → 自动触发：IndexBuildPass → XRefPass → TaintPass
}
```

---

## 内置 Pass 详细设计

### IndexBuildPass

**依赖**：无
**输出**：`IndexBuildResult`（标记构建完成，RocksDB 数据通过 `ctx.index()` 访问）

```cpp
struct IndexBuildResult {
    uint64_t inst_count;
    uint64_t anchor_count;
    uint64_t unique_pcs;
    uint64_t unique_mem_pages;
    double build_time_seconds;
    bool was_cached;  // 是否使用了已有缓存
};

class IndexBuildPass : public AnalysisPass {
public:
    std::string_view name() const override { return "index_build"; }
    std::string_view description() const override {
        return "Build RocksDB inverted indices from raw trace";
    }

    PassResult run(PassContext& ctx) override {
        // 如果缓存有效，直接返回
        if (ctx.index().is_valid_for(ctx.reader())) {
            return PassResult::success(IndexBuildResult{
                .was_cached = true, ...
            });
        }
        // 否则全量构建（顺序扫描 + batch write）
        IndexBuilder builder;
        builder.build(ctx.reader(), ctx.index(), [&](float pct) {
            ctx.progress(pct);
        });
        return PassResult::success(IndexBuildResult{...});
    }
};
```

---

### XRefPass

**依赖**：`index_build`
**输出**：`XRefResult`

XRef 提供 Use-Def / Def-Use 链。利用 Triton 语义和 RocksDB 索引加速。

```cpp
struct XRefResult {
    // 寄存器 XRef：reg_index + inst_id → 定义/使用链
    // 不预构建全局表（太大），而是提供按需查询接口

    // 查询：inst_id 的 reg_index 来自哪里（Use-Def）
    uint64_t reg_defined_by(uint64_t inst_id, uint8_t reg_index) const;

    // 查询：inst_id 写入的 reg_index 被谁使用（Def-Use）
    std::vector<uint64_t> reg_used_by(uint64_t inst_id, uint8_t reg_index) const;

    // 内存 XRef：利用 RocksDB mem_write/mem_read 索引
    uint64_t mem_defined_by(uint64_t addr, uint8_t size, uint64_t at_inst_id) const;
    std::vector<uint64_t> mem_used_by(uint64_t addr, uint8_t size,
                                       uint64_t after_inst_id) const;
};

class XRefPass : public AnalysisPass {
public:
    std::string_view name() const override { return "xref"; }
    std::vector<std::string_view> dependencies() const override {
        return {"index_build"};
    }

    PassResult run(PassContext& ctx) override {
        // XRef 是"按需计算"模型，run() 只构建加速结构
        // 实际查询时利用：
        //   - 寄存器 XRef：从目标 inst 向前扫描 diff 链
        //   - 内存 XRef：RocksDB mem_write CF 直接查
        return PassResult::success(XRefResult{ctx.index(), ctx.regfile()});
    }
};
```

**寄存器 Use-Def 算法**：

```
reg_defined_by(inst_id=162718, reg=x24):
  从 inst_id=162718 向前逐条检查 diff：
    if inst[id-1].reg_diffs contains x24 → return id-1
    if inst[id-2].reg_diffs contains x24 → return id-2
    ...
  性能：平均回溯 <100 条即命中（寄存器活跃间隔短）
  优化：如果需要跨越 anchor 边界，用 RocksDB 加速跳转
```

**内存 Use-Def 算法**：

```
mem_defined_by(addr=0x7fec60ebd9, size=1, at_inst_id=162718):
  1. page = addr >> 12
  2. writers_bitmap = index.mem_writers(page)
  3. 在 bitmap 中找 <= 162718 的最大 inst_id（Roaring 支持 rank/select）
  4. 验证该 inst 确实写了精确地址
  复杂度：O(1) RocksDB lookup + O(log N) bitmap rank
```

---

### TaintPass

**依赖**：`xref`
**输出**：`TaintResult`

核心：通过 Triton TaintEngine 做精确的正向/逆向污点传播。

```cpp
struct TaintSource {
    enum Kind { Register, Memory } kind;
    uint64_t inst_id;       // 污点起始指令
    uint8_t reg_index;      // kind==Register 时有效
    uint64_t mem_addr;      // kind==Memory 时有效
    uint8_t mem_size;
};

struct TaintConfig {
    TaintSource source;
    enum Direction { Forward, Backward } direction;
    uint64_t max_steps = 1000000;
    uint64_t max_taint_width = 64;  // 最大同时被污染的寄存器/内存数
    bool stop_at_function_boundary = false;
    std::vector<uint64_t> stop_pcs;   // 遇到这些 PC 停止
    bool propagate_through_memory = true;
    bool propagate_through_calls = true;
};

struct TaintResult {
    roaring::Roaring64Map tainted_insts;  // 被污染的指令集合
    struct PropagationStep {
        uint64_t inst_id;
        enum Event { RegToReg, RegToMem, MemToReg, MemToMem, Kill } event;
        uint8_t src_reg;  // 源寄存器（如适用）
        uint8_t dst_reg;  // 目标寄存器（如适用）
        uint64_t addr;    // 涉及的内存地址（如适用）
    };
    std::vector<PropagationStep> propagation_log;  // 详细传播日志
    uint64_t steps_executed;
    bool reached_limit;
    std::string stop_reason;
};

class TaintPass : public AnalysisPass {
public:
    std::string_view name() const override { return "taint"; }
    std::vector<std::string_view> dependencies() const override {
        return {"xref"};
    }

    // TaintPass 是"按需触发"型：用户选择 source 后才运行
    // run() 只是标记 ready
    PassResult run(PassContext& ctx) override;

    // 实际的 taint 计算（由 UI 层触发）
    TaintResult compute(PassContext& ctx, const TaintConfig& config);
};
```

**正向污点传播算法**：

```cpp
TaintResult TaintPass::forward_taint(PassContext& ctx, const TaintConfig& cfg) {
    TaintResult result;
    auto triton_ctx = ctx.triton().acquire();

    // 设置初始污点
    if (cfg.source.kind == TaintSource::Register)
        ctx.triton().taint_reg(triton_ctx, cfg.source.reg_index);
    else
        ctx.triton().taint_mem(triton_ctx, cfg.source.mem_addr, cfg.source.mem_size);

    uint64_t current_id = cfg.source.inst_id;
    uint64_t steps = 0;

    while (steps < cfg.max_steps && current_id < ctx.range().end_inst_id) {
        if (ctx.cancelled()) break;

        // 获取当前指令语义
        const auto& regs = ctx.regfile().state_before(current_id);
        uint64_t pc = regs.pc();
        auto opcode = ctx.code_table().opcode_at(pc);
        if (!opcode) { ++current_id; continue; }

        // 加速：通过语义缓存判断该指令是否可能传播污点
        const auto& sem = ctx.triton().semantics(pc, *opcode);
        if (!could_propagate(triton_ctx, sem)) {
            // 该指令不读任何被污染的源 → 跳过 Triton replay
            ++current_id; ++steps;
            continue;
        }

        // Triton replay（含污点传播）
        ctx.triton().replay(triton_ctx, pc, *opcode, regs, ctx.memory());

        // 收集新被污染的目标
        for (uint8_t reg : sem.regs_written) {
            if (ctx.triton().is_reg_tainted(triton_ctx, reg)) {
                result.tainted_insts.add(current_id);
                result.propagation_log.push_back({current_id, ...});
            }
        }

        // 检查终止条件
        if (auto it = std::find(cfg.stop_pcs.begin(), cfg.stop_pcs.end(), pc);
            it != cfg.stop_pcs.end()) {
            result.stop_reason = "reached stop PC";
            break;
        }

        ++current_id; ++steps;
    }

    result.steps_executed = steps;
    result.reached_limit = (steps >= cfg.max_steps);
    return result;
}
```

**XRef 加速跳跃**：

在正向传播中，如果当前污点集只在寄存器 x2 上，而接下来 100 条指令都不读 x2，传统逐条遍历是浪费的。优化方案：

```
优化：
  current_taint_set = {x2}
  next_use = xref.next_reader_of(current_id, x2)
  if (next_use - current_id > 100):
    jump to next_use directly (skip 100 instructions)
```

这使得稀疏传播的性能与 **tainted 指令数**成正比，而非与 trace 长度成正比。

---

### CFGPass

**依赖**：`index_build`
**输出**：`CFGResult`

从动态 trace 恢复函数级 CFG。天然解决间接跳转（因为有实际执行的目标地址）。

```cpp
struct BasicBlock {
    uint64_t id;              // 块 ID
    uint64_t start_pc;        // 块起始 PC
    uint64_t end_pc;          // 块末尾 PC
    uint32_t inst_count;      // 块内指令数
    uint64_t exec_count;      // 执行次数（从 trace 统计）
    bool is_entry;
    bool is_exit;
};

struct Edge {
    uint64_t from_block;
    uint64_t to_block;
    enum Type { FallThrough, ConditionalTrue, ConditionalFalse,
                Unconditional, Indirect, BackEdge } type;
    uint64_t exec_count;      // 该边的执行次数
};

struct Loop {
    uint64_t header_block_id;
    std::vector<uint64_t> body_block_ids;
    uint64_t back_edge_from;
    uint64_t iteration_count;  // 从 exec_count 推断
};

struct CFGResult {
    struct FunctionCFG {
        uint64_t entry_pc;
        std::string name;  // 从 SymbolTable
        std::vector<BasicBlock> blocks;
        std::vector<Edge> edges;
        std::vector<Loop> loops;
    };

    std::unordered_map<uint64_t/*entry_pc*/, FunctionCFG> functions;

    // 按需构建（不预构建所有函数的 CFG）
    const FunctionCFG& get_or_build(uint64_t func_entry_pc);
};

class CFGPass : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg"; }
    std::vector<std::string_view> dependencies() const override {
        return {"index_build"};
    }

    PassResult run(PassContext& ctx) override;
};
```

**CFG 构建算法**：

```
build_cfg(entry_pc):
  1. 从 RocksDB "pc" CF 获取 entry_pc 的所有 inst_id
  2. 从第一个 inst_id 开始，顺序遍历属于该函数的指令
     （通过 CallStack 识别函数边界，或通过 return 指令判断）
  3. 识别基本块边界：
     - 分支/跳转指令的目标 → 新块起始
     - 被跳转到的地址 → 新块起始
     - 函数调用后的下一条 → 新块起始（可选）
  4. 对每个 PC transition (from_pc → to_pc)：
     - 确定 from_block 和 to_block
     - 添加 Edge，类型由 from_pc 的指令类型决定
     - exec_count++
  5. 循环识别：Tarjan SCC 或 自然循环检测（back edge = 边的终点 dominates 起点）
```

---

### CFGLayoutPass

**依赖**：`cfg`
**输出**：`CFGLayoutResult`

使用 **Graphviz libgvc** 做 Sugiyama 分层布局，获取每个节点的坐标。

```cpp
struct BlockLayout {
    uint64_t block_id;
    double x, y;             // 布局坐标
    double width, height;    // 节点尺寸
    uint32_t layer;          // 分层编号
};

struct EdgeRoute {
    uint64_t from_block;
    uint64_t to_block;
    std::vector<std::pair<double, double>> control_points;  // 贝塞尔控制点
};

struct CFGLayoutResult {
    std::unordered_map<uint64_t/*func_entry*/, FunctionLayout> layouts;

    struct FunctionLayout {
        std::vector<BlockLayout> blocks;
        std::vector<EdgeRoute> edges;
        double total_width, total_height;
    };
};

class CFGLayoutPass : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg_layout"; }
    std::vector<std::string_view> dependencies() const override {
        return {"cfg"};
    }

    PassResult run(PassContext& ctx) override {
        const auto& cfg_result = ctx.require<CFGResult>("cfg");
        CFGLayoutResult layout_result;

        for (auto& [entry_pc, func_cfg] : cfg_result.functions) {
            layout_result.layouts[entry_pc] = layout_function(func_cfg);
        }
        return PassResult::success(std::move(layout_result));
    }

private:
    FunctionLayout layout_function(const CFGResult::FunctionCFG& cfg) {
        // 1. 构建 Graphviz 图
        Agraph_t* g = agopen("cfg", Agdirected, nullptr);
        agattr(g, AGRAPH, "rankdir", "TB");  // Top-to-Bottom

        // 2. 添加节点
        for (auto& block : cfg.blocks) {
            auto node_name = std::to_string(block.id);
            Agnode_t* n = agnode(g, node_name.c_str(), TRUE);
            // 节点大小基于指令数
            auto h = std::to_string(0.3 + block.inst_count * 0.15);
            agset(n, "height", h.c_str());
        }

        // 3. 添加边
        for (auto& edge : cfg.edges) {
            auto from_name = std::to_string(edge.from_block);
            auto to_name = std::to_string(edge.to_block);
            Agnode_t* from = agnode(g, from_name.c_str(), FALSE);
            Agnode_t* to = agnode(g, to_name.c_str(), FALSE);
            Agedge_t* e = agedge(g, from, to, nullptr, TRUE);
            if (edge.type == Edge::BackEdge)
                agset(e, "constraint", "false");  // 回边不影响层次
        }

        // 4. 运行 dot 布局
        GVC_t* gvc = gvContext();
        gvLayout(gvc, g, "dot");

        // 5. 提取坐标
        FunctionLayout result;
        for (auto& block : cfg.blocks) {
            auto* n = agnode(g, std::to_string(block.id).c_str(), FALSE);
            auto pos = ND_coord(n);
            result.blocks.push_back({block.id, pos.x, pos.y, ...});
        }

        // 6. 提取边路由
        // ... 从 Graphviz spline 数据提取控制点 ...

        gvFreeLayout(gvc, g);
        agclose(g);
        gvFreeContext(gvc);
        return result;
    }
};
```

**DOT/SVG 导出**：

```cpp
// 额外功能：导出为文件（给外部工具使用）
void export_dot(const CFGResult::FunctionCFG& cfg, const std::string& path);
void export_svg(const CFGResult::FunctionCFG& cfg, const std::string& path);
```

---

### StringPass

**依赖**：无（直接使用 MemoryModel）
**输出**：`StringResult`

```cpp
struct StringRef {
    uint64_t addr;
    uint32_t length;
    enum Encoding { ASCII, UTF8, UTF16LE, UTF16BE } encoding;
    std::string value;          // 解码后的字符串
    uint64_t first_write_id;    // 第一次写入该区域的 inst_id
    uint64_t first_read_id;     // 第一次读取该区域的 inst_id
};

struct StringResult {
    std::vector<StringRef> strings;  // 按 first_read_id 排序

    // 搜索
    std::vector<size_t> search(std::string_view pattern) const;
    std::vector<size_t> search_regex(std::string_view regex) const;
};

class StringPass : public AnalysisPass {
public:
    std::string_view name() const override { return "string"; }
    // 无依赖：直接使用 Core 层

    PassResult run(PassContext& ctx) override {
        // 策略：扫描 trace 末尾时刻的内存最终快照
        // 这自然绕过了运行时解密——因为看到的是解密后的明文
        StringResult result;
        scan_memory_for_strings(ctx.memory(), ctx.range().end_inst_id, result);
        return PassResult::success(std::move(result));
    }
};
```

---

### PatternPass

**依赖**：`string`
**输出**：`PatternResult`

识别密码学算法、反调试模式等。内置特征库 + 可扩展规则。

```cpp
struct PatternMatch {
    std::string pattern_name;    // e.g. "AES S-Box", "SHA-256 K constants"
    uint64_t addr;               // 匹配到的地址
    float confidence;            // 0.0 - 1.0
    std::string description;
    std::vector<uint64_t> related_insts;  // 使用该数据的指令
};

struct PatternResult {
    std::vector<PatternMatch> matches;
};

class PatternPass : public AnalysisPass {
public:
    std::string_view name() const override { return "pattern"; }
    std::vector<std::string_view> dependencies() const override {
        return {"string"};  // 利用 StringPass 的扫描结果
    }

    PassResult run(PassContext& ctx) override;

    // 可扩展：注册自定义模式
    void register_pattern(std::string name, std::vector<uint8_t> signature,
                         float min_confidence);

private:
    // 内置特征库
    struct PatternDef {
        std::string name;
        std::vector<uint8_t> signature;  // 特征字节
        std::string description;
    };
    std::vector<PatternDef> builtin_patterns_ = {
        {"AES S-Box", {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...}, "AES SubBytes lookup table"},
        {"SHA-256 K", {0x42, 0x8a, 0x2f, 0x98, ...}, "SHA-256 round constants"},
        {"Base64 table", {'A','B','C','D','E','F', ...}, "Standard Base64 encoding table"},
        // ...
    };
};
```

---

### CallGraphPass

**依赖**：`cfg`
**输出**：`CallGraphResult`

```cpp
struct CallGraphResult {
    struct CallSite {
        uint64_t caller_pc;     // 调用指令的 PC
        uint64_t callee_entry;  // 被调用函数入口
        uint64_t call_count;    // 调用次数
        uint64_t first_call_inst_id;
    };
    std::vector<CallSite> call_sites;

    // 查询
    std::vector<uint64_t> callees_of(uint64_t func_entry) const;
    std::vector<uint64_t> callers_of(uint64_t func_entry) const;
};
```

---

### SlicePass

**依赖**：`xref`, `taint`
**输出**：`SliceResult`

程序切片：给定一个变量（寄存器/内存位置）在某个 inst_id 的值，
找出所有影响该值的指令（backward slice）或被该值影响的指令（forward slice）。

```cpp
struct SliceResult {
    roaring::Roaring64Map slice_insts;  // 切片中的指令集合
    // 切片是 taint 的"精确版"——只保留真正的数据依赖链
};

class SlicePass : public AnalysisPass {
public:
    std::string_view name() const override { return "slice"; }
    std::vector<std::string_view> dependencies() const override {
        return {"xref", "taint"};
    }

    SliceResult compute_backward_slice(PassContext& ctx,
                                       uint64_t inst_id, uint8_t reg_index);
    SliceResult compute_forward_slice(PassContext& ctx,
                                      uint64_t inst_id, uint8_t reg_index);
};
```

---

## Pass 并行调度

```
依赖 DAG:

Level 0: [IndexBuildPass]
Level 1: [XRefPass, CFGPass, StringPass]    ← 这三个可并行
Level 2: [TaintPass, CFGLayoutPass, PatternPass, CallGraphPass]  ← 可并行
Level 3: [SlicePass]

执行策略：
  thread_pool(num_threads = 4)
  for each level:
    submit all passes in level to thread_pool
    wait_all()
```

---

## 自定义 Pass 开发指南

用户编写新的分析 Pass 只需：

```cpp
#include <tenet/analysis/pass.h>

class MyCustomPass : public AnalysisPass {
public:
    std::string_view name() const override { return "my_analysis"; }
    std::string_view description() const override {
        return "My custom analysis pass";
    }
    std::vector<std::string_view> dependencies() const override {
        return {"xref"};  // 需要 XRef 结果
    }

    PassResult run(PassContext& ctx) override {
        const auto& xref = ctx.require<XRefResult>("xref");
        // ... 使用 xref + ctx.regfile() + ctx.triton() 做分析 ...
        return PassResult::success(MyResult{...});
    }
};

// 注册
pm.register_pass(std::make_unique<MyCustomPass>());
```

---

## 性能预算

| Pass | 100M trace 预期耗时 | 内存占用 | 说明 |
|------|---------------------|----------|------|
| IndexBuild | ~60s（首次）/ 0（缓存） | ~50MB 峰值 | RocksDB batch write |
| XRef | ~0（按需） | ~10MB 缓存 | 查询时实时计算 |
| Taint (10K steps) | ~50ms | ~5MB | Triton + Roaring |
| CFG (单函数) | ~200ms | ~10MB | PC 索引 + 遍历 |
| CFGLayout | ~500ms | ~20MB | Graphviz 内部分配 |
| String | ~30s | ~100MB 峰值 | 全内存扫描 |
| Pattern | ~5s | ~10MB | 特征匹配 |

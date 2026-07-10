# Scan Fusion 接线 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 8 个扫描型 pass 通过 `declare_scan()` 注册 collector 到 `ScanOrchestrator`，实现单次 trace 扫描服务所有 collector。

**Architecture:** 扩展 `declare_scan()` 签名传入 `PassContext&`，新增 `has_scan()` 虚方法。PassManager 在 `run_all()` Phase 1 和 `execute_pass()` (require 路径) 中编排扫描。每个 pass 将 collector 从 `run()` 局部变量提升为类成员，`declare_scan()` 构造并注册，`run()` 只读结果。

**Tech Stack:** C++20, CMake, Ninja, Catch2/GTest

**Spec:** `docs/superpowers/specs/2026-07-10-scan-fusion-wiring-design.md`

## Global Constraints

- 固定 build 目录：`tools/tenet/build/`（禁止新建 build 目录）
- 增量编译：`cd tools/tenet/build && ninja -j$(nproc)`
- 测试：`cd tools/tenet/build && ctest --output-on-failure`
- 不删除 `_deps/` 目录
- 所有地址使用运行时地址（含 ASLR slide）
- Pass 名称用下划线小写

## File Structure

| 文件 | 改动 | 职责 |
|------|------|------|
| `src/analysis/pass_manager.h` | Modify | 扩展 `declare_scan()` 签名，新增 `has_scan()`，`PassEntry` 加 `scan_executed`，移除死代码 |
| `src/analysis/pass_manager.cpp` | Modify | `run_all()` Phase 1 传 ctx，`execute_pass()` 加扫描编排，移除死代码 |
| `src/analysis/passes/crypto/pattern_pass.h` | Modify | 加 `has_scan()`, `declare_scan()`, `collector_` 成员 |
| `src/analysis/passes/crypto/pattern_pass.cpp` | Modify | 迁移 collector 构造到 `declare_scan()`，`run()` 只读结果 |
| `src/analysis/passes/structure/function_pass.h` | Modify | 同上 |
| `src/analysis/passes/structure/function_pass.cpp` | Modify | 同上 |
| `src/analysis/passes/structure/cfg_pass.cpp` | Modify | 同上（collector 在 cpp 中定义） |
| `src/analysis/passes/memory/memory_string_pass.h` | Modify | 同上 |
| `src/analysis/passes/memory/memory_string_pass.cpp` | Modify | 迁移 Phase 1 扫描到 `declare_scan()`，Phase 2 保留在 `run()` |
| `src/analysis/passes/memory/string_pass.cpp` | Modify | 同上（Phase 1/2 分离） |
| `src/analysis/passes/platform/syscall_intercept_pass.h` | Modify | 同上 |
| `src/analysis/passes/platform/syscall_intercept_pass.cpp` | Modify | 同上 |
| `src/analysis/passes/misc/thread_pass.h` | Modify | 同上 |
| `src/analysis/passes/misc/thread_pass.cpp` | Modify | 同上 |
| `src/analysis/passes/profile/window_stats_pass.cpp` | Modify | 同上（collector 在 cpp 中定义） |

---

### Task 1: 扩展 AnalysisPass 基类接口

**Files:**
- Modify: `tools/tenet/src/analysis/pass_manager.h`
- Modify: `tools/tenet/src/analysis/pass_manager.cpp`

**Interfaces:**
- Produces: `AnalysisPass::declare_scan(ScanOrchestrator&, PassContext&)` — 新签名（替换旧的单参数版本）
- Produces: `AnalysisPass::has_scan() const` — 虚方法，默认 false
- Produces: `PassEntry::scan_executed` — bool 字段，默认 false
- Removes: `PassContext::scan_engine()`, `PassContext::set_scan_engine()`, `PassContext::make_scan_engine()`, `PassManager::scan_engine_` 成员

- [ ] **Step 1: 修改 `declare_scan()` 签名并新增 `has_scan()`**

在 `tools/tenet/src/analysis/pass_manager.h` 中，找到 `AnalysisPass` 类的 `declare_scan` 方法（约第 180 行附近）：

```cpp
    /// Declare scan collector requirements for Scan Fusion (default: none).
    /// Override to participate in unified trace scanning.
    /// Called before run() phase, after all passes are registered.
    virtual void declare_scan(class ScanOrchestrator& orchestrator) { (void)orchestrator; }
```

替换为：

```cpp
    /// Declare scan collector requirements for Scan Fusion (default: none).
    /// Override to participate in unified trace scanning.
    /// Called before run() phase, after all passes are registered.
    virtual void declare_scan(class ScanOrchestrator& orchestrator, PassContext& ctx) {
        (void)orchestrator; (void)ctx;
    }

    /// Whether this pass participates in scan fusion.
    /// Default false. Scanning passes override to return true.
    /// PassManager uses this to decide whether to orchestrate scanning
    /// before calling run() in the require() path.
    virtual bool has_scan() const { return false; }
```

- [ ] **Step 2: 在 PassEntry 中新增 `scan_executed` 字段**

在 `tools/tenet/src/analysis/pass_manager.h` 中，找到 `struct PassEntry`（约第 368 行），在 `std::atomic<bool> cancelled{false};` 之后添加：

```cpp
        std::atomic<bool>  cancelled{false};
        bool               scan_executed{false};  // prevents re-scan in require() path
```

- [ ] **Step 3: 移除 PassContext 中的死代码**

在 `tools/tenet/src/analysis/pass_manager.h` 中，找到并删除以下三处：

1. `PassContext` 类中的 `scan_engine()` 声明（约第 147 行）：
```cpp
TraceScanEngine* scan_engine();
```

2. `PassContext` 类中的 `make_scan_engine()` 声明（约第 149-151 行）：
```cpp
/// Create a new TraceScanEngine pre-configured with exclude ranges from AnalysisRange.
/// Passes should prefer this over constructing TraceScanEngine directly.
TraceScanEngine make_scan_engine();
```

3. `PassContext` 类中的 `set_scan_engine()` 和 `scan_engine_` 成员（约第 236-237 行和第 445 行）：
```cpp
void set_scan_engine(TraceScanEngine* e) { scan_engine_ = e; }
TraceScanEngine* scan_engine() { return scan_engine_; }
```
以及：
```cpp
TraceScanEngine* scan_engine_ = nullptr;
```

- [ ] **Step 4: 移除 PassManager 中的死代码实现**

在 `tools/tenet/src/analysis/pass_manager.cpp` 中，找到并删除以下两处：

1. `PassContext::scan_engine()` 实现（约第 61 行）：
```cpp
TraceScanEngine* PassContext::scan_engine() { return manager_.scan_engine(); }
```

2. `PassContext::make_scan_engine()` 实现（约第 63-69 行）：
```cpp
TraceScanEngine PassContext::make_scan_engine() {
    TraceScanEngine engine(reader(), index().inst_count(), &index());
    if (!range_.exclude_pc_ranges.empty()) {
        engine.set_exclude_pc_ranges(range_.exclude_pc_ranges);
    }
    return engine;
}
```

- [ ] **Step 5: 修改 `run_all()` Phase 1 调用签名**

在 `tools/tenet/src/analysis/pass_manager.cpp` 的 `run_all()` 方法中（约第 477-479 行），找到：

```cpp
    if (scan_orchestrator_) {
        for (auto& entry : entries_) {
            entry->pass->declare_scan(*scan_orchestrator_);
        }
```

替换为：

```cpp
    if (scan_orchestrator_) {
        PassContext ctx(*this, range_);
        for (auto& entry : entries_) {
            entry->pass->declare_scan(*scan_orchestrator_, ctx);
        }
```

- [ ] **Step 6: 在 `execute_pass()` 中新增扫描编排**

在 `tools/tenet/src/analysis/pass_manager.cpp` 的 `execute_pass()` 方法中，找到调用 `entry->pass->run(ctx)` 的位置（约第 304-308 行）：

```cpp
    PassContext ctx(*this, range_);
    ctx.pass_name_       = entry->pass->name();
    ctx.progress_pct_    = &entry->progress_pct;
    ctx.cancelled_flag_  = &entry->cancelled;
    PassResult result = entry->pass->run(ctx);
```

在 `PassResult result = entry->pass->run(ctx);` 之前插入扫描编排：

```cpp
    PassContext ctx(*this, range_);
    ctx.pass_name_       = entry->pass->name();
    ctx.progress_pct_    = &entry->progress_pct;
    ctx.cancelled_flag_  = &entry->cancelled;

    // Scan Fusion: if this pass participates in scan fusion and hasn't been
    // scanned yet (require() path), orchestrate a single scan before run().
    // In run_all() path, the scan was already done in Phase 2.
    if (entry->pass->has_scan() && !entry->scan_executed) {
        ScanOrchestrator orch(*reader_, index_->inst_count(), index_);
        entry->pass->declare_scan(orch, ctx);
        if (orch.has_declarations()) {
            orch.execute_scan(range_, cancelled_, no_parallel_scan_);
        }
        entry->scan_executed = true;
    }

    PassResult result = entry->pass->run(ctx);
```

- [ ] **Step 7: 增量编译验证**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) 2>&1 | tail -20`

Expected: 编译报错 — 因为 `pattern_pass.cpp`、`function_pass.cpp`、`syscall_intercept_pass.cpp`、`window_stats_pass.cpp` 中仍调用 `ctx.scan_engine()`。这些将在后续 task 中修复。暂时先注释掉这些调用或等待后续 task 修复。

> 如果编译错误仅来自 pass 文件中 `ctx.scan_engine()` 调用（约 4 处），这是预期的——后续 task 会修复。如果有其他编译错误，需要先修复。

- [ ] **Step 8: 暂时修复编译——注释掉 pass 中的 `ctx.scan_engine()` 调用**

在以下 4 个文件中，找到 `auto* engine = ctx.scan_engine();` 及其 `if (engine) { ... } else { ... }` 双路径，删除 `if (engine)` 分支，只保留 `else` 分支的 `local_engine` 代码（去掉 `else` 和大括号）：

- `src/analysis/passes/crypto/pattern_pass.cpp`（约第 1300 行）
- `src/analysis/passes/structure/function_pass.cpp`（约第 980 行）
- `src/analysis/passes/platform/syscall_intercept_pass.cpp`（约第 1309 行）
- `src/analysis/passes/profile/window_stats_pass.cpp`（约第 406 行）

每个文件的修改模式相同——将：
```cpp
    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        TraceScanEngine local_engine(...);
        ...
        local_engine.run();
    }
```
改为：
```cpp
    {
        TraceScanEngine local_engine(...);
        ...
        local_engine.run();
    }
```

- [ ] **Step 9: 编译并运行测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，所有现有测试通过（行为无变化——只是移除了死代码分支）。

- [ ] **Step 10: Commit**

```bash
git add tools/tenet/src/analysis/pass_manager.h tools/tenet/src/analysis/pass_manager.cpp tools/tenet/src/analysis/passes/crypto/pattern_pass.cpp tools/tenet/src/analysis/passes/structure/function_pass.cpp tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.cpp tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp
git commit -m "refactor(scan-fusion): extend declare_scan signature, add has_scan(), remove dead scan_engine code

- declare_scan() now takes PassContext& so passes can access code_table,
  decoder, regfile etc. for collector construction
- New has_scan() virtual method (default false) lets PassManager know
  which passes participate in scan fusion
- PassEntry::scan_executed prevents re-scan in require() path
- Remove dead code: PassContext::scan_engine() / make_scan_engine() /
  set_scan_engine() — never worked (set_scan_engine never called)
- Remove dead if(ctx.scan_engine()) branches in 4 passes
- execute_pass() now orchestrates scan for require() path"
```

---

### Task 2: 迁移 thread_pass（最简单的 pass）

**Files:**
- Modify: `tools/tenet/src/analysis/passes/misc/thread_pass.h`
- Modify: `tools/tenet/src/analysis/passes/misc/thread_pass.cpp`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::reader()`, `PassContext::index()`
- Produces: `ThreadPass::has_scan() == true`, `ThreadPass::declare_scan()`, `ThreadPass::collector_`

- [ ] **Step 1: 修改 thread_pass.h**

在 `tools/tenet/src/analysis/passes/misc/thread_pass.h` 中：

1. 在类定义中添加 `has_scan()` 和 `declare_scan()` 声明，以及 `collector_` 成员。找到 `ThreadPass` 类的 `run()` 方法声明附近，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
```

2. 在 `private:` 区域添加成员（如果 `ThreadCollector` 的 include 在 .h 中则直接用，否则需要 forward declare 或 include）。在文件顶部确认有 `#include "thread_pass.h"` 中的 `ThreadCollector` 定义（它在同一个 .h 文件中，所以可直接用）：

```cpp
private:
    std::unique_ptr<ThreadCollector> collector_;
```

3. 在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/misc/thread_pass.cpp` 中，在 `ThreadPass::run()` 之前添加：

```cpp
void ThreadPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    collector_ = std::make_unique<ThreadCollector>();
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

确保文件顶部有 `#include "infra/scan_orchestrator.h"`。

- [ ] **Step 3: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/misc/thread_pass.cpp` 的 `ThreadPass::run()` 中，找到创建 local engine 的部分（约第 283-295 行）：

```cpp
    ThreadCollector collector;
    TraceScanEngine engine(reader, index.inst_count());
    if (!ctx.range().exclude_pc_ranges.empty()) {
        engine.set_exclude_pc_ranges(ctx.range().exclude_pc_ranges);
    }
    engine.add_collector(&collector);
    engine.set_progress([&ctx, total = end - start](uint64_t processed, uint64_t /*total_arg*/) {
        if (total > 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }
    });
    engine.set_cancel_check([&ctx]() { return ctx.cancelled(); });
    engine.run(start, end);
```

替换为：

```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }
```

然后找到使用 `collector.result` 的部分（约第 298-309 行），将 `collector.result` 改为 `collector_->result`：

```cpp
    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = thread_serialize(collector_->result);
        if (!blob.empty()) {
            index.save_pass_blob("thread", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Thread: {} threads, {} switches, {} spans",
                                    collector_->result.thread_count(),
                                    collector_->result.switch_count(),
                                    collector_->result.spans.size()));
    return PassResult::success(std::move(collector_->result));
```

> 注意：`ThreadCollector` 直接暴露 `result` 成员（不是 `take_result()` 方法），因此用 `collector_->result`。

- [ ] **Step 4: 编译并运行 thread 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R thread --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，thread 相关测试通过。

- [ ] **Step 5: 运行完整测试套件确认无回归**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ctest --output-on-failure 2>&1 | tail -10`

Expected: 全部通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/misc/thread_pass.h tools/tenet/src/analysis/passes/misc/thread_pass.cpp
git commit -m "feat(scan-fusion): migrate thread_pass to declare_scan

ThreadPass now overrides has_scan() and declare_scan(). The collector
is constructed in declare_scan() and registered with ScanOrchestrator.
run() reads results from collector_ instead of creating a local
TraceScanEngine."
```

---

### Task 3: 迁移 cfg_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/structure/cfg_pass.cpp`（collector 在 cpp 中定义）
- Read-only: `tools/tenet/src/analysis/passes/structure/cfg_pass.h`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::reader()`, `PassContext::index()`
- Produces: `CfgPass::has_scan() == true`, `CfgPass::declare_scan()`, `CfgPass::collector_`
- Note: `CFGEdgeCollector` supports parallel scanning (`supports_parallel() == true`)

- [ ] **Step 1: 在 cfg_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/structure/cfg_pass.h` 中，找到 `CfgPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（需要 forward declare `CFGEdgeCollector` 或 include 它的定义。由于 `CFGEdgeCollector` 定义在 .cpp 中，用 forward declare）：

```cpp
private:
    class CFGEdgeCollector;  // forward declare (defined in .cpp)
    std::unique_ptr<CFGEdgeCollector> collector_;
```

> 注意：如果 `CFGEdgeCollector` 已经在 .h 中声明就不需要 forward declare。检查 .h 文件确认。如果它只在 .cpp 中定义，则在 .h 中 forward declare，并在 .cpp 中通过 `class CfgPass::CFGEdgeCollector` 访问。但更简单的方案是：由于 `CFGEdgeCollector` 目前是 .cpp 中的匿名/命名空间类，我们需要把它的声明提到 .h 中或使用 `std::unique_ptr` 的 deleter 技巧。
>
> **最简方案**：在 .h 中只声明 `void* collector_storage_` 或使用 `std::any`。但这不干净。
>
> **推荐方案**：将 `CFGEdgeCollector` 的类声明移到 `cfg_pass.h` 中（或至少 forward declare），实现在 .cpp 中保持。检查现有代码——如果 `CFGEdgeCollector` 在 .cpp 的匿名命名空间中，需要把它移到 `tenet` 命名空间下并 forward declare。

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 确保 CFGEdgeCollector 可被 forward declare**

在 `tools/tenet/src/analysis/passes/structure/cfg_pass.cpp` 中，检查 `CFGEdgeCollector` 的定义位置。如果它在匿名命名空间中：

```cpp
namespace {
class CFGEdgeCollector final : public TraceCollector { ... };
}
```

需要改为命名空间内定义：

```cpp
class CfgPass::CFGEdgeCollector final : public TraceCollector { ... };
```

并在 `cfg_pass.h` 中声明为 `CfgPass` 的嵌套类（forward declare）。

如果 `CFGEdgeCollector` 已经在命名空间中（非匿名），只需在 .h 中 forward declare 即可。

- [ ] **Step 3: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/structure/cfg_pass.cpp` 中，在 `CfgPass::run()` 之前添加：

```cpp
void CfgPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    // CFGEdgeCollector needs a pointer to the result to fill in.
    // We'll allocate the result here and pass it to the collector.
    // run() will retrieve it.
    // Note: CFGEdgeCollector supports parallel scanning.
    // However, we need the result object to persist until run().
    // Store it as part of collector_.
    collector_ = std::make_unique<CFGEdgeCollector>(/* same args as in run() */);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/true});
}
```

> **重要**：需要检查 `CFGEdgeCollector` 的构造函数。根据 Step 2 中看到的代码 `CFGEdgeCollector collector(&result);`，它接收一个 `CFGResult*` 指针。因此需要一个持久化的 `CFGResult` 对象。在 `declare_scan()` 中不能创建局部 `result`，需要将其作为 pass 成员或嵌入 collector 中。
>
> **方案**：将 `CFGResult result` 也作为 `CfgPass` 的成员，`declare_scan()` 中构造 collector 传入 `&result_`，`run()` 中从 `result_` 取结果。或者让 `CFGEdgeCollector` 内部持有 result。

- [ ] **Step 4: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/structure/cfg_pass.cpp` 的 `CfgPass::run()` 中，找到创建 engine 和 collector 的部分（约第 460-475 行），删除 local engine 创建：

```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    auto& edge_counts = collector_->edge_counts;
```

删除以下代码：
```cpp
    CFGEdgeCollector collector(&result);
    TraceScanEngine engine(reader, index.inst_count(), &index);
    if (!ctx.range().exclude_pc_ranges.empty()) {
        engine.set_exclude_pc_ranges(ctx.range().exclude_pc_ranges);
    }
    engine.add_collector(&collector);
    engine.set_progress(...);
    engine.set_cancel_check(...);
    engine.set_cancel_token(...);
    if (ctx.no_parallel_scan()) {
        engine.run(start, end);
    } else {
        engine.run_parallel(start, end);
    }

    auto& edge_counts = collector.edge_counts;
```

- [ ] **Step 5: 编译并运行 cfg 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R cfg --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，cfg 相关测试通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/structure/cfg_pass.h tools/tenet/src/analysis/passes/structure/cfg_pass.cpp
git commit -m "feat(scan-fusion): migrate cfg_pass to declare_scan

CfgPass now overrides has_scan() and declare_scan(). CFGEdgeCollector
supports parallel scanning. run() reads edge_counts from collector_
instead of creating a local TraceScanEngine."
```

---

### Task 4: 迁移 pattern_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/crypto/pattern_pass.h`
- Modify: `tools/tenet/src/analysis/passes/crypto/pattern_pass.cpp`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::code_table()`, `PassContext::decoder()`, `PassContext::regfile()`, `PassContext::reader()`
- Produces: `PatternPass::has_scan() == true`, `PatternPass::declare_scan()`, `PatternPass::collector_`
- Note: `PatternCollector` constructor needs: code_table, decoder, regfile_ptr, has_yara, constmat_min_parts, target_os

- [ ] **Step 1: 在 pattern_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/crypto/pattern_pass.h` 中，找到 `PatternPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`PatternCollector` 定义在同一个 .h 中）：

```cpp
private:
    std::unique_ptr<PatternCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/crypto/pattern_pass.cpp` 中，在 `PatternPass::run()` 之前添加：

```cpp
void PatternPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();
    auto& reader = ctx.reader();

    // regfile is only needed when building YARA syscall buffers
    bool has_yara = load_rules();  // load_rules() is an existing method
    RegisterFile* regfile_ptr = has_yara ? &ctx.regfile() : nullptr;

    collector_ = std::make_unique<PatternCollector>(
        code_table, decoder, regfile_ptr, has_yara, constmat_min_parts_,
        static_cast<uint32_t>(reader.header().target_os));
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

> 注意：`load_rules()` 是 `PatternPass` 的成员方法，在原 `run()` 中已调用。`constmat_min_parts_` 是 pass 成员变量。需要确认 `load_rules()` 不依赖 `PassContext`——如果它只加载 YARA 规则文件，应该安全。

- [ ] **Step 3: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/crypto/pattern_pass.cpp` 的 `PatternPass::run()` 中，找到创建 collector 和 engine 的部分（约第 1289-1315 行），删除 collector 构造和 engine 创建：

替换以下代码：
```cpp
    // Phase 1: Load YARA rules
    bool has_yara = load_rules();

    // Phase 2: Set up collector and run scan
    ctx.progress(0.0f, "Pattern: scanning trace...");

    // regfile is only needed when building YARA syscall buffers
    RegisterFile* regfile_ptr = has_yara ? &ctx.regfile() : nullptr;
    PatternCollector collector(code_table, decoder, regfile_ptr, has_yara, constmat_min_parts_,
                               static_cast<uint32_t>(reader.header().target_os));

    {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress(...);
        local_engine.set_cancel_check(...);
        local_engine.set_cancel_token(...);
        local_engine.add_collector(&collector);
        local_engine.run();
    }
```

为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector_->take_result();
```

然后保留 Phase 3（YARA on built buffers）及后续代码，将 `collector.take_result()` 改为 `collector_->take_result()`，`collector.take_reg_buf()` 改为 `collector_->take_reg_buf()`，`collector.take_sys_buf()` 改为 `collector_->take_sys_buf()`。

- [ ] **Step 4: 处理缓存逻辑**

在 `run()` 开头有缓存检查逻辑（约第 1270-1287 行），保留不变——缓存命中时直接返回，不会执行到 `declare_scan` 的结果读取。但注意：如果缓存命中，`declare_scan()` 仍然会被调用（在 `execute_pass()` 中），collector_ 会被构造但不被使用。这不影响正确性，只是浪费一点内存。可以在 `run()` 缓存命中时 `collector_.reset()` 释放。

在缓存命中返回前添加 `collector_.reset();`：

```cpp
    if (cached_from_blob) {
        collector_.reset();  // not needed, free memory
        ctx.progress(1.0f, ...);
        return PassResult::success(std::move(cached));
    }
```

- [ ] **Step 5: 编译并运行 pattern 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R pattern --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，pattern 相关测试通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/crypto/pattern_pass.h tools/tenet/src/analysis/passes/crypto/pattern_pass.cpp
git commit -m "feat(scan-fusion): migrate pattern_pass to declare_scan

PatternPass now overrides has_scan() and declare_scan(). The PatternCollector
is constructed in declare_scan() with code_table, decoder, regfile, YARA
config from PassContext. run() reads results from collector_ instead of
creating a local TraceScanEngine."
```

---

### Task 5: 迁移 function_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/structure/function_pass.h`
- Modify: `tools/tenet/src/analysis/passes/structure/function_pass.cpp`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::reader()`, `PassContext::index()`
- Produces: `FunctionPass::has_scan() == true`, `FunctionPass::declare_scan()`, `FunctionPass::collector_`
- Note: `FunctionCollector` constructor needs reader, index. `run()` has extensive post-processing after `take_result()`.

- [ ] **Step 1: 在 function_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/structure/function_pass.h` 中，找到 `FunctionPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`FunctionCollector` 定义在同一个 .h 中）：

```cpp
private:
    std::unique_ptr<FunctionCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/structure/function_pass.cpp` 中，在 `FunctionPass::run()` 之前添加：

```cpp
void FunctionPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    uint64_t total_insts = index.inst_count();

    collector_ = std::make_unique<FunctionCollector>(reader, total_insts);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

> **重要**：需要检查 `FunctionCollector` 的构造函数参数。在 `run()` 中搜索 `FunctionCollector collector(` 确认实际参数。如果它需要 `set_cancel_fn` 或 `set_progress_fn`，这些需要在 `declare_scan()` 中设置——但 progress/cancel 由 ScanOrchestrator 的 `execute_scan` 统一处理，不需要在 collector 上单独设置。
>
> 如果 `FunctionCollector` 需要 `set_progress_fn` 回调来驱动 Phase 2 进度，这部分需要特殊处理。检查 `run()` 中 `collector.set_progress_fn(...)` 和 `collector.set_cancel_fn(...)` 的用途——如果它们驱动 `run()` 内的后处理进度，则保留在 `run()` 中设置即可。

- [ ] **Step 3: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/structure/function_pass.cpp` 的 `FunctionPass::run()` 中，找到创建 collector 和 engine 的部分（约第 960-1010 行）。

将 collector 创建和 engine 代码：
```cpp
    FunctionCollector collector(reader, total_insts);
    collector.set_progress_fn(...);
    collector.set_cancel_fn(...);

    {
        TraceScanEngine local_engine(reader, total_insts, &index);
        ...
        local_engine.run();
        ctx.progress(kPhase2End, ...);
    }
```

替换为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    // Re-attach progress/cancel callbacks for post-processing phases
    collector_->set_progress_fn(...);
    collector_->set_cancel_fn([&]() { return ctx.cancelled(); });

    ctx.progress(kPhase2End, "Function analysis: finalising...");
```

然后保留后续的 `take_result()` 和后处理逻辑，将 `collector.take_result()` 改为 `collector_->take_result()`。

- [ ] **Step 4: 处理缓存逻辑**

`function_pass` 有缓存逻辑（`load_pass_blob`）。在缓存命中返回前添加 `collector_.reset();`。

- [ ] **Step 5: 编译并运行 function 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R function --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，function 相关测试通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/structure/function_pass.h tools/tenet/src/analysis/passes/structure/function_pass.cpp
git commit -m "feat(scan-fusion): migrate function_pass to declare_scan

FunctionPass now overrides has_scan() and declare_scan(). The FunctionCollector
is constructed in declare_scan(). run() reads results from collector_ and
performs post-processing (compact containers, etc.) instead of creating a
local TraceScanEngine."
```

---

### Task 6: 迁移 memory_string_pass（两阶段 pass）

**Files:**
- Modify: `tools/tenet/src/analysis/passes/memory/memory_string_pass.h`
- Modify: `tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::code_table()`
- Produces: `MemoryStringPass::has_scan() == true`, `MemoryStringPass::declare_scan()`, `MemoryStringPass::collector_`
- Note: This is a two-phase pass. Phase 1 scans trace to collect call sites. Phase 2 analyzes each call site with regfile+memory. Only Phase 1 migrates to `declare_scan()`.

- [ ] **Step 1: 在 memory_string_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/memory/memory_string_pass.h` 中，找到 `MemoryStringPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`MemoryStringCollector` 定义在同一个 .h 中）：

```cpp
private:
    std::unique_ptr<MemoryStringCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp` 中，在 `MemoryStringPass::run()` 之前添加：

```cpp
void MemoryStringPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    collector_ = std::make_unique<MemoryStringCollector>(code_table, config_);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

- [ ] **Step 3: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp` 的 `MemoryStringPass::run()` 中，找到 Phase 1 部分（约第 429-450 行），删除 collector 创建和 engine 代码：

替换：
```cpp
    ctx.progress(0.0f, "Scanning call sites for strings");

    // ─── Phase 1: collect call sites via collector ─────────────────────────
    MemoryStringCollector collector(code_table, config_);

    {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress(...);
        local_engine.set_cancel_check(...);
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    const auto& call_sites = collector.call_sites();
```

为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    ctx.progress(0.3f, "Scanning call sites for strings");

    const auto& call_sites = collector_->call_sites();
```

> 注意：Phase 1 的 progress 映射到 0-30%，现在扫描已在 `declare_scan` 阶段完成，直接跳到 30%。

然后保留 Phase 2 逻辑不变（它使用 `call_sites` 进行 regfile+memory 分析）。

- [ ] **Step 4: 处理缓存逻辑和 StringResolver 补充数据**

`memory_string_pass` 有缓存逻辑和末尾的 StringResolver 补充数据合并。在缓存命中返回前添加 `collector_.reset();`。

末尾的 StringResolver 补充数据合并逻辑保留不变。

- [ ] **Step 5: 编译并运行 memory_string 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R memory_string --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，memory_string 相关测试通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/memory/memory_string_pass.h tools/tenet/src/analysis/passes/memory/memory_string_pass.cpp
git commit -m "feat(scan-fusion): migrate memory_string_pass Phase 1 to declare_scan

MemoryStringPass now overrides has_scan() and declare_scan(). Phase 1
(call site collection) is done via ScanOrchestrator. Phase 2 (per-call-site
string analysis with regfile+memory) remains in run(). The StringResolver
supplementary data merge at end of run() is preserved."
```

---

### Task 7: 迁移 string_pass（两阶段 pass）

**Files:**
- Modify: `tools/tenet/src/analysis/passes/memory/string_pass.cpp`（`WriteEventCollector` 在 cpp 中定义）
- Read-only: `tools/tenet/src/analysis/passes/memory/string_pass.h`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::index()`
- Produces: `StringPass::has_scan() == true`, `StringPass::declare_scan()`, `StringPass::collector_`
- Note: Two-phase pass. Phase 1 collects write events. Phase 2 analyzes each write. `WriteEventCollector` is defined in .cpp.

- [ ] **Step 1: 在 string_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/memory/string_pass.h` 中，找到 `StringPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`WriteEventCollector` 定义在 .cpp 中，需要 forward declare）：

```cpp
private:
    class WriteEventCollector;  // forward declare (defined in .cpp)
    std::unique_ptr<WriteEventCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 确保 WriteEventCollector 可被 forward declare**

在 `tools/tenet/src/analysis/passes/memory/string_pass.cpp` 中，检查 `WriteEventCollector` 的定义。如果它在匿名命名空间中，需要移出匿名命名空间或改为 `StringPass::WriteEventCollector` 嵌套类定义。

- [ ] **Step 3: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/memory/string_pass.cpp` 中，在 `StringPass::run()` 之前添加：

```cpp
void StringPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& index = ctx.index();
    uint64_t start = ctx.range().start_inst_id;
    uint64_t end = std::min(ctx.range().end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    collector_ = std::make_unique<WriteEventCollector>(start, end);
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

- [ ] **Step 4: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/memory/string_pass.cpp` 的 `StringPass::run()` 中，找到 Phase 1 部分（约第 280-294 行），删除 collector 创建和 engine 代码：

替换：
```cpp
    // ─── Phase 1: collect all memory write events via a single scan ──────
    WriteEventCollector collector(start, end);

    TraceScanEngine local_engine(reader, index.inst_count(), &index);
    local_engine.set_progress(...);
    local_engine.set_cancel_check(...);
    local_engine.add_collector(&collector);

    local_engine.run(start, end);

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto events = collector.take_events();
    ctx.progress(0.4f, fmt::format("Collected {} memory write events", events.size()));
```

为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto events = collector_->take_events();
    ctx.progress(0.4f, fmt::format("Collected {} memory write events", events.size()));
```

保留 Phase 2 逻辑不变。

- [ ] **Step 5: 处理缓存逻辑**

`string_pass` 有缓存逻辑。在缓存命中返回前添加 `collector_.reset();`。

- [ ] **Step 6: 编译并运行 string 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R string --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，string 相关测试通过。

- [ ] **Step 7: Commit**

```bash
git add tools/tenet/src/analysis/passes/memory/string_pass.h tools/tenet/src/analysis/passes/memory/string_pass.cpp
git commit -m "feat(scan-fusion): migrate string_pass Phase 1 to declare_scan

StringPass now overrides has_scan() and declare_scan(). Phase 1 (write
event collection) is done via ScanOrchestrator. Phase 2 (per-write string
analysis with MemoryModel) remains in run()."
```

---

### Task 8: 迁移 syscall_intercept_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.h`
- Modify: `tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.cpp`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::code_table()`, `PassContext::memory()`, `PassContext::reader()`, `PassContext::try_require<ObjcResult>("objc")`
- Produces: `SyscallInterceptPass::has_scan() == true`, `SyscallInterceptPass::declare_scan()`, `SyscallInterceptPass::collector_`
- Note: `SyscallInterceptCollector` constructor needs: config, code_table, memory, objc_result_ptr, target_os

- [ ] **Step 1: 在 syscall_intercept_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.h` 中，找到 `SyscallInterceptPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`SyscallInterceptCollector` 定义在同一个 .h 中）：

```cpp
private:
    std::unique_ptr<SyscallInterceptCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.cpp` 中，在 `SyscallInterceptPass::run()` 之前添加：

```cpp
void SyscallInterceptPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    auto& memory = ctx.memory();
    auto& reader = ctx.reader();

    // Optional: get ObjC messages for context annotation.
    const ObjcResult* objc = ctx.try_require<ObjcResult>("objc");

    collector_ = std::make_unique<SyscallInterceptCollector>(
        config_, code_table, memory, objc,
        static_cast<uint32_t>(reader.header().target_os));
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

> **重要**：`ctx.try_require<ObjcResult>("objc")` 会递归 require "objc" pass。在 `declare_scan()` 中调用它是安全的——`execute_pass()` 已经在递归 require 依赖后才调 `declare_scan`。但 "objc" 不在 `SyscallInterceptPass::dependencies()` 中（它是 optional 的），所以需要确认 `try_require` 在 `declare_scan` 阶段是否安全。如果 `try_require` 只是检查缓存而没有触发执行，则安全。如果会触发执行，则可能有循环依赖问题。检查 `try_require` 的语义。

- [ ] **Step 3: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.cpp` 的 `SyscallInterceptPass::run()` 中，找到创建 collector 和 engine 的部分（约第 1301-1326 行），删除 collector 构造和 engine 代码：

替换：
```cpp
    // Optional: get ObjC messages for context annotation.
    const ObjcResult* objc = ctx.try_require<ObjcResult>("objc");

    ctx.progress(0.01f, "syscall_intercept: scanning trace...");

    SyscallInterceptCollector collector(config_, code_table, ctx.memory(), objc,
                                       static_cast<uint32_t>(reader.header().target_os));

    {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress(...);
        local_engine.set_cancel_check(...);
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    auto result = collector.take_result();
```

为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    ctx.progress(0.01f, "syscall_intercept: extracting results...");

    auto result = collector_->take_result();
```

保留后续的缓存持久化逻辑。

- [ ] **Step 4: 处理缓存逻辑**

在缓存命中返回前添加 `collector_.reset();`。

- [ ] **Step 5: 编译并运行 syscall_intercept 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R syscall --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，syscall_intercept 相关测试通过。

- [ ] **Step 6: Commit**

```bash
git add tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.h tools/tenet/src/analysis/passes/platform/syscall_intercept_pass.cpp
git commit -m "feat(scan-fusion): migrate syscall_intercept_pass to declare_scan

SyscallInterceptPass now overrides has_scan() and declare_scan(). The
SyscallInterceptCollector is constructed in declare_scan() with config,
code_table, memory, objc result, and target_os from PassContext. run()
reads results from collector_ instead of creating a local TraceScanEngine."
```

---

### Task 9: 迁移 window_stats_pass

**Files:**
- Modify: `tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp`（`WindowStatsCollector` 在 cpp 中定义）
- Read-only: `tools/tenet/src/analysis/passes/profile/window_stats_pass.h`

**Interfaces:**
- Consumes: `ScanOrchestrator::declare()`, `PassContext::code_table()`, `PassContext::decoder()`, `PassContext::index()`
- Produces: `WindowStatsPass::has_scan() == true`, `WindowStatsPass::declare_scan()`, `WindowStatsPass::collector_`
- Note: `WindowStatsCollector` constructor needs: config, code_table, total_insts, decoder*

- [ ] **Step 1: 在 window_stats_pass.h 中添加接口声明和成员**

在 `tools/tenet/src/analysis/passes/profile/window_stats_pass.h` 中，找到 `WindowStatsPass` 类，添加：

```cpp
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
```

在 `private:` 区域添加（`WindowStatsCollector` 定义在 .cpp 中，需要 forward declare）：

```cpp
private:
    class WindowStatsCollector;  // forward declare (defined in .cpp)
    std::unique_ptr<WindowStatsCollector> collector_;
```

在文件顶部添加 include（如果还没有）：

```cpp
#include "infra/scan_orchestrator.h"
#include <memory>
```

- [ ] **Step 2: 确保 WindowStatsCollector 可被 forward declare**

在 `tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp` 中，检查 `WindowStatsCollector` 的定义。如果它在匿名命名空间中，需要移出或改为 `WindowStatsPass::WindowStatsCollector` 嵌套类。

- [ ] **Step 3: 添加 declare_scan() 实现**

在 `tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp` 中，在 `WindowStatsPass::run()` 之前添加：

```cpp
void WindowStatsPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    auto& code_table = ctx.code_table();
    auto& index = ctx.index();
    uint64_t total_insts = index.inst_count();

    collector_ = std::make_unique<WindowStatsCollector>(
        cfg_, code_table, total_insts, &ctx.decoder());
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}
```

- [ ] **Step 4: 修改 run() 使用 collector_**

在 `tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp` 的 `WindowStatsPass::run()` 中，找到创建 collector 和 engine 的部分（约第 400-420 行），删除 collector 构造和 engine 代码：

替换：
```cpp
    ctx.progress(0.0f, "WindowStats: computing sliding window metrics...");

    WindowStatsCollector collector(cfg_, code_table, total_insts, &ctx.decoder());

    {
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress(...);
        local_engine.set_cancel_check(...);
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector.take_result();
```

为：
```cpp
    // collector_ was populated by declare_scan() + ScanOrchestrator::execute_scan()
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    auto result = collector_->take_result();
```

保留后续的缓存持久化逻辑。

- [ ] **Step 5: 处理缓存逻辑**

在缓存命中返回前添加 `collector_.reset();`。

- [ ] **Step 6: 编译并运行 window_stats 测试**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) && ctest -R window --output-on-failure 2>&1 | tail -20`

Expected: 编译通过，window_stats 相关测试通过。

- [ ] **Step 7: Commit**

```bash
git add tools/tenet/src/analysis/passes/profile/window_stats_pass.h tools/tenet/src/analysis/passes/profile/window_stats_pass.cpp
git commit -m "feat(scan-fusion): migrate window_stats_pass to declare_scan

WindowStatsPass now overrides has_scan() and declare_scan(). The
WindowStatsCollector is constructed in declare_scan() with config,
code_table, total_insts, decoder from PassContext. run() reads results
from collector_ instead of creating a local TraceScanEngine."
```

---

### Task 10: 全量测试与文档更新

**Files:**
- Modify: `tools/tenet/docs/analysis-layer.md`

- [ ] **Step 1: 增量编译验证**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ninja -j$(nproc) 2>&1 | tail -5`

Expected: 编译通过，无 warning。

- [ ] **Step 2: 运行完整测试套件**

Run: `cd /Users/liqiang/src/Clion/QBDI/tools/tenet/build && ctest --output-on-failure 2>&1 | tail -15`

Expected: 全部测试通过（589+ 个测试）。如有失败，检查是否与本次迁移相关。

- [ ] **Step 3: 更新 analysis-layer.md 文档**

在 `tools/tenet/docs/analysis-layer.md` 中，找到 "TraceScanEngine 与 Scan Fusion" 章节（约第 54 行），更新内容反映 `declare_scan()` 已被 pass 实际使用的现状。

找到描述 `prepare_scan()` / `finish_scan()` 的部分（如果存在），替换为 `declare_scan()` + `has_scan()` 的描述。

更新 "融合扫描" 小节：
```markdown
### 融合扫描

- pass 通过 `has_scan()` 声明自己参与扫描融合（默认 false）
- `declare_scan(orchestrator, ctx)` 中构造 collector 并注册到 orchestrator
- `PassManager::run_all()` Phase 1 调用所有 pass 的 `declare_scan()`
- Phase 2 orchestrator 单次 `execute_scan()` 广播所有 collector
- Phase 3 DAG 并行调度 `run()`，各 pass 从 collector 取结果
- `require()` 单 pass 路径也走 `declare_scan + execute_scan`
```

- [ ] **Step 4: Commit**

```bash
git add tools/tenet/docs/analysis-layer.md
git commit -m "docs: update analysis-layer.md for Scan Fusion wiring

Reflect that declare_scan() is now used by 8 scanning passes. Update
the fusion scan description to match the actual has_scan() + declare_scan()
+ run() three-part pattern."
```

- [ ] **Step 5: 更新进度文件**

更新 `.superpowers/sdd/scan-fusion-wiring-progress.md`（如果存在）或创建：

```markdown
Plan: docs/superpowers/plans/2026-07-10-scan-fusion-wiring.md

Task 1: complete — extend declare_scan signature, add has_scan(), remove dead code
Task 2: complete — migrate thread_pass
Task 3: complete — migrate cfg_pass
Task 4: complete — migrate pattern_pass
Task 5: complete — migrate function_pass
Task 6: complete — migrate memory_string_pass
Task 7: complete — migrate string_pass
Task 8: complete — migrate syscall_intercept_pass
Task 9: complete — migrate window_stats_pass
Task 10: complete — full test suite + docs update

ALL TASKS COMPLETE. Build OK. All tests pass.
8 scanning passes now use declare_scan() + ScanOrchestrator.
run_all() path: single scan serves all 8 collectors.
require() path: per-pass orchestrator, same behavior as before.
Dead code removed: ctx.scan_engine() / make_scan_engine() / set_scan_engine().
```

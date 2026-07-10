# Scan Fusion 接线设计

## 背景与动机

Infra 层已完成 `ScanOrchestrator`、`PageStats`、`StringResolver`、`CheckpointManager` 四个基础设施组件。`AnalysisPass` 基类新增了 `declare_scan()` 虚方法，`PassManager::run_all()` 已有 Phase 1（声明）→ Phase 2（统一扫描）→ Phase 3（DAG 并行执行）的三阶段流程。

**关键断层**：`declare_scan()` 从未被任何 pass override。8 个扫描型 pass 仍在 `run()` 中各自创建 `TraceScanEngine local_engine` 独立扫描 trace。ScanOrchestrator 的管道已建好，但没有任何 pass 使用它。

此外，`PassContext::scan_engine()` / `make_scan_engine()` 是一套从未真正工作的旧接口——`set_scan_engine()` 从未被调用，`ctx.scan_engine()` 永远返回 `nullptr`。`pattern_pass` 中的 `if (engine)` 分支永远走 false 路径。

## 目标

1. 让 8 个扫描型 pass 通过 `declare_scan()` 注册 collector 到 `ScanOrchestrator`
2. `run()` 只读 collector 结果，不再自建 `local_engine`
3. `require()` 单 pass 路径也走 `declare_scan + execute_scan`，消除 fallback `local_engine` 代码
4. 移除死代码：`PassContext::scan_engine()` / `set_scan_engine()` / `make_scan_engine()`

## 非目标

- 增量分析（`supports_incremental()`）— 保持现有自定义扫描逻辑
- `objc_pass` — 已用原始指针快扫绕过 TraceScanEngine，性能更优
- `xref_pass` — 自定义扫描器 + 增量支持，不强制迁移
- `require()` 路径复用持久 orchestrator — 属于增量优化，后续再做

## 架构

### 迁移前后对比

**迁移前**（每个 pass 独立扫描）：

```cpp
PassResult XxxPass::run(PassContext& ctx) {
    XxxCollector collector(...);                    // 局部 collector
    TraceScanEngine local_engine(reader, total, &index);
    local_engine.add_collector(&collector);
    local_engine.run();                             // 独立扫描
    auto result = collector.take_result();
    return PassResult::success(std::move(result));
}
```

**迁移后**（声明式）：

```cpp
void XxxPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    collector_ = std::make_unique<XxxCollector>(...);  // 从 ctx 获取依赖
    orch.declare({name(), collector_.get(),
                  collector_->supports_parallel()});
}

PassResult XxxPass::run(PassContext& ctx) {
    // collector_ 已被 orchestrator 扫描填充
    auto result = collector_->take_result();
    collector_.reset();
    return PassResult::success(std::move(result));
}
```

### PassManager 调度流程

```
run_all(num_threads):
  Phase 1: 对每个 pass 调用 declare_scan(orch, ctx)  → collector 注册到 orchestrator
  Phase 2: orchestrator.execute_scan(range, cancel)  → 单次 TraceScanEngine 扫描广播所有 collector
  Phase 3: DAG 并行调度各 pass.run(ctx)              → 从 collector 取结果

require(name):
  1. 缓存检查 → 未命中
  2. 递归 require 依赖
  3. 如果 pass->has_scan():
     a. 创建临时 ScanOrchestrator
     b. pass->declare_scan(orch, ctx)
     c. orch.execute_scan(range, cancel)
  4. pass->run(ctx)
  5. 缓存结果
```

### 数据流

```
declare_scan(orch, ctx) ──▶ ScanOrchestrator
                               │
                    execute_scan(range, cancel)
                               │
                               ▼
                    TraceScanEngine::run()
                    单次遍历 trace，广播到所有
                    collector 的 on_inst/on_code
                    /on_svc/on_objc/... 回调
                               │
                               ▼
                    DAG 并行调度 pass.run(ctx)
                    每个 pass 从自己的 collector
                    取结果，不再扫描 trace
```

## 组件改动

### 1. AnalysisPass 基类（`pass_manager.h`）

扩展 `declare_scan()` 签名，新增 `has_scan()`：

```cpp
class AnalysisPass {
    // 已有：virtual void declare_scan(class ScanOrchestrator& orchestrator) { ... }
    // 改为：
    virtual void declare_scan(class ScanOrchestrator& orchestrator, PassContext& ctx) {
        (void)orchestrator; (void)ctx;
    }

    /// Whether this pass participates in scan fusion.
    /// Default false. Scanning passes override to return true.
    virtual bool has_scan() const { return false; }
};
```

**为什么扩展签名传入 `PassContext&`**：部分 collector 构造需要 `code_table`、`decoder`、`regfile` 等资源（如 `PatternCollector` 需要 code_table + decoder + regfile_ptr）。这些资源在 PassContext 中，ScanOrchestrator 没有。扩展签名让 pass 能从 ctx 获取 collector 依赖，避免预存依赖的时序问题和生命周期管理负担。

### 2. PassManager（`pass_manager.cpp`）

#### `run_all()` — 微调 Phase 1 调用签名

```cpp
// Phase 1: declare_scan
for (auto& entry : entries_) {
    entry->pass->declare_scan(*scan_orchestrator_, ctx);  // 加 ctx 参数
}

// Phase 2、Phase 3 不变
```

#### `require()` — 新增扫描编排

在依赖递归完成后、`run()` 调用前，插入扫描编排：

```cpp
if (entry->pass->has_scan() && !entry->scan_executed) {
    ScanOrchestrator orch(*reader_, index_->inst_count(), index_);
    entry->pass->declare_scan(orch, ctx);
    if (orch.has_declarations()) {
        orch.execute_scan(range_, cancelled_, no_parallel_scan_);
    }
    entry->scan_executed = true;
}
```

> `scan_executed` 是 `PassEntry` 上新增的 `bool` 字段，默认 `false`。防止同一 pass 在 `require()` 路径被重复扫描（依赖链中多次引用时）。

#### 移除死代码

- `PassContext::scan_engine()` — 从未被真正使用
- `PassContext::set_scan_engine()` — 从未被调用
- `PassContext::make_scan_engine()` — pass 迁移后不再需要
- `PassManager::scan_engine()` / `scan_engine_` 成员 — 同上
- `pattern_pass` 中的 `if (engine)` 分支 — 永远 false 的死代码

### 3. 各扫描型 Pass 的改动模板

每个 pass 遵循统一改动模式：

**头文件**：
```cpp
class XxxPass : public AnalysisPass {
public:
    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;

private:
    std::unique_ptr<XxxCollector> collector_;
};
```

**实现文件**：
```cpp
void XxxPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    // 从 ctx 获取依赖，构造 collector
    collector_ = std::make_unique<XxxCollector>(
        ctx.code_table(), ctx.decoder(), ...);
    orch.declare({name(), collector_.get(),
                  collector_->supports_parallel()});
}

PassResult XxxPass::run(PassContext& ctx) {
    // collector_ 由 declare_scan() 构造，PassManager 保证 declare_scan 在 run 之前调用。
    // 如果 collector_ 为 null，说明 PassManager 未正确编排扫描——这是编程错误。
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    // 删除：XxxCollector collector(...);
    //       TraceScanEngine local_engine(...);
    //       local_engine.add_collector(...);
    //       local_engine.run();

    auto result = collector_->take_result();
    collector_.reset();
    return PassResult::success(std::move(result));
}
```

### 待迁移的 8 个 pass

| Pass | Collector | 并行支持 | Collector 构造依赖 |
|------|-----------|---------|-------------------|
| `pattern` | `PatternCollector` | ❌ | code_table, decoder, regfile_ptr, has_yara, constmat_min_parts, target_os |
| `function` | `FunctionCollector` | ❌ | reader, index |
| `cfg` | `CFGEdgeCollector` | ✅ | 无（结果指针） |
| `memory_string` | `MemoryStringCollector` | ❌ | config |
| `string` | `WriteEventCollector` | ❌ | start, end |
| `syscall_intercept` | `SyscallInterceptCollector` | ❌ | config, code_table, memory, objc_result_ptr, target_os |
| `thread` | `ThreadCollector` | ❌ | 无 |
| `window_stats` | `WindowStatsCollector` | ❌ | config (window_size, slide) |

### 不迁移的 pass

| Pass | 原因 |
|------|------|
| `objc` | 已用原始指针快扫绕过 TraceScanEngine，性能更优 |
| `xref` | 自定义扫描器 + 增量支持，不强制迁移 |
| `call_context` | 不扫描 trace，只查询 function 结果 |
| `loop` / `cfg_layout` / `call_graph` / `algorithm_summary` | 非扫描型，依赖其他 pass 结果 |

## 边界情况

### 1. `require()` 多次调用同一 pass

第一次 require 时 `declare_scan + execute_scan + run` 执行，结果被缓存。第二次直接返回缓存。`collector_` 在 `run()` 末尾 `reset()`，不会泄漏。

### 2. `require()` 调用有依赖关系的 pass

`require("call_graph")` → 递归 `require("function")` → `function` 的 `declare_scan + execute_scan + run` → 回到 `call_graph` 的 `run`。`call_graph` 不是扫描型（`has_scan() == false`），不创建 orchestrator。

### 3. Pass 取消

`execute_scan()` 接收 `cancel_token`。collector 的 `on_inst()` 回调检查取消标志，返回 false 中止扫描。与现有 `local_engine.set_cancel_check()` 机制一致。

### 4. Collector 的 `take_result()` 语义

多数 collector 的 `take_result()` 是 move 语义（清空内部状态）。`run()` 中调用后 collector 被清空。如果同一 pass 被再次执行（缓存未命中场景），`declare_scan()` 会重新构造 collector。

### 5. `require()` 临时 orchestrator 性能

`ScanOrchestrator` 构造 O(1)（存 3 个引用 + vector），`declare_scan()` O(1)（一次虚调用 + push_back），`execute_scan()` 内部创建 `TraceScanEngine` 与原 `local_engine` 等价。多出的开销是纳秒级，相对 trace 扫描（毫秒到秒级）完全可忽略。行为与迁移前等价，无退化。

## 测试与验证

### 测试策略

#### 1. 单元测试 — 无行为变化

所有 8 个 pass 的现有单元测试必须不修改地通过。迁移不改变 pass 的输入输出，只改变内部扫描方式。

#### 2. `require()` 路径测试

验证单 pass `require()` 也走 `declare_scan + execute_scan`：

```cpp
TEST(ScanFusion, RequireSinglePassTriggersOrchestrator) {
    auto env = make_trace_env(...);
    auto pm = make_pm(env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& result = pm->require("pattern");
    ASSERT_TRUE(result.ok());
}
```

#### 3. `run_all()` Scan Fusion 测试

验证多 pass 共享单次扫描：

```cpp
TEST(ScanFusion, RunAllSharesSingleScan) {
    auto env = make_trace_env(...);
    auto pm = make_pm(env);
    pm->register_pass(std::make_unique<PatternPass>());
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<ThreadPass>());

    pm->run_all();

    ASSERT_TRUE(pm->require("pattern").ok());
    ASSERT_TRUE(pm->require("function").ok());
    ASSERT_TRUE(pm->require("thread").ok());
}
```

#### 4. 性能验证

在 50MB trace 上对比迁移前后扫描次数。预期：`run_all()` 路径扫描阶段耗时降为 ~1/8（8 个 pass 共享 1 次扫描）。用 `os_signpost` 验证 `execute_scan` 只出现一次。

### 验证清单

- [ ] 增量编译无 warning
- [ ] 8 个 pass 的单元测试全部通过
- [ ] `require()` 单 pass 路径结果正确
- [ ] `run_all()` 多 pass 共享扫描结果正确
- [ ] 死代码清理后（`scan_engine()` / `make_scan_engine()` 移除）编译通过
- [ ] 完整 ctest 套件通过
- [ ] `os_signpost` 验证扫描次数减少

## 文档同步

更新 `docs/analysis-layer.md` 中 Scan Fusion 相关章节，反映 `declare_scan()` 已被 pass 实际使用的现状。

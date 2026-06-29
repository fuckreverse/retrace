# Analysis 层

Analysis 层把 IO / Core 提供的底层能力组织成可组合的分析 pass。这里的核心不是某个具体算法，而是：

- 如何声明依赖
- 如何避免重复扫描 trace
- 如何把结果缓存成可复用中间产物
- 如何让 GUI / CLI / MCP 共用同一套分析实现

## 核心对象

| 对象 | 文件 | 职责 |
|------|------|------|
| `AnalysisPass` | `pass_manager.h` | 每个分析能力的统一抽象 |
| `PassContext` | `pass_manager.h` | 向 pass 暴露 reader / index / regfile / memory / decoder / range / progress |
| `PassResult` | `pass_manager.h` | 类型擦除结果容器，承载成功 / 失败 / 跳过状态 |
| `PassManager` | `pass_manager.{h,cpp}` | 注册、依赖解析、执行、缓存、并发调度 |
| `TraceCollector` | `trace_collector.h` | 扫描型 pass 的回调接口 |
| `TraceScanEngine` | `trace_collector.{h,cpp}` | 单遍广播、并行分片、collector 融合扫描 |
| `pass_catalog()` | `pass_registry.cpp` | pass 名单、分类、默认 UI 集合、工厂入口 |

## 分析层的工作方式

```mermaid
flowchart TD
    A[请求某个能力\nGUI / CLI / MCP] --> B[PassManager::require(name)]
    B --> C{是否已缓存?}
    C -- yes --> D[返回 PassResult]
    C -- no --> E[递归注册/执行依赖]
    E --> F{扫描型 pass?}
    F -- yes --> G[TraceScanEngine 单遍广播]
    F -- no --> H[直接调用 pass.run(ctx)]
    G --> I[finish_scan 提取结果]
    H --> I
    I --> J[缓存到 PassEntry]
    J --> D
```

## PassManager 调度模型

### `require(name)`

- 先看 `PassEntry` 是否已有结果。
- 如果没有，则按 `dependencies()` 递归要求上游 pass。
- 用原子状态机避免重复执行。
- 适合 GUI 点一下某面板、CLI 只跑一个能力、MCP 单次调用等按需分析场景。

### `run_all(num_threads)`

- 第一阶段做 **Scan Fusion**：把同层、可扫描融合的 pass 共享一次 trace 遍历。
- 第二阶段按 DAG 层级并行调度剩余 pass。
- 适合 UI 启动阶段或需要预热一批默认 pass 的场景。

## TraceScanEngine 与 Scan Fusion

多个 pass 本质上都只是“扫一遍 trace 再统计”。如果每个 pass 各扫一次，IO 成本会线性叠加。

### TraceCollector 接口

Collector 可按记录类型覆写回调：

- `on_inst()`
- `on_anchor()`
- `on_code()`
- `on_svc()`
- `on_objc()`
- `on_thread()`
- `on_event()`

### 融合扫描

- pass 通过 `prepare_scan()` 返回自己的 collector。
- `PassManager::run_fused_scans()` 把同层 collector 挂到同一个 `TraceScanEngine`。
- 引擎只扫一遍 trace，依次广播给所有 collector。
- pass 再通过 `finish_scan()` 把 collector 内部状态转换成 `PassResult`。

### 并行分片

- 如果 collector 声明 `supports_parallel()` 且支持 `clone()` / `merge()`，引擎会按 ANCHOR 边界切分并行扫描。
- 典型受益者：`xref` 这类大范围统计型 pass。

## Pass 分类总览

当前 `pass_catalog()` 注册了 **36 个 pass**，分成 7 类。

### 1. Structure

| pass | 主要用途 |
|------|----------|
| `function` | 识别函数、调用事件、调用栈 |
| `xref` | 建 PC→inst_id 倒排与执行计数 |
| `cfg` | 从动态执行恢复控制流图 |
| `cfg_layout` | 为 CFG 生成布局坐标 / DOT |
| `call_graph` | 基于函数结果生成调用图 |
| `loop` | 基于 CFG 检测循环 |
| `index_build` | 显式触发索引构建 / 重建 |

### 2. Taint

| pass | 主要用途 |
|------|----------|
| `taint` | 前向污点传播 |
| `backward_taint` | 反向污点回溯 |
| `slice` | 反向切片 |
| `producer_chain` | 轻量寄存器来源追踪 |
| `taint_source_annotation` | 为反向叶子源补充 ObjC / 内存上下文 |

### 3. Crypto / Pattern

| pass | 主要用途 |
|------|----------|
| `pattern` | 模式检测：crypto / anti-debug / obfuscation / networking |
| `constant_materialization` | 识别 movz+movk 常量链 |
| `loop_semantics` | 判断循环是否像 Feistel / SPN / ARX / memcpy |
| `algorithm_summary` | 汇总模式、常量、循环、调用图做算法识别 |
| `objc_crypto` | 把密码学命中与 ObjC 调用上下文关联 |
| `symbol_annotation` | 汇总结构与模式注释成统一标签层 |

### 4. Memory / String

| pass | 主要用途 |
|------|----------|
| `strings` | 最终内存快照中的字符串恢复 |
| `memory_strings` | 调用点瞬时字符串恢复 |
| `memory_snapshot` | 在 inst_id 或调用点抓快照 |
| `mem_search` | 按字节模式搜索内存写 / 寄存器值 |
| `entropy` | 对内存区域做 Shannon 熵分析 |
| `literal_search` | 搜索常量字面值 |
| `yara_mem_scan` | 在内存页上跑 YARA 规则 |

### 5. ObjC / Syscall

| pass | 主要用途 |
|------|----------|
| `objc` | ObjC 消息发送解析 |
| `syscall_intercept` | CommonCrypto / Security.framework 等系统调用参数提取 |

### 6. Profile / Trace

| pass | 主要用途 |
|------|----------|
| `trace_fold` | 折叠重复循环迭代 |
| `reg_timeline` | 寄存器写时间线 |
| `call_context` | 某条指令的调用栈 / 循环 / 邻居上下文 |
| `window_stats` | 滑动窗口统计 |
| `cache_sim` | 缓存模拟与时序侧信道检测 |
| `trace_diff` | 对比两个 trace 区间 |
| `dataflow_graph` | 指令区间内的数据流图 |

### 7. Misc

| pass | 主要用途 |
|------|----------|
| `thread` | 线程时间线与切换统计 |
| `thread_filter` | 构建每线程 inst bitmap，用于过滤 |

## 关键依赖关系

下面是当前实现里最重要的一组依赖，和 `dependencies()` 保持一致：

```mermaid
flowchart LR
    xref --> cfg
    cfg --> cfg_layout
    cfg --> loop
    function --> call_graph
    xref --> taint
    taint --> slice
    loop --> trace_fold
    xref --> trace_fold
    loop --> loop_semantics
    xref --> loop_semantics
    function --> symbol_annotation
    loop --> symbol_annotation
    constant_materialization --> symbol_annotation
    pattern --> symbol_annotation
    backward_taint --> taint_source_annotation
    objc --> taint_source_annotation
    pattern --> objc_crypto
    objc --> objc_crypto
    thread --> thread_filter
    pattern --> algorithm_summary
    constant_materialization --> algorithm_summary
    loop_semantics --> algorithm_summary
    function --> algorithm_summary
    call_graph --> algorithm_summary
```

### 当前实现注意点

- `cfg` **当前仍依赖 `xref`**，这要以 `cfg_pass.h` 为准。
- `loop` 依赖 `cfg`。
- `loop_semantics` 依赖 `loop + xref`。
- `symbol_annotation` 聚合的是 `function + loop + constant_materialization + pattern`。
- `trace_fold` 依赖 `loop + xref`。
- `taint_source_annotation` 依赖 `backward_taint + objc`。

## pass_registry.cpp 的作用

`src/analysis/pass_registry.cpp` 是 Analysis 层的“目录服务”。它提供：

- `pass_catalog()`：维护 pass 名称、分类、说明、是否默认进 UI。
- `find_pass_catalog_entry()`：按名查元信息。
- `default_ui_pass_names()`：列出默认 UI 启动时建议预热的 pass。
- `register_pass_by_name()`：按名字递归注册依赖，支持 `--run-pass <name>` 这种通用入口。
- `summarize_pass_result()`：把 pass 结果压成一行摘要，供 CLI / 调试输出。

这意味着 tenet 的 pass 不只是“类很多”，而是已经被组织成一个可发现、可枚举、可程序化驱动的分析目录。

## 批处理如何使用 Analysis 层

`src/batch_analysis.cpp` 的模式基本固定：

1. 根据 CLI 选项构造配置对象。
2. 注册需要的 pass。
3. `pm.require(name)` 拿到 typed result。
4. 序列化成 JSON / DOT / 文本。

也就是说，CLI 并没有单独实现分析能力，只是给 pass 提供了一个人类可用的入口。

## MCP 如何使用 Analysis 层

`src/io/mcp/` 中的大部分工具最终也是：

- 按需注册 pass
- 调 `require_pass<T>()`
- 序列化结果

这让 GUI / CLI / MCP 三种入口共用完全相同的分析核心。

## 结果缓存与失效

- 每个 pass 对应一个 `PassEntry`。
- 结果一旦生成，会保存在 `PassEntry.result` 里供重复读取。
- `invalidate(name)` / `invalidate_all()` 可清理缓存。
- 对于 CLI 的 `--cache-list` / `--cache-delete`，还可以进一步管理持久化 pass blob 缓存。

## 写新 pass 的建议

### 最小模板

```cpp
class MyPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "my_pass"; }
    std::string_view description() const override { return "..."; }
    std::vector<std::string_view> dependencies() const override {
        return {"xref"};
    }

    PassResult run(PassContext& ctx) override {
        const auto& x = ctx.require<XrefResult>("xref");
        // ... 分析逻辑 ...
        return PassResult::success(MyResult{});
    }
};
```

### 什么时候做扫描融合

优先考虑给这类 pass 实现 `prepare_scan()` / `finish_scan()`：

- 只是顺序扫一遍 trace 做统计
- 不依赖复杂上游结果
- 结果能先暂存在 collector 中

### 什么时候不做扫描融合

这类 pass 更适合直接 `run(ctx)`：

- 明显依赖别的 pass 的中间结果
- 需要频繁查询 `RegisterFile` / `MemoryModel`
- 逻辑本质上是图遍历、回溯或局部 replay，而不是全表扫描

## 读这层文档之后下一步看什么

- 想看底层状态是怎么重建的：读 [`core-layer.md`](core-layer.md)
- 想看怎么真正落地一个 pass：读 [`pass-cookbook.md`](pass-cookbook.md)
- 想看 CLI / MCP / GUI 如何把 pass 暴露出去：读 [`ui-layer.md`](ui-layer.md)
- 想看整体装配：读 [`ARCHITECTURE.md`](ARCHITECTURE.md)

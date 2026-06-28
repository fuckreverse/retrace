# Analysis 层

> 职责：LLVM 风格的 **Pass Pipeline**。每个分析能力是独立 `AnalysisPass`，声明依赖后由 `PassManager` 自动调度并行执行。
> 源码：`src/analysis/`。核心：`pass_manager.{h,cpp}` + `trace_collector.{h,cpp}` + `passes/`（30+ Pass）。

## PassManager 框架

**核心三件套**（`pass_manager.h`）：

- **`PassResult`**：类型擦除结果容器。`Status{Success,Failed,Skipped}` + `error_message` + `std::any data`。`success<T>(val)` / `failed(msg)` / `skipped()` 工厂。`get<T>()` 类型安全取值。
- **`PassContext`**：Pass 执行上下文。提供 IO/Core 层访问（`reader()/index()/code_table()/regfile()/memory()/decoder()`）、Pass 间结果获取（`require<T>("name")` 触发依赖执行；`try_require<T>("name")` 不触发，返回 nullptr）、分析范围 `range()`、进度报告 `progress(pct)`、取消检查 `cancelled()`、共享扫描引擎 `scan_engine()`。
- **`AnalysisPass`**：基类。虚接口：`name()/description()/dependencies()/run(ctx)/supports_incremental()/update(ctx,changed)/estimated_cost()`。**Scan Fusion 接口**（可选）：`prepare_scan(ctx)→TraceCollector*` 声明可融合的 collector，`finish_scan(ctx)→PassResult` 从 collector 提取结果。返回 nullptr 表示不参与融合，走 `run()` 独立执行。

**PassManager 调度**：
- `register_pass(unique_ptr)` 注册（main.cpp 装配时调用）。
- `require("name")` 按需执行：递归解析依赖链，CAS 状态机防重复执行（`NotRun→Running→Completed/Failed`），条件变量等依赖完成。**线程安全**，多线程可并发 `require`。
- `run_all(num_threads)` 全量执行：**Phase 1 — Scan Fusion**（`run_fused_scans()`）：按 DAG 层级分组，每层所有声明了 `prepare_scan()` 的 Pass 的 collector 挂到同一个 `TraceScanEngine` 上，**单次 `run()` 广播给所有 collector**（只扫一遍 trace），然后 `finish_scan()` 提取各 Pass 结果并直接写入 `PassEntry`（标记 Completed）。**Phase 2 — DAG 调度**（`run_all_parallel()`）：TBB `task_group` 就绪队列调度，已融合的 Pass 走无锁快路径跳过。
- `invalidate("name")` / `invalidate_all()` 失效缓存。
- 内存压力：`set_rss_limit_mb()` 超限时跳过非关键 Pass。

**PassEntry 内部**：`unique_ptr<AnalysisPass> pass` + `PassResult result` + `atomic<PassState> state` + `mutex mtx`（保护 result 写）+ `condition_variable cv`（通知完成）。无锁快路径：已完成 Pass 的 `require` 直接读 result。

## TraceScanEngine — 单遍广播 + 并行分片

**设计**（`trace_collector.h`）：多个 Pass 经常需要扫一遍 trace，为避免每个 Pass 各扫一遍，`TraceScanEngine` 单遍顺序遍历 trace，把每条记录广播给所有注册的 `TraceCollector`。

**TraceCollector 接口**：`begin(start,end)/on_inst(id,inst)/on_anchor/on_code/on_svc/on_objc/on_thread/on_event/end`。每个回调默认空实现，Collector 按需重写。

**并行分片**：Collector 声明 `supports_parallel()==true` 并实现 `clone()`/`merge()`，则 Engine 以 ANCHOR 边界分片多线程扫（每分片一个 clone，扫完 `merge()` 合并）。非并行 Collector 单独顺序跑保证正确性。`run_parallel(num_threads)` 自动判断（trace <50K 或无并行 Collector 时回退顺序）。XrefCollector 是典型并行实现。

**Scan Fusion（`run_all` 模式）**：`PassManager::run_fused_scans()` 按 DAG 层级分组，每层所有声明了 `prepare_scan()` 的 Pass 的 collector 挂到同一个 `TraceScanEngine` 上，**单次 `run()` 广播给所有 collector**（一次 IO 遍历）。然后 `finish_scan()` 从各 collector 提取结果。11+ 个扫描型 Pass（xref/disasm/cfg/function/string/thread/objc/pattern/window_stats/syscall_intercept/const_mat）共享一次扫描，替代了原来各自独立扫一遍。`run()` 仍保留用于独立执行（如 `--run-pass xref`）。

**与 Pass 的关系**：Pass 通过 `prepare_scan()` 提供 collector 参与融合，`finish_scan()` 提取结果。独立执行时 `run()` 自建 local engine 扫描。

## Pass 依赖 DAG

```
Level 0 (无依赖，可并行):
  index_build  disassembly  xref  function  thread  backward_taint
  string  pattern  constant_materialization  trace_diff  objc
  memory_string  memory_snapshot  dataflow_graph  reg_timeline
  mem_search  producer_chain  window_stats  entropy  literal_search
  yara_mem_scan  cache_sim  syscall_intercept

Level 1:
  call_graph ← function         taint ← xref
  trace_fold ← {loop, xref}     loop_semantics ← {loop, xref}
  thread_filter ← thread        objc_crypto ← {pattern, objc}
  call_context ← loop           cfg_layout ← cfg
  slice ← taint

  注：cfg 已重设计为无依赖（collector 自行追踪 PC 执行计数和转移），
  不再依赖 xref，可参与 Round 0 融合。

Level 2:
  loop ← cfg                    symbol_annotation ← {function, loop, constant_materialization, pattern}
  taint_source_annotation ← {backward_taint, objc}

Level 3:
  algorithm_summary ← {pattern, constant_materialization, loop_semantics, function, call_graph}
```

> 注：`pattern` 硬依赖为空，但通过 `try_require()` 软消费 `constant_materialization` 结果（若已跑）避免重复扫描。

## Pass 全目录

### 基础索引与解码

| Pass | 依赖 | 说明 |
|------|------|------|
| `index_build` | — | 首次加载时触发 TraceIndex 构建（若缓存有效直接跳过）。结果含 inst/anchor/code 计数、构建耗时、是否命中缓存。 |
| `disassembly` | — | 建 PC→DecodedInst 表，按需查指令。用 InstructionDecoder + LRU 缓存。 |
| `xref` | — | PC→inst_id 倒排（Roaring64Map bitmap）+ PC 执行计数。支持并行分片。是 CFG/Taint/Loop 等的加速基础。 |

### 控制流与函数

| Pass | 依赖 | 说明 |
|------|------|------|
| `cfg` | xref | 从 trace 恢复基本块 + 边。天然解决间接跳转（有实际执行目标）。基本块按分支目标/分支指令切分，边按 PC transition 累计 taken_count。`extract_function(entry_pc)` BFS 取过程内子图。 |
| `cfg_layout` | cfg | 用 GraphGridLayout（自研，与 IDA 同源 Sugiyama 分层）算节点坐标 + 边路由，生成带注释 DOT。 |
| `function` | — | BL/BLR→RET 配对识别函数调用，模拟调用栈。含 tail call（b/br）检测。输出 CallEvent 列表 + FunctionInfo（entry_pc/name/calls/instructions）。`call_stack_at(inst_id)` 重建任意时刻调用栈。 |
| `call_graph` | function | 从函数分析结果建调用图（caller→callee + 调用次数）。 |
| `loop` | cfg | 基于 CFG 支配树的循环检测（LLVM 风格）。输出 header/body/back_edge/iteration_count。 |

### 污点与数据流

| Pass | 依赖 | 说明 |
|------|------|------|
| `taint` | xref | **前向污点**。TaintConfig 指定源寄存器（bitmask）/内存地址/方向/停止条件。Triton 精确模式（可用时）+ 启发式 fallback。XRef 加速：跳过不读任何污染源的指令。ABI 感知跨函数传播（BL→X0-X7，RET→X0）。输出 TaintEvent + 细粒度 PropagationStep（RegToReg/RegToMem/MemToReg/.../Kill/Call/Return）。 |
| `backward_taint` | — | **反向污点**（sink→source）。用 REG_WRITES 倒排索引 O(log N) 直接跳到 last writer，而非逐条回溯。支持跨函数（BL→callee 追 X0，RET→caller）、内存传播（load←store 链）、多 sink 归因（SinkTag）。输出 BackwardTaintEvent + DataflowEdge 图。 |
| `slice` | taint | 程序切片：给定 (inst_id, reg) 的反向切片，只保留真正数据依赖链。 |
| `dataflow_graph` | — | 构建指令区域的寄存器级数据流图（DataflowEdge: from_inst→to_inst via_reg）。 |
| `producer_chain` | — | 轻量反向寄存器值溯源（无 Triton），给 GUI 高亮用。 |

### 模式与算法识别

| Pass | 依赖 | 说明 |
|------|------|------|
| `pattern` | — | YARA 规则匹配检测加密/反调试/混淆/网络/密钥调度模式。构造三组可扫缓冲区：寄存器值缓冲（diff 值拼接）、syscall 缓冲、代码缓冲。`rules/` 目录 6 组 `.yar` 规则。外加 mnemonic 检测（HW AES/SHA、XOR 循环、MOVZ/MOVK 常量加载）。软消费 `constant_materialization` 避免重复扫。 |
| `constant_materialization` | — | 追踪 MOVZ+MOVK 常量构造链，匹配已知算法常量（AES S-Box、SHA-256 K 等）。 |
| `loop_semantics` | loop, xref | 采样循环 2-3 次迭代，对比寄存器状态识别 active/invariant 寄存器 + body 特征（sbox/xor/shift/add/modular），分类为 FeistelRound/SPNRound/ARXRound/CounterLoop/Accumulator/MemcpyLike。 |
| `algorithm_summary` | pattern, constant_materialization, loop_semantics, function, call_graph | 综合上述结果生成算法摘要报告（识别出 AES/SHA/RSA 等具体算法）。 |
| `entropy` | — | 内存区域 Shannon 熵分析，检测密文（高熵）/明文（低熵）。 |

### 字符串与内存

| Pass | 依赖 | 说明 |
|------|------|------|
| `string` | — | 扫 trace 末尾时刻内存最终快照发现可打印字符串（ASCII/UTF-8/UTF-16）。自然绕过运行时解密——看到的是解密后明文。 |
| `memory_string` | — | 时间感知：在调用点用 MemoryModel 重建当时内存，发现调用瞬间的字符串。 |
| `memory_snapshot` | — | 在函数调用和显式 inst_id 点捕获内存快照（按区域）。 |
| `mem_search` | — | YARA 加速的多模式搜索内存写入和寄存器值。支持 `AA BB ?? CC` 通配。 |
| `literal_search` | — | 搜特定字面值（寄存器/内存/立即数字段）。 |
| `yara_mem_scan` | — | YARA 规则扫内存快照（heap/stack 加密常量与模式）。支持最小熵过滤、代码缓冲扫描。 |

### ObjC 与 iOS 系统调用

| Pass | 依赖 | 说明 |
|------|------|------|
| `objc` | — | 解析 ObjC 消息发送记录（recv/sel/cls），按类名/选择子统计。 |
| `objc_crypto` | pattern, objc | 关联加密模式命中与 ObjC 调用栈上下文。 |
| `syscall_intercept` | — | 提取 iOS 系统 API 调用参数（CommonCrypto、Security.framework）。软依赖 objc 做上下文注释。捕获指针参数指向的字节。 |
| `taint_source_annotation` | backward_taint, objc | 为反向污点的叶节点源标注 ObjC getter / 内存上下文。 |

### 循环、轨迹折叠、差异

| Pass | 依赖 | 说明 |
|------|------|------|
| `trace_fold` | loop, xref | 把重复循环迭代折叠成摘要（减少显示噪音）。 |
| `trace_diff` | — | 比较两个 trace 区域（[a_start,a_end) vs [b_start,b_end)）找行为差异。直接操作 trace reader + code table。 |
| `call_context` | loop | 给指令生成富上下文：调用栈 + 循环位置 + 邻居指令。 |

### 统计与可视化辅助

| Pass | 依赖 | 说明 |
|------|------|------|
| `reg_timeline` | — | 构建寄存器值时间线（所有写时刻 + 值），给 GUI sparkline。 |
| `window_stats` | — | 滑动窗口统计：mnemonic 分布、内存热点等。用 `aarch64_classify.h` 的 OpcodeInfo 快速分类。 |
| `symbol_annotation` | function, loop, constant_materialization, pattern | 聚合所有 Pass 的注释为统一注释层（PC→标签集合）。 |

### 线程

| Pass | 依赖 | 说明 |
|------|------|------|
| `thread` | — | 线程感知分析：上下文切换、每线程时间线、执行跨度。 |
| `thread_filter` | thread | 建每线程指令 bitmap，支持多线程 trace 按线程过滤。 |

### 缓存模拟

| Pass | 依赖 | 说明 |
|------|------|------|
| `cache_sim` | — | 组相联缓存模拟（L1D/L2），输出 miss rate/hot lines/时序侧信道检测。可配 size/policy(LRU/PLRU/RAND)。软依赖 function。 |

## 关键算法详解

### TaintPass 前向传播（XRef 加速跳跃）

核心优化：稀疏传播——只处理可能传播污点的指令。当前污点集只在 x2，而接下来 100 条都不读 x2，传统逐条遍历是浪费。用 XRef 的 `next_reader` 直接跳到下一个读 x2 的指令。使传播性能与 **tainted 指令数**成正比，而非 trace 长度。

每条指令：取 `state_before` → `opcode_at(pc)` → `decoder.decode` 或 `triton.process_instruction` → 检查写寄存器是否被污染 → 记录 PropagationStep。停止条件：max_instructions/max_taint_width/stop_pcs。

### BackwardTaintPass 反向传播（REG_WRITES 跳跃）

从 sink 反向追：当前 needed 集合 = {x0}。用 `index.find_last_writer_of(x0, current_id)` O(log N) 直接跳到写 x0 的指令，而非逐条回退。在该指令读的寄存器加入 needed，继续追。内存传播：若指令从内存 load，追到写该内存的 store（用 mem_write CF）。跨函数：BL 处若需 X0 则进 callee 追，RET 处回到 caller。

### CFGPass 从动态 trace 恢复

基本块边界：分支指令的目标 + 被跳转到的地址。边：每个 PC transition (from→to) 建边，类型由 from 指令决定（FallThrough/Branch/Conditional/Call/Return/Indirect），taken_count++。`extract_function` 用 BFS 遍历可达块（跳过 Call 的非 fallthrough 边，保留过程内）。

### LoopSemanticsPass 循环语义分类

对每个 iteration_count≥2 的循环：用 XRef 的 PC bitmap O(K) 定位 header 的多次执行 → `regfile.state_before` 取 2-3 次迭代的寄存器状态 → 对比识别 active/invariant 寄存器 → 扫 body 指令检测特征（sbox=数据依赖索引的 LDR、xor_mix=EOR、shift_rotate=LSL/LSR/ROR、addition_chain=ADD/SUB、modular=MUL/UDIV）→ 按特征组合分类（Feistel/SPN/ARX/...）+ 置信度。

### PatternPass YARA + mnemonic 双路检测

构造缓冲区：寄存器值缓冲（8B LE diff 值拼接，带 offset→inst_id 映射）、syscall 缓冲（16B 条目）、代码缓冲（连续 opcode，带 offset→pc 映射）。YARA 扫描这些缓冲，命中后按 offset 反查 inst_id/pc。外加 inline mnemonic 检测（HW AES/SHA 指令、XOR 循环、MOVZ/MOVK 序列）。后者可由 `constant_materialization` 结果合成，避免重复扫。

## 自定义 Pass 开发

```cpp
#include "analysis/pass_manager.h"
class MyPass final : public AnalysisPass {
    std::string_view name() const override { return "my_analysis"; }
    std::string_view description() const override { return "..."; }
    std::vector<std::string_view> dependencies() const override { return {"xref"}; }
    PassResult run(PassContext& ctx) override {
        const auto& xref = ctx.require<XrefResult>("xref");
        // 用 ctx.regfile()/memory()/decoder() + xref 做分析
        return PassResult::success(MyResult{...});
    }
};
// main.cpp: pm.register_pass(std::make_unique<MyPass>());
```

**要点**：
- 结果类型放头文件（供其他 Pass `require<T>` 取）。
- 长耗时操作用 `ctx.progress(pct)` 报告，定期检查 `ctx.cancelled()`。
- 需扫 trace 时优先实现 `prepare_scan()/finish_scan()` 参与 Scan Fusion（`run_all` 模式下只扫一遍）。`run()` 中自建 local `TraceScanEngine` 作为独立执行的后备路径。
- 软依赖用 `try_require<T>`，硬依赖写进 `dependencies()`。
- 线程安全：`run()` 中创建的 RegisterFile/Decoder 等可变对象是 Pass 私有，无需加锁；共享只读对象（reader/index）天然安全。

## 性能预算

> 以下数字来自 **test_50m.bin**（真实 iOS App trace，19.8M 指令，block-compressed，50MB on disk → 1058MB logical），
> 在 Apple M1 上以 **RelWithDebInfo** 构建测量，RocksDB index + blob cache **已预热**（二次运行）。
> 首次运行需额外约 60s 构建 RocksDB 索引。

| Pass | 耗时（缓存热） | 说明 |
|------|---:|------|
| index_build | ~60s 首次 / **0**（缓存） | 构建 PC/inst/mem 倒排索引 |
| xref | **18.5 ms** | 并行分片扫描，Roaring64Map 倒排 |
| function | **318 ms** | BL/RET 配对 + 调用栈模拟，19.8M inst |
| loop | **2.3 ms** | CFG 支配树循环检测（缓存命中） |
| loop_semantics | **0.03 ms** | 依赖 loop 结果，采样 2-3 次迭代 |
| cfg（单函数） | **< 1 ms** | 从 xref 结果派生，缓存命中近零 |
| cfg_layout | **0.4 ms** | Sugiyama 分层布局（单函数子图） |
| taint（全量） | **10156 ms** | 前向污点，trace 全程；稀疏 XRef 跳跃 |
| backward_taint | **1.9 ms** | 反向污点，REG_WRITES 索引跳跃 |
| call_graph | **0.34 ms** | 依赖 function 结果，纯构图 |
| pattern | **0.03 ms** | YARA + mnemonic 检测（缓存命中） |
| constant_materialization | **0.7 ms** | MOVZ/MOVK 常量链匹配 |
| strings | **0.2 ms** | 内存字节缓存 → 字符串扫描（缓存命中） |
| memory_snapshot | **1031 ms** | 1000 个调用点快照，page-sorted batch read |
| objc | **0.16 ms** | ObjC 消息解析（缓存命中） |
| symbol_annotation | **485 ms** | 聚合多 pass 注释，by_pc/by_inst_id 构建 |
| algorithm_summary | **0.18 ms** | 综合推断，依赖上游 pass 缓存 |
| dataflow_graph | **0.9 ms** | 寄存器依赖图（5000 节点上限） |
| thread | **0.01 ms** | 线程上下文切换统计（缓存命中） |

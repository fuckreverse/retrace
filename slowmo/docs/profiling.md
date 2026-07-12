# 性能分析与优化

tenet 使用 macOS 原生 Instruments 工具链进行性能分析，通过 `os_signpost` API 提供自定义标记，无第三方依赖。

## 工具链概览

| 工具 | 用途 | 命令/入口 |
|------|------|-----------|
| Time Profiler | CPU 热点采样（函数级） | `xctrace record --template 'Time Profiler'` |
| System Trace | 线程调度/上下文切换/syscall | `xctrace record --template 'System Trace'` |
| CPU Counters | 硬件 PMU（IPC/cache miss/分支预测） | `xctrace record --template 'CPU Counters'` |
| Allocations | 内存分配追踪 | `xctrace record --template 'Allocations'` |
| os_signpost | tenet 自定义区间标记（Pass 耗时等） | 自动出现在 Points of Interest |

## 快速开始

### 1. 构建（保留调试符号）

```bash
cd tools/tenet/build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -j$(nproc)
```

`RelWithDebInfo` 是性能分析的最佳构建类型：`-O2 -g` 保证运行速度接近发布版本，同时 DWARF 符号让 Instruments 能显示函数名和源码行号。

### 2. 录制 Time Profiler（最常用）

```bash
# 启动并录制
xcrun xctrace record \
    --template 'Time Profiler' \
    --output tenet-profile.trace \
    --launch -- ./tenet --algorithm-summary /path/to/trace.bin

# 打开分析
open tenet-profile.trace
```

### 3. 附加到已运行进程

```bash
# 先启动 tenet（例如 GUI 模式）
./tenet trace.bin &

# 附加录制 30 秒
xcrun xctrace record \
    --template 'Time Profiler' \
    --output tenet-attached.trace \
    --time-limit 30s \
    --attach $(pgrep tenet)
```

### 4. 查看 os_signpost 标记

录制完成后在 Instruments 中：

1. 打开 `.trace` 文件
2. 在时间线区域找到 "Points of Interest" 行（自动出现）
3. 或手动添加 "os_signpost" instrument 查看完整的 `com.tenet.profiler` 日志

每个标记对应代码中的 `TENET_ZONE_NAMED("...")` 调用，显示 Pass 名称和精确耗时。

## os_signpost 集成

### 代码插桩

```cpp
#include "common/Profiling.h"

void MyPass::run(PassContext& ctx) {
    TENET_ZONE_NAMED("MyPass::run");   // 整个 Pass 的区间
    // ... 分析逻辑
}
```

宏定义在 `src/common/Profiling.h`，当 `TENET_ENABLE_PROFILING=ON`（默认）且目标为 macOS 时展开为 `os_signpost_interval_begin/end` RAII 对象。非 macOS 或关闭时编译为零开销 no-op。

### 可用宏

| 宏 | 说明 |
|----|------|
| `TENET_ZONE` | 自动以函数名为标记名 |
| `TENET_ZONE_NAMED("name")` | 指定标记名 |
| `TENET_ZONE_COLOR("name", color)` | 等同于 NAMED（os_signpost 无颜色概念） |

### 当前标记点

| 位置 | 标记名 | 说明 |
|------|--------|------|
| `pass_manager.cpp` | `PassManager::run_all_parallel` | 整个并行 Pass 调度 |
| `pass_manager.cpp` | 各 pass name | 单个 Pass 执行区间 |
| `index_builder.cpp` | `TraceIndex::open_or_build` | 索引加载/构建 |
| `index_builder.cpp` | `TraceIndex::build` | 纯索引构建 |
| `trace_reader.cpp` | `TraceReader::open` | trace 文件打开 |
| `register_file.cpp` | （函数名） | 寄存器状态重建 |
| `memory_model.cpp` | `MemoryModel::build` | 内存模型构建 |
| `gui_app.mm` | `GuiApp::render_frame` | GUI 单帧渲染 |

## 典型分析场景

### 场景 1：定位最慢的 Pass

```bash
xcrun xctrace record --template 'Time Profiler' \
    --output passes.trace \
    --launch -- ./tenet --taint 0 trace.bin
```

在 Instruments 中查看 "Points of Interest"，直接看到每个 Pass 的执行时间条。点击最长的条，在下方 Call Tree 中展开看具体热点函数。

### 场景 2：分析 TBB 并行效率

```bash
xcrun xctrace record --template 'System Trace' \
    --output parallel.trace \
    --launch -- ./tenet --call-graph cg.dot trace.bin
```

在 System Trace 视图中观察线程时间线，看 TBB worker 线程是否有大量空闲（调度空洞）。如果线程利用率低，可能需要调整 Pass 粒度或依赖关系。

### 场景 3：微架构级优化

```bash
xcrun xctrace record --template 'CPU Counters' \
    --output counters.trace \
    --launch -- ./tenet --cfg trace.bin
```

查看 IPC（Instructions Per Cycle）、L1/L2 cache miss rate、branch misprediction。低 IPC + 高 cache miss 通常意味着数据布局需要优化（AoS → SoA、预取、减少指针追踪）。

### 场景 4：内存分配热点

```bash
xcrun xctrace record --template 'Allocations' \
    --output alloc.trace \
    --launch -- ./tenet --xref trace.bin
```

找到高频分配路径（每秒 10k+ 次 malloc），考虑用 arena allocator 或 pool 替换。

## 导出与自动化

```bash
# 列出 trace 中的数据表
xcrun xctrace export --input profile.trace --toc

# 导出特定表为 XML（可脚本解析）
xcrun xctrace export --input profile.trace \
    --xpath '/trace-toc/run/data/table[@schema="time-profile"]' \
    > samples.xml
```

## CMake 选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `TENET_ENABLE_PROFILING` | ON | 启用 os_signpost 标记（仅 macOS 生效） |

关闭方式：

```bash
cmake .. -DTENET_ENABLE_PROFILING=OFF
```

关闭后所有 `TENET_ZONE*` 宏编译为 `(void)0`，零运行时开销，无需改动源码。

## 性能基准

项目自带基准测试套件，用于回归检测：

```bash
# 运行基准测试
cd tools/tenet/bench
bash run_benchmark.sh

# 运行性能单元测试
cd tools/tenet/build
ctest -R perf --output-on-failure
```

基准数据保存在 `bench/baseline_1M.json`，新的测试结果应与之对比。

### PGO 模式

`TENET_PGO_MODE` 支持 `generate` / `use` 两阶段 profile-guided optimization，profile 文件由 `TENET_PGO_PROFILE` 指定。PGO 只用于稳定 workload 的最终优化，不应替代 RelWithDebInfo 下的日常 profiling；生成与使用阶段必须保持编译器、源码和代表性输入一致。

## 最佳实践

1. **构建类型选择**：性能分析始终用 `RelWithDebInfo`，Debug 版本的 `-O0` 会引入大量虚假热点。
2. **多次采样取中位数**：单次运行受系统负载影响，至少录制 3 次。
3. **隔离变量**：分析时关闭不相关后台进程，保持 CPU 温度稳定（避免降频）。
4. **自顶向下**：先 Time Profiler 定位函数级热点 → 再 CPU Counters 看微架构瓶颈 → 最后针对性优化。
5. **保留 signpost**：`TENET_ZONE_NAMED` 调用开销在未录制时几乎为零（~1ns 判断 `os_signpost_enabled`），可以长期保留在代码中。

## Pass 性能优化方法论

### 四项原则

对任何 Pass 做性能优化前，先用这四条标准审视热路径：

1. **不做多余的事**——如果结果不被使用或已知无效，不要启动计算。例如：对明显不是指针的值（小整数、内核地址、ObjC tagged pointer）跳过 `read_region()` 解引用。
2. **不做重复的事**——相同输入必须产生相同输出的操作应缓存。例如：同一 selector 指针地址在整个 trace 中始终指向同一字符串，只需解析一次。
3. **使用高效算法和正确的数据结构**——单次扫描优于多次遍历；batch 读优于逐字节读；`ankerl::unordered_dense::map` 优于 `std::unordered_map`；page-sorted 批量 IO 优于随机 IO。
4. **避免锁等影响并发的操作**——Pass 内部数据对 Pass 私有，不需加锁。共享只读对象（reader/index）天然安全。需要修改共享状态时用 CAS 或 per-thread 收集 + 最终合并。

### 优化流程

```
1. 确定瓶颈（profiling / bench_all_passes 计时）
       ↓
2. 分析热路径特征（代码审查 + 调用计数统计）
       ↓
3. 分类瓶颈（IO-bound / CPU-bound / 重复计算 / 锁竞争）
       ↓
4. 实施优化（缓存 / batch / 跳过 / 算法替换）
       ↓
5. 验证正确性（单元测试必须全量通过）
       ↓
6. 量化收益（对比前后耗时）
```

### 成功案例：memory_snapshot_pass（4.5× 加速）

**问题**：`memory_snapshot_pass` 在 50MB trace 上耗时 ~5.4s，其中 93% 时间花在 `capture_region()` 的 `read_region()` 调用上。核心瓶颈是 `MemoryModel::read_region()` 对每个字节做独立的 `upper_bound()` 查找（O(N·log W)），在热页（5.2M write entries）上极其昂贵。

**分析**：

- 热页特征：栈页面 `0x16EFFE000`，5.2M 条写入记录，每次 per-byte lookup 都做一次 `upper_bound`。
- 读取模式：`capture_region` 请求的区域通常是连续字节（栈帧、堆缓冲区），不需要 N 次独立二分查找。
- 重复扫描：多个 snapshot 请求可能读同一页面的不同区域，page 内数据可以批量读取利用 locality。

**优化措施**：

1. **`index_read_range()`**（新 MemoryModel API）：对 N 个连续字节，单次 `upper_bound` + 一次反向扫描即可覆盖所有字节，复杂度从 O(N·log W) 降为 O(log W + S)，其中 S 是扫描的 entry 数。
2. **两阶段 page-sorted batch read**：收集所有 snapshot 的读请求 → 按 page 排序 → 顺序执行。相邻的 page 读取复用 RocksDB iterator seek 位置，利用 block cache locality。
3. **消除重复 page 读取**：同一 page + 同一 inst_id 的多次读请求合并为一次。

**结果**：5.4s → 1.2s（4.5× 加速）。热页从 5.2M 次 upper_bound 减少到 ~1000 次 range scan。

**关键教训**：

- bench 工具必须使用 RocksDB-backed MemoryModel（`MemoryModel memory(reader, index, index.raw_db(), index.mem_write_cf(), index.mem_read_cf())`），否则 `index_read_range` 优化路径不会生效，测出来的数字毫无意义。
- 增量编译 Debug 模式足够验证正确性，但性能数字应在 `RelWithDebInfo` 下测量。

### 成功案例：objc_pass（缓存 + 指针过滤）

**问题**：`objc_pass` 对每条 ObjC 消息（通常数千到数万条）执行：selector 名称解析、参数寄存器读取、每个参数的字符串解引用、返回值的字符串解引用。其中 selector 解析和字符串解引用都涉及 `read_region()` 调用。

**分析**：

- **Selector 重复**：真实 trace 中唯一 selector 数通常只有几百个，但消息总数可达数万。例如 `init`/`alloc`/`setObject:forKey:` 各被调用上千次，每次都重新从 binary image 或 trace memory 读取同一字符串。
- **无效指针解引用**：参数寄存器可能是 ObjC tagged pointer（top nibble 非 0/1）、小整数枚举值（<0x1000）、内核地址。对这些值调用 `read_region()` 一定返回空，但仍触发 RocksDB lookup。
- **同一字符串对象被传递多次**：`NSString` 常量（如 `@"key"`）在不同调用中作为参数传递，每次都对同一地址做 `read_region()`。

**优化措施**：

1. **Selector name cache**（`ankerl::unordered_dense::map<uint64_t, std::string>`）：以 selector 指针地址为 key 缓存解析结果。ObjC runtime 保证 selector 唯一（同一 SEL 指针始终指向同一字符串），缓存命中率 ~95%+。
2. **String deref cache**（`ankerl::unordered_dense::map<uint64_t, optional<string>>`）：缓存指针值→解引用结果（含"解引用失败"的 nullopt 负缓存），避免对同一地址重复调用 `read_region()`。
3. **`is_likely_pointer()` 快速过滤**：在调用 `read_region()` 前判断地址是否可能是有效 userspace 指针——过滤掉 `<0x1000`（小整数）、`>=0xFFFF000000000000`（内核地址）、top nibble 非 0/1（ObjC tagged pointer）。这些情况直接返回 nullopt，零 IO 开销。
4. **增大 chunk size**（32→64 字节）：减少 `read_region()` 调用次数（selector 名平均 15-20 字符，一次 64B 读取通常一次完成）。

### 成功案例：ankerl::unordered_dense 全量迁移（function -26%，symbol_annotation -42%）

**问题**：`function_pass` 和 `symbol_annotation_pass` 的热路径中大量使用 `std::unordered_map/set`，其链式哈希实现每次查找涉及指针追踪，cache miss 率高。

**分析**：

- **`function_pass`**：`FunctionResult::call_stack_at()` 和内部 `CallEvent` 按 inst_id 索引的 map（`std::unordered_map`），在 327ms 的 pass 里被百万次查询。
- **`symbol_annotation_pass`**：`AnnotationResult::by_pc` 和 `by_inst_id` 为 `std::unordered_map<uint64_t, vector<Annotation>>`，每次 GUI 渲染或 CLI 输出都密集查询。
- **`string_pass`**（`StringCollector`）：`bytes_` 和 `addr_first_inst_` 是每条 MEM 事件都写入的热路径 map，`std::unordered_map` 内存碎片化导致高 cache miss。
- **根因**：`std::unordered_map` 使用链式哈希（bucket array + linked list），元素分散在堆各处，连续 `find()` 操作对 L1/L2 cache 不友好。`ankerl::unordered_dense` 采用开放寻址 + Robin Hood 哈希，所有元素紧凑存储在单一连续数组，查找路径局部性极佳。

**优化措施**：

将以下 11 个文件共 29 处 `std::unordered_map/set` 替换为 `ankerl::unordered_dense::map/set`：

| 文件 | 替换字段 |
|---|---|
| `string_pass.h` | `addr_to_index`、`inst_to_strings` |
| `string_pass.cpp` | `bytes_`、`addr_first_inst_`（StringCollector 热路径） |
| `memory_string_pass.h` | `by_addr`、`by_call_site`、`unique_hashes` |
| `memory_snapshot_pass.h` | `by_inst_id` |
| `symbol_annotation_pass.h` | `by_pc`、`by_inst_id` |
| `objc_pass.h` | `classes`、`by_pc` |
| `objc_crypto_pass.h` | `by_selector`、`by_class` |
| `syscall_intercept_pass.h` | `by_callee`、`by_category`、`api_by_name_` |
| `dataflow_graph_pass.h` | `inst_to_node` |
| `constant_materialization_pass.h`（已并入 `pattern_pass.h`，见下方“Pass 名称变更”） | `known_db_`、`known_db_32_`、`by_algorithm` |
| `algorithm_summary_pass.cpp` | `accum`（局部 EvidenceAccumulator map） |

注：`syscall_intercept_pass.h` 中的 `ApiCategory` 是 `enum class`，需在 `namespace tenet` 外补充 `ankerl::unordered_dense::hash<ApiCategory>` 特化（以 `static_cast<uint64_t>` 直接映射枚举值，标记 `is_avalanching`）。

**结果**（test_50m.bin，19.8M 指令，RelWithDebInfo，RocksDB blob cache warm）：

| Pass | 优化前 | 优化后 | 变化 |
|---|---:|---:|---|
| `function_pass` | 427.8 ms | 318.0 ms | **-26%** |
| `symbol_annotation_pass` | 838.0 ms | 484.7 ms | **-42%** |
| `xref_pass` | 20.3 ms | 18.5 ms | -9% |
| `taint_pass` | 10382.3 ms | 10156.1 ms | -2% |

**关键教训**：

- `std::unordered_map` 在元素数量不大（< 10K）但访问频次极高的场景（如每条 trace 指令都查询一次）中，cache miss 是主要瓶颈，替换 `ankerl::unordered_dense` 通常有 20-50% 提升。
- 对于 `enum class` key，需要显式提供 `ankerl::unordered_dense::hash<T>` 特化，否则编译报错。特化需放在 `namespace tenet` 之外（全局命名空间），且必须在 key 类型定义之后、使用之前。
- 替换后接口完全兼容（`find`/`operator[]`/`insert`/`emplace`/迭代器语义一致），无需修改调用侧代码。

### 测试策略

#### 1. 单元测试验证正确性

每次修改 Pass 后必须先跑对应单元测试确保无回归：

```bash
cd tools/tenet/build
ninja -j$(nproc) test_pass_objc test_pass_objc_crypto
./tests/test_pass_objc           # 应 ALL PASSED
./tests/test_pass_objc_crypto    # 应 ALL PASSED
```

#### 2. 无头模式（CLI）端到端计时

tenet 的 CLI 分析模式就是无头模式——传入分析参数（如 `--objc`、`--taint`、`--pattern` 等）时直接走 `batch_analysis` 路径，不启动 GUI/TUI，输出 JSON 到 stdout 后退出。这是测量单个 Pass 真实端到端耗时的标准方式：

```bash
cd tools/tenet/build

# 无头模式跑 ObjC 分析（含 index 加载 + pass 执行 + JSON 序列化）
time ./tenet --objc /path/to/trace.bin > /dev/null

# 无头模式跑多个 pass（观察各 pass 耗时比例）
time ./tenet --objc --pattern --algorithm-summary /path/to/trace.bin > /dev/null

# 精确测量：用 --run-pass 只跑指定 pass（跳过无关 pass 的注册和执行）
time ./tenet --run-pass objc /path/to/trace.bin > /dev/null
```

注意：首次跑需要构建 RocksDB 索引（~60s），之后会命中缓存（秒开）。测性能时先跑一次预热索引，再跑第二次取真实 Pass 耗时。

```bash
# 预热索引（结果缓存到 .tenet_cache_* 目录）
./tenet --objc /path/to/trace.bin > /dev/null 2>&1

# 第二次：索引命中缓存，测量的是纯 pass 执行时间
time ./tenet --objc /path/to/trace.bin > /dev/null
```

#### 3. bench_all_passes 全量 Pass 对比

用于测量所有 Pass 的增量耗时，一次运行出全量数据：

```bash
ninja bench_all_passes
./bench/bench_all_passes /path/to/trace.bin --output results.json

# 对比 baseline
python3 -c "
import json
baseline = json.load(open('bench/baseline_1M.json'))
current  = json.load(open('results.json'))
for p in current['passes']:
    name = p['name']
    b = next((x for x in baseline['passes'] if x['name'] == name), None)
    if b:
        ratio = p['own_ms'] / max(b['own_ms'], 0.1)
        flag = '⚠️' if ratio > 1.2 else '✓'
        print(f'{flag} {name}: {b[\"own_ms\"]:.1f}ms → {p[\"own_ms\"]:.1f}ms ({ratio:.2f}x)')
"
```

#### 4. Instruments 精确 profiling（找热点函数）

当 `time` 命令显示优化空间但不确定瓶颈在哪时，用 Instruments 采样：

```bash
cd tools/tenet/build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo && ninja -j$(nproc)

# 无头模式 + Time Profiler（只测 pass 执行，不含 GUI 开销）
xcrun xctrace record --template 'Time Profiler' \
    --output objc-opt.trace \
    --launch -- ./tenet --objc /path/to/trace.bin
open objc-opt.trace
```

#### 5. 构建类型选择

| 构建类型 | 用途 | 说明 |
|---------|------|------|
| Debug | 最快编译、调试与单元测试 | `-O0 -g`，运行慢（性能数字无参考价值） |
| RelWithDebInfo（默认） | 日常开发与**性能测量标准** | `-O2 -g`，无 LTO/PGO/-mcpu；兼顾增量链接与运行速度 |
| Release | 最终基准 / 发布 | `-O3` + ThinLTO，最快运行，编译最慢 |

```bash
# 切换到 RelWithDebInfo 测性能（在已有 build 目录重新 cmake，不新建目录）
cd tools/tenet/build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -j$(nproc) tenet
```

### 常见陷阱

- **bench 用错 MemoryModel 构造函数**：`MemoryModel memory(reader, index)` 使用的是 legacy in-memory 模式，`index_read_range()` 等 RocksDB 优化路径完全不生效。必须用 5 参数版本：`MemoryModel memory(reader, index, index.raw_db(), index.mem_write_cf(), index.mem_read_cf())`。
- **Debug 模式测性能**：`-O0` 下 inline 全部关闭，函数调用开销放大 10 倍以上，会产生虚假热点。性能数字只在 `RelWithDebInfo` 或 `Release` 下有意义。
- **缓存失效假设**：ObjC selector 缓存假设同一地址→同一字符串（runtime 保证）。String deref 缓存假设字符串内容不变（对 NSString 常量成立，对可变堆字符串可能不精确——但对 ObjC pass 的参数显示用途完全可接受，非精确分析场景）。
- **负缓存的重要性**：`deref_cache_` 存储 `nullopt` 表示"此地址解引用失败"。如果不缓存失败结果，每次遇到相同的无效指针仍会触发 `read_region()` → RocksDB lookup。

---

## Pass 优化技术全景

对全部 30 个 Pass 进行系统性代码分析后，将所有优化手段归纳为以下 9 类。每类注明了已使用的 Pass 和可进一步推广的 Pass，供下一步优化参考。

### 1. 高速哈希表：`ankerl::unordered_dense`

**原理**：基于 Robin Hood 哈希 + 开放寻址，元素紧凑存储在单一连续数组，cache line 命中率比 `std::unordered_map`（链式哈希）高 3-5×。在每条指令都要查表的热路径上效果最显著。

**已用 Pass**：

| Pass | 用于哪些结构 |
|---|---|
| `pattern_pass` | `by_category`、`pc_info_`、`hw_sites_`、`constants.by_algorithm`（内嵌的 constant materialization 子结果） |
| `objc_pass` | `sel_name_cache_`、`deref_cache_` |
| `window_stats_pass` | `pc_cache_`、`mnemonic_counts_`、`unique_pcs_`、`unique_mem_addrs_` |
| `dataflow_graph_pass` | `incoming_edge_idx_`、`outgoing_edge_idx_` |
| `taint_source_annotation_pass` | 主结果表 |
| `loop_pass`、`cfg_pass`、`xref_pass` | 块 / PC / xref 索引 |

**可推广的 Pass**：`string_pass`（`addr_to_index`，`std::unordered_map`）、`memory_string_pass`（`unique_hashes`、`by_addr`）、`disassembly_pass`（`pc_table`）、`thread_pass`（call map）、`syscall_intercept_pass`（各统计表）。

---

### 2. RocksDB Blob 持久化缓存（全量 Pass Cache）

**原理**：首次全量扫描后，将结果序列化为自定义紧凑二进制格式（magic + version + fixed-size records）写入 RocksDB。后续运行直接反序列化跳过所有计算，将"分钟级"变为"毫秒级"。比 JSON/Protobuf 序列化快 5-10×，体积更小。

**已用 Pass**：几乎所有需要全量遍历的 Pass，包括 `xref`、`function`、`cfg`、`cfg_layout`、`call_graph`、`taint`、`backward_taint`、`string`、`memory_string`、`memory_snapshot`、`disassembly`、`pattern`（内嵌 constant materialization）、`algorithm_summary`、`objc`、`objc_crypto`、`window_stats`、`dataflow_graph`、`thread`、`syscall_intercept`、`trace_fold`。（`index_build` 不是 PassManager 里的 pass，是 `--index-build` 单独触发的索引构建/重建选项，见 [`analysis-layer.md`](analysis-layer.md)。）

**关键设计变体**：`memory_string`、`memory_snapshot`、`window_stats`、`trace_fold` 额外实现了**参数感知缓存**——只有当前参数与默认参数完全相同时才读写缓存，避免配置不匹配导致复用错误结果（`trace_fold` 覆盖 `min_iterations_to_fold`/`keep_iterations`/`include_reg_summary`/`include_fpr_summary`/`pattern_sample_points` 全部字段）；`cfg_layout`、`dataflow_graph` 仅在 `ctx.range().is_full_trace()`（全量扫描）时读写缓存，区间/增量扫描不受影响。

**可推广的 Pass**：`reg_timeline_pass`（目前每次重算，已用 `TraceIndex::find_last_writer_of()` 加速单寄存器查询但结果未持久化）、`mem_search_pass`（搜索结果可以 pattern hash 为 key 缓存，已含精确值搜索模式）、`entropy_pass`、`trace_diff_pass`。

---

### 3. 并行化：TBB 任务调度 + 分片扫描

**原理**：利用 TBB `task_group` 和 `parallel_sort` 进行数据并行和任务并行。

**已用 Pass**：

- **`PassManager`**：TBB `task_group` 实现 DAG 调度，依赖满足的 Pass 并行执行；lock-free CAS ready-queue 消除调度开销。
- **`xref_pass`**：最典型案例。将 trace 分成 N 个 shard（N = CPU 核数），每 shard 独立扫描。每个 shard 直接用原始指针算术解析 trace 字节（消除虚函数调用），扫完 `merge()` 合并。
- **`IndexBuilder`**（索引构建，位于 `io/index_builder.cpp`，非 pass）：`parallel_sort` 对地址/PC 数组排序（TBB 实现，O(N log N / P)）。

**可推广的 Pass**：

- `string_pass`：Phase 2 的连续地址段扫描相互独立，可 `parallel_for`。
- `entropy_pass`：多个内存区域的熵计算完全独立，可 `parallel_for`。
- `taint_pass`：理论上可按时间窗口分片 + 合并（有寄存器状态依赖，难度较高）。

---

### 4. Scan Fusion：多 Collector 单次遍历

**原理**：`TraceScanEngine` 单次遍历 trace，将每条记录广播给所有注册的 `TraceCollector`。11+ 个扫描型 Pass 共享一次 IO 遍历，替代各自独立扫描。`pattern_pass` 的 `PatternCollector` 现已内嵌 movz+movk 常量物化追踪（原独立的 `constant_materialization_pass` 已合并），在同一次扫描中顺带完成，进一步减少了 trace I/O。

**已用 Pass**：`xref`、`disassembly`、`cfg`、`function`、`string`、`thread`、`objc`、`pattern`（内嵌 constant materialization）、`window_stats`、`syscall_intercept`（通过 `prepare_scan()`/`finish_scan()` 接口参与）。

**可推广的 Pass**：

- `entropy_pass` + `memory_string_pass` 可共享同一次内存区域扫描。
- `reg_timeline_pass` + `disassembly_pass` 可合并（都需要全量指令遍历）。
- `string_pass` + `symbol_annotation_pass` 可合并（都扫内存读写事件）。

---

### 5. I/O 局部性优化：mmap Advise + 按页排序批量读

**原理**：通过空间局部性提升 MemoryModel / RocksDB block cache 命中率，减少随机 I/O。

**已用 Pass**：

- **`memory_snapshot_pass`（最典型）**：两阶段设计——Phase A 收集所有 `(addr, inst_id)` 请求但不读内存；Phase B 按 `page = addr >> 12` 排序后批量执行 `capture_region`。按页排序让同页访问连续，命中 MemoryModel 的 thread-local page cache。包含 `std::chrono` 精确计时对比，效果可量化，实测 5.4s → 1.2s（4.5×）。
- **`objc_pass`**：直接遍历 raw trace 字节（绕过 `TraceScanEngine` 抽象），只处理 OBJC 记录（kind=5），跳过 >99.99% 的 INST 记录。`advise_sequential()`/`advise_random()` 切换 mmap 预读策略。
- **`taint_pass`、`xref_pass`、`backward_taint_pass`、`mem_search_pass`**：显式调用 `advise_sequential()` 提示 OS 预读。（`slice_pass`/`literal_search_pass` 已废弃：前者被 `backward_taint` 取代，后者合并进 `mem_search`。）
- **`entropy_pass`、`syscall_intercept_pass`**：以 16 字节为单位批量调用 `memory.read()`，比逐字节 `byte_at()` 减少 RocksDB seek 次数 16×。

**可推广的 Pass**：

- `loop_pass`：遍历 CFG 块时按 PC 排序后访问，提升 code_table 局部性。
- `backward_taint_pass`：按内存地址批量请求 `find_last_writer_of`（当前逐个请求）。
- 任何涉及内存读取的 Pass：检查是否可将分散的地址请求先收集、排序、再批量提交。

---

### 6. Index 跳跃：O(log N) 定位，避免线性扫描

**原理**：利用 RocksDB 索引或预建的事件列表做二分/seek 定位，跳过不相关的大段 trace，避免从起点线性扫描。

**已用 Pass**：

| Pass | 跳跃机制 |
|---|---|
| `taint_pass` | `index.offset_of(inst_id)` + `reader.seek(offset)` 直接定位指令 |
| `backward_taint_pass` | `index.find_last_writer_of(reg, before_inst)`（一次跳过数十万指令）+ RocksDB `SeekForPrev` 反向查最近写入，O(log N)（原 `slice_pass`/`producer_chain_pass` 的 `offset_of_with_pc`/`SeekForPrev` 跳跃逻辑已废弃并合并到这里，两个 pass 均已从 catalog 移除） |
| `call_context_pass` | `lower_bound` 二分定位 `FunctionResult` 中的 call/ret 事件 |
| `dataflow_graph_pass` | `index.offset_of()` 定位子图起点 |
| `thread_pass` | 4 处 `std::lower_bound` 在有序事件列表上二分搜索 |

**可推广的 Pass**：

- `reg_timeline_pass`：当前从指定 inst_id 往前线性扫描，可改为反向 seek。
- `mem_search_pass`：对稀疏匹配引入地址区间索引，避免扫描不含目标的区域。
- `loop_semantics_pass`：定位 loop header 的多次执行可利用 XRef 的 PC→inst_id 倒排直接跳转。

---

### 7. 位操作与紧凑数据表示

**原理**：用位操作替代集合容器，用 bitmap 替代 `unordered_set`，减少内存占用和迭代开销。

**已用 Pass**：

| Pass | 位操作技术 |
|---|---|
| `taint_pass`、`backward_taint_pass` | 寄存器集合用 `uint64_t bitmask`（34 个 GPR 刚好覆盖），`__builtin_ctzll(mask)` 迭代非零位；stack-local 数组消除热路径堆分配 |
| `thread_filter_pass` | **Roaring64Map**（roaring bitmap）存储线程指令 ID 集合，`contains()` O(1)，内存远小于 `unordered_set<uint64_t>` |
| `memory_snapshot_pass` | `known` 标志位向量序列化时 bit-packing（每字节存 8 个 boolean），压缩比 8:1 |
| `xref_pass` | PC→inst_id 倒排用 `Roaring64Map` bitmap |
| `slice_pass` | 64-bit bitmask 标记 active 寄存器集合 |
| `taint_source_annotation_pass` | `__builtin_ctzll` 迭代寄存器 bitmask |

**可推广的 Pass**：

- `cfg_pass`：基本块 predecessor/successor 集合（当前 `vector`），块数 < 64 时可改为 `uint64_t` bitset。
- `call_graph_pass`：visited 集合改用 Roaring bitmap（函数 PC 离散，roaring 效果好）。
- `loop_pass`：loop body 的 inst_id 集合可用 Roaring bitmap，减少内存并加速 `contains`。

---

### 8. 数据局部性与内存布局优化

**原理**：减少堆分配、复用已有内存、利用访问模式的时间局部性。

**已用 Pass**：

- **`function_pass`（热/冷路径两阶段分离）**：Phase 1 热路径每条 INST 只做 1-bit 的 `HF_BRANCH_HINT` 查找；Phase 2 冷路径只处理 CALL/RET/SVC 等少数事件（< 0.1% 指令）。
- **`pattern_pass`（1-entry PC 缓存）**：`last_pc_`/`last_cls_`/`last_mn_str_` 利用循环局部性，连续相同 PC 直接命中，跳过哈希查找。`char[12]` 固定大小存 mnemonic，避免 `std::string` 堆分配。`PCInfo::xor_ring_[8]` 环形缓冲区滑动窗口。
- **`window_stats_pass`**：`std::array<uint32_t, 34>` 替代 map 存寄存器写计数；window 结束后 `clear()` 复用容器内存而非重建。
- **`entropy_pass`**：三个工作 vector 在循环外 `reserve()`，循环内 `resize()`（no-op），复用堆内存。
- **`dataflow_graph_pass`**：`std::array<uint64_t, AARCH64_GPR_COUNT> last_writer` 固定大小 34 元素数组，O(1) 寄存器写追踪，零堆分配。

**可推广的 Pass**：

- `taint_pass`：`PropagationState` 向量在 hot loop 中频繁分配，改用 monotonic arena allocator 可消除 malloc 碎片（批量分配 O(1)，整体释放 O(1)）。
- `cfg_pass`：`BasicBlock` 对象生命周期一致（一次性构建，结果保留），适合 arena 分配。
- `backward_taint_pass`：回溯路径节点可用 pool allocator。

---

### 9. 算法级优化

**原理**：从算法复杂度或领域特性入手，不依赖底层 trick 就能获得数量级提升。

**已用 Pass**：

| Pass | 算法优化 |
|---|---|
| `loop_semantics_pass` | `regfile.warm_range(start, end)` 预热 loop 范围内所有 ANCHOR 缓存，避免后续数万次 random replay |
| `pattern_pass` | XOR loop 检测用环形缓冲区 `xor_ring_[8]`，O(1) 维护窗口内 EOR 密度 |
| `trace_fold_pass` | 折叠区间排序后单遍扫描（`[first_inst_id asc, span desc]` + 贪心跳过嵌套/重叠区间）避免嵌套循环重复计数；`regfile.warm_range()` 批量预热所有候选区间再采样，避免逐区间冷 replay；寄存器变化模式检测采用"均匀采样点 + 半迭代周期伴随点"两层策略，避免周期性振荡信号（如 +delta/-delta 交替的临时寄存器）在均匀采样步长恰好对齐周期时被误判为单调/常量（混叠问题） |
| `mem_search_pass`、`yara_mem_scan_pass` | YARA Aho-Corasick 自动机多模式匹配，O(N)（与 pattern 数无关） |
| `yara_mem_scan_pass` | 三级预过滤：写入次数 → known 数据量 → Shannon 熵，大幅减少实际扫描页数 |
| `objc_pass` | selector name cache 利用 ObjC runtime 保证（同一 SEL 指针始终同一字符串），缓存命中率 ~95%+ |

**可推广的 Pass**：

- `string_pass`：引入 Shannon 熵预过滤，跳过熵值极低（全零/统一字节）的内存区域。
- `xref_pass`：热 PC 的 xref 统计可用 `partial_sort` 只取 Top-K，减少全排序开销。
- `memory_string_pass`：复用 `yara_mem_scan` 的多级过滤框架（写入次数、已知字节量）。
- `algorithm_summary_pass`：引入分层采样——先用 1% trace 快速估算置信度，置信度足够则提前终止（近似查询处理思路）。

---

### 当前优化覆盖率矩阵

> `index_build` 不是 pass（`--index-build` 是索引构建/重建的 CLI 选项，不经过 PassManager，见 [`analysis-layer.md`](analysis-layer.md)），`slice`/`producer_chain`/`literal_search`/`constant_mat`（`constant_materialization`）已从 catalog 移除，不再单独出现在下表——它们的能力/优化已分别并入 `backward_taint`（Index 跳跃 ✓ SeekPrev、位操作）、`mem_search`（I/O 优化 ✓ advise）、`pattern`（Blob 缓存/Scan Fusion/ring-buf）。

| Pass | 高速哈希表 | Blob 缓存 | Scan Fusion | 并行化 | Index 跳跃 | 位操作 | I/O 优化 | 算法优化 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| xref | ✓ | ✓ | ✓ | ✓ shard | — | ✓ roaring | ✓ advise | — |
| function | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | ✓ hot/cold |
| cfg | ✓ | ✓ | ✓ | — | — | — | — | — |
| call_graph | ✓ | ✓ | — | — | — | — | — | — |
| taint | ✓ | ✓ | — | — | ✓ | ✓ bitmask | ✓ advise | — |
| backward_taint | ✓ | ✓ | — | — | ✓ SeekPrev | ✓ bitmask | ✓ advise | — |
| loop | ✓ | ✓ | — | — | — | — | — | — |
| loop_semantics | — | — | — | — | — | — | — | ✓ warm_range |
| string | — | ✓ | ✓ | — | — | — | — | — |
| memory_string | — | ✓ | ✓ | — | — | — | — | — |
| memory_snapshot | — | ✓ | — | — | — | ✓ bitpack | ✓ page-sort | — |
| disassembly | — | ✓ | ✓ | — | — | — | — | — |
| entropy | — | — | — | — | — | — | ✓ 16B batch | — |
| pattern | ✓ | ✓ | ✓ | — | — | — | — | ✓ ring-buf |
| algorithm_summary | — | ✓ | — | — | — | — | — | — |
| objc | ✓ | ✓ | — | — | — | — | ✓ raw-scan | ✓ sel-cache |
| objc_crypto | — | ✓ | — | — | — | — | — | ✓ binary-search |
| window_stats | ✓ | ✓ | ✓ | — | — | — | — | ✓ sliding-win |
| dataflow_graph | ✓ | ✓ | — | — | ✓ | — | — | — |
| thread_filter | — | — | — | — | — | ✓ roaring | — | — |
| thread | ✓ | ✓ | ✓ | — | ✓ binary | — | — | — |
| mem_search | ✓ | — | — | — | — | — | ✓ advise | ✓ YARA AC |
| reg_timeline | ✓ | — | — | — | ✓ anchor | — | — | — |
| symbol_annotation | — | ✓ | — | — | — | — | — | — |
| taint_src_annot | ✓ | — | — | — | — | ✓ ctzll | — | — |
| syscall_intercept | — | ✓ | ✓ | — | — | — | ✓ 16B batch | — |
| yara_mem_scan | — | — | — | — | — | — | — | ✓ multi-filter |

---

### 尚未引入但可考虑的优化方向

**1. 增量 Pass 执行（Dirty 标记传播）**

投入产出比最高的方向。当用户修改分析范围或过滤参数后，当前实现全量重算。`PassManager` 已有 DAG 框架，只需补充：Pass 结果的 range-keyed cache（key = inst_range + config hash）+ dirty 标记沿 DAG 向下游传播。未 dirty 的 Pass 直接复用缓存，只重算 dirty Pass 及其下游。

**2. SIMD 向量化**

**经分析，手写 NEON intrinsics 在当前架构下收益极低，不建议投入。** 原因如下：

- **编译器已经处理**：Release 构建使用 `-mcpu=apple-m1`，Clang 对满足条件的循环会自动生成 NEON 指令；手写 intrinsics 只能弥补编译器无法自动向量化的剩余场景。
- **候选场景的瓶颈不在计算**：`entropy_pass` 的核心是 256-bucket 频率统计（间接索引写 `freq[data[i]]++`），瓶颈是 RocksDB `read_region()` I/O（单次 ≥ 1μs），而非频率计算本身（4096B ≈ 0.4μs）；I/O 与计算比超过 1000:1，NEON 对总时间的改善 < 0.2%。`string_pass` 实测仅耗时 **0.2ms**，根本不是瓶颈。
- **热路径本质上不可向量化**：`taint_pass`（10s+）是 Triton 串行依赖链，`function_pass`（318ms）是条件分支密集的调用栈更新，`symbol_annotation`（485ms）是 hash map 批量插入——这三类都无法从 NEON 获益。
- **`entropy` 多区域批量场景**：即使 `yara_mem_scan` 对 50K 个页批量计算熵（50K × 0.4μs ≈ 20ms CPU），同期 I/O 仍以数量级压倒计算，NEON 对总时间的改变微乎其微。

如确实需要提升 `entropy_pass` 性能，应聚焦于减少 RocksDB seek 次数（如增大 batch 读取粒度、或引入页级别的预读缓存），而非向量化计算本身。

**3. 稀疏倒排索引（xref 扩展）**

当前 `xref_pass` 按时序存储执行记录。对"找所有调用 PC X 的位置"需顺序扫描。可为高频被调用 PC 建立稀疏倒排索引，实现 O(result) 而非 O(trace) 查询。

**4. GPU 加速（yara_mem_scan / entropy）**

**经分析，GPU offload 在当前架构下不可行，不建议投入。** 原因如下：

- **尚未实现**：`src/` 下没有任何 `.metal` 文件或 Metal Compute API 调用，属于未验证的假设。
- **真正瓶颈不在计算**：`yara_mem_scan` 和 `entropy` 均不是高耗时 Pass（未进 Top-5）；每页 `read_region()` 是 RocksDB I/O，GPU 无法加速数据库读取。
- **小数据量 + kernel launch overhead 倒挂**：单页 4KB，Metal kernel launch 延迟约 50-200μs，而 CPU 处理同等数据只需 < 1μs；overhead 远超计算本身。
- **YARA 不可 GPU 化**：Aho-Corasick 是分支密集型状态机，在 GPU warp 上存在严重的 warp divergence，实际性能可能劣于 CPU。
- **架构不配合**：最大瓶颈 `taint_pass`（占总时间 87%）是强顺序依赖的数据流传播，是 GPU 的天然死穴。

如需改善 `yara_mem_scan` 性能，应聚焦于：增大 `max_bytes_per_page`（当前 64KB）配合更积极的熵预过滤阈值，以及将所有页的 `read_region()` 请求按页地址排序后批量提交（类似 `memory_snapshot_pass` 的两阶段 page-sorted batch 设计），而非引入 GPU pipeline。

**5. Trace Column-Store 格式（整体 I/O）**

将 PC 列、寄存器列、内存列分离存储，配合 Delta/Zigzag 编码。PC 扫描（最频繁）只读 PC 列，不触碰寄存器数据，减少 I/O 放大。对 `xref`、`function`、`cfg` 等只需 PC 的 Pass 尤其有效。

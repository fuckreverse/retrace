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
| Debug（默认） | 开发迭代、单元测试 | `-O0 -g`，编译快，运行慢（性能数字无参考价值） |
| RelWithDebInfo | **性能测量标准** | `-O2 -g`，有符号可 profile，性能接近 Release |
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

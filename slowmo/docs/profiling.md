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

# Trace Diff 重设计：跨文件差分分析

## 1. 背景与动机

### 1.1 现状

当前 `TraceDiffPass`（`src/analysis/passes/trace_diff_pass.{h,cpp}`）只能比较同一 trace 文件内的两个 inst_id 区间。实现方式是把 Region A 全量加载到 `std::vector<InstSnapshot>` 内存中，再流式遍历 Region B 逐对比较。比较采用纯位置对齐（第 N 条对第 N 条），无重同步机制。

### 1.2 问题

1. **不支持跨 trace 文件比较**——差分分析的标准场景是：用不同输入录制两个独立的 `.bin` trace 文件，然后跨文件比较。当前实现要求用户在一个 Frida 脚本里连续调用两次目标函数并录制到同一 trace，这在实践中非常别扭。
2. **分歧后无法重新同步**——一旦 PC 在某处分叉，后续所有指令对的 PC 都不同，产生海量 `ControlFlow` diff 条目，淹没真正有用的信息。
3. **Region A 全量驻留内存**——每个 `InstSnapshot` 约 200 字节，100 万条指令约 200MB。对十亿级 trace 不可行。
4. **寄存器名映射不准确**——index 29 是 FP、30 是 LR、31 是 SP 等，但统一显示为 `x{index}`。
5. **只显示第一个差异**——一条指令的多个寄存器同时不同时，detail 只展示第一个。
6. **无单元测试**。

### 1.3 目标

重新设计 TraceDiffPass，支持：

- 跨文件比较两个独立 `.bin` trace 文件
- 分叉点检测 + 自动重同步（在下一个相同 PC 处重新对齐，继续找下一个分叉）
- 十亿级指令的存储和分析效率（工作内存 < 150MB）
- 向后兼容同 trace 区域比较模式
- CLI / GUI / MCP 三入口完整集成

## 2. 架构总览

### 2.1 Pass 自治模式

TraceDiffPass 在 config 中携带 `trace_b_path`。`run()` 中自行打开 trace B 的 `TraceReader`，通过 `TraceIndex::open_or_build()` 构建索引（首次约 60s，之后秒开）。Pass 持有 trace B 的 reader + index 生命周期，`run()` 结束后释放。不修改 `PassContext` 或 `PassManager` 接口。

如果 `trace_b_path` 为空，退回同 trace 区域比较模式（完全向后兼容）。

### 2.2 地址归一化

两条 trace 来自同一二进制但 ASLR slide 不同。比较前统一减去各自的 `module_slide`，转换为静态地址。如果 `module_name` 不一致，发出警告但仍继续（用户可能在比较不同版本）。

### 2.3 数据流

```
TraceDiffConfig (trace_b_path, ranges, window_size, max_diffs)
        |
TraceDiffPass::run()
    +-- 打开 trace B (TraceReader::open + TraceIndex::open_or_build)
    +-- 地址归一化 (减去各自 module_slide)
    +-- 获取两条 trace 的起始 offset (通过各自 sparse index)
    +-- 创建双迭代器 (create_thread_reader for lock-free)
    +-- 流式比较循环 (lockstep + resync)
    +-- 输出 TraceDiffResult
        |
   CLI JSON / GUI Panel / MCP Tool
```

## 3. 数据结构

### 3.1 TraceDiffConfig

```cpp
struct TraceDiffConfig {
    // 跨文件模式：指定 trace B 的路径。为空则退回同 trace 区域比较。
    std::string trace_b_path;

    // Region A (trace A / 主 trace)
    uint64_t trace_a_start = 0;
    uint64_t trace_a_end = UINT64_MAX;   // 默认全量

    // Region B (trace B，或同 trace 的第二个区域)
    uint64_t trace_b_start = 0;
    uint64_t trace_b_end = UINT64_MAX;

    // 重同步窗口大小（在双方各 lookahead 多少条指令中找匹配 PC）
    uint32_t resync_window = 16384;

    // diff 数量上限（防止十亿级比较产生海量 diff 条目）
    size_t max_diffs = 100000;

    // 是否在重同步时优先选择 CALL/RET 边界作为锚点
    bool prefer_call_ret_anchor = true;
};
```

### 3.2 DivergeSegment

结果以"分叉段"（DivergeSegment）为核心，而非扁平的 diff 列表。在十亿级 trace 上，分叉后逐条记录所有差异可能产生数百万条 entry。DivergeSegment 用 O(分叉次数) 条目（通常 <100）完整描述分叉-恢复模式，内存极小。

```cpp
enum class DiffType : uint8_t {
    ControlFlow,     // PC 不同——触发重同步
    RegisterValue,   // 同一 PC，寄存器输出值不同
    MemoryValue,     // 同一 PC，内存访问值不同
    OpcodeChange,    // 同一 PC，opcode 不同（自修改代码）
};

struct DivergeSegment {
    // 分叉起点
    uint64_t start_inst_a;     // trace A 中的 inst_id
    uint64_t start_inst_b;     // trace B 中的 inst_id
    uint64_t start_pc;         // 归一化后的静态 PC
    DiffType  start_type;      // 分叉类型
    std::string start_detail;  // 首个差异的描述

    // 重同步终点 (resynced=false 表示到 trace 结尾都未对齐)
    bool      resynced = false;
    uint64_t  resync_inst_a = 0;  // 重同步点的 inst_id (A)
    uint64_t  resync_inst_b = 0;  // 重同步点的 inst_id (B)
    uint64_t  resync_pc = 0;      // 重同步处的 PC

    // 分叉区域长度
    uint64_t  skip_a = 0;         // A 中跳过的指令数
    uint64_t  skip_b = 0;         // B 中跳过的指令数
};
```

### 3.3 TraceDiffResult

```cpp
struct TraceDiffResult {
    std::vector<DivergeSegment> segments;   // 所有分叉段
    uint64_t matched_count = 0;             // 完全匹配的指令对数
    uint64_t total_diverged = 0;            // 处于分叉区域的指令总数
    uint64_t resync_count = 0;              // 成功重同步次数
    bool     truncated = false;             // 是否因 max_diffs 截断

    // 便捷查询
    bool has_divergence() const { return !segments.empty(); }
    size_t permanent_divergence_count() const;  // resynced=false 的段数

    // 按类型过滤
    std::vector<const DivergeSegment*> control_flow_segments() const;
    std::vector<const DivergeSegment*> register_value_segments() const;
};
```

### 3.4 寄存器名映射

修正现有实现中统一用 `x{index}` 的问题。提供 `reg_name(uint8_t index)` 函数：

| index | 名称 |
|-------|------|
| 0-28 | x0-x28 |
| 29 | fp |
| 30 | lr |
| 31 | sp |
| 32 | nzcv |
| 33 | pc |

## 4. 核心算法

### 4.1 阶段 1：初始化

```
1. 如果 trace_b_path 非空：
   a. TraceReader::open(trace_b_path) -> reader_b
   b. TraceIndex::open_or_build(reader_b) -> index_b（带进度回调）
   c. 验证两条 trace 的 arch、num_gpr 一致
2. 计算 slide_a = reader_a.header().module_slide
        slide_b = reader_b.header().module_slide
3. 对 trace A 和 B 分别通过 index.offset_of() 跳到起始位置
4. 创建各自的 ThreadReader（lock-free 读取）
5. 初始化两个 Iterator
```

### 4.2 阶段 2：流式 lockstep 比较

```
while it_a != end_a and it_b != end_b:
    pc_a = it_a.pc - slide_a    // 归一化
    pc_b = it_b.pc - slide_b

    if pc_a == pc_b:
        // 同一指令，比较数据
        diff = compare_inst_data(it_a.inst, it_b.inst)
        if diff != None:
            record DivergeSegment(start=当前, type=diff.type, detail=diff.detail)
            // 数据差异不影响控制流，不触发 resync
            // 直接继续 lockstep（两条 trace 仍然对齐）
        ++matched_count  // PC 层面匹配
        ++it_a; ++it_b
    else:
        // 控制流分叉！
        -> 进入阶段 3：重同步
```

**关键决策：RegisterValue / MemoryValue 差异不触发 resync。** 两条 trace 执行同一条指令但数据不同，说明控制流仍然对齐，只是数据流有差异。只有 PC 不同（ControlFlow）才触发 resync。这避免了在"同一函数内大量数据差异"场景下产生无谓的 resync 扫描。

数据差异会被记录为 `resynced=false, skip_a=0, skip_b=0` 的 segment，表示"在此处分叉但未跳过任何指令"。

### 4.3 阶段 3：重同步

```
function try_resync(it_a, it_b, window_size):
    // 在 trace A 的窗口内建 PC -> offset 的哈希表
    pc_map = flat_hash_map<uint64_t, uint32_t>()
    probe_a = it_a
    for k in 0..window_size:
        if probe_a == end_a: break
        pc = normalize(probe_a.pc)
        if prefer_call_ret_anchor and probe_a.inst.branch_hint() in {CALL, RET}:
            pc_map.emplace(pc, k)  // 优先位置，覆盖已有
        else:
            pc_map.try_emplace(pc, k)  // 只记录第一次出现
        ++probe_a

    // 在 trace B 的窗口内查找匹配
    probe_b = it_b
    for k in 0..window_size:
        if probe_b == end_b: break
        pc = normalize(probe_b.pc)
        if pc in pc_map:
            // 找到重同步点！
            skip_a = pc_map[pc]
            skip_b = k
            return Found(skip_a, skip_b, pc)
        ++probe_b

    // 窗口内未找到匹配，尝试扩大窗口（2x 原大小），最多重试 2 次
    // 最大有效窗口 = resync_window * 2 * 2 = 65536（默认配置下）
    // 如果仍然失败，标记为永久分叉
    return NotFound
```

重同步成功后，记录一个 DivergeSegment（包含 skip_a / skip_b 长度），然后逐条前进两个 Iterator 跳过中间指令，从重同步点继续 lockstep。

**永久分叉处理**：如果重同步失败，记录 segment（resynced=false），然后尝试粗粒度恢复——跳到两个 trace 中各自下一个 ANCHOR 记录（完整寄存器快照点），从那里重新开始。如果到 trace 结尾都没有 ANCHOR，则终止比较。

### 4.4 指令数据比较

```cpp
struct InstDataDiff {
    DiffType type;
    std::string detail;
};

// 比较 reg_diffs 和 mem_accesses（PC 已确认相同）
// 返回 0、1 或 2 条差异（RegisterValue 和/或 MemoryValue）
std::vector<InstDataDiff> compare_inst_data(
    const InstView& a, const InstView& b
);
```

比较逻辑：
1. 比较 reg_diff_count 和每个 reg_diff 的 (index, value)。如果不同，收集**所有**差异寄存器（不仅第一个），构造 detail 字符串如 `"x0(A=0x1 B=0x2), x1(A=0x3 B=0x4)"`，生成一条 `InstDataDiff{RegisterValue, detail}`。
2. 比较 mem_access_count 和每个 mem_access 的 (addr, value)。同样收集所有差异，生成一条 `InstDataDiff{MemoryValue, detail}`。
3. 调用方对返回的 vector 中每条 `InstDataDiff` 生成一个 `DivergeSegment`（同一 inst_id，不同 type）。

### 4.5 进度报告

- 0-30%：trace B 索引构建（跨文件模式时）
- 30-100%：流式比较，按 `(inst_a_progress + inst_b_progress) / 2` 计算
- 每 `max(region_len / 100, 10000)` 条指令报告一次
- 取消检查同样每 10000 条一次，减少原子读开销

## 5. CLI 集成

### 5.1 命令行选项

```bash
# 跨文件比较（新）
./tenet --trace-diff-file traceB.bin \
        --trace-diff 0 1000000 0 1000000 \
        traceA.bin

# 同 trace 区域比较（向后兼容）
./tenet --trace-diff 0 1000000 5000000 6000000 traceA.bin

# 可选参数
--trace-diff-window 32768      # 重同步窗口大小（默认 16384）
--trace-diff-max-diffs 50000   # diff 上限（默认 100000）
```

新增 CLI 选项：
- `--trace-diff-file <path>` — trace B 文件路径
- `--trace-diff-window <N>` — 重同步窗口大小
- `--trace-diff-max-diffs <N>` — diff 数量上限

现有 `--trace-diff <a_start> <a_end> <b_start> <b_end>` 保持不变。

### 5.2 JSON 输出格式

```json
{
  "matched_count": 847291,
  "total_diverged": 152709,
  "resync_count": 3,
  "truncated": false,
  "segments": [
    {
      "start_inst_a": 12345,
      "start_inst_b": 12345,
      "start_pc": "0x100004A0",
      "type": "ControlFlow",
      "detail": "PC diverged: A=0x100004A0 B=0x100004B4",
      "resynced": true,
      "resync_inst_a": 12500,
      "resync_inst_b": 12480,
      "resync_pc": "0x100005C0",
      "skip_a": 155,
      "skip_b": 135
    },
    {
      "start_inst_a": 847292,
      "start_inst_b": 847292,
      "start_pc": "0x100008F0",
      "type": "RegisterValue",
      "detail": "x0(A=0x1 B=0x2), x1(A=0x3 B=0x4)",
      "resynced": false,
      "skip_a": 0,
      "skip_b": 0
    }
  ]
}
```

## 6. GUI 集成

### 6.1 面板布局

Trace Diff 面板重新设计：

- **顶部**：Trace B 文件选择器（File Dialog + 路径显示 + 索引构建进度条）
- **Region 输入**：Region A / Region B 各两组 start/end，加 "Full Trace" 和 "Set = current" 快捷按钮
- **参数**：重同步窗口大小输入框（默认 16384）
- **Run Diff 按钮**

### 6.2 结果表格

Segment 视图，使用 ImGuiListClipper 虚拟滚动：

| 列 | 内容 | 宽度 |
|----|------|------|
| # | segment 序号 | 40px |
| Type | ControlFlow / RegValue / MemValue / OpcodeChange | 100px |
| Inst A | start_inst_a | 80px |
| Inst B | start_inst_b | 80px |
| PC | 归一化 PC (0x...) | 140px |
| Skip A | skip_a 指令数 | 80px |
| Skip B | skip_b 指令数 | 80px |
| Resync PC | 重同步处 PC（永久分叉显示 "—"） | 140px |
| Detail | 差异详情 | stretch |

行颜色：
- ControlFlow: 橙色 `(1.0, 0.5, 0.2)`
- RegisterValue: 蓝色 `(0.4, 0.8, 1.0)`
- MemoryValue: 紫色 `(0.8, 0.6, 1.0)`
- OpcodeChange: 红色 `(1.0, 0.3, 0.3)`
- 永久分叉（resynced=false 且 type=ControlFlow）: 深红色背景

点击 segment 行：navigate 到 trace A 的 `start_inst_a`。

### 6.3 GUI App 状态变更

```cpp
// 新增成员
std::string trace_b_path_;              // 用户选择的 trace B 路径
uint32_t diff_window_size_ = 16384;      // 重同步窗口大小

// 移除 static TraceDiffResult，改为成员
std::unique_ptr<TraceDiffResult> trace_diff_result_owned_;
```

Trace B 的 reader 和 index 由 Pass 内部管理（run() 中打开，run() 结束后释放）。GUI 只持有路径和结果，不持有 trace B 的 IO 对象。trace B 的索引在 Pass 运行期间构建，进度通过 PassContext::progress 回调显示。

移除 `panels_trace_diff.cpp` 中的 `static TraceDiffResult s_result`，改为 `GuiApp` 成员变量 `trace_diff_result_owned_`。

## 7. MCP 集成

`trace_diff` 工具增加可选参数：

```json
{
  "trace_b_path": "/path/to/traceB.bin",
  "range_a_start": 0,
  "range_a_end": 1000000,
  "range_b_start": 0,
  "range_b_end": 1000000,
  "resync_window": 16384,
  "max_diffs": 100000
}
```

如果 `trace_b_path` 省略，使用同 trace 模式（向后兼容）。返回结果中 `segments` 数组替代现有的 `diffs` 数组，但保留 `matched_count` / `diverged_count` / `has_divergence` 字段。

## 8. PassRegistry 变更

`trace_diff` 的默认配置改为：不预设范围（`start=0, end=UINT64_MAX`），`trace_b_path` 为空。如果 `--run-pass trace_diff` 不带参数则 skip（返回 `PassResult::skipped()`）。

## 9. 内存与性能

### 9.1 内存预算

| 组件 | 大小 | 说明 |
|------|------|------|
| Trace B Reader | ~0 | mmap 零拷贝，仅文件描述符 |
| Trace B Index | ~50-100MB | RocksDB，首次构建后秒级加载 |
| 重同步哈希表 | 128KB-512KB | window_size x 8B，用完即释放 |
| DivergeSegment 列表 | ~1KB/段 | 通常 <100 段 = 100KB |
| 流式比较缓冲 | 0 | 两个 Iterator 各自前进，不预读 |
| **总计** | **<150MB** | 不含主 trace 已有的 index |

对比现有实现：当前把 Region A 全量加载到 `std::vector<InstSnapshot>`（每条约 200B），100 万条 = 200MB。新设计完全消除这个开销。

### 9.2 性能优化

1. **ThreadReader 无锁读取**：两条 trace 各自创建 `ThreadReader`，避免 block-compressed 模式下的 LRU 缓存锁竞争。
2. **批量进度检查**：每 10000 条检查一次 `cancelled()`，减少原子读开销。
3. **重同步窗口用 flat_hash_map**：absl::flat_hash_map 或 robin_hood::map，比 std::unordered_map 快 3-5x。key 是 uint64_t（归一化 PC），value 是 uint32_t（窗口内偏移）。
4. **避免 fmt::format 在热路径**：segment 的 detail 字符串只在确认分叉后才构造，不在 lockstep 比较的内层循环中。
5. **v5 PC 重建**：重同步时跳过的指令需要逐条前进 Iterator（不能简单 `+= skip * record_size`），但 16K 条前进只需 ~0.5ms。
6. **内存上限保护**：`max_diffs` 达到上限后设置 `truncated=true`，停止记录新 segment，但继续统计 matched/diverged count。

### 9.3 十亿级 trace 时间估算

两条 trace 各 10 亿条指令，PC 匹配率 99.9%（约 1000 个分叉点）：

- 索引构建（trace B）：~60s（首次）/ ~2s（缓存命中）
- Lockstep 比较：10 亿 x ~100ns/条 = ~100s（mmap 顺序读取，CPU 缓存友好）
- 重同步：1000 次 x 16K x ~100ns = ~1.6s
- **总计**：~102s（缓存命中）/ ~162s（首次）

## 10. 测试策略

### 10.1 单元测试（GTest）

| 测试 | 验证点 |
|------|--------|
| `test_trace_diff_same_trace` | 同 trace 内两个区域比较，向后兼容 |
| `test_trace_diff_cross_file_identical` | 同一文件作为 A 和 B，matched_count = 总指令数 |
| `test_trace_diff_cross_file_diverge` | 两条不同 trace，第一个 segment 的 start_pc 和 type 正确 |
| `test_trace_diff_resync` | 分叉后重同步：skip_a / skip_b / resync_pc 正确 |
| `test_trace_diff_permanent_divergence` | 窗口内找不到匹配，resynced=false |
| `test_trace_diff_address_normalization` | 两条 trace slide 不同，PC 归一化后正确匹配 |
| `test_trace_diff_max_diffs` | 达到上限后 truncated=true，count 仍继续统计 |
| `test_trace_diff_progress_cancel` | 进度回调和取消机制 |
| `test_trace_diff_reg_name` | 寄存器名映射：fp/lr/sp/nzcv/pc |

### 10.2 测试 trace 生成

使用 qbditrace 的 host 测试模式录制小型 trace（几千条指令），同一函数用不同输入调用两次，生成两个 .bin 文件。

### 10.3 集成测试

CLI 端到端：运行 `./tenet --trace-diff-file traceB.bin --trace-diff 0 10000 0 10000 traceA.bin`，验证 JSON 输出格式。

## 11. 文件变更清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `src/analysis/passes/trace_diff_pass.h` | 重写 | 新 config、DivergeSegment、TraceDiffResult |
| `src/analysis/passes/trace_diff_pass.cpp` | 重写 | 跨文件打开、lockstep+resync 算法 |
| `src/cli_options.h` | 编辑 | 新增 trace-diff-file / window / max-diffs 选项 |
| `src/cli_options.cpp` | 编辑 | 解析新选项 |
| `src/batch_analysis.cpp` | 编辑 | 适配新 config 和 JSON 输出 |
| `src/gui/gui_app.h` | 编辑 | 新增 trace B 状态成员 |
| `src/gui/panels_trace_diff.cpp` | 重写 | 新面板布局、segment 表格 |
| `src/io/mcp/mcp_tools_analysis.cpp` | 编辑 | MCP 工具参数扩展 |
| `src/analysis/pass_registry.cpp` | 编辑 | 默认配置调整 |
| `tests/test_trace_diff.cpp` | 新建 | 单元测试 |

## 12. 向后兼容性

- `--trace-diff <a_start> <a_end> <b_start> <b_end>` 不带 `--trace-diff-file` 时，行为与当前实现一致（同 trace 区域比较），但内部算法升级为 lockstep + resync。
- MCP `trace_diff` 工具不传 `trace_b_path` 时，同 trace 模式。
- `TraceDiffResult` 结构变化是 breaking change，但由于 trace_diff 尚无外部消费者，影响仅限于 tenet 内部的 CLI/GUI/MCP 代码。
- 现有 GUI 面板的 Region A / Region B 输入框保留，新增 Trace B 文件选择器在顶部。

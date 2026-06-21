# Core 层

> 职责：在 IO 层的原始记录流之上，重建程序执行的**完整状态快照**（寄存器/内存/指令语义），并桥接 Triton。
> 源码：`src/core/`。是 Analysis 层与 IO 层之间的「状态预言机」。

## 组件清单

| 文件 | 类 | 职责 |
|------|------|------|
| register_file.{h,cpp} | `RegisterFile` | 任意 inst_id 的寄存器状态 O(1) 重建 |
| memory_model.{h,cpp} | `MemoryModel` | 时间索引内存（带写历史） |
| instruction_decoder.{h,cpp} | `InstructionDecoder` | Capstone 反汇编 + LRU 缓存 |
| triton_bridge.{h,cpp} | `TritonBridge` + `TritonPool` | Triton 语义引擎桥接（可选，stub 降级） |
| breakpoint_engine.{h,cpp} | `BreakpointEngine` | 时空断点/观察点（前向+后向） |

## RegisterFile — Anchor + Diff + LRU

**算法**：trace 每 ~4096 条 INST 夹一个 ANCHOR 全量快照，中间 INST 只存 diff。重建 inst_id=N：
1. `index.nearest_anchor_before(N)` → 二分找到 ≤N 的最近 anchor。
2. 加载 anchor 的 34 个 GPR 全量值。
3. 从 anchor 向前顺序扫，逐条 apply diff（`InstView.reg_diff(i)` 覆盖对应寄存器）。
4. 结果存入 LRU。

**接口**：
- `state_before(inst_id)` → `const RegState&`（主接口，返回引用可能被后续 LRU 淘汰失效）。
- `state_after(inst_id)` → 值返回（= before + apply 本条 diff）。
- `warm_range(start, end, stride, progress)` → 预热缓存：按 stride 采样若干 checkpoint 插入 LRU，使后续 `state_before()` 命中附近 baseline，最多 replay stride 条而非几千条。Pass 在密集遍历前调用。
- `warm_at(inst_id)` → 预热单点。
- `cache_stats()` → hits/misses/warm_samples。

**LRU**：4096 条 × 272B ≈ 1.1MB。用 `common/types.h` 的零分配 LRU（数组 + 侵入式链表）。

**性能**：cache hit <1μs；跨 anchor 随机跳转 ~500μs（加载 anchor + apply ≤4096 diff）；`warm_range` 批量 ~2ms/万条。

**双向遍历**：LRU 存 `state_before`。`state_after(id)` = `state_before(id+1)` = `state_before(id)` + apply diff[id]。逆向单步若 LRU 有前一条则直接命中。

## MemoryModel — 时间索引内存

**设计**：所有内存写按 `[page(8)|page_off(2)|inst_id(8)]` 大端编码存入 RocksDB `mem_write` CF。单条 N 字节写产生 1 个 KV（跨页拆 2 个），value = `[size(1)|data]`。这比逐字节存省 8-16x KV 数量。

**读查询** `read(addr, size, at_inst_id)`：
1. page = addr >> 12。
2. 用 RocksDB iterator `SeekForPrev([page|target_byte_off|at_inst_id])`。
3. 向前回扫，找覆盖目标字节的写（写的 `[page_off, page_off+size)` 覆盖 target_byte）。
4. 回扫上限 = MAX_WRITE_SIZE-1（16B 写最多覆盖前 15 字节）。
5. 拼装 `MemReadResult{data[16], known[16], writer_id[16]}`。

**mem_read CF 的妙用**：read 访问携带当时内存值。若某地址从未被追踪代码写过（如未插桩代码准备的 buffer），可从最近 read 恢复值。编码与 mem_write 相同。

**接口**：
- `read(addr, size, at_inst_id)` → 16B 内结果。
- `read_region(addr, size, at_inst_id)` → 任意大小，内部分块。
- `last_writer(addr, size, before_id)` → inst_id。
- `write_history(addr, size)` → 所有写入时刻列表。
- `byte_at(addr, at_inst_id)` → 单字节。
- `active_pages()` → 所有被访问过的页的活动统计（PageActivity：first/last inst_id、读/写计数）。
- `was_accessed(addr)` → 单地址快速判断。

**缓存**：三級——
1. `page_cache_`：512 页的 LRU，缓存页内完整写历史（`vector<MemWrite>`）。
2. `byte_cache_`：65536 项的 `(addr,inst_id)→byte` 热查询缓存。
3. RocksDB block cache（256MB）。

**线程安全**：thread_local iterator 池（每线程缓一对 write/read iterator，按 owner_db 校验避免 use-after-free）。`cache_mutex_`/`byte_cache_mutex_` 保护缓存。统计用 atomic。

**懒加载**：不预加载任何内存数据。`build()` 单遍扫 trace 写入 mem_write CF（带 sentinel 防重复构建）。内存占用与活跃分析地址范围成正比，而非 trace 总量。

## InstructionDecoder — Capstone + 缓存

**设计**：Capstone handle 非线程安全，用 mutex 保护。`DecodedInst` 用**定长数组**（mnemonic[12]/op_str[64]/regs_read[8]/regs_written[8]）消除热路径堆分配。

**接口**：
- `decode(pc, opcode)` → `optional<DecodedInst>`。
- `decode(pc, code_table)` → 便捷包装。
- `format(pc, opcode)` → "addr: mnemonic operands" 字符串。

**LRU**：16384 条，按 PC 缓存。同一 PC 的指令语义确定（除 SMC，本系统暂不支持版本链）。

**注意**：许多 Pass 用 `common/aarch64_classify.h` 的纯位运算分类，绕过 Capstone 提速。

## TritonBridge — 语义预言机（可选）

**设计**：抽象接口 `TritonBridge`，默认 `TritonBridgeStub`（全返回 not available）。`create_triton_bridge()` 工厂在链接了 libTriton 时返回真实实现，否则返回 stub。`TritonBridgeTaint` 扩展接口提供污点 API（`taint_register`/`process_instruction`/`is_register_tainted`）。

**语义查询**：`query_semantics(pc, code, size)` → `InstructionSemantics{reg_accesses, mem_accesses, is_branch/is_call/is_return, expression}`。`set_register_context()`/`set_memory_context()` 设具体状态做上下文敏感分析。

**TritonPool**：池化 4 个 TritonBridge 实例供并发 Pass 使用。`borrow()` 返回 RAII `BorrowedBridge`，析构自动归还。池满阻塞。

**降级策略**：无 Triton 时，TaintPass/BackwardTaintPass 用启发式 fallback（基于 `aarch64_classify.h` 的指令分类 + 手写传播规则），精度略降但功能完整。

**编译开关**：`TENET_ENABLE_TRITON=ON/OFF`。OFF 时编译为纯 stub，无 libTriton 依赖。

## BreakpointEngine — 时空断点

**设计**：在静态 trace 上模拟断点/观察点，支持前向（continue）和后向（reverse-continue）。

**三种断点**：
| 类型 | 结构 | 复杂度 | 实现 |
|------|------|--------|------|
| PC 断点 | `PcBreakpoint{addr}` | O(1) | 从 XRef 的 `pc_to_inst_ids` bitmap 直接取所有命中 inst_id |
| 内存写观察点 | `WatchBreakpoint{addr, size}` | O(log N) | 从 RocksDB mem_write CF 取该地址所有写入 |
| 条件断点 | `ConditionalBreakpoint{predicate}` | O(N) | 顺序扫，每条调 predicate |

**接口**：
- `add_breakpoint(spec)` / `remove_breakpoint(id)` / `clear_breakpoints()`。
- `run_forward(from_id)` / `run_backward(from_id)` → `optional<BreakpointHit>`。
- 便捷：`next_execution(pc, from)` / `prev_execution(pc, from)` / `next_write(addr, size, from)` / `prev_write(...)`。

**TUI 命令**：`parse_breakpoint_cmd("b 0x1234")` → PcBreakpoint；`"w 0x1234 8"` → WatchBreakpoint。

## 组件交互

```
        ┌──────────────┐
        │ TritonPool    │  (语义/污点，可选)
        └──────┬───────┘
               │ borrow()
   ┌───────────┼───────────┐
   ▼           ▼           ▼
┌─────────┐ ┌───────────┐ ┌──────────────────┐
│RegFile  │ │MemoryModel│ │InstructionDecoder │
└────┬────┘ └─────┬─────┘ └────────┬─────────┘
     │            │                │
     └────────────┴────────────────┘
                  │ 都依赖
                  ▼
          ┌─────────────────┐
          │ IO (TraceReader │
          │  + TraceIndex)  │
          └─────────────────┘
```

Pass 使用典型模式：`regfile.state_before(id)` 取状态 → `code_table.opcode_at(pc)` 取指令 → `decoder.decode(pc, opcode)` 或 `triton.query_semantics(...)` 取语义 → `memory.read(addr, size, id)` 取内存值。

## 线程安全模型

| 组件 | 线程安全 | 说明 |
|------|----------|------|
| TraceReader | 完全 | 只读 mmap |
| TraceIndex | 完全 | RocksDB MVCC |
| RegisterFile | 单线程 | LRU 无锁，每 Pass 线程建议独立实例（轻量） |
| MemoryModel | 并发安全 | thread_local iterator + 缓存 mutex |
| InstructionDecoder | mutex 保护 | Capstone handle 非线程安全 |
| TritonBridge | 池化 | 每实例独占，池本身 mutex |
| BreakpointEngine | 单线程 | 读多写少，调用方串行 |

**推荐**：每 Pass 线程拥有独立 RegisterFile/Decoder（轻量），共享 TraceReader/TraceIndex（天然安全），TritonBridge 通过池化共享。

## 关键设计决策

1. **Anchor 周期是核心**：整个寄存器重建依赖 ANCHOR 间隔。间隔大→重建慢但 trace 小；间隔小→重建快但 trace 大。qbditrace 默认 ~4096。
2. **内存写按「写」粒度存**：而非逐字节。一次 8B STR 只产 1 个 KV，读时回扫找覆盖写。
3. **mem_read 回填**：巧妙利用 read 访问携带的值，恢复未插桩代码写入的数据。
4. **Triton 可选**：stub 模式保证无 libTriton 也能编译运行，启发式 fallback 保功能。
5. **BreakpointEngine 索引加速**：PC/内存断点不扫 trace，直接查索引，秒级定位。

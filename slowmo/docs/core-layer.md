# Core Layer 详细设计 (v2)

## 职责

Core 层在 IO 层提供的原始记录流之上，重建程序执行的**完整状态快照**，并桥接 Triton 语义引擎。核心组件：

1. **RegisterFile** — 任意 inst_id 的寄存器状态 O(1) 重建
2. **MemoryModel** — 带时间维度的内存状态
3. **TritonBridge** — Triton 语义预言机的管理和复用
4. **InstructionDecoder** — Capstone 反汇编 + 缓存

## RegisterFile

### 算法：Anchor + Diff + LRU

```
Timeline:  ──A₀──────────────────A₁──────────────────A₂──────
           │  d₁ d₂ d₃ ... d₄₀₉₅ │  d₁ d₂ ...       │
           
要重建 inst_id = A₀ + 2000:
  1. 从 RocksDB 找到 nearest_anchor_before(A₀+2000) = A₀
  2. 加载 A₀ 的完整快照 → RegState
  3. 从 A₀ 向前扫描 2000 条 INST，逐条 apply diff
  4. 结果存入 LRU cache
```

### 接口

```cpp
// AArch64 寄存器数量：34 个（x0-x28, lr, sp, nzcv, pc）
// 与 TraceFormat.h QBDITRACE_AARCH64_NUM_GPR 保持一致
constexpr uint8_t AARCH64_GPR_COUNT = 34;
constexpr uint8_t AARCH64_GPR_SIZE = 8;
constexpr uint8_t IDX_LR = 30;
constexpr uint8_t IDX_SP = 31;
constexpr uint8_t IDX_NZCV = 32;
constexpr uint8_t IDX_PC = 33;

struct RegState {
    uint64_t gpr[AARCH64_GPR_COUNT];  // 272 bytes

    uint64_t pc() const { return gpr[IDX_PC]; }
    uint64_t sp() const { return gpr[IDX_SP]; }
    uint64_t lr() const { return gpr[IDX_LR]; }
    uint64_t fp() const { return gpr[29]; }  // x29 = fp
    uint32_t nzcv() const { return static_cast<uint32_t>(gpr[IDX_NZCV] & 0xF); }
};

class RegisterFile {
public:
    RegisterFile(TraceReader& reader, RocksDBIndex& index);

    // 核心：获取 inst_id 执行前/后的寄存器状态
    const RegState& state_before(uint64_t inst_id);
    const RegState& state_after(uint64_t inst_id);

    // 查询：哪条指令最后写了某寄存器（在 inst_id 之前）
    uint64_t last_writer(uint64_t inst_id, uint8_t reg_index);

    // 查询：哪条指令下一次读了某寄存器（在 inst_id 之后）
    uint64_t next_reader(uint64_t inst_id, uint8_t reg_index);

    // 批量重建（给 Pass 用，一次重建一个范围）
    void prefetch_range(uint64_t start_id, uint64_t end_id);

    // LRU 配置
    void set_cache_capacity(size_t num_entries);
    struct CacheStats { size_t hits, misses, evictions; };
    CacheStats cache_stats() const;

private:
    // Anchor 缓存：所有 anchor 的 inst_id + offset
    // 从 RocksDB "anchor" CF 加载，排好序，支持二分查找
    std::vector<std::pair<uint64_t, uint64_t>> anchors_;

    // LRU 缓存：inst_id → RegState
    // 容量默认 4096 条，覆盖 ~16 个 anchor 区间
    LRUCache<uint64_t, RegState> cache_;

    // 重建引擎
    RegState rebuild(uint64_t target_id);
};
```

### 性能分析

| 场景 | 延迟 | 说明 |
|------|------|------|
| LRU cache hit | < 1μs | 直接返回 |
| 同 anchor 区间内顺序访问 | < 10μs | 前次结果 + 1 diff |
| 跨 anchor 随机跳转 | ~500μs | 加载 anchor + apply ≤4096 diffs |
| prefetch_range 批量 | ~2ms/万条 | 一次遍历，无重复 anchor 加载 |

内存占用：LRU 4096 条 × 280B = **~1.1MB**。极轻量。

### 双向遍历优化

逆向单步（step backward）场景：如果 LRU 中有前一条的状态，直接 "undo" diff：

```cpp
RegState undo_diff(const RegState& after, const InstView& inst) {
    RegState before = after;
    // inst 的 reg_diffs 记录的是"执行后的新值"
    // 但我们需要"执行前的旧值"——这需要额外信息
    // 方案：在 LRU 中存 (state_before, state_after) 对
    // 或者：存 (state_before) + diff 即可双向推导
}
```

实际方案：LRU 存的是 **state_before**。
- `state_after(id)` = `state_before(id)` + apply diff of inst[id]
- `state_before(id)` = `state_after(id-1)` = `state_before(id-1)` + apply diff of inst[id-1]
- 逆向：`state_before(id-1)` = cache hit（如果连续逆向单步）

---

## MemoryModel

### 设计：时间索引内存

MemoryModel 管理 trace 中所有的内存写操作，支持按 (address, time) 二维查询。

核心思想：**每次内存写 = (addr, size, data, inst_id)**，按 page 分桶、桶内按 inst_id 排序，二分查找定位特定时刻的内存状态。

### 接口

```cpp
struct MemWrite {
    uint64_t addr;
    uint8_t size;         // 1-16
    uint64_t inst_id;     // 写入时刻
    uint8_t data[16];     // 写入的数据（内联小对象）
};

class MemoryModel {
public:
    MemoryModel(TraceReader& reader, RocksDBIndex& index);

    // 核心查询：在 inst_id 时刻，addr 处的 size 字节内容
    struct ReadResult {
        std::array<uint8_t, 16> data;
        std::array<bool, 16> known;    // 哪些字节有已知值
        std::array<uint64_t, 16> writer_id;  // 每字节的最后写入者
    };
    ReadResult read(uint64_t addr, uint8_t size, uint64_t at_inst_id);

    // 谁最后写了这个地址（在 inst_id 之前）
    uint64_t last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id);

    // 谁下一次读了这个地址（在 inst_id 之后）
    uint64_t next_reader(uint64_t addr, uint8_t size, uint64_t after_inst_id);

    // 写入历史：该地址的所有写入时间点
    std::vector<uint64_t> write_history(uint64_t addr, uint8_t size);

    // 内存快照导出（给字符串扫描等用）
    // 返回在 at_inst_id 时刻的完整已知内存区域
    void snapshot_region(uint64_t base, uint64_t size, uint64_t at_inst_id,
                        uint8_t* out_data, bool* out_known);

private:
    // 存储策略：分两级
    // 1. RocksDB mem_write CF 提供 page 级索引（"哪些 inst_id 写了这个 page"）
    // 2. 具体 MemWrite 数据在 trace 文件中（通过 inst_id → offset 定位）
    //
    // 热路径优化：LRU 缓存最近访问的页的完整写入历史
    RocksDBIndex& index_;
    TraceReader& reader_;

    struct PageWriteHistory {
        std::vector<MemWrite> writes;  // 按 inst_id 排序
    };
    LRUCache<uint64_t/*page_addr*/, PageWriteHistory> page_cache_;
};
```

### 查询流程

```
read(0x7fec60ebd9, 4, inst_id=162718):
  1. page_addr = 0x7fec60ebd9 >> 12 = 0x7fec60eb
  2. 如果 page_cache_ 有该页 → 直接用
     否则：
       a. 从 RocksDB "mem_write" CF 获取该页的写入者 bitmap
       b. 筛选 inst_id <= 162718 的写入者
       c. 对每个写入者，从 trace 中读取其 MemAccess 记录
       d. 构建 PageWriteHistory 存入 cache
  3. 在 PageWriteHistory.writes 中二分查找：
     对目标 [addr, addr+4) 的每个字节，找 inst_id <= 162718 的最后一条写入
  4. 拼装 ReadResult
```

### 内存预算

- page_cache_ 容量：1024 页 × avg 1000 writes/page × 32B/write ≈ **32MB**
- 加上 RocksDB block cache 分摊 → **总共 ~50MB**
- 远低于 v1 设计的 1GB（v1 试图把全部 MemWrite 加载到内存）

### 懒加载策略

不预加载任何内存数据。所有 page 数据首次访问时从 RocksDB 索引 + trace 文件按需构建。这保证了：
- 启动时间不受内存访问数量影响
- 内存占用与**活跃分析的地址范围**成正比，而非与 trace 总量成正比

---

## TritonBridge — 语义预言机

### 职责

封装 Triton API，提供面向 trace replay 优化的接口。

### 设计要点

1. **Triton Context 池化**：Triton 的 `triton::API` 对象创建/销毁有开销。维护一个小池（4-8 个实例），支持 Pass 并行使用。
2. **Stateless Replay 模式**：每次 replay 一条指令前，从 RegisterFile/MemoryModel 设置 concrete state，不依赖 Triton 自身的状态连续性。这使得可以**跳跃式 replay**（只处理相关指令，跳过无关指令）。
3. **结果缓存**：对同一条指令的语义信息（read/write set）做 LRU 缓存——同一 PC 的指令语义是确定的（除 SMC 外）。

```cpp
class TritonBridge {
public:
    TritonBridge(size_t pool_size = 4);

    // 获取一个 Triton Context（RAII 句柄，用完自动归还）
    class ContextHandle {
    public:
        triton::API& api();
        ~ContextHandle();  // 归还到池
    };
    ContextHandle acquire();

    // 高层封装：获取指令的精确语义
    struct InstructionSemantics {
        std::vector<uint8_t> regs_read;    // 读取的寄存器索引
        std::vector<uint8_t> regs_written; // 写入的寄存器索引
        struct MemRef {
            uint64_t addr;
            uint8_t size;
        };
        std::vector<MemRef> mem_reads;
        std::vector<MemRef> mem_writes;
        bool is_branch;
        bool is_call;
        bool is_return;
    };

    // 缓存：PC → InstructionSemantics（对非 SMC 指令）
    const InstructionSemantics& semantics(uint64_t pc, uint32_t opcode);

    // Replay 一条指令（完整 Triton processing，含污点/符号状态更新）
    // 调用者需先设好 concrete state
    void replay(ContextHandle& ctx, uint64_t pc, uint32_t opcode,
                const RegState& state, const MemoryModel& mem);

    // 污点查询（在 replay 之后）
    bool is_reg_tainted(ContextHandle& ctx, uint8_t reg_index);
    bool is_mem_tainted(ContextHandle& ctx, uint64_t addr, uint8_t size);

    // 设置污点源
    void taint_reg(ContextHandle& ctx, uint8_t reg_index);
    void taint_mem(ContextHandle& ctx, uint64_t addr, uint8_t size);

private:
    std::vector<std::unique_ptr<triton::API>> pool_;
    std::mutex pool_mutex_;
    std::condition_variable pool_cv_;

    // 语义缓存：opcode → InstructionSemantics
    // AArch64 定长 4B，opcode 本身就是完美的 key
    LRUCache<uint32_t, InstructionSemantics> semantics_cache_;
};
```

### Triton 初始化配置

```cpp
void init_triton_context(triton::API& api) {
    api.setArchitecture(triton::arch::ARCH_AARCH64);
    api.setMode(triton::modes::ALIGNED_MEMORY, true);  // 假设对齐访问
    api.setMode(triton::modes::TAINT_THROUGH_POINTERS, true);  // 指针解引用传播
    // 不启用符号执行（按需开启以节省 CPU）
    api.setMode(triton::modes::SYMBOLIZE_LOAD, false);
    api.setMode(triton::modes::SYMBOLIZE_STORE, false);
}
```

### 性能特征

| 操作 | 延迟 | 说明 |
|------|------|------|
| semantics() cache hit | < 100ns | flat_hash_map 查找 |
| semantics() cache miss | ~3μs | Triton decode + 语义提取 |
| replay() 含污点 | ~5μs | 全量 Triton processing |
| acquire() 池满等待 | 阻塞 | 极少发生（池大小 = 线程数） |

对 TaintPass 传播 10K 步：10000 × 5μs = **50ms**，满足交互需求。

---

## InstructionDecoder

Capstone 反汇编封装，带缓存。

```cpp
class InstructionDecoder {
public:
    InstructionDecoder(const CodeTable& code_table);

    struct DecodedInst {
        uint64_t pc;
        uint32_t opcode;
        std::string mnemonic;     // e.g. "ldrb"
        std::string op_str;       // e.g. "w2, [x24, x0]"
        uint8_t size;             // AArch64 always 4
        // Capstone detail（仅当需要时才填充）
        cs_detail* detail;
    };

    const DecodedInst& decode(uint64_t pc);
    std::string format(uint64_t pc);  // 完整格式化字符串

    // 批量反汇编一个范围
    std::vector<DecodedInst> decode_range(uint64_t start_pc, uint64_t end_pc);

private:
    const CodeTable& code_table_;
    csh cs_handle_;
    LRUCache<uint64_t, DecodedInst> cache_;  // 容量 16K 条
};
```

---

## 组件交互关系

```
                    ┌──────────────┐
                    │  TritonBridge │
                    └──────┬───────┘
                           │ 需要 concrete state
                    ┌──────┴───────┐
              ┌─────┤              ├─────┐
              ▼     ▼              ▼     ▼
     ┌────────────┐  ┌────────────────┐  ┌────────────────┐
     │RegisterFile│  │  MemoryModel   │  │InstructionDecoder│
     └─────┬──────┘  └───────┬────────┘  └───────┬────────┘
           │                  │                    │
           └──────────┬───────┴────────────────────┘
                      ▼
              ┌──────────────┐
              │  IO Layer    │
              │ (TraceReader │
              │  + RocksDB)  │
              └──────────────┘
```

Pass 使用 Core 的典型模式：

```cpp
// TaintPass 内部
void TaintPass::run(PassContext& ctx) {
    auto triton_ctx = ctx.triton_bridge().acquire();

    // 设置初始污点
    ctx.triton_bridge().taint_reg(triton_ctx, source_reg);

    // 从 source_inst_id 开始正向遍历
    for (uint64_t id = source_inst_id; id < end_id; ++id) {
        // 1. 获取寄存器/内存状态
        const auto& regs = ctx.regfile().state_before(id);

        // 2. Triton replay
        auto pc = regs.pc();
        auto opcode = ctx.code_table().opcode_at(pc);
        ctx.triton_bridge().replay(triton_ctx, pc, *opcode, regs, ctx.memory());

        // 3. 检查污点传播结果
        // ... 收集被污染的寄存器/内存
    }
}
```

---

## 线程安全模型

| 组件 | 线程安全 | 说明 |
|------|----------|------|
| TraceReader | 完全安全 | 只读 mmap，无可变状态 |
| RocksDBIndex | 完全安全 | RocksDB 内置 MVCC |
| RegisterFile | 需同步 | LRU cache 需 mutex 或 per-thread |
| MemoryModel | 需同步 | page_cache_ 需 mutex |
| TritonBridge | 池化安全 | 每个 Context 独占，池本身用 mutex |
| InstructionDecoder | 需同步 | Capstone handle 非线程安全 |

**推荐**：每个 Pass 在自己的线程中拥有独立的 RegisterFile/MemoryModel/Decoder 实例（它们很轻量），共享 TraceReader 和 RocksDBIndex（天然线程安全）。TritonBridge 通过池化实现共享。

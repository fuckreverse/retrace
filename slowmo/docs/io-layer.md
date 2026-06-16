# IO Layer 详细设计 (v2)

## 职责

IO 层负责 trace 文件的**零拷贝访问**和**高性能索引**。核心组件：

1. **TraceReader** — mmap 映射 + 记录解析
2. **RocksDBIndex** — 多维倒排索引（持久化）
3. **CodeTable** — 可执行代码缓存
4. **SymbolTable** — 符号/名称加载

## TraceReader

### 设计原则

- 整个 trace 文件通过 `mmap` 映射到虚拟地址空间，由 OS 管理页面换入换出
- 记录解析为零拷贝：返回指向 mmap 区域的指针视图，不复制数据
- 线程安全：只读映射 + 无可变状态，多线程可并发读取

### 接口

```cpp
class TraceReader {
public:
    // 生命周期
    static std::expected<TraceReader, Error> open(const std::filesystem::path& path);
    void close();

    // 文件元信息
    const FileHeader& header() const;
    uint64_t file_size() const;
    uint64_t record_count() const;  // 所有类型记录总数
    uint64_t inst_count() const;    // INST 类型记录数

    // 顺序遍历（最高效）
    class Iterator {
    public:
        RecordView operator*() const;  // 零拷贝视图
        Iterator& operator++();
        bool operator==(Sentinel) const;
    };
    Iterator begin() const;
    Sentinel end() const;

    // 随机访问（需索引配合）
    RecordView record_at_offset(uint64_t file_offset) const;

    // 原始字节访问（给 RocksDB 索引构建用）
    std::span<const uint8_t> raw_bytes() const;
    std::span<const uint8_t> raw_bytes(uint64_t offset, uint64_t length) const;

private:
    int fd_ = -1;
    void* mapped_ = nullptr;
    uint64_t size_ = 0;
    FileHeader header_;
};
```

### RecordView — 零拷贝记录视图

```cpp
// 不拥有数据，指向 mmap 区域
struct RecordView {
    RecordKind kind;
    uint64_t file_offset;       // 在文件中的偏移
    std::span<const uint8_t> raw;  // 原始字节（含 kind 字节）

    // 类型安全访问（按需解析）
    std::optional<InstView> as_inst() const;
    std::optional<AnchorView> as_anchor() const;
    std::optional<EventView> as_event() const;
    // ... 其他类型
};

struct InstView {
    uint64_t pc;
    uint8_t reg_diff_count;
    struct RegDiff { uint8_t index; uint64_t value; };
    std::span<const RegDiff> reg_diffs() const;  // 零拷贝
    uint8_t mem_access_count;
    // mem_access 因变长需逐个解析
    MemAccessIterator mem_accesses() const;
};

struct AnchorView {
    uint32_t inst_id;
    std::span<const uint64_t> gpr_values() const;  // 直接指向 mmap
};
```

### 性能特征

| 操作 | 复杂度 | 说明 |
|------|--------|------|
| open() | O(1) | mmap 是懒加载，只映射地址空间 |
| 顺序遍历 | ~300 MB/s | 受限于 page fault + 解析，预读友好 |
| record_at_offset() | O(1) | 指针算术 |
| 并发读 | 无锁 | 只读映射天然线程安全 |

### mmap 策略

```cpp
// Linux/macOS 优化提示
mmap(nullptr, size, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
madvise(mapped, size, MADV_SEQUENTIAL);  // 索引构建时
madvise(mapped, size, MADV_RANDOM);      // 随机访问模式
```

对于超大 trace（>4GB），使用 `MAP_NORESERVE` 避免 commit charge。
在索引构建阶段用 `MADV_SEQUENTIAL`（预读优化），构建完成后切换为 `MADV_RANDOM`。

---

## RocksDBIndex — 多维倒排索引

### 为什么用 RocksDB

| 需求 | RocksDB 优势 |
|------|-------------|
| 100M+ 条目的倒排索引 | LSM-tree 设计就是为此优化 |
| 持久化（不必每次重建） | 原生磁盘存储 |
| 范围查询（"PC=X 的所有 inst_id"） | 有序 KV + prefix iterator |
| 多种索引共存 | Column Family 隔离 |
| 并发读 | 内置 MVCC |
| 压缩 | 内置 LZ4/Zstd 块压缩 |

### Column Family 设计

```
DB path: <trace_dir>/.tenet_cache/<trace_hash>/

Column Families:
┌──────────────────────────────────────────────────────────────┐
│ CF: "meta"                                                   │
│   Key: "version"        → Value: "2"                         │
│   Key: "trace_hash"     → Value: sha256(header + first 4KB) │
│   Key: "inst_count"     → Value: uint64                      │
│   Key: "build_time"     → Value: uint64 (ns)                │
├──────────────────────────────────────────────────────────────┤
│ CF: "offset"   (inst_id → file_offset 主索引)                │
│   Key: inst_id (uint64 BE)                                   │
│   Value: file_offset (uint64)                                │
│   ※ 稀疏：每 256 条 INST 存一个条目                           │
├──────────────────────────────────────────────────────────────┤
│ CF: "anchor"   (anchor inst_id → file_offset)                │
│   Key: anchor_inst_id (uint64 BE)                            │
│   Value: file_offset (uint64)                                │
├──────────────────────────────────────────────────────────────┤
│ CF: "pc"       (PC → inst_id 列表，Roaring Bitmap 编码)      │
│   Key: pc (uint64 BE)                                        │
│   Value: Roaring Bitmap of inst_ids (序列化)                  │
├──────────────────────────────────────────────────────────────┤
│ CF: "mem_write" (page_addr → 写入该页的 inst_id 列表)         │
│   Key: page_addr = addr >> 12 (uint64 BE)                    │
│   Value: Roaring Bitmap of inst_ids                          │
├──────────────────────────────────────────────────────────────┤
│ CF: "mem_read"  (page_addr → 读取该页的 inst_id 列表)         │
│   Key: page_addr = addr >> 12 (uint64 BE)                    │
│   Value: Roaring Bitmap of inst_ids                          │
├──────────────────────────────────────────────────────────────┤
│ CF: "func"     (函数入口 PC → 相关信息)                       │
│   Key: entry_pc (uint64 BE)                                  │
│   Value: {call_count, first_call_inst_id, last_ret_inst_id}  │
└──────────────────────────────────────────────────────────────┘
```

### 关键设计决策

**稀疏 offset 索引**：不存每条 inst_id 的偏移（100M 条 = 1.6GB），而是每 256 条存一个锚点。定位 inst_id=N 时：找到 floor(N/256)*256 的 offset，然后从该 offset 向前扫描最多 256 条记录。256 条 × ~50B/条 ≈ 12KB 顺序读，在 SSD 上 < 100μs。

**Roaring Bitmap 做值列表**：对于 "PC=0x750bd554 出现在哪些 inst_id" 这类查询，结果可能是上万个 inst_id。用 Roaring Bitmap 存储比排序数组紧凑 2-5x，且支持高效的集合运算（交集、并集），直接服务于 TaintPass 的 taint set 计算。

**Page 粒度内存索引**：按 4KB 页粒度（addr >> 12）建索引。查找 "谁写了 0x7fec60ebd9" 时，先查 page = 0x7fec60eb 的写入者 bitmap，再在对应指令中精确匹配字节地址。这在精度和索引大小之间取平衡。

### 索引构建流程

```cpp
class IndexBuilder {
public:
    // 顺序扫描一遍 trace 构建所有索引
    void build(const TraceReader& reader, rocksdb::DB* db,
               ProgressCallback progress);

    struct Stats {
        uint64_t inst_count;
        uint64_t anchor_count;
        uint64_t unique_pcs;
        uint64_t unique_mem_pages;
        double elapsed_seconds;
    };
};
```

构建策略：

1. 顺序遍历 trace（利用 MADV_SEQUENTIAL 预读）
2. 使用 RocksDB `WriteBatch`，每 10000 条记录 flush 一批
3. Roaring Bitmap 在内存中增量构建，遍历结束后一次序列化写入
4. 内存峰值：unique_pcs × bitmap_overhead ≈ 10K PCs × 1MB = ~10GB → **分段构建**：
   - 第一遍：构建 offset + anchor 索引（O(1) 内存）
   - 第二遍：构建 pc 索引（按 PC 前缀分段）
   - 第三遍：构建 mem 索引（按 page 前缀分段）
   - 或者：如果内存充足（>4GB），单遍构建

### 查询接口

```cpp
class RocksDBIndex {
public:
    static std::expected<RocksDBIndex, Error> open_or_build(
        const std::filesystem::path& trace_path,
        const TraceReader& reader);

    // 主索引：inst_id → file_offset
    uint64_t offset_of(uint64_t inst_id) const;

    // Anchor 查找：找到 inst_id 之前最近的 anchor
    std::pair<uint64_t/*anchor_inst_id*/, uint64_t/*offset*/> 
        nearest_anchor_before(uint64_t inst_id) const;

    // PC 索引：哪些 inst_id 执行了该 PC
    roaring::Roaring64Map insts_at_pc(uint64_t pc) const;

    // 内存索引：哪些 inst_id 写入/读取了该地址
    roaring::Roaring64Map mem_writers(uint64_t addr) const;
    roaring::Roaring64Map mem_readers(uint64_t addr) const;

    // 范围查询
    roaring::Roaring64Map mem_writers_in_range(uint64_t addr, uint64_t size) const;

    // 函数相关
    std::vector<uint64_t> all_function_entries() const;
    FuncInfo func_info(uint64_t entry_pc) const;

    // 统计
    IndexStats stats() const;

    // 缓存验证（trace 文件改变时 invalidate）
    bool is_valid_for(const TraceReader& reader) const;
};
```

### RocksDB 调优

```cpp
rocksdb::Options opts;
opts.create_if_missing = true;
opts.compression = rocksdb::kZSTD;  // Zstd 压缩
opts.bottommost_compression = rocksdb::kZSTD;
opts.optimize_filters_for_hits = true;
opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory({
    .block_cache = rocksdb::NewLRUCache(256 * 1024 * 1024),  // 256MB
    .filter_policy = rocksdb::NewBloomFilterPolicy(10),       // Bloom filter
    .block_size = 16 * 1024,  // 16KB blocks
}));
// 写入优化（构建阶段）
opts.write_buffer_size = 64 * 1024 * 1024;
opts.max_write_buffer_number = 3;
opts.target_file_size_base = 256 * 1024 * 1024;
```

---

## CodeTable

存储 trace 中出现的可执行代码字节，供 Capstone 反汇编使用。

```cpp
class CodeTable {
public:
    void ingest(const CodeRecord& rec);  // 从 CODE 记录导入

    // 查询：获取 PC 处的机器码（AArch64 固定 4 字节）
    std::optional<uint32_t> opcode_at(uint64_t pc) const;

    // 批量查询（给 Capstone 做批量反汇编）
    std::span<const uint8_t> code_region(uint64_t base, uint64_t size) const;

    // SMC 支持：同一 PC 在不同时刻可能有不同代码
    std::optional<uint32_t> opcode_at(uint64_t pc, uint64_t inst_id) const;

    // 统计
    size_t region_count() const;
    size_t total_bytes() const;

private:
    // 主存储：base_addr → code_bytes
    // 对 AArch64 定长指令，可优化为 flat_hash_map<pc, uint32_t>
    absl::flat_hash_map<uint64_t, uint32_t> opcode_cache_;

    // SMC 版本链：pc → [(inst_id_range, opcode)]
    // 大多数 PC 无 SMC，只有少数需要版本链
    absl::flat_hash_map<uint64_t, std::vector<VersionedOpcode>> smc_table_;
};
```

---

## SymbolTable

加载外部符号信息，提供地址 → 名称的映射。

```cpp
class SymbolTable {
public:
    // 多来源加载
    void load_from_ida_names(const std::filesystem::path& path);   // IDA .names
    void load_from_nm(const std::filesystem::path& path);          // nm 输出
    void load_from_class_dump(const std::filesystem::path& path);  // ObjC headers
    void load_from_json(const std::filesystem::path& path);        // 通用 JSON

    // 查询
    std::optional<std::string_view> name_at(uint64_t addr) const;
    std::optional<std::string_view> name_containing(uint64_t addr) const; // 函数内
    std::vector<uint64_t> search(std::string_view pattern) const;  // 模糊搜索

    // 反向：名称 → 地址
    std::optional<uint64_t> addr_of(std::string_view name) const;

private:
    // 按地址排序，支持 lower_bound 范围查找
    std::vector<std::pair<uint64_t, std::string>> symbols_;  // sorted
};
```

---

## 性能预算

以 100M 指令 / 1.5GB trace 为基准：

| 组件 | 内存占用 | 磁盘占用 |
|------|----------|----------|
| mmap 映射 | 虚拟 1.5GB，RSS 由 OS 管理 | — |
| RocksDB block cache | 256MB (可配) | — |
| RocksDB 数据文件 | — | ~200-500MB（视压缩率） |
| offset CF (稀疏) | — | ~6MB (100M/256 × 16B) |
| pc CF (Roaring) | — | ~50-100MB |
| mem CF (Roaring) | — | ~100-300MB |
| CodeTable | ~40MB (10K unique PCs × 4B + overhead) | — |
| SymbolTable | ~5MB (典型) | — |
| **IO 层合计** | **~300MB RSS** | **~500MB 缓存** |

索引构建后持久化到磁盘，后续打开同一 trace 直接加载（< 50ms）。

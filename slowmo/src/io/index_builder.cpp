#include "io/index_builder.h"
#include "io/code_table.h"
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>
#include <rocksdb/slice_transform.h>

#include <chrono>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <thread>
#include <vector>
#include <mutex>
#include <sstream>

namespace tenet {

// Schema version for the RocksDB index cache.
// Bump this whenever TraceFormat struct sizes change, column families are
// added/removed, or the encoding of keys/values in the DB changes.
// This ensures stale caches from older builds are invalidated automatically.
//
// v5: code_bytes CF + adaptive sparse interval + parallel build
// v6: OFFSET CF now uses correct memacc size for v6 traces (HF_OLD_VALUE).
//     Caches built before the fix used sizeof(qbditrace_memacc_t)=32 for all
//     traces; v6 traces need sizeof(qbditrace_memacc_v6_t)=48. Any cache
//     built with schema v5 that covers a v6 trace has wrong OFFSET entries.
//     Bumping to v6 invalidates all such caches globally, forcing a rebuild.
// v7: Added trace_hash (xxHash64 of trace content) for integrity detection.
//     Index directory renamed from .tenet_cache_<name> to <name>.tenet
static constexpr uint32_t INDEX_SCHEMA_VERSION = 7;

// ─── Helpers ──────────────────────────────────────────────────────────────

namespace {

// Encode uint64 as big-endian key (for correct RocksDB sort order).
// Returns a Slice pointing to the caller-provided 8-byte buffer.
// *** Zero heap allocation — critical for millions of calls during index build. ***
inline rocksdb::Slice encode_u64_to(uint64_t v, char buf[8]) {
    // Use __builtin_bswap64 (single REV instruction on ARM64)
#if defined(__GNUC__) || defined(__clang__)
    uint64_t be = __builtin_bswap64(v);
#else
    uint64_t be = 0;
    for (int i = 7; i >= 0; --i) {
        be = (be << 8) | ((v >> (i * 8)) & 0xFF);
    }
#endif
    std::memcpy(buf, &be, 8);
    return rocksdb::Slice(buf, 8);
}

// Legacy: heap-allocating version (kept for query paths where lifetime matters)
std::string encode_u64(uint64_t v) {
    char buf[8];
    encode_u64_to(v, buf);
    return std::string(buf, 8);
}

uint64_t decode_u64(const rocksdb::Slice& s) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint8_t>(s.data()[i]);
    }
    return v;
}

std::filesystem::path index_path_for(const TraceReader& reader) {
    auto trace_dir = reader.path().parent_path();
    auto trace_name = reader.path().stem().string();
    // P2: use <name>.tenet/ as the index directory name.
    // This matches macOS package conventions (Finder shows it as a single unit)
    // and makes it obvious which trace the cache belongs to.
    return trace_dir / (trace_name + ".tenet");
}

// ─── xxHash-64 (single-pass, zero dependency) ─────────────────────────────
// Compact implementation for hashing the trace file content.
// Reference: https://github.com/Cyan4973/xxHash (BSD 2-Clause)

static constexpr uint64_t XXH_PRIME64_1 = 0x9E3779B185EBCA87ULL;
static constexpr uint64_t XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
static constexpr uint64_t XXH_PRIME64_3 = 0x165667B19E3779F9ULL;
static constexpr uint64_t XXH_PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
static constexpr uint64_t XXH_PRIME64_5 = 0x27D4EB2F165667C5ULL;

static uint64_t xxrotl64(uint64_t v, int r) {
    return (v << r) | (v >> (64 - r));
}

/// Compute xxHash-64 of a memory region.
static uint64_t xxhash64(const uint8_t* data, size_t len, uint64_t seed = 0) {
    const uint8_t* p   = data;
    const uint8_t* end = data + len;
    uint64_t h64;

    if (len >= 32) {
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - XXH_PRIME64_1;
        const uint8_t* limit = end - 32;
        do {
            uint64_t k;
            std::memcpy(&k, p +  0, 8); v1 = xxrotl64(v1 + k * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            std::memcpy(&k, p +  8, 8); v2 = xxrotl64(v2 + k * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            std::memcpy(&k, p + 16, 8); v3 = xxrotl64(v3 + k * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            std::memcpy(&k, p + 24, 8); v4 = xxrotl64(v4 + k * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            p += 32;
        } while (p <= limit);
        h64 = xxrotl64(v1, 1) + xxrotl64(v2, 7) + xxrotl64(v3, 12) + xxrotl64(v4, 18);
        auto merge = [&](uint64_t v) {
            v = xxrotl64(v * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            h64 = (h64 ^ v) * XXH_PRIME64_1 + XXH_PRIME64_4;
        };
        merge(v1); merge(v2); merge(v3); merge(v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }
    h64 += static_cast<uint64_t>(len);
    while (p + 8 <= end) {
        uint64_t k; std::memcpy(&k, p, 8);
        k *= XXH_PRIME64_2; k = xxrotl64(k, 31); k *= XXH_PRIME64_1;
        h64 = xxrotl64(h64 ^ k, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
    }
    if (p + 4 <= end) {
        uint32_t k; std::memcpy(&k, p, 4);
        h64 ^= static_cast<uint64_t>(k) * XXH_PRIME64_1;
        h64 = xxrotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
    }
    while (p < end) {
        h64 ^= static_cast<uint64_t>(*p) * XXH_PRIME64_5;
        h64 = xxrotl64(h64, 11) * XXH_PRIME64_1;
        p++;
    }
    h64 ^= h64 >> 33; h64 *= XXH_PRIME64_2;
    h64 ^= h64 >> 29; h64 *= XXH_PRIME64_3;
    h64 ^= h64 >> 32;
    return h64;
}

/// Hash only a representative sample of the trace file (first 1MB + last 1MB).
/// For large traces this is much faster than full hash while still detecting
/// truncation, corruption at head/tail, and file swaps.
static uint64_t sample_trace_hash(const TraceReader& reader) {
    constexpr size_t SAMPLE = 1024 * 1024;  // 1MB per end
    const uint8_t* data = reader.data();
    const uint64_t size = reader.file_size();
    if (size <= SAMPLE * 2) {
        return xxhash64(data, static_cast<size_t>(size));
    }
    // Hash first SAMPLE bytes (includes file header + first instructions)
    uint64_t h1 = xxhash64(data, SAMPLE);
    // Hash last SAMPLE bytes (tail of the trace)
    uint64_t h2 = xxhash64(data + size - SAMPLE, SAMPLE);
    // Combine with file size as salt to detect truncation
    uint64_t combined = h1 ^ (h2 * XXH_PRIME64_2) ^ (size * XXH_PRIME64_3);
    return combined;
}

}  // anonymous namespace

// ─── TraceIndex lifecycle ─────────────────────────────────────────────────

TraceIndex::~TraceIndex() {
close();
}

void TraceIndex::close() {
for (auto* h : cf_handles_) {
if (h && db_) db_->DestroyColumnFamilyHandle(h);
}
cf_handles_.clear();
db_.reset();
}

TraceIndex::TraceIndex(TraceIndex&& other) noexcept
    : db_(std::move(other.db_)),
      cf_handles_(std::move(other.cf_handles_)),
      stats_(other.stats_),
      db_path_(std::move(other.db_path_)),
      anchors_(std::move(other.anchors_)),
      sparse_interval_(other.sparse_interval_) {
    other.cf_handles_.clear();
}

TraceIndex& TraceIndex::operator=(TraceIndex&& other) noexcept {
    if (this != &other) {
        for (auto* h : cf_handles_) {
            if (h && db_) db_->DestroyColumnFamilyHandle(h);
        }
        db_ = std::move(other.db_);
        cf_handles_ = std::move(other.cf_handles_);
        stats_ = other.stats_;
        db_path_ = std::move(other.db_path_);
        anchors_ = std::move(other.anchors_);
        sparse_interval_ = other.sparse_interval_;
        other.cf_handles_.clear();
    }
    return *this;
}

rocksdb::ColumnFamilyHandle* TraceIndex::get_cf(const char* name) const {
    // Order: default(0), meta(1), offset(2), anchor(3), mem_write(4), mem_read(5), reg_writes(6), code_bytes(7)
    if (std::strcmp(name, "default") == 0)      return cf_handles_[0];
    if (std::strcmp(name, cf::META) == 0)       return cf_handles_[1];
    if (std::strcmp(name, cf::OFFSET) == 0)     return cf_handles_[2];
    if (std::strcmp(name, cf::ANCHOR) == 0)     return cf_handles_[3];
    if (std::strcmp(name, cf::MEM_WRITE) == 0   && cf_handles_.size() > 4) return cf_handles_[4];
    if (std::strcmp(name, cf::MEM_READ) == 0    && cf_handles_.size() > 5) return cf_handles_[5];
    if (std::strcmp(name, cf::REG_WRITES) == 0  && cf_handles_.size() > 6) return cf_handles_[6];
    if (std::strcmp(name, cf::CODE_BYTES) == 0  && cf_handles_.size() > 7) return cf_handles_[7];
    return nullptr;
}

bool TraceIndex::is_valid_for(const TraceReader& reader) const {
    // Check schema version: if the index was built by a different version of
    // the code (different struct sizes, different CF layout), it's invalid.
    std::string schema_val;
    auto sv = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                       "schema_version", &schema_val);
    if (!sv.ok() || schema_val.size() < 4) return false;
    uint32_t stored_schema = 0;
    std::memcpy(&stored_schema, schema_val.data(), 4);
    if (stored_schema != INDEX_SCHEMA_VERSION) return false;

    // Check stored file size matches
    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                      "file_size", &value);
    if (!s.ok()) return false;
    uint64_t stored_size = 0;
    std::memcpy(&stored_size, value.data(), std::min(value.size(), size_t(8)));
    if (stored_size != reader.file_size()) return false;

    // Check trace hash (schema v7+): detects file swaps and content corruption.
    // Old caches (schema < v7) lack this key; they're already invalidated by the
    // schema version check above, so we don't need a fallback here.
    std::string hash_val;
    auto hs = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                       "trace_hash", &hash_val);
    if (!hs.ok() || hash_val.size() < 8) return false;
    uint64_t stored_hash = 0;
    std::memcpy(&stored_hash, hash_val.data(), 8);
    uint64_t current_hash = sample_trace_hash(reader);
    return stored_hash == current_hash;
}

// ─── Open or build ────────────────────────────────────────────────────────

Result<TraceIndex> TraceIndex::open_or_build(
    const TraceReader& reader, ProgressCallback progress) {

    auto db_path = index_path_for(reader);

    // Try to open existing DB
    if (std::filesystem::exists(db_path)) {
        TraceIndex idx;
        idx.db_path_ = db_path;

        rocksdb::Options opts;
        opts.create_if_missing = false;

        // MEM_WRITE/MEM_READ CF options must match build-time settings
        // (prefix extractor, block cache, bloom filter) for correct operation.
        auto make_mem_cf_opts = []() {
            rocksdb::ColumnFamilyOptions o;
            o.compression = rocksdb::kLZ4Compression;
            o.prefix_extractor = std::shared_ptr<const rocksdb::SliceTransform>(
                rocksdb::NewFixedPrefixTransform(8));  // page(8) only
            rocksdb::BlockBasedTableOptions tbl;
            tbl.block_size = 4 * 1024;
            tbl.block_cache = rocksdb::NewLRUCache(512 * 1024 * 1024);
            tbl.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
            tbl.whole_key_filtering = false;
            o.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tbl));
            return o;
        };

        std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
            {"default", rocksdb::ColumnFamilyOptions()},
            {cf::META, rocksdb::ColumnFamilyOptions()},
            {cf::OFFSET, rocksdb::ColumnFamilyOptions()},
            {cf::ANCHOR, rocksdb::ColumnFamilyOptions()},
            {cf::MEM_WRITE, make_mem_cf_opts()},
            {cf::MEM_READ,  make_mem_cf_opts()},
            {cf::REG_WRITES, rocksdb::ColumnFamilyOptions()},
            {cf::CODE_BYTES, rocksdb::ColumnFamilyOptions()},
        };

        rocksdb::DB* raw_db = nullptr;
        auto s = rocksdb::DB::Open(opts, db_path.string(), cf_descs,
                                   &idx.cf_handles_, &raw_db);
        if (s.ok()) {
            idx.db_ = std::unique_ptr<rocksdb::DB>(raw_db);
            if (idx.is_valid_for(reader)) {
                // Load stats from the META column family. inst_count and
                // file_size are always present (written by build()). The
                // record/anchor/code/event counts were added later, so read
                // them defensively (an older cache may lack some keys).
                auto* meta_cf = idx.get_cf(cf::META);
                auto load_u64 = [&](const char* key, uint64_t& out) {
                    std::string v;
                    if (idx.db_->Get(rocksdb::ReadOptions(), meta_cf, key, &v).ok() &&
                        v.size() == 8) {
                        std::memcpy(&out, v.data(), 8);
                    }
                };
                load_u64("inst_count", idx.stats_.inst_count);
                load_u64("total_records", idx.stats_.total_records);
                load_u64("code_count", idx.stats_.code_count);
                load_u64("event_count", idx.stats_.event_count);
                // Restore adaptive sparse_interval_ (written since schema v5)
                {
                    std::string sv;
                    uint64_t si_val = 256;
                    if (idx.db_->Get(rocksdb::ReadOptions(), meta_cf,
                                     "sparse_interval", &sv).ok() && sv.size() == 8) {
                        std::memcpy(&si_val, sv.data(), 8);
                    }
                    idx.sparse_interval_ = si_val;
                    idx.stats_.sparse_interval = static_cast<uint32_t>(si_val);
                }

                // Load anchor table into memory
                auto* anchor_cf = idx.get_cf(cf::ANCHOR);
                std::unique_ptr<rocksdb::Iterator> it(
                    idx.db_->NewIterator(rocksdb::ReadOptions(), anchor_cf));
                for (it->SeekToFirst(); it->Valid(); it->Next()) {
                    AnchorEntry entry;
                    entry.inst_id = decode_u64(it->key());
                    std::memcpy(&entry.file_offset, it->value().data(),
                               std::min(it->value().size(), size_t(8)));
                    idx.anchors_.push_back(entry);
                }
                std::sort(idx.anchors_.begin(), idx.anchors_.end(),
                          [](const auto& a, const auto& b) {
                              return a.inst_id < b.inst_id;
                          });
                // Derive anchor_count from the loaded vector so the stat is
                // always consistent with the in-memory table (and the display
                // shows the real count instead of 0 when loading from cache).
                idx.stats_.anchor_count = idx.anchors_.size();

                return idx;
            }
        }
        // Invalid cache - rebuild
        for (auto* h : idx.cf_handles_) {
            if (h && raw_db) raw_db->DestroyColumnFamilyHandle(h);
        }
        idx.cf_handles_.clear();
        idx.db_.reset();
        std::filesystem::remove_all(db_path);
    }

    // Build from scratch
    return build(reader, db_path, std::move(progress));
}

// ─── Full index build ─────────────────────────────────────────────────────
//
// P1.5: Parallel build — the trace file is partitioned at ANCHOR record
// boundaries. Each shard scans its slice independently, producing a private
// WriteBatch. Shards run on separate std::threads and are committed to
// RocksDB in order after all threads finish.
//
// Sharding is safe because:
//   - ANCHOR records are always at known file offsets (built into anchors_).
//   - Each shard owns a disjoint [start_offset, end_offset) region.
//   - inst_id ranges are likewise disjoint and known upfront from the anchor table.
//   - SPARSE_INTERVAL entries are globally unique (keyed by inst_id).
//
// P1.6: Adaptive sparse interval — we choose SPARSE_INTERVAL so the sparse
// offset index has at most TARGET_SPARSE_ENTRIES entries, bounding the RocksDB
// lookup + linear scan overhead regardless of trace size.
//
// P1.7: v6 memacc struct size — the linear scan in offset_of_with_pc and
// xref_pass uses the correct 48-byte size when HF_OLD_VALUE is set.
//
// P1.9: CODE_BYTES CF — raw instruction bytes are written to a dedicated CF
// during the same single scan, so main.cpp can call load_code_table() instead
// of performing a second full file traversal.

Result<TraceIndex> TraceIndex::build(
    const TraceReader& reader,
    const std::filesystem::path& db_path,
    ProgressCallback progress) {

    auto t0 = std::chrono::steady_clock::now();

    // ── P1.6: Compute adaptive sparse interval ────────────────────────────
    // First pass: count INST records by scanning just the first 4KB of each
    // mmap page so we can determine inst_count cheaply.  Actually, we don't
    // know inst_count before scanning; instead, use file_size as a proxy:
    // assume ~50 bytes/record on average to estimate.  After the full build
    // we re-snapshot the actual value.
    // For safety, start with the default (256) and keep it if we have no hint.
    // We will recalculate and store the actual value at the end of the build.
    constexpr uint64_t TARGET_SPARSE_ENTRIES = 65536;
    // Rough inst_count estimate from file size (very conservative)
    uint64_t est_inst_count = reader.file_size() / 20;  // 20B/inst avg
    uint64_t adaptive_interval = est_inst_count / TARGET_SPARSE_ENTRIES;
    if (adaptive_interval < SPARSE_MIN) adaptive_interval = SPARSE_MIN;
    if (adaptive_interval > SPARSE_MAX) adaptive_interval = SPARSE_MAX;

    // ── Create RocksDB with column families ───────────────────────────────
    rocksdb::Options opts;
    opts.create_if_missing = true;
    opts.create_missing_column_families = true;
    opts.compression = rocksdb::kNoCompression;
    opts.write_buffer_size = 256 * 1024 * 1024;  // 256MB: reduces compactions during bulk build
    // Bulk-load optimisation: disable auto-compaction and raise L0 triggers
    // so the initial write doesn't stall.  After build we CompactRange() once.
    opts.disable_auto_compactions = true;
    opts.level0_file_num_compaction_trigger = 1024;
    opts.level0_slowdown_writes_trigger = 1024;
    opts.level0_stop_writes_trigger = 1024;
    opts.max_write_buffer_number = 4;

    // Helper: apply bulk-load settings to a column-family options object.
    auto apply_bulk_load_opts = [](rocksdb::ColumnFamilyOptions& o) {
        o.disable_auto_compactions = true;
        o.level0_file_num_compaction_trigger = 1024;
        o.level0_slowdown_writes_trigger = 1024;
        o.level0_stop_writes_trigger = 1024;
        o.max_write_buffer_number = 4;
        o.write_buffer_size = 256 * 1024 * 1024;
    };

    rocksdb::BlockBasedTableOptions table_opts;
    table_opts.block_cache = rocksdb::NewLRUCache(128 * 1024 * 1024);
    table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    table_opts.block_size = 16 * 1024;
    opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_opts));

    rocksdb::ColumnFamilyOptions mem_write_cf_opts;
    mem_write_cf_opts.compression = rocksdb::kLZ4Compression;
    mem_write_cf_opts.prefix_extractor =
        std::shared_ptr<const rocksdb::SliceTransform>(
            rocksdb::NewFixedPrefixTransform(8));  // page(8) only — optimal for SeekForPrev
    rocksdb::BlockBasedTableOptions mem_table_opts;
    mem_table_opts.block_size = 4 * 1024;
    mem_table_opts.block_cache = rocksdb::NewLRUCache(512 * 1024 * 1024);
    mem_table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    mem_table_opts.whole_key_filtering = false;
    mem_write_cf_opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(mem_table_opts));

    rocksdb::ColumnFamilyOptions reg_writes_cf_opts;
    reg_writes_cf_opts.compression = rocksdb::kNoCompression;
    rocksdb::BlockBasedTableOptions reg_writes_table_opts;
    reg_writes_table_opts.block_size = 32 * 1024;
    reg_writes_cf_opts.table_factory.reset(
        rocksdb::NewBlockBasedTableFactory(reg_writes_table_opts));

    std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
        {"default", rocksdb::ColumnFamilyOptions()},
        {cf::META,       rocksdb::ColumnFamilyOptions()},
        {cf::OFFSET,     rocksdb::ColumnFamilyOptions()},
        {cf::ANCHOR,     rocksdb::ColumnFamilyOptions()},
        {cf::MEM_WRITE,  mem_write_cf_opts},
        {cf::MEM_READ,   mem_write_cf_opts},
        {cf::REG_WRITES, reg_writes_cf_opts},
        {cf::CODE_BYTES, rocksdb::ColumnFamilyOptions()},  // P1.9: CODE records
    };

    TraceIndex idx;
    idx.db_path_ = db_path;
    idx.sparse_interval_ = adaptive_interval;

    rocksdb::DB* raw_db = nullptr;
    auto s = rocksdb::DB::Open(opts, db_path.string(), cf_descs,
                               &idx.cf_handles_, &raw_db);
    if (!s.ok()) {
        return Error::rocksdb_error(s.ToString());
    }
    idx.db_ = std::unique_ptr<rocksdb::DB>(raw_db);

    reader.advise_sequential();

    rocksdb::WriteOptions write_opts;
    write_opts.disableWAL = true;
    write_opts.sync = false;

    const uint64_t file_size   = reader.file_size();
    const uint32_t num_gpr     = reader.header().num_gpr;
    const bool     is_v5       = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA)  != 0;
    const bool     is_v6       = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;

    // P1.7: correct memacc struct size depending on format version
    const size_t memacc_sz = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)   // 48 bytes
        : sizeof(qbditrace::qbditrace_memacc_t);      // 32 bytes
    const size_t inst_hdr_sz = is_v5
        ? sizeof(qbditrace::qbditrace_inst_head_v5_t) // 6 bytes
        : sizeof(qbditrace::qbditrace_inst_head_t);   // 16 bytes

    // ── P1.5: Parallel build ──────────────────────────────────────────────
    // Strategy:
    //   1. First pass (serial, cheap): collect all ANCHOR offsets and inst_ids.
    //      This is the same fast raw-pointer scan used by register_file.cpp.
    //   2. Divide anchors into N shards (N = hw_concurrency, capped at 8).
    //      Each shard owns [anchor[i].file_offset, anchor[i+1].file_offset).
    //   3. Each shard thread scans its slice and produces a WriteBatch.
    //   4. Main thread commits all batches in order.
    //
    // Note: OFFSET entries (sparse inst_id → offset) are globally keyed by
    // inst_id, which is unique across shards, so there are no key conflicts.

    // ── Phase 0: Collect anchor positions (serial, one scan) ───────────────
    struct ShardBoundary {
        uint64_t file_start;  // inclusive
        uint64_t file_end;    // exclusive
        uint64_t inst_id_start;
    };

    std::vector<ShardBoundary> shard_bounds;
    {
        // Collect all anchor positions by scanning the raw mmap.
        // We also build the in-memory anchor table here (same data needed later).
        struct RawAnchor {
            uint64_t inst_id;
            uint64_t file_offset;
            uint64_t pc;  // absolute PC stored in the anchor
        };
        std::vector<RawAnchor> raw_anchors;
        raw_anchors.reserve(4096);

        uint64_t scan_id = 0;
        const uint8_t* base = reader.data();
        const uint8_t* end  = base + file_size;
        const uint8_t* ptr  = base + sizeof(qbditrace::qbditrace_file_header_t);

        while (ptr < end) {
            auto kind = static_cast<RecordKind>(ptr[0]);
            size_t rec_size = 0;
            switch (kind) {
            case RecordKind::Inst:
                rec_size = inst_hdr_sz
                    + ptr[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                    + ptr[3] * memacc_sz;
                scan_id++;
                break;
            case RecordKind::Anchor: {
                rec_size = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
                const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                uint64_t foff = static_cast<uint64_t>(ptr - base);
                raw_anchors.push_back({scan_id, foff, ah->pc});
                break;
            }
            case RecordKind::Thread: rec_size = sizeof(qbditrace::qbditrace_thread_head_t); break;
            case RecordKind::Event:  rec_size = sizeof(qbditrace::qbditrace_event_head_t);  break;
            case RecordKind::Svc:    rec_size = sizeof(qbditrace::qbditrace_svc_head_t);    break;
            case RecordKind::Objc:   rec_size = sizeof(qbditrace::qbditrace_objc_head_t);   break;
            case RecordKind::Code:   rec_size = sizeof(qbditrace::qbditrace_code_head_t) + ptr[1]; break;
            default: rec_size = 1; break;
            }
            if (rec_size == 0) break;  // guard against corrupt records
            ptr += rec_size;
        }

        // Populate in-memory anchor table
        for (const auto& a : raw_anchors) {
            idx.anchors_.push_back({a.inst_id, a.file_offset});
        }
        // anchors_ will be sorted after build

        // P1.6 fix: recompute sparse_interval_ from the EXACT inst_count
        // obtained by Phase 0 scanning. The initial adaptive_interval was
        // estimated from file_size/20, which can differ significantly from
        // the actual count. If sparse_interval_ at build time != query time,
        // the OFFSET CF keys will be at wrong positions and offset_of() will
        // FALLBACK for most inst_ids.
        uint64_t exact_interval = scan_id / TARGET_SPARSE_ENTRIES;
        if (exact_interval < SPARSE_MIN) exact_interval = SPARSE_MIN;
        if (exact_interval > SPARSE_MAX) exact_interval = SPARSE_MAX;
        idx.sparse_interval_ = exact_interval;
        idx.stats_.sparse_interval = static_cast<uint32_t>(exact_interval);

        // Compute shard boundaries: split anchor list evenly across threads.
        const uint32_t hw_threads = std::min(
            static_cast<uint32_t>(std::thread::hardware_concurrency()),
            uint32_t(8));
        // Use parallel only if we have enough anchors (at least 4 per shard)
        const uint32_t num_shards = (raw_anchors.size() >= hw_threads * 4)
            ? hw_threads : 1u;
        idx.stats_.num_shards = num_shards;

        const uint64_t records_start = sizeof(qbditrace::qbditrace_file_header_t);
        if (num_shards == 1 || raw_anchors.empty()) {
            shard_bounds.push_back({records_start, file_size, 0});
        } else {
            // Distribute anchors roughly evenly, always starting each shard at
            // an ANCHOR boundary so the shard's first record is a full snapshot.
            size_t anchors_per_shard = raw_anchors.size() / num_shards;
            for (uint32_t s = 0; s < num_shards; s++) {
                size_t anchor_idx = s * anchors_per_shard;
                // First shard starts from beginning of records (before first anchor)
                uint64_t fstart = (s == 0)
                    ? records_start
                    : raw_anchors[anchor_idx].file_offset;
                uint64_t fend = (s + 1 < num_shards)
                    ? raw_anchors[(s + 1) * anchors_per_shard].file_offset
                    : file_size;
                uint64_t id_start = (s == 0) ? 0 : raw_anchors[anchor_idx].inst_id;
                shard_bounds.push_back({fstart, fend, id_start});
            }
        }
    }

    // ── Phase 1: Parallel shard processing ────────────────────────────────
    // Each shard produces one WriteBatch.  We use atomic progress counter
    // for the progress callback.
    const uint32_t num_shards = static_cast<uint32_t>(shard_bounds.size());

    struct ShardResult {
        rocksdb::WriteBatch batch;
        uint64_t inst_count    = 0;  // INST records in this shard
        uint64_t anchor_count  = 0;
        uint64_t code_count    = 0;
        uint64_t event_count   = 0;
        uint64_t total_records = 0;
        std::string error;  // non-empty on failure
    };

    std::vector<ShardResult> shard_results(num_shards);
    std::atomic<uint64_t> progress_bytes{0};

    auto process_shard = [&](uint32_t shard_idx) {
        auto& result = shard_results[shard_idx];
        const auto& bounds = shard_bounds[shard_idx];
        // Start with a modest batch; we flush periodically to keep memory
        // bounded and overlap scanning with RocksDB writes.
        result.batch = rocksdb::WriteBatch(64 * 1024);

        auto* offset_cf   = idx.get_cf(cf::OFFSET);
        auto* anchor_cf   = idx.get_cf(cf::ANCHOR);
        auto* rw_cf       = idx.get_cf(cf::REG_WRITES);
        auto* code_cf     = idx.get_cf(cf::CODE_BYTES);

        const uint8_t* base = reader.data();
        const uint8_t* ptr  = base + bounds.file_start;
        const uint8_t* end  = base + bounds.file_end;

        uint64_t inst_id = bounds.inst_id_start;
        uint64_t batch_writes = 0;

        // Flush threshold: write to RocksDB every N entries to bound memory
        // and overlap I/O with scanning. 50K entries per flush keeps each
        // WriteBatch around 2-5MB (keys+values), fast for MemTable insertion.
        constexpr uint64_t FLUSH_THRESHOLD = 50000;
        auto flush_batch = [&]() {
            if (batch_writes == 0) return;
            auto ws = idx.db_->Write(write_opts, &result.batch);
            if (!ws.ok()) {
                result.error = ws.ToString();
            }
            result.batch.Clear();
            batch_writes = 0;
        };

        while (ptr < end) {
            auto kind = static_cast<RecordKind>(ptr[0]);
            size_t rec_size = 0;

            switch (kind) {
            case RecordKind::Inst: {
                // P1.6: Sparse offset with adaptive interval
                if (inst_id % idx.sparse_interval_ == 0) {
                    uint64_t foff = static_cast<uint64_t>(ptr - base);
                    char key_buf[8];
                    result.batch.Put(offset_cf,
                        encode_u64_to(inst_id, key_buf),
                        rocksdb::Slice(reinterpret_cast<const char*>(&foff), 8));
                    batch_writes++;
                }
                // REG_WRITES inverted index
                if (rw_cf) {
                    uint8_t n_regdiff = ptr[2];
                    const uint8_t* diffs = ptr + inst_hdr_sz;
                    for (uint8_t d = 0; d < n_regdiff; d++) {
                        const auto* rd = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                            diffs + d * sizeof(qbditrace::qbditrace_regdiff_t));
                        char rw_key[10];
                        rw_key[0] = 0;
                        rw_key[1] = static_cast<char>(rd->reg_index);
                        for (int i = 7; i >= 0; --i)
                            rw_key[2 + (7 - i)] = static_cast<char>((inst_id >> (i * 8)) & 0xFF);
                        result.batch.Put(rw_cf,
                            rocksdb::Slice(rw_key, 10),
                            rocksdb::Slice());
                        batch_writes++;
                    }
                }
                // P1.7: use correct memacc_sz for record size
                rec_size = inst_hdr_sz
                    + ptr[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                    + ptr[3] * memacc_sz;
                inst_id++;
                result.inst_count++;
                break;
            }
            case RecordKind::Anchor: {
                rec_size = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
                uint64_t foff = static_cast<uint64_t>(ptr - base);
                char anchor_key_buf[8];
                result.batch.Put(anchor_cf,
                    encode_u64_to(inst_id, anchor_key_buf),
                    rocksdb::Slice(reinterpret_cast<const char*>(&foff), 8));
                batch_writes++;
                result.anchor_count++;
                break;
            }
            case RecordKind::Code: {
                // P1.9: Store raw instruction bytes in CODE_BYTES CF
                uint8_t code_size = ptr[1];
                rec_size = sizeof(qbditrace::qbditrace_code_head_t) + code_size;
                if (code_cf && code_size == 4) {
                    const auto* ch = reinterpret_cast<const qbditrace::qbditrace_code_head_t*>(ptr);
                    char key_buf[8];
                    result.batch.Put(code_cf,
                        encode_u64_to(ch->pc, key_buf),
                        rocksdb::Slice(reinterpret_cast<const char*>(
                            ptr + sizeof(qbditrace::qbditrace_code_head_t)), 4));
                    batch_writes++;
                }
                result.code_count++;
                break;
            }
            case RecordKind::Event:
                rec_size = sizeof(qbditrace::qbditrace_event_head_t);
                result.event_count++;
                break;
            case RecordKind::Thread:
                rec_size = sizeof(qbditrace::qbditrace_thread_head_t);
                break;
            case RecordKind::Svc:
                rec_size = sizeof(qbditrace::qbditrace_svc_head_t);
                break;
            case RecordKind::Objc:
                rec_size = sizeof(qbditrace::qbditrace_objc_head_t);
                break;
            default:
                rec_size = 1;
                break;
            }

            result.total_records++;

            // Periodic flush: write the accumulated batch to RocksDB so
            // memory stays bounded and writes overlap with scanning.
            // RocksDB::Write() is thread-safe — multiple shards flush
            // concurrently, and the MemTable's skip list handles parallel
            // inserts (with internal locking).
            if (batch_writes >= FLUSH_THRESHOLD) {
                flush_batch();
            }

            if (rec_size == 0) break;
            ptr += rec_size;

            // Update shared progress counter (relaxed — just for display)
            progress_bytes.fetch_add(rec_size, std::memory_order_relaxed);
        }

        // Final flush for any remaining entries in this shard's batch.
        flush_batch();
    };

    if (num_shards == 1) {
        // Single-threaded path (small trace or no anchors)
        process_shard(0);
        if (progress) progress(file_size, file_size);
    } else {
        std::atomic<uint32_t> workers_done{0};
        std::vector<std::thread> workers;
        workers.reserve(num_shards);
        for (uint32_t s = 0; s < num_shards; s++) {
            workers.emplace_back([&, s]() {
                process_shard(s);
                workers_done.fetch_add(1, std::memory_order_relaxed);
            });
        }
        // Progress callback on main thread while workers run.
        // Poll every 50ms; exit once all workers have incremented workers_done.
        if (progress) {
            while (workers_done.load(std::memory_order_relaxed) < num_shards) {
                uint64_t done = progress_bytes.load(std::memory_order_relaxed);
                progress(done, file_size);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            progress(file_size, file_size);  // final 100%
        }
        for (auto& w : workers) w.join();
    }

    // Check for shard errors
    for (const auto& r : shard_results) {
        if (!r.error.empty()) {
            return Error::rocksdb_error(r.error);
        }
    }

    // ── Phase 2: Flush any remaining batch entries ──────────────────────
    // With periodic flushing during Phase 1, most (or all) data is already
    // in RocksDB by the time workers finish. This loop handles any residual
    // entries (the final partial batch of each shard) and is typically fast.
    {
        uint32_t shards_to_commit = 0;
        for (auto& r : shard_results) {
            if (r.batch.Count() > 0) shards_to_commit++;
        }
        if (shards_to_commit > 0) {
            std::fprintf(stderr, "\r  Flushing remaining index entries (%u shards)...    \n",
                         shards_to_commit);
            std::fflush(stderr);
        }
    }
    for (size_t si = 0; si < shard_results.size(); si++) {
        auto& r = shard_results[si];
        if (r.batch.Count() == 0) continue;
        auto ws = idx.db_->Write(write_opts, &r.batch);
        if (!ws.ok()) {
            return Error::rocksdb_error(ws.ToString());
        }
        r.batch.Clear();
    }
    std::fprintf(stderr, "\r                                                            \r");
    std::fflush(stderr);

    // ── Phase 3: Aggregate statistics ────────────────────────────────────
    uint64_t inst_id = 0, total_records = 0;
    for (auto& r : shard_results) {
        inst_id       += r.inst_count;
        total_records += r.total_records;
        idx.stats_.anchor_count += r.anchor_count;
        idx.stats_.code_count   += r.code_count;
        idx.stats_.event_count  += r.event_count;
    }
    idx.stats_.inst_count    = inst_id;
    idx.stats_.total_records = total_records;

    // P1.6: Re-compute adaptive interval from actual inst_count and persist it.
    uint64_t actual_interval = inst_id / TARGET_SPARSE_ENTRIES;
    if (actual_interval < SPARSE_MIN) actual_interval = SPARSE_MIN;
    if (actual_interval > SPARSE_MAX) actual_interval = SPARSE_MAX;
    idx.sparse_interval_ = actual_interval;
    idx.stats_.sparse_interval = static_cast<uint32_t>(actual_interval);

    // Write metadata
    auto* meta_cf = idx.get_cf(cf::META);
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "version", "1");
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "schema_version",
                 rocksdb::Slice(reinterpret_cast<const char*>(&INDEX_SCHEMA_VERSION), 4));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "inst_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&inst_id), 8));
    uint64_t fsize = reader.file_size();
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "file_size",
                 rocksdb::Slice(reinterpret_cast<const char*>(&fsize), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "total_records",
                 rocksdb::Slice(reinterpret_cast<const char*>(&total_records), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "anchor_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.anchor_count), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "code_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.code_count), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "event_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.event_count), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "sparse_interval",
                 rocksdb::Slice(reinterpret_cast<const char*>(&actual_interval), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "num_shards",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.num_shards), 4));

    // Store trace hash for integrity verification (fast sample-based hash)
    uint64_t trace_hash = sample_trace_hash(reader);
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "trace_hash",
                 rocksdb::Slice(reinterpret_cast<const char*>(&trace_hash), 8));

    auto t1 = std::chrono::steady_clock::now();
    idx.stats_.build_seconds =
        std::chrono::duration<double>(t1 - t0).count();

    // Sort anchors (gathered from Phase 0 raw scan, already in order but sort for safety)
    std::sort(idx.anchors_.begin(), idx.anchors_.end(),
              [](const auto& a, const auto& b) { return a.inst_id < b.inst_id; });

    reader.advise_random();

    return idx;
}

// ─── Query: offset_of ─────────────────────────────────────────────────────

uint64_t TraceIndex::offset_of(uint64_t inst_id, const TraceReader& reader) const {
    return offset_of_with_pc(inst_id, reader).offset;
}

TraceIndex::OffsetResult TraceIndex::offset_of_with_pc(uint64_t inst_id, const TraceReader& reader) const {
    // ── Hot offset cache: avoid RocksDB seek + linear scan for repeat queries ──
    {
        std::lock_guard<std::mutex> lk(offset_cache_mtx_);
        if (auto cached = offset_cache_.get(inst_id)) {
            return cached->get();
        }
    }

    // Find the sparse entry at or before inst_id (adaptive interval)
    const uint64_t si = sparse_interval_;
    uint64_t base_id = (inst_id / si) * si;

    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), get_cf(cf::OFFSET),
                      encode_u64(base_id), &value);
    if (!s.ok() || value.size() < 8) {
        // Fallback: start from beginning
        // FALLBACK: no sparse entry found
        return {sizeof(qbditrace::qbditrace_file_header_t), 0};
    }

    uint64_t offset = 0;
    std::memcpy(&offset, value.data(), 8);

    // Linear scan from base_id to inst_id
    // The stored offset points to the INST record for base_id.
    // We need to find the INST record for inst_id.
    uint64_t current_id = base_id;
    uint64_t current_offset = offset;
    const uint32_t num_gpr = reader.header().num_gpr;
    const bool is_v5 = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;

    // For v5 traces we track the running PC so we can return seed_pc to callers
    // (they need it to correctly call as_inst() on the resulting offset).
    // We need to find an anchor at/before base_id to seed running_pc.
    // Use the in-memory anchor table: nearest_anchor_before(base_id) gives us a
    // file_offset to scan from with a known absolute PC.
    uint64_t running_pc = 0;
    if (is_v5) {
        // Walk from the nearest anchor up to base_id to seed running_pc.
        auto anchor_info = nearest_anchor_before(base_id);
        if (anchor_info.file_offset > 0) {
            const uint8_t* a_ptr = reader.data_at(anchor_info.file_offset);
            const auto* a_hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(a_ptr);
            running_pc = a_hdr->pc;
            // Walk from anchor's inst_id up to base_id accumulating pc_delta
            uint64_t walk_offset = anchor_info.file_offset;
            uint64_t walk_id = anchor_info.inst_id;
            while (walk_offset < reader.file_size() && walk_id < base_id) {
                const uint8_t* wp = reader.data_at(walk_offset);
                auto wkind = static_cast<RecordKind>(wp[0]);
                if (wkind == RecordKind::Inst) {
                    int16_t delta;
                    std::memcpy(&delta, wp + 4, 2);  // pc_delta at byte offset 4 in v5 head
                    running_pc += static_cast<int64_t>(delta);
                    walk_id++;
                    // P1.7: use v6-aware memacc size
                    const bool wis_v6 = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
                    const size_t wmacc_sz = wis_v6
                        ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                        : sizeof(qbditrace::qbditrace_memacc_t);
                    walk_offset += sizeof(qbditrace::qbditrace_inst_head_v5_t)
                        + wp[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                        + wp[3] * wmacc_sz;
                } else if (wkind == RecordKind::Anchor) {
                    const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(wp);
                    running_pc = ah->pc;
                    walk_offset += sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
                } else {
                    auto rec = reader.record_at(walk_offset);
                    walk_offset += rec.byte_size(num_gpr);
                }
            }
        }
    }

    while (current_offset < reader.file_size()) {
        const uint8_t* ptr = reader.data_at(current_offset);
        auto kind = static_cast<RecordKind>(ptr[0]);

        if (kind == RecordKind::Inst) {
            if (is_v5) {
                // Accumulate pc_delta BEFORE checking if we've reached the target,
                // so running_pc holds the absolute PC of the instruction at current_offset.
                int16_t delta;
                std::memcpy(&delta, ptr + 4, 2);
                running_pc += static_cast<int64_t>(delta);
            }
            if (current_id == inst_id) {
                // seed_pc is only meaningful for v5 traces:
                // - v5: return running_pc so callers can pass it to record_at(offset, seed_pc),
                //   which sets RecordView::is_v5 = true so as_inst() uses the 6-byte v5 layout.
                // - v4: return 0; record_at(offset, 0) is the 1-arg overload leaving is_v5=false,
                //   so as_inst() uses the 16-byte v4 layout and reads pc from the raw struct.
                uint64_t seed = is_v5 ? running_pc : 0;
                OffsetResult result{current_offset, seed};
                { std::lock_guard<std::mutex> lk(offset_cache_mtx_); offset_cache_.put(inst_id, result); }
                return result;
            }
            current_id++;
            // Compute record size directly from raw bytes, respecting v4/v5 layout.
            // (RecordView::byte_size() now uses the is_v5 flag; however this hot path
            //  avoids constructing a RecordView at all for speed.)
            size_t hdr_size = is_v5
                ? sizeof(qbditrace::qbditrace_inst_head_v5_t)   // 6 bytes
                : sizeof(qbditrace::qbditrace_inst_head_t);     // 16 bytes (with padding)
            uint8_t n_regdiff = ptr[2];
            uint8_t n_mem = ptr[3];
            // P1.7: use v6-aware memacc size in linear scan
            const bool is_v6_scan = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
            const size_t macc_scan_sz = is_v6_scan
                ? sizeof(qbditrace::qbditrace_memacc_v6_t)   // 48 bytes
                : sizeof(qbditrace::qbditrace_memacc_t);      // 32 bytes
            current_offset += hdr_size
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)   // 16 bytes each
                + n_mem     * macc_scan_sz;
        } else {
            // For non-INST records, use the generic byte_size() helper.
            // These records (Anchor, Code, Event, etc.) have the same layout in v4/v5.
            if (is_v5 && kind == RecordKind::Anchor) {
                // Resync running_pc from anchor's absolute PC
                const auto* a_hdr = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                running_pc = a_hdr->pc;
            }
            auto rec = reader.record_at(current_offset);
            current_offset += rec.byte_size(num_gpr);
        }
    }

    OffsetResult result{current_offset, running_pc};
    { std::lock_guard<std::mutex> lk(offset_cache_mtx_); offset_cache_.put(inst_id, result); }
    return result;
}

// ─── Query: nearest_anchor_before ─────────────────────────────────────────

TraceIndex::AnchorInfo TraceIndex::nearest_anchor_before(uint64_t inst_id) const {
    if (anchors_.empty()) {
        return {0, sizeof(qbditrace::qbditrace_file_header_t), 0};
    }

    // Binary search for the largest anchor_inst_id <= inst_id
    AnchorEntry target{inst_id, 0};
    auto it = std::upper_bound(anchors_.begin(), anchors_.end(), target,
                               [](const AnchorEntry& a, const AnchorEntry& b) {
                                   return a.inst_id < b.inst_id;
                               });

    if (it == anchors_.begin()) {
        // All anchors are after inst_id, use first one or file start
        return {0, anchors_[0].file_offset, anchors_[0].inst_id};
    }

    --it;  // Now points to the largest anchor <= inst_id
    auto idx = static_cast<uint64_t>(std::distance(anchors_.begin(), it));
    return {idx, it->file_offset, it->inst_id};
}

// ─── Query: find_last_writer_of ───────────────────────────────────────────

uint64_t TraceIndex::find_last_writer_of(uint8_t reg_idx, uint64_t before_id,
                                         const TraceReader& reader) const {
    // ── Fast path: REG_WRITES inverted index ──────────────────────────────
    // Key format: u16(reg_idx) big-endian (2 bytes) + u64(inst_id) big-endian (8 bytes).
    // SeekForPrev on key=(reg, before_id - 1) → largest entry ≤ that key.
    // If it belongs to the same reg_idx, that is the last writer. O(log N).
    auto* rw_cf = get_cf(cf::REG_WRITES);
    if (rw_cf) {
        // Build seek key for (reg_idx, before_id - 1):
        // We want the entry with the largest inst_id strictly < before_id.
        uint64_t seek_id = (before_id > 0) ? before_id - 1 : 0;

        char seek_key[10];
        seek_key[0] = 0;
        seek_key[1] = static_cast<char>(reg_idx);
        for (int i = 7; i >= 0; --i) {
            seek_key[2 + (7 - i)] = static_cast<char>((seek_id >> (i * 8)) & 0xFF);
        }

        rocksdb::ReadOptions ro;
        ro.total_order_seek = false;
        std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(ro, rw_cf));
        it->SeekForPrev(rocksdb::Slice(seek_key, 10));

        if (it->Valid()) {
            auto k = it->key();
            if (k.size() == 10) {
                // Decode reg from first 2 bytes
                uint8_t found_reg = static_cast<uint8_t>(k.data()[1]);
                if (found_reg == reg_idx) {
                    // Decode inst_id from next 8 bytes
                    uint64_t found_id = 0;
                    for (int i = 0; i < 8; ++i) {
                        found_id = (found_id << 8) |
                                   static_cast<uint8_t>(k.data()[2 + i]);
                    }
                    if (found_id < before_id) {
                        return found_id;
                    }
                }
            }
        }

        // No writer found in index
        return 0;
    }

    // ── Fallback: linear scan (old index without REG_WRITES CF) ──────────
    // Limit scan to the last 50K instructions to bound worst-case cost.
    uint64_t scan_start = (before_id > 50000) ? before_id - 50000 : 0;
    uint64_t start_offset = 0;
    if (scan_start > 0) {
        start_offset = offset_of(scan_start, reader);
    }

    uint64_t last_writer_id = 0;
    uint64_t inst_id = scan_start;

    auto it_start = (start_offset > 0)
        ? TraceReader::Iterator(&reader, start_offset)
        : reader.begin();

    for (auto it = it_start; it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        inst_id++;
        if (inst_id >= before_id) break;
        auto inst = rec.as_inst();
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            if (diff.index == reg_idx) {
                last_writer_id = inst_id;
            }
        }
    }
    return last_writer_id;
}

// ─── Query: load_code_table (P1.9) ─────────────────────────────────────────
//
// Populate a CodeTable from the CODE_BYTES column family.
// This replaces the second full file scan that main.cpp previously did:
//
//   Old flow:  build index (1 pass)  +  scan file for CODE records (2nd pass)
//   New flow:  build index (1 pass, CODE_BYTES CF populated inline)
//              load_code_table() reads from RocksDB  ← zero extra file I/O

uint64_t TraceIndex::load_code_table(CodeTable& out) const {
    auto* cf = get_cf(cf::CODE_BYTES);
    if (!cf || !db_) return 0;

    rocksdb::ReadOptions ro;
    ro.fill_cache = false;  // sequential scan — avoid polluting block cache
    std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(ro, cf));

    uint64_t count = 0;
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        if (it->key().size() != 8) continue;
        if (it->value().size() != 4) continue;
        // Decode big-endian PC key
        uint64_t pc = decode_u64(it->key());
        uint32_t opcode = 0;
        std::memcpy(&opcode, it->value().data(), 4);
        out.insert(pc, opcode);
        count++;
    }
    return count;
}

// ─── verify_integrity ─────────────────────────────────────────────────────
//
// Two-level check:
//   1. RocksDB VerifyChecksum()   — detects SST block-level corruption
//   2. Trace content hash check   — detects file swap / external modification
//
// Both checks are fast (<10ms on typical hardware) because:
//   - VerifyChecksum() only reads the index blocks (not all data blocks).
//   - sample_trace_hash() reads at most 2MB of the trace file (already mmap'd).

TraceIndex::IntegrityResult TraceIndex::verify_integrity(const TraceReader& reader) const {
    IntegrityResult result;

    if (!db_) {
        result.ok = false;
        result.error = "index not open";
        return result;
    }

    // ── Step 1: RocksDB internal checksum ─────────────────────────────────
    auto s = db_->VerifyChecksum();
    if (!s.ok()) {
        result.ok = false;
        result.error = "RocksDB checksum failure: " + s.ToString();
        return result;
    }

    // ── Step 2: Trace content hash ─────────────────────────────────────────
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) {
        result.ok = false;
        result.error = "META column family missing";
        return result;
    }

    std::string hash_val;
    auto hs = db_->Get(rocksdb::ReadOptions(), meta_cf, "trace_hash", &hash_val);
    if (!hs.ok() || hash_val.size() < 8) {
        // Index was built before schema v7 — skip hash check
        // (is_valid_for already rejected old caches; if we get here it's fine)
        return result;
    }

    uint64_t stored_hash = 0;
    std::memcpy(&stored_hash, hash_val.data(), 8);
    uint64_t current_hash = sample_trace_hash(reader);

    if (stored_hash != current_hash) {
        result.ok = false;
        std::ostringstream oss;
        oss << "trace content mismatch: stored hash 0x" << std::hex << stored_hash
            << " != current 0x" << current_hash
            << " (trace file may have been replaced or corrupted)";
        result.error = oss.str();
        return result;
    }

    return result;
}

// ─── Session persistence ───────────────────────────────────────────────────
//
// Bookmarks and last-cursor are stored in the META column family under fixed
// keys:
//   "bookmarks"   → packed array of uint64_t (little-endian, N×8 bytes)
//   "last_inst"   → single uint64_t (8 bytes, little-endian)
//
// Using the existing META CF avoids adding a new column family and keeps all
// per-trace user data in a single well-known place.

void TraceIndex::save_bookmarks(const std::vector<uint64_t>& bookmarks) {
    if (!db_) return;
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return;

    // Encode as packed little-endian uint64_t array
    std::string value;
    value.resize(bookmarks.size() * 8);
    for (size_t i = 0; i < bookmarks.size(); i++) {
        std::memcpy(&value[i * 8], &bookmarks[i], 8);
    }
    db_->Put(rocksdb::WriteOptions(), meta_cf, "bookmarks",
             rocksdb::Slice(value));
}

std::vector<uint64_t> TraceIndex::load_bookmarks() const {
    if (!db_) return {};
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return {};

    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), meta_cf, "bookmarks", &value);
    if (!s.ok() || value.size() % 8 != 0) return {};

    std::vector<uint64_t> result;
    result.reserve(value.size() / 8);
    for (size_t i = 0; i + 8 <= value.size(); i += 8) {
        uint64_t id = 0;
        std::memcpy(&id, &value[i], 8);
        result.push_back(id);
    }
    return result;
}

void TraceIndex::save_last_inst(uint64_t inst_id) {
    if (!db_) return;
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return;
    db_->Put(rocksdb::WriteOptions(), meta_cf, "last_inst",
             rocksdb::Slice(reinterpret_cast<const char*>(&inst_id), 8));
}

uint64_t TraceIndex::load_last_inst() const {
    if (!db_) return 0;
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return 0;
    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), meta_cf, "last_inst", &value);
    if (!s.ok() || value.size() < 8) return 0;
    uint64_t id = 0;
    std::memcpy(&id, value.data(), 8);
    return id;
}

// ─── Generic pass-result blob cache ───────────────────────────────────────

void TraceIndex::save_pass_blob(std::string_view pass_name,
                                const void* data, size_t size) {
    if (!db_ || !data || size == 0) return;
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return;

    // Key: "pass:<name>" to avoid collisions with other META keys.
    std::string key;
    key.reserve(5 + pass_name.size());
    key += "pass:";
    key += pass_name;

    rocksdb::WriteOptions wo;
    wo.sync = false;
    db_->Put(wo, meta_cf, key,
             rocksdb::Slice(static_cast<const char*>(data), size));
}

bool TraceIndex::load_pass_blob(std::string_view pass_name,
                                std::string& out) const {
    if (!db_) return false;
    auto* meta_cf = get_cf(cf::META);
    if (!meta_cf) return false;

    std::string key;
    key.reserve(5 + pass_name.size());
    key += "pass:";
    key += pass_name;

    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), meta_cf, key, &value);
    if (!s.ok() || value.empty()) return false;

    out = std::move(value);
    return true;
}

}  // namespace tenet

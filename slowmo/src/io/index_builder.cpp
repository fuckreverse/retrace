#include "io/index_builder.h"
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>
#include <rocksdb/slice_transform.h>

#include <chrono>
#include <algorithm>
#include <cstring>

namespace tenet {

// Schema version for the RocksDB index cache.
// Bump this whenever TraceFormat struct sizes change, column families are
// added/removed, or the encoding of keys/values in the DB changes.
// This ensures stale caches from older builds are invalidated automatically.
static constexpr uint32_t INDEX_SCHEMA_VERSION = 4;  // v4: mem CF prefix extractor 10→8, dedicated block cache

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
    return trace_dir / (".tenet_cache_" + trace_name);
}

}  // anonymous namespace

// ─── TraceIndex lifecycle ─────────────────────────────────────────────────

TraceIndex::~TraceIndex() {
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
      anchors_(std::move(other.anchors_)) {
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
        other.cf_handles_.clear();
    }
    return *this;
}

rocksdb::ColumnFamilyHandle* TraceIndex::get_cf(const char* name) const {
    // Order: default(0), meta(1), offset(2), anchor(3), mem_write(4), mem_read(5), reg_writes(6)
    if (std::strcmp(name, "default") == 0)     return cf_handles_[0];
    if (std::strcmp(name, cf::META) == 0)      return cf_handles_[1];
    if (std::strcmp(name, cf::OFFSET) == 0)    return cf_handles_[2];
    if (std::strcmp(name, cf::ANCHOR) == 0)    return cf_handles_[3];
    if (std::strcmp(name, cf::MEM_WRITE) == 0  && cf_handles_.size() > 4) return cf_handles_[4];
    if (std::strcmp(name, cf::MEM_READ) == 0   && cf_handles_.size() > 5) return cf_handles_[5];
    if (std::strcmp(name, cf::REG_WRITES) == 0 && cf_handles_.size() > 6) return cf_handles_[6];
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
    return stored_size == reader.file_size();
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

Result<TraceIndex> TraceIndex::build(
    const TraceReader& reader,
    const std::filesystem::path& db_path,
    ProgressCallback progress) {

    auto t0 = std::chrono::steady_clock::now();

    // Create RocksDB with column families
    rocksdb::Options opts;
    opts.create_if_missing = true;
    opts.create_missing_column_families = true;
    opts.compression = rocksdb::kNoCompression;
    opts.write_buffer_size = 256 * 1024 * 1024;  // 256MB: reduces compactions during bulk build

    rocksdb::BlockBasedTableOptions table_opts;
    table_opts.block_cache = rocksdb::NewLRUCache(128 * 1024 * 1024);
    table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    table_opts.block_size = 16 * 1024;
    opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_opts));

    rocksdb::ColumnFamilyOptions mem_write_cf_opts;
    mem_write_cf_opts.compression = rocksdb::kLZ4Compression;
    // mem_write CF uses SeekForPrev on [page(8B)|offset(2B)|inst_id(8B)] keys.
    // Prefix bloom on the first 8 bytes (page only) is better suited to the
    // SeekForPrev access pattern: queries scan backwards across multiple offsets
    // within a page, so page-level bloom lets RocksDB skip entire SST files for
    // pages that don't exist, while offset-level bloom would miss adjacent offsets.
    mem_write_cf_opts.prefix_extractor =
        std::shared_ptr<const rocksdb::SliceTransform>(
            rocksdb::NewFixedPrefixTransform(8));  // page(8) only — optimal for SeekForPrev
    rocksdb::BlockBasedTableOptions mem_table_opts;
    mem_table_opts.block_size = 4 * 1024;
    // Dedicated 512MB block cache for mem_write/mem_read CFs.
    // These CFs are the hottest during analysis passes (string scan, taint, etc.)
    // and benefit from not sharing cache space with offset/anchor CFs.
    mem_table_opts.block_cache = rocksdb::NewLRUCache(512 * 1024 * 1024);
    mem_table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    mem_table_opts.whole_key_filtering = false;  // use prefix bloom only
    mem_write_cf_opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(mem_table_opts));

    // reg_writes CF: dense sequential writes (one entry per reg_diff), use larger blocks
    rocksdb::ColumnFamilyOptions reg_writes_cf_opts;
    reg_writes_cf_opts.compression = rocksdb::kNoCompression;
    rocksdb::BlockBasedTableOptions reg_writes_table_opts;
    reg_writes_table_opts.block_size = 32 * 1024;
    reg_writes_cf_opts.table_factory.reset(
        rocksdb::NewBlockBasedTableFactory(reg_writes_table_opts));

    std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
        {"default", rocksdb::ColumnFamilyOptions()},
        {cf::META, rocksdb::ColumnFamilyOptions()},
        {cf::OFFSET, rocksdb::ColumnFamilyOptions()},
        {cf::ANCHOR, rocksdb::ColumnFamilyOptions()},
        {cf::MEM_WRITE, mem_write_cf_opts},
        {cf::MEM_READ,  mem_write_cf_opts},  // same prefix-extractor/table config as mem_write
        {cf::REG_WRITES, reg_writes_cf_opts},
    };

    TraceIndex idx;
    idx.db_path_ = db_path;

    rocksdb::DB* raw_db = nullptr;
    auto s = rocksdb::DB::Open(opts, db_path.string(), cf_descs,
                               &idx.cf_handles_, &raw_db);
    if (!s.ok()) {
        return Error::rocksdb_error(s.ToString());
    }
    idx.db_ = std::unique_ptr<rocksdb::DB>(raw_db);

    // Sequential scan
    reader.advise_sequential();

    // ── Performance: disable WAL during bulk build ──────────────────────────
    // The index is fully reconstructible from the trace file, so WAL is pure
    // overhead (fsync + write amplification). This alone saves 20-40% build time.
    rocksdb::WriteOptions write_opts;
    write_opts.disableWAL = true;
    write_opts.sync = false;

    rocksdb::WriteBatch batch(256 * 1024);  // Pre-reserve batch memory
    uint64_t inst_id = 0;
    uint64_t total_records = 0;
    const uint64_t file_size = reader.file_size();
    const uint32_t num_gpr = reader.header().num_gpr;

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        total_records++;

        switch (rec.kind) {
        case RecordKind::Inst: {
            // Sparse offset: every SPARSE_INTERVAL instructions
            if (inst_id % SPARSE_INTERVAL == 0) {
                char key_buf[8];
                batch.Put(idx.get_cf(cf::OFFSET),
                         encode_u64_to(inst_id, key_buf),
                         rocksdb::Slice(reinterpret_cast<const char*>(&rec.file_offset), 8));
            }

            // REG_WRITES inverted index: one entry per reg_diff.
            // Key (10 bytes, big-endian): [u16 reg_index][u64 inst_id]
            // This lets ProducerChainPass find the last writer of any register
            // in O(log N) via SeekForPrev instead of O(N) linear scan.
            {
                auto* rw_cf = idx.get_cf(cf::REG_WRITES);
                if (rw_cf) {
                    auto inst = rec.as_inst();
                    for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                        auto diff = inst.reg_diff(d);
                        // Build 10-byte big-endian key: reg(2B) + inst_id(8B)
                        char rw_key[10];
                        rw_key[0] = 0;
                        rw_key[1] = static_cast<char>(diff.index);
                        for (int i = 7; i >= 0; --i) {
                            rw_key[2 + (7 - i)] = static_cast<char>((inst_id >> (i * 8)) & 0xFF);
                        }
                        batch.Put(rw_cf,
                                  rocksdb::Slice(rw_key, 10),
                                  rocksdb::Slice());  // value is empty
                    }
                }
            }

            inst_id++;
            break;
        }
        case RecordKind::Anchor: {
            // Store anchor: keyed by the inst_id at which it appears
            // The anchor provides state for the NEXT instruction (inst_id at this point)
            char anchor_key_buf[8];
            batch.Put(idx.get_cf(cf::ANCHOR),
                     encode_u64_to(inst_id, anchor_key_buf),
                     rocksdb::Slice(reinterpret_cast<const char*>(&rec.file_offset), 8));
            idx.anchors_.push_back({inst_id, rec.file_offset});
            idx.stats_.anchor_count++;
            break;
        }
        case RecordKind::Code:
            idx.stats_.code_count++;
            break;
        case RecordKind::Event:
            idx.stats_.event_count++;
            break;
        default:
            break;
        }

        // ── Performance: flush every 100K records instead of 10K ─────────────
        // Amortizes WriteBatch overhead. For a 10M-record trace:
        //   Old: 1000 writes × WAL fsync each = ~10s overhead
        //   New: 100 writes × no WAL = ~0.1s overhead
        if (total_records % 100000 == 0) {
            auto ws = idx.db_->Write(write_opts, &batch);
            if (!ws.ok()) {
                return Error::rocksdb_error(ws.ToString());
            }
            batch.Clear();

            if (progress) {
                progress(rec.file_offset, file_size);
            }
        }
    }

    // Final flush
    if (batch.Count() > 0) {
        auto ws = idx.db_->Write(write_opts, &batch);
        if (!ws.ok()) {
            return Error::rocksdb_error(ws.ToString());
        }
    }

    idx.stats_.inst_count = inst_id;
    idx.stats_.total_records = total_records;

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
    // Persist the remaining counters so open_or_build can restore them on a
    // cache hit instead of reporting 0 for everything except inst_count.
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "total_records",
                 rocksdb::Slice(reinterpret_cast<const char*>(&total_records), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "anchor_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.anchor_count), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "code_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.code_count), 8));
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "event_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.event_count), 8));

    auto t1 = std::chrono::steady_clock::now();
    idx.stats_.build_seconds =
        std::chrono::duration<double>(t1 - t0).count();

    // Sort anchors
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
    // Find the sparse entry at or before inst_id
    uint64_t base_id = (inst_id / SPARSE_INTERVAL) * SPARSE_INTERVAL;

    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), get_cf(cf::OFFSET),
                      encode_u64(base_id), &value);
    if (!s.ok() || value.size() < 8) {
        // Fallback: start from beginning
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
                    walk_offset += sizeof(qbditrace::qbditrace_inst_head_v5_t)
                        + wp[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                        + wp[3] * sizeof(qbditrace::qbditrace_memacc_t);
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
                return {current_offset, seed};
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
            current_offset += hdr_size
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)   // 16 bytes each
                + n_mem     * sizeof(qbditrace::qbditrace_memacc_t);   // 32 bytes each
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

    return {current_offset, running_pc};
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

}  // namespace tenet

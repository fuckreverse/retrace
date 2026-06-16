#include "io/index_builder.h"

#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>

#include <chrono>
#include <algorithm>
#include <cstring>

namespace tenet {

// ─── Helpers ──────────────────────────────────────────────────────────────

namespace {

// Encode uint64 as big-endian key (for correct RocksDB sort order)
std::string encode_u64(uint64_t v) {
    std::string s(8, '\0');
    for (int i = 7; i >= 0; --i) {
        s[7 - i] = static_cast<char>((v >> (i * 8)) & 0xFF);
    }
    return s;
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
    // Order: default(0), meta(1), offset(2), anchor(3), mem_write(4)
    if (std::strcmp(name, "default") == 0) return cf_handles_[0];
    if (std::strcmp(name, cf::META) == 0)   return cf_handles_[1];
    if (std::strcmp(name, cf::OFFSET) == 0) return cf_handles_[2];
    if (std::strcmp(name, cf::ANCHOR) == 0) return cf_handles_[3];
    if (std::strcmp(name, cf::MEM_WRITE) == 0 && cf_handles_.size() > 4) return cf_handles_[4];
    return nullptr;
}

bool TraceIndex::is_valid_for(const TraceReader& reader) const {
    // Simple validation: check stored file size matches
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

        std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
            {"default", rocksdb::ColumnFamilyOptions()},
            {cf::META, rocksdb::ColumnFamilyOptions()},
            {cf::OFFSET, rocksdb::ColumnFamilyOptions()},
            {cf::ANCHOR, rocksdb::ColumnFamilyOptions()},
            {cf::MEM_WRITE, rocksdb::ColumnFamilyOptions()},
        };

        rocksdb::DB* raw_db = nullptr;
        auto s = rocksdb::DB::Open(opts, db_path.string(), cf_descs,
                                   &idx.cf_handles_, &raw_db);
        if (s.ok()) {
            idx.db_ = std::unique_ptr<rocksdb::DB>(raw_db);
            if (idx.is_valid_for(reader)) {
                // Load stats
                std::string val;
                if (idx.db_->Get(rocksdb::ReadOptions(), idx.get_cf(cf::META),
                                 "inst_count", &val).ok() && val.size() == 8) {
                    std::memcpy(&idx.stats_.inst_count, val.data(), 8);
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
    opts.write_buffer_size = 64 * 1024 * 1024;

    rocksdb::BlockBasedTableOptions table_opts;
    table_opts.block_cache = rocksdb::NewLRUCache(128 * 1024 * 1024);
    table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    table_opts.block_size = 16 * 1024;
    opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_opts));

    rocksdb::ColumnFamilyOptions mem_write_cf_opts;
    mem_write_cf_opts.compression = rocksdb::kNoCompression;
    // mem_write CF will have many small values (1 byte each), optimize block size
    rocksdb::BlockBasedTableOptions mem_table_opts;
    mem_table_opts.block_size = 4 * 1024;
    mem_write_cf_opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(mem_table_opts));

    std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
        {"default", rocksdb::ColumnFamilyOptions()},
        {cf::META, rocksdb::ColumnFamilyOptions()},
        {cf::OFFSET, rocksdb::ColumnFamilyOptions()},
        {cf::ANCHOR, rocksdb::ColumnFamilyOptions()},
        {cf::MEM_WRITE, mem_write_cf_opts},
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

    rocksdb::WriteBatch batch;
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
                batch.Put(idx.get_cf(cf::OFFSET),
                         encode_u64(inst_id),
                         rocksdb::Slice(reinterpret_cast<const char*>(&rec.file_offset), 8));
            }
            inst_id++;
            break;
        }
        case RecordKind::Anchor: {
            // Store anchor: keyed by the inst_id at which it appears
            // The anchor provides state for the NEXT instruction (inst_id at this point)
            batch.Put(idx.get_cf(cf::ANCHOR),
                     encode_u64(inst_id),
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

        // Flush batch periodically
        if (total_records % 10000 == 0) {
            auto ws = idx.db_->Write(rocksdb::WriteOptions(), &batch);
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
        auto ws = idx.db_->Write(rocksdb::WriteOptions(), &batch);
        if (!ws.ok()) {
            return Error::rocksdb_error(ws.ToString());
        }
    }

    idx.stats_.inst_count = inst_id;
    idx.stats_.total_records = total_records;

    // Write metadata
    auto* meta_cf = idx.get_cf(cf::META);
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "version", "1");
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "inst_count",
                 rocksdb::Slice(reinterpret_cast<const char*>(&inst_id), 8));
    uint64_t fsize = reader.file_size();
    idx.db_->Put(rocksdb::WriteOptions(), meta_cf, "file_size",
                 rocksdb::Slice(reinterpret_cast<const char*>(&fsize), 8));

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
    // Find the sparse entry at or before inst_id
    uint64_t base_id = (inst_id / SPARSE_INTERVAL) * SPARSE_INTERVAL;

    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), get_cf(cf::OFFSET),
                      encode_u64(base_id), &value);
    if (!s.ok() || value.size() < 8) {
        // Fallback: start from beginning
        return sizeof(qbditrace::qbditrace_file_header_t);
    }

    uint64_t offset = 0;
    std::memcpy(&offset, value.data(), 8);

    // Linear scan from base_id to inst_id
    // The stored offset points to the INST record for base_id.
    // We need to find the INST record for inst_id.
    uint64_t current_id = base_id;
    uint64_t current_offset = offset;
    const uint32_t num_gpr = reader.header().num_gpr;

    while (current_offset < reader.file_size()) {
        auto rec = reader.record_at(current_offset);
        if (rec.kind == RecordKind::Inst) {
            if (current_id == inst_id) {
                return current_offset;  // Found the target INST
            }
            current_id++;
        }
        current_offset += rec.byte_size(num_gpr);
    }

    return current_offset;
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

}  // namespace tenet

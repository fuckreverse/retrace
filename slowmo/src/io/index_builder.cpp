#include "common/platform_file.h"
#include "common/compiler_compat.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "common/logger.h"
#include "common/Profiling.h"

#if defined(TENET_HAS_TBB) && TENET_HAS_TBB
#include <tbb/parallel_sort.h>
#endif

#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>
#include <rocksdb/slice_transform.h>
#include <rocksdb/sst_file_writer.h>

#if defined(TENET_HAS_ZSTD) && TENET_HAS_ZSTD
#include <zstd.h>
#endif

#include <chrono>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <thread>
#include <vector>
#include <mutex>
#include <numeric>
#include <sstream>
#include <unordered_map>

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
// v8: All index CFs now use LZ4 compression; REG_WRITES CF gains a prefix
//     extractor (FixedPrefix(2)) + bloom filter; CompactRange after build.
//     Old uncompressed caches are invalidated to rebuild with new settings.
// v9: Added PASS_CACHE CF for large pass result blobs (previously stored in
//     META CF).  On macOS, pread(2) rejects requests > 2 GB (EINVAL); with
//     large traces, META+blobs exceeded 2 GB in a single SST file, making
//     DB::Open fail and causing perpetual cache misses.  Keeping blobs in a
//     dedicated CF with 512 MB target_file_size_base keeps each SST small.
//     meta_batch.Write() now uses sync=true to survive OOM-kills.
// v10: PASS_CACHE CF removed entirely.  Pass result blobs are now stored as
//      plain files under <index_dir>/pass_cache/<name>.bin rather than
//      inside RocksDB.  Pass blobs are opaque byte arrays with no need for
//      DB key lookup, iteration, or transactions.  Plain files avoid the
//      2 GB macOS pread SST limit, allow zero-copy reads, and eliminate
//      compaction overhead.  The pass_cache/ directory is wiped together
//      with the index when DestroyDB removes the .tenet directory.
// v11: Added v7 (HF_HAS_FPR) support to index builder.  Previous versions
//      miscalculated INST/ANCHOR record sizes for v7 traces, causing the
//      record walk to desynchronize and produce non-monotonic keys for
//      SstFileWriter — resulting in "Keys must be added in strict ascending
//      order" errors.  Caches built with schema ≤v10 for v7 traces are invalid.
// v12: OFFSET CF values expanded from 8 bytes (file_offset only) to 16 bytes
//      (file_offset + seed_pc).  For v5 traces this eliminates the ANCHOR
//      walk in offset_of_with_pc() — the seed_pc is read directly from the
//      sparse index instead of being reconstructed by linear-scanning pc_delta
//      from the nearest anchor.  Caches built with schema ≤v11 are invalid.
static constexpr uint32_t INDEX_SCHEMA_VERSION = 13;

// ─── Helpers ──────────────────────────────────────────────────────────────

namespace {

// Encode uint64 as big-endian key (for correct RocksDB sort order).
// Returns a Slice pointing to the caller-provided 8-byte buffer.
// *** Zero heap allocation — critical for millions of calls during index build. ***
inline rocksdb::Slice encode_u64_to(uint64_t v, char buf[8]) {
    // Native byte swap on each supported compiler (REV on ARM64).
    uint64_t be = tenet::platform::byte_swap64(v);
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
    return TraceIndex::index_dir_for(reader);
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

/// Copy `len` bytes starting at file offset `offset` into `out` (block mode).
///
/// `TraceReader::data_at()` only guarantees `kOverlapBytes` (32 KB, see
/// block_cache_reader.h) contiguous bytes past the returned pointer, even
/// when the read straddles a block boundary — decompressed block sizes are
/// NOT guaranteed to be a fixed 1 MB (the last block in particular is
/// usually smaller). Requesting more than that in one data_at() + memcpy
/// reads past the end of the block's heap-allocated buffer (SIGBUS/SIGSEGV
/// depending on what's mapped there). This helper honors the contract by
/// copying in bounded chunks and re-resolving the pointer via data_at() for
/// every chunk, regardless of `len`.
static void copy_block_mode(const TraceReader& reader, uint64_t offset,
                             size_t len, uint8_t* out) {
    // Stay comfortably under kOverlapBytes (32 KB) to leave headroom.
    constexpr size_t kChunk = 16 * 1024;
    size_t done = 0;
    while (done < len) {
        size_t n = std::min(kChunk, len - done);
        const uint8_t* p = reader.data_at(offset + done);
        std::memcpy(out + done, p, n);
        done += n;
    }
}

/// Hash only a representative sample of the trace file (first 1MB + last 1MB).
/// For large traces this is much faster than full hash while still detecting
/// truncation, corruption at head/tail, and file swaps.
static uint64_t sample_trace_hash(const TraceReader& reader) {
    constexpr size_t SAMPLE = 1024 * 1024;  // 1MB per end
    const uint64_t size = reader.file_size();
    if (reader.is_block_mode()) {
        // Block-compressed: cannot get a single contiguous pointer spanning
        // a full 1 MB sample (data_at() only guarantees kOverlapBytes=32KB
        // past any given offset — see copy_block_mode() above). Copy each
        // sample into a local buffer in bounded chunks, then hash that.
        reader.pin_all();
        // data_at() takes a file offset (0 = start of file). In block mode
        // it subtracts header_size_ before passing to the block cache, so
        // we must pass header_size() (536) to get the first record byte.
        // Passing 0 would underflow: 0 - 536 = 0xFFFFFFFFFFFFFDE8.
        uint64_t actual_head = std::min(static_cast<uint64_t>(SAMPLE), size);
        std::vector<uint8_t> head_buf(static_cast<size_t>(actual_head));
        copy_block_mode(reader, reader.header_size(), head_buf.size(), head_buf.data());
        uint64_t h1 = xxhash64(head_buf.data(), head_buf.size());
        uint64_t h2 = 0;
        if (size > SAMPLE) {
            std::vector<uint8_t> tail_buf(SAMPLE);
            copy_block_mode(reader, size - SAMPLE, tail_buf.size(), tail_buf.data());
            h2 = xxhash64(tail_buf.data(), tail_buf.size());
        }
        reader.unpin_all();
        return h1 ^ (h2 * XXH_PRIME64_2) ^ (size * XXH_PRIME64_3);
    }
    // mmap mode: contiguous access
    const uint8_t* data = reader.data();
    if (size <= SAMPLE * 2) {
        return xxhash64(data, static_cast<size_t>(size));
    }
    uint64_t h1 = xxhash64(data, SAMPLE);
    uint64_t h2 = xxhash64(data + size - SAMPLE, SAMPLE);
    uint64_t combined = h1 ^ (h2 * XXH_PRIME64_2) ^ (size * XXH_PRIME64_3);
    return combined;
}

}  // anonymous namespace

// ─── TraceIndex lifecycle ─────────────────────────────────────────────────

std::filesystem::path TraceIndex::index_dir_for(const TraceReader& reader) {
    auto trace_dir = reader.path().parent_path();
    auto trace_name = reader.path().stem().string();
    // P2: use <name>.tenet/ as the index directory name.
    // This matches macOS package conventions (Finder shows it as a single unit)
    // and makes it obvious which trace the cache belongs to.
    return trace_dir / (trace_name + ".tenet");
}

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
      anchor_threads_(std::move(other.anchor_threads_)),
      anchors_have_threads_(other.anchors_have_threads_),
      thread_chunks_(std::move(other.thread_chunks_)),
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
        anchor_threads_ = std::move(other.anchor_threads_);
        anchors_have_threads_ = other.anchors_have_threads_;
        thread_chunks_ = std::move(other.thread_chunks_);
        sparse_interval_ = other.sparse_interval_;
        other.cf_handles_.clear();
    }
    return *this;
}

rocksdb::ColumnFamilyHandle* TraceIndex::get_cf(const char* name) const {
    // Order: default(0), meta(1), offset(2), anchor(3), mem_write(4), mem_read(5),
    //        reg_writes(6), code_bytes(7)
    if (std::strcmp(name, "default") == 0)       return cf_handles_[0];
    if (std::strcmp(name, cf::META) == 0)        return cf_handles_[1];
    if (std::strcmp(name, cf::OFFSET) == 0)      return cf_handles_[2];
    if (std::strcmp(name, cf::ANCHOR) == 0)      return cf_handles_[3];
    if (std::strcmp(name, cf::MEM_WRITE) == 0    && cf_handles_.size() > 4) return cf_handles_[4];
    if (std::strcmp(name, cf::MEM_READ) == 0     && cf_handles_.size() > 5) return cf_handles_[5];
    if (std::strcmp(name, cf::REG_WRITES) == 0   && cf_handles_.size() > 6) return cf_handles_[6];
    if (std::strcmp(name, cf::CODE_BYTES) == 0   && cf_handles_.size() > 7) return cf_handles_[7];
    return nullptr;
}

bool TraceIndex::is_valid_for(const TraceReader& reader) const {
    // Check schema version: if the index was built by a different version of
    // the code (different struct sizes, different CF layout), it's invalid.
    std::string schema_val;
    auto sv = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                       "schema_version", &schema_val);
    if (!sv.ok() || schema_val.size() < 4) {
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: missing schema_version key ({})",
                 sv.ok() ? "too short" : sv.ToString());
        return false;
    }
    uint32_t stored_schema = 0;
    std::memcpy(&stored_schema, schema_val.data(), 4);
    if (stored_schema != INDEX_SCHEMA_VERSION) {
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: schema version mismatch "
                 "(stored={}, current={}) — rebuilding",
                 stored_schema, INDEX_SCHEMA_VERSION);
        return false;
    }

    // Check stored file size matches
    std::string value;
    auto s = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                      "file_size", &value);
    if (!s.ok()) {
        // Dump all keys in META CF to diagnose what's actually present
        std::string meta_keys_str;
        if (auto* meta_cf = get_cf(cf::META)) {
            std::unique_ptr<rocksdb::Iterator> it(
                db_->NewIterator(rocksdb::ReadOptions(), meta_cf));
            for (it->SeekToFirst(); it->Valid(); it->Next()) {
                auto k = it->key().ToString();
                // Truncate long values (pass blobs can be hundreds of MB)
                if (k.size() < 32) {
                    if (!meta_keys_str.empty()) meta_keys_str += ", ";
                    meta_keys_str += k;
                }
            }
        }
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: missing file_size key — rebuilding "
                 "(status={}, meta_cf={}, keys_in_meta=[{}])",
                 s.ToString(), static_cast<void*>(get_cf(cf::META)), meta_keys_str);
        return false;
    }
    uint64_t stored_size = 0;
    std::memcpy(&stored_size, value.data(), std::min(value.size(), size_t(8)));
    if (stored_size != reader.file_size()) {
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: file size mismatch "
                 "(stored={}, current={}) — rebuilding",
                 stored_size, reader.file_size());
        return false;
    }

    // Check trace hash (schema v7+): detects file swaps and content corruption.
    // Old caches (schema < v7) lack this key; they're already invalidated by the
    // schema version check above, so we don't need a fallback here.
    std::string hash_val;
    auto hs = db_->Get(rocksdb::ReadOptions(), get_cf(cf::META),
                       "trace_hash", &hash_val);
    if (!hs.ok() || hash_val.size() < 8) {
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: missing trace_hash key — rebuilding");
        return false;
    }
    uint64_t stored_hash = 0;
    std::memcpy(&stored_hash, hash_val.data(), 8);
    uint64_t current_hash = sample_trace_hash(reader);
    if (stored_hash != current_hash) {
        LOG_WARN_M(::tenet::log::Module::Io, "Index cache invalid: trace content hash mismatch "
                 "(stored={:#018x}, current={:#018x}) — rebuilding",
                 stored_hash, current_hash);
        return false;
    }
    return true;
}

// ─── Open or build ────────────────────────────────────────────────────────

Result<TraceIndex> TraceIndex::open_or_build(
    const TraceReader& reader, ProgressCallback progress) {
    TENET_ZONE_NAMED("TraceIndex::open_or_build");

    auto db_path = index_path_for(reader);

    // Try to open existing DB
    if (std::filesystem::exists(db_path)) {
        TraceIndex idx;
        idx.db_path_ = db_path;

        rocksdb::Options opts;
        opts.create_if_missing = false;
        opts.max_open_files = -1;  // match build-time setting (see build path)

        // MEM_WRITE/MEM_READ CF options must match build-time settings
        // (prefix extractor, block cache, bloom filter) for correct operation.
        // Share a single 512MB block cache between both CFs to avoid doubling
        // memory usage and improve cross-CF cache hit rate.
        auto mem_block_cache = rocksdb::NewLRUCache(512 * 1024 * 1024);
        auto make_mem_cf_opts = [&mem_block_cache]() {
            rocksdb::ColumnFamilyOptions o;
            o.compression = rocksdb::kLZ4Compression;
            o.prefix_extractor = std::shared_ptr<const rocksdb::SliceTransform>(
                rocksdb::NewFixedPrefixTransform(8));  // page(8) only
            rocksdb::BlockBasedTableOptions tbl;
            tbl.block_size = 4 * 1024;
            tbl.block_cache = mem_block_cache;  // shared between MEM_WRITE & MEM_READ
            tbl.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
            tbl.whole_key_filtering = false;
            o.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tbl));
            return o;
        };

        // OFFSET/ANCHOR/CODE_BYTES: match build-time settings (LZ4, 16KB block)
        // for consistent read performance.
        auto make_index_cf_opts = [&mem_block_cache]() {
            rocksdb::ColumnFamilyOptions o;
            o.compression = rocksdb::kLZ4Compression;
            rocksdb::BlockBasedTableOptions tbl;
            tbl.block_size = 16 * 1024;
            tbl.block_cache = mem_block_cache;  // share cache with MEM CFs
            tbl.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
            o.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tbl));
            return o;
        };

        // REG_WRITES: prefix extractor (2 bytes = 0x00 + reg_idx) + bloom filter
        // to accelerate SeekForPrev per-register lookups.
        auto make_reg_writes_cf_opts = [&mem_block_cache]() {
            rocksdb::ColumnFamilyOptions o;
            o.compression = rocksdb::kNoCompression;
            o.prefix_extractor = std::shared_ptr<const rocksdb::SliceTransform>(
                rocksdb::NewFixedPrefixTransform(2));  // 0x00 + reg_idx
            rocksdb::BlockBasedTableOptions tbl;
            tbl.block_size = 32 * 1024;
            tbl.block_cache = mem_block_cache;
            tbl.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
            tbl.whole_key_filtering = false;
            o.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tbl));
            return o;
        };

        // META CF: small key-value metadata only (no blobs). Keep target SST
        // size <= 128 MB so we never hit macOS pread's 2 GB EINVAL limit.
        rocksdb::ColumnFamilyOptions meta_cf_opts;
        meta_cf_opts.compression = rocksdb::kLZ4Compression;
        meta_cf_opts.target_file_size_base = 128 * 1024 * 1024;  // 128 MB

        std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
            {"default", rocksdb::ColumnFamilyOptions()},
            {cf::META,       meta_cf_opts},
            {cf::OFFSET,     make_index_cf_opts()},
            {cf::ANCHOR,     make_index_cf_opts()},
            {cf::MEM_WRITE,  make_mem_cf_opts()},
            {cf::MEM_READ,   make_mem_cf_opts()},
            {cf::REG_WRITES, make_reg_writes_cf_opts()},
            {cf::CODE_BYTES, make_index_cf_opts()},
        };

        // Helper: close db + cf handles, then wipe the DB directory.
        // Uses rocksdb::DestroyDB (not remove_all) so RocksDB removes its own
        // lock files and WAL in the correct order, preventing stale LOCK files
        // that would make the next DB::Open fail with "Resource unavailable".
        // Falls back to filesystem::remove_all if DestroyDB itself fails.
        //
        // keep_pass_cache: when true, the pass_cache/ subdirectory is moved
        // out before DestroyDB and moved back afterwards.  Use this when only
        // the index schema changed but the trace content is unchanged — in that
        // case pass results are still valid and should not be recomputed.
        auto destroy_and_wipe = [&](rocksdb::DB* rdb, bool keep_pass_cache) {
            // 0. Optionally rescue pass_cache/ before wiping the DB dir.
            auto pc_dir    = db_path / "pass_cache";
            auto pc_tmp    = db_path.parent_path() / (db_path.filename().string() + ".pc_tmp");
            bool pc_saved  = false;
            if (keep_pass_cache) {
                std::error_code ec;
                if (std::filesystem::exists(pc_dir, ec) && !ec) {
                    std::filesystem::rename(pc_dir, pc_tmp, ec);
                    if (!ec) {
                        pc_saved = true;
                    } else {
                        LOG_WARN_M(::tenet::log::Module::Io, "destroy_and_wipe: could not move pass_cache aside ({})"
                                 " — pass results will be recomputed", ec.message());
                    }
                }
            }

            // 1. Destroy CF handles and close DB first.
            for (auto* h : idx.cf_handles_) {
                if (h && rdb) rdb->DestroyColumnFamilyHandle(h);
            }
            idx.cf_handles_.clear();
            idx.db_.reset();  // calls delete rdb

            // 2. DestroyDB removes SSTs, WAL, MANIFEST, LOCK cleanly.
            rocksdb::Options destroy_opts;
            auto ds = rocksdb::DestroyDB(db_path.string(), destroy_opts);
            if (!ds.ok()) {
                LOG_WARN_M(::tenet::log::Module::Io, "DestroyDB '{}' failed ({}), falling back to remove_all",
                         db_path.string(), ds.ToString());
                std::error_code ec;
                std::filesystem::remove_all(db_path, ec);
                if (ec) {
                    LOG_WARN_M(::tenet::log::Module::Io, "remove_all '{}' also failed: {} — build will overwrite in-place",
                             db_path.string(), ec.message());
                }
            }

            // 3. Restore pass_cache/ into the (now empty / recreatable) db_path.
            if (pc_saved) {
                std::error_code ec;
                std::filesystem::create_directories(db_path, ec);  // re-create dir if gone
                std::filesystem::rename(pc_tmp, pc_dir, ec);
                if (ec) {
                    LOG_WARN_M(::tenet::log::Module::Io, "destroy_and_wipe: could not restore pass_cache ({})"
                             " — pass results will be recomputed", ec.message());
                    std::filesystem::remove_all(pc_tmp, ec);
                } else {
                    LOG_INFO_M(::tenet::log::Module::Io, "Pass cache preserved across index rebuild ({} entries)",
                             [&]() -> size_t {
                                 std::error_code e2;
                                 size_t n = 0;
                                 for (auto& ent : std::filesystem::directory_iterator(pc_dir, e2))
                                     if (ent.path().extension() == ".bin") n++;
                                 return n;
                             }());
                }
            }
        };

        rocksdb::DB* raw_db = nullptr;
        auto s = rocksdb::DB::Open(opts, db_path.string(), cf_descs,
                                   &idx.cf_handles_, &raw_db);
        if (!s.ok()) {
            // Open failed (e.g. corrupt SST, schema mismatch, missing CF).
            // raw_db may be null, but cf_handles_ may have been partially
            // populated by RocksDB — clean up whatever was allocated.
            LOG_WARN_M(::tenet::log::Module::Io, "Failed to open index cache '{}': {} — will rebuild",
                     db_path.string(), s.ToString());
            // DestroyColumnFamilyHandle requires a valid DB pointer; if raw_db
            // is null we just clear the handles (they are already invalid).
            if (raw_db) {
                for (auto* h : idx.cf_handles_) {
                    if (h) raw_db->DestroyColumnFamilyHandle(h);
                }
                delete raw_db;
            }
            idx.cf_handles_.clear();
            // Wipe the broken RocksDB directory so build() starts clean.
            // pass_cache/ is a plain-file directory independent of RocksDB;
            // we cannot verify its validity without opening the DB, so leave
            // it in place — build() will overwrite individual blobs as passes
            // run, and stale blobs for passes that don't re-run are harmless
            // (they'll be reused on the next open after trace hash is stored).
            {
                // Move pass_cache/ aside before DestroyDB/remove_all.
                std::error_code ec;
                auto pc_dir = db_path / "pass_cache";
                auto pc_tmp = db_path.parent_path()
                              / (db_path.filename().string() + ".pc_tmp");
                bool pc_saved = false;
                if (std::filesystem::exists(pc_dir, ec) && !ec) {
                    std::filesystem::rename(pc_dir, pc_tmp, ec);
                    pc_saved = !ec;
                }

                rocksdb::Options destroy_opts;
                auto ds = rocksdb::DestroyDB(db_path.string(), destroy_opts);
                if (!ds.ok()) {
                    std::filesystem::remove_all(db_path, ec);
                }

                if (pc_saved) {
                    std::filesystem::create_directories(db_path, ec);
                    std::filesystem::rename(pc_tmp, pc_dir, ec);
                    if (ec) std::filesystem::remove_all(pc_tmp, ec);
                }
            }
        } else {
            idx.db_ = std::unique_ptr<rocksdb::DB>(raw_db);
            LOG_INFO_M(::tenet::log::Module::Io, "Index cache found at '{}', validating...", db_path.string());
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
                    // v13: 16-byte value = (file_offset, thread_id).
                    // Defensive: a legacy 8-byte value (shouldn't survive the
                    // schema bump, but just in case) decodes as thread 0.
                    std::memcpy(&entry.file_offset, it->value().data(),
                               std::min(it->value().size(), size_t(8)));
                    idx.anchors_.push_back(entry);
                    uint64_t tid = 0;
                    if (it->value().size() >= 16) {
                        std::memcpy(&tid, it->value().data() + 8, 8);
                        idx.anchors_have_threads_ = true;
                    }
                    idx.anchor_threads_.push_back(tid);
                }
                std::sort(idx.anchors_.begin(), idx.anchors_.end(),
                          [](const auto& a, const auto& b) {
                              return a.inst_id < b.inst_id;
                          });
                // anchor_threads_ was collected in (anchor-key → inst_id) order,
                // which is already ascending by inst_id; the anchors_ sort above
                // is a no-op safety net for the same ordering.
                // Derive anchor_count from the loaded vector so the stat is
                // always consistent with the in-memory table (and the display
                // shows the real count instead of 0 when loading from cache).
                idx.stats_.anchor_count = idx.anchors_.size();

                // Load thread chunk table (multi-thread traces).
                {
                    std::string tc_val;
                    if (idx.db_->Get(rocksdb::ReadOptions(), meta_cf,
                                     "thread_chunks", &tc_val).ok() &&
                        tc_val.size() % 16 == 0) {
                        const size_t n = tc_val.size() / 16;
                        idx.thread_chunks_.resize(n);
                        std::memcpy(idx.thread_chunks_.data(), tc_val.data(), tc_val.size());
                    }
                }

                LOG_INFO_M(::tenet::log::Module::Io, "Index cache hit: {} instructions, {} anchors",
                         idx.stats_.inst_count, idx.stats_.anchor_count);
                return idx;
            }
            // Valid open but stale schema/hash — destroy and rebuild.
            // Before wiping, check whether the trace CONTENT is still the
            // same (file_size + trace_hash).  If so, pass results remain valid
            // even though the index schema changed; we can preserve pass_cache/.
            bool trace_content_unchanged = false;
            {
                auto* meta_cf = idx.get_cf(cf::META);
                if (meta_cf) {
                    std::string fsz_val, hash_val;
                    bool have_fsz  = idx.db_->Get(rocksdb::ReadOptions(), meta_cf,
                                                   "file_size",  &fsz_val).ok()
                                     && fsz_val.size() == 8;
                    bool have_hash = idx.db_->Get(rocksdb::ReadOptions(), meta_cf,
                                                   "trace_hash", &hash_val).ok()
                                     && hash_val.size() == 8;
                    if (have_fsz && have_hash) {
                        uint64_t stored_fsz = 0, stored_hash = 0;
                        std::memcpy(&stored_fsz,  fsz_val.data(),  8);
                        std::memcpy(&stored_hash, hash_val.data(), 8);
                        uint64_t cur_hash = sample_trace_hash(reader);
                        trace_content_unchanged = (stored_fsz  == reader.file_size())
                                               && (stored_hash == cur_hash);
                    }
                }
            }
            LOG_INFO_M(::tenet::log::Module::Io, "Removing stale index cache at '{}' (pass_cache: {})",
                     db_path.string(),
                     trace_content_unchanged ? "preserved" : "invalidated");
            destroy_and_wipe(raw_db, /*keep_pass_cache=*/trace_content_unchanged);
        }
    } else {
        LOG_INFO_M(::tenet::log::Module::Io, "No index cache found for '{}', building from scratch...",
                 reader.path().filename().string());
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
    TENET_ZONE_NAMED("TraceIndex::build");

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
    // so the initial write doesn't stall.  After ingest we CompactRange() on
    // CFs used for point lookups (OFFSET, REG_WRITES, CODE_BYTES).
    opts.disable_auto_compactions = true;
    opts.level0_file_num_compaction_trigger = 1024;
    opts.level0_slowdown_writes_trigger = 1024;
    opts.level0_stop_writes_trigger = 1024;
    opts.max_write_buffer_number = 4;
    // Allow RocksDB to open as many SST files as needed during bulk ingest
    // and compaction.  The process raises RLIMIT_NOFILE to 65536 at startup
    // (see main.cpp), so -1 is safe.  A fixed limit like 1024 caused EMFILE
    // during CompactRange on large traces with thousands of L0 SSTs.
    opts.max_open_files = -1;

    rocksdb::BlockBasedTableOptions table_opts;
    table_opts.block_cache = rocksdb::NewLRUCache(128 * 1024 * 1024);
    table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    table_opts.block_size = 16 * 1024;
    opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_opts));

    // MEM_WRITE / MEM_READ share a single 128 MB block cache during build.
    // Previously each had its own 512 MB cache (1 GB total), causing OOM on
    // large traces where the build already consumes GBs of address space for
    // mmap + WriteBatches.  During build we don't do read-heavy MEM queries,
    // so a small shared cache is sufficient.
    auto mem_build_block_cache = rocksdb::NewLRUCache(128 * 1024 * 1024);
    rocksdb::ColumnFamilyOptions mem_write_cf_opts;
    mem_write_cf_opts.compression = rocksdb::kLZ4Compression;
    mem_write_cf_opts.prefix_extractor =
        std::shared_ptr<const rocksdb::SliceTransform>(
            rocksdb::NewFixedPrefixTransform(8));  // page(8) only — optimal for SeekForPrev
    rocksdb::BlockBasedTableOptions mem_table_opts;
    mem_table_opts.block_size = 4 * 1024;
    mem_table_opts.block_cache = mem_build_block_cache;  // shared — avoid OOM
    mem_table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    mem_table_opts.whole_key_filtering = false;
    mem_write_cf_opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(mem_table_opts));

    rocksdb::ColumnFamilyOptions reg_writes_cf_opts;
    reg_writes_cf_opts.compression = rocksdb::kNoCompression;
    reg_writes_cf_opts.prefix_extractor = std::shared_ptr<const rocksdb::SliceTransform>(
        rocksdb::NewFixedPrefixTransform(2));  // key prefix = 0x00 + reg_idx
    rocksdb::BlockBasedTableOptions reg_writes_table_opts;
    reg_writes_table_opts.block_size = 32 * 1024;
    reg_writes_table_opts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
    reg_writes_table_opts.whole_key_filtering = false;
    reg_writes_cf_opts.table_factory.reset(
        rocksdb::NewBlockBasedTableFactory(reg_writes_table_opts));

    // OFFSET/ANCHOR/CODE_BYTES: LZ4 compression + 16KB blocks (matches default table_opts)
    rocksdb::ColumnFamilyOptions index_cf_opts;
    index_cf_opts.compression = rocksdb::kLZ4Compression;
    {
        rocksdb::BlockBasedTableOptions tbl;
        tbl.block_size = 16 * 1024;
        tbl.block_cache = table_opts.block_cache;  // share build-time cache
        tbl.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
        index_cf_opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tbl));
    }

    // META CF: small metadata keys only. 128 MB SST ceiling keeps DB::Open
    // working even after many write cycles (avoids macOS pread 2 GB limit).
    rocksdb::ColumnFamilyOptions meta_cf_opts;
    meta_cf_opts.compression = rocksdb::kLZ4Compression;
    meta_cf_opts.target_file_size_base = 128 * 1024 * 1024;  // 128 MB

    std::vector<rocksdb::ColumnFamilyDescriptor> cf_descs = {
        {"default", rocksdb::ColumnFamilyOptions()},
        {cf::META,       meta_cf_opts},
        {cf::OFFSET,     index_cf_opts},
        {cf::ANCHOR,     index_cf_opts},
        {cf::MEM_WRITE,  mem_write_cf_opts},
        {cf::MEM_READ,   mem_write_cf_opts},
        {cf::REG_WRITES, reg_writes_cf_opts},
        {cf::CODE_BYTES, index_cf_opts},
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

    const uint64_t file_size   = reader.file_size();
    const uint32_t num_gpr     = reader.header().num_gpr;
    const bool     is_v5       = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA)  != 0;
    const bool     is_v6       = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    const bool     is_v7       = (reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR)  != 0;
const bool     is_v8       = (reader.header().flags & qbditrace::QBDITRACE_HF_WIDE_API_ID) != 0;

    // P1.7: correct memacc struct size depending on format version
    const size_t memacc_sz = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)   // 48 bytes
        : sizeof(qbditrace::qbditrace_memacc_t);      // 32 bytes
    // v7 headers are larger: v7+v5 = 8 bytes, v7 = 24 bytes
    const size_t inst_hdr_sz = inst_header_size(is_v5, is_v7);
    // v7: n_fprdiff byte offset within the INST header
    const size_t fprdiff_off = fprdiff_byte_offset(is_v5, is_v7);

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
        uint64_t thread_id_start = 0;  // owning thread at file_start (v13)
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
        // Thread attribution for each raw anchor (parallel vector).
        // THREAD records encountered during the scan reassign cur_thread;
        // every anchor stamped after that belongs to it.
        std::vector<uint64_t> raw_anchor_threads;
        uint64_t cur_thread = 0;
        bool saw_thread_record = false;
        // Thread chunk table: (first inst_id of chunk, thread_id), ascending.
        // One entry per THREAD marker; persisted in the META CF.
        std::vector<std::pair<uint64_t, uint64_t>> raw_thread_chunks;

        uint64_t scan_id = 0;
        const uint64_t hdr_sz = sizeof(qbditrace::qbditrace_file_header_t);
        const size_t anchor_fpr_sz = is_v7 ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
        const size_t anchor_rec_sz = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + anchor_fpr_sz;

        // Progress reporting for Phase 0 (anchor discovery).
        // For large traces (especially block-compressed), this scan can take
        // minutes. Report progress to stderr so the user doesn't think it's hung.
        auto phase0_start = std::chrono::steady_clock::now();
        uint64_t phase0_last_report = 0;

        // ── Scan lambda: processes a contiguous buffer of records ──
        // `buf_ptr` points to the first byte of the buffer.
        // `scan_limit` is the number of bytes in which new records may START.
        //   Typically this is the block's own data size (blk_size).
        // `buf_total` is the total readable bytes (including any overlap from
        //   the next block).  A record that starts within scan_limit may
        //   extend into the overlap zone — that's fine; we use buf_total
        //   for the `remaining` check so cross-boundary records are read
        //   correctly.  But we never START a new record in the overlap zone,
        //   preventing zero-padded overlap from being parsed as records.
        // `base_file_offset` is the absolute file offset of `buf_ptr[0]`.
        // Returns the number of bytes consumed (may be < scan_limit if the
        // last record straddles the buffer boundary).
        auto scan_buffer = [&](const uint8_t* buf_ptr, uint32_t scan_limit,
                               uint32_t buf_total,
                               uint64_t base_file_offset) -> uint32_t {
            uint32_t pos = 0;
            while (pos < scan_limit) {
                const uint8_t* ptr = buf_ptr + pos;
                // Need at least 1 byte for the record kind, but also enough
                // to read the inst header fields (n_regdiff, n_mem at ptr[2]/[3]).
                // The minimum INST header is 6 bytes (v5). Be conservative:
                // if remaining < inst_hdr_sz, we might be at a boundary.
                uint32_t remaining = buf_total - pos;
                if (remaining < 4) break;  // can't even read kind + counts safely

                auto kind = static_cast<RecordKind>(ptr[0]);
                size_t rec_size = 0;
                switch (kind) {
                case RecordKind::Inst: {
                    if (remaining < inst_hdr_sz) return pos;  // partial record
                    uint8_t n_fprdiff_val = is_v7 ? ptr[fprdiff_off] : 0;
                    rec_size = inst_hdr_sz
                        + ptr[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                        + n_fprdiff_val * sizeof(qbditrace::qbditrace_fprdiff_t)
                        + ptr[3] * memacc_sz;
                    if (remaining < rec_size) return pos;  // partial record
                    scan_id++;
                    break;
                }
                case RecordKind::Anchor: {
                    if (remaining < anchor_rec_sz) return pos;
                    rec_size = anchor_rec_sz;
                    const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                    raw_anchors.push_back({scan_id, base_file_offset + pos, ah->pc});
                    raw_anchor_threads.push_back(cur_thread);
                    break;
                }
                case RecordKind::Thread: {
                    rec_size = sizeof(qbditrace::qbditrace_thread_head_t);
                    const auto* th = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(ptr);
                    cur_thread = th->thread_id;
                    saw_thread_record = true;
                    raw_thread_chunks.push_back({scan_id, cur_thread});
                    break;
                }
                case RecordKind::Event:  rec_size = sizeof(qbditrace::qbditrace_event_head_t);  break;
                case RecordKind::Svc:    rec_size = sizeof(qbditrace::qbditrace_svc_head_t);    break;
                case RecordKind::Objc:   rec_size = raw_record_size(ptr, reader.header()); break;
                case RecordKind::CapiCall: {
                    if (is_v8) {
                        const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr);
                        rec_size = sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                        const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                        for (uint8_t s = 0; s < cc->str_count; ++s) {
                            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                            uint16_t data_bytes = sh->str_len + 1;
                            uint16_t padded = (data_bytes + 3u) & ~3u;
                            rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                            sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        }
                    } else {
                        const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr);
                        rec_size = sizeof(qbditrace::qbditrace_capicall_head_t);
                        const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_t);
                        for (uint8_t s = 0; s < cc->str_count; ++s) {
                            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                            uint16_t data_bytes = sh->str_len + 1;
                            uint16_t padded = (data_bytes + 3u) & ~3u;
                            rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                            sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        }
                    }
                    break;
                }
                case RecordKind::Code: {
                    rec_size = sizeof(qbditrace::qbditrace_code_head_t) + ptr[1];
                    break;
                }
                case RecordKind::Retval:
                    rec_size = raw_record_size(ptr, reader.header());
                    break;
                case RecordKind::MemImg:
                    if (remaining < sizeof(qbditrace::qbditrace_memimg_t)) return pos;
                    rec_size = raw_record_size(ptr, reader.header());
                    break;
                default: rec_size = 1; break;
                }
                if (rec_size == 0) return pos;  // corrupt record guard
                if (remaining < rec_size) return pos;  // partial record at tail
                pos += static_cast<uint32_t>(rec_size);
            }
            return pos;
        };

        if (reader.is_block_mode()) {
            // ── Block-compressed fast path ──
            // Decompress one block at a time into a local buffer, then scan
            // records using plain pointer arithmetic — no mutex, no LRU, no
            // binary search.  This is ~200-500x faster than per-record data_at().
            //
            // Records can straddle block boundaries (the writer doesn't align
            // records to blocks).  decompress_block() provides an overlap zone
            // (kOverlapBytes from the next block) appended to each block's
            // buffer, so cross-boundary records can be read safely.
            //
            // We track `logical_pos` — the logical offset (after header) of
            // the next unprocessed record.  For each block, we start scanning
            // at `logical_pos - blk_logical_offset` within the buffer, which
            // handles the case where a previous block's overlap already
            // consumed bytes from this block.
            const uint32_t n_blocks = reader.block_count();
            std::vector<uint8_t> block_buf;
            uint64_t logical_pos = 0;  // next unprocessed logical offset

            for (uint32_t bi = 0; bi < n_blocks; bi++) {
                const uint8_t* blk_data = nullptr;
                uint32_t blk_size = 0;
                uint64_t blk_logical_offset = 0;
                if (!reader.decompress_block(bi, block_buf, blk_data,
                                              blk_size, blk_logical_offset))
                    break;

                // Skip this block if we've already scanned past it via overlap.
                if (logical_pos >= blk_logical_offset + blk_size) continue;

                // Start position within this block's buffer.
                uint32_t pos = 0;
                if (logical_pos > blk_logical_offset)
                    pos = static_cast<uint32_t>(logical_pos - blk_logical_offset);

                // scan_limit = bytes within this block's own data where new
                // records can start.  buf_total = readable bytes including
                // any overlap from the next block (for cross-boundary reads).
                uint32_t scan_limit = blk_size - pos;
                uint32_t buf_total  = static_cast<uint32_t>(block_buf.size()) - pos;
                uint64_t base_file_offset = blk_logical_offset + hdr_sz;
                uint32_t consumed = scan_buffer(blk_data + pos, scan_limit,
                                                buf_total,
                                                base_file_offset + pos);
                logical_pos = blk_logical_offset + pos + consumed;

                // Report Phase 0 progress every ~500 MB.
                constexpr uint64_t kReportInterval = 500ULL * 1024 * 1024;
                if (logical_pos - phase0_last_report >= kReportInterval) {
                    phase0_last_report = logical_pos;
                    auto now = std::chrono::steady_clock::now();
                    double elapsed = std::chrono::duration<double>(now - phase0_start).count();
                    double pct = 100.0 * logical_pos / (file_size - hdr_sz);
                    double speed_mb = (logical_pos / (1024.0 * 1024.0)) / elapsed;
                    double eta_s = (elapsed / logical_pos) * ((file_size - hdr_sz) - logical_pos);
                    std::fprintf(stderr,
                        "\r  Phase 0: scanning anchors  %.1f%%  "
                        "(%.0f MB/s, ETA %.0fs, %zu anchors, %llu insts)   ",
                        pct, speed_mb, eta_s,
                        raw_anchors.size(), (unsigned long long)scan_id);
                    std::fflush(stderr);
                }
            }
        } else {
            // ── mmap (uncompressed) path — original per-record data_at() ──
            uint64_t scan_offset = hdr_sz;
            reader.pin_all();
            while (scan_offset < file_size) {
                const uint8_t* ptr = reader.data_at(scan_offset);
                auto kind = static_cast<RecordKind>(ptr[0]);
                size_t rec_size = 0;
                switch (kind) {
                case RecordKind::Inst: {
                    uint8_t n_fprdiff_val = is_v7 ? ptr[fprdiff_off] : 0;
                    rec_size = inst_hdr_sz
                        + ptr[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                        + n_fprdiff_val * sizeof(qbditrace::qbditrace_fprdiff_t)
                        + ptr[3] * memacc_sz;
                    scan_id++;
                    break;
                }
                case RecordKind::Anchor: {
                    rec_size = anchor_rec_sz;
                    const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                    raw_anchors.push_back({scan_id, scan_offset, ah->pc});
                    raw_anchor_threads.push_back(cur_thread);
                    break;
                }
                case RecordKind::Thread: {
                    rec_size = sizeof(qbditrace::qbditrace_thread_head_t);
                    const auto* th = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(ptr);
                    cur_thread = th->thread_id;
                    saw_thread_record = true;
                    raw_thread_chunks.push_back({scan_id, cur_thread});
                    break;
                }
                case RecordKind::Event:  rec_size = sizeof(qbditrace::qbditrace_event_head_t);  break;
                case RecordKind::Svc:    rec_size = sizeof(qbditrace::qbditrace_svc_head_t);    break;
                case RecordKind::Objc:   rec_size = raw_record_size(ptr, reader.header()); break;
                case RecordKind::CapiCall: {
                    if (is_v8) {
                        const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr);
                        rec_size = sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                        const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                        for (uint8_t s = 0; s < cc->str_count; ++s) {
                            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                            uint16_t data_bytes = sh->str_len + 1;
                            uint16_t padded = (data_bytes + 3u) & ~3u;
                            rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                            sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        }
                    } else {
                        const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr);
                        rec_size = sizeof(qbditrace::qbditrace_capicall_head_t);
                        const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_t);
                        for (uint8_t s = 0; s < cc->str_count; ++s) {
                            const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                            uint16_t data_bytes = sh->str_len + 1;
                            uint16_t padded = (data_bytes + 3u) & ~3u;
                            rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                            sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        }
                    }
                    break;
                }
case RecordKind::Code:   rec_size = sizeof(qbditrace::qbditrace_code_head_t) + ptr[1]; break;
            case RecordKind::Retval:
                rec_size = raw_record_size(ptr, reader.header());
                break;
            case RecordKind::MemImg:
                if (file_size - scan_offset < sizeof(qbditrace::qbditrace_memimg_t)) {
                    rec_size = file_size - scan_offset;
                } else {
                    rec_size = raw_record_size(ptr, reader.header());
                }
                break;
            default: rec_size = 1; break;
                }
                if (rec_size == 0) break;
                scan_offset += rec_size;

                // Report Phase 0 progress every ~500 MB.
                constexpr uint64_t kReportInterval = 500ULL * 1024 * 1024;
                if (scan_offset - phase0_last_report >= kReportInterval) {
                    phase0_last_report = scan_offset;
                    auto now = std::chrono::steady_clock::now();
                    double elapsed = std::chrono::duration<double>(now - phase0_start).count();
                    double pct = 100.0 * scan_offset / file_size;
                    double speed_mb = (scan_offset / (1024.0 * 1024.0)) / elapsed;
                    double eta = (elapsed / scan_offset) * (file_size - scan_offset);
                    std::fprintf(stderr,
                        "\r  Phase 0: scanning anchors  %.1f%%  "
                        "(%.0f MB/s, ETA %.0fs, %zu anchors, %llu insts)   ",
                        pct, speed_mb, eta,
                        raw_anchors.size(), (unsigned long long)scan_id);
                    std::fflush(stderr);
                }
            }
            reader.unpin_all();
        }

        if (phase0_last_report > 0) {
            auto phase0_end = std::chrono::steady_clock::now();
            double phase0_sec = std::chrono::duration<double>(phase0_end - phase0_start).count();
            std::fprintf(stderr,
                "\r  Phase 0: done — %llu insts, %zu anchors in %.1fs                \n",
                (unsigned long long)scan_id, raw_anchors.size(), phase0_sec);
        }

        // Populate in-memory anchor table
        for (const auto& a : raw_anchors) {
            idx.anchors_.push_back({a.inst_id, a.file_offset});
        }
        idx.anchors_have_threads_ = saw_thread_record;
        // NOTE: raw_anchor_threads / raw_thread_chunks are moved into idx AFTER
        // the shard-bounds computation below — the shard loop reads
        // raw_anchor_threads[anchor_idx], which would be empty after the move.

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
            shard_bounds.push_back({records_start, file_size, 0, 0});
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
                uint64_t tid_start = (s == 0) ? 0 : raw_anchor_threads[anchor_idx];
                shard_bounds.push_back({fstart, fend, id_start, tid_start});
            }
        }

        // Move thread metadata into the index now that the shard loop above no
        // longer needs the local vectors (raw_anchors itself is never moved).
        idx.anchor_threads_ = std::move(raw_anchor_threads);
        idx.thread_chunks_ = std::move(raw_thread_chunks);
    }

    // ── Phase 1: Parallel shard processing (SST bulk-load) ──────────────
    //
    // P2.0: Direct SST file generation — bypasses MemTable SkipList entirely.
    //
    // Previous approach: each shard produced a WriteBatch and called
    //   db_->Write().  Profile showed 100% of time in SkipList::Insert +
    //   background compaction.  On large traces this dominated build time.
    //
    // New approach: each shard writes sorted SST files directly via
    //   SstFileWriter, then bulk-ingests them via IngestExternalFile().
    //   This bypasses MemTable, WAL, and compaction entirely — the SST
    //   files land directly in L0.
    //
    // Key ordering guarantee: within each shard the keys are naturally
    //   ascending (inst_id increases monotonically for OFFSET/ANCHOR;
    //   reg_write keys encode (reg_idx, inst_id) which also ascend;
    //   CODE_BYTES pc keys need sorting and are buffered + sorted before write).
    //
    const uint32_t num_shards = static_cast<uint32_t>(shard_bounds.size());

struct ShardResult {
    uint64_t inst_count    = 0;  // INST records in this shard
    uint64_t anchor_count  = 0;
    uint64_t code_count    = 0;
    uint64_t event_count   = 0;
    uint64_t capicall_count = 0;
    uint64_t total_records = 0;
        // SST files generated by this shard, per CF.
        // Key: cf_handle pointer, Value: list of SST file paths.
        std::vector<std::string> offset_ssts;
        std::vector<std::string> anchor_ssts;
        std::vector<std::string> reg_writes_ssts;
        std::vector<std::string> code_bytes_ssts;
        std::string error;  // non-empty on failure
    };

    std::vector<ShardResult> shard_results(num_shards);
    std::atomic<uint64_t> progress_bytes{0};

    // SST files are written to a temp subdirectory inside the index folder.
    auto sst_dir = db_path / "_sst_tmp";
    std::filesystem::create_directories(sst_dir);

    auto process_shard = [&](uint32_t shard_idx) {
        auto& result = shard_results[shard_idx];
        const auto& bounds = shard_bounds[shard_idx];

        // ── Per-CF SstFileWriter management ────────────────────────────
        // Each CF gets its own SstFileWriter.  When a writer accumulates
        // enough entries it is finished (producing one SST) and a new one
        // is opened. This bounds memory and allows incremental I/O.

        struct CfWriter {
            rocksdb::SstFileWriter writer;
            std::vector<std::string>* sst_list;  // where to record finished SST paths
            std::string cf_tag;   // for file naming
            uint32_t shard_idx;
            uint32_t file_seq = 0;
            uint64_t entry_count = 0;
            bool is_open = false;
            std::filesystem::path sst_dir;
            // Dedup support: when enabled, if a new key equals the pending key,
            // the pending entry is silently replaced (last-writer-wins).
            // This handles ANCHOR CF where multiple anchors can share the same inst_id.
            bool dedup_enabled = false;
            bool has_pending = false;
            std::string pending_key;
            std::string pending_value;

            CfWriter(const rocksdb::Options& opts, std::vector<std::string>* list,
                     const char* tag, uint32_t si, const std::filesystem::path& dir,
                     bool dedup = false)
                : writer(rocksdb::EnvOptions(), opts), sst_list(list),
                  cf_tag(tag), shard_idx(si), sst_dir(dir), dedup_enabled(dedup) {}

            rocksdb::Status ensure_open() {
                if (is_open) return rocksdb::Status::OK();
                auto path = sst_dir / (cf_tag + "_s" + std::to_string(shard_idx)
                                       + "_" + std::to_string(file_seq++) + ".sst");
                auto s = writer.Open(path.string());
                if (s.ok()) is_open = true;
                return s;
            }

            // Flush the pending entry to the SST writer.
            rocksdb::Status flush_pending() {
                if (!has_pending) return rocksdb::Status::OK();
                auto s = ensure_open();
                if (!s.ok()) return s;
                s = writer.Put(rocksdb::Slice(pending_key), rocksdb::Slice(pending_value));
                if (s.ok()) entry_count++;
                has_pending = false;
                return s;
            }

            rocksdb::Status add(const rocksdb::Slice& key, const rocksdb::Slice& value) {
                if (dedup_enabled) {
                    // If key matches pending, replace pending (last-writer-wins)
                    if (has_pending && pending_key.size() == key.size() &&
                        std::memcmp(pending_key.data(), key.data(), key.size()) == 0) {
                        pending_value.assign(value.data(), value.size());
                        return rocksdb::Status::OK();
                    }
                    // Flush previous pending before accepting new key
                    auto s = flush_pending();
                    if (!s.ok()) return s;
                    pending_key.assign(key.data(), key.size());
                    pending_value.assign(value.data(), value.size());
                    has_pending = true;
                    return rocksdb::Status::OK();
                }
                auto s = ensure_open();
                if (!s.ok()) return s;
                s = writer.Put(key, value);
                if (s.ok()) entry_count++;
                return s;
            }

            // Finish current SST file if open.  Returns OK if nothing to finish.
            rocksdb::Status finish() {
                if (dedup_enabled) {
                    auto s = flush_pending();
                    if (!s.ok()) return s;
                }
                if (!is_open) return rocksdb::Status::OK();
                // If no entries were written (e.g. rotate happened at exact
                // boundary then no more records arrived), SstFileWriter::Finish()
                // would fail with InvalidArgument.  Skip Finish — the internal
                // builder will be Abandoned when the next Open() resets it or
                // when the SstFileWriter destructor runs.  The empty 0-byte
                // file on disk is harmless and cleaned up with _sst_tmp.
                if (entry_count == 0) {
                    is_open = false;
                    return rocksdb::Status::OK();
                }
                auto s = writer.Finish();
                if (s.ok() && sst_list) {
                    // Recover the path from the writer by naming convention
                    auto path = sst_dir / (cf_tag + "_s" + std::to_string(shard_idx)
                                           + "_" + std::to_string(file_seq - 1) + ".sst");
                    sst_list->push_back(path.string());
                }
                is_open = false;
                entry_count = 0;
                return s;
            }

            // Rotate: finish current file and prepare for a new one.
            // Returns true on success (including no-op), false on error.
            // The error can be retrieved via last_error.
            rocksdb::Status last_rotate_error;

            bool rotate_if_needed(uint64_t threshold) {
                if (entry_count < threshold || !is_open) return true;
                last_rotate_error = finish();
                return last_rotate_error.ok();
            }
        };

        // SstFileWriter needs Options that match the CF's table format.
        // All CFs use LZ4 compression for reduced disk usage.
        rocksdb::Options sst_opts;
        sst_opts.compression = rocksdb::kLZ4Compression;

        CfWriter offset_w(sst_opts, &result.offset_ssts, "offset", shard_idx, sst_dir);
        // Enable dedup for anchor_w: multiple ANCHOR records can share the same
        // inst_id (e.g. explicit emit_anchor + auto-anchor at inst_count%interval==0).
        // SstFileWriter requires strict ascending keys, so we buffer one pending
        // entry and silently replace it when the next key is identical (last-writer-wins).
        CfWriter anchor_w(sst_opts, &result.anchor_ssts, "anchor", shard_idx, sst_dir,
                           /*dedup=*/true);

        // REG_WRITES: key = (0, reg_index, inst_id).  Sort order is by
        // reg_index first, then inst_id.  A single instruction can modify
        // multiple registers with different reg_index values, so a single
        // SstFileWriter would see non-monotonic keys.
        //
        // Solution: one CfWriter PER register (0..33).  Within each writer,
        // inst_id is strictly increasing, so keys are naturally sorted.
        // AArch64 has 34 GPRs (x0-x28, fp, lr, sp, nzcv, pc), so 34 writers.
        constexpr uint32_t NUM_REGS = 34;
        std::vector<std::unique_ptr<CfWriter>> regw_per_reg;
        regw_per_reg.reserve(NUM_REGS);
        for (uint32_t r = 0; r < NUM_REGS; r++) {
            auto tag = "regw_r" + std::to_string(r);
            regw_per_reg.push_back(std::make_unique<CfWriter>(
                sst_opts, &result.reg_writes_ssts, tag.c_str(), shard_idx, sst_dir));
        }

        // CODE_BYTES: pc keys are NOT monotonically increasing (CODE records
        // appear at arbitrary points), so we buffer them in-memory and write
        // a single sorted SST at the end.
        struct CodeEntry {
            char key[8];
            char val[4];
        };
        std::vector<CodeEntry> code_entries;

        // v5 seed_pc tracking: each producer thread has an independent
        // pc_delta chain. THREAD records switch the active accumulator;
        // ANCHOR records reset that thread's chain. Stored alongside each
        // sparse file offset so offset_of_with_pc() avoids an anchor walk.
        std::unordered_map<uint64_t, uint64_t> running_pcs;
        running_pcs.emplace(0, 0);

        uint64_t scan_offset = bounds.file_start;
        const uint64_t scan_end = bounds.file_end;

        uint64_t inst_id = bounds.inst_id_start;
        // Producer thread currently owning the records being scanned (v13:
        // updated at THREAD records; used to annotate ANCHOR CF values).
        uint64_t cur_thread = bounds.thread_id_start;

        // SST rotation threshold: ~500K entries per SST file.
        constexpr uint64_t SST_ROTATE_THRESHOLD = 500000;

        // ── Per-record processing lambda ──
        // Processes one record at `ptr` with absolute file offset `rec_offset`.
        // Returns the record size in bytes, or 0 on corrupt/unknown record.
        // On SST error sets result.error and returns 0.
        auto process_record = [&](const uint8_t* ptr, uint64_t rec_offset,
                                  size_t remaining) -> size_t {
            auto kind = static_cast<RecordKind>(ptr[0]);
            size_t rec_size = 0;

            switch (kind) {
            case RecordKind::Inst: {
                if (remaining < inst_hdr_sz) return 0;
                uint8_t n_fprdiff_val = is_v7 ? ptr[fprdiff_off] : 0;
                rec_size = inst_hdr_sz
                    + ptr[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                    + n_fprdiff_val * sizeof(qbditrace::qbditrace_fprdiff_t)
                    + ptr[3] * memacc_sz;
                if (remaining < rec_size) return 0;
                // v5: accumulate this producer's pc_delta chain so the
                // sparse entry holds this INST's resolved absolute PC.
                if (is_v5) {
                    int16_t delta;
                    std::memcpy(&delta, ptr + 4, 2);
                    running_pcs[cur_thread] += static_cast<int64_t>(delta);
                }
                // P1.6: Sparse offset with adaptive interval
                if (inst_id % idx.sparse_interval_ == 0) {
                    char key_buf[8];
                    encode_u64_to(inst_id, key_buf);
                    // Store 16-byte value: file_offset (8B) + seed_pc (8B).
                    // For v5 traces seed_pc is the running PC; for others it's 0.
                    char val_buf[16];
                    std::memcpy(val_buf, &rec_offset, 8);
                    uint64_t seed = is_v5 ? running_pcs[cur_thread] : 0;
                    std::memcpy(val_buf + 8, &seed, 8);
                    auto s = offset_w.add(
                        rocksdb::Slice(key_buf, 8),
                        rocksdb::Slice(val_buf, 16));
                    if (!s.ok()) { result.error = s.ToString(); return 0; }
                }
                // REG_WRITES inverted index (per-register SST writers)
                {
                    uint8_t n_regdiff = ptr[2];
                    const uint8_t* diffs = ptr + inst_hdr_sz;
                    for (uint8_t d = 0; d < n_regdiff; d++) {
                        const auto* rd = reinterpret_cast<const qbditrace::qbditrace_regdiff_t*>(
                            diffs + d * sizeof(qbditrace::qbditrace_regdiff_t));
                        uint8_t ri = rd->reg_index;
                        if (ri >= NUM_REGS) continue;
                        char rw_key[10];
                        rw_key[0] = 0;
                        rw_key[1] = static_cast<char>(ri);
                        for (int i = 7; i >= 0; --i)
                            rw_key[2 + (7 - i)] = static_cast<char>((inst_id >> (i * 8)) & 0xFF);
                        auto s = regw_per_reg[ri]->add(
                            rocksdb::Slice(rw_key, 10),
                            rocksdb::Slice());
                        if (!s.ok()) { result.error = s.ToString(); return 0; }
                    }
                }
                inst_id++;
                result.inst_count++;
                break;
            }
            case RecordKind::Anchor: {
                size_t anchor_fpr = is_v7 ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
                rec_size = sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + anchor_fpr;
                if (remaining < rec_size) return 0;
                // v5: reset this producer's pc chain from the anchor's
                // absolute PC (ANCHOR re-anchors a single thread's chain).
                if (is_v5) {
                    const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(ptr);
                    running_pcs[cur_thread] = ah->pc;
                }
                char anchor_key_buf[8];
                encode_u64_to(inst_id, anchor_key_buf);
                // v13: 16-byte value = (file_offset, owning_thread_id).
                // Legacy 8-byte caches are rejected by the schema bump.
                char anchor_val_buf[16];
                std::memcpy(anchor_val_buf, &rec_offset, 8);
                std::memcpy(anchor_val_buf + 8, &cur_thread, 8);
                auto s = anchor_w.add(
                    rocksdb::Slice(anchor_key_buf, 8),
                    rocksdb::Slice(anchor_val_buf, 16));
                if (!s.ok()) { result.error = s.ToString(); return 0; }
                result.anchor_count++;
                break;
            }
            case RecordKind::Code: {
                uint8_t code_size = ptr[1];
                rec_size = sizeof(qbditrace::qbditrace_code_head_t) + code_size;
                if (remaining < rec_size) return 0;
                if (code_size == 4) {
                    const auto* ch = reinterpret_cast<const qbditrace::qbditrace_code_head_t*>(ptr);
                    CodeEntry ce;
                    encode_u64_to(ch->pc, ce.key);
                    std::memcpy(ce.val, ptr + sizeof(qbditrace::qbditrace_code_head_t), 4);
                    code_entries.push_back(ce);
                }
                result.code_count++;
                break;
            }
            case RecordKind::Event:
                rec_size = sizeof(qbditrace::qbditrace_event_head_t);
                if (remaining < rec_size) return 0;
                result.event_count++;
                break;
            case RecordKind::Thread: {
                rec_size = sizeof(qbditrace::qbditrace_thread_head_t);
                if (remaining < rec_size) return 0;
                cur_thread = reinterpret_cast<const qbditrace::qbditrace_thread_head_t*>(ptr)->thread_id;
                // Each producer keeps its own pc_delta chain; a fresh
                // THREAD marker starts a chunk whose first ANCHOR (emitted
                // immediately by the writer) re-anchors the chain.
                running_pcs.try_emplace(cur_thread, 0);
                break;
            }
            case RecordKind::Svc:
                rec_size = sizeof(qbditrace::qbditrace_svc_head_t);
                if (remaining < rec_size) return 0;
                break;
            case RecordKind::Objc:
                rec_size = raw_record_size(ptr, reader.header());
                if (remaining < rec_size) return 0;
                break;
            case RecordKind::CapiCall: {
                if (is_v8) {
                    if (remaining < sizeof(qbditrace::qbditrace_capicall_head_v8_t)) return 0;
                    const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr);
                    rec_size = sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                    const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_v8_t);
                    for (uint8_t s = 0; s < cc->str_count; ++s) {
                        if (remaining < rec_size + sizeof(qbditrace::qbditrace_capicall_str_t)) return 0;
                        const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                        uint16_t data_bytes = sh->str_len + 1;
                        uint16_t padded = (data_bytes + 3u) & ~3u;
                        rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                    }
                } else {
                    if (remaining < sizeof(qbditrace::qbditrace_capicall_head_t)) return 0;
                    const auto* cc = reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr);
                    rec_size = sizeof(qbditrace::qbditrace_capicall_head_t);
                    const uint8_t* sp = ptr + sizeof(qbditrace::qbditrace_capicall_head_t);
                    for (uint8_t s = 0; s < cc->str_count; ++s) {
                        if (remaining < rec_size + sizeof(qbditrace::qbditrace_capicall_str_t)) return 0;
                        const auto* sh = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(sp);
                        uint16_t data_bytes = sh->str_len + 1;
                        uint16_t padded = (data_bytes + 3u) & ~3u;
                        rec_size += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                        sp += sizeof(qbditrace::qbditrace_capicall_str_t) + padded;
                    }
                }
                if (remaining < rec_size) return 0;
                result.capicall_count++;
                break;
            }
            case RecordKind::Retval:
                rec_size = raw_record_size(ptr, reader.header());
                if (remaining < rec_size) return 0;
                break;
            case RecordKind::MemImg:
                if (remaining < sizeof(qbditrace::qbditrace_memimg_t)) return 0;
                rec_size = raw_record_size(ptr, reader.header());
                if (remaining < rec_size) return 0;
                break;
            default:
                rec_size = 1;
                break;
            }

            result.total_records++;

            // Rotate SST files periodically to bound memory.
            if ((result.total_records & 0x3FF) == 0) {
                if (!offset_w.rotate_if_needed(SST_ROTATE_THRESHOLD)) {
                    result.error = offset_w.last_rotate_error.ToString(); return 0;
                }
                if (!anchor_w.rotate_if_needed(SST_ROTATE_THRESHOLD)) {
                    result.error = anchor_w.last_rotate_error.ToString(); return 0;
                }
                for (auto& rw : regw_per_reg) {
                    if (!rw->rotate_if_needed(SST_ROTATE_THRESHOLD)) {
                        result.error = rw->last_rotate_error.ToString(); return 0;
                    }
                }
            }

            return rec_size;
        };

        if (reader.is_block_mode()) {
            // ── Block-compressed fast path ──
            // Decompress blocks covering [file_start, file_end) and scan
            // records using pointer arithmetic — no mutex, no LRU.
            // Same cross-boundary handling as Phase 0: track logical_pos
            // across blocks, use overlap buffer for straddling records.
            const uint64_t hdr_sz = reader.header_size();
            const uint64_t logical_start = bounds.file_start - hdr_sz;
            const uint64_t logical_end   = bounds.file_end   - hdr_sz;

            uint32_t start_block = reader.find_block_for_offset(logical_start);
            const uint32_t n_blocks = reader.block_count();
            std::vector<uint8_t> block_buf;
            uint64_t logical_pos = logical_start;

            for (uint32_t bi = start_block; bi < n_blocks; bi++) {
                const uint8_t* blk_data = nullptr;
                uint32_t blk_size = 0;
                uint64_t blk_logical_offset = 0;
                if (!reader.decompress_block(bi, block_buf, blk_data,
                                              blk_size, blk_logical_offset))
                    break;

                // Skip if we've already scanned past this block via overlap.
                if (logical_pos >= blk_logical_offset + blk_size) continue;
                // Stop if this block starts at or beyond our shard end.
                if (blk_logical_offset >= logical_end) break;

                uint32_t pos = 0;
                if (logical_pos > blk_logical_offset)
                    pos = static_cast<uint32_t>(logical_pos - blk_logical_offset);

                // scan_limit = range within this block's own data where new
                // records can start.  buf_total = total readable bytes
                // (including overlap) for cross-boundary record content.
                uint32_t scan_limit = blk_size - pos;
                uint32_t buf_total  = static_cast<uint32_t>(block_buf.size()) - pos;
                // Clamp scan_limit to shard end.
                if (blk_logical_offset + pos + scan_limit > logical_end)
                    scan_limit = static_cast<uint32_t>(logical_end - blk_logical_offset - pos);

                uint32_t inner_pos = 0;
                while (inner_pos < scan_limit) {
                    const uint8_t* ptr = blk_data + pos + inner_pos;
                    uint32_t remaining = buf_total - inner_pos;
                    uint64_t rec_offset = blk_logical_offset + hdr_sz + pos + inner_pos;
                    size_t rec_size = process_record(ptr, rec_offset, remaining);
                    if (rec_size == 0) break;
                    inner_pos += static_cast<uint32_t>(rec_size);
                    progress_bytes.fetch_add(rec_size, std::memory_order_relaxed);
                }
                logical_pos = blk_logical_offset + pos + inner_pos;
                scan_offset = logical_pos + hdr_sz;
            }
        } else {
            // ── mmap path — original per-record data_at() ──
            while (scan_offset < scan_end) {
                const uint8_t* ptr = reader.data_at(scan_offset);
                size_t rec_size = process_record(ptr, scan_offset, scan_end - scan_offset);
                if (rec_size == 0) break;
                scan_offset += rec_size;
                progress_bytes.fetch_add(rec_size, std::memory_order_relaxed);
            }
        }

        // Finish all open SST writers
        {
            auto s = offset_w.finish();
            if (s.ok()) s = anchor_w.finish();
            if (!s.ok()) { result.error = s.ToString(); return; }
            for (auto& rw : regw_per_reg) {
                s = rw->finish();
                if (!s.ok()) { result.error = s.ToString(); return; }
            }
        }

        // Write sorted CODE_BYTES SST
        if (!code_entries.empty()) {
            // Sort by key (big-endian PC) — required by SstFileWriter
#if defined(TENET_HAS_TBB) && TENET_HAS_TBB
            tbb::parallel_sort(code_entries.begin(), code_entries.end(),
                      [](const CodeEntry& a, const CodeEntry& b) {
                          return std::memcmp(a.key, b.key, 8) < 0;
                      });
#else
            std::sort(code_entries.begin(), code_entries.end(),
                      [](const CodeEntry& a, const CodeEntry& b) {
                          return std::memcmp(a.key, b.key, 8) < 0;
                      });
#endif
            // Deduplicate: keep last occurrence of each PC (latest code bytes)
            auto new_end = std::unique(code_entries.rbegin(), code_entries.rend(),
                                       [](const CodeEntry& a, const CodeEntry& b) {
                                           return std::memcmp(a.key, b.key, 8) == 0;
                                       });
            code_entries.erase(code_entries.begin(),
                               new_end.base());

            rocksdb::Options code_sst_opts;
            code_sst_opts.compression = rocksdb::kLZ4Compression;
            rocksdb::SstFileWriter code_w(rocksdb::EnvOptions(), code_sst_opts);
            auto code_path = sst_dir / ("code_s" + std::to_string(shard_idx) + ".sst");
            auto s = code_w.Open(code_path.string());
            if (!s.ok()) { result.error = s.ToString(); return; }
            for (const auto& ce : code_entries) {
                s = code_w.Put(rocksdb::Slice(ce.key, 8), rocksdb::Slice(ce.val, 4));
                if (!s.ok()) { result.error = s.ToString(); return; }
            }
            s = code_w.Finish();
            if (!s.ok()) { result.error = s.ToString(); return; }
            result.code_bytes_ssts.push_back(code_path.string());
        }
    };

    // Pin all cached blocks during Phase 1 so that worker threads' pointers
    // (from data_at) are not evicted by other threads' LRU activity.
    reader.pin_all();

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

    reader.unpin_all();

    // Check for shard errors
    for (const auto& r : shard_results) {
        if (!r.error.empty()) {
            // Clean up temp SST directory on error
            std::error_code ec;
            std::filesystem::remove_all(sst_dir, ec);
            return Error::rocksdb_error(r.error);
        }
    }

    // ── Phase 2: Ingest SST files into RocksDB ────────────────────────
    //
    // P2.0: Bulk-ingest all SST files produced by shards.
    // IngestExternalFile() moves SST files directly into L0 — no MemTable,
    // no WAL, no compaction overhead.  This is O(N) in the number of files,
    // not in the number of entries.
    {
        rocksdb::IngestExternalFileOptions ingest_opts;
        ingest_opts.move_files = true;          // move, don't copy (same FS)
        ingest_opts.snapshot_consistency = false; // no snapshots during build
        ingest_opts.allow_global_seqno = true;
        ingest_opts.allow_blocking_flush = false; // no memtable to flush

        // Helper: collect SST paths from all shards for a given CF.
        // Filters out any 0-byte files (from abandoned empty SST writers)
        // which would cause IngestExternalFile to fail.
        auto ingest_cf = [&](rocksdb::ColumnFamilyHandle* cf_handle,
                             auto sst_getter) -> rocksdb::Status {
            std::vector<std::string> all_ssts;
            for (auto& r : shard_results) {
                auto& ssts = sst_getter(r);
                for (auto& p : ssts) {
                    std::error_code fec;
                    auto fsize = std::filesystem::file_size(p, fec);
                    if (!fec && fsize > 0)
                        all_ssts.push_back(std::move(p));
                }
            }
            if (all_ssts.empty()) return rocksdb::Status::OK();
            return idx.db_->IngestExternalFile(cf_handle, all_ssts, ingest_opts);
        };

        auto s = ingest_cf(idx.get_cf(cf::OFFSET),
                           [](ShardResult& r) -> auto& { return r.offset_ssts; });
        if (s.ok())
            s = ingest_cf(idx.get_cf(cf::ANCHOR),
                          [](ShardResult& r) -> auto& { return r.anchor_ssts; });
        if (s.ok())
            s = ingest_cf(idx.get_cf(cf::REG_WRITES),
                          [](ShardResult& r) -> auto& { return r.reg_writes_ssts; });
        if (s.ok())
            s = ingest_cf(idx.get_cf(cf::CODE_BYTES),
                          [](ShardResult& r) -> auto& { return r.code_bytes_ssts; });

        // Clean up temp SST directory (moved files are gone; empty dir remains)
        std::error_code ec;
        std::filesystem::remove_all(sst_dir, ec);

        if (!s.ok()) {
            return Error::rocksdb_error("SST ingest failed: " + s.ToString());
        }

        // Compact CFs used for point lookups / SeekForPrev to consolidate L0
        // SSTs into sorted levels. This is a one-time cost during build that
        // significantly improves subsequent read performance (avoids checking
        // multiple overlapping L0 files per query).
        //
        // Compactions run in parallel (one thread per CF) to cut wall-clock
        // time on large traces where each CF can be hundreds of MB.
        //
        // Report Phase 2 progress via the same callback using the sentinel
        // convention: processed = file_size + step (1..3), total = file_size.
        // Callers detect Phase 2 when processed > total.
        rocksdb::CompactRangeOptions cro;
        cro.bottommost_level_compaction = rocksdb::BottommostLevelCompaction::kForceOptimized;

        if (progress) progress(file_size + 1, file_size);  // compact phase started

        // Run the three compactions in parallel — each can take tens of seconds
        // on large traces, so parallelising cuts the total wait to the slowest one.
        struct CompactTask {
            rocksdb::ColumnFamilyHandle* cf;
            std::string error;
        };
        std::vector<CompactTask> compact_tasks = {
            {idx.get_cf(cf::OFFSET),     {}},
            {idx.get_cf(cf::REG_WRITES), {}},
            {idx.get_cf(cf::CODE_BYTES), {}},
        };
        std::atomic<uint32_t> compact_done{0};
        const uint32_t compact_total = static_cast<uint32_t>(
            std::count_if(compact_tasks.begin(), compact_tasks.end(),
                          [](const CompactTask& t) { return t.cf != nullptr; }));
        std::vector<std::thread> compact_threads;
        compact_threads.reserve(compact_tasks.size());
        for (auto& task : compact_tasks) {
            if (!task.cf) continue;
            compact_threads.emplace_back([&idx, &cro, &task, &compact_done]() {
                auto cs = idx.db_->CompactRange(cro, task.cf, nullptr, nullptr);
                if (!cs.ok()) task.error = cs.ToString();
                compact_done.fetch_add(1, std::memory_order_relaxed);
            });
        }
        // Poll progress while compactions run.
        if (progress) {
            while (compact_done.load(std::memory_order_relaxed) < compact_total) {
                uint32_t done = compact_done.load(std::memory_order_relaxed);
                // Map done count (0-3) to step (1-3) so progress stays in [1,3].
                progress(file_size + 1 + done, file_size);
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        for (auto& t : compact_threads) {
            if (t.joinable()) t.join();
        }
        // Log compaction errors but don't abort — the index is still usable
        // (queries just do more L0 file checks).
        for (const auto& task : compact_tasks) {
            if (!task.error.empty()) {
                LOG_WARN_M(::tenet::log::Module::Io, "CompactRange failed: {} — reads may be slower", task.error);
            }
        }
        if (progress) progress(file_size + 3, file_size);  // compact done
    }

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

    // Write metadata as a single atomic batch (one WAL + memtable write)
    auto* meta_cf = idx.get_cf(cf::META);
    uint64_t fsize = reader.file_size();
    uint64_t trace_hash = sample_trace_hash(reader);

    rocksdb::WriteBatch meta_batch;
    meta_batch.Put(meta_cf, "version", "1");
    meta_batch.Put(meta_cf, "schema_version",
                   rocksdb::Slice(reinterpret_cast<const char*>(&INDEX_SCHEMA_VERSION), 4));
    meta_batch.Put(meta_cf, "inst_count",
                   rocksdb::Slice(reinterpret_cast<const char*>(&inst_id), 8));
    meta_batch.Put(meta_cf, "file_size",
                   rocksdb::Slice(reinterpret_cast<const char*>(&fsize), 8));
    meta_batch.Put(meta_cf, "total_records",
                   rocksdb::Slice(reinterpret_cast<const char*>(&total_records), 8));
    meta_batch.Put(meta_cf, "anchor_count",
                   rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.anchor_count), 8));
    meta_batch.Put(meta_cf, "code_count",
                   rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.code_count), 8));
    meta_batch.Put(meta_cf, "event_count",
                   rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.event_count), 8));
    meta_batch.Put(meta_cf, "sparse_interval",
                   rocksdb::Slice(reinterpret_cast<const char*>(&actual_interval), 8));
    meta_batch.Put(meta_cf, "num_shards",
                   rocksdb::Slice(reinterpret_cast<const char*>(&idx.stats_.num_shards), 4));
    meta_batch.Put(meta_cf, "trace_hash",
                   rocksdb::Slice(reinterpret_cast<const char*>(&trace_hash), 8));
    meta_batch.Put(meta_cf, "anchors_have_threads",
                   rocksdb::Slice(reinterpret_cast<const char*>(&idx.anchors_have_threads_), 1));
    // Thread chunk table (multi-thread traces): 16 bytes per THREAD marker —
    // (first inst_id of chunk, thread_id), ascending. Consumed by
    // thread_at() without re-scanning the trace.
    if (!idx.thread_chunks_.empty()) {
        std::string chunks_blob;
        chunks_blob.reserve(idx.thread_chunks_.size() * 16);
        for (const auto& [iid, tid] : idx.thread_chunks_) {
            chunks_blob.append(reinterpret_cast<const char*>(&iid), 8);
            chunks_blob.append(reinterpret_cast<const char*>(&tid), 8);
        }
        meta_batch.Put(meta_cf, "thread_chunks",
                       rocksdb::Slice(chunks_blob.data(), chunks_blob.size()));
    }
    {
        rocksdb::WriteOptions wo;
        wo.sync = true;  // Sync meta to disk: must survive crashes / OOM-kills.
        // Without sync, a hard kill between Write() and DB close can leave the
        // DB in a state where all SSTs are present but the META CF is empty —
        // triggering "missing file_size key" on every subsequent open.
        auto wstatus = idx.db_->Write(wo, &meta_batch);
        if (!wstatus.ok()) {
            LOG_ERROR_M(::tenet::log::Module::Io, "Failed to write index metadata: {} — index may be incomplete",
                      wstatus.ToString());
            return Error::rocksdb_error("meta_batch write failed: " + wstatus.ToString());
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    idx.stats_.build_seconds =
        std::chrono::duration<double>(t1 - t0).count();

    // Sort anchors (gathered from Phase 0 raw scan, already in order but sort for safety)
#if defined(TENET_HAS_TBB) && TENET_HAS_TBB
    tbb::parallel_sort(idx.anchors_.begin(), idx.anchors_.end(),
              [](const auto& a, const auto& b) { return a.inst_id < b.inst_id; });
#else
    std::sort(idx.anchors_.begin(), idx.anchors_.end(),
              [](const auto& a, const auto& b) { return a.inst_id < b.inst_id; });
#endif
    // Keep anchor_threads_ parallel to anchors_: pair them and sort together.
    // Phase 0 produced both in file order (ascending inst_id), but dedup of
    // anchors sharing an inst_id can only happen in the CF layer — the raw
    // vectors here stay 1:1, so an index-permutation sort is sufficient.
    if (idx.anchor_threads_.size() != idx.anchors_.size()) {
        idx.anchor_threads_.assign(idx.anchors_.size(), 0);
    } else {
        std::vector<uint32_t> order(idx.anchors_.size());
        std::iota(order.begin(), order.end(), 0u);
        std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
            return idx.anchors_[a].inst_id < idx.anchors_[b].inst_id;
        });
        std::vector<uint64_t> sorted_tids(order.size());
        for (size_t i = 0; i < order.size(); ++i) {
            sorted_tids[i] = idx.anchor_threads_[order[i]];
        }
        idx.anchor_threads_ = std::move(sorted_tids);
    }

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

    const uint32_t num_gpr = reader.header().num_gpr;
    const bool is_v5 = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    const bool is_v7_scan = (reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;

    // v12+: seed_pc is stored alongside the offset (16-byte value).
    // For v5 traces this eliminates the ANCHOR walk that previously
    // reconstructed running_pc by linear-scanning pc_delta from the
    // nearest anchor to base_id.
    uint64_t running_pc = 0;
    if (is_v5 && value.size() >= 16) {
        std::memcpy(&running_pc, value.data() + 8, 8);
    } else if (is_v5) {
        // Legacy 8-byte value (pre-v12 cache) — fall back to ANCHOR walk.
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
                    // v7+v5: inst header is 8 bytes, n_fprdiff at byte 6
                    const size_t whdr_sz = is_v7_scan
                        ? sizeof(qbditrace::qbditrace_inst_head_v7_v5_t)
                        : sizeof(qbditrace::qbditrace_inst_head_v5_t);
                    uint8_t wfpr = is_v7_scan ? wp[6] : 0;
                    walk_offset += whdr_sz
                        + wp[2] * sizeof(qbditrace::qbditrace_regdiff_t)
                        + wfpr  * sizeof(qbditrace::qbditrace_fprdiff_t)
                        + wp[3] * wmacc_sz;
                } else if (wkind == RecordKind::Anchor) {
                    const auto* ah = reinterpret_cast<const qbditrace::qbditrace_anchor_head_t*>(wp);
                    running_pc = ah->pc;
                    size_t afpr = is_v7_scan ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
                    walk_offset += sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + afpr;
                } else {
                    auto rec = reader.record_at(walk_offset);
                    walk_offset += rec.byte_size(num_gpr);
                }
            }
        }
    }

    // Linear scan from base_id to inst_id
    // The stored offset points to the INST record for base_id.
    // We need to find the INST record for inst_id.
    uint64_t current_id = base_id;
    uint64_t current_offset = offset;

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
            // Compute record size directly from raw bytes, respecting v4/v5/v7 layout.
            // (RecordView::byte_size() now uses the is_v5/is_v7 flags; however this hot path
            //  avoids constructing a RecordView at all for speed.)
            size_t hdr_size = (is_v7_scan && is_v5)
                ? sizeof(qbditrace::qbditrace_inst_head_v7_v5_t)  // 8 bytes
                : is_v7_scan
                ? sizeof(qbditrace::qbditrace_inst_head_v7_t)     // 24 bytes
                : is_v5
                ? sizeof(qbditrace::qbditrace_inst_head_v5_t)     // 6 bytes
                : sizeof(qbditrace::qbditrace_inst_head_t);       // 16 bytes
            uint8_t n_regdiff = ptr[2];
            uint8_t n_mem = ptr[3];
            // v7: read n_fprdiff from the correct byte offset
            const size_t fpr_off = fprdiff_byte_offset(is_v5, is_v7_scan);
            uint8_t n_fprdiff_scan = is_v7_scan ? ptr[fpr_off] : 0;
            // P1.7: use v6-aware memacc size in linear scan
            const bool is_v6_scan = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
            const size_t macc_scan_sz = is_v6_scan
                ? sizeof(qbditrace::qbditrace_memacc_v6_t)   // 48 bytes
                : sizeof(qbditrace::qbditrace_memacc_t);      // 32 bytes
            current_offset += hdr_size
                + n_regdiff      * sizeof(qbditrace::qbditrace_regdiff_t)   // 16 bytes each
                + n_fprdiff_scan * sizeof(qbditrace::qbditrace_fprdiff_t)   // 24 bytes each
                + n_mem          * macc_scan_sz;
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

// ─── Query: nearest_thread_anchor_before ──────────────────────────────────

TraceIndex::AnchorInfo TraceIndex::nearest_thread_anchor_before(
    uint64_t inst_id, uint64_t thread_id) const {
    // Single-thread traces (no THREAD records) or unmatched annotations fall
    // back to the plain anchor lookup.
    if (!anchors_have_threads_) {
        return nearest_anchor_before(inst_id);
    }

    if (anchors_.empty() ||
        anchor_threads_.size() != anchors_.size()) {
        return {0, sizeof(qbditrace::qbditrace_file_header_t), 0};
    }

    // Binary search for the largest anchor inst_id <= inst_id, then walk back
    // to the most recent anchor owned by thread_id. Anchors are spaced by
    // anchor_interval instructions, so the walk back is bounded in practice
    // (interleaved threads make each thread's anchors sparser, but the total
    // anchor count is inst_count / interval).
    AnchorEntry target{inst_id, 0};
    auto it = std::upper_bound(anchors_.begin(), anchors_.end(), target,
                               [](const AnchorEntry& a, const AnchorEntry& b) {
                                   return a.inst_id < b.inst_id;
                               });

    while (it != anchors_.begin()) {
        --it;
        const auto i = static_cast<size_t>(std::distance(anchors_.begin(), it));
        if (anchor_threads_[i] == thread_id) {
            return {static_cast<uint64_t>(i), it->file_offset, it->inst_id};
        }
    }
    // No anchor of this thread at or before inst_id.
    return {0, sizeof(qbditrace::qbditrace_file_header_t), 0};
}

// ─── Query: thread_at / thread_ids ─────────────────────────────────────────

uint64_t TraceIndex::thread_at(uint64_t inst_id) const {
    if (thread_chunks_.empty()) return 0;
    // Find the last chunk whose first inst_id <= inst_id. Chunks are
    // ascending by inst_id; std::upper_bound finds the first chunk with
    // first_id > inst_id, so the chunk before it (if any) owns inst_id.
    auto it = std::upper_bound(
        thread_chunks_.begin(), thread_chunks_.end(), inst_id,
        [](uint64_t v, const std::pair<uint64_t, uint64_t>& chunk) {
            return v < chunk.first;
        });
    if (it == thread_chunks_.begin()) return 0;  // before first THREAD marker
    --it;
    return it->second;
}

std::vector<uint64_t> TraceIndex::thread_ids() const {
    std::vector<uint64_t> ids;
    ids.reserve(thread_chunks_.size());
    for (const auto& [iid, tid] : thread_chunks_) ids.push_back(tid);
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
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

// ─── Pass blob file helpers ───────────────────────────────────────────────
//
// Pass result blobs are stored as plain files under
//   <db_path_>/pass_cache/<pass_name>.bin
//
// Rationale: blobs are opaque byte arrays with no need for DB key lookup,
// iteration, or transactions.  Plain files allow:
//   - Zero-copy reads via the caller's own mmap or fread.
//   - Simple atomic replace (write to .tmp, rename).
//   - No 2 GB macOS pread SST size limit.
//   - Directory listing via std::filesystem for list_pass_blobs().

namespace {

/// Returns the pass_cache directory for this index.
std::filesystem::path pass_cache_dir(const std::filesystem::path& db_path) {
    return db_path / "pass_cache";
}

/// Returns the file path for a given pass name.
std::filesystem::path pass_blob_path(const std::filesystem::path& db_path,
                                     std::string_view pass_name) {
    // Sanitise: pass names are short identifiers (xref, cfg, …) with no
    // path separators, but be safe.
    std::string fname(pass_name);
    for (char& c : fname) {
        if (c == '/' || c == '\\' || c == ':') c = '_';
    }
    fname += ".bin";
    return pass_cache_dir(db_path) / fname;
}

// File-level magic for zstd-compressed pass blobs.
// Layout: [4-byte magic][8-byte original_size][zstd-compressed payload]
// Old uncompressed files lack this magic and are loaded as-is (backward compat).
static constexpr uint32_t PASS_BLOB_ZSTD_MAGIC = 0x5A504243u;  // "ZPBC"

} // namespace

void TraceIndex::save_pass_blob(std::string_view pass_name,
                                const void* data, size_t size) {
    if (db_path_.empty() || !data || size == 0) return;

    // Ensure the pass_cache directory exists.
    std::error_code ec;
    auto dir = pass_cache_dir(db_path_);
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        LOG_WARN_M(::tenet::log::Module::Io, "save_pass_blob: cannot create pass_cache dir '{}': {}",
                 dir.string(), ec.message());
        return;
    }

    // Write to a .tmp file then rename for atomicity.
    auto final_path = pass_blob_path(db_path_, pass_name);
    auto tmp_path   = final_path;
    tmp_path += ".tmp";

    FILE* f = tenet::platform::open_file(tmp_path, "wb");
    if (!f) {
        LOG_WARN_M(::tenet::log::Module::Io, "save_pass_blob '{}': cannot open '{}' for write",
                 pass_name, tmp_path.string());
        return;
    }

    bool write_ok = false;

#if defined(TENET_HAS_ZSTD) && TENET_HAS_ZSTD
    // Compress with zstd level 3 (fast, ~3-8x ratio on serialised structs).
    // For blobs < 4KB compression overhead isn't worth it; store raw.
    if (size >= 4096) {
        size_t bound = ZSTD_compressBound(size);
        std::vector<char> cbuf(bound);
        size_t csize = ZSTD_compress(cbuf.data(), bound, data, size, /*level=*/3);
        if (!ZSTD_isError(csize) && csize < size) {
            // Write header: magic(4) + original_size(8) + compressed_payload
            uint64_t orig_size = static_cast<uint64_t>(size);
            bool ok = true;
            ok = ok && std::fwrite(&PASS_BLOB_ZSTD_MAGIC, 4, 1, f) == 1;
            ok = ok && std::fwrite(&orig_size, 8, 1, f) == 1;
            ok = ok && std::fwrite(cbuf.data(), 1, csize, f) == csize;
            write_ok = ok;
            if (ok) {
                LOG_DEBUG_M(::tenet::log::Module::Io, "save_pass_blob '{}': {}B → {}B (zstd, {:.1f}x)",
                          pass_name, size, csize, static_cast<double>(size) / csize);
            }
        }
        // If zstd failed or didn't compress, fall through to raw write below.
    }
#endif

    if (!write_ok) {
        // Raw (uncompressed) write — no magic header, plain payload.
        // This is the fallback when zstd is unavailable, disabled, or
        // the compressed output is larger than the input.
        std::rewind(f);
        write_ok = (std::fwrite(data, 1, size, f) == size);
    }

    std::fflush(f);
    std::fclose(f);

    if (!write_ok) {
        LOG_WARN_M(::tenet::log::Module::Io, "save_pass_blob '{}': write failed, discarding", pass_name);
        std::filesystem::remove(tmp_path, ec);
        return;
    }

    // Atomic rename
    std::filesystem::rename(tmp_path, final_path, ec);
    if (ec) {
        LOG_WARN_M(::tenet::log::Module::Io, "save_pass_blob '{}': rename failed: {}", pass_name, ec.message());
        std::filesystem::remove(tmp_path, ec);
    }
}

bool TraceIndex::load_pass_blob(std::string_view pass_name,
                                std::string& out) const {
    if (db_path_.empty()) return false;

    auto path = pass_blob_path(db_path_, pass_name);
    std::error_code ec;
    auto fsize_u = std::filesystem::file_size(path, ec);
    if (ec || fsize_u == 0) return false;
    size_t fsize = static_cast<size_t>(fsize_u);

    FILE* f = tenet::platform::open_file(path, "rb");
    if (!f) return false;

    // Peek at the first 4 bytes to detect the zstd magic.
    uint32_t magic = 0;
    bool has_magic = (fsize >= 12) && (std::fread(&magic, 4, 1, f) == 1);

#if defined(TENET_HAS_ZSTD) && TENET_HAS_ZSTD
    if (has_magic && magic == PASS_BLOB_ZSTD_MAGIC) {
        // Read original_size from next 8 bytes.
        uint64_t orig_size = 0;
        if (std::fread(&orig_size, 8, 1, f) != 1 || orig_size == 0 || orig_size > 4ULL * 1024 * 1024 * 1024) {
            std::fclose(f);
            LOG_WARN_M(::tenet::log::Module::Io, "load_pass_blob '{}': corrupt header", pass_name);
            return false;
        }
        // Read compressed payload.
        size_t payload_size = fsize - 12;
        std::vector<char> cbuf(payload_size);
        if (std::fread(cbuf.data(), 1, payload_size, f) != payload_size) {
            std::fclose(f);
            LOG_WARN_M(::tenet::log::Module::Io, "load_pass_blob '{}': short read of compressed payload", pass_name);
            return false;
        }
        std::fclose(f);

        // Decompress.
        std::string buf;
        buf.resize(static_cast<size_t>(orig_size));
        size_t dsize = ZSTD_decompress(buf.data(), buf.size(),
                                       cbuf.data(), payload_size);
        if (ZSTD_isError(dsize) || dsize != orig_size) {
            LOG_WARN_M(::tenet::log::Module::Io, "load_pass_blob '{}': decompression failed: {}",
                     pass_name, ZSTD_getErrorName(dsize));
            return false;
        }
        out = std::move(buf);
        return true;
    }
#endif

    // No magic (or zstd unavailable) — read as raw uncompressed blob.
    // If we already read 4 bytes, rewind and read from the start.
    if (has_magic) std::rewind(f);

    std::string buf;
    buf.resize(fsize);
    size_t nread = std::fread(buf.data(), 1, fsize, f);
    std::fclose(f);

    if (nread != fsize) {
        LOG_WARN_M(::tenet::log::Module::Io, "load_pass_blob '{}': short read ({}/{})", pass_name, nread, fsize);
        return false;
    }
    out = std::move(buf);
    return true;
}

void TraceIndex::delete_pass_blob(std::string_view pass_name) {
    if (db_path_.empty()) return;
    std::error_code ec;
    std::filesystem::remove(pass_blob_path(db_path_, pass_name), ec);
    // Ignore ec: no-op if file doesn't exist.
}

std::vector<TraceIndex::PassBlobInfo> TraceIndex::list_pass_blobs() const {
    std::vector<PassBlobInfo> result;
    if (db_path_.empty()) return result;

    auto dir = pass_cache_dir(db_path_);
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) return result;

    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        auto& p = entry.path();
        if (p.extension() != ".bin") continue;
        PassBlobInfo info;
        info.name = p.stem().string();  // filename without .bin = pass name
        info.size = static_cast<size_t>(entry.file_size(ec));
        if (!ec) result.push_back(std::move(info));
    }
    return result;
}

size_t TraceIndex::delete_all_pass_blobs() {
    if (db_path_.empty()) return 0;

    auto dir = pass_cache_dir(db_path_);
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) return 0;

    size_t count = 0;
    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (entry.path().extension() != ".bin") continue;
        std::error_code rem_ec;
        std::filesystem::remove(entry.path(), rem_ec);
        if (!rem_ec) count++;
    }
    return count;
}

std::filesystem::path TraceIndex::pass_blob_file_path(std::string_view pass_name) const {
    if (db_path_.empty()) return {};
    // Ensure the pass_cache directory exists before returning the path,
    // so callers can immediately open the file for writing.
    auto dir = pass_cache_dir(db_path_);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return {};
    return pass_blob_path(db_path_, pass_name);
}

}  // namespace tenet

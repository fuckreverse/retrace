#include "core/memory_model.h"
#include "common/Profiling.h"
#include "common/logger.h"

#include <rocksdb/write_batch.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>
#include <rocksdb/sst_file_writer.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <numeric>
#include <thread>
#include <unordered_map>

#if defined(TENET_HAS_TBB) && TENET_HAS_TBB
#include <tbb/parallel_sort.h>
#endif

namespace tenet {

// ─── Static thread_local definition ───────────────────────────────────────
thread_local MemoryModel::IteratorPair MemoryModel::tl_iterators_;

// ─── Thread-local page cache (for read_region fast path) ──────────────────
// Caches the last PageWriteIndex pointer to skip mutex + hash map lookup when
// consecutive reads hit the same page (common for try_deref_string chunks).
//
// We hold a shared_ptr<const void> (a type-erased shared_ptr<const
// PageWriteIndex>) rather than a raw pointer so the cached index stays alive
// even if a concurrent LRU eviction on another thread removes it from
// page_index_cache_ — this is what makes read_region() safe to call from
// parallel passes without holding index_cache_mutex_ for the whole read.
struct TLPageCache {
    const void* owner = nullptr;  // &page_index_cache_ of owning MemoryModel
    uint64_t page = UINT64_MAX;
    std::shared_ptr<const void> idx;  // actually shared_ptr<const PageWriteIndex>
};

static TLPageCache& tl_page_cache() {
    static thread_local TLPageCache instance;
    return instance;
}

// ─── Key encoding ─────────────────────────────────────────────────────────
// Key = [page_addr BE(8)] [page_offset BE(2)] [inst_id BE(8)] = 18 bytes
// This ensures RocksDB's byte-wise comparator groups by page, then offset, then time.
// page_offset is the starting offset of the write within the page.

// Stack-local key encoding — zero heap allocation.
// Returns a Slice pointing into the caller-provided 18-byte buffer.
// For the hot path (find_covering_write called per-byte), this eliminates
// millions of std::string constructions during a typical session.
static inline rocksdb::Slice encode_key_to(uint64_t page_addr, uint16_t page_offset,
                                            uint64_t inst_id, char buf[18]) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t pa_be = __builtin_bswap64(page_addr);
    uint64_t id_be = __builtin_bswap64(inst_id);
#else
    uint64_t pa_be = 0, id_be = 0;
    for (int i = 7; i >= 0; --i) pa_be = (pa_be << 8) | ((page_addr >> (i*8)) & 0xFF);
    for (int i = 7; i >= 0; --i) id_be = (id_be << 8) | ((inst_id >> (i*8)) & 0xFF);
#endif
    std::memcpy(buf, &pa_be, 8);
    buf[8] = static_cast<char>((page_offset >> 8) & 0xFF);
    buf[9] = static_cast<char>(page_offset & 0xFF);
    std::memcpy(buf + 10, &id_be, 8);
    return rocksdb::Slice(buf, 18);
}

// Legacy heap-allocating version (kept for compatibility with external callers)
std::string MemoryModel::encode_key(uint64_t page_addr, uint16_t page_offset, uint64_t inst_id) {
    char buf[18];
    encode_key_to(page_addr, page_offset, inst_id, buf);
    return std::string(buf, 18);
}

void MemoryModel::decode_key(const rocksdb::Slice& key,
                              uint64_t& page_addr, uint16_t& page_offset, uint64_t& inst_id) {
    const auto* d = reinterpret_cast<const uint8_t*>(key.data());
    page_addr = 0;
    for (int i = 0; i < 8; i++) page_addr = (page_addr << 8) | d[i];
    page_offset = static_cast<uint16_t>((d[8] << 8) | d[9]);
    inst_id = 0;
    for (int i = 0; i < 8; i++) inst_id = (inst_id << 8) | d[10 + i];
}

// ─── Constructors ─────────────────────────────────────────────────────────

MemoryModel::MemoryModel(const TraceReader& reader, const TraceIndex& index,
                          rocksdb::DB* db, rocksdb::ColumnFamilyHandle* mem_cf,
                          rocksdb::ColumnFamilyHandle* mem_read_cf)
    : reader_(reader), index_(index), db_(db), mem_cf_(mem_cf),
      mem_read_cf_(mem_read_cf),
      has_rocksdb_(db != nullptr && mem_cf != nullptr) {}

MemoryModel::MemoryModel(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index) {}

void MemoryModel::invalidate_thread_iterators() {
// If this thread's cached iterators belong to our DB, invalidate them now.
// This prevents a use-after-free when the DB is closed (e.g., between tests):
// the next MemoryModel that happens to get the same DB pointer would otherwise
// reuse stale iterators that belong to the now-closed DB.
if (has_rocksdb_ && db_ != nullptr) {
auto& pair = tl_iterators_;
if (pair.owner_db == db_) {
pair.write_iter.reset();
pair.read_iter.reset();
pair.owner_db = nullptr;
}
}
}

void MemoryModel::invalidate_tl_page_cache() {
    auto& tl = tl_page_cache();
    if (tl.owner == &page_index_cache_) {
        tl.owner = nullptr;
        tl.page  = UINT64_MAX;
        tl.idx.reset();
    }
}

MemoryModel::~MemoryModel() {
invalidate_thread_iterators();
// Also invalidate the thread-local page cache if it points into our cache.
// This prevents use-after-free when a new MemoryModel is allocated at the
// same address (common in unit tests).
invalidate_tl_page_cache();
}

// ─── Sentinel / persistence detection ─────────────────────────────────────

static constexpr const char* SENTINEL_KEY = "__mem_model_built__";

std::string MemoryModel::compute_trace_fingerprint() const {
    // Fingerprint = schema_version (1 byte) + file_size (8 bytes LE) +
    //               inst_count (8 bytes LE).
    // file_size + inst_count detect whether the trace file has changed.
    // schema_version detects whether the on-disk KV encoding semantics have
    // changed between tenet builds; bump it whenever the stored key/value
    // layout or visibility semantics change so stale indexes are rebuilt.
    //
    // Schema history:
    //   1 = initial time-indexed layout
    //   2 = read-derived entries stored at inst_id-1 (read observed value is
    //       visible at the instruction that read it, not one inst later)
    static constexpr uint8_t kMemModelSchemaVersion = 2;
    uint64_t fsize = reader_.file_size();
    uint64_t icount = index_.inst_count();
    char fp[17];
    fp[0] = static_cast<char>(kMemModelSchemaVersion);
    std::memcpy(fp + 1, &fsize, 8);
    std::memcpy(fp + 9, &icount, 8);
    return std::string(fp, 17);
}

bool MemoryModel::check_persisted_sentinel() const {
    if (!has_rocksdb_ || !db_) return false;

    // Read sentinel from default CF (cf_handles_[0], accessible via db_ directly)
    std::string stored_value;
    auto s = db_->Get(rocksdb::ReadOptions(), SENTINEL_KEY, &stored_value);
    if (!s.ok()) return false;

    auto expected = compute_trace_fingerprint();
    return stored_value == expected;
}

void MemoryModel::write_persisted_sentinel() {
    if (!has_rocksdb_ || !db_) return;

    auto fp = compute_trace_fingerprint();
    rocksdb::WriteOptions wo;
    wo.disableWAL = true;
    db_->Put(wo, SENTINEL_KEY, fp);
}

// ─── Thread-local iterator pool ───────────────────────────────────────────

MemoryModel::IteratorPair& MemoryModel::get_thread_iterators() {
    auto& pair = tl_iterators_;
    // Re-create iterators if they belong to a different DB (or haven't been created yet)
    if (pair.owner_db != db_ && has_rocksdb_) {
        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        pair.write_iter.reset(db_->NewIterator(ro, mem_cf_));
        if (mem_read_cf_) {
            pair.read_iter.reset(db_->NewIterator(ro, mem_read_cf_));
        } else {
            pair.read_iter.reset();
        }
        pair.owner_db = db_;
    }
    return pair;
}

// ─── Build (persist writes to RocksDB) ────────────────────────────────────

void MemoryModel::ensure_built() {
    if (built_) return;
    std::lock_guard<std::mutex> lock(build_mutex_);
    if (built_) return;
    build();
}

void MemoryModel::build(BuildProgressFn progress_fn) {
    TENET_ZONE_NAMED("MemoryModel::build");
    if (built_) return;

    // ─── Opt #1: Check if already persisted from a previous session ──────
    if (has_rocksdb_ && check_persisted_sentinel()) {
        // Data already in RocksDB from last run. Just load page activity cache.
        // We still need to scan the CF for page activity (or load from a cached key).
        // For now, mark built and let active_pages() do lazy scan if needed.
        LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel: using persisted data from previous session (skip rebuild)");
        built_ = true;
        return;
    }

    const uint64_t total_insts = index_.inst_count();
    LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build: starting full trace scan ({} instructions, {})",
             total_insts, has_rocksdb_ ? "RocksDB" : "in-memory");

    if (!has_rocksdb_) {
        // Fallback: in-memory only. Build LRU cache from trace.
        std::unordered_map<uint64_t, std::vector<MemWrite>> page_buckets;

        uint64_t inst_id = 0;
        for (auto it = reader_.begin(); it != reader_.end(); ++it) {
            auto rec = *it;
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto mem = inst.mem_access(m);
                    if (!(mem.type & 0x02)) continue;  // writes only

                    // Skip accesses where QBDI could not capture the value
                    // (bit2 of mem_flags = unknown_value / QBDI_MEMORY_UNKNOWN_VALUE).
                    // Storing a zero/garbage value as 'known' is worse than unknown.
                    if (mem.flags & 0x04) continue;

                    MemWrite mw;
                    mw.inst_id = inst_id;
                    mw.addr = mem.addr;
                    mw.size = static_cast<uint8_t>(std::min<uint64_t>(mem.size, 16));
                    std::memset(mw.data, 0, 16);
                    std::memcpy(mw.data, &mem.value, std::min<uint8_t>(mw.size, 8));
                    if (mw.size > 8) {
                        std::memcpy(mw.data + 8, &mem.value_hi,
                                    std::min<uint8_t>(mw.size - 8, 8));
                    }

                    uint64_t p = page_of(mem.addr);
                    page_buckets[p].push_back(mw);
                    stats_.total_writes_persisted.fetch_add(1, std::memory_order_relaxed);
                }
                inst_id++;
                if ((inst_id & 0xFFFFF) == 0) {  // every ~1M instructions
                    LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build (in-memory): {}/{}  ({:.0f}%)",
                             inst_id, total_insts,
                             100.0 * static_cast<double>(inst_id) / static_cast<double>(total_insts));
                    if (progress_fn) progress_fn(inst_id, total_insts);
                }
            }
        }

        // build() is single-threaded, lock only for consistency
        std::lock_guard<std::mutex> lk(page_cache_mutex_);
        for (auto& [page, writes] : page_buckets) {
            std::sort(writes.begin(), writes.end(),
                      [](const MemWrite& a, const MemWrite& b) {
                          return a.inst_id < b.inst_id;
                      });
            // Populate page_activity_cache_ so active_pages() works in-memory too
            {
                PageActivity pa;
                pa.page_addr = page << kPageShift;
                pa.first_inst_id = writes.front().inst_id;
                pa.last_inst_id  = writes.back().inst_id;
                pa.write_count   = static_cast<uint32_t>(writes.size());
                pa.read_count    = 0;
                page_activity_cache_.push_back(pa);
            }
            page_cache_.put(page, std::move(writes));
        }
        std::sort(page_activity_cache_.begin(), page_activity_cache_.end(),
                  [](const PageActivity& a, const PageActivity& b) {
                      return a.page_addr < b.page_addr;
                  });
        page_activity_cached_ = true;

        LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build: complete (in-memory, {} instructions, {} pages)",
                 inst_id, page_activity_cache_.size());

        built_ = true;
        return;
    }

    // ─── RocksDB path: parallel SST bulk-load ────────────────────────────
    //
    // Strategy: divide the trace into shards at ANCHOR boundaries (using the
    // already-built TraceIndex anchor table), scan each shard in parallel with
    // independent ThreadReaders, buffer KV entries in flat arrays, sort by key,
    // write sorted SST files via SstFileWriter, and bulk-ingest via
    // IngestExternalFile().  This bypasses the MemTable SkipList entirely,
    // which was the dominant bottleneck (~60% of build time) in the previous
    // double-buffered WriteBatch approach.
    //
    // Key format: [page BE(8)] [page_offset BE(2)] [inst_id BE(8)] = 18 bytes
    // Value format: [write_size(1)] [raw_data(write_size)]

    // ── Compact KV entry for buffering + sorting ────────────────────────
    // 36 bytes per entry: 18B key + 1B val_size + 16B val_data + 1B is_read
    struct alignas(4) KVEntry {
        char     key[KEY_SIZE];   // 18 bytes, big-endian encoded
        uint8_t  val_size;        // 1-16 (number of data bytes in val_data)
        uint8_t  val_data[16];    // written/read bytes
        uint8_t  is_read;         // 0 = write (mem_cf_), 1 = read (mem_read_cf_)
    };
    static_assert(sizeof(KVEntry) == 36, "KVEntry must be 36 bytes");

    // ── Shard boundary computation from TraceIndex anchors ──────────────
    struct ShardBounds {
        uint64_t file_start;      // inclusive file offset
        uint64_t file_end;        // exclusive file offset
        uint64_t inst_id_start;   // known inst_id at shard start
    };

    const size_t num_anchors = index_.anchor_table_size();
    const uint64_t file_size = reader_.file_size();
    const uint64_t header_size = sizeof(qbditrace::qbditrace_file_header_t);

    // Determine number of shards: min(hw_threads, 8), need ≥4 anchors/shard.
    uint32_t hw_threads = std::max(1u, std::thread::hardware_concurrency());
    uint32_t num_shards = std::min(hw_threads, 8u);
    if (num_anchors < num_shards * 4) {
        num_shards = std::max(1u, static_cast<uint32_t>(num_anchors / 4));
    }
    if (num_shards == 0) num_shards = 1;

    std::vector<ShardBounds> shard_bounds;
    if (num_shards == 1 || num_anchors == 0) {
        shard_bounds.push_back({header_size, file_size, 0});
        num_shards = 1;
    } else {
        size_t anchors_per_shard = num_anchors / num_shards;
        for (uint32_t s = 0; s < num_shards; s++) {
            size_t anchor_idx = s * anchors_per_shard;
            auto anchor = index_.anchor_table_at(anchor_idx);
            uint64_t fstart = (s == 0) ? header_size : anchor.file_offset;
            uint64_t fend = (s + 1 < num_shards)
                ? index_.anchor_table_at((s + 1) * anchors_per_shard).file_offset
                : file_size;
            uint64_t id_start = (s == 0) ? 0 : anchor.inst_id;
            shard_bounds.push_back({fstart, fend, id_start});
        }
    }

    LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build: {} shards, {} anchors", num_shards, num_anchors);

    // ── Per-shard result container ──────────────────────────────────────
    struct ShardResult {
        ankerl::unordered_dense::map<uint64_t, PageActivity> page_map;
        uint64_t writes_persisted = 0;
        uint64_t insts_scanned = 0;
        std::vector<std::string> write_ssts;
        std::vector<std::string> read_ssts;
        std::string error;
    };

    std::vector<ShardResult> shard_results(num_shards);
    std::atomic<uint64_t> progress_insts{0};

    // SST temp directory: inside the RocksDB index folder
    auto sst_dir = std::filesystem::path(db_->GetName()) / "_mem_sst_tmp";
    std::filesystem::create_directories(sst_dir);

    bool has_read_cf = (mem_read_cf_ != nullptr);

    // ── Shard processor: scan → buffer → sort → SST ────────────────────
    auto process_shard = [&](uint32_t shard_idx) {
        auto& result = shard_results[shard_idx];
        const auto& bounds = shard_bounds[shard_idx];

        result.page_map.reserve(16384);

        // ── Batched SST generation ─────────────────────────────────────
        // To prevent memory blow-up on large traces, we cap in-memory entry
        // buffers and flush them as sorted SST files periodically.  Each
        // batch of 4M entries × 36 bytes = ~144 MB per vector — bounded.
        static constexpr size_t kSstBatchSize = 4'000'000;

        std::vector<KVEntry> write_entries;
        std::vector<KVEntry> read_entries;
        write_entries.reserve(std::min<size_t>(kSstBatchSize, 1'000'000));
        if (has_read_cf) read_entries.reserve(std::min<size_t>(kSstBatchSize, 500'000));

        uint32_t batch_seq = 0;  // SST filename sequence within this shard

        auto key_less = [](const KVEntry& a, const KVEntry& b) noexcept {
            return std::memcmp(a.key, b.key, KEY_SIZE) < 0;
        };

        // Helper: sort a buffer, write one SST file, clear the buffer.
        auto flush_entries = [&](std::vector<KVEntry>& entries,
                                 const char* tag,
                                 std::vector<std::string>& out_ssts) -> rocksdb::Status {
            if (entries.empty()) return rocksdb::Status::OK();

#if defined(TENET_HAS_TBB) && TENET_HAS_TBB
            tbb::parallel_sort(entries.begin(), entries.end(), key_less);
#else
            std::sort(entries.begin(), entries.end(), key_less);
#endif

            rocksdb::Options sst_opts;
            sst_opts.compression = rocksdb::kLZ4Compression;
            rocksdb::SstFileWriter writer(rocksdb::EnvOptions(), sst_opts);

            auto path = sst_dir / (std::string(tag) + "_s"
                        + std::to_string(shard_idx) + "_b"
                        + std::to_string(batch_seq) + ".sst");
            auto s = writer.Open(path.string());
            if (!s.ok()) return s;

            for (const auto& e : entries) {
                uint8_t val_buf[17];
                val_buf[0] = e.val_size;
                std::memcpy(val_buf + 1, e.val_data, e.val_size);

                s = writer.Put(
                    rocksdb::Slice(e.key, KEY_SIZE),
                    rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                   1 + e.val_size));
                if (!s.ok()) return s;
            }

            s = writer.Finish();
            if (s.ok()) out_ssts.push_back(path.string());
            entries.clear();
            return s;
        };

        // Create a thread-local reader for lock-free access.
        auto thread_reader = reader_.create_thread_reader(8);

        // Create an iterator starting at shard's file offset.
        auto it = TraceReader::Iterator(&reader_, bounds.file_start, &thread_reader);
        auto it_end = TraceReader::Iterator(&reader_, bounds.file_end, &thread_reader);

        uint64_t inst_id = bounds.inst_id_start;

        for (; it != it_end; ++it) {
            auto rec = *it;
            if (rec.kind != RecordKind::Inst) continue;

            auto inst = rec.as_inst();
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                bool is_write = (mem.type & 0x02) != 0;
                if (!is_write && !has_read_cf) continue;

                // Skip accesses where QBDI could not capture the value
                // (bit2 of mem_flags = unknown_value / QBDI_MEMORY_UNKNOWN_VALUE).
                // Storing a zero/garbage value as 'known' is worse than unknown.
                if (mem.flags & 0x04) continue;

                uint8_t total_size = static_cast<uint8_t>(std::min<uint64_t>(mem.size, 16));

                // Extract data bytes
                uint8_t all_data[16];
                std::memcpy(all_data, &mem.value, 8);
                std::memcpy(all_data + 8, &mem.value_hi, 8);

                uint64_t acc_addr = mem.addr;
                uint16_t first_page_offset = static_cast<uint16_t>(acc_addr & (kPageSize - 1));
                uint16_t bytes_in_first_page = static_cast<uint16_t>(
                    std::min<uint64_t>(kPageSize - first_page_offset, total_size));

                // Helper: emit one KV entry + track page activity
                auto emit_entry = [&](uint64_t page, uint16_t offset,
                                      const uint8_t* data, uint8_t size, bool is_rd) {
                    KVEntry e;
                    // Visibility semantics: queries use search_id = at_inst_id - 1
                    // and match entries with entry.inst_id <= search_id, i.e. an
                    // entry stored at inst_id K becomes visible at at_inst_id >= K+1.
                    //
                    //  - WRITE at inst N: the new value only exists AFTER N runs, so
                    //    storing it at inst_id = N (visible at at_inst_id >= N+1) is
                    //    correct.
                    //  - READ at inst N: the observed value was already present in
                    //    memory BEFORE/AT N (the read does not modify memory).  To
                    //    make that value visible starting at at_inst_id = N (the very
                    //    instruction that observed it -- which is what a caller
                    //    naturally queries), the read-derived entry is stored at
                    //    inst_id = N-1.  A real write to the same byte at inst N wins
                    //    ties because it is stored at the higher inst_id = N.
                    uint64_t entry_inst_id = inst_id;
                    if (is_rd && entry_inst_id > 0) entry_inst_id -= 1;
                    encode_key_to(page, offset, entry_inst_id, e.key);
                    e.val_size = size;
                    std::memcpy(e.val_data, data, size);
                    if (size < 16) std::memset(e.val_data + size, 0, 16 - size);
                    e.is_read = is_rd ? 1 : 0;

                    if (is_rd) {
                        read_entries.push_back(e);
                    } else {
                        write_entries.push_back(e);
                    }

                    // Track page activity
                    auto [it_pa, inserted] = result.page_map.try_emplace(page, PageActivity{});
                    auto& pa = it_pa->second;
                    if (inserted) {
                        pa.page_addr = page << kPageShift;
                        pa.first_inst_id = inst_id;
                        pa.last_inst_id = inst_id;
                        pa.write_count = 0;
                        pa.read_count = 0;
                    } else {
                        pa.last_inst_id = inst_id;
                    }
                    if (is_rd) pa.read_count++;
                    else pa.write_count++;
                };

                // First (possibly only) page
                emit_entry(page_of(acc_addr), first_page_offset,
                           all_data, bytes_in_first_page, !is_write);

                // Second page (cross-page boundary — rare)
                if (__builtin_expect(bytes_in_first_page < total_size, 0)) {
                    uint8_t remaining = total_size - bytes_in_first_page;
                    emit_entry(page_of(acc_addr + bytes_in_first_page), 0,
                               all_data + bytes_in_first_page, remaining, !is_write);
                }

                if (is_write) result.writes_persisted++;
            }

            inst_id++;
            result.insts_scanned++;

            // Flush buffers when batch threshold reached (prevents OOM on large traces)
            if (write_entries.size() >= kSstBatchSize ||
                read_entries.size() >= kSstBatchSize) {
                auto s = flush_entries(write_entries, "memw", result.write_ssts);
                if (!s.ok()) { result.error = s.ToString(); return; }
                s = flush_entries(read_entries, "memr", result.read_ssts);
                if (!s.ok()) { result.error = s.ToString(); return; }
                batch_seq++;
            }

            if ((inst_id & 0xFFFFF) == 0) {
                progress_insts.fetch_add(0x100000, std::memory_order_relaxed);
            }
        }
        // Flush residual progress
        progress_insts.fetch_add(result.insts_scanned & 0xFFFFF, std::memory_order_relaxed);

        // ── Flush remaining entries ─────────────────────────────────────
        {
            auto s = flush_entries(write_entries, "memw", result.write_ssts);
            if (!s.ok()) { result.error = s.ToString(); return; }
            s = flush_entries(read_entries, "memr", result.read_ssts);
            if (!s.ok()) { result.error = s.ToString(); return; }
        }

        LOG_DEBUG_M(::tenet::log::Module::Core, "MemoryModel shard {}: {} insts, {} writes, {} write SSTs, {} read SSTs",
                  shard_idx, result.insts_scanned, result.writes_persisted,
                  result.write_ssts.size(), result.read_ssts.size());
    };

    // ── Launch parallel shards ──────────────────────────────────────────
    reader_.pin_all();  // prevent LRU eviction during parallel scans
    reader_.advise_sequential();

    if (num_shards == 1) {
        process_shard(0);
        if (progress_fn) progress_fn(total_insts, total_insts);
    } else {
        std::vector<std::thread> workers;
        workers.reserve(num_shards);
        for (uint32_t s = 0; s < num_shards; s++) {
            workers.emplace_back([&, s]() { process_shard(s); });
        }
        // Progress reporting while workers run
        if (progress_fn) {
            while (progress_insts.load(std::memory_order_relaxed) < total_insts) {
                uint64_t done = progress_insts.load(std::memory_order_relaxed);
                progress_fn(done, total_insts);
                LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build (parallel): {}/{}  ({:.0f}%)",
                         done, total_insts,
                         100.0 * static_cast<double>(done) / static_cast<double>(total_insts));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            progress_fn(total_insts, total_insts);
        }
        for (auto& w : workers) w.join();
    }

    reader_.unpin_all();

    // ── Check for shard errors ──────────────────────────────────────────
    for (const auto& r : shard_results) {
        if (!r.error.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(sst_dir, ec);
            LOG_ERROR_M(::tenet::log::Module::Core, "MemoryModel::build shard failed: {}", r.error);
            built_ = true;  // mark built to prevent retry loops
            return;
        }
    }

    // ── Phase 2: Ingest SST files into RocksDB ─────────────────────────
    // IngestExternalFile() moves SSTs directly into L0, bypassing MemTable,
    // WAL, and compaction.  O(N) in file count, not entry count.
    {
        rocksdb::IngestExternalFileOptions ingest_opts;
        ingest_opts.move_files = true;
        ingest_opts.snapshot_consistency = false;
        ingest_opts.allow_global_seqno = true;
        ingest_opts.allow_blocking_flush = false;

        // Helper: collect SST paths from all shards, filter empty files, ingest.
        auto ingest_cf = [&](rocksdb::ColumnFamilyHandle* cf_handle,
                             auto sst_getter) -> rocksdb::Status {
            if (!cf_handle) return rocksdb::Status::OK();
            std::vector<std::string> all_ssts;
            for (auto& r : shard_results) {
                for (auto& p : sst_getter(r)) {
                    std::error_code fec;
                    auto fsize = std::filesystem::file_size(p, fec);
                    if (!fec && fsize > 0) all_ssts.push_back(std::move(p));
                }
            }
            if (all_ssts.empty()) return rocksdb::Status::OK();
            return db_->IngestExternalFile(cf_handle, all_ssts, ingest_opts);
        };

        auto s = ingest_cf(mem_cf_,
                           [](ShardResult& r) -> auto& { return r.write_ssts; });
        if (!s.ok()) {
            LOG_ERROR_M(::tenet::log::Module::Core, "MemoryModel::build: ingest mem_write failed: {}", s.ToString());
        }

        s = ingest_cf(mem_read_cf_,
                      [](ShardResult& r) -> auto& { return r.read_ssts; });
        if (!s.ok()) {
            LOG_ERROR_M(::tenet::log::Module::Core, "MemoryModel::build: ingest mem_read failed: {}", s.ToString());
        }
    }

    // Clean up temp SST directory
    {
        std::error_code ec;
        std::filesystem::remove_all(sst_dir, ec);
    }

    // ── Phase 2b: Compact MEM_WRITE and MEM_READ CFs ───────────────────
    // After SST ingest, all data sits in L0 where key ranges overlap across
    // shards.  Each prefix-seek query must check every L0 file, causing
    // massive read amplification.  CompactRange merges L0 into leveled SSTs
    // with non-overlapping key ranges, reducing query cost to 1 file/level.
    // This also consolidates many small SST files into fewer large ones,
    // keeping the total open-file count well within max_open_files.
    {
        rocksdb::CompactRangeOptions cro;
        cro.bottommost_level_compaction =
            rocksdb::BottommostLevelCompaction::kForceOptimized;

        // Run both compactions in parallel (each can take seconds on large traces).
        auto compact_cf = [&](rocksdb::ColumnFamilyHandle* cf) {
            if (cf) {
                auto cs = db_->CompactRange(cro, cf, nullptr, nullptr);
                if (!cs.ok()) {
                    LOG_WARN_M(::tenet::log::Module::Core, "MemoryModel CompactRange failed: {}", cs.ToString());
                }
            }
        };

        if (mem_cf_ && mem_read_cf_) {
            std::thread t1([&]() { compact_cf(mem_cf_); });
            compact_cf(mem_read_cf_);
            t1.join();
        } else {
            compact_cf(mem_cf_);
            compact_cf(mem_read_cf_);
        }

        LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build: compaction complete");
    }

    // ── Phase 3: Merge page activity from all shards ────────────────────
    uint64_t total_writes_persisted = 0;
    {
        ankerl::unordered_dense::map<uint64_t, PageActivity> merged_map;
        merged_map.reserve(65536);
        for (auto& r : shard_results) {
            total_writes_persisted += r.writes_persisted;
            for (auto& [page, pa] : r.page_map) {
                auto [it_m, inserted] = merged_map.try_emplace(page, pa);
                if (!inserted) {
                    auto& m = it_m->second;
                    m.first_inst_id = std::min(m.first_inst_id, pa.first_inst_id);
                    m.last_inst_id = std::max(m.last_inst_id, pa.last_inst_id);
                    m.write_count += pa.write_count;
                    m.read_count += pa.read_count;
                }
            }
        }
        page_activity_cache_.reserve(merged_map.size());
        for (auto& [_, pa] : merged_map) {
            page_activity_cache_.push_back(pa);
        }
    }
    std::sort(page_activity_cache_.begin(), page_activity_cache_.end(),
              [](const PageActivity& a, const PageActivity& b) {
                  return a.page_addr < b.page_addr;
              });
    page_activity_cached_ = true;

    stats_.total_writes_persisted.store(total_writes_persisted, std::memory_order_relaxed);

    // Opt #1: Write sentinel so next session skips rebuild
    write_persisted_sentinel();

    LOG_INFO_M(::tenet::log::Module::Core, "MemoryModel::build: complete ({} instructions, {} writes persisted, "
             "{} pages, {} shards)",
             total_insts, total_writes_persisted,
             page_activity_cache_.size(), num_shards);

    built_ = true;
}

// ─── RocksDB query: find last write covering a byte ───────────────────────

void MemoryModel::find_covering_write(rocksdb::Iterator* iter,
                                       uint64_t page, uint16_t target_offset,
                                       uint64_t at_inst_id,
                                       MemReadResult& out, uint8_t result_index) {
    char seek_key_buf[KEY_SIZE];
    auto seek_key = encode_key_to(page, target_offset, at_inst_id, seek_key_buf);
    iter->SeekForPrev(seek_key);

    uint16_t min_offset = (target_offset >= (MAX_WRITE_SIZE - 1))
                              ? static_cast<uint16_t>(target_offset - (MAX_WRITE_SIZE - 1))
                              : 0;

    while (iter->Valid()) {
        if (iter->key().size() != KEY_SIZE) break;

        uint64_t found_page;
        uint16_t found_offset;
        uint64_t found_inst_id;
        decode_key(iter->key(), found_page, found_offset, found_inst_id);

        // Moved past our page — done
        if (found_page != page) break;

        // Offset too far back — no write starting here can reach target_offset
        if (found_offset < min_offset) break;

        // Skip entries with inst_id > at_inst_id
        if (found_inst_id > at_inst_id) {
            iter->Prev();
            continue;
        }

        // Parse value: [write_size(1)] [data(write_size)]
        auto val = iter->value();
        if (val.size() < 1) {
            iter->Prev();
            continue;
        }
        uint8_t write_size = static_cast<uint8_t>(val.data()[0]);

        // Check if this write covers target_offset
        if (found_offset <= target_offset &&
            static_cast<uint16_t>(found_offset + write_size) > target_offset) {
            // Found it! Extract the byte value.
            uint8_t byte_index_in_write = static_cast<uint8_t>(target_offset - found_offset);
            if (val.size() >= static_cast<size_t>(1 + byte_index_in_write + 1)) {
                out.data[result_index] = static_cast<uint8_t>(val.data()[1 + byte_index_in_write]);
                out.known[result_index] = true;
                out.writer_id[result_index] = found_inst_id;
            }
            stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        iter->Prev();
    }

    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
}

// ─── Public query methods ─────────────────────────────────────────────────

MemReadResult MemoryModel::read(uint64_t addr, uint8_t size, uint64_t at_inst_id) {
    MemReadResult result{};
    if (size == 0 || size > 16) return result;

    ensure_built();

    // at_inst_id is exclusive: find the most recent write with inst_id < at_inst_id.
    // This matches the "state before instruction at_inst_id executes" semantics used
    // everywhere in tenet (state_before, last_writer, etc.).
    // When at_inst_id == 0, no writes have occurred yet → result is all-unknown.
    if (at_inst_id == 0) return result;

    if (has_rocksdb_) {
        // Optimised path: use index_read_range() for batch reading with
        // thread-local page cache to skip mutex on repeated same-page hits.
        //
        // For the common case where all requested bytes are on the same page
        // (which is almost always true for 1-16 byte reads), we do a single
        // index_read_range() call. The thread-local page cache avoids the
        // mutex + hash lookup when consecutive reads hit the same page (the
        // dominant pattern in VM abstract pass: reading ctx fields, VM
        // registers, and stack slots all from the same vm_ctx page).
        auto& iters = get_thread_iterators();
        const uint64_t search_id = at_inst_id - 1;
        auto& tl_page = tl_page_cache();

        uint8_t offset = 0;
        while (offset < size) {
            uint64_t byte_addr   = addr + offset;
            uint64_t page        = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (kPageSize - 1));

            // How many bytes remain on this page from page_offset?
            uint16_t bytes_on_page = static_cast<uint16_t>(kPageSize - page_offset);
            uint8_t chunk = static_cast<uint8_t>(
                std::min<uint16_t>(bytes_on_page, static_cast<uint16_t>(size - offset)));

            // Get (or load) the PageWriteIndex for this page.
            std::shared_ptr<const PageWriteIndex> idx_ptr;

            // Fast path: same page as last lookup AND same MemoryModel instance.
            // The thread-local cache holds a shared_ptr copy of the index, so it
            // stays valid even if a concurrent LRU eviction removes it from
            // page_index_cache_ — no generation check needed.
            if (tl_page.owner == &page_index_cache_ &&
                page == tl_page.page && tl_page.idx) {
                idx_ptr = std::static_pointer_cast<const PageWriteIndex>(tl_page.idx);
            }

            if (!idx_ptr) {
                // Slow path: shared_lock + peek (no promote, no exclusive lock).
                // page_index_cache_ stores shared_ptr<const PageWriteIndex> which
                // is immutable once loaded, so concurrent readers are safe.
                {
                    std::shared_lock<std::shared_mutex> lk(index_cache_mutex_);
                    if (const auto* p = page_index_cache_.peek(page)) idx_ptr = *p;
                }
                if (!idx_ptr) {
                    idx_ptr = load_page_index(page,
                                              iters.write_iter.get(),
                                              iters.read_iter.get());
                }
                // Update thread-local cache.
                if (idx_ptr) {
                    tl_page.owner = &page_index_cache_;
                    tl_page.page = page;
                    tl_page.idx = std::static_pointer_cast<const void>(idx_ptr);
                }
            }

            if (idx_ptr) {
                // Batch read: one upper_bound + one reverse scan for all
                // `chunk` bytes, instead of `chunk` independent queries.
                uint8_t  buf_data[16];
                bool     buf_known[16];
                size_t known = index_read_range(
                    *idx_ptr, page_offset, chunk, search_id,
                    buf_data, buf_known);

                for (uint8_t i = 0; i < chunk; ++i) {
                    if (buf_known[i]) {
                        result.data[offset + i]     = buf_data[i];
                        result.known[offset + i]    = true;
                        // writer_id not available from index_read_range;
                        // leave as default (0). This field is only used by
                        // last_writer() and debug tools, not by read() callers.
                    }
                }
                if (known > 0) {
                    stats_.cache_hits.fetch_add(known, std::memory_order_relaxed);
                }
                if (known < chunk) {
                    stats_.rocksdb_reads.fetch_add(chunk - known,
                                                   std::memory_order_relaxed);
                }
            }

            offset += chunk;
        }
    } else {
        return read_inmemory(addr, size, at_inst_id);
    }

    return result;
}

// ─── Per-Page Sorted Write Index ──────────────────────────────────────────
//
// load_page_index() does a single forward RocksDB scan over all writes (and
// optionally reads) for a given page, building a vector of PageWriteEntry
// sorted by (page_offset, inst_id).  The result is inserted into the LRU
// page_index_cache_ so subsequent queries for the same page never touch
// RocksDB again.
//
// index_read_byte() uses std::upper_bound to find the last write at or before
// search_id that covers the target byte, in O(log W) comparisons.

std::shared_ptr<const MemoryModel::PageWriteIndex>
MemoryModel::load_page_index(uint64_t page,
                              rocksdb::Iterator* write_iter,
                              rocksdb::Iterator* read_iter) {
    if (!has_rocksdb_ || !write_iter) return nullptr;

    PageWriteIndex idx;

    // Helper: forward-scan one CF from the first key on `page` to the last.
    auto scan_cf = [&](rocksdb::Iterator* it) {
        if (!it) return;

        // Seek to the first key belonging to this page.
        char seek_buf[KEY_SIZE];
        auto first_key = encode_key_to(page, 0, 0, seek_buf);
        it->Seek(first_key);

        while (it->Valid()) {
            if (it->key().size() != KEY_SIZE) break;

            uint64_t found_page;
            uint16_t found_offset;
            uint64_t found_inst_id;
            decode_key(it->key(), found_page, found_offset, found_inst_id);

            if (found_page != page) break;  // past this page

            auto val = it->value();
            if (val.size() >= 2) {
                PageWriteEntry e;
                e.page_offset = found_offset;
                e.inst_id     = found_inst_id;
                e.size        = static_cast<uint8_t>(val.data()[0]);
                e._pad        = 0;
                if (e.size > 16) e.size = 16;
                // Clamp write to page boundary: a write starting at found_offset
                // with size e.size may not exceed kPageSize.
                uint16_t max_size = static_cast<uint16_t>(kPageSize - found_offset);
                if (e.size > max_size) e.size = static_cast<uint8_t>(max_size);
                // Guard against truncated value (should not happen with a correct
                // build, but defend against DB corruption / partial writes).
                size_t avail = val.size() - 1;  // bytes actually present after size byte
                if (avail < e.size) e.size = static_cast<uint8_t>(avail);
                if (e.size > 0) {
                    std::memset(e.data, 0, 16);
                    std::memcpy(e.data, val.data() + 1, e.size);
                    idx.push_back(e);
                }
                // If e.size == 0, skip (don't push) but still advance below.
            }

            it->Next();
        }
    };

    scan_cf(write_iter);
    scan_cf(read_iter);  // read-fallback entries

    // Sort by (page_offset, inst_id) ascending.
    std::sort(idx.begin(), idx.end(), PageWriteEntryLess{});

    // Store in LRU cache and return a shared_ptr copy.
    // unique_lock: put() mutates the LRU (eviction/promote).
    std::unique_lock<std::shared_mutex> lk(index_cache_mutex_);
    page_index_cache_.put(page, std::make_shared<PageWriteIndex>(std::move(idx)));
    const auto* cached = page_index_cache_.peek(page);
    return cached ? *cached : nullptr;
}

bool MemoryModel::index_read_byte(const PageWriteIndex& idx,
                                   uint16_t page_offset,
                                   uint64_t search_id,
                                   uint8_t& out_value,
                                   uint64_t& out_writer) noexcept {
    if (idx.empty()) return false;

    // We want the last entry with (page_offset_of_write <= page_offset) AND
    // (inst_id <= search_id) whose write covers page_offset.
    //
    // A write starting at `e.page_offset` with size `e.size` covers
    // page_offset iff:
    //   e.page_offset <= page_offset < e.page_offset + e.size
    // i.e. page_offset - e.page_offset < e.size (unsigned)
    //
    // Because writes may span up to MAX_WRITE_SIZE bytes (16), we only need
    // to look back at most 15 offsets before page_offset.
    const uint16_t min_start = (page_offset >= (MAX_WRITE_SIZE - 1))
                                   ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                   : 0;

    // upper_bound for the exclusive upper limit: (page_offset, search_id+1)
    // gives us an iterator past all entries with (page_offset <= page_offset
    // AND inst_id <= search_id).  We then walk backwards.
    auto end_it = std::upper_bound(idx.begin(), idx.end(),
                                   std::make_pair(page_offset, search_id),
                                   PageWriteEntryLess{});

    // Walk backwards from end_it — we want the most-recent write that covers
    // `page_offset`.  Because entries are sorted ascending by offset then
    // inst_id, the highest inst_id entries come last within each offset group.
    if (end_it == idx.begin()) return false;

    // Track the best (highest inst_id) covering write found so far.
    // We cannot return at the first hit because the index sorts by
    // (page_offset ASC, inst_id ASC) — a write at a smaller offset with a
    // higher inst_id may appear later in the backward scan and should win.
    // Example: (offset=0, inst_id=100, size=8) wins over (offset=4, inst_id=80, size=4)
    // for byte at offset=5, even though offset=4 entry is encountered first in
    // the backward scan.
    bool found = false;
    uint64_t best_id = 0;  // 0 is valid; use `found` to distinguish "no hit yet"

    auto it = end_it;
    while (it != idx.begin()) {
        --it;

        // Stop if we've gone past the valid offset window.
        if (it->page_offset < min_start) break;

        // Skip entries whose inst_id is too new (shouldn't happen after
        // upper_bound, but guard against boundary edge cases).
        if (it->inst_id > search_id) continue;

        // Once we have a winner, skip any entry strictly older than it.
        // (An entry with the same inst_id at a different offset cannot win because
        // a single instruction cannot write two overlapping locations with the same id.)
        if (found && it->inst_id < best_id) continue;

        // Check coverage: does this write reach page_offset?
        uint16_t end_off = static_cast<uint16_t>(it->page_offset + it->size);
        if (it->page_offset <= page_offset && page_offset < end_off) {
            if (!found || it->inst_id > best_id) {
                uint8_t byte_idx = static_cast<uint8_t>(page_offset - it->page_offset);
                out_value  = it->data[byte_idx];
                out_writer = it->inst_id;
                best_id    = it->inst_id;
                found      = true;
            }
        }
    }

    return found;
}

// ─── Batch range read (single reverse scan) ──────────────────────────────
//
// For reading N contiguous bytes on the same page at the same time point,
// doing N independent upper_bound + backward scans is O(N log W) where W is
// the page write count.  This method does a single backward scan from the
// upper bound of the LAST byte in the range, resolving all bytes in one pass.
// Complexity: O(log W + S) where S is the number of write entries in the
// [start_offset - 15, start_offset + count - 1] window.

size_t MemoryModel::index_read_range(const PageWriteIndex& idx,
                                      uint16_t start_offset,
                                      uint16_t count,
                                      uint64_t search_id,
                                      uint8_t* out_data,
                                      bool* out_known) noexcept {
    if (idx.empty() || count == 0) return 0;

    std::memset(out_known, 0, count * sizeof(bool));
    size_t known_count = 0;

    // The last byte offset in the range.
    const uint16_t end_offset = static_cast<uint16_t>(start_offset + count - 1);

    // A write at page_offset P with size S covers bytes [P, P+S-1].
    // To cover any byte in [start_offset, end_offset], a write must satisfy:
    //   P <= end_offset (its start is at or before our last byte)
    //   P + S > start_offset (it extends past our first byte)
    // The minimum P we need to consider is: start_offset - (MAX_WRITE_SIZE - 1)
    const uint16_t min_start = (start_offset >= (MAX_WRITE_SIZE - 1))
                                   ? static_cast<uint16_t>(start_offset - (MAX_WRITE_SIZE - 1))
                                   : 0;

    // upper_bound past the last relevant entry: any write starting after
    // end_offset can't cover our range.  We search for (end_offset, search_id).
    auto scan_end = std::upper_bound(idx.begin(), idx.end(),
                                      std::make_pair(end_offset, search_id),
                                      PageWriteEntryLess{});

    if (scan_end == idx.begin()) return 0;

    // Track per-byte winning inst_id to resolve ordering across different
    // page_offset groups.  The index sorts by (page_offset ASC, inst_id ASC),
    // so a backward scan does NOT guarantee we see the highest inst_id first
    // when writes at different offsets interleave in time.  For example, a
    // write at offset=0, inst_id=100, size=8 may cover bytes 4-7 but be seen
    // AFTER a write at offset=4, inst_id=80, size=4 — so the "first seen wins"
    // approach would incorrectly keep the older write for bytes 4-7.
    // Solution: track the highest inst_id seen per byte and overwrite when a
    // newer entry is found.  `count` is bounded by kPageSize (4096 bytes);
    // use a stack buffer that fits the typical small case (≤16B from read())
    // and falls back to a heap buffer for larger read_region() calls.
    constexpr uint16_t kSmallBuf = 64;
    uint64_t small_best[kSmallBuf];
    std::unique_ptr<uint64_t[]> heap_best;
    uint64_t* best_inst_id;
    if (count <= kSmallBuf) {
        std::memset(small_best, 0, count * sizeof(uint64_t));
        best_inst_id = small_best;
    } else {
        heap_best = std::make_unique<uint64_t[]>(count);
        best_inst_id = heap_best.get();
        // make_unique<uint64_t[]> value-initializes (zero-initializes) the array
    }

    auto it = scan_end;
    while (it != idx.begin()) {
        --it;

        // Stop when we're past the relevant offset window.
        if (it->page_offset < min_start) break;

        // Skip writes that are newer than our search point.
        if (it->inst_id > search_id) continue;

        // Determine byte coverage overlap with [start_offset, end_offset].
        uint16_t write_start = it->page_offset;
        uint16_t write_end   = static_cast<uint16_t>(write_start + it->size); // exclusive

        // Intersect [write_start, write_end) with [start_offset, start_offset+count)
        uint16_t overlap_begin = std::max(write_start, start_offset);
        uint16_t overlap_end   = std::min(write_end, static_cast<uint16_t>(start_offset + count));

        if (overlap_begin >= overlap_end) continue;

        // For each covered byte, keep the value from the highest inst_id write.
        // Note: best_inst_id[] is zero-initialized and inst_id 0 is valid,
        // so we use !out_known[] as the "no winner yet" sentinel and only
        // apply the inst_id comparison when a previous winner exists.
        for (uint16_t b = overlap_begin; b < overlap_end; ++b) {
            size_t result_idx = b - start_offset;
            if (!out_known[result_idx] || it->inst_id > best_inst_id[result_idx]) {
                uint8_t byte_in_write = static_cast<uint8_t>(b - write_start);
                out_data[result_idx]     = it->data[byte_in_write];
                best_inst_id[result_idx] = it->inst_id;
                if (!out_known[result_idx]) {
                    out_known[result_idx] = true;
                    ++known_count;
                }
            }
        }

        // Early exit: all bytes resolved and no earlier write can beat them
        // (entries are sorted by page_offset ASC then inst_id ASC, so further
        // backward steps may still have higher inst_ids at smaller offsets).
        // We cannot early-exit until min_start is reached.
    }

    return known_count;
}

// ─── In-memory fallback helpers ──────────────────────────────────────────
// These methods implement the non-RocksDB query paths using page_cache_.
// Each acquires page_cache_mutex_ internally, matching the original inline code.

MemReadResult MemoryModel::read_inmemory(uint64_t addr, uint8_t size, uint64_t at_inst_id) {
    MemReadResult result{};
    std::lock_guard<std::mutex> lk(page_cache_mutex_);
    for (uint8_t i = 0; i < size; i++) {
        uint64_t byte_addr = addr + i;
        uint64_t page = page_of(byte_addr);

        auto* writes = page_cache_.get_mutable(page);
        if (!writes) continue;

        stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);

        // Scan from newest to oldest to find last write covering this byte.
        // at_inst_id is exclusive: we want inst_id < at_inst_id ("before" semantics),
        // matching the RocksDB path which uses search_id = at_inst_id - 1.
        const MemWrite* best = nullptr;
        for (auto rit = writes->rbegin(); rit != writes->rend(); ++rit) {
            if (rit->inst_id >= at_inst_id) continue;
            // Check if this write covers our byte
            if (byte_addr >= rit->addr && byte_addr < rit->addr + rit->size) {
                best = &(*rit);
                break;
            }
        }

        if (best) {
            uint8_t offset_in_write = static_cast<uint8_t>(byte_addr - best->addr);
            result.data[i] = best->data[offset_in_write];
            result.known[i] = true;
            result.writer_id[i] = best->inst_id;
        }
    }
    return result;
}

uint64_t MemoryModel::last_writer_inmemory(uint64_t addr, uint8_t size, uint64_t search_id) {
    uint64_t latest_writer = 0;
    std::lock_guard<std::mutex> lk(page_cache_mutex_);
    for (uint8_t i = 0; i < size; i++) {
        uint64_t byte_addr = addr + i;
        uint64_t page = page_of(byte_addr);

        auto* writes = page_cache_.get_mutable(page);
        if (!writes) continue;

        for (auto rit = writes->rbegin(); rit != writes->rend(); ++rit) {
            if (rit->inst_id > search_id) continue;
            if (byte_addr >= rit->addr && byte_addr < rit->addr + rit->size) {
                latest_writer = std::max(latest_writer, rit->inst_id);
                break;
            }
        }
    }
    return latest_writer;
}

std::vector<uint64_t> MemoryModel::write_history_inmemory(uint64_t addr, uint8_t size) {
    std::vector<uint64_t> result;
    std::lock_guard<std::mutex> lk(page_cache_mutex_);
    uint64_t page = page_of(addr);
    auto* writes = page_cache_.get_mutable(page);
    if (writes) {
        for (const auto& w : *writes) {
            if (addr >= w.addr && addr < w.addr + w.size) {
                result.push_back(w.inst_id);
            }
        }
    }
    return result;
}

std::optional<uint8_t> MemoryModel::byte_at_inmemory(uint64_t addr, uint64_t at_inst_id) {
    std::lock_guard<std::mutex> lk(page_cache_mutex_);
    uint64_t page = page_of(addr);
    auto* writes = page_cache_.get_mutable(page);
    if (!writes) return std::nullopt;

    for (auto rit = writes->rbegin(); rit != writes->rend(); ++rit) {
        // at_inst_id is exclusive: inst_id < at_inst_id ("before" semantics),
        // matching the RocksDB path which uses search_id = at_inst_id - 1.
        if (rit->inst_id >= at_inst_id) continue;
        if (addr >= rit->addr && addr < rit->addr + rit->size) {
            uint8_t offset = static_cast<uint8_t>(addr - rit->addr);
            return rit->data[offset];
        }
    }

    return std::nullopt;
}

bool MemoryModel::was_accessed_inmemory(uint64_t addr) {
    std::lock_guard<std::mutex> lk(page_cache_mutex_);
    uint64_t page = page_of(addr);
    return page_cache_.get_mutable(page) != nullptr;
}

// ─── Extended API implementations ─────────────────────────────────────────

// Opt #2 + PageWriteIndex fast path:
// read_region first checks the per-page sorted-vector index (O(log W) per byte).
// On a cache miss it loads the whole page from RocksDB in one forward scan and
// caches it, so subsequent queries for the same page never touch RocksDB again.
MemoryModel::RegionReadResult MemoryModel::read_region(uint64_t addr, size_t size, uint64_t at_inst_id) {
    RegionReadResult result;
    result.data.resize(size, 0);
    result.known.resize(size, false);
    result.known_count = 0;

    if (size == 0) return result;
    ensure_built();

    if (!has_rocksdb_) {
        // In-memory fallback: use read() in chunks
        constexpr size_t chunk_size = 16;
        for (size_t off = 0; off < size; off += chunk_size) {
            size_t remaining = size - off;
            uint8_t read_size = static_cast<uint8_t>(std::min(remaining, chunk_size));
            MemReadResult mr = read(addr + off, read_size, at_inst_id);
            for (uint8_t i = 0; i < read_size; ++i) {
                result.data[off + i] = mr.data[i];
                result.known[off + i] = mr.known[i];
                if (mr.known[i]) result.known_count++;
            }
        }
        return result;
    }

    if (at_inst_id == 0) return result;
    const uint64_t search_id = at_inst_id - 1;

    // Get thread-local iterators (needed for load_page_index on cache miss).
    auto& iters = get_thread_iterators();

    // Thread-local page cache (defined at file scope, see TLPageCache above).
    auto& tl_page = tl_page_cache();

    // Process each byte via the PageWriteIndex fast path.
    // We group consecutive bytes on the same page to avoid redundant cache
    // lookups: load the page index once, then resolve all bytes on that page.
    size_t off = 0;
    while (off < size) {
        uint64_t byte_addr = addr + off;
        uint64_t page      = page_of(byte_addr);

        // --- Get (or load) the PageWriteIndex for this page ---------------
        std::shared_ptr<const PageWriteIndex> idx_ptr;

        // Fast path: same page as last lookup AND same MemoryModel instance.
        // The thread-local cache holds a shared_ptr copy of the index, so it
        // stays valid even if a concurrent LRU eviction removes it from
        // page_index_cache_ — no generation check needed.
        if (tl_page.owner == &page_index_cache_ &&
            page == tl_page.page && tl_page.idx) {
            idx_ptr = std::static_pointer_cast<const PageWriteIndex>(tl_page.idx);
        } else {
            {
                std::shared_lock<std::shared_mutex> lk(index_cache_mutex_);
                if (const auto* p = page_index_cache_.peek(page)) idx_ptr = *p;
            }
            if (!idx_ptr) {
                // Cache miss: load whole page from RocksDB (one forward scan).
                // load_page_index acquires index_cache_mutex_ internally.
                idx_ptr = load_page_index(page,
                                          iters.write_iter.get(),
                                          iters.read_iter.get());
            }
            // Cache the shared_ptr (not a raw pointer) so the index survives
            // across evictions while this thread keeps using it.
            tl_page.owner = &page_index_cache_;
            tl_page.page  = page;
            tl_page.idx   = std::static_pointer_cast<const void>(idx_ptr);
        }

        // Resolve all bytes on this page using batch range read.
        uint64_t page_base = page << kPageShift;
        uint64_t page_end  = page_base + kPageSize;

        // How many bytes of our request fall on this page?
        uint16_t page_off_start = static_cast<uint16_t>((addr + off) & (kPageSize - 1));
        size_t bytes_on_page = std::min(
            size - off,
            static_cast<size_t>(page_end - (addr + off)));
        uint16_t chunk_count = static_cast<uint16_t>(bytes_on_page);

        if (idx_ptr && chunk_count > 0) {
            // Use batch range read: single upper_bound + one reverse scan
            // instead of chunk_count individual upper_bound calls.
            // vector<bool> can't give us a bool* directly, so use a stack buffer.
            bool known_buf[4096];  // max page size

            size_t resolved = index_read_range(
                *idx_ptr, page_off_start, chunk_count, search_id,
                result.data.data() + off,
                known_buf);

            for (uint16_t i = 0; i < chunk_count; ++i) {
                if (known_buf[i]) {
                    result.known[off + i] = true;
                    result.known_count++;
                }
            }
            stats_.cache_hits.fetch_add(resolved, std::memory_order_relaxed);
        }
        // If idx_ptr is null (RocksDB unavailable for this page), all bytes
        // remain unknown — consistent with the previous behaviour.

        off += bytes_on_page;
    }

    return result;
}

// ─── Batch read: page-sorted multi-region read ────────────────────────────
//
// Collects all requests, sorts them by page so that accesses to the same
// page share one PageWriteIndex load (the thread-local page cache turns
// subsequent same-page hits into O(1) pointer chases).  Results are
// returned in input order.
//
// The page-sorted execution order is the key win: N scattered read_region()
// calls that touch only K distinct pages (K << N, e.g. ObjC selector
// strings, syscall key buffers) perform K RocksDB forward scans instead of
// N, and the thread-local page cache makes the remaining N-K hits free.
std::vector<MemoryModel::RegionReadResult>
MemoryModel::read_batch(const std::vector<ReadRequest>& requests) {
    const size_t n = requests.size();
    std::vector<RegionReadResult> results(n);
    if (n == 0) return results;

    // Sort an index array by (page, at_inst_id) for locality.
    std::vector<size_t> order(n);
    std::iota(order.begin(), order.end(), 0);
    auto page_key = [&](size_t i) {
        return (page_of(requests[i].addr) << 20) ^ requests[i].at_inst_id;
    };
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return page_key(a) < page_key(b);
    });

    // Execute in page-sorted order; store results at original indices.
    for (size_t sorted_idx : order) {
        const auto& req = requests[sorted_idx];
        results[sorted_idx] = read_region(req.addr, req.size, req.at_inst_id);
    }

    return results;
}

MemoryModel::RegionReadResult MemoryModel::read_region_impl(
    uint64_t addr, size_t size, uint64_t at_inst_id,
    rocksdb::Iterator* write_iter, rocksdb::Iterator* read_iter) {

    RegionReadResult result;
    result.data.resize(size, 0);
    result.known.resize(size, false);
    result.known_count = 0;

    if (size == 0) return result;
    // at_inst_id == 0 means before any instruction — nothing written yet.
    if (at_inst_id == 0) return result;

    // Exclusive semantics: find writes with inst_id < at_inst_id.
    const uint64_t search_id = at_inst_id - 1;

    // Process in 16-byte chunks but reuse the provided iterators
    constexpr size_t chunk_size = 16;
    for (size_t off = 0; off < size; off += chunk_size) {
        size_t remaining = size - off;
        uint8_t read_size = static_cast<uint8_t>(std::min(remaining, chunk_size));
        uint64_t chunk_addr = addr + off;

        // --- Phase 1: resolve from write CF ---
        for (uint8_t i = 0; i < read_size; ) {
            uint64_t byte_addr = chunk_addr + i;
            uint64_t page = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (kPageSize - 1));

            char seek_key_buf[KEY_SIZE];
            auto seek_key = encode_key_to(page, page_offset, search_id, seek_key_buf);
            write_iter->SeekForPrev(seek_key);

            uint16_t min_offset = (page_offset >= (MAX_WRITE_SIZE - 1))
                                      ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                      : 0;

            bool found = false;
            while (write_iter->Valid()) {
                if (write_iter->key().size() != KEY_SIZE) break;

                uint64_t found_page;
                uint16_t found_offset;
                uint64_t found_inst_id;
                decode_key(write_iter->key(), found_page, found_offset, found_inst_id);

                if (found_page != page) break;
                if (found_offset < min_offset) break;
                if (found_inst_id > search_id) {
                    write_iter->Prev();
                    continue;
                }

                auto val = write_iter->value();
                if (val.size() < 1) { write_iter->Prev(); continue; }
                uint8_t write_size_val = static_cast<uint8_t>(val.data()[0]);

                if (found_offset <= page_offset &&
                    static_cast<uint16_t>(found_offset + write_size_val) > page_offset) {
                    uint16_t write_end = static_cast<uint16_t>(found_offset + write_size_val);
                    for (uint8_t j = i; j < read_size; j++) {
                        uint64_t baddr = chunk_addr + j;
                        if (page_of(baddr) != page) break;
                        uint16_t boff = static_cast<uint16_t>(baddr & (kPageSize - 1));
                        if (boff >= write_end) break;
                        if (boff < found_offset) break;

                        uint8_t idx_in_write = static_cast<uint8_t>(boff - found_offset);
                        if (val.size() >= static_cast<size_t>(1 + idx_in_write + 1)) {
                            result.data[off + j] = static_cast<uint8_t>(val.data()[1 + idx_in_write]);
                            result.known[off + j] = true;
                            result.known_count++;
                        }
                    }
                    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                    found = true;
                    break;
                }

                write_iter->Prev();
            }

            if (!found) {
                stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
            }

            i++;
            while (i < read_size && result.known[off + i]) i++;
        }

        // --- Phase 2: read-fallback for unresolved bytes ---
        if (read_iter) {
            for (uint8_t i = 0; i < read_size; ) {
                if (result.known[off + i]) { i++; continue; }

                uint64_t byte_addr = chunk_addr + i;
                uint64_t page = page_of(byte_addr);
                uint16_t page_offset = static_cast<uint16_t>(byte_addr & (kPageSize - 1));

                char seek_key_buf[KEY_SIZE];
                auto seek_key = encode_key_to(page, page_offset, search_id, seek_key_buf);
                read_iter->SeekForPrev(seek_key);

                uint16_t min_offset = (page_offset >= (MAX_WRITE_SIZE - 1))
                                          ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                          : 0;

                bool found = false;
                while (read_iter->Valid()) {
                    if (read_iter->key().size() != KEY_SIZE) break;

                    uint64_t found_page;
                    uint16_t found_offset;
                    uint64_t found_inst_id;
                    decode_key(read_iter->key(), found_page, found_offset, found_inst_id);

                    if (found_page != page) break;
                    if (found_offset < min_offset) break;
                    if (found_inst_id > search_id) {
                        read_iter->Prev();
                        continue;
                    }

                    auto val = read_iter->value();
                    if (val.size() < 1) { read_iter->Prev(); continue; }
                    uint8_t rd_size = static_cast<uint8_t>(val.data()[0]);

                    if (found_offset <= page_offset &&
                        static_cast<uint16_t>(found_offset + rd_size) > page_offset) {
                        uint16_t read_end = static_cast<uint16_t>(found_offset + rd_size);
                        for (uint8_t j = i; j < read_size; j++) {
                            uint64_t baddr = chunk_addr + j;
                            if (page_of(baddr) != page) break;
                            uint16_t boff = static_cast<uint16_t>(baddr & (kPageSize - 1));
                            if (boff >= read_end) break;
                            if (boff < found_offset) break;

                            uint8_t idx_in_read = static_cast<uint8_t>(boff - found_offset);
                            if (val.size() >= static_cast<size_t>(1 + idx_in_read + 1)) {
                                result.data[off + j] = static_cast<uint8_t>(val.data()[1 + idx_in_read]);
                                result.known[off + j] = true;
                                result.known_count++;
                            }
                        }
                        stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                        found = true;
                        break;
                    }

                    read_iter->Prev();
                }

                if (!found) {
                    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                }

                i++;
                while (i < read_size && result.known[off + i]) i++;
            }
        }
    }

    return result;
}

std::vector<MemoryModel::PageActivity> MemoryModel::active_pages() {
    ensure_built();

    // Return cached result if available (populated during build)
    if (page_activity_cached_) {
        return page_activity_cache_;
    }

    std::vector<PageActivity> pages;

    if (!has_rocksdb_) {
        // In-memory fallback: enumerate pages from the LRU page_cache_.
        std::lock_guard<std::mutex> lk(page_cache_mutex_);
        // page_cache_ maps page_number → vector<MemWrite> sorted by inst_id.
        // We need to enumerate the keys — but LRUCache doesn't expose an
        // iterator, so we rely on the page_activity_cache_ that was populated
        // by build() via the page_buckets map.
        // (build() fills page_activity_cache_ only for the RocksDB path;
        //  for the in-memory path we reconstruct it here from the data available
        //  in the per-page write vectors.)
        // Since LRUCache doesn't expose keys, fall back to the page_activity_cache_
        // that was populated by build() for all paths since PR #xxx.
        return page_activity_cache_;
    }

    // Full scan fallback (only reached if build() didn't cache, e.g. old DB)
    std::unordered_map<uint64_t, PageActivity> page_map;

    auto scan_cf = [&](rocksdb::ColumnFamilyHandle* cf, bool is_write) {
        if (!cf) return;
        rocksdb::ReadOptions ro;
        ro.fill_cache = false;
        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, cf));

        for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
            if (iter->key().size() != KEY_SIZE) continue;

            uint64_t page_addr, inst_id;
            uint16_t page_offset;
            decode_key(iter->key(), page_addr, page_offset, inst_id);

            uint64_t full_page_addr = page_addr << kPageShift;

            auto& pa = page_map[full_page_addr];
            if (pa.page_addr == 0) {
                pa.page_addr = full_page_addr;
                pa.first_inst_id = inst_id;
                pa.last_inst_id = inst_id;
                pa.write_count = 0;
                pa.read_count = 0;
            }
            pa.first_inst_id = std::min(pa.first_inst_id, inst_id);
            pa.last_inst_id = std::max(pa.last_inst_id, inst_id);
            if (is_write) pa.write_count++;
            else pa.read_count++;
        }
    };

    scan_cf(mem_cf_, true);
    scan_cf(mem_read_cf_, false);

    pages.reserve(page_map.size());
    for (auto& [_, pa] : page_map) {
        pages.push_back(pa);
    }
    std::sort(pages.begin(), pages.end(),
              [](const PageActivity& a, const PageActivity& b) {
                  return a.page_addr < b.page_addr;
              });

    // Cache for future calls
    page_activity_cache_ = pages;
    page_activity_cached_ = true;

    return pages;
}

bool MemoryModel::was_accessed(uint64_t addr) {
    ensure_built();

    if (!has_rocksdb_) {
        return was_accessed_inmemory(addr);
    }

    uint64_t page = page_of(addr);
    uint16_t page_offset = static_cast<uint16_t>(addr & (kPageSize - 1));

    auto check_cf = [&](rocksdb::ColumnFamilyHandle* cf) -> bool {
        if (!cf) return false;
        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, cf));

        char seek_buf[KEY_SIZE];
        auto seek_key = encode_key_to(page, page_offset, 0, seek_buf);
        iter->Seek(seek_key);

        if (iter->Valid() && iter->key().size() == KEY_SIZE) {
            uint64_t found_page;
            uint16_t found_offset;
            uint64_t found_inst_id;
            decode_key(iter->key(), found_page, found_offset, found_inst_id);
            if (found_page == page && found_offset == page_offset) {
                return true;
            }
        }
        return false;
    };

    return check_cf(mem_cf_) || check_cf(mem_read_cf_);
}

// ─── Original query methods ───────────────────────────────────────────────────────

uint64_t MemoryModel::index_last_writer(const PageWriteIndex& idx,
                                         uint16_t page_offset,
                                         uint64_t search_id) noexcept {
    if (idx.empty()) return 0;

    // Same logic as index_read_byte but returns the writer inst_id instead
    // of the byte value.  We want the last entry with inst_id <= search_id
    // whose write range covers page_offset.
    const uint16_t min_start = (page_offset >= (MAX_WRITE_SIZE - 1))
                                   ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                   : 0;

    auto end_it = std::upper_bound(idx.begin(), idx.end(),
                                   std::make_pair(page_offset, search_id),
                                   PageWriteEntryLess{});

    if (end_it == idx.begin()) return 0;

    uint64_t best_id = 0;
    bool found = false;

    auto it = end_it;
    while (it != idx.begin()) {
        --it;

        if (it->page_offset < min_start) break;
        if (it->inst_id > search_id) continue;
        if (found && it->inst_id < best_id) continue;  // strictly older, can't improve

        uint16_t end_off = static_cast<uint16_t>(it->page_offset + it->size);
        if (it->page_offset <= page_offset && page_offset < end_off) {
            if (!found || it->inst_id > best_id) {
                best_id = it->inst_id;
                found = true;
            }
        }
    }

    return best_id;
}

uint64_t MemoryModel::last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id) {
    uint64_t latest_writer = 0;
    ensure_built();

    if (before_inst_id == 0) return 0;
    uint64_t search_id = before_inst_id - 1;

    if (has_rocksdb_) {
        // Fast path: use per-page sorted write index (O(log W) per byte)
        // instead of raw RocksDB SeekForPrev.
        auto& iters = get_thread_iterators();

        for (uint8_t i = 0; i < size; i++) {
            uint64_t byte_addr = addr + i;
            uint64_t page      = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (kPageSize - 1));

            // Get (or load) the PageWriteIndex for this page.
            std::shared_ptr<const PageWriteIndex> idx_ptr;
            {
                std::shared_lock<std::shared_mutex> lk(index_cache_mutex_);
                if (const auto* p = page_index_cache_.peek(page)) idx_ptr = *p;
            }
            if (!idx_ptr) {
                idx_ptr = load_page_index(page,
                                          iters.write_iter.get(),
                                          iters.read_iter.get());
            }

            if (idx_ptr) {
                uint64_t writer = index_last_writer(*idx_ptr, page_offset, search_id);
                if (writer > 0) {
                    latest_writer = std::max(latest_writer, writer);
                    stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    } else {
        return last_writer_inmemory(addr, size, search_id);
    }

    return latest_writer;
}

std::vector<uint64_t> MemoryModel::write_history(uint64_t addr, uint8_t size) {
    ensure_built();
    std::vector<uint64_t> result;

    if (has_rocksdb_) {
        uint64_t page = page_of(addr);
        uint16_t target_offset = static_cast<uint16_t>(addr & (kPageSize - 1));
        uint16_t min_offset = (target_offset >= (MAX_WRITE_SIZE - 1))
                                  ? static_cast<uint16_t>(target_offset - (MAX_WRITE_SIZE - 1))
                                  : 0;

        auto start_key = encode_key(page, min_offset, 0);
        std::string end_key = encode_key(page, static_cast<uint16_t>(target_offset + 1), 0);

        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        rocksdb::Slice upper(end_key);
        ro.iterate_upper_bound = &upper;

        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, mem_cf_));

        for (iter->Seek(start_key); iter->Valid(); iter->Next()) {
            if (iter->key().size() != KEY_SIZE) continue;

            uint64_t found_page;
            uint16_t found_offset;
            uint64_t found_inst_id;
            decode_key(iter->key(), found_page, found_offset, found_inst_id);

            if (found_page != page) break;
            if (found_offset > target_offset) break;

            auto val = iter->value();
            if (val.size() < 1) continue;
            uint8_t write_size = static_cast<uint8_t>(val.data()[0]);

            if (found_offset <= target_offset &&
                static_cast<uint16_t>(found_offset + write_size) > target_offset) {
                result.push_back(found_inst_id);
            }
        }
    } else {
        result = write_history_inmemory(addr, size);
    }

    std::sort(result.begin(), result.end());
    return result;
}

std::optional<uint8_t> MemoryModel::byte_at(uint64_t addr, uint64_t at_inst_id) {
    ensure_built();

    // Check hot-byte cache first
    if (has_rocksdb_) {
        ByteCacheKey cache_key{addr, at_inst_id};
        {
            std::lock_guard<std::mutex> lk(byte_cache_mutex_);
            auto cached = byte_cache_.get(cache_key);
            if (cached) {
                stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                if (cached->get().known) return cached->get().value;
                return std::nullopt;
            }
        }

        // at_inst_id == 0 means "before any instruction" → nothing written yet.
        if (at_inst_id == 0) {
            std::lock_guard<std::mutex> lk(byte_cache_mutex_);
            byte_cache_.put(cache_key, {0, false, 0});
            return std::nullopt;
        }

        const uint64_t search_id = at_inst_id - 1;
        uint64_t page = page_of(addr);
        uint16_t page_offset = static_cast<uint16_t>(addr & (kPageSize - 1));

        // Fast path: use per-page sorted write index (O(log W) per byte)
        // instead of raw RocksDB SeekForPrev.
        auto& iters = get_thread_iterators();
        std::shared_ptr<const PageWriteIndex> idx_ptr;
        {
            std::shared_lock<std::shared_mutex> lk(index_cache_mutex_);
            if (const auto* p = page_index_cache_.peek(page)) idx_ptr = *p;
        }
        if (!idx_ptr) {
            idx_ptr = load_page_index(page,
                                      iters.write_iter.get(),
                                      iters.read_iter.get());
        }

        if (idx_ptr) {
            uint8_t  val    = 0;
            uint64_t writer = 0;
            if (index_read_byte(*idx_ptr, page_offset, search_id, val, writer)) {
                stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lk(byte_cache_mutex_);
                    byte_cache_.put(cache_key, {val, true, writer});
                }
                return val;
            }
        }

        // Not found — cache as unknown
        {
            std::lock_guard<std::mutex> lk(byte_cache_mutex_);
            byte_cache_.put(cache_key, {0, false, 0});
        }
        return std::nullopt;
    }

    return byte_at_inmemory(addr, at_inst_id);
}

}  // namespace tenet

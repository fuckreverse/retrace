#include "core/memory_model.h"
#include "common/Profiling.h"
#include "common/logger.h"

#include <rocksdb/write_batch.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <thread>
#include <unordered_map>

namespace tenet {

// ─── Static thread_local definition ───────────────────────────────────────
thread_local MemoryModel::IteratorPair MemoryModel::tl_iterators_;

// ─── Thread-local page cache (for read_region fast path) ──────────────────
// Caches the last PageWriteIndex pointer to skip mutex + hash map lookup when
// consecutive reads hit the same page (common for try_deref_string chunks).
// We store idx as `const void*` because PageWriteIndex is a private type alias
// inside MemoryModel; the pointer is cast back inside read_region().
struct TLPageCache {
    const void* owner = nullptr;  // &page_index_cache_ of owning MemoryModel
    uint64_t page = UINT64_MAX;
    uint64_t gen  = 0;            // LRU generation at snapshot time
    const void* idx = nullptr;    // actually const PageWriteIndex*
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
        tl.gen   = 0;
        tl.idx   = nullptr;
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
    // Fingerprint = file_size (8 bytes LE) + inst_count from index (8 bytes LE)
    // This is sufficient to detect whether the trace file has changed.
    uint64_t fsize = reader_.file_size();
    uint64_t icount = index_.inst_count();
    char fp[16];
    std::memcpy(fp, &fsize, 8);
    std::memcpy(fp + 8, &icount, 8);
    return std::string(fp, 16);
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
        LOG_INFO("MemoryModel: using persisted data from previous session (skip rebuild)");
        built_ = true;
        return;
    }

    const uint64_t total_insts = index_.inst_count();
    LOG_INFO("MemoryModel::build: starting full trace scan ({} instructions, {})",
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
                    LOG_INFO("MemoryModel::build (in-memory): {}/{}  ({:.0f}%)",
                             inst_id, total_insts,
                             100.0 * static_cast<double>(inst_id) / static_cast<double>(total_insts));
                    if (progress_fn) progress_fn(inst_id, total_insts);
                }
            }
        }

        // build() is single-threaded, lock only for consistency
        std::lock_guard<std::mutex> lk(cache_mutex_);
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

        LOG_INFO("MemoryModel::build: complete (in-memory, {} instructions, {} pages)",
                 inst_id, page_activity_cache_.size());

        built_ = true;
        return;
    }

    // ─── RocksDB path: store one KV pair per write (not per byte) ─────────
    // Key: [page BE(8)] [page_offset_of_first_byte BE(2)] [inst_id BE(8)]
    // Value: [write_size(1)] [raw_data(write_size)]
    //
    // Cross-page writes are split into two KV pairs at the page boundary.

    // Opt #4: Collect page activity data during build to avoid later full scan.
    // Pre-size to reduce rehash (typical trace has 10-50K pages).
    ankerl::unordered_dense::map<uint64_t, PageActivity> build_page_map;
    build_page_map.reserve(65536);

    // Use a local write counter to avoid 200M+ atomic fetch_add calls.
    uint64_t local_writes_persisted = 0;

    // ─── Double-buffered pipeline ─────────────────────────────────────────
    // Front thread (this): parses trace → fills batch_front
    // Back thread: writes batch_back to RocksDB
    // When batch_front is full, swap with batch_back (which has been flushed).
    // This overlaps RocksDB I/O with trace parsing for ~2x speedup.

    rocksdb::WriteBatch batch_a, batch_b;
    rocksdb::WriteBatch* batch_front = &batch_a;  // currently being filled
    rocksdb::WriteBatch* batch_back  = &batch_b;  // being written by bg thread
    uint64_t inst_id = 0;
    uint64_t batch_count = 0;

    // Threshold per batch: 2M entries × ~30 bytes ≈ 60MB.
    static constexpr uint64_t kBatchFlushThreshold = 2'000'000;

    rocksdb::WriteOptions wo;
    wo.disableWAL = true;
    wo.no_slowdown = false;

    // Background writer state
    std::mutex writer_mu;
    std::condition_variable writer_cv;
    bool writer_has_work = false;
    bool writer_done = false;
    rocksdb::WriteBatch* writer_batch = nullptr;  // batch to write (set by producer)

    std::thread writer_thread([&]() {
        while (true) {
            std::unique_lock<std::mutex> lk(writer_mu);
            writer_cv.wait(lk, [&]{ return writer_has_work || writer_done; });
            if (writer_done && !writer_has_work) break;
            rocksdb::WriteBatch* wb = writer_batch;
            writer_has_work = false;
            lk.unlock();
            writer_cv.notify_one();  // signal producer that batch_back is free

            db_->Write(wo, wb);
            wb->Clear();
        }
    });

    // Helper: submit current batch_front to background writer, then swap.
    auto flush_batch = [&]() {
        // Wait until writer finishes previous batch_back.
        {
            std::unique_lock<std::mutex> lk(writer_mu);
            writer_cv.wait(lk, [&]{ return !writer_has_work; });
            writer_batch = batch_front;
            writer_has_work = true;
        }
        writer_cv.notify_one();
        // Swap: next fill goes into the (now-free) other buffer.
        std::swap(batch_front, batch_back);
        batch_count = 0;
    };

    // Hint the OS to prefetch trace pages sequentially.
    reader_.advise_sequential();

    for (auto it = reader_.begin(); it != reader_.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;  // skip non-INST early

        auto inst = rec.as_inst();
        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
            auto mem = inst.mem_access(m);
            bool is_write = (mem.type & 0x02) != 0;
            // Route writes to mem_write CF, reads to mem_read CF.
            rocksdb::ColumnFamilyHandle* target_cf = is_write ? mem_cf_ : mem_read_cf_;
            if (!target_cf) continue;  // skip reads when mem_read CF absent

            uint8_t total_size = static_cast<uint8_t>(std::min<uint64_t>(mem.size, 16));

            // Extract all data bytes (branchless: always copy full 16 bytes)
            uint8_t all_data[16];
            std::memcpy(all_data, &mem.value, 8);
            std::memcpy(all_data + 8, &mem.value_hi, 8);

            uint64_t acc_addr = mem.addr;
            uint16_t first_page_offset = static_cast<uint16_t>(acc_addr & (kPageSize - 1));

            // Check if access crosses a page boundary
            uint16_t bytes_in_first_page = static_cast<uint16_t>(
                std::min<uint64_t>(kPageSize - first_page_offset, total_size));

            // First (possibly only) KV pair: bytes in the first page
            {
                uint64_t page = page_of(acc_addr);
                char key_buf[KEY_SIZE];
                auto key = encode_key_to(page, first_page_offset, inst_id, key_buf);

                // Value: [size(1)] [data(size)]
                uint8_t val_buf[17]; // max 1 + 16
                val_buf[0] = bytes_in_first_page;
                std::memcpy(val_buf + 1, all_data, bytes_in_first_page);

                batch_front->Put(target_cf, key,
                                 rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                                1 + bytes_in_first_page));
                batch_count++;

                // Track page activity
                auto [it_pa, inserted] = build_page_map.try_emplace(page, PageActivity{});
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
                if (is_write) pa.write_count++;
                else pa.read_count++;
            }

            // Second KV pair (if access crosses page boundary — rare)
            if (__builtin_expect(bytes_in_first_page < total_size, 0)) {
                uint8_t remaining = total_size - bytes_in_first_page;
                uint64_t second_page_addr = acc_addr + bytes_in_first_page;
                uint64_t second_page = page_of(second_page_addr);
                uint16_t second_offset = 0;

                char key_buf2[KEY_SIZE];
                auto key2 = encode_key_to(second_page, second_offset, inst_id, key_buf2);

                uint8_t val_buf2[17];
                val_buf2[0] = remaining;
                std::memcpy(val_buf2 + 1, all_data + bytes_in_first_page, remaining);

                batch_front->Put(target_cf, key2,
                                 rocksdb::Slice(reinterpret_cast<const char*>(val_buf2),
                                                1 + remaining));
                batch_count++;

                // Track page activity for second page
                auto [it_pa2, ins2] = build_page_map.try_emplace(second_page, PageActivity{});
                auto& pa2 = it_pa2->second;
                if (ins2) {
                    pa2.page_addr = second_page << kPageShift;
                    pa2.first_inst_id = inst_id;
                    pa2.last_inst_id = inst_id;
                    pa2.write_count = 0;
                    pa2.read_count = 0;
                } else {
                    pa2.last_inst_id = inst_id;
                }
                if (is_write) pa2.write_count++;
                else pa2.read_count++;
            }

            if (is_write) {
                local_writes_persisted++;
            }
        }

        // Flush batch to background writer when threshold reached
        if (batch_count >= kBatchFlushThreshold) {
            flush_batch();
        }

        inst_id++;
        if ((inst_id & 0xFFFFF) == 0) {  // every ~1M instructions
            LOG_INFO("MemoryModel::build (RocksDB): {}/{}  ({:.0f}%)",
                     inst_id, total_insts,
                     100.0 * static_cast<double>(inst_id) / static_cast<double>(total_insts));
            if (progress_fn) progress_fn(inst_id, total_insts);
        }
    }

    // Final flush: write remaining entries
    if (batch_front->Count() > 0) {
        // Wait for any in-progress background write to finish
        {
            std::unique_lock<std::mutex> lk(writer_mu);
            writer_cv.wait(lk, [&]{ return !writer_has_work; });
        }
        db_->Write(wo, batch_front);
        batch_front->Clear();
    }

    // Shut down writer thread
    {
        std::lock_guard<std::mutex> lk(writer_mu);
        writer_done = true;
    }
    writer_cv.notify_one();
    writer_thread.join();

    // Publish the local write counter to the atomic stat.
    stats_.total_writes_persisted.store(local_writes_persisted, std::memory_order_relaxed);

    // Opt #4: Store page activity cache
    page_activity_cache_.reserve(build_page_map.size());
    for (auto& [_, pa] : build_page_map) {
        page_activity_cache_.push_back(pa);
    }
    std::sort(page_activity_cache_.begin(), page_activity_cache_.end(),
              [](const PageActivity& a, const PageActivity& b) {
                  return a.page_addr < b.page_addr;
              });
    page_activity_cached_ = true;

    // Opt #1: Write sentinel so next session skips rebuild
    write_persisted_sentinel();

    LOG_INFO("MemoryModel::build: complete ({} instructions, {} writes persisted, {} pages)",
             inst_id, local_writes_persisted, page_activity_cache_.size());

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
        // Fast path: use per-page sorted write index (O(log W) per byte).
        // Falls back to loading the page from RocksDB on the first access.
        auto& iters = get_thread_iterators();
        const uint64_t search_id = at_inst_id - 1;

        for (uint8_t i = 0; i < size; i++) {
            if (result.known[i]) continue;

            uint64_t byte_addr  = addr + i;
            uint64_t page       = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (kPageSize - 1));

            // Get (or load) the PageWriteIndex for this page.
            const PageWriteIndex* idx_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lk(cache_mutex_);
                idx_ptr = page_index_cache_.get_mutable(page);
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
                    result.data[i]      = val;
                    result.known[i]     = true;
                    result.writer_id[i] = writer;
                    stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                }
            }
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

const MemoryModel::PageWriteIndex*
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
                std::memset(e.data, 0, 16);
                std::memcpy(e.data, val.data() + 1, e.size);
                idx.push_back(e);
            }

            it->Next();
        }
    };

    scan_cf(write_iter);
    scan_cf(read_iter);  // read-fallback entries

    // Sort by (page_offset, inst_id) ascending.
    std::sort(idx.begin(), idx.end(), PageWriteEntryLess{});

    // Store in LRU cache and return a stable pointer.
    std::lock_guard<std::mutex> lk(cache_mutex_);
    page_index_cache_.put(page, std::move(idx));
    auto* cached = page_index_cache_.get_mutable(page);
    return cached;
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

    auto it = end_it;
    while (it != idx.begin()) {
        --it;

        // Stop if we've gone past the valid offset window.
        if (it->page_offset < min_start) break;

        // Skip entries whose inst_id is too new (shouldn't happen after
        // upper_bound, but guard against floating-point / boundary issues).
        if (it->inst_id > search_id) continue;

        // Check coverage: does this write reach page_offset?
        uint16_t end_off = static_cast<uint16_t>(it->page_offset + it->size);
        if (it->page_offset <= page_offset && page_offset < end_off) {
            uint8_t byte_idx = static_cast<uint8_t>(page_offset - it->page_offset);
            out_value  = it->data[byte_idx];
            out_writer = it->inst_id;
            return true;
        }
        // If this entry's offset is already < min_start we can stop early.
        if (it->page_offset < min_start) break;
    }

    return false;
}

// ─── In-memory fallback helpers ──────────────────────────────────────────
// These methods implement the non-RocksDB query paths using page_cache_.
// Each acquires cache_mutex_ internally, matching the original inline code.

MemReadResult MemoryModel::read_inmemory(uint64_t addr, uint8_t size, uint64_t at_inst_id) {
    MemReadResult result{};
    std::lock_guard<std::mutex> lk(cache_mutex_);
    for (uint8_t i = 0; i < size; i++) {
        uint64_t byte_addr = addr + i;
        uint64_t page = page_of(byte_addr);

        auto* writes = page_cache_.get_mutable(page);
        if (!writes) continue;

        stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);

        // Scan from newest to oldest to find last write covering this byte
        const MemWrite* best = nullptr;
        for (auto rit = writes->rbegin(); rit != writes->rend(); ++rit) {
            if (rit->inst_id > at_inst_id) continue;
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
    std::lock_guard<std::mutex> lk(cache_mutex_);
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
    std::lock_guard<std::mutex> lk(cache_mutex_);
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
    std::lock_guard<std::mutex> lk(cache_mutex_);
    uint64_t page = page_of(addr);
    auto* writes = page_cache_.get_mutable(page);
    if (!writes) return std::nullopt;

    for (auto rit = writes->rbegin(); rit != writes->rend(); ++rit) {
        if (rit->inst_id > at_inst_id) continue;
        if (addr >= rit->addr && addr < rit->addr + rit->size) {
            uint8_t offset = static_cast<uint8_t>(addr - rit->addr);
            return rit->data[offset];
        }
    }

    return std::nullopt;
}

bool MemoryModel::was_accessed_inmemory(uint64_t addr) {
    std::lock_guard<std::mutex> lk(cache_mutex_);
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
        const PageWriteIndex* idx_ptr = nullptr;

        // Fast path: same page as last lookup AND no eviction since snapshot
        // AND same MemoryModel instance — skip lock entirely.
        if (tl_page.owner == &page_index_cache_ &&
            page == tl_page.page && tl_page.idx &&
            tl_page.gen == page_index_cache_.generation()) {
            idx_ptr = static_cast<const PageWriteIndex*>(tl_page.idx);
        } else {
            {
                std::lock_guard<std::mutex> lk(cache_mutex_);
                idx_ptr = page_index_cache_.get_mutable(page);
            }
            if (!idx_ptr) {
                // Cache miss: load whole page from RocksDB (one forward scan).
                // load_page_index acquires cache_mutex_ internally.
                idx_ptr = load_page_index(page,
                                          iters.write_iter.get(),
                                          iters.read_iter.get());
            }
            // Update thread-local cache with current generation and owner.
            tl_page.owner = &page_index_cache_;
            tl_page.page  = page;
            tl_page.gen   = page_index_cache_.generation();
            tl_page.idx   = static_cast<const void*>(idx_ptr);
        }

        // Resolve all bytes on this page.
        uint64_t page_base = page << kPageShift;
        uint64_t page_end  = page_base + kPageSize;

        while (off < size && (addr + off) < page_end) {
            uint64_t ba         = addr + off;
            uint16_t page_off   = static_cast<uint16_t>(ba & (kPageSize - 1));

            if (idx_ptr) {
                uint8_t  val    = 0;
                uint64_t writer = 0;
                if (index_read_byte(*idx_ptr, page_off, search_id, val, writer)) {
                    result.data[off]  = val;
                    result.known[off] = true;
                    result.known_count++;
                    stats_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                }
            }
            // If idx_ptr is null (RocksDB unavailable for this page), the byte
            // remains unknown — consistent with the previous behaviour.

            ++off;
        }
    }

    return result;
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
        std::lock_guard<std::mutex> lk(cache_mutex_);
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

    auto it = end_it;
    while (it != idx.begin()) {
        --it;

        if (it->page_offset < min_start) break;
        if (it->inst_id > search_id) continue;

        uint16_t end_off = static_cast<uint16_t>(it->page_offset + it->size);
        if (it->page_offset <= page_offset && page_offset < end_off) {
            return it->inst_id;
        }
        if (it->page_offset < min_start) break;
    }

    return 0;
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
            const PageWriteIndex* idx_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lk(cache_mutex_);
                idx_ptr = page_index_cache_.get_mutable(page);
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
        const PageWriteIndex* idx_ptr = nullptr;
        {
            std::lock_guard<std::mutex> lk(cache_mutex_);
            idx_ptr = page_index_cache_.get_mutable(page);
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

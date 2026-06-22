#include "core/memory_model.h"

#include <rocksdb/write_batch.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/cache.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace tenet {

// ─── Static thread_local definition ───────────────────────────────────────
thread_local MemoryModel::IteratorPair MemoryModel::tl_iterators_;

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

MemoryModel::~MemoryModel() {
invalidate_thread_iterators();
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

void MemoryModel::build() {
    if (built_) return;

    // ─── Opt #1: Check if already persisted from a previous session ──────
    if (has_rocksdb_ && check_persisted_sentinel()) {
        // Data already in RocksDB from last run. Just load page activity cache.
        // We still need to scan the CF for page activity (or load from a cached key).
        // For now, mark built and let active_pages() do lazy scan if needed.
        built_ = true;
        return;
    }

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
                pa.page_addr = page << PAGE_SHIFT;
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

        built_ = true;
        return;
    }

    // ─── RocksDB path: store one KV pair per write (not per byte) ─────────
    // Key: [page BE(8)] [page_offset_of_first_byte BE(2)] [inst_id BE(8)]
    // Value: [write_size(1)] [raw_data(write_size)]
    //
    // Cross-page writes are split into two KV pairs at the page boundary.

    // Opt #4: Collect page activity data during build to avoid later full scan
    std::unordered_map<uint64_t, PageActivity> build_page_map;

    rocksdb::WriteBatch batch;
    uint64_t inst_id = 0;
    uint64_t batch_count = 0;

    rocksdb::WriteOptions wo;
    wo.disableWAL = true;  // Faster bulk load, data is reconstructible

    for (auto it = reader_.begin(); it != reader_.end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                bool is_write = (mem.type & 0x02) != 0;
                // Route writes to mem_write CF, reads to mem_read CF.
                rocksdb::ColumnFamilyHandle* target_cf = is_write ? mem_cf_ : mem_read_cf_;
                if (!target_cf) continue;  // skip reads when mem_read CF absent

                uint8_t total_size = static_cast<uint8_t>(std::min<uint64_t>(mem.size, 16));

                // Extract all data bytes
                uint8_t all_data[16];
                std::memset(all_data, 0, 16);
                std::memcpy(all_data, &mem.value, std::min<uint8_t>(total_size, 8));
                if (total_size > 8) {
                    std::memcpy(all_data + 8, &mem.value_hi,
                                std::min<uint8_t>(total_size - 8, 8));
                }

                uint64_t acc_addr = mem.addr;
                uint16_t first_page_offset = static_cast<uint16_t>(acc_addr & (PAGE_SIZE - 1));

                // Check if access crosses a page boundary
                uint16_t bytes_in_first_page = static_cast<uint16_t>(
                    std::min<uint64_t>(PAGE_SIZE - first_page_offset, total_size));

                // First (possibly only) KV pair: bytes in the first page
                {
                    uint64_t page = page_of(acc_addr);
                    char key_buf[KEY_SIZE];
                    auto key = encode_key_to(page, first_page_offset, inst_id, key_buf);

                    // Value: [size(1)] [data(size)]
                    uint8_t val_buf[17]; // max 1 + 16
                    val_buf[0] = bytes_in_first_page;
                    std::memcpy(val_buf + 1, all_data, bytes_in_first_page);

                    batch.Put(target_cf, key,
                              rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                             1 + bytes_in_first_page));
                    batch_count++;

                    // Opt #4: track page activity
                    auto& pa = build_page_map[page];
                    if (pa.page_addr == 0) {
                        pa.page_addr = page << PAGE_SHIFT;
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

                // Second KV pair (if access crosses page boundary)
                if (bytes_in_first_page < total_size) {
                    uint8_t remaining = total_size - bytes_in_first_page;
                    uint64_t second_page_addr = acc_addr + bytes_in_first_page;
                    uint64_t second_page = page_of(second_page_addr);
                    uint16_t second_offset = 0; // starts at beginning of next page

                    char key_buf2[KEY_SIZE];
                    auto key2 = encode_key_to(second_page, second_offset, inst_id, key_buf2);

                    uint8_t val_buf[17];
                    val_buf[0] = remaining;
                    std::memcpy(val_buf + 1, all_data + bytes_in_first_page, remaining);

                    batch.Put(target_cf, key2,
                              rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                             1 + remaining));
                    batch_count++;

                    // Opt #4: track page activity for second page
                    auto& pa2 = build_page_map[second_page];
                    if (pa2.page_addr == 0) {
                        pa2.page_addr = second_page << PAGE_SHIFT;
                        pa2.first_inst_id = inst_id;
                        pa2.last_inst_id = inst_id;
                        pa2.write_count = 0;
                        pa2.read_count = 0;
                    }
                    pa2.first_inst_id = std::min(pa2.first_inst_id, inst_id);
                    pa2.last_inst_id = std::max(pa2.last_inst_id, inst_id);
                    if (is_write) pa2.write_count++;
                    else pa2.read_count++;
                }

                if (is_write) {
                    stats_.total_writes_persisted.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Flush batch periodically (every ~100K entries)
            if (batch_count >= 100000) {
                db_->Write(wo, &batch);
                batch.Clear();
                batch_count = 0;
            }

            inst_id++;
        }
    }

    // Final flush
    if (batch.Count() > 0) {
        db_->Write(wo, &batch);
    }

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
        // Opt #3: Use thread-local iterators instead of creating new ones each call.
        auto& iters = get_thread_iterators();
        auto* iter = iters.write_iter.get();
        auto* read_iter = iters.read_iter.get();

        // Use at_inst_id - 1 as the inclusive upper bound so that inst_id == at_inst_id
        // is excluded (exclusive semantics: "state before at_inst_id executes").
        const uint64_t search_id = at_inst_id - 1;

        for (uint8_t i = 0; i < size; ) {
            uint64_t byte_addr = addr + i;
            uint64_t page = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

            // Seek once for this byte
            char seek_key_buf[KEY_SIZE];
            auto seek_key = encode_key_to(page, page_offset, search_id, seek_key_buf);
            iter->SeekForPrev(seek_key);

            uint16_t min_offset = (page_offset >= (MAX_WRITE_SIZE - 1))
                                      ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                      : 0;

            bool found = false;
            while (iter->Valid()) {
                if (iter->key().size() != KEY_SIZE) break;

                uint64_t found_page;
                uint16_t found_offset;
                uint64_t found_inst_id;
                decode_key(iter->key(), found_page, found_offset, found_inst_id);

                if (found_page != page) break;
                if (found_offset < min_offset) break;
                if (found_inst_id > search_id) {
                    iter->Prev();
                    continue;
                }

                auto val = iter->value();
                if (val.size() < 1) { iter->Prev(); continue; }
                uint8_t write_size = static_cast<uint8_t>(val.data()[0]);

                // Check if this write covers our target byte
                if (found_offset <= page_offset &&
                    static_cast<uint16_t>(found_offset + write_size) > page_offset) {
                    // Found it! Now extract as many consecutive bytes as this write covers.
                    uint16_t write_end = static_cast<uint16_t>(found_offset + write_size);
                    for (uint8_t j = i; j < size; j++) {
                        uint64_t baddr = addr + j;
                        // Stop if we cross a page boundary
                        if (page_of(baddr) != page) break;
                        uint16_t boff = static_cast<uint16_t>(baddr & (PAGE_SIZE - 1));
                        if (boff >= write_end) break;  // beyond this write
                        if (boff < found_offset) break; // before this write (shouldn't happen)

                        uint8_t idx_in_write = static_cast<uint8_t>(boff - found_offset);
                        if (val.size() >= static_cast<size_t>(1 + idx_in_write + 1)) {
                            result.data[j] = static_cast<uint8_t>(val.data()[1 + idx_in_write]);
                            result.known[j] = true;
                            result.writer_id[j] = found_inst_id;
                        }
                    }
                    stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
                    found = true;
                    break;
                }

                iter->Prev();
            }

            if (!found) {
                stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);
            }

            // Advance i past all bytes we've already resolved
            i++;
            while (i < size && result.known[i]) i++;
        }

        // ── Phase 2: read-fallback for unresolved bytes ──────────────────
        if (read_iter) {
            for (uint8_t i = 0; i < size; ) {
                if (result.known[i]) { i++; continue; }

                uint64_t byte_addr = addr + i;
                uint64_t page = page_of(byte_addr);
                uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

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
                    uint8_t read_size = static_cast<uint8_t>(val.data()[0]);

                    // Check if this read covers our target byte
                    if (found_offset <= page_offset &&
                        static_cast<uint16_t>(found_offset + read_size) > page_offset) {
                        // Extract as many consecutive bytes as this read covers.
                        uint16_t read_end = static_cast<uint16_t>(found_offset + read_size);
                        for (uint8_t j = i; j < size; j++) {
                            uint64_t baddr = addr + j;
                            if (page_of(baddr) != page) break;
                            uint16_t boff = static_cast<uint16_t>(baddr & (PAGE_SIZE - 1));
                            if (boff >= read_end) break;
                            if (boff < found_offset) break;

                            uint8_t idx_in_read = static_cast<uint8_t>(boff - found_offset);
                            if (val.size() >= static_cast<size_t>(1 + idx_in_read + 1)) {
                                result.data[j] = static_cast<uint8_t>(val.data()[1 + idx_in_read]);
                                result.known[j] = true;
                                result.writer_id[j] = found_inst_id;
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
                while (i < size && result.known[i]) i++;
            }
        }
    } else {
        // In-memory fallback path — LRU cache needs mutex protection
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
    }

    return result;
}

// ─── Extended API implementations ─────────────────────────────────────────

// Opt #2: read_region with single-iterator approach for RocksDB path.
// Instead of calling read() in a loop (which previously would create iterators
// per call), we now create one iterator pair and reuse across all chunks.
MemoryModel::RegionReadResult MemoryModel::read_region(uint64_t addr, size_t size, uint64_t at_inst_id) {
    RegionReadResult result;
    result.data.resize(size, 0);
    result.known.resize(size, false);
    result.known_count = 0;

    if (size == 0) return result;
    ensure_built();

    if (has_rocksdb_) {
        // Use thread-local iterators — single pair for the entire region read
        auto& iters = get_thread_iterators();
        return read_region_impl(addr, size, at_inst_id,
                                iters.write_iter.get(),
                                iters.read_iter.get());
    }

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
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

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
                        uint16_t boff = static_cast<uint16_t>(baddr & (PAGE_SIZE - 1));
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
                uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

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
                            uint16_t boff = static_cast<uint16_t>(baddr & (PAGE_SIZE - 1));
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

            uint64_t full_page_addr = page_addr << PAGE_SHIFT;

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
        std::lock_guard<std::mutex> lk(cache_mutex_);
        uint64_t page = page_of(addr);
        return page_cache_.get_mutable(page) != nullptr;
    }

    uint64_t page = page_of(addr);
    uint16_t page_offset = static_cast<uint16_t>(addr & (PAGE_SIZE - 1));

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

uint64_t MemoryModel::last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id) {
    uint64_t latest_writer = 0;
    ensure_built();

    if (before_inst_id == 0) return 0;
    uint64_t search_id = before_inst_id - 1;

    if (has_rocksdb_) {
        auto& iters = get_thread_iterators();
        auto* iter = iters.write_iter.get();

        bool resolved[16] = {};
        uint64_t writer_ids[16] = {};

        for (uint8_t i = 0; i < size; ) {
            if (resolved[i]) { i++; continue; }

            uint64_t byte_addr = addr + i;
            uint64_t page = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

            char seek_key_buf[KEY_SIZE];
            auto seek_key = encode_key_to(page, page_offset, search_id, seek_key_buf);
            iter->SeekForPrev(seek_key);

            uint16_t min_offset = (page_offset >= (MAX_WRITE_SIZE - 1))
                                      ? static_cast<uint16_t>(page_offset - (MAX_WRITE_SIZE - 1))
                                      : 0;

            bool found = false;
            while (iter->Valid()) {
                if (iter->key().size() != KEY_SIZE) break;

                uint64_t found_page;
                uint16_t found_offset;
                uint64_t found_inst_id;
                decode_key(iter->key(), found_page, found_offset, found_inst_id);

                if (found_page != page) break;
                if (found_offset < min_offset) break;
                if (found_inst_id > search_id) {
                    iter->Prev();
                    continue;
                }

                auto val = iter->value();
                if (val.size() < 1) { iter->Prev(); continue; }
                uint8_t write_size = static_cast<uint8_t>(val.data()[0]);

                if (found_offset <= page_offset &&
                    static_cast<uint16_t>(found_offset + write_size) > page_offset) {
                    uint16_t write_end = static_cast<uint16_t>(found_offset + write_size);
                    for (uint8_t j = i; j < size; j++) {
                        uint64_t baddr = addr + j;
                        if (page_of(baddr) != page) break;
                        uint16_t boff = static_cast<uint16_t>(baddr & (PAGE_SIZE - 1));
                        if (boff >= write_end) break;
                        if (boff < found_offset) break;

                        uint8_t idx_in_write = static_cast<uint8_t>(boff - found_offset);
                        if (val.size() >= static_cast<size_t>(1 + idx_in_write + 1)) {
                            resolved[j] = true;
                            writer_ids[j] = found_inst_id;
                        }
                    }
                    found = true;
                    break;
                }

                iter->Prev();
            }

            stats_.rocksdb_reads.fetch_add(1, std::memory_order_relaxed);

            i++;
            while (i < size && resolved[i]) i++;
        }

        for (uint8_t i = 0; i < size; i++) {
            if (resolved[i]) {
                latest_writer = std::max(latest_writer, writer_ids[i]);
            }
        }
    } else {
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
    }

    return latest_writer;
}

std::vector<uint64_t> MemoryModel::write_history(uint64_t addr, uint8_t size) {
    ensure_built();
    std::vector<uint64_t> result;

    if (has_rocksdb_) {
        uint64_t page = page_of(addr);
        uint16_t target_offset = static_cast<uint16_t>(addr & (PAGE_SIZE - 1));
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

        auto& iters = get_thread_iterators();
        auto* iter = iters.write_iter.get();

        uint64_t page = page_of(addr);
        uint16_t page_offset = static_cast<uint16_t>(addr & (PAGE_SIZE - 1));

        MemReadResult tmp{};
        find_covering_write(iter, page, page_offset, at_inst_id, tmp, 0);

        // Store in cache (LRUCache handles eviction automatically)
        {
            std::lock_guard<std::mutex> lk(byte_cache_mutex_);
            byte_cache_.put(cache_key, {tmp.data[0], tmp.known[0],
                                        tmp.known[0] ? at_inst_id : 0});
        }

        if (tmp.known[0]) {
            return tmp.data[0];
        }

        // Try read CF fallback
        if (iters.read_iter) {
            MemReadResult tmp2{};
            find_covering_write(iters.read_iter.get(), page, page_offset, at_inst_id, tmp2, 0);
            if (tmp2.known[0]) {
                std::lock_guard<std::mutex> lk(byte_cache_mutex_);
                byte_cache_.put(cache_key, {tmp2.data[0], true, at_inst_id});
                return tmp2.data[0];
            }
        }

        return std::nullopt;
    }

    // In-memory fallback
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

}  // namespace tenet

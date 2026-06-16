#include "core/memory_model.h"

#include <rocksdb/write_batch.h>
#include <rocksdb/options.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace tenet {

// ─── Key encoding ─────────────────────────────────────────────────────────
// Key = [page_addr BE(8)] [page_offset BE(2)] [inst_id BE(8)] = 18 bytes
// This ensures RocksDB's byte-wise comparator groups by page, then offset, then time.
// page_offset is the starting offset of the write within the page.

std::string MemoryModel::encode_key(uint64_t page_addr, uint16_t page_offset, uint64_t inst_id) {
    std::string key(KEY_SIZE, '\0');
    // page_addr big-endian
    for (int i = 7; i >= 0; --i) key[7 - i] = static_cast<char>((page_addr >> (i * 8)) & 0xFF);
    // page_offset big-endian
    key[8] = static_cast<char>((page_offset >> 8) & 0xFF);
    key[9] = static_cast<char>(page_offset & 0xFF);
    // inst_id big-endian
    for (int i = 7; i >= 0; --i) key[10 + (7 - i)] = static_cast<char>((inst_id >> (i * 8)) & 0xFF);
    return key;
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
                          rocksdb::DB* db, rocksdb::ColumnFamilyHandle* mem_cf)
    : reader_(reader), index_(index), db_(db), mem_cf_(mem_cf),
      has_rocksdb_(db != nullptr && mem_cf != nullptr) {}

MemoryModel::MemoryModel(const TraceReader& reader, const TraceIndex& index)
    : reader_(reader), index_(index) {}

// ─── Build (persist writes to RocksDB) ────────────────────────────────────

void MemoryModel::ensure_built() {
    if (built_) return;
    std::lock_guard<std::mutex> lock(build_mutex_);
    if (built_) return;
    build();
}

void MemoryModel::build() {
    if (built_) return;

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
            page_cache_.put(page, std::move(writes));
        }

        built_ = true;
        return;
    }

    // ─── RocksDB path: store one KV pair per write (not per byte) ─────────
    // Key: [page BE(8)] [page_offset_of_first_byte BE(2)] [inst_id BE(8)]
    // Value: [write_size(1)] [raw_data(write_size)]
    //
    // Cross-page writes are split into two KV pairs at the page boundary.

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
                if (!(mem.type & 0x02)) continue;  // writes only

                uint8_t total_size = static_cast<uint8_t>(std::min<uint64_t>(mem.size, 16));

                // Extract all data bytes
                uint8_t all_data[16];
                std::memset(all_data, 0, 16);
                std::memcpy(all_data, &mem.value, std::min<uint8_t>(total_size, 8));
                if (total_size > 8) {
                    std::memcpy(all_data + 8, &mem.value_hi,
                                std::min<uint8_t>(total_size - 8, 8));
                }

                uint64_t write_addr = mem.addr;
                uint16_t first_page_offset = static_cast<uint16_t>(write_addr & (PAGE_SIZE - 1));

                // Check if write crosses a page boundary
                uint16_t bytes_in_first_page = static_cast<uint16_t>(
                    std::min<uint64_t>(PAGE_SIZE - first_page_offset, total_size));

                // First (possibly only) KV pair: bytes in the first page
                {
                    uint64_t page = page_of(write_addr);
                    auto key = encode_key(page, first_page_offset, inst_id);

                    // Value: [size(1)] [data(size)]
                    uint8_t val_buf[17]; // max 1 + 16
                    val_buf[0] = bytes_in_first_page;
                    std::memcpy(val_buf + 1, all_data, bytes_in_first_page);

                    batch.Put(mem_cf_, key,
                              rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                             1 + bytes_in_first_page));
                    batch_count++;
                }

                // Second KV pair (if write crosses page boundary)
                if (bytes_in_first_page < total_size) {
                    uint8_t remaining = total_size - bytes_in_first_page;
                    uint64_t second_page_addr = write_addr + bytes_in_first_page;
                    uint64_t second_page = page_of(second_page_addr);
                    uint16_t second_offset = 0; // starts at beginning of next page

                    auto key = encode_key(second_page, second_offset, inst_id);

                    uint8_t val_buf[17];
                    val_buf[0] = remaining;
                    std::memcpy(val_buf + 1, all_data + bytes_in_first_page, remaining);

                    batch.Put(mem_cf_, key,
                              rocksdb::Slice(reinterpret_cast<const char*>(val_buf),
                                             1 + remaining));
                    batch_count++;
                }

                stats_.total_writes_persisted.fetch_add(1, std::memory_order_relaxed);
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

    built_ = true;
}

// ─── RocksDB query: find last write covering a byte ───────────────────────

void MemoryModel::find_covering_write(rocksdb::Iterator* iter,
                                       uint64_t page, uint16_t target_offset,
                                       uint64_t at_inst_id,
                                       MemReadResult& out, uint8_t result_index) {
    // We want the most recent write (highest inst_id <= at_inst_id) whose range
    // covers target_offset. A write stored at page_offset X with size S covers
    // bytes [X, X+S-1]. So we need X <= target_offset <= X+S-1, i.e. X >= target_offset - (S-1).
    // Since max S = 16, the earliest possible X is target_offset - 15.
    //
    // Strategy: SeekForPrev to [page | target_offset | at_inst_id].
    // Then scan backwards. Stop when:
    //   - page changes (no more candidates)
    //   - page_offset < target_offset - 15 (no write can reach target)
    //
    // For each candidate entry at (page, entry_offset, entry_inst_id):
    //   - If entry_inst_id > at_inst_id: skip (too new)
    //   - Parse value to get write_size
    //   - If entry_offset + write_size > target_offset: this write covers our byte!
    //     (i.e., entry_offset <= target_offset && entry_offset + write_size - 1 >= target_offset)

    auto seek_key = encode_key(page, target_offset, at_inst_id);
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
        // (This can happen when SeekForPrev lands on the same page_offset
        //  but a future instruction)
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
        // Write covers [found_offset, found_offset + write_size - 1]
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

    if (has_rocksdb_) {
        // RocksDB iterators are thread-safe per-iterator (each thread gets its own).
        // No mutex needed here since we create a fresh iterator.
        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, mem_cf_));

        for (uint8_t i = 0; i < size; i++) {
            uint64_t byte_addr = addr + i;
            uint64_t page = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

            find_covering_write(iter.get(), page, page_offset, at_inst_id, result, i);
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

uint64_t MemoryModel::last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id) {
    uint64_t latest_writer = 0;
    ensure_built();

    if (before_inst_id == 0) return 0;
    uint64_t search_id = before_inst_id - 1;

    if (has_rocksdb_) {
        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, mem_cf_));

        for (uint8_t i = 0; i < size; i++) {
            uint64_t byte_addr = addr + i;
            uint64_t page = page_of(byte_addr);
            uint16_t page_offset = static_cast<uint16_t>(byte_addr & (PAGE_SIZE - 1));

            MemReadResult tmp{};
            find_covering_write(iter.get(), page, page_offset, search_id, tmp, 0);
            if (tmp.known[0]) {
                latest_writer = std::max(latest_writer, tmp.writer_id[0]);
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
        // RocksDB path: scan all writes that could cover addr's byte.
        // upper_bound is a stack-local string; the Slice points into it.
        // Both remain valid for the iterator's entire lifetime.
        uint64_t page = page_of(addr);
        uint16_t target_offset = static_cast<uint16_t>(addr & (PAGE_SIZE - 1));
        uint16_t min_offset = (target_offset >= (MAX_WRITE_SIZE - 1))
                                  ? static_cast<uint16_t>(target_offset - (MAX_WRITE_SIZE - 1))
                                  : 0;

        auto start_key = encode_key(page, min_offset, 0);
        // upper_bound string lives on the stack — Slice references it safely.
        std::string end_key = encode_key(page, static_cast<uint16_t>(target_offset + 1), 0);

        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        rocksdb::Slice upper(end_key);  // Slice points into end_key's buffer
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

            // Check if this write covers the target byte
            auto val = iter->value();
            if (val.size() < 1) continue;
            uint8_t write_size = static_cast<uint8_t>(val.data()[0]);

            if (found_offset <= target_offset &&
                static_cast<uint16_t>(found_offset + write_size) > target_offset) {
                result.push_back(found_inst_id);
            }
        }
    } else {
        // In-memory path — needs cache lock
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

    if (has_rocksdb_) {
        rocksdb::ReadOptions ro;
        ro.fill_cache = true;
        std::unique_ptr<rocksdb::Iterator> iter(db_->NewIterator(ro, mem_cf_));

        uint64_t page = page_of(addr);
        uint16_t page_offset = static_cast<uint16_t>(addr & (PAGE_SIZE - 1));

        MemReadResult tmp{};
        find_covering_write(iter.get(), page, page_offset, at_inst_id, tmp, 0);
        if (tmp.known[0]) {
            return tmp.data[0];
        }
        return std::nullopt;
    }

    // In-memory fallback — needs cache lock
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

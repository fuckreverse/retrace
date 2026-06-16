#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <rocksdb/db.h>

#include <atomic>
#include <array>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <filesystem>

namespace tenet {

/// Represents a single memory write event in the trace.
struct MemWrite {
    uint64_t inst_id;     // which instruction performed the write
    uint64_t addr;        // byte address
    uint8_t size;         // 1-16 bytes
    uint8_t data[16];     // written data (little-endian)
};

/// Result of reading memory at a specific point in time.
struct MemReadResult {
    std::array<uint8_t, 16> data{};
    std::array<bool, 16> known{};         // which bytes have known values
    std::array<uint64_t, 16> writer_id{}; // inst_id that last wrote each byte
};

/// Time-indexed memory model with RocksDB persistence.
///
/// Memory writes are persisted into a RocksDB column family ("mem_write")
/// with keys encoding [page_addr(8) | page_offset_of_first_byte(2) | inst_id(8)]
/// in big-endian for correct sort order.
///
/// Value format: [write_size(1)] [raw_data(write_size)]
///   - write_size: number of bytes in the original write starting at page_offset
///   - raw_data: the written bytes
///
/// A single N-byte write produces 1 KV pair (or 2 if it crosses a page boundary).
/// This dramatically reduces the number of KV pairs vs the per-byte approach.
///
/// Read queries use a single RocksDB iterator to find the last write
/// covering each byte in the requested range, scanning backwards from
/// the target byte offset to find writes that may span multiple bytes.
///
/// Design:
///   - build() performs a single-pass scan and bulk-loads all writes into RocksDB
///   - Queries use a single RocksDB iterator for the entire read range
///   - In-memory LRU cache of hot pages for repeated queries
///   - Column family: "mem_write" in the shared trace index DB
class MemoryModel {
public:
    /// Open MemoryModel backed by RocksDB.
    /// `db` is the shared trace index DB (must outlive MemoryModel).
    /// `mem_cf` is the "mem_write" column family handle.
    MemoryModel(const TraceReader& reader, const TraceIndex& index,
                rocksdb::DB* db, rocksdb::ColumnFamilyHandle* mem_cf);

    /// Legacy constructor (in-memory only, no RocksDB persistence).
    MemoryModel(const TraceReader& reader, const TraceIndex& index);

    /// Read `size` bytes at `addr` as they were at time `at_inst_id`.
    MemReadResult read(uint64_t addr, uint8_t size, uint64_t at_inst_id);

    /// Find the inst_id that last wrote to [addr, addr+size) before `before_inst_id`.
    uint64_t last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id);

    /// Find all inst_ids that wrote to a given address.
    std::vector<uint64_t> write_history(uint64_t addr, uint8_t size);

    /// Get a single byte value at a specific time.
    std::optional<uint8_t> byte_at(uint64_t addr, uint64_t at_inst_id);

    /// Cache statistics (atomic counters for thread-safe concurrent queries).
    struct CacheStats {
        std::atomic<uint64_t> rocksdb_reads{0};
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> total_writes_persisted{0};
    };

    /// Snapshot of statistics (non-atomic copy for reporting).
    struct CacheStatsSnapshot {
        uint64_t rocksdb_reads = 0;
        uint64_t cache_hits = 0;
        uint64_t total_writes_persisted = 0;
    };
    CacheStatsSnapshot cache_stats() const {
        return {stats_.rocksdb_reads.load(std::memory_order_relaxed),
                stats_.cache_hits.load(std::memory_order_relaxed),
                stats_.total_writes_persisted.load(std::memory_order_relaxed)};
    }

    /// Build the mem_write column family data from trace.
    /// Performs a single sequential scan and bulk-writes all memory writes.
    void build();

    /// Check if already built (data persisted in RocksDB).
    bool is_built() const { return built_; }

private:
    static constexpr uint64_t PAGE_SHIFT = 12;
    static constexpr uint64_t PAGE_SIZE = 1ULL << PAGE_SHIFT;
    static constexpr uint8_t MAX_WRITE_SIZE = 16;

    static uint64_t page_of(uint64_t addr) { return addr >> PAGE_SHIFT; }

    // ─── RocksDB key encoding ────────────────────────────────────────────
    // Key format: [page_addr BE(8)] [page_offset BE(2)] [inst_id BE(8)]
    // Total: 18 bytes
    // page_offset is the offset of the FIRST byte of the write within the page.
    static constexpr size_t KEY_SIZE = 18;

    static std::string encode_key(uint64_t page_addr, uint16_t page_offset, uint64_t inst_id);
    static void decode_key(const rocksdb::Slice& key, uint64_t& page_addr,
                           uint16_t& page_offset, uint64_t& inst_id);

    /// Find the last write covering a specific byte within a page, using the
    /// provided iterator. Writes result into `out` at position `result_index`.
    /// The iterator must already be created on mem_cf_.
    ///
    /// A write at page_offset X with size S covers bytes [X, X+S-1].
    /// To find a write covering target byte T, we seek to [page|T|at_inst_id]
    /// using SeekForPrev and scan backwards. We stop when the key's page_offset
    /// is more than (MAX_WRITE_SIZE-1) bytes before T, since no write can reach T.
    void find_covering_write(rocksdb::Iterator* iter,
                             uint64_t page, uint16_t target_offset,
                             uint64_t at_inst_id,
                             MemReadResult& out, uint8_t result_index);

    /// Ensure build has been performed.
    void ensure_built();

    const TraceReader& reader_;
    const TraceIndex& index_;

    // RocksDB backing store
    rocksdb::DB* db_ = nullptr;
    rocksdb::ColumnFamilyHandle* mem_cf_ = nullptr;
    bool has_rocksdb_ = false;

    // In-memory cache for recently queried writes (protected by cache_mutex_)
    LRUCache<uint64_t, std::vector<MemWrite>> page_cache_{512};
    mutable std::mutex cache_mutex_;  // protects page_cache_ for concurrent queries

    CacheStats stats_;  // atomic counters, no mutex needed
    bool built_ = false;
    std::mutex build_mutex_;
};

}  // namespace tenet

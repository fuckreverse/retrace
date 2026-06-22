#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <rocksdb/db.h>
#include <rocksdb/iterator.h>

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
                rocksdb::DB* db, rocksdb::ColumnFamilyHandle* mem_write_cf,
                rocksdb::ColumnFamilyHandle* mem_read_cf = nullptr);

    /// Legacy constructor (in-memory only, no RocksDB persistence).
    MemoryModel(const TraceReader& reader, const TraceIndex& index);

    /// Destructor: invalidates any thread-local iterators pointing to our DB,
    /// preventing use-after-free across test boundaries.
    ~MemoryModel();

    /// Read `size` bytes at `addr` as they were at time `at_inst_id`.
    MemReadResult read(uint64_t addr, uint8_t size, uint64_t at_inst_id);

    /// Find the inst_id that last wrote to [addr, addr+size) before `before_inst_id`.
    uint64_t last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id);

    /// Find all inst_ids that wrote to a given address.
    std::vector<uint64_t> write_history(uint64_t addr, uint8_t size);

    /// Get a single byte value at a specific time.
    std::optional<uint8_t> byte_at(uint64_t addr, uint64_t at_inst_id);

    // ─── Extended API for bulk memory operations ──────────────────────────

    /// Read a region of arbitrary size at a specific point in time.
    /// Unlike read() which is limited to 16 bytes, this handles chunking internally.
    /// Returns a byte vector and a parallel 'known' vector indicating validity.
    struct RegionReadResult {
        std::vector<uint8_t> data;
        std::vector<bool> known;
        size_t known_count = 0;  // number of bytes with known values
    };
    RegionReadResult read_region(uint64_t addr, size_t size, uint64_t at_inst_id);

    /// Describes the activity timeline of a single memory page.
    struct PageActivity {
        uint64_t page_addr;        // page-aligned address (page_number << 12)
        uint64_t first_inst_id;    // earliest inst_id that accessed this page
        uint64_t last_inst_id;     // latest inst_id that accessed this page
        uint32_t write_count;      // number of write events to this page
        uint32_t read_count;       // number of read events to this page
    };

    /// Enumerate all memory pages that were accessed during the trace.
    /// Returns a list sorted by page_addr.
    /// This enables "what memory existed" queries without scanning each address.
    std::vector<PageActivity> active_pages();

    /// Check if a given address was ever accessed (read or written) in the trace.
    /// Faster than active_pages() for single-address checks.
    bool was_accessed(uint64_t addr);

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
    /// If the data has been persisted from a previous session (sentinel key matches),
    /// build() returns immediately without re-scanning.
    void build();

    /// Check if already built (data persisted in RocksDB).
    bool is_built() const { return built_; }

    /// Invalidate this thread's cached RocksDB iterators if they belong to
    /// our DB.  Call this BEFORE closing the DB so that the thread-local
    /// IteratorPair does not hold dangling iterators.
    ///
    /// This is invoked automatically by the destructor, but callers that
    /// need to close the DB before destroying the MemoryModel should call
    /// this first.
    void invalidate_thread_iterators();

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

    /// Internal implementation of read_region that reuses a single iterator pair.
    RegionReadResult read_region_impl(uint64_t addr, size_t size, uint64_t at_inst_id,
                                      rocksdb::Iterator* write_iter,
                                      rocksdb::Iterator* read_iter);

    /// Check if the RocksDB already contains persisted MemoryModel data
    /// matching the current trace file (sentinel key check).
    bool check_persisted_sentinel() const;

    /// Write the sentinel key after a successful build.
    void write_persisted_sentinel();

    /// Compute a fingerprint string for the current trace file.
    std::string compute_trace_fingerprint() const;

    /// Ensure build has been performed.
    void ensure_built();

    const TraceReader& reader_;
    const TraceIndex& index_;

    // RocksDB backing store
    rocksdb::DB* db_ = nullptr;
    rocksdb::ColumnFamilyHandle* mem_cf_ = nullptr;       // mem_write
    rocksdb::ColumnFamilyHandle* mem_read_cf_ = nullptr;  // mem_read (may be null)
    bool has_rocksdb_ = false;

    // Thread-local iterator pool for avoiding repeated NewIterator() calls.
    // Each thread gets its own cached iterator pair (write_iter, read_iter).
    // The pool is tied to a specific DB instance via owner_db pointer.
    struct IteratorPair {
        std::unique_ptr<rocksdb::Iterator> write_iter;
        std::unique_ptr<rocksdb::Iterator> read_iter;
        rocksdb::DB* owner_db = nullptr;  // which DB these iterators belong to
    };
    IteratorPair& get_thread_iterators();
    static thread_local IteratorPair tl_iterators_;

    // In-memory cache for recently queried writes (protected by cache_mutex_)
    LRUCache<uint64_t, std::vector<MemWrite>> page_cache_{512};
    mutable std::mutex cache_mutex_;  // protects page_cache_ for concurrent queries

    // Page activity cache (populated during build, never changes after)
    std::vector<PageActivity> page_activity_cache_;
    bool page_activity_cached_ = false;

    // Hot-byte read cache: caches recent (addr, inst_id) → byte lookups
    // to avoid repeated RocksDB seeks for the same query.
    struct ByteCacheKey {
        uint64_t addr;
        uint64_t inst_id;
        bool operator==(const ByteCacheKey& o) const {
            return addr == o.addr && inst_id == o.inst_id;
        }
    };
    struct ByteCacheHash {
        size_t operator()(const ByteCacheKey& k) const {
            return std::hash<uint64_t>{}(k.addr) ^ (std::hash<uint64_t>{}(k.inst_id) << 1);
        }
    };
    struct ByteCacheEntry {
        uint8_t value;
        bool known;
        uint64_t writer_id;
    };
    // True LRU cache: per-entry eviction (O(1)) instead of the previous
    // "clear all when full" strategy that caused periodic latency spikes.
    // 65536 slots — same capacity as before, but with proper LRU eviction.
    LRUCache<ByteCacheKey, ByteCacheEntry, ByteCacheHash> byte_cache_{65536};
    mutable std::mutex byte_cache_mutex_;

    CacheStats stats_;  // atomic counters, no mutex needed
    bool built_ = false;
    std::mutex build_mutex_;
};

}  // namespace tenet

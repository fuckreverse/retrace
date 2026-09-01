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
#include <functional>
#include <filesystem>
#include <algorithm>

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
///
/// Configure-time REC_MEMIMG regions form a lazily loaded base layer beneath
/// the access logs. Queries resolve bytes in this order: write log, read log,
/// then snapshot. Snapshot bytes represent memory at trace start (inst_id 0),
/// so using them at a later query instant is an explicit approximation marked
/// by kSnapshotWriterId rather than a traced writer instruction.
class MemoryModel {
public:
    /// Sentinel writer_id marking bytes resolved from the configure-time memory
    /// snapshot (REC_MEMIMG) rather than from the write/read log. The value is
    /// the memory content at trace start (inst_id 0); it is an APPROXIMATION of
    /// the value at the query instant for any address that was never logged.
    static constexpr uint64_t kSnapshotWriterId = UINT64_MAX;

    static bool is_snapshot_writer(uint64_t writer_id) {
        return writer_id == kSnapshotWriterId;
    }

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

    /// Return whether the trace contains a configure-time memory snapshot.
    /// This lazily collects REC_MEMIMG regions on first use.
    bool has_snapshot() const;

    /// Find the inst_id that last wrote to [addr, addr+size) before `before_inst_id`.
    uint64_t last_writer(uint64_t addr, uint8_t size, uint64_t before_inst_id);

    /// Find all inst_ids that wrote to a given address.
    std::vector<uint64_t> write_history(uint64_t addr, uint8_t size);

    /// Get a single byte value at a specific time.
    std::optional<uint8_t> byte_at(uint64_t addr, uint64_t at_inst_id);

    // ─── Multi-thread: writer thread annotation ──────────────────────────
    // inst_ids are file-wide; the owning producer thread is resolved via the
    // trace index's thread chunk table (TraceIndex::thread_at).

    /// Producer thread of the write at `writer_inst_id` (multi-thread
    /// traces). 0 for single-producer traces or snapshot writers.
    uint64_t writer_thread(uint64_t writer_inst_id) const;

    /// Last writer of [addr, addr+size) before `before_inst_id` whose
    /// producer thread == `thread_id`. Returns 0 when no such write exists.
    /// Walks the write history backwards, so it is O(history) — fine for
    /// spot queries, not for bulk scans.
    uint64_t last_writer_on_thread(uint64_t addr, uint8_t size,
                                   uint64_t before_inst_id, uint64_t thread_id);

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

    /// A single bulk-read request for read_batch().
    struct ReadRequest {
        uint64_t addr;
        size_t   size;
        uint64_t at_inst_id;
    };

    /// Batch-read multiple memory regions in a single call.
    ///
    /// Requests are internally sorted by page so that all accesses to the
    /// same page share one PageWriteIndex load (RocksDB forward scan) and
    /// benefit from the thread-local page cache.
    ///
    /// This is the preferred API for passes that issue many scattered
    /// read_region() calls (e.g. objc args, memory_string, syscall_intercept,
    /// memory_snapshot) — it converts N random RocksDB seeks into a
    /// page-sorted sequential access pattern, mirroring the 4.5× speedup
    /// originally achieved inside memory_snapshot_pass but now available to
    /// every consumer.
    ///
    /// Returns one RegionReadResult per input request (same order as input).
    std::vector<RegionReadResult> read_batch(const std::vector<ReadRequest>& requests);

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
    /// Optional progress callback: (current_insts, total_insts).
    using BuildProgressFn = std::function<void(uint64_t, uint64_t)>;
    void build(BuildProgressFn progress_fn = nullptr);

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

    /// Invalidate the thread-local page-cache entry if it belongs to this
    /// instance.  Called from destructor to prevent dangling pointers.
    void invalidate_tl_page_cache();

private:
    static constexpr uint64_t kPageShift = 12;
    static constexpr uint64_t kPageSize = 1ULL << kPageShift;
    static constexpr uint8_t MAX_WRITE_SIZE = 16;

    static uint64_t page_of(uint64_t addr) { return addr >> kPageShift; }

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

    // ─── Per-Page Sorted Write Index ────────────────────────────────────
    // Each entry records one write event compactly: the page-relative offset
    // of the first byte, the write size, the inst_id, and the data bytes.
    // Entries are stored sorted by (page_offset ASC, inst_id ASC) so that
    // std::upper_bound can find the last write covering any byte at any time
    // in O(log W) comparisons — eliminating the RocksDB Prev() hot loop.
    struct PageWriteEntry {
        uint16_t page_offset; // first byte offset within the page [0, 4095]
        uint8_t  size;        // write size in bytes [1, 16]
        uint8_t  _pad = 0;
        uint64_t inst_id;     // instruction that performed the write
        uint8_t  data[16];    // written bytes
    };
    static_assert(sizeof(PageWriteEntry) == 32, "PageWriteEntry must be 32 bytes");

    // Comparator: sort by (page_offset, inst_id) — both ascending.
    struct PageWriteEntryLess {
        bool operator()(const PageWriteEntry& a, const PageWriteEntry& b) const noexcept {
            if (a.page_offset != b.page_offset) return a.page_offset < b.page_offset;
            return a.inst_id < b.inst_id;
        }
        // Heterogeneous lookup: compare (offset, inst_id) pair against an entry
        bool operator()(const PageWriteEntry& e, std::pair<uint16_t,uint64_t> k) const noexcept {
            if (e.page_offset != k.first) return e.page_offset < k.first;
            return e.inst_id < k.second;
        }
        bool operator()(std::pair<uint16_t,uint64_t> k, const PageWriteEntry& e) const noexcept {
            if (k.first != e.page_offset) return k.first < e.page_offset;
            return k.second < e.inst_id;
        }
    };

    using PageWriteIndex = std::vector<PageWriteEntry>;

    /// Load all write entries for `page` from RocksDB into a sorted PageWriteIndex.
    /// Returns nullptr on error or if RocksDB is not available.
    /// Result is inserted into page_index_cache_ under cache_mutex_.
    ///
    /// Returns a shared_ptr so callers can hold the index alive across an
    /// unlocked query window without fear of LRU eviction destroying it
    /// mid-read (which would be a use-after-free under concurrent
    /// read_region() from parallel passes).  The PageWriteIndex itself is
    /// immutable once loaded, so a stale-by-eviction copy is still correct.
    std::shared_ptr<const PageWriteIndex> load_page_index(uint64_t page,
                                           rocksdb::Iterator* write_iter,
                                           rocksdb::Iterator* read_iter);

    /// Look up a single byte in a PageWriteIndex.  Returns true and fills
    /// `out_value` / `out_writer` if a covering write was found at or before
    /// `search_id` (i.e. inst_id <= search_id).
    static bool index_read_byte(const PageWriteIndex& idx,
                                 uint16_t page_offset,
                                 uint64_t search_id,
                                 uint8_t& out_value,
                                 uint64_t& out_writer) noexcept;

    /// Batch-read a contiguous range of bytes [start_offset, start_offset+count)
    /// within one page from a PageWriteIndex.  Much faster than calling
    /// index_read_byte() per byte because it uses a single reverse scan.
    /// Fills `out_data` and `out_known` arrays (must have `count` elements).
    /// Returns number of bytes resolved (known_count).
    static size_t index_read_range(const PageWriteIndex& idx,
                                    uint16_t start_offset,
                                    uint16_t count,
                                    uint64_t search_id,
                                    uint8_t* out_data,
                                    bool* out_known) noexcept;

    /// Find the inst_id of the most recent write covering `page_offset` with
    /// inst_id <= `search_id`.  Returns 0 if no such write exists.
    static uint64_t index_last_writer(const PageWriteIndex& idx,
                                       uint16_t page_offset,
                                       uint64_t search_id) noexcept;

    /// Check if the RocksDB already contains persisted MemoryModel data
    /// matching the current trace file (sentinel key check).
    bool check_persisted_sentinel() const;

    /// Write the sentinel key after a successful build.
    void write_persisted_sentinel();

    /// Compute a fingerprint string for the current trace file.
    std::string compute_trace_fingerprint() const;

    /// Ensure build has been performed.
    void ensure_built();

    /// Lazily collect and sort the configure-time REC_MEMIMG base layer.
    void ensure_snapshot_loaded();

    /// Fill unresolved bytes from the snapshot base layer.
    void apply_snapshot(uint64_t addr, uint8_t size, MemReadResult& result);
    void apply_snapshot(uint64_t addr, RegionReadResult& result);

    // ─── In-memory fallback helpers (used when has_rocksdb_ == false) ────
    MemReadResult read_inmemory(uint64_t addr, uint8_t size, uint64_t at_inst_id);
    uint64_t last_writer_inmemory(uint64_t addr, uint8_t size, uint64_t search_id);
    std::vector<uint64_t> write_history_inmemory(uint64_t addr, uint8_t size);
    std::optional<uint8_t> byte_at_inmemory(uint64_t addr, uint64_t at_inst_id);
    bool was_accessed_inmemory(uint64_t addr);

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
    //
    // CRITICAL: RocksDB iterators must be destroyed BEFORE the DB is closed.
    // Because tl_iterators_ is static thread_local, a TBB worker thread's
    // copy survives even after the owning MemoryModel/DB is destroyed.
    // The destructor unregisters from the global registry (see .cpp) so
    // that invalidate_thread_iterators() can clear ALL threads' iterators
    // before DB close — preventing a use-after-free SIGSEGV.
    struct IteratorPair {
        std::unique_ptr<rocksdb::Iterator> write_iter;
        std::unique_ptr<rocksdb::Iterator> read_iter;
        rocksdb::DB* owner_db = nullptr;  // which DB these iterators belong to
        bool registered = false;          // true once added to global registry
        ~IteratorPair();
    };
    IteratorPair& get_thread_iterators();
    static thread_local IteratorPair tl_iterators_;

    // ── Global iterator registry (cross-thread cleanup) ──
    // Registers/unregisters an IteratorPair in the global thread-tracking set.
    // Called from get_thread_iterators() and ~IteratorPair() respectively.
    static void register_iterator_pair(IteratorPair* p);
    static void unregister_iterator_pair(IteratorPair* p);
    // Clear all threads' iterators that belong to db_ (called by
    // invalidate_thread_iterators()).  Defined here so it can access
    // the private IteratorPair type.
    static void invalidate_all_iterators_for_db(rocksdb::DB* db);

    // In-memory cache for recently queried writes (protected by cache_mutex_)
    LRUCache<uint64_t, std::vector<MemWrite>> page_cache_{512};

    // Per-page sorted write index — the fast query path (protected by cache_mutex_).
    // Key: page number (addr >> kPageShift).
    // Value: shared_ptr to a sorted vector of PageWriteEntry (see above).
    //
    // shared_ptr (rather than PageWriteIndex by value) makes read_region()
    // safe under concurrent access from parallel passes: a query copies out a
    // shared_ptr under the lock, releases the lock, and then reads the vector
    // without fear that an LRU eviction on another thread move-assigns over
    // the slot it is iterating.  Capacity: 512 pages × ~1000 entries × 32 B
    // ≈ 16 MB worst-case.
    LRUCache<uint64_t, std::shared_ptr<PageWriteIndex>> page_index_cache_{512};

    // shared_mutex: page_index_cache_ stores shared_ptr<const PageWriteIndex>
    // which is immutable once loaded, so concurrent readers use shared_lock +
    // peek().  Only load_page_index() (insert) needs a unique_lock.  This
    // eliminates the parallel-pass read contention that the former exclusive
    // mutex caused under run_all(N).
    mutable std::shared_mutex index_cache_mutex_;  // protects page_index_cache_
    mutable std::mutex page_cache_mutex_;           // protects page_cache_ (in-mem fallback)

    // Lazily loaded REC_MEMIMG base layer. It is intentionally excluded from
    // active_pages()/was_accessed(): a snapshot is initial state, not an access.
    // snapshot_regions_ is written once under snapshot_mutex_ before
    // snapshot_loaded_ is released; afterwards it is read lock-free.
    std::vector<MemSnapshotRegion> snapshot_regions_;
    std::atomic<bool> snapshot_loaded_{false};
    mutable std::mutex snapshot_mutex_;

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

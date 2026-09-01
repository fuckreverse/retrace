#pragma once

#include "common/types.h"
#include "io/trace_reader.h"

#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/write_batch.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace tenet {

/// Callback for progress reporting: (processed_records, total_file_bytes)
///
/// Phase convention:
///   - During scan (Phase 1): 0 ≤ processed ≤ total, with total = file_size.
///   - During compaction (Phase 2): processed > total.  The value
///     (processed - total) encodes the compaction step (1, 2, 3) out of 3
///     column families.  Callers can detect this with `processed > total`.
using ProgressCallback = std::function<void(uint64_t processed, uint64_t total)>;

/// Statistics from an index build.
struct IndexStats {
    uint64_t inst_count = 0;
    uint64_t anchor_count = 0;
    uint64_t code_count = 0;
    uint64_t event_count = 0;
    uint64_t total_records = 0;
    double build_seconds = 0.0;
    uint32_t sparse_interval = 256;  ///< actual SPARSE_INTERVAL used (adaptive)
    uint32_t num_shards = 1;         ///< number of parallel build shards used
};

/// Column family names used in the RocksDB index.
namespace cf {
    constexpr const char* META       = "meta";
    constexpr const char* OFFSET     = "offset";     // sparse inst_id → file_offset
    constexpr const char* ANCHOR     = "anchor";     // anchor sequential id → file_offset
    constexpr const char* MEM_WRITE  = "mem_write";  // [page|byte_off|inst_id] → byte_val
    // MEM_READ: mirrors MEM_WRITE but for memory READS. A read access carries
    // the value that was in memory at that instant, so when an address was
    // never WRITTEN by traced code (e.g. a buffer prepared by uninstrumented
    // code that the traced function then loads), the decoder can still recover
    // the value from the most recent read at or before the query inst_id.
    // Key/value encoding is identical to MEM_WRITE.
    constexpr const char* MEM_READ   = "mem_read";   // [page|byte_off|inst_id] → byte_val
    // REG_WRITES: inverted index for fast "find last writer of register R before inst_id".
    // Key format (10 bytes, big-endian for correct sort order):
    //   u16 reg_index (0..33)  +  u64 inst_id
    // Value: empty (key encodes all needed info).
    // SeekForPrev on key=(reg, inst_id) returns the largest entry ≤ (reg, inst_id),
    // giving the most recent write of that register in O(log N) instead of O(N).
    constexpr const char* REG_WRITES = "reg_writes"; // (reg_idx << 48 | inst_id) → ""
    // CODE_BYTES: stores raw instruction bytes extracted from REC_CODE records.
    // Built in the same single pass as the main index, eliminating a second
    // full file scan for CodeTable population (P1.9 optimization).
    // Key: u64 runtime_pc (big-endian, 8 bytes)
    // Value: u8 opcode[4]  (AArch64 instruction, little-endian)
    constexpr const char* CODE_BYTES  = "code_bytes";  // runtime_pc → 4-byte opcode
    // NOTE: Pass result blobs are no longer stored in RocksDB.
    // They are stored as plain files in <index_dir>/pass_cache/<name>.bin
    // because pass blobs are opaque byte arrays with no need for DB features
    // (no key lookup, no iteration, no transactions).  Plain files allow
    // zero-copy mmap reads and avoid the 2 GB macOS pread SST limit entirely.
}

/// Manages the RocksDB-based trace index.
/// For M1 we build: sparse offset index + anchor index.
/// PC/mem indices are deferred to M2/M3.
class TraceIndex {
public:
    ~TraceIndex();

    /// Explicitly close the RocksDB DB and join all background threads.
    /// Safe to call multiple times (idempotent).  After close(), the index
    /// is no longer usable but the DB's background compaction/flush threads
    /// are guaranteed to have exited.
    ///
    /// This is used to avoid a macOS-specific crash: pthread_mutex_destroy()
    /// uses a global os_unfair_lock that can collide with RocksDB's background
    /// threads' own pthread_mutex_destroy() calls, triggering
    /// _os_unfair_lock_corruption_abort.  Call close() before destroying
    /// MemoryModel (whose ~mutex() runs pthread_mutex_destroy).
    void close();

    // Movable but not copyable
    TraceIndex(TraceIndex&& other) noexcept;
    TraceIndex& operator=(TraceIndex&& other) noexcept;
    TraceIndex(const TraceIndex&) = delete;
    TraceIndex& operator=(const TraceIndex&) = delete;

    /// Open or build the index for a given trace file.
    /// If a valid cached index exists, opens it directly (< 50ms).
    /// Otherwise, performs a full sequential build.
    /// The build is automatically parallelised over available CPU cores using
    /// ANCHOR record boundaries as shard boundaries (P1.5 optimisation).
    static Result<TraceIndex> open_or_build(
        const TraceReader& reader,
        ProgressCallback progress = nullptr);

    /// Returns the RocksDB index directory for a given trace file
    /// (`<trace_dir>/<trace_name>.tenet/`), without opening or building
    /// anything. Useful for callers that need to reference the index
    /// directory before (or without) calling open_or_build(), e.g. to
    /// place a session lock file alongside the index data.
    static std::filesystem::path index_dir_for(const TraceReader& reader);

    /// Result of offset_of_with_pc(): file offset + resolved PC at that offset.
    /// `seed_pc` is only meaningful for v5 (HF_PC_DELTA) traces;
    /// it equals the absolute PC of the target instruction so callers can
    /// create a seeded Iterator or directly call as_inst() correctly.
    struct OffsetResult {
        uint64_t offset;    ///< byte offset into the trace file
        uint64_t seed_pc;   ///< resolved PC of the instruction at `offset`
    };

    /// Get file offset for a given inst_id.
    /// Uses sparse index (every 256th inst) + linear scan.
    /// Compatible with both v4 and v5 traces (correct byte-size calculation).
    uint64_t offset_of(uint64_t inst_id, const TraceReader& reader) const;

    /// Like offset_of() but also returns the resolved absolute PC of the target
    /// instruction. Required for correctly calling as_inst() on v5 traces.
    OffsetResult offset_of_with_pc(uint64_t inst_id, const TraceReader& reader) const;

    /// Find the nearest anchor at or before the given inst_id.
    /// Returns (anchor_sequential_index, file_offset, inst_id_of_anchor).
    struct AnchorInfo {
        uint64_t anchor_idx;
        uint64_t file_offset;
        uint64_t inst_id;  // the inst_id at which this anchor appears
    };
    AnchorInfo nearest_anchor_before(uint64_t inst_id) const;

    /// Nearest anchor at or before inst_id that belongs to producer thread
    /// `thread_id` (multi-thread traces). When the anchor table carries no
    /// thread annotations (single-thread legacy trace), this falls back to
    /// nearest_anchor_before(). The returned anchor belongs to the thread's
    /// own instruction stream, so replaying forward from it — skipping
    /// foreign-thread INST records — reconstructs that thread's register
    /// state correctly.
    AnchorInfo nearest_thread_anchor_before(uint64_t inst_id,
                                            uint64_t thread_id) const;

    /// Whether the anchor table carries per-anchor thread annotations
    /// (i.e. the trace contains THREAD records).
    bool anchors_have_threads() const { return anchors_have_threads_; }

    /// ── Thread chunk table (multi-thread traces) ─────────────────────────
    /// One entry per THREAD marker: (first inst_id of the chunk, thread_id).
    /// Chunks partition the global inst_id space; `thread_at(inst_id)` is a
    /// binary search. The table is persisted in the META CF so cached
    /// indexes answer thread queries without re-scanning the trace.
    /// Empty for single-producer traces (thread_at() then reports 0).
    const std::vector<std::pair<uint64_t, uint64_t>>& thread_chunks() const {
        return thread_chunks_;
    }

    /// Producer thread of the instruction at `inst_id`. Returns 0 for
    /// single-producer traces or inst_ids before the first THREAD marker.
    uint64_t thread_at(uint64_t inst_id) const;

    /// Distinct producer threads observed in the trace (sorted).
    std::vector<uint64_t> thread_ids() const;

    /// Find the most recent instruction before `before_id` that wrote `reg_idx`.
    /// Uses the REG_WRITES inverted index: O(log N) via RocksDB SeekForPrev.
    /// Returns the inst_id of the last writer, or 0 if no writer exists.
    /// Falls back to linear scan (offset_of + iterate) when REG_WRITES CF is absent
    /// (e.g., old cache rebuilt before this CF was introduced).
    uint64_t find_last_writer_of(uint8_t reg_idx, uint64_t before_id,
                                 const TraceReader& reader) const;

    /// Populate a CodeTable from the embedded CODE_BYTES column family.
    /// Call this instead of scanning the trace file a second time.
    /// Returns the number of distinct PCs loaded (0 if CF absent or empty).
    uint64_t load_code_table(class CodeTable& out) const;

    /// Get total instruction count in the trace.
    uint64_t inst_count() const { return stats_.inst_count; }

    /// Get build statistics.
    const IndexStats& stats() const { return stats_; }

    /// Check if this index is still valid for the given reader.
    bool is_valid_for(const TraceReader& reader) const;

    /// Integrity check result.
    struct IntegrityResult {
        bool ok = true;
        std::string error;  ///< non-empty if ok==false
    };

    /// Verify the integrity of the index.
    /// Runs RocksDB VerifyChecksum() and cross-checks stored trace hash
    /// against the reader's current content.
    /// Returns immediately (<10ms for a warm cache) if the DB is healthy.
    IntegrityResult verify_integrity(const TraceReader& reader) const;

    // ─── Session persistence (bookmarks + last cursor) ────────────────────

    /// Save bookmarks to the META column family.
    /// @param bookmarks  Sorted list of inst_ids to persist.
    void save_bookmarks(const std::vector<uint64_t>& bookmarks);

    /// Load bookmarks from the META column family.
    /// Returns an empty vector if no bookmarks are stored.
    std::vector<uint64_t> load_bookmarks() const;

    /// Save the last-visited instruction id (for "continue where you left off").
    void save_last_inst(uint64_t inst_id);

    /// Load the last-visited instruction id, or 0 if not stored.
    uint64_t load_last_inst() const;

    // ─── Generic pass-result blob cache ──────────────────────────────────
    //
    // Pass results are persisted as plain files under
    //   <index_dir>/pass_cache/<pass_name>.bin
    // rather than inside RocksDB, because:
    //   - Blobs are opaque byte arrays; no DB key lookup / iteration needed.
    //   - Large blobs (xref, cfg, symbol_annotation: 100s of MB) caused
    //     RocksDB SST files to exceed macOS pread's 2 GB EINVAL limit.
    //   - Plain files allow zero-copy mmap reads and simple atomic replace.
    //
    // Cache validity: when the RocksDB index is rebuilt (schema / file_size /
    // trace_hash mismatch) the entire .tenet directory is wiped by DestroyDB,
    // which also removes the pass_cache/ subdirectory automatically.

    /// Persist a pass-result blob.  Overwrites any previously saved value.
    /// @param pass_name  Unique pass identifier (e.g. "xref", "function").
    /// @param data       Pointer to serialized bytes.
    /// @param size       Byte count.
    void save_pass_blob(std::string_view pass_name,
                        const void* data, size_t size);

    /// Load a previously persisted pass-result blob.
    /// Returns false (and leaves `out` unchanged) if no blob exists for this pass.
    /// @param pass_name  Same identifier used in save_pass_blob().
    /// @param out        Receives the raw bytes on success.
    bool load_pass_blob(std::string_view pass_name, std::string& out) const;

    /// Delete a persisted pass-result blob, forcing re-computation on the next run.
    /// No-op if no blob exists for this pass.
    /// @param pass_name  Same identifier used in save_pass_blob().
    void delete_pass_blob(std::string_view pass_name);

    /// Enumerate all persisted pass-result blobs.
    /// Returns a list of (pass_name, blob_size_bytes) pairs for every entry
    /// in the META CF whose key starts with "pass:".
    /// Useful for the cache management panel.
    struct PassBlobInfo {
        std::string name;    ///< Pass name (without "pass:" prefix)
        size_t      size;    ///< Blob size in bytes
    };
    std::vector<PassBlobInfo> list_pass_blobs() const;

    /// Delete all persisted pass-result blobs in one batch operation.
    /// Returns the number of entries deleted.
    size_t delete_all_pass_blobs();

    /// Return the absolute filesystem path where a pass blob would be stored.
    /// Useful when a pass wants to write an uncompressed side-car file to the
    /// same directory without going through save_pass_blob's zstd compressor.
    /// Returns an empty path if the index has no db_path.
    std::filesystem::path pass_blob_file_path(std::string_view pass_name) const;

private:
    TraceIndex() = default;

    /// Build the index from scratch.
    static Result<TraceIndex> build(const TraceReader& reader, 
                                    const std::filesystem::path& db_path,
                                    ProgressCallback progress);

    std::unique_ptr<rocksdb::DB> db_;
    std::vector<rocksdb::ColumnFamilyHandle*> cf_handles_;
    IndexStats stats_;
    std::filesystem::path db_path_;

    // In-memory anchor table for fast binary search.
    // Each entry: (inst_id_at_anchor, file_offset_of_anchor)
    struct AnchorEntry {
        uint64_t inst_id;
        uint64_t file_offset;
    };
    std::vector<AnchorEntry> anchors_;

    // Per-anchor owning thread (parallel to anchors_). Built during the same
    // Phase 0 scan: THREAD records observed while walking the file assign
    // every anchor until the next THREAD marker. Empty for traces without
    // any THREAD record (single-producer legacy format) — thread_at_anchor()
    // then reports 0.
    std::vector<uint64_t> anchor_threads_;
    bool anchors_have_threads_ = false;

    // Thread chunk table: (first inst_id of chunk, thread_id), ascending.
    // Collected during Phase 0 and persisted in the META CF.
    std::vector<std::pair<uint64_t, uint64_t>> thread_chunks_;

    // Sparse offset granularity (adaptive: set at build time based on inst_count).
    // Default 256; for large traces (>16M inst) this is increased to keep the
    // sparse index ≤ 65536 entries and reduce RocksDB lookup overhead.
    uint64_t sparse_interval_ = 256;

    // Minimum and maximum allowed sparse interval values.
    static constexpr uint64_t SPARSE_MIN = 64;
    static constexpr uint64_t SPARSE_MAX = 4096;

    // ─── Hot offset cache ───────────────────────────────────────────────
    // Caches (inst_id → OffsetResult) for repeated offset_of queries.
    // Eliminates the RocksDB seek + linear scan for hot inst_ids (e.g. when
    // the TUI scrolls or when multiple passes query nearby inst_ids).
    // Mutex-protected: the lock is held for ~100ns (hash + promote), which
    // is 50× faster than the RocksDB seek it avoids.
    mutable LRUCache<uint64_t, OffsetResult> offset_cache_{8192};
    mutable std::mutex offset_cache_mtx_;

    // Helper: get column family handle by name
    rocksdb::ColumnFamilyHandle* get_cf(const char* name) const;

    // Public access to DB and mem_write CF for MemoryModel
public:
    rocksdb::DB* raw_db() const { return db_.get(); }
    rocksdb::ColumnFamilyHandle* mem_write_cf() const { return get_cf(cf::MEM_WRITE); }
    rocksdb::ColumnFamilyHandle* mem_read_cf() const { return get_cf(cf::MEM_READ); }
    rocksdb::ColumnFamilyHandle* code_bytes_cf() const { return get_cf(cf::CODE_BYTES); }

    /// Expose the in-memory anchor table for parallel shard partitioning.
    /// Each entry stores (inst_id, file_offset) at an ANCHOR boundary.
    /// Used by MemoryModel::build() to divide the trace into segments with
    /// pre-known inst_id starting points, enabling parallel scanning.
    struct AnchorView {
        uint64_t inst_id;
        uint64_t file_offset;
    };
    size_t anchor_table_size() const { return anchors_.size(); }
    AnchorView anchor_table_at(size_t i) const {
        return {anchors_[i].inst_id, anchors_[i].file_offset};
    }

    /// Return the DB path on disk (used by MemoryModel for SST temp directory).
    const std::filesystem::path& db_path() const { return db_path_; }
};

}  // namespace tenet

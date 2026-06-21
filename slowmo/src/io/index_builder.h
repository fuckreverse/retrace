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
#include <string>

namespace tenet {

/// Callback for progress reporting: (processed_records, total_file_bytes)
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
    constexpr const char* CODE_BYTES = "code_bytes"; // runtime_pc → 4-byte opcode
}

/// Manages the RocksDB-based trace index.
/// For M1 we build: sparse offset index + anchor index.
/// PC/mem indices are deferred to M2/M3.
class TraceIndex {
public:
    ~TraceIndex();

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

    // Sparse offset granularity (adaptive: set at build time based on inst_count).
    // Default 256; for large traces (>16M inst) this is increased to keep the
    // sparse index ≤ 65536 entries and reduce RocksDB lookup overhead.
    uint64_t sparse_interval_ = 256;

    // Minimum and maximum allowed sparse interval values.
    static constexpr uint64_t SPARSE_MIN = 64;
    static constexpr uint64_t SPARSE_MAX = 4096;

    // Helper: get column family handle by name
    rocksdb::ColumnFamilyHandle* get_cf(const char* name) const;

    // Public access to DB and mem_write CF for MemoryModel
public:
    rocksdb::DB* raw_db() const { return db_.get(); }
    rocksdb::ColumnFamilyHandle* mem_write_cf() const { return get_cf(cf::MEM_WRITE); }
    rocksdb::ColumnFamilyHandle* mem_read_cf() const { return get_cf(cf::MEM_READ); }
    rocksdb::ColumnFamilyHandle* code_bytes_cf() const { return get_cf(cf::CODE_BYTES); }
};

}  // namespace tenet

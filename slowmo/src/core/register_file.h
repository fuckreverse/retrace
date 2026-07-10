#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <functional>
#include <mutex>

namespace tenet {

// ═══════════════════════════════════════════════════════════════════════════
// RegisterFileCursor — forward-only sequential register state reconstruction.
//
// Designed for analysis passes that access inst_ids in strictly increasing
// order (e.g. VM abstract pass's anchor iteration). Maintains a running
// register state and only moves forward — no cache, no mutex, zero overhead
// per query beyond the diff replay from the last position.
//
// Total cost over a sorted query sequence = O(N) where N is the trace length,
// because each instruction's diff is applied exactly once. Amortised cost
// per query = O(gap between consecutive query inst_ids).
//
// Usage:
//   RegisterFileCursor cursor(reader, index);
//   for (auto inst_id : sorted_inst_ids) {
//       const RegState& state = cursor.advance_to(inst_id);
//       // use state...
//   }
//
// Thread-safety: NOT thread-safe. One cursor per thread.
// ═══════════════════════════════════════════════════════════════════════════

class RegisterFileCursor {
public:
    RegisterFileCursor(const TraceReader& reader, const TraceIndex& index);
    ~RegisterFileCursor();

    // Non-copyable, non-movable (holds references + pin count).
    RegisterFileCursor(const RegisterFileCursor&) = delete;
    RegisterFileCursor& operator=(const RegisterFileCursor&) = delete;
    RegisterFileCursor(RegisterFileCursor&&) = delete;
    RegisterFileCursor& operator=(RegisterFileCursor&&) = delete;

    /// Advance to target_inst_id and return the state BEFORE that instruction.
    /// target_inst_id must be >= the last advance_to() target (forward-only).
    /// The first call initializes from the nearest anchor before target.
    const RegState& advance_to(uint64_t target_inst_id);

    /// Current inst_id (last advanced-to position).
    uint64_t current_inst_id() const { return current_inst_id_; }

    /// File offset of the next record to process (for checkpoint building).
    uint64_t current_offset() const { return current_offset_; }

    /// Whether the cursor has been initialized.
    bool initialized() const { return initialized_; }

    /// Current state (valid after advance_to).
    const RegState& state() const { return state_; }

    /// Seed the cursor from a known state + position (for checkpoint queries).
    /// After calling this, advance_to(target > inst_id) works without
    /// init_from_anchor.
    void seed(const RegState& state, uint64_t inst_id, uint64_t file_offset);

private:
    void init_from_anchor(uint64_t target_inst_id);

    const TraceReader& reader_;
    const TraceIndex& index_;

    RegState state_{};
    uint64_t current_inst_id_ = 0;
    uint64_t current_offset_ = 0;
    bool initialized_ = false;

    // PC fixup: the forward scan leaves PC = last-processed-instruction's PC.
    // state_before(target) needs target's PC. We peek at the record at
    // current_offset_ to read target's PC and patch state_.gpr[IDX_PC].
    // To keep the running PC correct for the next advance_to(), we save the
    // pre-fixup PC and restore it at the start of the next call.
    uint64_t pre_fixup_pc_ = 0;
    bool has_pre_fixup_pc_ = false;

    // Cached header info (avoid repeated flag checks)
    uint32_t num_gpr_;
    bool is_v5_;
    bool is_v6_;
    bool is_v7_;
    size_t inst_hdr_size_;
    size_t memacc_size_;
    size_t anchor_total_;
};

// ═══════════════════════════════════════════════════════════════════════════
// RegisterFile — random-access register state reconstruction.
//
// Two query strategies:
//
// 1. **Dense checkpoint array** (preferred when built):
//    build_checkpoints() performs one O(N) forward sweep, storing a full
//    RegState snapshot every K instructions. Subsequent state_before()
//    queries are O(K) — load checkpoint, replay at most K-1 diffs.
//    Memory: ~(N/K) * sizeof(RegState). Adaptive K keeps it ~80 MB.
//
// 2. **Anchor + Diff + LRU cache** (fallback / pre-build):
//    Find nearest anchor (binary search), load snapshot, replay diffs.
//    LRU cache amortises repeated nearby queries.
//
// Thread-safety: a single RegisterFile instance IS shared across threads in
// tenet (GUI render thread, MCP/RPC server threads, and background
// PassManager worker threads all hold a reference to the same instance —
// see GuiApp::regfile_ / PassManager::set_regfile()). All public accessors
// therefore take an internal mutex around the LRU cache, and state_before()/
// state_after() return RegState by value (a flat ~800-byte POD copy) rather
// than a reference into the cache, since a reference could otherwise be
// invalidated by a concurrent put()/eviction on another thread.
//
// The checkpoint array is immutable after build and can be read lock-free.
// ═══════════════════════════════════════════════════════════════════════════

class RegisterFile {
public:
    RegisterFile(const TraceReader& reader, const TraceIndex& index);

    /// Get the register state BEFORE instruction `inst_id` executes.
    /// This is the primary query interface. Returned by value — safe to use
    /// after concurrent calls from other threads evict the cache entry.
    ///
    /// If checkpoints are built (build_checkpoints()), uses the O(K) fast
    /// path. Otherwise falls back to LRU cache + anchor replay.
    RegState state_before(uint64_t inst_id);

    /// Get the register state AFTER instruction `inst_id` executes.
    /// Equivalent to state_before(inst_id) + applying inst_id's diffs.
    RegState state_after(uint64_t inst_id);

    /// Configure LRU cache capacity (default: 4096 entries ≈ 1.1 MB).
    void set_cache_capacity(size_t num_entries) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.set_capacity(num_entries);
    }

    /// Pre-populate the LRU cache for the range [start_id, end_id).
    ///
    /// Analysis passes that are about to access a dense sequence of instructions
    /// should call this once before the inner loop. The implementation samples
    /// the range every `stride` instructions (default: matches anchor_interval),
    /// rebuilding register state at each sample point and inserting it into the
    /// cache. Subsequent state_before() calls for any instruction within the
    /// range then find a nearby cached baseline and only need to replay diffs
    /// from that point (at most `stride` records) instead of from the nearest
    /// anchor (potentially thousands of records away).
    ///
    /// The optional `progress` callback is invoked with (samples_done, total)
    /// for long traces (e.g. during a full-trace sweep).
    ///
    /// warm_range() is safe to call multiple times and is a no-op for ranges
    /// already fully cached; it is also safe to call concurrently with other
    /// state_before()/state_after()/warm_*() calls from other threads on the
    /// same instance (internally serialized by mutex_).
    ///
    /// @param start_id  First instruction id in the range to warm (inclusive).
    /// @param end_id    Last instruction id in the range to warm (exclusive).
    ///                  Pass UINT64_MAX to warm through the end of the trace.
    /// @param stride    Spacing between sampled checkpoints (0 = auto: use
    ///                  the anchor interval from the trace header, or 256).
    /// @param progress  Optional progress callback: (done, total) sample counts.
    void warm_range(uint64_t start_id, uint64_t end_id,
                    uint64_t stride = 0,
                    std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Pre-populate the cache at exactly one instruction id.
    /// Equivalent to state_before(inst_id) but discards the return value so
    /// the caller does not need to take a const-ref that may be invalidated by
    /// a later cache eviction.
    void warm_at(uint64_t inst_id);

    // ── Dense checkpoint array ───────────────────────────────────────────

    /// Build dense checkpoint array for O(K) random-access queries.
    ///
    /// Performs one forward sweep over the entire trace, storing a full
    /// RegState snapshot (plus file offset) every `stride` instructions.
    /// After build, state_before() uses checkpoints instead of LRU+rebuild.
    ///
    /// Memory: (inst_count / stride) * (sizeof(RegState) + 16) bytes.
    /// Auto-stride targets ~80 MB. For 10M instructions at stride=128,
    /// memory ≈ 62 MB.
    ///
    /// @param stride  Checkpoint spacing (0 = auto, targeting ~80 MB).
    /// @param progress  Optional (done, total) callback.
    void build_checkpoints(uint64_t stride = 0,
                           std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Check if checkpoints are built.
    bool has_checkpoints() const { return checkpoints_built_.load(std::memory_order_acquire); }

    struct CacheStats {
        uint64_t hits = 0;
        uint64_t misses = 0;
        uint64_t warm_samples = 0;  ///< checkpoints inserted by warm_range()
        uint64_t ckpt_queries = 0;  ///< queries served by checkpoint array
        uint64_t ckpt_fallbacks = 0; ///< checkpoint miss → rebuild fallback
    };
    CacheStats cache_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_stats_;
    }

private:
    /// Rebuild register state at target_id by replaying from nearest anchor.
    /// Does not touch cache_ or cache_stats_ — safe to call without holding
    /// mutex_ (only reads from reader_/index_, which are themselves const&
    /// and safe for concurrent read access).
    RegState rebuild(uint64_t target_id);

    /// Fast query using dense checkpoint array.
    /// O(stride) diff replay from nearest checkpoint.
    RegState state_before_ckpt(uint64_t inst_id);

    const TraceReader& reader_;
    const TraceIndex& index_;

    /// Guards cache_ and cache_stats_ against concurrent access from the GUI
    /// render thread, MCP/RPC server threads, and background analysis
    /// worker threads (see class-level thread-safety note above).
    mutable std::mutex mutex_;
    LRUCache<uint64_t, RegState> cache_{4096};
    CacheStats cache_stats_;

    // ── Dense checkpoint array ───────────────────────────────────────────
    struct Checkpoint {
        RegState state;        // full register snapshot at this inst_id
        uint64_t file_offset;  // file offset of the INST record at this inst_id
    };

    std::atomic<bool> checkpoints_built_{false};
    uint64_t ckpt_stride_ = 0;
    std::vector<Checkpoint> checkpoints_;  // immutable after build
};

}  // namespace tenet

#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <array>
#include <atomic>
#include <functional>

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
// Single query strategy: a **dense checkpoint array** built eagerly at
// init_infra() (CheckpointManager::ensure_checkpoints → build_checkpoints).
// build_checkpoints() performs one O(N) forward sweep, storing a full
// RegState snapshot every K instructions (adaptive K targets ~80 MB).
// Subsequent state_before() queries are O(K) — load checkpoint, replay at
// most K-1 diffs via a seeded RegisterFileCursor.
//
// Thread-safety: the checkpoint array is immutable after build, so all
// state_before()/state_after() queries are lock-free. A single RegisterFile
// instance is shared across threads (GUI render, MCP/RPC, background
// PassManager workers). The only mutable post-build state is the atomic
// CacheStats counters (relaxed fetch_add). state_before()/state_after()
// return RegState by value (a flat ~800-byte POD copy).
// ═══════════════════════════════════════════════════════════════════════════

class RegisterFile {
public:
    RegisterFile(const TraceReader& reader, const TraceIndex& index);

    /// Get the register state BEFORE instruction `inst_id` executes.
    /// This is the primary query interface. Returned by value — safe to use
    /// across threads (the checkpoint array is immutable after build).
    ///
    /// Uses the O(K) checkpoint fast path. If checkpoints are not built yet
    /// (e.g. a GUI thread queries before init_infra() completes), returns an
    /// empty RegState.
    RegState state_before(uint64_t inst_id);

    /// Get the register state AFTER instruction `inst_id` executes.
    /// Equivalent to state_before(inst_id) + applying inst_id's diffs.
    RegState state_after(uint64_t inst_id);

    /// Sample GPR[0..30] at multiple inst_ids in one call.
    ///
    /// This is the shared sampling primitive used by LoopSemanticsPass and
    /// TraceFoldPass to avoid duplicated `state_before()` call loops.
    /// Each `state_before(iid)` returns the full ~800-byte RegState, but
    /// loop analysis only needs GPR[0..30] (x0-x30).  This method fetches
    /// only the needed registers and returns them as a compact vector of
    /// 31-element arrays.
    ///
    /// @param inst_ids  pointer to inst_id array
    /// @param count     number of inst_ids
    /// @returns vector of <count> arrays, each holding GPR[0..30]
    std::vector<std::array<uint64_t, 31>> sample_gprs(
        const uint64_t* inst_ids, size_t count);

    // ── Dense checkpoint array ───────────────────────────────────────────

    /// Build dense checkpoint array for O(K) random-access queries.
    ///
    /// Performs one forward sweep over the entire trace, storing a full
    /// RegState snapshot (plus file offset) every `stride` instructions.
    /// After build, state_before() uses checkpoints (lock-free O(K) replay).
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

    const TraceReader& reader() const { return reader_; }
    const TraceIndex&  index() const  { return index_; }

    struct CacheStats {
        uint64_t ckpt_queries = 0;     ///< queries served by checkpoint array
        uint64_t ckpt_fallbacks = 0;   ///< out-of-range → last checkpoint state
    };
    CacheStats cache_stats() const {
        CacheStats s;
        s.ckpt_queries   = counters_.ckpt_queries.load(std::memory_order_relaxed);
        s.ckpt_fallbacks = counters_.ckpt_fallbacks.load(std::memory_order_relaxed);
        return s;
    }

private:
    /// Fast query using dense checkpoint array.
    /// O(stride) diff replay from nearest checkpoint.
    RegState state_before_ckpt(uint64_t inst_id);

    const TraceReader& reader_;
    const TraceIndex& index_;

    /// Checkpoint query/fallback counters (atomic — lock-free after build).
    struct AtomicCounters {
        std::atomic<uint64_t> ckpt_queries{0};
        std::atomic<uint64_t> ckpt_fallbacks{0};
    };
    mutable AtomicCounters counters_;

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

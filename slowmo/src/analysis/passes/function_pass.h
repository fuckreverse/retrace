#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>  // std::upper_bound, std::lower_bound, std::sort
#include <ankerl/unordered_dense.h>
#include <numeric>    // std::iota

namespace tenet {

class CodeTable;  // forward declaration

// ─── Function analysis result ─────────────────────────────────────────────

/// A single function call event.
struct CallEvent {
    uint64_t call_inst_id;       // inst_id of the BL/BLR instruction
    uint64_t return_inst_id;     // inst_id of the corresponding RET (0 if not found)
    uint64_t call_site_pc;       // PC of the call instruction
    uint64_t target_pc;          // PC of the call target (first instruction of callee)
    uint64_t depth;              // Call stack depth at this point
    bool is_tail_call = false;   // Whether this was detected as a tail call (b/br)
};

/// Function info (aggregated from call events).
struct FunctionInfo {
    uint64_t entry_pc;           // First PC in this function
    std::string name;            // Symbol name (if known), else "sub_XXXXXX"
    uint64_t total_calls;        // How many times this function was called
    uint64_t total_instructions; // Sum of instructions across all invocations
    std::vector<size_t> call_event_indices; // Indices into CallEvent vector
};

/// Result of function analysis.
struct FunctionResult {
    /// All call events in order.
    std::vector<CallEvent> call_events;

    /// Functions by entry PC.
    ankerl::unordered_dense::map<uint64_t, FunctionInfo> functions;

    /// Call stack at a given instruction ID.
    /// Returns vector of call event pointers from outermost to innermost.
    /// O(N) worst case — suitable for interactive UI at the current position.
    /// For bulk queries (e.g. sparkline with 600 samples), use depth_at().
    std::vector<const CallEvent*> call_stack_at(uint64_t inst_id) const;

    /// Fast O(log N) depth query at inst_id.
    /// Uses the pre-built depth_table_ sorted by inst_id to binary-search the
    /// last depth-change event before inst_id.  Falls back to full scan if the
    /// table has not been built yet.
    uint64_t depth_at(uint64_t inst_id) const;

    /// Which function contains inst_id? (by checking which call is active)
    /// O(log N) via sorted index built lazily on first call.
    const FunctionInfo* function_at(uint64_t inst_id) const;

    /// Get call event if inst_id is a call site.
    const CallEvent* call_at(uint64_t inst_id) const {
        auto it = call_site_map_.find(inst_id);
        if (it == call_site_map_.end()) return nullptr;
        return &call_events[it->second];
    }

    /// Get call event if inst_id is a return site.
    const CallEvent* return_at(uint64_t inst_id) const {
        auto it = return_site_map_.find(inst_id);
        if (it == return_site_map_.end()) return nullptr;
        return &call_events[it->second];
    }

    /// Build the depth_table_ for fast depth_at() queries.
    /// Called once after the pass completes (or after deserialization).
    void build_depth_table();

    /// Build the sorted call event index for fast function_at() / call_stack_at().
    /// Called automatically (lazy) on first query, or can be triggered explicitly.
    void build_call_index() const;

    // Internal lookup maps (populated during pass)
    ankerl::unordered_dense::map<uint64_t, size_t> call_site_map_;   // call_inst_id → index
    ankerl::unordered_dense::map<uint64_t, size_t> return_site_map_; // return_inst_id → index

    // Depth-table for fast bulk depth queries.
    // Sorted by inst_id; each entry is the depth AFTER that inst_id fires.
    // Built by build_depth_table(); empty until then.
    struct DepthEntry {
        uint64_t inst_id;  // call_inst_id (or return_inst_id) that caused a change
        uint64_t depth;    // stack depth immediately after this event
    };
    std::vector<DepthEntry> depth_table_;

    // Sorted index into call_events by call_inst_id for O(log N) lookups.
    // Lazily built on first function_at() / call_stack_at() call.
    mutable std::vector<size_t> sorted_call_indices_;  // indices into call_events, sorted by call_inst_id
    mutable bool call_index_built_ = false;
};

// ─── FunctionCollector ────────────────────────────────────────────────────

/// TraceCollector that implements function call/return pairing via a state machine.
/// Extracted from FunctionPass to enable scan fusion via TraceScanEngine.
///
/// Two-phase design for maximum performance:
///   Phase 1 (on_inst loop): Collects only branch-related events into a compact
///     BranchEvent array.  The pc_kind_ lookup table is a sorted flat array
///     (binary search) instead of a hash map — better cache behaviour for
///     sparse PC sets.
///   Phase 2 (end()): Runs the call/return state machine over the small
///     BranchEvent array (typically 2-5% of total instructions), then performs
///     tail-call resolution and bookkeeping.
class FunctionCollector final : public TraceCollector {
public:
    /// `has_branch_hint` should be set to `reader.header().has_branch_hint()` so
    /// on_inst can skip the binary-search pc_kind lookup for the vast majority of
    /// instructions (ordinary ones) using the cheap bit-shift path instead.
    FunctionCollector(CodeTable& code_table, uint64_t module_slide, uint32_t num_gpr,
                      bool has_branch_hint = false);

    std::string_view name() const override { return "FunctionCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void on_anchor(uint64_t inst_id, const AnchorView& anchor) override;
    void end() override;

    /// Set a progress callback for Phase 2.  The callback receives a float in
    /// [0, 1] representing progress within Phase 2 only.  The caller is
    /// responsible for mapping this into the overall pass progress range.
    /// Must be called before end().
    using ProgressFn = std::function<void(float)>;
    void set_progress_fn(ProgressFn fn) { progress_fn_ = std::move(fn); }

    /// Take ownership of the result after the scan completes.
    FunctionResult take_result() { return std::move(result_); }

    /// Statistics from the scan (valid after end()).
    uint64_t tail_calls_detected() const { return tail_calls_detected_; }
    uint64_t non_local_unwinds() const { return non_local_unwinds_; }

private:
    // ── Opcode classification constants ──
    static constexpr uint8_t KIND_CALL   = 0x1;
    static constexpr uint8_t KIND_RET    = 0x2;
    static constexpr uint8_t KIND_BRANCH = 0x4;

    // ── Compact event record (Phase 1 output / Phase 2 input) ───────────
    // Replaces per-instruction state machine updates with a two-step approach:
    // Phase 1 records only branch-class events; Phase 2 processes them.
    struct BranchEvent {
        uint64_t inst_id;
        uint64_t pc;
        uint8_t  kind;         // KIND_CALL | KIND_RET | KIND_BRANCH; 0 = plain successor
        bool     sp_valid;
        uint64_t sp;           // SP value (valid when sp_valid == true)
        // For CALL events: target_pc is resolved in Phase 1 when the successor
        // instruction fires (phase1_need_next_).  0 = not yet resolved.
        uint64_t target_pc;
    };

    struct StackFrame {
        size_t call_event_idx;
        uint64_t return_pc;     // LR at time of call (pc + 4 for BL)
        uint64_t entry_sp;      // SP when this frame was pushed (0 if unknown)
    };

    struct TailCallCandidate {
        uint64_t inst_id;
        uint64_t jump_pc;
        uint64_t target_pc;     // PC of first instruction after the jump
        uint64_t sp;            // SP at time of jump
        bool sp_known;
    };

    // ─── Phase-1 helpers ────────────────────────────────────────────────
    /// Look up the kind bits for `pc`.  Returns 0 if not a branch-class PC.
    /// Uses binary search on the sorted pc_kind_sorted_ flat array.
    inline uint8_t lookup_pc_kind(uint64_t pc) const;

    // ─── Phase-2 helpers ────────────────────────────────────────────────
    void run_state_machine();
    void handle_deferred_ret(uint64_t pc, uint64_t ret_inst_id);
    void handle_branch_event(const BranchEvent& ev);

    // ── Configuration (immutable after construction) ──
    CodeTable& code_table_;
    uint64_t module_slide_;
    uint32_t num_gpr_;
    /// When true, on_inst reads the branch-hint nibble (bits[7:4] of inst.nzcv)
    /// before falling back to the binary-search pc_kind table.  Set when the
    /// trace file has HF_BRANCH_HINT (qbditrace records branch class inline).
    bool has_branch_hint_ = false;

    // ── Pre-built PC classification table (sorted flat array) ──────────
    // Replaces ankerl::unordered_dense::map<uint64_t, uint8_t>:
    //   - Binary search on a sorted contiguous array has much better cache
    //     behaviour than open-addressing hash map for sparse PC sets
    //   - No per-entry heap allocation overhead
    struct PcKindEntry {
        uint64_t pc;
        uint8_t  kind;
    };
    std::vector<PcKindEntry> pc_kind_sorted_;  // sorted by pc

    // ── Phase-1 output ──────────────────────────────────────────────────
    // Compact event stream: only CALL/RET/BRANCH instructions are recorded.
    // Typically 2-5% of total instruction count.
    std::vector<BranchEvent> branch_events_;

    // SP state maintained during Phase 1 (to attach to BranchEvent records).
    uint64_t phase1_sp_      = 0;
    bool     phase1_sp_valid_ = false;
    // When phase1_need_next_ is true, the next on_inst call must resolve the
    // target_pc of the last BranchEvent (the preceding CALL).
    bool     phase1_need_next_ = false;

    // ── State machine (Phase 2) ──────────────────────────────────────────
    std::vector<StackFrame> call_stack_;
    std::vector<TailCallCandidate> tail_candidates_;

    // Fast lookup: return_pc → count of frames in call_stack_ with that return_pc.
    ankerl::unordered_dense::map<uint64_t, uint32_t> ret_pc_refcount_;

    // Deferred RET tracking (Phase 2)
    bool     p2_prev_was_ret_   = false;
    uint64_t p2_prev_ret_inst_id_ = 0;

    // Unconditional branch tracking (Phase 2)
    bool     p2_prev_was_branch_  = false;
    uint64_t p2_prev_jump_inst_id_ = 0;
    uint64_t p2_prev_jump_pc_      = 0;
    uint64_t p2_prev_jump_sp_      = 0;
    bool     p2_prev_jump_sp_known_ = false;

    uint64_t non_local_unwinds_ = 0;
    uint64_t tail_calls_detected_ = 0;

    // ── Phase 2 progress callback (optional, set via set_progress_fn()) ──
    ProgressFn progress_fn_;

    // ── Result ──
    FunctionResult result_;
};

// ─── Function analysis pass ───────────────────────────────────────────────

/// Identifies function calls and builds a call graph.
/// Uses BL/BLR → RET matching with a simulated call stack.
/// Result type: FunctionResult
class FunctionPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "function"; }
    std::string_view description() const override {
        return "Function identification via call/return pairing";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // Standalone — uses efficient linear scan with pc_kind filtering
    }

    PassResult run(PassContext& ctx) override;

    float estimated_cost() const override { return 7.0f; }
};

}  // namespace tenet

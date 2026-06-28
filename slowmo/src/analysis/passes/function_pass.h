#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>  // std::upper_bound, std::lower_bound
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
class FunctionCollector final : public TraceCollector {
public:
    FunctionCollector(CodeTable& code_table, uint64_t module_slide, uint32_t num_gpr);

    std::string_view name() const override { return "FunctionCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void on_anchor(uint64_t inst_id, const AnchorView& anchor) override;
    void end() override;

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

    struct StackFrame {
        size_t call_event_idx;
        uint64_t return_pc;     // LR at time of call (pc + 4 for BL)
        uint64_t entry_sp;      // SP when this frame was pushed (0 if unknown)
    };

    struct TailCallCandidate {
        uint64_t inst_id;
        uint64_t jump_pc;
        uint64_t target_pc;     // filled from next instruction's PC
        uint64_t sp;            // SP at time of jump
        bool sp_known;
    };

    void handle_deferred_ret(uint64_t pc);
    void try_fill_call_target(uint64_t cur_inst_id, uint64_t pc);
    void handle_inst_inner(uint64_t cur_inst_id, uint64_t pc,
                           uint64_t sp_new, bool sp_updated);

    // ── Configuration (immutable after construction) ──
    CodeTable& code_table_;
    uint64_t module_slide_;
    uint32_t num_gpr_;

    // ── Pre-built PC classification table ──
    ankerl::unordered_dense::map<uint64_t, uint8_t> pc_kind_;

    // ── State machine ──
    std::vector<StackFrame> call_stack_;
    std::vector<TailCallCandidate> tail_candidates_;

    // Fast lookup: return_pc → count of frames in call_stack_ with that return_pc.
    // Allows O(1) existence check before doing linear search.
    ankerl::unordered_dense::map<uint64_t, uint32_t> ret_pc_refcount_;

    uint64_t current_sp_ = 0;
    bool sp_valid_ = false;

    bool prev_was_unconditional_jump_ = false;
    uint64_t prev_jump_inst_id_ = 0;
    uint64_t prev_jump_pc_ = 0;
    uint64_t prev_jump_sp_ = 0;
    bool prev_jump_sp_known_ = false;

    bool prev_was_ret_ = false;
    uint64_t prev_ret_inst_id_ = 0;

    bool need_next_ = false;  // next inst triggers handle_inst unconditionally

    uint64_t non_local_unwinds_ = 0;
    uint64_t tail_calls_detected_ = 0;

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

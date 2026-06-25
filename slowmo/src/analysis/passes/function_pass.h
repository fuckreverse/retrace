#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>  // std::upper_bound, std::lower_bound
#include <ankerl/unordered_dense.h>
#include <numeric>    // std::iota

namespace tenet {

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
        return {};  // Standalone
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 7.0f; }
};

}  // namespace tenet

#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

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
    std::unordered_map<uint64_t, FunctionInfo> functions;

    /// Call stack at a given instruction ID.
    /// Returns vector of (call_event_index, depth) pairs from bottom to top.
    std::vector<const CallEvent*> call_stack_at(uint64_t inst_id) const;

    /// Which function contains inst_id? (by checking which call is active)
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

    // Internal lookup maps (populated during pass)
    std::unordered_map<uint64_t, size_t> call_site_map_;   // call_inst_id → index
    std::unordered_map<uint64_t, size_t> return_site_map_; // return_inst_id → index
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

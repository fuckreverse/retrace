#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/taint_pass.h"
#include <cstdint>
#include <vector>
#include <unordered_set>

namespace tenet {

// ─── Slice result ─────────────────────────────────────────────────────────

struct SliceResult {
    /// The target (slice criterion) instruction ID.
    uint64_t target_inst_id;

    /// Register index that was sliced.
    uint8_t target_reg;

    /// All instruction IDs that contribute to the slice (backward from target).
    std::vector<uint64_t> slice_inst_ids;

    /// Quick lookup.
    std::unordered_set<uint64_t> slice_set;

    bool is_in_slice(uint64_t inst_id) const {
        return slice_set.count(inst_id) > 0;
    }
};

// ─── Backward slice pass ──────────────────────────────────────────────────

/// Computes a backward slice from a given (inst_id, reg) criterion.
/// Uses the TaintPass result to trace data dependencies backward.
/// Result type: SliceResult
class SlicePass final : public AnalysisPass {
public:
    /// @param target_inst_id  The instruction where slicing starts.
    /// @param target_reg      The register to slice (0-33).
    SlicePass(uint64_t target_inst_id, uint8_t target_reg)
        : target_inst_id_(target_inst_id), target_reg_(target_reg) {}

    std::string_view name() const override { return "slice"; }
    std::string_view description() const override {
        return "Backward slice from a given instruction and register";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"taint"};  // Requires taint analysis
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 3.0f; }

private:
    uint64_t target_inst_id_;
    uint8_t target_reg_;
};

}  // namespace tenet

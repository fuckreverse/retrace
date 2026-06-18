#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <string>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct TraceFoldConfig {
    /// Minimum consecutive iterations of a loop to fold (default: 3).
    uint32_t min_iterations_to_fold = 3;
    /// Maximum representative iterations to keep (first N + last N).
    uint32_t keep_iterations = 2;
    /// If true, output includes per-loop register diff summary.
    bool include_reg_summary = true;
};

// ─── Folded region description ─────────────────────────────────────────────

struct FoldedRegion {
    uint64_t header_pc;          // Loop header PC
    uint64_t first_inst_id;      // First instruction of the folded region
    uint64_t last_inst_id;       // Last instruction of the folded region
    uint64_t total_iterations;   // Total iterations folded
    uint64_t instructions_per_iteration;  // Average body size
    uint64_t total_instructions_folded;   // Total instructions removed

    /// Representative iterations kept (inst_id ranges: [start, end])
    struct IterRange { uint64_t start; uint64_t end; };
    std::vector<IterRange> kept_iterations;

    /// Registers modified across folded iterations (index, first_value, last_value)
    struct RegChange { uint8_t reg; uint64_t first_val; uint64_t last_val; };
    std::vector<RegChange> reg_changes;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct TraceFoldResult {
    std::vector<FoldedRegion> folded_regions;
    uint64_t original_inst_count = 0;
    uint64_t folded_inst_count = 0;        // Instructions remaining after fold
    uint64_t total_instructions_removed = 0;
    float compression_ratio = 1.0f;        // original / folded

    /// Ordered list of inst_id ranges that are kept (not folded).
    /// Can be used to reconstruct a "simplified" trace view.
    struct KeptRange { uint64_t start; uint64_t end; };
    std::vector<KeptRange> kept_ranges;
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Folds repetitive loop iterations in the trace, producing a compressed
/// view that shows only representative iterations plus a summary.
///
/// Dependencies: "loop" pass (for loop detection and iteration counts).
///
/// Result type: TraceFoldResult
class TraceFoldPass final : public AnalysisPass {
public:
    explicit TraceFoldPass(TraceFoldConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "trace_fold"; }
    std::string_view description() const override {
        return "Fold repetitive loop iterations into summaries";
    }
    std::vector<std::string_view> dependencies() const override {
        return { "loop", "xref" };
    }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    TraceFoldConfig cfg_;
};

}  // namespace tenet

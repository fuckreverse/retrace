#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct TraceFoldConfig {
    /// Only fold regions whose complete removed instruction span is contained
    /// in the half-open instruction-ID range [start_inst_id, end_inst_id).
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;
    /// Minimum consecutive iterations of a loop to fold (default: 3).
    uint32_t min_iterations_to_fold = 3;
    /// Maximum representative iterations to keep (first N + last N).
    uint32_t keep_iterations = 2;
    /// If true, output includes per-loop register diff summary.
    bool include_reg_summary = true;
    /// If true (and the trace carries FPR/NEON data, i.e. v7 "HF_HAS_FPR"),
    /// also compute first/last FPR (v0-v31) differences per folded region.
    bool include_fpr_summary = true;
    /// Number of interior sample points (in addition to first/last) used to
    /// classify each register's change pattern across the folded region
    /// (monotonic increasing/decreasing, oscillating, or constant).
    /// 0 disables interior sampling (first/last comparison only).
    uint32_t pattern_sample_points = 6;
};

// ─── Folded region description ─────────────────────────────────────────────

/// Per-register change-pattern classification across the folded (removed)
/// iterations of a region, derived from `pattern_sample_points` interior
/// samples plus the first/last values. This is a cheap heuristic — NOT a
/// substitute for `loop_semantics` — intended to give a quick hint about
/// whether a register looks like a counter/accumulator (monotonic) versus
/// something that is being reused as scratch state (oscillating).
enum class RegChangePattern : uint8_t {
    Constant,     // Value never changed across sampled points.
    Monotonic,    // Strictly increasing or strictly decreasing at every sample.
    Oscillating,  // Changed direction at least once (non-monotonic).
};

inline const char* reg_change_pattern_name(RegChangePattern p) {
    switch (p) {
        case RegChangePattern::Constant:    return "constant";
        case RegChangePattern::Monotonic:   return "monotonic";
        case RegChangePattern::Oscillating: return "oscillating";
    }
    return "unknown";
}

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

    /// GPR registers modified across folded iterations (index, first_value, last_value).
    struct RegChange {
        uint8_t reg;
        uint64_t first_val;
        uint64_t last_val;
        RegChangePattern pattern = RegChangePattern::Oscillating;
    };
    std::vector<RegChange> reg_changes;

    /// NEON/FPR registers (v0-v31) modified across folded iterations.
    /// Only populated when the trace has FPR data (v7 "HF_HAS_FPR") and
    /// `TraceFoldConfig::include_fpr_summary` is set.
    struct FprChange {
        uint8_t reg;
        uint64_t first_lo, first_hi;
        uint64_t last_lo, last_hi;
    };
    std::vector<FprChange> fpr_changes;
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

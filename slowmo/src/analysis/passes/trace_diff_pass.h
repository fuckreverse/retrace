#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>

namespace tenet {

// ─── Diff type enum ───────────────────────────────────────────────────────

enum class DiffType : uint8_t {
    ControlFlow,     // Branch divergence — PCs differ at the same offset
    RegisterValue,   // Same opcode, different register output values
    MemoryValue,     // Same opcode, different memory access values
    OpcodeChange,    // Different opcode at the same instruction offset
};

// ─── Diff entry ───────────────────────────────────────────────────────────

struct DiffEntry {
    uint64_t inst_offset_a;   // instruction offset within region A
    uint64_t inst_offset_b;   // instruction offset within region B
    uint64_t pc;              // PC of the instruction (from region A)
    DiffType type;
    std::string detail;       // human-readable description of the difference
};

// ─── Configuration ────────────────────────────────────────────────────────

struct TraceDiffConfig {
    uint64_t trace_a_start = 0;
    uint64_t trace_a_end = 0;      // exclusive end of region A
    uint64_t trace_b_start = 0;
    uint64_t trace_b_end = 0;      // exclusive end of region B
};

// ─── Result ───────────────────────────────────────────────────────────────

struct TraceDiffResult {
    /// All differences found between the two regions.
    std::vector<DiffEntry> diffs;

    /// Number of instruction pairs that matched perfectly.
    uint64_t matched_count = 0;

    /// Number of instruction pairs that diverged.
    uint64_t diverged_count = 0;

    /// PCs where control flow diverged (unique divergence points).
    std::vector<uint64_t> diverge_points;

    // ─── Query helpers ────────────────────────────────────────────────

    /// Get all diffs at a specific PC.
    std::vector<const DiffEntry*> diffs_at_pc(uint64_t pc) const {
        std::vector<const DiffEntry*> out;
        for (const auto& d : diffs) {
            if (d.pc == pc) out.push_back(&d);
        }
        return out;
    }

    /// Whether any divergence was found.
    bool has_divergence() const { return diverged_count > 0; }

    /// Get only control-flow diffs.
    std::vector<const DiffEntry*> control_flow_diffs() const {
        std::vector<const DiffEntry*> out;
        for (const auto& d : diffs) {
            if (d.type == DiffType::ControlFlow) out.push_back(&d);
        }
        return out;
    }

    /// Get only register-value diffs.
    std::vector<const DiffEntry*> register_value_diffs() const {
        std::vector<const DiffEntry*> out;
        for (const auto& d : diffs) {
            if (d.type == DiffType::RegisterValue) out.push_back(&d);
        }
        return out;
    }
};

// ─── Trace diff pass ──────────────────────────────────────────────────────

/// Compares two regions within the same trace instruction-by-instruction to
/// find behavioral differences.  This is the core differential analysis
/// technique for algorithm reverse engineering: run the same algorithm with
/// different inputs and diff the execution paths.
///
/// Result type: TraceDiffResult
class TraceDiffPass final : public AnalysisPass {
public:
    explicit TraceDiffPass(TraceDiffConfig config)
        : config_(std::move(config)) {}

    ~TraceDiffPass() override = default;

    std::string_view name() const override { return "trace_diff"; }
    std::string_view description() const override {
        return "Compare two trace regions to find behavioral differences";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — operates directly on trace reader + code table
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 6.0f; }

private:
    TraceDiffConfig config_;
};

}  // namespace tenet

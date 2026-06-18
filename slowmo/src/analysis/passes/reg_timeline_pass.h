#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <string>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct RegTimelineConfig {
    /// Which register to track (0-33). If 0xFF, track all modified registers.
    uint8_t target_reg = 0xFF;
    /// Optional range restriction.
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;
    /// Maximum number of timeline entries to collect (0 = unlimited).
    uint64_t max_entries = 0;
};

// ─── Timeline entry ────────────────────────────────────────────────────────

struct RegTimelineEntry {
    uint64_t inst_id;       // Instruction that wrote the register
    uint64_t pc;            // PC of that instruction
    uint8_t  reg_index;     // Which register was written
    uint64_t old_value;     // Value before this write
    uint64_t new_value;     // Value after this write
};

// ─── Result ────────────────────────────────────────────────────────────────

struct RegTimelineResult {
    /// Timeline entries sorted by inst_id.
    std::vector<RegTimelineEntry> entries;

    /// Per-register write count.
    uint64_t write_counts[34] = {};

    /// Total number of register writes observed.
    uint64_t total_writes = 0;

    /// Unique values seen per tracked register (only for single-reg mode).
    std::vector<uint64_t> unique_values;
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Builds a timeline of all writes to a specific register (or all registers),
/// recording the old and new values at each write point.
///
/// This is the native C++ implementation backing the MCP `reg_timeline` tool.
///
/// Dependencies: none (operates directly on TraceReader).
///
/// Result type: RegTimelineResult
class RegTimelinePass final : public AnalysisPass {
public:
    explicit RegTimelinePass(RegTimelineConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "reg_timeline"; }
    std::string_view description() const override {
        return "Build register value timeline showing all writes";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 6.0f; }

private:
    RegTimelineConfig cfg_;
};

}  // namespace tenet

#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct LiteralSearchConfig {
    /// Values to search for in register diffs and immediate operands.
    std::vector<uint64_t> search_values;
    /// Whether to match 32-bit truncation (value & 0xFFFFFFFF).
    bool match_32bit = true;
    /// Whether to search in memory write values.
    bool search_mem_values = true;
    /// Whether to search in register diff values.
    bool search_reg_values = true;
    /// Maximum results per value (0 = unlimited).
    uint64_t max_results = 1000;
};

// ─── Search hit ────────────────────────────────────────────────────────────

struct LiteralHit {
    uint64_t inst_id;
    uint64_t pc;
    uint64_t matched_value;     // The full 64-bit value found
    uint64_t search_value;      // Which search value matched
    enum Source : uint8_t {
        RegDiff,     // Found in register diff (new value)
        MemWrite,    // Found in memory write value
        Immediate,   // Found in instruction immediate field
    } source;
    uint8_t reg_or_size;        // Register index (for RegDiff) or size (for MemWrite)
    uint64_t mem_addr;          // Memory address (for MemWrite, else 0)
};

// ─── Result ────────────────────────────────────────────────────────────────

struct LiteralSearchResult {
    std::vector<LiteralHit> hits;
    uint64_t instructions_scanned = 0;

    /// Group by search value.
    std::vector<std::vector<size_t>> by_value;  // value_idx → hit indices
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Searches for specific literal values in register diffs, memory writes,
/// and instruction immediate fields. Useful for locating where a known
/// constant first appears (e.g., MD5 IV 0x67452301) or tracking a specific
/// address value through the trace.
///
/// Dependencies: none.
///
/// Result type: LiteralSearchResult
class LiteralSearchPass final : public AnalysisPass {
public:
    explicit LiteralSearchPass(LiteralSearchConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "literal_search"; }
    std::string_view description() const override {
        return "Search for specific literal values in register/memory/immediate fields";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

private:
    LiteralSearchConfig cfg_;
};

}  // namespace tenet

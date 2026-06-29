#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

#ifdef TENET_HAS_YARA
struct YR_RULES;
#endif

namespace tenet {

// ─── Configuration ─────────────────────────────────────────────────────────

struct MemSearchConfig {
    /// Patterns to search for. Each pattern is a byte sequence with optional
    /// wildcards (0xFF in the mask = match any byte).
    struct Pattern {
        std::vector<uint8_t> bytes;   // Pattern bytes
        std::vector<uint8_t> mask;    // Mask: 0xFF = wildcard, 0x00 = exact match
        std::string label;            // Optional human-readable label

        Pattern() = default;
        Pattern(std::vector<uint8_t> b, std::string lbl = "")
            : bytes(std::move(b)), mask(bytes.size(), 0x00), label(std::move(lbl)) {}
        Pattern(std::vector<uint8_t> b, std::vector<uint8_t> m, std::string lbl = "")
            : bytes(std::move(b)), mask(std::move(m)), label(std::move(lbl)) {}
    };

    std::vector<Pattern> patterns;

    /// Search in memory write values (default: true).
    bool search_mem_writes = true;
    /// Search in register values / reg_diff (default: false).
    bool search_reg_values = false;
    /// Maximum matches per pattern (0 = unlimited).
    uint64_t max_matches = 1000;
    /// Optional inst_id range to restrict search.
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;
};

// ─── Match result ──────────────────────────────────────────────────────────

struct MemSearchMatch {
    uint64_t inst_id;          // Instruction where match occurred
    uint64_t pc;               // PC of that instruction
    uint64_t addr;             // Memory address (for mem writes) or 0 (for reg)
    uint16_t offset;           // Byte offset within the value where pattern starts
    uint8_t  pattern_index;    // Which pattern matched (index into config.patterns)
    enum Source : uint8_t { MemWrite, RegDiff } source;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct MemSearchResult {
    std::vector<MemSearchMatch> matches;
    uint64_t bytes_scanned = 0;
    uint64_t instructions_scanned = 0;

    /// Matches grouped by pattern index.
    std::vector<std::vector<size_t>> by_pattern;  // pattern_idx → match indices
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Multi-pattern memory/register search engine.
///
/// Strategy selection:
/// - If YARA is available and patterns have no wildcards:
///   Builds a contiguous buffer from all mem-write values, then uses YARA
///   Aho-Corasick (O(N + M)) for multi-pattern matching in a single pass.
///   This eliminates the O(N × P) per-instruction brute-force.
///
/// - Fallback: mask-based linear scan per instruction (always works).
///
/// Designed for locating known byte sequences (keys, IVs, ciphertext blocks).
///
/// Dependencies: none (direct TraceReader scan).
///
/// Result type: MemSearchResult
class MemSearchPass final : public AnalysisPass {
public:
    explicit MemSearchPass(MemSearchConfig cfg = {}) : cfg_(std::move(cfg)) {}
    ~MemSearchPass() override;

    // Non-copyable, movable
    MemSearchPass(const MemSearchPass&) = delete;
    MemSearchPass& operator=(const MemSearchPass&) = delete;
    MemSearchPass(MemSearchPass&& o) noexcept;
    MemSearchPass& operator=(MemSearchPass&& o) noexcept;

    std::string_view name() const override { return "mem_search"; }
    std::string_view description() const override {
        return "Multi-pattern search on memory writes and register values (YARA-accelerated)";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

private:
    MemSearchConfig cfg_;

#ifdef TENET_HAS_YARA
    YR_RULES* yr_rules_ = nullptr;

    /// Compile user-provided patterns into YARA hex rules.
    bool compile_patterns_to_yara();
    /// Run YARA on a contiguous buffer, translate offsets back.
    void yara_scan_buffer(const uint8_t* data, size_t len,
                          const std::vector<uint64_t>& offset_to_inst_id,
                          const std::vector<uint64_t>& offset_to_pc,
                          const std::vector<uint64_t>& offset_to_addr,
                          const std::vector<uint8_t>& offset_to_size,
                          MemSearchMatch::Source source,
                          MemSearchResult& result,
                          const std::function<bool()>& cancel_check = {});
#endif

    /// Whether any pattern uses wildcards (mask != all-zero).
    bool has_wildcards() const;

    /// Fallback: per-instruction linear scan (always works).
    void linear_scan(PassContext& ctx, MemSearchResult& result);

    /// Pattern matching with mask support.
    static bool match_at(const uint8_t* data, size_t data_len, size_t pos,
                         const MemSearchConfig::Pattern& pat);
};

}  // namespace tenet

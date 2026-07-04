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
    /// Byte-sequence patterns to search for. Each pattern is a byte sequence
    /// with optional wildcards (0xFF in the mask = match any byte).
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

    /// Exact scalar values to search for (fast O(1) hash-map path — no byte
    /// pattern matching needed). This absorbs what used to be the standalone
    /// LiteralSearchPass: a value like a crypto IV (0x67452301) or a known
    /// pointer/address, searched directly against register diffs, memory
    /// write values, and MOVZ/MOVK immediate fields.
    std::vector<uint64_t> exact_values;
    /// Whether an exact_values entry also matches its 32-bit truncation
    /// (value & 0xFFFFFFFF). Mirrors the old LiteralSearchConfig::match_32bit.
    bool match_32bit = true;

    /// Search in memory write values (default: true).
    bool search_mem_writes = true;
    /// Search in register values / reg_diff (default: false).
    bool search_reg_values = false;
    /// Search MOVZ/MOVK instruction immediate fields (default: false).
    /// Only meaningful for exact_values (byte-pattern search against a
    /// single 16-bit immediate is rarely useful, so `patterns` is not
    /// matched against immediates).
    bool search_immediates = false;
    /// Maximum matches per pattern/value (0 = unlimited).
    uint64_t max_matches = 1000;
    /// Optional inst_id range to restrict search.
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;
};

// ─── Match result ──────────────────────────────────────────────────────────

struct MemSearchMatch {
    uint64_t inst_id;          // Instruction where match occurred
    uint64_t pc;               // PC of that instruction
    uint64_t addr;             // Memory address (for mem writes) or 0 (for reg/imm)
    uint16_t offset;           // Byte offset within the value where pattern starts
    uint8_t  pattern_index;    // Which pattern/exact_value matched (index into
                               // config.patterns, or config.exact_values when
                               // source == Immediate/ExactReg/ExactMem — see
                               // `is_exact_value_match` below)
    enum Source : uint8_t {
        MemWrite,    // Found in memory write value (byte-pattern match)
        RegDiff,     // Found in register diff value (byte-pattern match)
        Immediate,   // Found in a MOVZ/MOVK instruction immediate field
                     // (exact_values only)
    } source;
    uint64_t matched_value = 0;  // Full matched scalar value (exact_values path only)

    /// Whether `pattern_index` indexes into `exact_values` (true) or
    /// `patterns` (false). Immediate matches are always exact-value matches;
    /// MemWrite/RegDiff matches can be either, depending on which search
    /// path produced them.
    bool is_exact_value_match = false;
};

// ─── Result ────────────────────────────────────────────────────────────────

struct MemSearchResult {
    std::vector<MemSearchMatch> matches;
    uint64_t bytes_scanned = 0;
    uint64_t instructions_scanned = 0;

    /// Byte-pattern matches grouped by pattern index (config.patterns).
    std::vector<std::vector<size_t>> by_pattern;  // pattern_idx → match indices
    /// Exact-value matches grouped by value index (config.exact_values).
    std::vector<std::vector<size_t>> by_value;    // value_idx → match indices
};

// ─── Pass ──────────────────────────────────────────────────────────────────

/// Unified memory/register/immediate search engine.
///
/// Two complementary search modes, both available in a single pass:
///
/// 1. **Byte-pattern search** (`patterns`): arbitrary-length byte sequences
///    with optional wildcards, matched against memory-write values and/or
///    register diffs. Strategy selection:
///    - If YARA is available and patterns have no wildcards:
///      Builds a contiguous buffer from all mem-write values, then uses YARA
///      Aho-Corasick (O(N + M)) for multi-pattern matching in a single pass.
///      This eliminates the O(N × P) per-instruction brute-force.
///    - Fallback: mask-based linear scan per instruction (always works).
///    Designed for locating known byte sequences (keys, IVs, ciphertext
///    blocks) where the byte layout matters.
///
/// 2. **Exact-value search** (`exact_values`, formerly the standalone
///    `LiteralSearchPass`): O(1) hash-map lookup for specific scalar values
///    (e.g. a crypto constant or a known pointer) against register diffs,
///    memory write values, and MOVZ/MOVK instruction immediates. Useful for
///    "where does this known value first appear" queries where byte order/
///    wildcards don't matter.
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
        return "Multi-pattern byte search + exact-value search on memory/registers/immediates";
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

    /// Fallback: per-instruction linear scan for byte patterns (always works).
    /// Also handles exact-value search (reg/mem/immediate) inline, since both
    /// need a per-instruction walk over the same trace records.
    /// `scan_patterns` lets the caller disable byte-pattern matching for a
    /// given call (used when patterns were already handled via YARA and only
    /// exact_values still need a pass).
    void linear_scan(PassContext& ctx, MemSearchResult& result, bool scan_patterns = true);

    /// Pattern matching with mask support.
    static bool match_at(const uint8_t* data, size_t data_len, size_t pos,
                         const MemSearchConfig::Pattern& pat);
};

}  // namespace tenet

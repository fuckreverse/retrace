/*
 * trace_diff_pass.h — Cross-file differential trace analysis.
 *
 * Compares two traces (or two regions within the same trace) to find divergence
 * points and automatically resynchronize after control-flow splits.  Designed
 * for billion-instruction traces with O(1) working memory (streaming dual-
 * iterator, no region pre-load).
 *
 * Typical use case: record the same function with two different inputs, then
 * compare the traces to find where the data starts to diverge (differential
 * cryptanalysis / white-box analysis).
 */
#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

// ─── Register name helper ─────────────────────────────────────────────────────

/// Human-readable register name for AArch64 GPR index.
/// 0-28 → "x0".."x28", 29 → "fp", 30 → "lr", 31 → "sp", 32 → "nzcv", 33 → "pc"
inline std::string_view reg_name(uint8_t index) {
    static constexpr std::string_view names[] = {
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
        "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "sp",
        "nzcv", "pc"
    };
    if (index < 34) return names[index];
    return "?";
}

// ─── Diff types ───────────────────────────────────────────────────────────────

enum class DiffType : uint8_t {
    ControlFlow,     ///< PCs differ — triggers resynchronization
    RegisterValue,   ///< Same PC, register output values differ
    MemoryValue,     ///< Same PC, memory access values differ
    // NOTE: OpcodeChange is reserved for self-modifying-code detection
    // (same PC executed with a different underlying opcode across the two
    // ranges/traces) but TraceDiffPass does not currently produce this
    // diff type — InstView carries register/memory diffs but not the raw
    // opcode, and opcode history is only available via the separate,
    // PC-keyed CODE_BYTES/CodeTable stream (which cannot distinguish two
    // different opcodes recorded at the same PC at different times).
    // Detecting this would require tracking REC_CODE events per range and
    // is not yet implemented. The enumerator, GUI filter checkbox, and MCP
    // "type" field are kept for forward compatibility once this lands.
    OpcodeChange,    ///< Same PC, opcode differs (self-modifying code) — NOT YET PRODUCED
};

inline std::string_view diff_type_name(DiffType t) {
    switch (t) {
    case DiffType::ControlFlow:   return "ControlFlow";
    case DiffType::RegisterValue: return "RegisterValue";
    case DiffType::MemoryValue:   return "MemoryValue";
    case DiffType::OpcodeChange:  return "OpcodeChange";
    }
    return "Unknown";
}

// ─── Configuration ────────────────────────────────────────────────────────────

struct TraceDiffConfig {
    /// Cross-file mode: path to trace B.  Empty → same-trace region comparison.
    std::string trace_b_path;

    /// Region A (main trace / trace A).
    uint64_t trace_a_start = 0;
    uint64_t trace_a_end   = UINT64_MAX;  ///< default: full trace

    /// Region B (trace B, or second region in same trace).
    uint64_t trace_b_start = 0;
    uint64_t trace_b_end   = UINT64_MAX;

    /// Resync window size: how many instructions to lookahead when searching
    /// for a matching PC after a control-flow divergence.
    uint32_t resync_window = 16384;

    /// Maximum number of DivergeSegments to record before truncating.
    size_t max_diffs = 100000;

    /// Prefer CALL/RET boundaries as resync anchor points.
    bool prefer_call_ret_anchor = true;
};

// ─── Result types ─────────────────────────────────────────────────────────────

/// A single divergence segment: describes where traces diverged and (optionally)
/// where they resynchronized.
struct DivergeSegment {
    // ── Divergence start ──
    uint64_t start_inst_a = 0;    ///< inst_id in trace A where divergence begins
    uint64_t start_inst_b = 0;    ///< inst_id in trace B where divergence begins
    uint64_t start_pc     = 0;    ///< Normalized (static) PC at divergence point
    DiffType start_type   = DiffType::ControlFlow;
    std::string start_detail;     ///< Human-readable description of first difference

    // ── Resynchronization ──
    bool     resynced      = false;  ///< true if traces re-aligned after this segment
    uint64_t resync_inst_a = 0;      ///< inst_id in trace A at resync point
    uint64_t resync_inst_b = 0;      ///< inst_id in trace B at resync point
    uint64_t resync_pc     = 0;      ///< Normalized PC at resync point

    // ── Skip counts ──
    uint64_t skip_a = 0;  ///< Instructions skipped in trace A (diverged region length)
    uint64_t skip_b = 0;  ///< Instructions skipped in trace B
};

/// Aggregate result of a trace diff analysis.
struct TraceDiffResult {
    std::vector<DivergeSegment> segments;  ///< All divergence segments found

    uint64_t matched_count   = 0;  ///< Instructions that matched perfectly (PC + data)
    uint64_t total_diverged  = 0;  ///< Total instructions in diverged regions
    uint64_t resync_count    = 0;  ///< Number of successful resynchronizations
    bool     truncated       = false;  ///< true if max_diffs reached

    // ── Convenience queries ──

    bool has_divergence() const { return !segments.empty(); }

    /// Count of segments where resync failed (permanent divergences).
    size_t permanent_divergence_count() const {
        size_t n = 0;
        for (auto& s : segments)
            if (!s.resynced && s.start_type == DiffType::ControlFlow) ++n;
        return n;
    }

    /// Filter: control-flow divergences only.
    std::vector<const DivergeSegment*> control_flow_segments() const {
        std::vector<const DivergeSegment*> out;
        for (auto& s : segments)
            if (s.start_type == DiffType::ControlFlow) out.push_back(&s);
        return out;
    }

    /// Filter: register-value divergences only.
    std::vector<const DivergeSegment*> register_value_segments() const {
        std::vector<const DivergeSegment*> out;
        for (auto& s : segments)
            if (s.start_type == DiffType::RegisterValue) out.push_back(&s);
        return out;
    }
};

// ─── Pass class ───────────────────────────────────────────────────────────────

class TraceDiffPass final : public AnalysisPass {
public:
    explicit TraceDiffPass(TraceDiffConfig cfg) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "trace_diff"; }
    std::string_view description() const override {
        return "Cross-file differential trace analysis with auto-resync";
    }
    std::vector<std::string_view> dependencies() const override { return {}; }
    float estimated_cost() const override { return 6.0f; }

    PassResult run(PassContext& ctx) override;

private:
    TraceDiffConfig cfg_;
};

}  // namespace tenet

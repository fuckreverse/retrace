#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

// ─── Loop semantic classification ─────────────────────────────────────────

enum class LoopKind : uint8_t {
    Unknown,
    CounterLoop,
    FeistelRound,
    SPNRound,
    ARXRound,
    ShiftRotate,
    Accumulator,
    MemcpyLike,
};

/// Returns a human-readable string for a LoopKind.
inline const char* loop_kind_name(LoopKind k) {
    switch (k) {
        case LoopKind::Unknown:       return "Unknown";
        case LoopKind::CounterLoop:   return "CounterLoop";
        case LoopKind::FeistelRound:  return "FeistelRound";
        case LoopKind::SPNRound:      return "SPNRound";
        case LoopKind::ARXRound:      return "ARXRound";
        case LoopKind::ShiftRotate:   return "ShiftRotate";
        case LoopKind::Accumulator:   return "Accumulator";
        case LoopKind::MemcpyLike:    return "MemcpyLike";
    }
    return "Unknown";
}

// ─── Per-loop semantic info ───────────────────────────────────────────────

struct LoopSemanticInfo {
    uint64_t header_pc = 0;
    uint64_t iteration_count = 0;

    LoopKind kind = LoopKind::Unknown;
    float confidence = 0.0f;
    std::string description;

    /// Registers that change across iterations (register indices).
    std::vector<uint8_t> active_regs;

    /// Registers that remain constant across all sampled iterations.
    std::vector<uint8_t> invariant_regs;

    /// Number of unique instruction PCs in the loop body.
    uint64_t body_instruction_count = 0;

    // ─── Feature flags (detected from body instructions) ─────────────
    bool has_sbox_pattern = false;       // LDR with data-dependent index (table lookup)
    bool has_xor_mix = false;            // EOR instructions
    bool has_shift_rotate = false;       // LSL, LSR, ASR, ROR, EON
    bool has_addition_chain = false;     // ADD/SUB chains
    bool has_modular_arithmetic = false; // MUL/UDIV patterns

    // ─── Iteration sampling info ─────────────────────────────────────
    uint64_t sample_iter_start = 0;      // inst_id of first sampled iteration start
    uint64_t sample_iter_end = 0;        // inst_id of first sampled iteration end
};

// ─── Loop semantics result ────────────────────────────────────────────────

struct LoopSemanticsResult {
    /// One entry per analyzed loop (order matches LoopResult::loops for loops
    /// with iteration_count >= 2).
    std::vector<LoopSemanticInfo> loop_semantics;

    /// Return all loops classified as Feistel rounds.
    std::vector<const LoopSemanticInfo*> feistel_loops() const {
        std::vector<const LoopSemanticInfo*> result;
        for (const auto& ls : loop_semantics) {
            if (ls.kind == LoopKind::FeistelRound) {
                result.push_back(&ls);
            }
        }
        return result;
    }

    /// Return all loops likely to be crypto-related
    /// (confidence > 0.5 and kind != Unknown).
    std::vector<const LoopSemanticInfo*> crypto_loops() const {
        std::vector<const LoopSemanticInfo*> result;
        for (const auto& ls : loop_semantics) {
            if (ls.kind != LoopKind::Unknown && ls.confidence > 0.5f) {
                result.push_back(&ls);
            }
        }
        return result;
    }
};

// ─── Loop semantics analysis pass ─────────────────────────────────────────

/// Analyzes the semantic behavior of detected loops across iterations
/// to identify cryptographic round functions, Feistel structures, ARX
/// ciphers, SPN networks, etc.
///
/// Algorithm:
///   1. Obtain LoopResult from the "loop" dependency.
///   2. For each loop with iteration_count >= 2:
///      a. Sample 2-3 iterations by scanning the trace for header PC hits.
///      b. Record register state at header PC using RegisterFile::state_before().
///      c. Compare register states: identify active vs invariant registers.
///      d. Analyze loop body instructions for feature detection (XOR, shifts,
///         table lookups, addition chains, modular arithmetic).
///      e. Classify the loop based on detected features and iteration count.
///
/// Result type: LoopSemanticsResult
class LoopSemanticsPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "loop_semantics"; }
    std::string_view description() const override {
        return "Loop semantic classification for crypto algorithm identification";
    }

    std::vector<std::string_view> dependencies() const override {
        // "xref" provides the PC→inst_id bitmap index used to locate loop
        // header executions in O(K) instead of O(trace_length).
        return {"loop", "xref"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 12.0f; }
};

}  // namespace tenet

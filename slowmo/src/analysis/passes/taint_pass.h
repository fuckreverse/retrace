#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <string>

#include <ankerl/unordered_dense.h>
#include <roaring64map.hh>

namespace tenet {

// Forward declarations
struct XrefResult;

// ─── Taint direction ──────────────────────────────────────────────────────

enum class TaintDirection : uint8_t {
    Forward,   // Source → downstream (default)
    Backward,  // Sink ← upstream (use BackwardTaintPass for full backward)
};

// ─── Propagation step event types ─────────────────────────────────────────

/// Fine-grained classification of how taint propagated at each step.
/// Mirrors the article's "Timeless Debugging" event taxonomy.
enum class PropagationType : uint8_t {
    RegToReg,       // Taint flows register → register (MOV, ADD, etc.)
    RegToMem,       // Taint flows register → memory (STR, STP)
    MemToReg,       // Taint flows memory → register (LDR, LDP)
    MemToMem,       // Taint flows memory → memory (rare: memcpy-like)
    Immediate,      // Taint killed by immediate overwrite (MOV Xn, #imm)
    Call,           // Taint crosses into callee via argument registers
    Return,         // Taint returns from callee via X0
    Kill,           // Taint explicitly removed (register fully overwritten)
};

// ─── Propagation step (detailed event) ────────────────────────────────────

/// Describes a single taint propagation step with full provenance.
struct PropagationStep {
    uint64_t inst_id;
    uint64_t pc;
    PropagationType type;

    /// Destination: what became tainted (or untainted for Kill).
    uint8_t dst_reg = 0xFF;          // 0xFF = not a register destination
    uint64_t dst_mem_addr = 0;       // 0 = not a memory destination
    uint8_t dst_mem_size = 0;

    /// Source: where taint came from.
    std::vector<uint8_t> src_regs;
    std::vector<uint64_t> src_mem_addrs;

    /// For Call/Return: the callee/caller PC.
    uint64_t cross_function_pc = 0;

    /// Whether this step was resolved by Triton (precise) or heuristic.
    bool triton_resolved = false;
};

// ─── Taint analysis configuration ─────────────────────────────────────────

struct TaintConfig {
    // ─── Source specification ─────────────────────────────────────────

    /// Initial taint sources: register indices that start tainted.
    std::unordered_set<uint8_t> source_regs;

    /// Source instruction ID: start taint propagation from this instruction.
    /// If 0, starts from the beginning of the analysis range.
    uint64_t source_inst_id = 0;

    /// Source memory addresses: these memory locations start tainted.
    std::vector<uint64_t> source_mem_addrs;

    // ─── Propagation control ──────────────────────────────────────────

    /// Direction of taint propagation.
    TaintDirection direction = TaintDirection::Forward;

    /// Consider memory loads as taint sources (MemToReg propagation).
    bool taint_from_memory = true;

    /// Consider memory stores as taint sinks (RegToMem propagation).
    bool track_memory_sinks = true;

    /// Propagate through arithmetic/logic operations.
    bool propagate_arithmetic = true;

    /// Propagate through moves/copies.
    bool propagate_moves = true;

    /// Propagate taint through function calls (BL/BLR → callee via X0-X7).
    bool propagate_through_calls = true;

    /// Track return values: if callee's X0 is tainted at RET, propagate back.
    bool propagate_through_returns = true;

    // ─── Stop conditions ──────────────────────────────────────────────

    /// Stop analysis after this many instructions (0 = unlimited).
    uint64_t max_instructions = 0;

    /// Stop when taint width (number of tainted registers) exceeds this.
    /// 0 = unlimited. Prevents taint explosion.
    uint32_t max_taint_width = 0;

    /// Stop when reaching any of these PCs (e.g., known sanitizers).
    std::unordered_set<uint64_t> stop_pcs;

    // ─── XRef acceleration ────────────────────────────────────────────

    /// Use XRef pass results to skip instructions that cannot affect tainted state.
    /// Requires "xref" pass to have been run.
    bool use_xref_acceleration = true;

    // ─── Output control ───────────────────────────────────────────────

    /// Emit detailed PropagationStep events (vs. legacy TaintEvent).
    bool emit_propagation_steps = true;

    /// Include Kill events in the output (register untainted).
    bool emit_kill_events = true;
};

// ─── Legacy taint event (backward compat) ─────────────────────────────────

/// Describes a single taint propagation event (legacy format).
struct TaintEvent {
    uint64_t inst_id;
    uint64_t pc;
    uint8_t dst_reg;       // register that became tainted
    std::vector<uint8_t> src_regs;  // registers that contributed
    bool is_memory_source; // taint came from memory
    bool is_memory_sink;   // taint was stored to memory
};

// ─── Taint analysis pass result ───────────────────────────────────────────

struct TaintResult {
    TaintConfig config;

    /// Legacy events (always populated for backward compat).
    std::vector<TaintEvent> events;

    /// Detailed propagation steps (populated when config.emit_propagation_steps).
    std::vector<PropagationStep> steps;

    /// Current taint state at the end of analysis: which regs are tainted.
    std::unordered_set<uint8_t> tainted_regs;

    /// Memory addresses that are currently tainted.
    roaring::Roaring64Map tainted_memory;

    /// Quick lookup: which instructions produced taint events.
    roaring::Roaring64Map tainted_inst_ids;
    ankerl::unordered_dense::map<uint64_t, size_t> inst_id_to_event;

    /// Mapping from inst_id to PropagationStep index.
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> inst_id_to_steps;

    /// Statistics
    uint64_t instructions_processed = 0;
    uint64_t instructions_skipped_xref = 0;  // skipped via XRef acceleration
    uint64_t kill_events_count = 0;
    uint64_t call_crossings = 0;
    uint64_t return_crossings = 0;

    /// Stop reason (empty if completed normally).
    std::string stop_reason;

    bool is_tainted(uint8_t reg) const {
        return tainted_regs.count(reg) > 0;
    }

    bool is_memory_addr_tainted(uint64_t addr) const {
        return tainted_memory.contains(addr);
    }

    bool has_event_at(uint64_t inst_id) const {
        return tainted_inst_ids.contains(inst_id);
    }

    const TaintEvent* event_at(uint64_t inst_id) const {
        if (!tainted_inst_ids.contains(inst_id)) return nullptr;
        auto it = inst_id_to_event.find(inst_id);
        if (it == inst_id_to_event.end()) return nullptr;
        return &events[it->second];
    }

    /// Get all propagation steps at a given instruction.
    const std::vector<size_t>* steps_at(uint64_t inst_id) const {
        auto it = inst_id_to_steps.find(inst_id);
        if (it == inst_id_to_steps.end()) return nullptr;
        return &it->second;
    }

    uint64_t tainted_memory_count() const {
        return tainted_memory.cardinality();
    }

    uint64_t tainted_inst_count() const {
        return tainted_inst_ids.cardinality();
    }
};

// ─── Taint analysis pass ───────────────────────────────────────────────────

/// Forward taint propagation with:
/// - Triton-based precise mode (when available)
/// - Heuristic fallback with kill semantics
/// - XRef acceleration (sparse propagation skip)
/// - ABI-aware cross-function tracking
/// - Configurable stop conditions
/// - Detailed PropagationStep event emission
class TaintPass final : public AnalysisPass {
public:
    explicit TaintPass(TaintConfig config) : config_(std::move(config)) {}

    std::string_view name() const override { return "taint"; }
    std::string_view description() const override {
        return "Forward taint propagation with XRef acceleration and kill semantics";
    }

    std::vector<std::string_view> dependencies() const override {
        if (config_.use_xref_acceleration) {
            return {"xref"};
        }
        return {};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }

private:
    TaintConfig config_;
};

}  // namespace tenet

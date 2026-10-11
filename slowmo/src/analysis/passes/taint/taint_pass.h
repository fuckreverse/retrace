#include "common/compiler_compat.h"
#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
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

    /// Source registers: bitmask where bit N = register N contributed taint.
    /// Zero heap allocation — replaces the old std::vector<uint8_t> src_regs.
    /// For 34 AArch64 GPRs, a single uint64_t covers all (bits 0-33).
    uint64_t src_reg_mask = 0;

    /// Source memory addresses: still a vector because memory addresses are
    /// arbitrary 64-bit values that don't fit a bitmask.  However, most
    /// propagation steps have 0-2 memory sources, so we use a small inline
    /// buffer (max 4) to avoid heap allocation for the common case.
    static constexpr uint8_t kMaxInlineMemAddrs = 4;
    uint8_t src_mem_count = 0;
    uint64_t src_mem_addrs[kMaxInlineMemAddrs] = {};  // inline, no heap alloc

    /// Overflow: when >4 memory sources (extremely rare), stored here.
    /// This avoids the 99.9% case of heap allocation while remaining correct.
    std::vector<uint64_t> src_mem_addrs_overflow;

    /// Add a memory source address (inline-first, overflow for rare >4 case).
    void add_src_mem(uint64_t addr) {
        if (src_mem_count < kMaxInlineMemAddrs) {
            src_mem_addrs[src_mem_count++] = addr;
        } else {
            src_mem_addrs_overflow.push_back(addr);
        }
    }

    /// Iterate over all source memory addresses (inline + overflow).
    template<typename Fn>
    void for_each_src_mem(Fn fn) const {
        for (uint8_t i = 0; i < src_mem_count && i < kMaxInlineMemAddrs; i++)
            fn(src_mem_addrs[i]);
        for (uint64_t addr : src_mem_addrs_overflow)
            fn(addr);
    }

    /// For Call/Return: the callee/caller PC.
    uint64_t cross_function_pc = 0;

    /// Whether this step was resolved by Triton (precise) or heuristic.
    bool triton_resolved = false;
};

// ─── Taint analysis configuration ─────────────────────────────────────────

struct TaintConfig {
    // ─── Source specification ─────────────────────────────────────────

    /// Initial taint sources: register indices that start tainted.
    /// Stored as a bitmask: bit N set means register N is a source.
    uint64_t source_regs = 0;

    /// Convenience: add a source register.
    void add_source_reg(uint8_t reg) { source_regs |= (1ULL << reg); }
    bool has_source_reg(uint8_t reg) const { return (source_regs >> reg) & 1; }

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
    std::vector<uint64_t> stop_pcs;

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
    uint64_t src_reg_mask; // bitmask: bit N = register N contributed taint
    bool is_memory_source; // taint came from memory
    bool is_memory_sink;   // taint was stored to memory

    /// Legacy helper: check if a specific register was a source.
    bool has_src_reg(uint8_t reg) const { return (src_reg_mask >> reg) & 1; }
};

// ─── Taint analysis pass result ───────────────────────────────────────────

struct TaintResult {
    TaintConfig config;

    /// Legacy events (always populated for backward compat).
    std::vector<TaintEvent> events;

    /// Detailed propagation steps (populated when config.emit_propagation_steps).
    std::vector<PropagationStep> steps;

    /// Current taint state at the end of analysis: which regs are tainted.
    /// Bitmask: bit N set means register N is tainted.
    uint64_t tainted_regs = 0;

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
        return (tainted_regs >> reg) & 1;
    }

    /// Number of currently tainted registers.
    uint32_t tainted_reg_count() const {
        return static_cast<uint32_t>(tenet::platform::population_count(tainted_regs));
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

    /// Return event instruction IDs in ascending order for UI navigation.
    /// Iterating the Roaring bitmap is O(number of events), avoiding an
    /// O(total trace instructions) membership scan in frontends.
    std::vector<uint64_t> ordered_event_inst_ids() const {
        std::vector<uint64_t> ids;
        ids.reserve(tainted_inst_ids.cardinality());
        for (uint64_t id : tainted_inst_ids) {
            ids.push_back(id);
        }
        return ids;
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

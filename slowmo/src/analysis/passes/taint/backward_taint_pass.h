#pragma once

#include "analysis/pass_manager.h"
#include "common/dataflow_types.h"
#include <cstdint>
#include <vector>
#include <string>

#include <ankerl/unordered_dense.h>
#include <roaring64map.hh>

namespace tenet {

// Forward declarations
struct TaintResult;

// ─── Backward taint analysis result ───────────────────────────────────────

/// Tag identifying which original sink a propagation chain belongs to.
/// Enables per-sink attribution when multiple sink registers/addresses are traced.
struct SinkTag {
    enum Kind : uint8_t { Register, Memory };
    Kind kind;
    uint8_t reg_id = 0;       // valid when kind == Register
    uint64_t mem_addr = 0;    // valid when kind == Memory

    bool operator==(const SinkTag& o) const {
        return kind == o.kind && reg_id == o.reg_id && mem_addr == o.mem_addr;
    }
};

/// Describes a single backward taint propagation event.
/// "This instruction at inst_id defined register dst_reg, which flows to the sink.
///  Its computation reads from src_regs and/or src_memory addresses."
///
/// Register sets and sink tags are stored as uint64_t bitmasks for zero-alloc
/// hot-path performance.  Bit i corresponds to register/tag index i.
/// Use the helper methods below to query and iterate.
struct BackwardTaintEvent {
    uint64_t inst_id;
    uint64_t pc;

    /// Bitmask: bit i set → register i is a destination (defined by this instruction).
    uint64_t dst_regs_mask = 0;

    /// Legacy single-reg accessor (first dst_reg, for simple cases).
    uint8_t dst_reg = 0;

    /// Bitmask: bit i set → register i is a source (read by this instruction).
    uint64_t src_regs_mask = 0;

    /// Source memory addresses read by this instruction.
    std::vector<uint64_t> src_mem_addrs;

    /// If true, this instruction loads from memory → data came from memory.
    bool loads_from_memory = false;

    /// If true, this instruction stores to memory → propagate through memory.
    bool stores_to_memory = false;

    /// Store destination address (if stores_to_memory is true).
    uint64_t store_addr = 0;
    uint8_t store_size = 0;

    /// Bitmask: bit i set → this event contributes to sink tag i.
    uint64_t sink_tags_mask = 0;

    // ── Bitmask helper methods ──────────────────────────────────────────

    bool has_dst_reg(uint8_t r) const { return (dst_regs_mask >> r) & 1; }
    bool has_src_reg(uint8_t r) const { return (src_regs_mask >> r) & 1; }
    bool has_sink_tag(uint8_t t) const { return (sink_tags_mask >> t) & 1; }

    bool dst_regs_empty() const { return dst_regs_mask == 0; }
    bool src_regs_empty() const { return src_regs_mask == 0; }
    bool sink_tags_empty() const { return sink_tags_mask == 0; }

    void add_dst_reg(uint8_t r) { dst_regs_mask |= (1ULL << r); }
    void add_src_reg(uint8_t r) { src_regs_mask |= (1ULL << r); }
    void add_sink_tag(uint8_t t) { sink_tags_mask |= (1ULL << t); }

    /// Iterate over all set destination registers.  Fn receives uint8_t reg_id.
    template <typename Fn>
    void for_each_dst_reg(Fn&& fn) const {
        for (uint64_t m = dst_regs_mask; m; m &= m - 1)
            fn(static_cast<uint8_t>(__builtin_ctzll(m)));
    }
    /// Iterate over all set source registers.  Fn receives uint8_t reg_id.
    template <typename Fn>
    void for_each_src_reg(Fn&& fn) const {
        for (uint64_t m = src_regs_mask; m; m &= m - 1)
            fn(static_cast<uint8_t>(__builtin_ctzll(m)));
    }
    /// Iterate over all set sink tags.  Fn receives uint8_t tag index.
    template <typename Fn>
    void for_each_sink_tag(Fn&& fn) const {
        for (uint64_t m = sink_tags_mask; m; m &= m - 1)
            fn(static_cast<uint8_t>(__builtin_ctzll(m)));
    }

    /// Build a vector of destination register IDs (for serialization / JSON).
    std::vector<uint8_t> dst_regs_list() const;
    /// Build a vector of source register IDs (for serialization / JSON).
    std::vector<uint8_t> src_regs_list() const;
    /// Build a vector of sink tag indices (for serialization / JSON).
    std::vector<uint8_t> sink_tags_list() const;
};

// DataflowEdge is defined in common/dataflow_types.h (included above).

/// Backward taint analysis configuration.
struct BackwardTaintConfig {
    /// The sink instruction ID: where backward propagation starts.
    uint64_t sink_inst_id = 0;

    /// The sink register(s): which register values at the sink to trace back.
    /// Bitmask: bit i is set if register i is a sink (AArch64 has 34 GPRs, fits in 64 bits).
    uint64_t sink_regs = 0;

    void add_sink_reg(uint8_t reg) { sink_regs |= (1ULL << reg); }
    bool has_sink_reg(uint8_t reg) const { return (sink_regs >> reg) & 1; }

    /// Optionally: sink memory address(es) to trace back.
    std::vector<uint64_t> sink_mem_addrs;

    /// Whether to propagate through memory (load←store chains).
    bool propagate_through_memory = true;

    /// Maximum number of instructions to walk backward (0 = unlimited).
    uint64_t max_steps = 0;

    /// Maximum number of tainted instructions to collect before stopping.
    uint64_t max_tainted_insts = 100000;

    /// Whether to track through function calls (follow BL→callee, RET→caller).
    /// When true: at a BL, if the return value (X0) is needed, we enter the callee
    /// and trace backward inside it. At a RET, we continue tracing in the caller.
    bool cross_function = true;

    /// Whether to include the SP register in propagation.
    bool include_sp = false;

    /// Whether to include the PC register in propagation.
    bool include_pc = false;

    /// Build dataflow dependency graph (edges between contributing instructions).
    bool build_dataflow_graph = true;

    /// Compute per-sink attribution tags.
    bool per_sink_tags = true;

    /// Use REG_WRITES inverted index for O(log N) backward jumps.
    /// When true (default), for each needed register in the current state
    /// the pass jumps directly to its last writer (via TraceIndex::find_last_writer_of)
    /// instead of stepping backward one instruction at a time.
    /// Disable only for debugging or when REG_WRITES CF is absent.
    bool use_index_acceleration = true;
};

/// Backward taint analysis pass result.
struct BackwardTaintResult {
    BackwardTaintConfig config;

    /// All backward taint events, ordered from sink → earliest contributing instruction.
    std::vector<BackwardTaintEvent> events;

    /// All instruction IDs that contribute to the sink value (the "backward slice").
    roaring::Roaring64Map contributing_inst_ids;

    /// All registers that were part of the backward dependency chain at any point.
    /// Bitmask: bit i is set if register i was involved.
    uint64_t all_involved_regs = 0;

    /// Count of involved registers.
    int involved_reg_count() const { return __builtin_popcountll(all_involved_regs); }

    /// All memory addresses that were part of load-store chains.
    roaring::Roaring64Map involved_mem_addrs;

    /// Depth of the dependency tree (longest path from sink).
    uint64_t max_depth = 0;

    /// Dataflow dependency graph: edges between contributing instructions.
    /// Only populated if config.build_dataflow_graph == true.
    std::vector<DataflowEdge> dataflow_edges;

    /// Per-sink tags for attribution.
    std::vector<SinkTag> sink_tags;

    /// Per-sink contributing instruction sets (parallel to sink_tags).
    std::vector<roaring::Roaring64Map> per_sink_inst_ids;

    /// Quick lookup: is this instruction in the backward taint set?
    bool is_contributing(uint64_t inst_id) const {
        return contributing_inst_ids.contains(inst_id);
    }

    /// Get event at a given instruction, or nullptr.
    const BackwardTaintEvent* event_at(uint64_t inst_id) const {
        auto it = inst_id_to_event_.find(inst_id);
        if (it == inst_id_to_event_.end()) return nullptr;
        return &events[it->second];
    }

    /// Total contributing instructions count.
    uint64_t contributing_count() const {
        return contributing_inst_ids.cardinality();
    }

    /// Return contributing instruction IDs in ascending order for UI navigation.
    /// Iterating the Roaring bitmap is O(number of contributors), avoiding an
    /// O(total trace instructions) membership scan in frontends.
    std::vector<uint64_t> ordered_contributing_inst_ids() const {
        std::vector<uint64_t> ids;
        ids.reserve(contributing_inst_ids.cardinality());
        for (uint64_t id : contributing_inst_ids) {
            ids.push_back(id);
        }
        return ids;
    }

    /// Generate DOT representation of the dataflow graph.
    std::string to_dot() const;

    /// Generate JSON representation of the dataflow graph.
    std::string to_graph_json() const;

    /// Compute the intersection with a forward taint result → critical path.
    /// Returns instruction IDs that appear in BOTH forward and backward taint.
    roaring::Roaring64Map critical_path(const TaintResult& forward) const;

    // Internal: populated by the pass
    ankerl::unordered_dense::map<uint64_t, size_t> inst_id_to_event_;
};

// ─── Backward taint analysis pass ────────────────────────────────────────

/// Precise backward taint propagation: from a sink (inst_id, reg/mem),
/// walks backward through the trace to find all instructions whose outputs
/// contribute to the sink's value.
///
/// Uses Triton for precise read/write set identification when available.
/// Falls back to register-diff-based heuristic when Triton is not linked.
///
/// Key difference from forward TaintPass:
/// - Forward: "what does this source affect?" (follows data forward in time)
/// - Backward: "what contributed to this value?" (traces data backward in time)
///
/// Features:
/// - Multi-definition handling: if one instruction writes multiple needed registers
///   (e.g., LDP), all are processed in a single pass.
/// - Cross-function: tracks through BL/RET boundaries using ABI conventions
///   (X0-X7 arguments, X0 return value, X30/LR call linkage).
/// - Per-sink attribution: each contributing instruction is tagged with which
///   original sink register(s) it feeds into.
/// - Dataflow graph: builds explicit edges between producer→consumer instructions.
/// - Critical path: intersect with forward taint to identify the minimal
///   computation chain.
///
/// Result type: BackwardTaintResult
class BackwardTaintPass final : public AnalysisPass {
public:
    explicit BackwardTaintPass(BackwardTaintConfig config)
        : config_(std::move(config)) {}

    std::string_view name() const override { return "backward_taint"; }
    std::string_view description() const override {
        return "Backward taint propagation from sink to sources";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // Runs standalone; uses REG_WRITES index for acceleration when available
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 10.0f; }

private:
    BackwardTaintConfig config_;
};

}  // namespace tenet

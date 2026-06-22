#pragma once

#include "analysis/pass_manager.h"
#include "common/dataflow_types.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Configuration ────────────────────────────────────────────────────────

struct DataflowGraphConfig {
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id = UINT64_MAX;
    uint64_t max_nodes = 5000;  // limit graph size for practical visualization
};

// ─── Graph primitives ─────────────────────────────────────────────────────

/// A node in the dataflow graph, representing one executed instruction.
struct DataflowNode {
    uint64_t inst_id;
    uint64_t pc;
    std::string mnemonic;
    std::vector<uint8_t> regs_read;
    std::vector<uint8_t> regs_written;
};

// DFGEdge = DataflowEdge alias is defined in common/dataflow_types.h.
// Use DFGEdge::via_reg (previously reg_index) to access the register field.

// ─── Result ───────────────────────────────────────────────────────────────

struct DataflowGraphResult {
    std::vector<DataflowNode> nodes;
    std::vector<DFGEdge> edges;
    std::unordered_map<uint64_t, size_t> inst_to_node;  // inst_id → node index

    // ─── Adjacency index (built by build_adjacency()) ─────────────────
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> incoming_edge_idx_;
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> outgoing_edge_idx_;

    void build_adjacency() {
        incoming_edge_idx_.clear();
        outgoing_edge_idx_.clear();
        for (size_t i = 0; i < edges.size(); ++i) {
            outgoing_edge_idx_[edges[i].from_inst_id].push_back(i);
            incoming_edge_idx_[edges[i].to_inst_id].push_back(i);
        }
    }

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Get all incoming edges (data producers) for the given instruction.
    /// O(1) via the adjacency index.
    std::vector<DFGEdge> producers_of(uint64_t inst_id) const;

    /// Get all outgoing edges (data consumers) for the given instruction.
    /// O(1) via the adjacency index.
    std::vector<DFGEdge> consumers_of(uint64_t inst_id) const;

    /// Export the graph as Graphviz DOT format.
    std::string to_dot() const;

    /// Export the graph as JSON.
    std::string to_json() const;
};

// ─── Pass ─────────────────────────────────────────────────────────────────

/// Builds a register-level data-flow graph for a region of the trace.
/// Each node is an instruction; edges represent data dependencies
/// (register writes → register reads).
///
/// Result type: DataflowGraphResult
class DataflowGraphPass final : public AnalysisPass {
public:
    explicit DataflowGraphPass(DataflowGraphConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "dataflow_graph"; }
    std::string_view description() const override {
        return "Build register-level data-flow graph for a trace region";
    }

    std::vector<std::string_view> dependencies() const override { return {}; }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }

private:
    DataflowGraphConfig config_;
};

}  // namespace tenet

#pragma once
#include "common/chunked_vector.h"

#include "common/analysis_quality.h"

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

// DFG IDs retain trace GPR IDs 0..33; v0..v31 occupy 34..65.
inline constexpr uint8_t kDataflowSimdBase = AARCH64_GPR_COUNT;
inline constexpr uint8_t kDataflowRegisterCount = kDataflowSimdBase + 32;

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
    AnalysisQuality quality;
    bool truncated = false; // max_nodes stopped the scan before the range ended.
    ChunkedVector<DataflowNode> nodes;
    ChunkedVector<DFGEdge> edges;
    ankerl::unordered_dense::map<uint64_t, size_t> inst_to_node;  // inst_id → node index

    // ─── Adjacency index (built by build_adjacency()) ─────────────────
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> incoming_edge_idx_;
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> outgoing_edge_idx_;

    bool compact_adjacency = false;
    ChunkedVector<size_t> incoming_offsets, outgoing_offsets, incoming_edges, outgoing_edges;
    size_t node_index(uint64_t id) const {
        if (!nodes.empty() && id >= nodes.front().inst_id) {
            const auto guess = id - nodes.front().inst_id;
            if (guess < nodes.size() && nodes[guess].inst_id == id) return static_cast<size_t>(guess);
        }
        auto it = std::lower_bound(nodes.begin(), nodes.end(), id,
            [](const DataflowNode& n, uint64_t value) { return n.inst_id < value; });
        return it != nodes.end() && it->inst_id == id ? static_cast<size_t>(it - nodes.begin()) : SIZE_MAX;
    }
    void build_adjacency(std::function<bool()> stop = {}) {
        incoming_edge_idx_.clear(); outgoing_edge_idx_.clear();
        compact_adjacency = nodes.size() > 65536;
        if (!compact_adjacency) {
            for (size_t i = 0; i < edges.size(); ++i) {
                outgoing_edge_idx_[edges[i].from_inst_id].push_back(i);
                incoming_edge_idx_[edges[i].to_inst_id].push_back(i);
            }
            return;
        }
        inst_to_node.clear();
        incoming_offsets.clear(); outgoing_offsets.clear(); incoming_edges.clear(); outgoing_edges.clear();
        incoming_offsets.resize(nodes.size() + 1); outgoing_offsets.resize(nodes.size() + 1);
        for (size_t i = 0; i < edges.size(); ++i) {
            if ((i & 65535) == 0 && stop && stop()) throw std::runtime_error("adjacency build cancelled or memory limit exceeded");
            const auto from = node_index(edges[i].from_inst_id), to = node_index(edges[i].to_inst_id);
            if (from == SIZE_MAX || to == SIZE_MAX) throw std::runtime_error("Invalid dataflow edge endpoint");
            ++outgoing_offsets[from + 1]; ++incoming_offsets[to + 1];
        }
        for (size_t i = 1; i <= nodes.size(); ++i) {
            outgoing_offsets[i] += outgoing_offsets[i-1]; incoming_offsets[i] += incoming_offsets[i-1];
        }
        incoming_edges.resize(edges.size()); outgoing_edges.resize(edges.size());
        auto next_in = incoming_offsets, next_out = outgoing_offsets;
        for (size_t i = 0; i < edges.size(); ++i) {
            if ((i & 65535) == 0 && stop && stop()) throw std::runtime_error("adjacency build cancelled or memory limit exceeded");
            incoming_edges[next_in[node_index(edges[i].to_inst_id)]++] = i;
            outgoing_edges[next_out[node_index(edges[i].from_inst_id)]++] = i;
        }
    }

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Get all incoming edges (data producers) for the given instruction.
    /// O(degree) to copy the matching edges; O(1) index lookup.
    std::vector<DFGEdge> producers_of(uint64_t inst_id) const;

    /// Get all outgoing edges (data consumers) for the given instruction.
    /// O(degree) to copy the matching edges; O(1) index lookup.
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

#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Call graph result ─────────────────────────────────────────────────────

/// An edge in the call graph: caller → callee.
struct CallGraphEdge {
    uint64_t caller_pc;        // Entry PC of the calling function
    uint64_t callee_pc;        // Entry PC of the called function
    uint64_t call_count;       // How many times this edge was taken
    std::vector<uint64_t> call_site_pcs;  // Distinct call-site PCs for this edge
};

/// A node in the call graph: a function with its call relationships.
struct CallGraphNode {
    uint64_t entry_pc;                     // Entry PC of this function
    std::string name;                      // Symbol name (if known)
    uint64_t total_calls_made;             // Outgoing call count (sum of all edge call_counts)
    uint64_t total_calls_received;         // Incoming call count
    std::vector<size_t> outgoing_edges;    // Indices into CallGraphResult::edges
    std::vector<size_t> incoming_edges;    // Indices into CallGraphResult::edges
};

/// Result of call graph analysis.
struct CallGraphResult {
    /// All edges in the call graph.
    std::vector<CallGraphEdge> edges;

    /// Nodes indexed by function entry PC.
    ankerl::unordered_dense::map<uint64_t, CallGraphNode> nodes;

    /// Reverse lookup: (caller_pc, callee_pc) → edge index.
    ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint64_t, size_t>> edge_map_;

    /// Maximum call depth observed in the trace.
    uint64_t max_depth = 0;

    /// Total number of call events analyzed.
    uint64_t total_call_events = 0;

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Get node for a function by entry PC. Returns nullptr if not found.
    const CallGraphNode* node_at(uint64_t entry_pc) const {
        auto it = nodes.find(entry_pc);
        if (it == nodes.end()) return nullptr;
        return &it->second;
    }

    /// Get edge between caller and callee. Returns nullptr if no such edge.
    const CallGraphEdge* edge_between(uint64_t caller_pc, uint64_t callee_pc) const {
        auto it1 = edge_map_.find(caller_pc);
        if (it1 == edge_map_.end()) return nullptr;
        auto it2 = it1->second.find(callee_pc);
        if (it2 == it1->second.end()) return nullptr;
        return &edges[it2->second];
    }

    /// Get all functions called by a given function.
    std::vector<const CallGraphNode*> callees_of(uint64_t caller_pc) const {
        std::vector<const CallGraphNode*> result;
        auto it = nodes.find(caller_pc);
        if (it == nodes.end()) return result;
        for (auto edge_idx : it->second.outgoing_edges) {
            result.push_back(&nodes.at(edges[edge_idx].callee_pc));
        }
        return result;
    }

    /// Get all functions that call a given function.
    std::vector<const CallGraphNode*> callers_of(uint64_t callee_pc) const {
        std::vector<const CallGraphNode*> result;
        auto it = nodes.find(callee_pc);
        if (it == nodes.end()) return result;
        for (auto edge_idx : it->second.incoming_edges) {
            result.push_back(&nodes.at(edges[edge_idx].caller_pc));
        }
        return result;
    }

    /// Get the top-N functions by total calls received (hottest callees).
    std::vector<std::pair<uint64_t, uint64_t>> hottest_callees(size_t n) const {
        std::vector<std::pair<uint64_t, uint64_t>> entries;
        entries.reserve(nodes.size());
        for (const auto& [pc, node] : nodes) {
            entries.emplace_back(pc, node.total_calls_received);
        }
        std::partial_sort(entries.begin(),
                          entries.begin() + std::min(n, entries.size()),
                          entries.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
        if (entries.size() > n) entries.resize(n);
        return entries;
    }

    /// Get the top-N functions by total calls made (most active callers).
    std::vector<std::pair<uint64_t, uint64_t>> most_active_callers(size_t n) const {
        std::vector<std::pair<uint64_t, uint64_t>> entries;
        entries.reserve(nodes.size());
        for (const auto& [pc, node] : nodes) {
            entries.emplace_back(pc, node.total_calls_made);
        }
        std::partial_sort(entries.begin(),
                          entries.begin() + std::min(n, entries.size()),
                          entries.end(),
                          [](const auto& a, const auto& b) { return a.second > b.second; });
        if (entries.size() > n) entries.resize(n);
        return entries;
    }

    /// Check if there is a call path from `from_pc` to `to_pc` (BFS).
    bool has_call_path(uint64_t from_pc, uint64_t to_pc) const {
        if (from_pc == to_pc) return true;
        ankerl::unordered_dense::set<uint64_t> visited;
        std::vector<uint64_t> queue = {from_pc};
        visited.insert(from_pc);
        while (!queue.empty()) {
            uint64_t current = queue.back();
            queue.pop_back();
            auto it = nodes.find(current);
            if (it == nodes.end()) continue;
            for (auto edge_idx : it->second.outgoing_edges) {
                uint64_t callee = edges[edge_idx].callee_pc;
                if (callee == to_pc) return true;
                if (visited.insert(callee).second) {
                    queue.push_back(callee);
                }
            }
        }
        return false;
    }

    /// Find all recursive functions (functions that directly or indirectly call themselves).
    std::vector<uint64_t> recursive_functions() const {
        std::vector<uint64_t> result;
        for (const auto& [pc, node] : nodes) {
            if (has_call_path(pc, pc)) {
                result.push_back(pc);
            }
        }
        return result;
    }
};

// ─── Call graph pass ──────────────────────────────────────────────────────

/// Builds a call graph from FunctionPass results.
/// Creates nodes for each function and edges for caller→callee relationships.
/// Result type: CallGraphResult
class CallGraphPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "call_graph"; }
    std::string_view description() const override {
        return "Build call graph from function analysis results";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "function" };
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 3.0f; }
};

}  // namespace tenet

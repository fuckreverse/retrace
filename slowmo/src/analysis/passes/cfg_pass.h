#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── CFG pass result types ────────────────────────────────────────────────

/// How a basic block terminates.
enum class TerminatorKind : uint8_t {
    Fallthrough,       // Non-branch, flows into the next block
    Branch,            // Unconditional branch (b)
    ConditionalBranch, // Conditional branch (b.cond, cbz, cbnz, tbz, tbnz)
    Call,              // Call (bl / blr)
    Return,            // Return (ret)
    IndirectBranch,    // Indirect branch (br)
};

/// A basic block in the CFG.
struct BasicBlock {
    uint64_t start_pc;                     // First PC in this block
    uint64_t end_pc;                       // Last PC in this block (inclusive)
    std::vector<uint64_t> instructions;     // All PCs in this block, in order
    uint64_t execution_count = 0;           // Sum of execution counts across all PCs
    TerminatorKind terminator = TerminatorKind::Fallthrough;
};

/// A directed edge in the CFG between two basic blocks.
struct CFGEdge {
    uint64_t from_block;   // start_pc of the source block
    uint64_t to_block;     // start_pc of the destination block
    uint64_t taken_count;  // How many times this edge was taken in the trace
    bool is_fallthrough;   // True if this is a fallthrough edge (not an explicit branch)
};

/// Result of CFG analysis.
struct CFGResult {
    /// Basic blocks indexed by their start_pc.
    std::map<uint64_t, BasicBlock> blocks;

    /// All edges in the CFG.
    std::vector<CFGEdge> edges;

    // ─── Adjacency index (built by build_adjacency()) ─────────────────
    // O(1) successor/predecessor lookup; eliminates the previous O(E)
    // linear scan in successors() / predecessors().
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> succ_edge_idx_;
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> pred_edge_idx_;

    /// Build (or rebuild) the adjacency index from `edges`.
    /// Call this once after edges are populated.
    void build_adjacency() {
        succ_edge_idx_.clear();
        pred_edge_idx_.clear();
        succ_edge_idx_.reserve(blocks.size());
        pred_edge_idx_.reserve(blocks.size());
        for (size_t i = 0; i < edges.size(); ++i) {
            succ_edge_idx_[edges[i].from_block].push_back(i);
            pred_edge_idx_[edges[i].to_block].push_back(i);
        }
    }

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Find the basic block that contains the given PC.
    /// Returns nullptr if no block contains this PC.
    const BasicBlock* block_containing(uint64_t pc) const {
        // Use upper_bound to find the first block starting after pc,
        // then step back to the previous block which may contain pc.
        auto it = blocks.upper_bound(pc);
        if (it == blocks.begin()) return nullptr;
        --it;
        const auto& block = it->second;
        if (pc >= block.start_pc && pc <= block.end_pc) {
            return &block;
        }
        return nullptr;
    }

    /// Get successor edges of a block (by its start_pc).
    /// O(1) via the adjacency index.
    std::vector<const CFGEdge*> successors(uint64_t block_start) const {
        std::vector<const CFGEdge*> result;
        auto it = succ_edge_idx_.find(block_start);
        if (it == succ_edge_idx_.end()) return result;
        result.reserve(it->second.size());
        for (size_t idx : it->second) {
            result.push_back(&edges[idx]);
        }
        return result;
    }

    /// Get predecessor edges of a block (by its start_pc).
    /// O(1) via the adjacency index.
    std::vector<const CFGEdge*> predecessors(uint64_t block_start) const {
        std::vector<const CFGEdge*> result;
        auto it = pred_edge_idx_.find(block_start);
        if (it == pred_edge_idx_.end()) return result;
        result.reserve(it->second.size());
        for (size_t idx : it->second) {
            result.push_back(&edges[idx]);
        }
        return result;
    }

    /// Extract a sub-CFG containing only blocks whose start_pc falls within [lo, hi).
    /// Edges are kept only when both endpoints are in the sub-graph.
    CFGResult extract_range(uint64_t lo, uint64_t hi) const {
        CFGResult sub;
        for (auto it = blocks.lower_bound(lo); it != blocks.end() && it->first < hi; ++it) {
            sub.blocks.emplace(it->first, it->second);
        }
        for (const auto& e : edges) {
            if (sub.blocks.count(e.from_block) && sub.blocks.count(e.to_block)) {
                sub.edges.push_back(e);
            }
        }
        sub.build_adjacency();
        return sub;
    }

    /// Extract a sub-CFG for a single function by walking reachable blocks
    /// from `entry_pc` through edges (forward + backward).
    /// This captures the complete intra-procedural CFG even when blocks
    /// are not contiguous in address space.
    ///
    /// Optimized: uses the existing succ_edge_idx_/pred_edge_idx_ adjacency
    /// index for O(1) neighbor lookup instead of rebuilding O(E) adjacency
    /// maps from scratch each call.
    CFGResult extract_function(uint64_t entry_pc) const {
        CFGResult sub;
        if (blocks.find(entry_pc) == blocks.end()) return sub;

        // If adjacency index is not built, fall back to edge scan
        if (succ_edge_idx_.empty() && !edges.empty()) {
            const_cast<CFGResult*>(this)->build_adjacency();
        }

        // BFS from entry_pc using adjacency index (forward + backward)
        ankerl::unordered_dense::set<uint64_t> visited;
        visited.reserve(64);
        std::vector<uint64_t> worklist = {entry_pc};

        while (!worklist.empty()) {
            uint64_t pc = worklist.back();
            worklist.pop_back();
            if (!visited.insert(pc).second) continue;
            if (blocks.find(pc) == blocks.end()) continue;

            // Forward: successors via succ_edge_idx_
            auto succ_it = succ_edge_idx_.find(pc);
            if (succ_it != succ_edge_idx_.end()) {
                for (size_t idx : succ_it->second) {
                    const auto& e = edges[idx];
                    // Skip non-fallthrough call edges (inter-function)
                    auto src_it = blocks.find(e.from_block);
                    if (src_it != blocks.end() &&
                        src_it->second.terminator == TerminatorKind::Call &&
                        !e.is_fallthrough) continue;
                    if (!visited.count(e.to_block))
                        worklist.push_back(e.to_block);
                }
            }

            // Backward: predecessors via pred_edge_idx_
            auto pred_it = pred_edge_idx_.find(pc);
            if (pred_it != pred_edge_idx_.end()) {
                for (size_t idx : pred_it->second) {
                    const auto& e = edges[idx];
                    // Skip non-fallthrough call edges (inter-function)
                    auto dst_it = blocks.find(e.to_block);
                    if (dst_it != blocks.end() &&
                        /* skip edges coming from call blocks that aren't
                           fallthrough (return edges) */ false) continue;
                    if (!visited.count(e.from_block))
                        worklist.push_back(e.from_block);
                }
            }
        }

        for (uint64_t pc : visited) {
            auto it = blocks.find(pc);
            if (it != blocks.end()) sub.blocks.emplace(it->first, it->second);
        }
        for (const auto& e : edges) {
            if (visited.count(e.from_block) && visited.count(e.to_block)) {
                sub.edges.push_back(e);
            }
        }
        sub.build_adjacency();
        return sub;
    }

    /// Total number of basic blocks.
    size_t block_count() const { return blocks.size(); }

    /// Total number of edges.
    size_t edge_count() const { return edges.size(); }
};

// ─── CFG pass ─────────────────────────────────────────────────────────────

/// Builds a control flow graph from the trace.
/// Identifies basic blocks by detecting branch targets and branch instructions,
/// then constructs edges by walking the trace.
/// Dependencies: "xref" (for the set of executed PCs)
/// Result type: CFGResult
class CFGPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "cfg"; }
    std::string_view description() const override {
        return "Build control flow graph from trace";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "xref" };
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }
};

}  // namespace tenet

#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <vector>
#include <map>
#include <memory>
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

        // An edge is inter-procedural (crosses a function boundary) when its
        // source block ends in a Call (bl/blr — jumping into a callee) or a
        // Return (ret — jumping back to the caller) and it is not a
        // fallthrough edge. Such edges must not be walked in either
        // direction, or the BFS below would pull the caller's or callee's
        // blocks into this function's extracted sub-CFG.
        auto is_inter_procedural = [this](const CFGEdge& e) {
            auto src_it = blocks.find(e.from_block);
            if (src_it == blocks.end() || e.is_fallthrough) return false;
            auto term = src_it->second.terminator;
            return term == TerminatorKind::Call || term == TerminatorKind::Return;
        };

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
                    if (is_inter_procedural(e)) continue;
                    if (!visited.count(e.to_block))
                        worklist.push_back(e.to_block);
                }
            }

            // Backward: predecessors via pred_edge_idx_
            auto pred_it = pred_edge_idx_.find(pc);
            if (pred_it != pred_edge_idx_.end()) {
                for (size_t idx : pred_it->second) {
                    const auto& e = edges[idx];
                    // Mirrors the forward-direction check above: a
                    // predecessor edge that is itself inter-procedural
                    // (e.g. "caller calls into this function's entry", or
                    // "callee returns into this block") must not be walked,
                    // or it would pull the caller's/callee's blocks in.
                    if (is_inter_procedural(e)) continue;
                    if (!visited.count(e.from_block))
                        worklist.push_back(e.from_block);
                }
            }
        }

        for (uint64_t pc : visited) {
            auto it = blocks.find(pc);
            if (it != blocks.end()) sub.blocks.emplace(it->first, it->second);
        }
        // Collect edges by iterating only the adjacency lists of visited nodes
        // instead of scanning the entire edges vector — O(visited_edges) vs O(E).
        ankerl::unordered_dense::set<size_t> added_edge_indices;
        for (uint64_t pc : visited) {
            auto succ_it = succ_edge_idx_.find(pc);
            if (succ_it != succ_edge_idx_.end()) {
                for (size_t idx : succ_it->second) {
                    const auto& e = edges[idx];
                    if (visited.count(e.to_block) && added_edge_indices.insert(idx).second) {
                        sub.edges.push_back(e);
                    }
                }
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

    bool has_scan() const override { return true; }
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }

private:
    // ─── Edge key type for edge count map ────────────────────────────────
    struct EdgeKey {
        uint64_t from_block;
        uint64_t to_block;
        bool operator==(const EdgeKey& o) const {
            return from_block == o.from_block && to_block == o.to_block;
        }
    };
    struct EdgeKeyHash {
        size_t operator()(const EdgeKey& k) const {
            size_t h1 = std::hash<uint64_t>{}(k.from_block);
            size_t h2 = std::hash<uint64_t>{}(k.to_block);
            return h1 ^ (h2 * 0x9e3779b97f4a7c15ULL + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
        }
    };
    using EdgeCountMap = ankerl::unordered_dense::map<EdgeKey, uint64_t, EdgeKeyHash>;

    /// Collector that accumulates CFG edge counts during trace scan.
    /// Supports parallel sharding: each shard independently tracks block
    /// transitions, then merge() sums edge counts.
    ///
    /// Locality cache: most consecutive trace instructions fall within the
    /// same basic block, so we cache the current block's [start, end] range.
    /// On cache hit we skip the O(log B) upper_bound lookup entirely.
    class CFGEdgeCollector final : public TraceCollector {
    public:
        const CFGResult* cfg;       // Shared (read-only) block map
        EdgeCountMap edge_counts;
        uint64_t prev_block_start = UINT64_MAX;
        uint64_t prev_pc = UINT64_MAX;  // PC of the previous instruction

        // Locality cache — avoids block_containing() for sequential PCs
        uint64_t cached_block_start_ = 0;
        uint64_t cached_block_end_   = 0;   // inclusive, matching BasicBlock::end_pc

        explicit CFGEdgeCollector(const CFGResult* c) : cfg(c) {}

        std::string_view name() const override { return "cfg_edge_collector"; }
        bool supports_parallel() const override { return true; }

        std::unique_ptr<TraceCollector> clone() const override {
            return std::make_unique<CFGEdgeCollector>(cfg);
        }

        void merge(TraceCollector& shard) override;
        void on_inst(uint64_t inst_id, const InstView& inst) override;
    };

    std::unique_ptr<CFGEdgeCollector> collector_;
    CFGResult result_;
    bool blocks_built_ = false;
    bool transitions_available_ = false;  ///< xref provides pc_transitions

    /// Build basic blocks into result_ from xref data.
    /// Returns true on success, false if xref not available.
    bool build_blocks(PassContext& ctx);

    /// Build edges from xref pc_transitions (skip trace scan).
    /// Returns true on success, false if transitions insufficient.
    bool build_edges_from_transitions(PassContext& ctx);
};
}  // namespace tenet

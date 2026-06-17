#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <vector>
#include <algorithm>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Loop analysis result ─────────────────────────────────────────────────

/// Information about a single loop identified in the trace.
struct LoopInfo {
    uint64_t header_pc;          // PC of the loop header (back-edge target)
    uint64_t back_edge_pc;       // PC of the back-edge source (branch instruction)
    uint64_t iteration_count;    // How many times the back-edge was taken
    uint32_t nesting_depth;      // 0 = outermost loop, 1 = first nested, etc.

    /// All unique PCs that are part of this loop body (ordered).
    std::vector<uint64_t> body_pcs;
};

/// Result of loop analysis.
struct LoopResult {
    /// All detected loops, ordered by header_pc.
    std::vector<LoopInfo> loops;

    /// Per-PC: loop-head depth (0 = not a loop head, 1+ = deepest nesting level at that PC).
    ankerl::unordered_dense::map<uint64_t, uint32_t> pc_loop_depth;

    /// Per-PC: is this the header of a loop?
    ankerl::unordered_dense::map<uint64_t, bool> pc_is_loop_header;

    /// Per-PC: which loop index (into loops[]) contains this PC.
    /// A PC can be in multiple loops (nested); the innermost is stored.
    ankerl::unordered_dense::map<uint64_t, size_t> pc_innermost_loop;

    /// Total number of back-edges detected.
    size_t total_back_edges = 0;

    /// Maximum nesting depth observed.
    uint32_t max_nesting_depth = 0;

    // ─── Query helpers ────────────────────────────────────────────────

    /// Is this PC a loop header?
    bool is_loop_header(uint64_t pc) const {
        auto it = pc_is_loop_header.find(pc);
        return it != pc_is_loop_header.end() && it->second;
    }

    /// Is this PC inside any loop body (includes the header)?
    bool is_in_loop(uint64_t pc) const {
        return pc_loop_depth.find(pc) != pc_loop_depth.end();
    }

    /// Get the nesting depth of this PC (0 = not in a loop).
    uint32_t loop_depth_at(uint64_t pc) const {
        auto it = pc_loop_depth.find(pc);
        if (it == pc_loop_depth.end()) return 0;
        return it->second;
    }

    /// Get the innermost LoopInfo* for a PC (nullptr if not in any loop).
    const LoopInfo* innermost_loop_at(uint64_t pc) const {
        auto it = pc_innermost_loop.find(pc);
        if (it == pc_innermost_loop.end()) return nullptr;
        if (it->second >= loops.size()) return nullptr;
        return &loops[it->second];
    }
};

// ─── Loop pass ────────────────────────────────────────────────────────────

/// Detects loops in the execution trace using CFG-based dominator tree analysis.
///
/// Algorithm (LLVM LoopInfo-style, adapted for dynamic CFG):
///   1. Depend on "cfg" pass to get the basic block graph with edge counts.
///   2. Build a dominator tree on the block graph using the Semi-NCA algorithm.
///   3. Identify back-edges: an edge (u → v) where v dominates u.
///   4. For each back-edge, compute the natural loop body via reverse BFS
///      from u to v within the dominator tree.
///   5. Compute nesting by checking loop containment (fast set intersection).
///
/// Complexity: O(|V| + |E|) where V = basic blocks, E = CFG edges.
///   Typically V is in the thousands and E in the tens of thousands,
///   making this 1000x+ faster than full trace scans for large traces.
///
/// Result type: LoopResult
class LoopPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "loop"; }
    std::string_view description() const override {
        return "Loop detection via dominator tree on CFG (LLVM-style)";
    }

    std::vector<std::string_view> dependencies() const override {
        return { "cfg" };  // Depends on CFG pass (which depends on xref)
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }  // Much cheaper now
};

}  // namespace tenet

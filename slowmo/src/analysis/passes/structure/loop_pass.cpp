#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <stack>
#include <queue>
#include <numeric>

#include "common/byte_codec.h"

namespace tenet {

// ─── LoopResult serialization helpers ─────────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4C4F4F50 ("LOOP")
//   u32  version = 1
//   u64  total_back_edges
//   u32  max_nesting_depth
//   u64  num_loops
//   for each LoopInfo:
//     u64  header_pc
//     u64  back_edge_pc
//     u64  iteration_count
//     u32  nesting_depth
//     u64  num_body_pcs
//     u64[] body_pcs[num_body_pcs]
//   u64  num_pc_loop_depth  (map entries)
//   for each entry: u64 pc, u32 depth
//   u64  num_pc_is_loop_header
//   for each entry: u64 pc, u8 is_header
//   u64  num_pc_innermost_loop
//   for each entry: u64 pc, u64 loop_idx

namespace {

static constexpr uint32_t LOOP_BLOB_MAGIC   = 0x4C4F4F50u;  // "LOOP"
static constexpr uint32_t LOOP_BLOB_VERSION = 1u;

std::string loop_serialize(const LoopResult& res) {
    ByteWriter w;

    w.u32(LOOP_BLOB_MAGIC);
    w.u32(LOOP_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.total_back_edges));
    w.u32(res.max_nesting_depth);
    w.u64(static_cast<uint64_t>(res.loops.size()));

    for (const auto& li : res.loops) {
        w.u64(li.header_pc);
        w.u64(li.back_edge_pc);
        w.u64(li.iteration_count);
        w.u32(li.nesting_depth);
        w.u64(static_cast<uint64_t>(li.body_pcs.size()));
        for (uint64_t pc : li.body_pcs) w.u64(pc);
    }

    w.u64(static_cast<uint64_t>(res.pc_loop_depth.size()));
    for (const auto& [pc, depth] : res.pc_loop_depth) {
        w.u64(pc);
        w.u32(depth);
    }

    w.u64(static_cast<uint64_t>(res.pc_is_loop_header.size()));
    for (const auto& [pc, is_hdr] : res.pc_is_loop_header) {
        w.u64(pc);
        w.u8(is_hdr ? 1u : 0u);
    }

    w.u64(static_cast<uint64_t>(res.pc_innermost_loop.size()));
    for (const auto& [pc, idx] : res.pc_innermost_loop) {
        w.u64(pc);
        w.u64(static_cast<uint64_t>(idx));
    }

    return std::move(w).take();
}

bool loop_deserialize(const std::string& blob, LoopResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != LOOP_BLOB_MAGIC)   return false;
    if (r.u32() != LOOP_BLOB_VERSION) return false;

    out.total_back_edges  = static_cast<size_t>(r.u64());
    out.max_nesting_depth = r.u32();

    uint64_t n_loops = r.u64();
    out.loops.reserve(static_cast<size_t>(n_loops));
    for (uint64_t i = 0; i < n_loops; i++) {
        LoopInfo li;
        li.header_pc      = r.u64();
        li.back_edge_pc   = r.u64();
        li.iteration_count = r.u64();
        li.nesting_depth  = r.u32();
        uint64_t n_pcs    = r.u64();
        if (!r.ok()) return false;
        li.body_pcs.resize(static_cast<size_t>(n_pcs));
        for (uint64_t j = 0; j < n_pcs; j++) li.body_pcs[j] = r.u64();
        out.loops.push_back(std::move(li));
    }

    uint64_t n_depth = r.u64();
    if (!r.ok()) return false;
    out.pc_loop_depth.reserve(static_cast<size_t>(n_depth));
    for (uint64_t i = 0; i < n_depth; i++) {
        uint64_t pc = r.u64();
        uint32_t d  = r.u32();
        out.pc_loop_depth[pc] = d;
    }

    uint64_t n_hdr = r.u64();
    if (!r.ok()) return false;
    out.pc_is_loop_header.reserve(static_cast<size_t>(n_hdr));
    for (uint64_t i = 0; i < n_hdr; i++) {
        uint64_t pc   = r.u64();
        bool is_hdr   = r.u8() != 0;
        out.pc_is_loop_header[pc] = is_hdr;
    }

    uint64_t n_inner = r.u64();
    if (!r.ok()) return false;
    out.pc_innermost_loop.reserve(static_cast<size_t>(n_inner));
    for (uint64_t i = 0; i < n_inner; i++) {
        uint64_t pc  = r.u64();
        uint64_t idx = r.u64();
        out.pc_innermost_loop[pc] = static_cast<size_t>(idx);
    }

    return r.ok();
}

}  // anonymous namespace (loop serialization)

// ═══════════════════════════════════════════════════════════════════════════
// Semi-NCA Dominator Tree Implementation
// ═══════════════════════════════════════════════════════════════════════════
//
// Based on:
//   - Loukas Georgiadis: "Linear-Time Algorithms for Dominators and Related
//     Problems" (PhD thesis, Princeton, 2005)
//   - MaskRay's implementation for LLVM
//   - Keith D. Cooper et al: "A Simple, Fast Dominance Algorithm" (simplified
//     version used here for clarity, with Semi-NCA complexity)
//
// We use the simpler iterative algorithm from Cooper et al. since the graph
// sizes (typically < 10K blocks, < 50K edges) make the difference between
// O(V*alpha(V)) and O(V^2) worst-case negligible, while being much simpler
// to implement correctly.

namespace {

/// Compact graph representation for dominator computation.
/// Maps block start_pc → integer node ID for dense array access.
struct CompactCFG {
    // Node ID ↔ block_start_pc mapping
    std::vector<uint64_t> id_to_pc;           // node_id → start_pc
    ankerl::unordered_dense::map<uint64_t, uint32_t> pc_to_id;  // start_pc → node_id

    // Adjacency lists
    std::vector<std::vector<uint32_t>> successors;    // node → succ list
    std::vector<std::vector<uint32_t>> predecessors;  // node → pred list

    // Edge weights (for iteration count)
    // Key: (from_id << 32 | to_id), Value: taken_count
    ankerl::unordered_dense::map<uint64_t, uint64_t> edge_counts;

    uint32_t entry_node = 0;  // Entry block (lowest PC or first executed)
    uint32_t num_nodes = 0;

    uint64_t edge_key(uint32_t from, uint32_t to) const {
        return (static_cast<uint64_t>(from) << 32) | to;
    }
};

/// Build compact CFG from CFGResult.
CompactCFG build_compact_cfg(const CFGResult& cfg) {
    CompactCFG g;

    // Assign IDs to blocks (sorted by start_pc for determinism)
    g.id_to_pc.reserve(cfg.blocks.size());
    for (const auto& [start_pc, block] : cfg.blocks) {
        uint32_t id = static_cast<uint32_t>(g.id_to_pc.size());
        g.pc_to_id[start_pc] = id;
        g.id_to_pc.push_back(start_pc);
    }
    g.num_nodes = static_cast<uint32_t>(g.id_to_pc.size());

    // Build adjacency lists
    g.successors.resize(g.num_nodes);
    g.predecessors.resize(g.num_nodes);

    for (const auto& edge : cfg.edges) {
        auto from_it = g.pc_to_id.find(edge.from_block);
        auto to_it = g.pc_to_id.find(edge.to_block);
        if (from_it == g.pc_to_id.end() || to_it == g.pc_to_id.end()) continue;

        uint32_t from = from_it->second;
        uint32_t to = to_it->second;
        g.successors[from].push_back(to);
        g.predecessors[to].push_back(from);
        g.edge_counts[g.edge_key(from, to)] = edge.taken_count;
    }

    // Entry node = first block (lowest start_pc, since map is ordered)
    g.entry_node = 0;

    return g;
}

/// Compute DFS ordering (reverse post-order) from entry.
/// Returns the RPO numbering: rpo[node_id] = rpo_number.
/// Also returns rpo_order: the nodes in RPO order.
struct DFSInfo {
    std::vector<uint32_t> rpo;        // node → RPO number (lower = earlier)
    std::vector<uint32_t> rpo_order;  // RPO number → node (traversal order)
};

DFSInfo compute_rpo(const CompactCFG& g) {
    DFSInfo info;
    info.rpo.assign(g.num_nodes, UINT32_MAX);  // UINT32_MAX = unreachable
    info.rpo_order.reserve(g.num_nodes);

    // Iterative DFS for post-order
    std::vector<bool> visited(g.num_nodes, false);
    std::vector<uint32_t> post_order;
    post_order.reserve(g.num_nodes);

    // Use explicit stack to avoid recursion overflow
    struct Frame {
        uint32_t node;
        size_t child_idx;
    };
    std::stack<Frame> stack;

    visited[g.entry_node] = true;
    stack.push({g.entry_node, 0});

    while (!stack.empty()) {
        auto& frame = stack.top();
        if (frame.child_idx < g.successors[frame.node].size()) {
            uint32_t child = g.successors[frame.node][frame.child_idx];
            frame.child_idx++;
            if (!visited[child]) {
                visited[child] = true;
                stack.push({child, 0});
            }
        } else {
            post_order.push_back(frame.node);
            stack.pop();
        }
    }

    // Reverse post-order
    uint32_t rpo_num = 0;
    for (auto it = post_order.rbegin(); it != post_order.rend(); ++it) {
        info.rpo[*it] = rpo_num;
        info.rpo_order.push_back(*it);
        rpo_num++;
    }

    return info;
}

/// Compute immediate dominators using Cooper et al.'s iterative algorithm.
/// "A Simple, Fast Dominance Algorithm" (2001)
///
/// Returns idom[node_id] = immediate dominator's node_id.
/// idom[entry] = entry (self-dominates).
/// idom[node] = UINT32_MAX for unreachable nodes.
std::vector<uint32_t> compute_idom(const CompactCFG& g, const DFSInfo& dfs) {
    const uint32_t UNDEF = UINT32_MAX;
    std::vector<uint32_t> idom(g.num_nodes, UNDEF);
    idom[g.entry_node] = g.entry_node;

    // intersect: find common dominator (LCA in dom tree using RPO numbers)
    auto intersect = [&](uint32_t b1, uint32_t b2) -> uint32_t {
        while (b1 != b2) {
            while (dfs.rpo[b1] > dfs.rpo[b2]) {
                b1 = idom[b1];
                if (b1 == UNDEF) return UNDEF;
            }
            while (dfs.rpo[b2] > dfs.rpo[b1]) {
                b2 = idom[b2];
                if (b2 == UNDEF) return UNDEF;
            }
        }
        return b1;
    };

    // Iterate until convergence
    bool changed = true;
    while (changed) {
        changed = false;
        // Process nodes in RPO order (skip entry)
        for (size_t i = 1; i < dfs.rpo_order.size(); i++) {
            uint32_t node = dfs.rpo_order[i];
            uint32_t new_idom = UNDEF;

            for (uint32_t pred : g.predecessors[node]) {
                if (idom[pred] == UNDEF) continue;  // Skip unprocessed preds
                if (new_idom == UNDEF) {
                    new_idom = pred;
                } else {
                    new_idom = intersect(new_idom, pred);
                    if (new_idom == UNDEF) break;
                }
            }

            if (new_idom != UNDEF && idom[node] != new_idom) {
                idom[node] = new_idom;
                changed = true;
            }
        }
    }

    return idom;
}

/// Check if 'dom' dominates 'node' using the idom tree.
bool dominates(const std::vector<uint32_t>& idom, uint32_t dom, uint32_t node) {
    if (dom == node) return true;
    const uint32_t UNDEF = UINT32_MAX;
    uint32_t current = node;
    // Walk up the dominator tree
    while (current != UNDEF && current != dom) {
        uint32_t next = idom[current];
        if (next == current) break;  // Reached entry
        current = next;
    }
    return current == dom;
}

/// Find natural loop body for a back-edge (latch → header).
/// The natural loop body is the set of nodes from which the header can be
/// reached without going through the header itself (i.e., nodes between
/// header and latch in the dominator tree).
///
/// Algorithm: reverse BFS from latch, staying within nodes dominated by header.
std::vector<uint32_t> find_loop_body(
    const CompactCFG& g,
    const std::vector<uint32_t>& idom,
    uint32_t header,
    uint32_t latch)
{
    // The loop body includes at minimum the header and latch
    std::vector<uint32_t> body;
    ankerl::unordered_dense::set<uint32_t> in_body;

    in_body.insert(header);
    body.push_back(header);

    if (header == latch) {
        // Self-loop
        return body;
    }

    // BFS backwards from latch, adding predecessors until we reach header
    std::queue<uint32_t> worklist;
    if (in_body.insert(latch).second) {
        body.push_back(latch);
        worklist.push(latch);
    }

    while (!worklist.empty()) {
        uint32_t node = worklist.front();
        worklist.pop();

        for (uint32_t pred : g.predecessors[node]) {
            if (in_body.insert(pred).second) {
                body.push_back(pred);
                worklist.push(pred);
            }
        }
    }

    return body;
}

/// Represent a detected natural loop in the graph domain.
struct GraphLoop {
    uint32_t header;             // Header node ID
    uint32_t latch;              // Latch (back-edge source) node ID
    uint64_t iteration_count;    // Edge taken count of back-edge
    std::vector<uint32_t> body;  // All node IDs in the loop body
    uint32_t nesting_depth = 0;  // Computed later
};

}  // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════
// LoopPass::run — Main entry point
// ═══════════════════════════════════════════════════════════════════════════

PassResult LoopPass::run(PassContext& ctx) {
    auto& index = ctx.index();
    const auto& range = ctx.range();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("loop", blob)) {
            LoopResult cached;
            if (loop_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Loop pass: {} loops (from cache)", cached.loops.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // ── Step 1: Get CFG from dependency ───────────────────────────────────
    ctx.progress(0.0f, "Loop pass: acquiring CFG...");

    const auto& cfg = ctx.require<CFGResult>("cfg");

    if (cfg.blocks.empty()) {
        ctx.progress(1.0f, "Loop pass: no blocks in CFG");
        return PassResult::success(LoopResult{});
    }

    // ── Step 2: Build compact graph ──────────────────────────────────────
    ctx.progress(0.1f, fmt::format("Loop pass: building compact CFG ({} blocks, {} edges)...",
                                    cfg.blocks.size(), cfg.edges.size()));

    CompactCFG g = build_compact_cfg(cfg);
    if (g.num_nodes == 0) {
        ctx.progress(1.0f, "Loop pass: empty graph");
        return PassResult::success(LoopResult{});
    }

    // ── Step 3: Compute reverse post-order ────────────────────────────────
    ctx.progress(0.2f, "Loop pass: computing DFS order...");
    DFSInfo dfs = compute_rpo(g);

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    // ── Step 4: Compute dominator tree ────────────────────────────────────
    ctx.progress(0.3f, "Loop pass: computing dominator tree...");
    std::vector<uint32_t> idom = compute_idom(g, dfs);

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    // ── Step 5: Find back-edges ──────────────────────────────────────────
    // A back-edge is (u → v) where v dominates u.
    ctx.progress(0.5f, "Loop pass: identifying back-edges...");

    std::vector<GraphLoop> graph_loops;
    for (uint32_t u = 0; u < g.num_nodes; u++) {
        for (uint32_t v : g.successors[u]) {
            if (dominates(idom, v, u)) {
                // (u → v) is a back-edge, v is loop header, u is latch
                GraphLoop loop;
                loop.header = v;
                loop.latch = u;

                // Get iteration count from edge
                auto it = g.edge_counts.find(g.edge_key(u, v));
                loop.iteration_count = (it != g.edge_counts.end()) ? it->second : 1;

                // Find natural loop body
                loop.body = find_loop_body(g, idom, v, u);

                graph_loops.push_back(std::move(loop));
            }
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    if (graph_loops.empty()) {
        ctx.progress(1.0f, "Loop pass: no loops found");
        return PassResult::success(LoopResult{});
    }

    // ── Step 6: Merge loops with same header ─────────────────────────────
    // Multiple back-edges to the same header form a single loop.
    // Merge their bodies and sum iteration counts.
    ctx.progress(0.6f, "Loop pass: merging multi-latch loops...");

    // Group by header
    ankerl::unordered_dense::map<uint32_t, size_t> header_to_loop;
    std::vector<GraphLoop> merged_loops;

    for (auto& loop : graph_loops) {
        auto it = header_to_loop.find(loop.header);
        if (it == header_to_loop.end()) {
            header_to_loop[loop.header] = merged_loops.size();
            merged_loops.push_back(std::move(loop));
        } else {
            auto& existing = merged_loops[it->second];
            existing.iteration_count += loop.iteration_count;
            // Merge body
            ankerl::unordered_dense::set<uint32_t> body_set(
                existing.body.begin(), existing.body.end());
            for (uint32_t n : loop.body) {
                if (body_set.insert(n).second) {
                    existing.body.push_back(n);
                }
            }
            // Keep the most recent latch (largest RPO = closest to header)
            if (dfs.rpo[loop.latch] != UINT32_MAX &&
                (dfs.rpo[existing.latch] == UINT32_MAX ||
                 dfs.rpo[loop.latch] > dfs.rpo[existing.latch])) {
                existing.latch = loop.latch;
            }
        }
    }

    // ── Step 7: Compute nesting depths ────────────────────────────────────
    ctx.progress(0.7f, "Loop pass: computing nesting depths...");

    // Build body sets for fast containment check
    std::vector<ankerl::unordered_dense::set<uint32_t>> body_sets;
    body_sets.reserve(merged_loops.size());
    for (const auto& loop : merged_loops) {
        body_sets.emplace_back(loop.body.begin(), loop.body.end());
    }

    // Loop A is nested inside loop B if A.header ∈ B.body && A != B
    for (size_t i = 0; i < merged_loops.size(); i++) {
        uint32_t depth = 0;
        for (size_t j = 0; j < merged_loops.size(); j++) {
            if (i == j) continue;
            if (body_sets[j].contains(merged_loops[i].header)) {
                depth++;
            }
        }
        merged_loops[i].nesting_depth = depth;
    }

    // ── Step 8: Convert to LoopResult ─────────────────────────────────────
    ctx.progress(0.85f, "Loop pass: building final result...");

    LoopResult result;
    result.total_back_edges = graph_loops.size();  // Original count before merging

    for (const auto& gloop : merged_loops) {
        LoopInfo info;
        info.header_pc = g.id_to_pc[gloop.header];
        info.back_edge_pc = g.id_to_pc[gloop.latch];
        info.iteration_count = gloop.iteration_count;
        info.nesting_depth = gloop.nesting_depth;

        if (gloop.nesting_depth > result.max_nesting_depth) {
            result.max_nesting_depth = gloop.nesting_depth;
        }

        // Expand block-level body to PC-level body
        // Each block contains multiple instruction PCs
        for (uint32_t node : gloop.body) {
            uint64_t block_pc = g.id_to_pc[node];
            auto block_it = cfg.blocks.find(block_pc);
            if (block_it != cfg.blocks.end()) {
                for (uint64_t pc : block_it->second.instructions) {
                    info.body_pcs.push_back(pc);
                }
            }
        }
        std::sort(info.body_pcs.begin(), info.body_pcs.end());
        // Remove duplicates (shouldn't happen, but be safe)
        info.body_pcs.erase(
            std::unique(info.body_pcs.begin(), info.body_pcs.end()),
            info.body_pcs.end());

        result.loops.push_back(std::move(info));
    }

    // Sort loops by header_pc for determinism
    std::sort(result.loops.begin(), result.loops.end(),
        [](const LoopInfo& a, const LoopInfo& b) {
            return a.header_pc < b.header_pc;
        });

    // ── Step 9: Build per-PC lookup maps ──────────────────────────────────
    ctx.progress(0.9f, "Loop pass: building PC lookup maps...");

    for (size_t li = 0; li < result.loops.size(); li++) {
        const auto& loop = result.loops[li];

        // Mark loop header
        result.pc_is_loop_header[loop.header_pc] = true;

        // For each body PC: update depth (use max depth seen across all loops)
        for (uint64_t pc : loop.body_pcs) {
            uint32_t current_depth = loop.nesting_depth + 1;  // +1 so "in a loop" >= 1
            auto it = result.pc_loop_depth.find(pc);
            if (it == result.pc_loop_depth.end() || it->second < current_depth) {
                result.pc_loop_depth[pc] = current_depth;
            }

            // For innermost loop: keep the loop with the highest nesting depth
            auto it2 = result.pc_innermost_loop.find(pc);
            if (it2 == result.pc_innermost_loop.end()) {
                result.pc_innermost_loop[pc] = li;
            } else {
                if (result.loops[it2->second].nesting_depth < loop.nesting_depth) {
                    result.pc_innermost_loop[pc] = li;
                }
            }
        }
    }

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = loop_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("loop", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "Loop pass: {} loops detected (max nesting={}) from {} blocks + {} edges [graph-based]",
        result.loops.size(), result.max_nesting_depth,
        g.num_nodes, cfg.edges.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

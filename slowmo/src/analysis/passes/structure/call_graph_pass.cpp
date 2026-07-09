#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "io/index_builder.h"

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <algorithm>
#include <queue>

#include "common/byte_codec.h"

namespace tenet {

// ─── CallGraphResult serialization helpers ─────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic    = 0x43414C47 ("CALG")
//   u32  version  = 1
//   u64  max_depth
//   u64  total_call_events
//   u64  num_edges
//   for each CallGraphEdge:
//     u64  caller_pc
//     u64  callee_pc
//     u64  call_count
//     u64  num_call_sites
//     u64[] call_site_pcs[num_call_sites]
//   u64  num_nodes
//   for each CallGraphNode:
//     u64  entry_pc
//     u64  total_calls_made
//     u64  total_calls_received
//     u32  name_len
//     u8[] name[name_len]
//     u64  num_outgoing
//     u64[] outgoing_edges[num_outgoing]
//     u64  num_incoming
//     u64[] incoming_edges[num_incoming]
//   (edge_map_ is rebuilt from edges + nodes after deserialization)

namespace {

static constexpr uint32_t CALG_BLOB_MAGIC   = 0x43414C47u;  // "CALG"
static constexpr uint32_t CALG_BLOB_VERSION = 1u;

// Local helper: build a root pseudo-key from a call-site PC. See the
// kCallGraphRootTagBit / call_graph_is_root_key / call_graph_root_call_site
// declarations in call_graph_pass.h for the full rationale — this file uses
// those shared helpers throughout instead of redefining the tag-bit logic.
uint64_t make_root_key(uint64_t call_site_pc) {
    return kCallGraphRootTagBit | call_site_pc;
}

std::string call_graph_serialize(const CallGraphResult& res) {
    ByteWriter w;

    w.u32(CALG_BLOB_MAGIC);
    w.u32(CALG_BLOB_VERSION);
    w.u64(res.max_depth);
    w.u64(res.total_call_events);
    w.u64(static_cast<uint64_t>(res.edges.size()));

    for (const auto& e : res.edges) {
        w.u64(e.caller_pc);
        w.u64(e.callee_pc);
        w.u64(e.call_count);
        w.u64(static_cast<uint64_t>(e.call_site_pcs.size()));
        for (uint64_t cs : e.call_site_pcs) w.u64(cs);
    }

    w.u64(static_cast<uint64_t>(res.nodes.size()));
    for (const auto& [pc, node] : res.nodes) {
        w.u64(node.entry_pc);
        w.u64(node.total_calls_made);
        w.u64(node.total_calls_received);
        w.str(node.name);
        w.u64(static_cast<uint64_t>(node.outgoing_edges.size()));
        for (size_t idx : node.outgoing_edges) w.u64(static_cast<uint64_t>(idx));
        w.u64(static_cast<uint64_t>(node.incoming_edges.size()));
        for (size_t idx : node.incoming_edges) w.u64(static_cast<uint64_t>(idx));
    }

    return std::move(w).take();
}

bool call_graph_deserialize(const std::string& blob, CallGraphResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != CALG_BLOB_MAGIC)   return false;
    if (r.u32() != CALG_BLOB_VERSION) return false;

    out.max_depth         = r.u64();
    out.total_call_events = r.u64();

    uint64_t n_edges = r.u64();
    out.edges.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        CallGraphEdge e;
        e.caller_pc  = r.u64();
        e.callee_pc  = r.u64();
        e.call_count = r.u64();
        uint64_t n_cs = r.u64();
        if (!r.ok()) return false;
        e.call_site_pcs.resize(static_cast<size_t>(n_cs));
        for (uint64_t j = 0; j < n_cs; j++) e.call_site_pcs[j] = r.u64();
        out.edges.push_back(std::move(e));
    }

    uint64_t n_nodes = r.u64();
    if (!r.ok()) return false;
    out.nodes.reserve(static_cast<size_t>(n_nodes));
    for (uint64_t i = 0; i < n_nodes; i++) {
        CallGraphNode node;
        node.entry_pc              = r.u64();
        node.total_calls_made      = r.u64();
        node.total_calls_received  = r.u64();
        if (!r.str(node.name)) return false;
        uint64_t n_out = r.u64();
        if (!r.ok()) return false;
        node.outgoing_edges.resize(static_cast<size_t>(n_out));
        for (uint64_t j = 0; j < n_out; j++)
            node.outgoing_edges[j] = static_cast<size_t>(r.u64());
        uint64_t n_in = r.u64();
        if (!r.ok()) return false;
        node.incoming_edges.resize(static_cast<size_t>(n_in));
        for (uint64_t j = 0; j < n_in; j++)
            node.incoming_edges[j] = static_cast<size_t>(r.u64());
        // Deserialized nodes are always fully populated (blob format has no
        // "empty placeholder" concept) — mark initialized so downstream code
        // never mistakes it for a fresh default-constructed node. `is_root`
        // isn't persisted explicitly (no blob format bump needed); it's
        // fully recoverable from the tag bit baked into entry_pc itself.
        node.initialized = true;
        node.is_root      = call_graph_is_root_key(node.entry_pc);
        out.nodes.emplace(node.entry_pc, std::move(node));
    }

    if (!r.ok()) return false;

    // Rebuild edge_map_ from edges
    for (size_t ei = 0; ei < out.edges.size(); ei++) {
        const auto& e = out.edges[ei];
        out.edge_map_[e.caller_pc][e.callee_pc] = ei;
    }

    return true;
}

}  // anonymous namespace (call_graph serialization)

// ─── CallGraphPass implementation ─────────────────────────────────────────

PassResult CallGraphPass::run(PassContext& ctx) {
    auto& index = ctx.index();
    const auto& range = ctx.range();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("call_graph", blob)) {
            CallGraphResult cached;
            if (call_graph_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Call graph: {} nodes, {} edges (from cache)",
                    cached.nodes.size(), cached.edges.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // Require function pass results
    const auto& func_result = ctx.require<FunctionResult>("function");

    CallGraphResult result;
    result.total_call_events = func_result.call_events.size();

    // We need to determine the caller function for each call event.
    // Strategy: for each CallEvent, the call_site_pc belongs to the caller function,
    // and the target_pc is the callee function entry.
    // We use FunctionResult::function_at() to find which function contains the call site,
    // but since function_at() checks by inst_id, we need the inst_id of the call.
    // Instead, we build a pc→function mapping from FunctionResult::functions.

    // Step 1: Build a reverse map: for any PC inside a function, find the function.
    // Since FunctionResult only gives us entry PCs, we use a simpler approach:
    // For each call event, the "caller" is determined by checking which function's
    // active call frame contains this call site (using the call stack at that point).
    // The outer function (one level up in the call stack) is the caller.

    // Track caller→callee edges and their counts.
    // Key: (caller_entry_pc, callee_entry_pc)
    struct EdgeKey {
        uint64_t caller_pc;
        uint64_t callee_pc;

        bool operator==(const EdgeKey& o) const {
            return caller_pc == o.caller_pc && callee_pc == o.callee_pc;
        }
    };
    struct EdgeKeyHash {
        size_t operator()(const EdgeKey& k) const {
            // Combine two uint64_t hashes
            size_t h1 = std::hash<uint64_t>{}(k.caller_pc);
            size_t h2 = std::hash<uint64_t>{}(k.callee_pc);
            return h1 ^ (h2 * 0x9e3779b97f4a7c15ULL + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
        }
    };

    // Temporary edge accumulator: key → {count, call_site_pcs}
    // Uses ankerl::unordered_dense::map for better cache locality, and
    // vector instead of unordered_set for call sites (sort+unique at the end).
    ankerl::unordered_dense::map<EdgeKey, std::pair<uint64_t, std::vector<uint64_t>>, EdgeKeyHash> edge_accum;

    // Track max depth
    uint64_t max_depth = 0;

    // Simulated call stack to determine caller of each call event.
    // Each entry: function entry PC of the active function.
    std::vector<uint64_t> call_stack_funcs;

    // Access function names directly from FunctionResult instead of copying.
    const auto& func_names = func_result.functions;

    // ── Process call events with O(N log D) merge instead of O(N log N) sort ──
    //
    // CallEvents are already sorted by call_inst_id.  Return events are NOT
    // globally sorted by return_inst_id (they follow LIFO call-stack order),
    // but we can interleave them with calls using a min-heap of pending
    // returns.  The heap size is bounded by the call depth D (typically < 1000),
    // so total complexity is O(N log D) instead of O(N log N).
    //
    // At the same inst_id, calls are processed before returns (matching the
    // original sort comparator's tie-break rule).

    // Min-heap: (return_inst_id, event_index), ordered by return_inst_id.
    std::priority_queue<
        std::pair<uint64_t, size_t>,
        std::vector<std::pair<uint64_t, size_t>>,
        std::greater<>> pending_returns;

    for (size_t i = 0; i < func_result.call_events.size(); i++) {
        if ((i % 1000) == 0 && ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        const auto& evt = func_result.call_events[i];

        // Drain all returns that happen strictly before this call.
        // (Using < not <= ensures calls precede returns at the same inst_id.)
        while (!pending_returns.empty() &&
               pending_returns.top().first < evt.call_inst_id) {
            if (!call_stack_funcs.empty()) {
                call_stack_funcs.pop_back();
            }
            pending_returns.pop();
        }

        // Determine caller: top of stack, or a synthetic per-call-site
        // root pseudo-key if the stack is empty (see
        // kCallGraphRootTagBit in call_graph_pass.h for why we don't
        // collapse all of these into a single PC-0 node).
        uint64_t caller_entry_pc = call_stack_funcs.empty()
                                       ? make_root_key(evt.call_site_pc)
                                       : call_stack_funcs.back();
        uint64_t callee_entry_pc = evt.target_pc;

        // Update max depth
        if (evt.depth > max_depth) {
            max_depth = evt.depth;
        }

        // Accumulate edge
        EdgeKey key{caller_entry_pc, callee_entry_pc};
        auto& acc = edge_accum[key];
        acc.first++;
        acc.second.push_back(evt.call_site_pc);

        // Push callee onto stack
        call_stack_funcs.push_back(callee_entry_pc);

        // Schedule return if present
        if (evt.return_inst_id != 0) {
            pending_returns.emplace(evt.return_inst_id, i);
        }
    }

    // Drain remaining returns after all calls have been processed.
    while (!pending_returns.empty()) {
        if (!call_stack_funcs.empty()) {
            call_stack_funcs.pop_back();
        }
        pending_returns.pop();
    }

    result.max_depth = max_depth;

    // Step 3: Build final edges and nodes from accumulated data.
    // Reserve edge vector
    result.edges.reserve(edge_accum.size());

    for (const auto& [key, acc_data] : edge_accum) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        size_t edge_idx = result.edges.size();

        CallGraphEdge edge;
        edge.caller_pc = key.caller_pc;
        edge.callee_pc = key.callee_pc;
        edge.call_count = acc_data.first;
        edge.call_site_pcs = std::move(acc_data.second);
        // Sort and deduplicate call sites for deterministic output
        std::sort(edge.call_site_pcs.begin(), edge.call_site_pcs.end());
        edge.call_site_pcs.erase(
            std::unique(edge.call_site_pcs.begin(), edge.call_site_pcs.end()),
            edge.call_site_pcs.end());

        result.edge_map_[key.caller_pc][key.callee_pc] = edge_idx;
        result.edges.push_back(std::move(edge));

        // Ensure both caller and callee nodes exist. Use `initialized` (not
        // `entry_pc == 0`) to detect first-touch, since entry_pc == 0 is also
        // a legitimate *value* a root pseudo-key's call-site component could
        // have — comparing against 0 would misidentify a root node as "not
        // yet initialized" and clobber it on every edge that touches it.
        auto& caller_node = result.nodes[key.caller_pc];
        if (!caller_node.initialized) {
            caller_node.entry_pc = key.caller_pc;
            if (call_graph_is_root_key(key.caller_pc)) {
                caller_node.is_root = true;
                caller_node.name = fmt::format("<root@{:#x}>", call_graph_root_call_site(key.caller_pc));
            } else {
                auto nit = func_names.find(key.caller_pc);
                caller_node.name = (nit != func_names.end()) ? nit->second.name
                                : fmt::format("sub_{:x}", key.caller_pc);
            }
            caller_node.initialized = true;
        }
        caller_node.outgoing_edges.push_back(edge_idx);
        caller_node.total_calls_made += acc_data.first;

        auto& callee_node = result.nodes[key.callee_pc];
        if (!callee_node.initialized) {
            callee_node.entry_pc = key.callee_pc;
            auto nit = func_names.find(key.callee_pc);
            callee_node.name = (nit != func_names.end()) ? nit->second.name
                            : fmt::format("sub_{:x}", key.callee_pc);
            callee_node.initialized = true;
        }
        callee_node.incoming_edges.push_back(edge_idx);
        callee_node.total_calls_received += acc_data.first;
    }

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = call_graph_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("call_graph", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Call graph: {} nodes, {} edges, max depth {}",
                                    result.nodes.size(), result.edges.size(), result.max_depth));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

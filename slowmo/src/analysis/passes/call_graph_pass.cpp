#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/function_pass.h"

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <algorithm>

namespace tenet {

// ─── CallGraphPass implementation ─────────────────────────────────────────

PassResult CallGraphPass::run(PassContext& ctx) {
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

    // Step 2: Walk through call events in order to build edges.
    // We simulate the call stack: when we see a call event, the caller is
    // the top of the stack (or "root" if stack is empty), then we push the callee.
    // When we see a return, we pop.

    // We need to process events in inst_id order. CallEvents are already in order
    // by call_inst_id, but returns may come out of order. We'll process using
    // both the call_site_map_ and return_site_map_ from FunctionResult.

    // Build a timeline of events (call and return) sorted by inst_id.
    struct TimelineEvent {
        uint64_t inst_id;
        bool is_call;       // true = call, false = return
        size_t event_index; // index into call_events
    };
    std::vector<TimelineEvent> timeline;
    timeline.reserve(func_result.call_events.size() * 2);

    for (size_t i = 0; i < func_result.call_events.size(); i++) {
        const auto& evt = func_result.call_events[i];
        timeline.push_back({evt.call_inst_id, true, i});
        if (evt.return_inst_id != 0) {
            timeline.push_back({evt.return_inst_id, false, i});
        }
    }

    // Sort by inst_id, calls before returns at same inst_id
    std::sort(timeline.begin(), timeline.end(),
              [](const TimelineEvent& a, const TimelineEvent& b) {
                  if (a.inst_id != b.inst_id) return a.inst_id < b.inst_id;
                  // At same inst_id, calls come before returns
                  return a.is_call && !b.is_call;
              });

    // Process timeline
    for (const auto& te : timeline) {
        const auto& evt = func_result.call_events[te.event_index];

        if (te.is_call) {
            // Determine caller: top of stack, or 0 for root
            uint64_t caller_entry_pc = call_stack_funcs.empty() ? 0 : call_stack_funcs.back();
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
        } else {
            // Return: pop from stack
            if (!call_stack_funcs.empty()) {
                call_stack_funcs.pop_back();
            }
        }
    }

    result.max_depth = max_depth;

    // Step 3: Build final edges and nodes from accumulated data.
    // Reserve edge vector
    result.edges.reserve(edge_accum.size());

    // Create a "root" pseudo-node (entry_pc = 0) for calls from outside the trace
    const uint64_t ROOT_PC = 0;

    for (const auto& [key, acc_data] : edge_accum) {
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

        // Ensure both caller and callee nodes exist
        auto& caller_node = result.nodes[key.caller_pc];
        if (caller_node.entry_pc == 0 && key.caller_pc != 0) {
            caller_node.entry_pc = key.caller_pc;
            auto nit = func_names.find(key.caller_pc);
            caller_node.name = (nit != func_names.end()) ? nit->second.name
                            : fmt::format("sub_{:x}", key.caller_pc);
        } else if (key.caller_pc == 0) {
            caller_node.entry_pc = 0;
            caller_node.name = "<root>";
        }
        caller_node.outgoing_edges.push_back(edge_idx);
        caller_node.total_calls_made += acc_data.first;

        auto& callee_node = result.nodes[key.callee_pc];
        if (callee_node.entry_pc == 0) {
            callee_node.entry_pc = key.callee_pc;
            auto nit = func_names.find(key.callee_pc);
            callee_node.name = (nit != func_names.end()) ? nit->second.name
                            : fmt::format("sub_{:x}", key.callee_pc);
        }
        callee_node.incoming_edges.push_back(edge_idx);
        callee_node.total_calls_received += acc_data.first;
    }

    ctx.progress(1.0f, fmt::format("Call graph: {} nodes, {} edges, max depth {}",
                                    result.nodes.size(), result.edges.size(), result.max_depth));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

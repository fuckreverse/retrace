#pragma once

#include <cstdint>

// ─── Shared dataflow graph edge type ─────────────────────────────────────────
// Used by both DataflowGraphPass (register-only DFG) and BackwardTaintPass
// (register + memory propagation).
//
// DFGEdge was previously a separate struct in dataflow_graph_pass.h with a
// `reg_index` field; it is now a type alias for DataflowEdge, using `via_reg`
// for consistency.  Code that previously read `edge.reg_index` should use
// `edge.via_reg` instead.

namespace tenet {

/// A directed data-flow edge in the instruction dependency graph.
/// Represents: instruction `from_inst_id` produces a value consumed by `to_inst_id`.
///
/// For pure-register edges (DataflowGraphPass):  via_mem_addr == 0.
/// For memory-propagated edges (BackwardTaintPass): via_mem_addr != 0.
struct DataflowEdge {
    uint64_t from_inst_id = 0;   ///< producer (earlier in trace)
    uint64_t to_inst_id   = 0;   ///< consumer (later in trace)
    uint8_t  via_reg      = 0;   ///< the register carrying the value (0 = none / memory only)
    uint64_t via_mem_addr = 0;   ///< non-zero when data flows through a memory location

    DataflowEdge() = default;
    DataflowEdge(uint64_t from, uint64_t to, uint8_t reg, uint64_t mem = 0)
        : from_inst_id(from), to_inst_id(to), via_reg(reg), via_mem_addr(mem) {}
};

/// Alias kept for DataflowGraphPass which previously used DFGEdge with reg_index.
/// New code should use DataflowEdge directly.
using DFGEdge = DataflowEdge;

}  // namespace tenet

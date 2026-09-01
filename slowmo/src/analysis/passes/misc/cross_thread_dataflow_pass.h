#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "common/dataflow_types.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace tenet {

// ─── Result ────────────────────────────────────────────────────────────────

/// One hand-off: thread A wrote a memory location, thread B read it back.
struct CrossThreadEdge {
    uint64_t from_inst_id = 0;    ///< writing instruction (producer, thread A)
    uint64_t to_inst_id   = 0;    ///< reading instruction (consumer, thread B)
    uint64_t from_thread  = 0;    ///< producer thread id
    uint64_t to_thread    = 0;    ///< consumer thread id
    uint64_t addr         = 0;    ///< memory location carrying the value
    uint8_t  size         = 0;    ///< access size in bytes (min of W/R)

    DataflowEdge as_dataflow_edge() const {
        // Memory-propagated edge: via_reg = 0, via_mem_addr = addr.
        return DataflowEdge(from_inst_id, to_inst_id, /*via_reg=*/0, addr);
    }
};

/// Aggregated channel: one address used to pass values between two threads.
struct CrossThreadChannel {
    uint64_t addr = 0;
    uint64_t from_thread = 0;
    uint64_t to_thread = 0;
    uint64_t edge_count = 0;      ///< number of hand-offs on this channel
    std::vector<uint32_t> edge_indices;  ///< indices into CrossThreadDataflowResult::edges
};

/// Result of the cross_thread_dataflow pass.
struct CrossThreadDataflowResult {
    /// All observed cross-thread memory hand-offs, ordered by to_inst_id
    /// (consumer order), i.e. the order the data arrived on the reader side.
    std::vector<CrossThreadEdge> edges;

    /// Channels aggregated by (addr, from_thread, to_thread), sorted by
    /// descending edge_count (busiest channels first).
    std::vector<CrossThreadChannel> channels;

    /// Number of distinct thread pairs with at least one hand-off.
    size_t thread_pair_count = 0;

    /// True when the trace has only one thread (nothing to find).
    bool single_thread = false;

    /// Filter helper: edges whose endpoints are both < before_inst_id.
    std::vector<const CrossThreadEdge*> edges_before(uint64_t before_inst_id) const {
        std::vector<const CrossThreadEdge*> out;
        for (const auto& e : edges)
            if (e.to_inst_id < before_inst_id) out.push_back(&e);
        return out;
    }
};

// ─── Config ────────────────────────────────────────────────────────────────

struct CrossThreadDataflowConfig {
    /// Cap on distinct tracked addresses (memory). Once exceeded, new
    /// addresses are ignored (bounds RAM on huge traces). 0 = no cap.
    uint64_t max_tracked_addrs = 1u << 20;  // 1M

    /// Cap on emitted edges. Scanning stops adding hand-offs once reached.
    uint64_t max_edges = 1u << 20;  // 1M

    /// Minimum access size granularity: accesses are matched byte-exact via
    /// per-address page map; no configuration needed beyond the caps.
};

// ─── CrossThreadDataflowPass ───────────────────────────────────────────────

/// Finds cross-thread data hand-offs through shared memory:
///
///   thread A: STR x0, [addr]        (producer)
///   ... (interleaving / other threads) ...
///   thread B: LDR x1, [addr]        (consumer, value flows A→B)
///
/// A hand-off is recorded when a thread READS a location whose most recent
/// WRITE came from a different thread (and the read is the FIRST read of that
/// written value by the reading thread — repeated reads of the same value are
/// collapsed so loops don't flood the edge list).
///
/// The result edges are also expressed as DataflowEdge (via_mem_addr != 0),
/// so existing dataflow UIs (DFG rendering, producers/consumers) can consume
/// them directly.
///
/// Dependencies: thread
///
/// Result type: CrossThreadDataflowResult
class CrossThreadDataflowPass final : public AnalysisPass {
public:
    explicit CrossThreadDataflowPass(CrossThreadDataflowConfig cfg = {})
        : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "cross_thread_dataflow"; }
    std::string_view description() const override {
        return "Cross-thread data hand-offs through shared memory (memory-mediated channels)";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"thread"};
    }

    void declare_scan(class ScanOrchestrator& orch, PassContext& ctx) override;
    bool has_scan() const override { return true; }
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 6.0f; }

private:
    CrossThreadDataflowConfig cfg_;

    // Collector state (built during the unified scan). Defined inline so the
    // unique_ptr destructor instantiated in other TUs sees a complete type.
    struct Collector final : public TraceCollector {
        // Per-address write state. Addresses are tracked exactly; overlapping
        // accesses (different base addresses covering the same byte) are
        // treated as separate locations — matching MemoryModel's coarse
        // granularity is unnecessary for hand-off detection.
        struct AddrState {
            uint64_t writer_inst = 0;
            uint64_t writer_thread = 0;
            // Generation dedup: threads that already read the current value
            // (repeated reads of the same written value collapse to one edge).
            ankerl::unordered_dense::set<uint64_t> consumed_threads;
        };

        std::string_view name() const override {
            return "cross_thread_dataflow_collector";
        }

        bool begin(uint64_t start, uint64_t end) override {
            (void)start; (void)end;
            return true;
        }

        void on_thread(uint64_t inst_id, const ThreadView& thread) override {
            (void)inst_id;
            cur_thread = thread.thread_id;
        }

        void on_inst(uint64_t inst_id, const InstView& inst) override;

        // Sequential-only collector: on_thread() must be observed in stream
        // order to attribute each inst to its producing thread.
        bool supports_parallel() const override { return false; }

        CrossThreadDataflowConfig cfg;
        CrossThreadDataflowResult result;
        uint64_t cur_thread = 0;

        ankerl::unordered_dense::map<uint64_t, AddrState> addrs;
    };

    std::unique_ptr<Collector> collector_;
};

}  // namespace tenet

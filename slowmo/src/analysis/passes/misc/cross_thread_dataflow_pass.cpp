#include "cross_thread_dataflow_pass.h"

#include "analysis/passes/misc/thread_pass.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <algorithm>
#include <fmt/core.h>
#include <unordered_map>

namespace tenet {

// ─── Collector::on_inst ─────────────────────────────────────────────────────

void CrossThreadDataflowPass::Collector::on_inst(uint64_t inst_id,
                                                  const InstView& inst) {
    // Memory accesses: WALK THEN READ (mem_access(i) is in QBDI order,
    // which lists writes before reads of the same instruction when both
    // exist — a store-then-load instruction sees its own store first,
    // which correctly self-consumes and suppresses a false hand-off).
    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
        auto ma = inst.mem_access(i);
        if (ma.size == 0) continue;
        if (ma.type & 0x2) {  // write
            if (addrs.size() < cfg.max_tracked_addrs || addrs.count(ma.addr)) {
                auto& st = addrs[ma.addr];
                st.writer_inst = inst_id;
                st.writer_thread = cur_thread;
                st.consumed_threads.clear();
                // Self-consume: the writer obviously "knows" the value.
                st.consumed_threads.insert(cur_thread);
            }
        } else if (ma.type & 0x1) {  // read
            auto it = addrs.find(ma.addr);
            if (it == addrs.end()) continue;
            auto& st = it->second;
            if (st.writer_thread != cur_thread &&
                !st.consumed_threads.count(cur_thread) &&
                result.edges.size() < cfg.max_edges) {
                CrossThreadEdge edge;
                edge.from_inst_id = st.writer_inst;
                edge.to_inst_id   = inst_id;
                edge.from_thread  = st.writer_thread;
                edge.to_thread    = cur_thread;
                edge.addr         = ma.addr;
                edge.size         = static_cast<uint8_t>(
                    std::min<uint64_t>(ma.size, 255));
                result.edges.push_back(edge);
                st.consumed_threads.insert(cur_thread);
            }
        }
    }
}

// ─── Pass lifecycle ────────────────────────────────────────────────────────

void CrossThreadDataflowPass::declare_scan(ScanOrchestrator& orch, PassContext& ctx) {
    (void)ctx;
    collector_ = std::make_unique<Collector>();
    collector_->cfg = cfg_;
    orch.declare({name(), collector_.get(), /*wants_parallel=*/false});
}

PassResult CrossThreadDataflowPass::run(PassContext& ctx) {
    if (!collector_) {
        return PassResult::failed("declare_scan() was not called before run()");
    }

    // ── Aggregate channels ───────────────────────────────────────────────
    auto& result = collector_->result;

    if (result.edges.empty()) {
        ctx.progress(1.0f, "CrossThreadDataflow: no cross-thread memory hand-offs");
        return PassResult::success(std::move(result));
    }

    // Order edges by consumer (to_inst_id) — the order data arrived.
    std::sort(result.edges.begin(), result.edges.end(),
              [](const CrossThreadEdge& a, const CrossThreadEdge& b) {
                  return a.to_inst_id < b.to_inst_id;
              });

    // Aggregate by (addr, from_thread, to_thread).
    struct ChannelKey {
        uint64_t addr, from, to;
        bool operator==(const ChannelKey& o) const {
            return addr == o.addr && from == o.from && to == o.to;
        }
    };
    struct ChannelKeyHash {
        size_t operator()(const ChannelKey& k) const {
            // Simple mixing hash — good enough for map keys.
            size_t h = std::hash<uint64_t>{}(k.addr);
            h ^= std::hash<uint64_t>{}(k.from) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            h ^= std::hash<uint64_t>{}(k.to)   + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_map<ChannelKey, size_t, ChannelKeyHash> channel_idx;
    result.channels.reserve(result.edges.size());

    for (size_t i = 0; i < result.edges.size(); i++) {
        const auto& e = result.edges[i];
        ChannelKey key{e.addr, e.from_thread, e.to_thread};
        auto it = channel_idx.find(key);
        if (it == channel_idx.end()) {
            CrossThreadChannel ch;
            ch.addr = e.addr;
            ch.from_thread = e.from_thread;
            ch.to_thread = e.to_thread;
            ch.edge_count = 1;
            ch.edge_indices.push_back(static_cast<uint32_t>(i));
            result.channels.push_back(std::move(ch));
            channel_idx.emplace(key, result.channels.size() - 1);
        } else {
            auto& ch = result.channels[it->second];
            ch.edge_count++;
            ch.edge_indices.push_back(static_cast<uint32_t>(i));
        }
    }

    // Busiest channels first.
    std::sort(result.channels.begin(), result.channels.end(),
              [](const CrossThreadChannel& a, const CrossThreadChannel& b) {
                  if (a.edge_count != b.edge_count) return a.edge_count > b.edge_count;
                  return a.addr < b.addr;
              });

    // Distinct thread pairs.
    ankerl::unordered_dense::set<uint64_t> pairs;
    for (const auto& e : result.edges) {
        uint64_t lo = std::min(e.from_thread, e.to_thread);
        uint64_t hi = std::max(e.from_thread, e.to_thread);
        pairs.insert((hi << 32) ^ (lo & 0xFFFFFFFFULL));
    }
    result.thread_pair_count = pairs.size();

    // ── Persist for future sessions ──────────────────────────────────────
    if (ctx.range().is_full_trace() && result.edges.size() <= (1u << 20)) {
        // Blob is cheap to rebuild and edges depend on nothing but the trace;
        // skip persistence — the pass is a single fast sequential scan.
    }

    ctx.progress(1.0f, fmt::format(
        "CrossThreadDataflow: {} hand-offs, {} channels, {} thread pairs",
        result.edges.size(), result.channels.size(), result.thread_pair_count));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

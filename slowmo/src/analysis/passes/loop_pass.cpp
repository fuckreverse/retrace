#include "analysis/passes/loop_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <unordered_set>

namespace tenet {

// ─── Phase-2 body collector ───────────────────────────────────────────────

/// Second-pass collector that records all unique PCs seen within a loop body range.
/// For each (header_pc, body_inst_start, body_inst_end) tuple, it collects all
/// unique PCs that appear in [body_inst_start, body_inst_end].
class LoopBodyCollector final : public TraceCollector {
public:
    struct BodyRange {
        uint64_t header_pc;
        uint64_t start_inst;
        uint64_t end_inst;
        std::unordered_set<uint64_t> body_pcs;
    };

    std::string_view name() const override { return "loop_body_collector"; }

    explicit LoopBodyCollector(std::vector<BodyRange> ranges)
        : ranges_(std::move(ranges)) {}

    bool begin(uint64_t /*s*/, uint64_t /*e*/) override { return true; }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        for (auto& r : ranges_) {
            if (inst_id >= r.start_inst && inst_id <= r.end_inst) {
                r.body_pcs.insert(inst.pc);
            }
        }
    }

    void end() override {}

    std::vector<BodyRange> ranges_;
};

// ─── LoopPass::run ───────────────────────────────────────────────────────

PassResult LoopPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // ── Phase 1: Single-pass scan to detect backward branches ────────────
    ctx.progress(0.0f, "Loop pass: detecting backward branches...");

    LoopCollector collector;
    TraceScanEngine engine1(reader, index.inst_count());
    engine1.add_collector(&collector);
    engine1.set_progress([&ctx, total = end - start](uint64_t processed, uint64_t) {
        ctx.progress(static_cast<float>(processed) / static_cast<float>(total) * 0.4f);
    });
    engine1.set_cancel_check([&ctx]() { return ctx.cancelled(); });
    engine1.run(start, end);

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    if (collector.back_edges_.empty()) {
        ctx.progress(1.0f, "Loop pass: no loops found");
        return PassResult::success(LoopResult{});
    }

    // ── Phase 2: Collect body PCs for each loop ──────────────────────────
    ctx.progress(0.4f, fmt::format("Loop pass: collecting body PCs for {} loops...",
                                    collector.back_edges_.size()));

    std::vector<LoopBodyCollector::BodyRange> body_ranges;
    body_ranges.reserve(collector.back_edges_.size());
    for (const auto& [header_pc, be] : collector.back_edges_) {
        if (be.body_inst_start == 0 && be.body_inst_end == 0) continue;
        LoopBodyCollector::BodyRange r;
        r.header_pc = header_pc;
        r.start_inst = be.body_inst_start;
        r.end_inst = be.body_inst_end;
        body_ranges.push_back(std::move(r));
    }

    LoopBodyCollector body_collector(std::move(body_ranges));
    TraceScanEngine engine2(reader, index.inst_count());
    engine2.add_collector(&body_collector);
    engine2.set_progress([&ctx, total = end - start](uint64_t processed, uint64_t) {
        ctx.progress(0.4f + static_cast<float>(processed) / static_cast<float>(total) * 0.4f);
    });
    engine2.set_cancel_check([&ctx]() { return ctx.cancelled(); });
    engine2.run(start, end);

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    // ── Phase 3: Build LoopResult ─────────────────────────────────────────
    ctx.progress(0.8f, "Loop pass: computing nesting depths...");

    LoopResult result;
    result.total_back_edges = collector.back_edges_.size();

    // Build a LoopInfo for each detected back-edge
    for (auto& body_range : body_collector.ranges_) {
        uint64_t header_pc = body_range.header_pc;
        auto be_it = collector.back_edges_.find(header_pc);
        if (be_it == collector.back_edges_.end()) continue;
        const auto& be = be_it->second;

        LoopInfo info;
        info.header_pc = header_pc;
        info.back_edge_pc = be.back_edge_pc;
        info.iteration_count = be.iteration_count;
        info.nesting_depth = 0;  // will be computed below

        // Collect sorted body PCs
        info.body_pcs.reserve(body_range.body_pcs.size());
        for (uint64_t pc : body_range.body_pcs) {
            info.body_pcs.push_back(pc);
        }
        std::sort(info.body_pcs.begin(), info.body_pcs.end());

        result.loops.push_back(std::move(info));
    }

    // Sort loops by header_pc for determinism
    std::sort(result.loops.begin(), result.loops.end(),
        [](const LoopInfo& a, const LoopInfo& b) {
            return a.header_pc < b.header_pc;
        });

    // ── Phase 3a: Compute nesting depths ─────────────────────────────────
    // A loop A is nested inside loop B if A.header_pc is in B.body_pcs.
    // We iterate and for each loop, find all loops that contain its header.
    for (size_t i = 0; i < result.loops.size(); i++) {
        uint32_t depth = 0;
        for (size_t j = 0; j < result.loops.size(); j++) {
            if (i == j) continue;
            const auto& outer = result.loops[j];
            // Check if loop[i]'s header is inside outer's body
            if (std::binary_search(outer.body_pcs.begin(), outer.body_pcs.end(),
                                   result.loops[i].header_pc)) {
                depth++;
            }
        }
        result.loops[i].nesting_depth = depth;
        if (depth > result.max_nesting_depth) {
            result.max_nesting_depth = depth;
        }
    }

    // ── Phase 3b: Build per-PC lookup maps ────────────────────────────────
    for (size_t li = 0; li < result.loops.size(); li++) {
        const auto& loop = result.loops[li];

        // Mark loop header
        result.pc_is_loop_header[loop.header_pc] = true;

        // For each body PC: update depth (use max depth seen across all loops)
        for (uint64_t pc : loop.body_pcs) {
            uint32_t current_depth = loop.nesting_depth + 1;  // +1 so "in a loop" = >= 1
            auto it = result.pc_loop_depth.find(pc);
            if (it == result.pc_loop_depth.end() || it->second < current_depth) {
                result.pc_loop_depth[pc] = current_depth;
            }

            // For innermost loop: keep the loop with the highest nesting depth
            auto it2 = result.pc_innermost_loop.find(pc);
            if (it2 == result.pc_innermost_loop.end()) {
                result.pc_innermost_loop[pc] = li;
            } else {
                // Replace if this loop is deeper (more nested)
                if (result.loops[it2->second].nesting_depth < loop.nesting_depth) {
                    result.pc_innermost_loop[pc] = li;
                }
            }
        }
    }

    ctx.progress(1.0f, fmt::format(
        "Loop pass: {} loops detected (max nesting depth={}), {} loop PCs",
        result.loops.size(), result.max_nesting_depth, result.pc_loop_depth.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

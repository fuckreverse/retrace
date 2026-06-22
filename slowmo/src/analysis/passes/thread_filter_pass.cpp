#include "thread_filter_pass.h"

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <algorithm>
#include <fmt/core.h>

namespace tenet {

// ─── Collector ────────────────────────────────────────────────────────────

/// Collector that builds per-thread instruction bitmaps in a single pass.
class ThreadBitmapCollector final : public TraceCollector {
public:
    explicit ThreadBitmapCollector(const std::vector<uint64_t>& filter_tids)
        : filter_tids_(filter_tids) {}

    std::string_view name() const override { return "thread_bitmap_collector"; }

    void on_thread(uint64_t inst_id, const ThreadView& thread) override {
        (void)inst_id;
        current_tid_ = thread.thread_id;
        // Ensure bitmap entry exists
        bitmaps_[current_tid_];  // default-constructs if not present
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        (void)inst;
        if (current_tid_ == 0 && bitmaps_.empty()) {
            // Single-thread trace with no THREAD records — use thread 0 as sentinel
            current_tid_ = kDefaultThread;
        }
        bitmaps_[current_tid_].add(inst_id);
    }

    void end() override {}

    ankerl::unordered_dense::map<uint64_t, roaring::Roaring64Map>& bitmaps() {
        return bitmaps_;
    }

    static constexpr uint64_t kDefaultThread = 0;

private:
    const std::vector<uint64_t>& filter_tids_;
    uint64_t current_tid_ = 0;
    ankerl::unordered_dense::map<uint64_t, roaring::Roaring64Map> bitmaps_;
};

// ─── ThreadFilterPass::run ────────────────────────────────────────────────

PassResult ThreadFilterPass::run(PassContext& ctx) {
    // Require ThreadPass first (to enumerate all thread IDs)
    const auto& thread_raw = ctx.require_raw("thread");
    if (!thread_raw.ok()) {
        return PassResult::failed(
            std::string("ThreadFilterPass: thread pass failed: ") + thread_raw.error_message);
    }
    const auto& thread_result = thread_raw.get<ThreadResult>();

    ThreadFilterResult result;
    result.thread_count = thread_result.thread_count();

    if (!cfg_.build_bitmaps) {
        // Light mode: just record thread count and return
        result.is_filtered = !cfg_.include_thread_ids.empty();
        return PassResult::success(std::move(result));
    }

    // ── Single-thread short circuit ─────────────────────────────────────
    // tenet currently assumes single-thread traces (THREAD records are
    // ignored).  When the trace has only one thread and no explicit filter
    // is requested, the "included" set is trivially all instructions.
    // We still build the bitmap so that contains()/cardinality() work for
    // downstream consumers, but we skip the per-thread classification scan.
    if (thread_result.thread_count() <= 1 && cfg_.include_thread_ids.empty()) {
        result.is_filtered = false;
        // Populate included_inst_ids with all inst_ids in range.
        auto& index = ctx.index();
        uint64_t start = ctx.range().start_inst_id;
        uint64_t end = std::min(ctx.range().end_inst_id, index.inst_count());
        if (end == 0) end = index.inst_count();
        if (end > start) {
            result.included_inst_ids.addRange(start, end);
        }
        ctx.progress(1.0f, fmt::format(
            "thread_filter: single-thread, {} inst_ids included",
            result.included_inst_ids.cardinality()));
        return PassResult::success(std::move(result));
    }

    // Build per-thread bitmaps via a single trace scan
    ThreadBitmapCollector collector(cfg_.include_thread_ids);

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run(ctx.range().start_inst_id, ctx.range().end_inst_id);
    } else {
        auto& reader = ctx.reader();
        auto& index  = ctx.index();
        TraceScanEngine own_engine(reader, index.inst_count(), &index);
        own_engine.set_progress([&ctx, total = index.inst_count()](
                uint64_t done, uint64_t /*total_arg*/) {
            if (total > 0) ctx.progress(float(done) / float(total));
        });
        own_engine.set_cancel_check([&ctx] { return ctx.cancelled(); });
        own_engine.add_collector(&collector);
        own_engine.run(ctx.range().start_inst_id, ctx.range().end_inst_id);
    }

    // Move bitmaps into result
    result.thread_inst_bitmaps = std::move(collector.bitmaps());

    // Build the "included" bitmap (union of filtered threads)
    const bool has_filter = !cfg_.include_thread_ids.empty();
    result.is_filtered = has_filter;

    if (has_filter) {
        for (uint64_t tid : cfg_.include_thread_ids) {
            auto it = result.thread_inst_bitmaps.find(tid);
            if (it != result.thread_inst_bitmaps.end()) {
                result.included_inst_ids |= it->second;
            }
        }
    } else {
        // No filter: included = all instructions
        for (const auto& [tid, bm] : result.thread_inst_bitmaps) {
            result.included_inst_ids |= bm;
        }
    }

    ctx.progress(1.0f, fmt::format(
        "ThreadFilter: {} threads, {} filtered inst_ids",
        result.thread_count,
        result.included_inst_ids.cardinality()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

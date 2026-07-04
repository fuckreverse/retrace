#include "thread_filter_pass.h"

#include "analysis/pass_manager.h"
#include "io/index_builder.h"

#include <fmt/core.h>

namespace tenet {

// ─── ThreadFilterPass::run ────────────────────────────────────────────────

PassResult ThreadFilterPass::run(PassContext& ctx) {
    // Require ThreadPass first (to enumerate all thread IDs and spans)
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

    // ── Build per-thread bitmaps directly from ThreadResult spans ────────
    // This is O(num_spans) instead of O(num_instructions), since Roaring64Map's
    // addRange() is O(1) per contiguous range.  For typical traces with a few
    // hundred to a few thousand spans, this completes in microseconds and uses
    // minimal memory (range-encoded bitmaps compress perfectly).
    for (const auto& span : thread_result.spans) {
        // addRange is [start, end) — half-open interval
        result.thread_inst_bitmaps[span.thread_id].addRange(
            span.start_inst_id, span.end_inst_id + 1);
    }

    // Run-optimize all bitmaps for better compression
    for (auto& [tid, bm] : result.thread_inst_bitmaps) {
        bm.runOptimize();
    }

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
        "ThreadFilter: {} threads, {} filtered inst_ids (from spans, no trace scan)",
        result.thread_count,
        result.included_inst_ids.cardinality()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

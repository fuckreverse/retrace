#include "analysis/passes/thread_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <algorithm>
#include <fmt/core.h>

namespace tenet {

// ─── ThreadCollector implementation ──────────────────────────────────────────

void ThreadCollector::on_thread(uint64_t inst_id, const ThreadView& thread) {
    uint64_t new_tid = thread.thread_id;

    // If we had a previous span, close it
    if (has_initial_thread_ && current_thread_id_ != new_tid) {
        // Close previous span
        if (span_inst_count_ > 0) {
            ThreadSpan span;
            span.thread_id = current_thread_id_;
            span.start_inst_id = span_start_;
            span.end_inst_id = inst_id > 0 ? inst_id - 1 : 0;
            span.inst_count = span_inst_count_;
            result.spans.push_back(span);
        }

        // Record switch event
        ThreadSwitchEvent ev;
        ev.inst_id = inst_id;
        ev.thread_id = new_tid;
        result.switch_events.push_back(ev);

        // Update thread switch-in count
        result.threads[new_tid].switch_in_count++;

        // Start new span
        span_start_ = inst_id;
        span_inst_count_ = 0;
    } else if (!has_initial_thread_) {
        // First thread record ever
        span_start_ = inst_id;
        span_inst_count_ = 0;
        has_initial_thread_ = true;
    }

    current_thread_id_ = new_tid;

    // Ensure thread is registered
    auto& info = result.threads[new_tid];
    if (info.thread_id == 0) {
        info.thread_id = new_tid;
        info.first_seen_inst = inst_id;
        info.last_seen_inst = inst_id;
        info.total_instructions = 0;
        info.switch_in_count = 1;  // First activation counts as a switch-in
    }
}

void ThreadCollector::on_inst(uint64_t inst_id, const InstView& inst) {
    (void)inst;

    if (!has_initial_thread_) return;

    span_inst_count_++;

    // Update per-thread stats
    auto it = result.threads.find(current_thread_id_);
    if (it != result.threads.end()) {
        it->second.total_instructions++;
        it->second.last_seen_inst = inst_id;
    }
}

void ThreadCollector::end() {
    // Close the final span
    if (has_initial_thread_ && span_inst_count_ > 0) {
        auto it = result.threads.find(current_thread_id_);
        uint64_t last_inst = (it != result.threads.end()) ? it->second.last_seen_inst : 0;

        ThreadSpan span;
        span.thread_id = current_thread_id_;
        span.start_inst_id = span_start_;
        span.end_inst_id = last_inst;
        span.inst_count = span_inst_count_;
        result.spans.push_back(span);
    }
}

// ─── ThreadResult query methods ──────────────────────────────────────────────

uint64_t ThreadResult::thread_at(uint64_t inst_id) const {
    // Binary search in switch_events to find the last switch before inst_id
    if (switch_events.empty()) {
        // If no switches, there's at most one thread
        if (threads.size() == 1) {
            return threads.begin()->first;
        }
        // Check spans
        if (!spans.empty()) {
            return spans.front().thread_id;
        }
        return 0;
    }

    // Find the last switch event with inst_id <= target
    auto it = std::upper_bound(switch_events.begin(), switch_events.end(), inst_id,
        [](uint64_t id, const ThreadSwitchEvent& ev) { return id < ev.inst_id; });

    if (it == switch_events.begin()) {
        // Before any switch — use the first span's thread
        if (!spans.empty()) {
            return spans.front().thread_id;
        }
        return 0;
    }

    --it;
    return it->thread_id;
}

std::vector<const ThreadSpan*> ThreadResult::spans_for(uint64_t thread_id) const {
    std::vector<const ThreadSpan*> result;
    for (const auto& span : spans) {
        if (span.thread_id == thread_id) {
            result.push_back(&span);
        }
    }
    return result;
}

const ThreadSpan* ThreadResult::span_at(uint64_t inst_id) const {
    // Binary search — spans are sorted by start_inst_id
    auto it = std::upper_bound(spans.begin(), spans.end(), inst_id,
        [](uint64_t id, const ThreadSpan& s) { return id < s.start_inst_id; });

    if (it == spans.begin()) return nullptr;
    --it;

    if (inst_id >= it->start_inst_id && inst_id <= it->end_inst_id) {
        return &(*it);
    }
    return nullptr;
}

const ThreadSwitchEvent* ThreadResult::next_switch_after(uint64_t inst_id) const {
    auto it = std::upper_bound(switch_events.begin(), switch_events.end(), inst_id,
        [](uint64_t id, const ThreadSwitchEvent& ev) { return id < ev.inst_id; });
    if (it == switch_events.end()) return nullptr;
    return &(*it);
}

const ThreadSwitchEvent* ThreadResult::prev_switch_before(uint64_t inst_id) const {
    auto it = std::lower_bound(switch_events.begin(), switch_events.end(), inst_id,
        [](const ThreadSwitchEvent& ev, uint64_t id) { return ev.inst_id < id; });
    if (it == switch_events.begin()) return nullptr;
    --it;
    return &(*it);
}

// ─── ThreadPass::run ─────────────────────────────────────────────────────────

PassResult ThreadPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    ThreadCollector collector;
    TraceScanEngine engine(reader, index.inst_count());
    engine.add_collector(&collector);
    engine.set_progress([&ctx, total = end - start](uint64_t processed, uint64_t /*total_arg*/) {
        if (total > 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }
    });
    engine.set_cancel_check([&ctx]() { return ctx.cancelled(); });
    engine.run(start, end);

    ctx.progress(1.0f, fmt::format("Thread: {} threads, {} switches, {} spans",
                                    collector.result.thread_count(),
                                    collector.result.switch_count(),
                                    collector.result.spans.size()));
    return PassResult::success(std::move(collector.result));
}

}  // namespace tenet

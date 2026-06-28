#include "analysis/passes/thread_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <cstring>
#include <algorithm>
#include <fmt/core.h>

namespace tenet {

// ─── Blob persistence helpers ─────────────────────────────────────────────

static constexpr uint32_t THREAD_BLOB_MAGIC   = 0x54485244u;  // "THRD"
static constexpr uint32_t THREAD_BLOB_VERSION = 1u;

/// Serialize ThreadResult into a compact binary blob.
/// Format: [magic:u32][version:u32]
///   [num_switches:u64]
///     per switch: [inst_id:u64][thread_id:u64]
///   [num_threads:u64]
///     per thread: [thread_id:u64][name_len:u32][name]
///                 [first_seen_inst:u64][last_seen_inst:u64]
///                 [total_instructions:u64][switch_in_count:u64]
///   [num_spans:u64]
///     per span: [thread_id:u64][start_inst_id:u64][end_inst_id:u64][inst_count:u64]
static std::string thread_serialize(const ThreadResult& res) {
    // Estimate buffer size
    size_t est = 4 + 4
               + 8 + res.switch_events.size() * 16
               + 8;
    for (const auto& [tid, info] : res.threads) {
        est += 8 + 4 + info.name.size() + 24;
    }
    est += 8 + res.spans.size() * 32;

    std::string buf;
    buf.reserve(est);

    auto write = [&](const void* data, size_t n) {
        buf.append(reinterpret_cast<const char*>(data), n);
    };
    auto write_u32 = [&](uint32_t v) { write(&v, 4); };
    auto write_u64 = [&](uint64_t v) { write(&v, 8); };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        if (!s.empty()) write(s.data(), s.size());
    };

    write_u32(THREAD_BLOB_MAGIC);
    write_u32(THREAD_BLOB_VERSION);

    // Switch events
    write_u64(static_cast<uint64_t>(res.switch_events.size()));
    for (const auto& ev : res.switch_events) {
        write_u64(ev.inst_id);
        write_u64(ev.thread_id);
    }

    // Threads
    write_u64(static_cast<uint64_t>(res.threads.size()));
    for (const auto& [tid, info] : res.threads) {
        write_u64(info.thread_id);
        write_str(info.name);
        write_u64(info.first_seen_inst);
        write_u64(info.last_seen_inst);
        write_u64(info.total_instructions);
        write_u64(info.switch_in_count);
    }

    // Spans
    write_u64(static_cast<uint64_t>(res.spans.size()));
    for (const auto& span : res.spans) {
        write_u64(span.thread_id);
        write_u64(span.start_inst_id);
        write_u64(span.end_inst_id);
        write_u64(span.inst_count);
    }

    return buf;
}

/// Deserialize ThreadResult from a binary blob. Returns false on corruption.
static bool thread_deserialize(const std::string& blob, ThreadResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto remaining = [&]() -> size_t { return static_cast<size_t>(end - p); };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (remaining() < 4) return false;
        uint32_t len = read_u32();
        if (remaining() < len) return false;
        s.assign(p, len);
        p += len;
        return true;
    };

    uint32_t magic = read_u32();
    uint32_t version = read_u32();
    if (magic != THREAD_BLOB_MAGIC || version != THREAD_BLOB_VERSION) return false;

    // Switch events
    if (remaining() < 8) return false;
    uint64_t num_switches = read_u64();
    if (remaining() < num_switches * 16) return false;
    out.switch_events.resize(static_cast<size_t>(num_switches));
    for (size_t i = 0; i < num_switches; i++) {
        out.switch_events[i].inst_id   = read_u64();
        out.switch_events[i].thread_id = read_u64();
    }

    // Threads
    if (remaining() < 8) return false;
    uint64_t num_threads = read_u64();
    for (size_t i = 0; i < num_threads; i++) {
        if (remaining() < 8) return false;
        uint64_t tid = read_u64();
        auto& info = out.threads[tid];
        info.thread_id = tid;
        if (!read_str(info.name)) return false;
        if (remaining() < 24) return false;
        info.first_seen_inst    = read_u64();
        info.last_seen_inst     = read_u64();
        info.total_instructions = read_u64();
        if (remaining() < 8) return false;
        info.switch_in_count    = read_u64();
    }

    // Spans
    if (remaining() < 8) return false;
    uint64_t num_spans = read_u64();
    if (remaining() < num_spans * 32) return false;
    out.spans.resize(static_cast<size_t>(num_spans));
    for (size_t i = 0; i < num_spans; i++) {
        out.spans[i].thread_id     = read_u64();
        out.spans[i].start_inst_id = read_u64();
        out.spans[i].end_inst_id   = read_u64();
        out.spans[i].inst_count    = read_u64();
    }

    return true;
}

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

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("thread", blob)) {
            ThreadResult cached;
            if (thread_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Thread: {} threads, {} switches, {} spans (from cache)",
                    cached.thread_count(), cached.switch_count(), cached.spans.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

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

    // ─── Persist result for future sessions ───────────────────────────────
    if (range.is_full_trace()) {
        std::string blob = thread_serialize(collector.result);
        if (!blob.empty()) {
            index.save_pass_blob("thread", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("Thread: {} threads, {} switches, {} spans",
                                    collector.result.thread_count(),
                                    collector.result.switch_count(),
                                    collector.result.spans.size()));
    return PassResult::success(std::move(collector.result));
}

}  // namespace tenet

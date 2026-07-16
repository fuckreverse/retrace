#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Thread analysis result ───────────────────────────────────────────────

/// Represents a single thread switch event in the trace.
struct ThreadSwitchEvent {
    uint64_t inst_id;        // inst_id at which the switch occurs (next inst runs on new thread)
    uint64_t thread_id;      // thread ID that becomes active
};

/// Information about a single thread observed in the trace.
struct ThreadInfo {
    uint64_t thread_id;
    std::string name;             // Optional thread name (if known)
    uint64_t first_seen_inst;     // First inst_id where this thread ran
    uint64_t last_seen_inst;      // Last inst_id where this thread was active
    uint64_t total_instructions;  // Total number of instructions executed on this thread
    uint64_t switch_in_count;     // How many times execution switched TO this thread
};

/// A contiguous span of instructions executing on the same thread.
struct ThreadSpan {
    uint64_t thread_id;
    uint64_t start_inst_id;   // First inst_id of this span
    uint64_t end_inst_id;     // Last inst_id (inclusive) of this span
    uint64_t inst_count;      // Number of instructions in this span
};

/// Result of thread analysis pass.
struct ThreadResult {
    /// All thread switch events in temporal order.
    std::vector<ThreadSwitchEvent> switch_events;

    /// All observed threads.
    ankerl::unordered_dense::map<uint64_t, ThreadInfo> threads;

    /// Contiguous execution spans per thread (sorted by start_inst_id).
    std::vector<ThreadSpan> spans;

    /// Total number of unique threads observed.
    size_t thread_count() const { return threads.size(); }

    /// Total number of context switches.
    size_t switch_count() const { return switch_events.size(); }

    /// Which thread is active at a given inst_id?
    /// Returns thread_id, or 0 if unknown (before first thread record).
    uint64_t thread_at(uint64_t inst_id) const;

    /// Get all spans for a given thread_id.
    std::vector<const ThreadSpan*> spans_for(uint64_t thread_id) const;

    /// Get the span containing a given inst_id.
    const ThreadSpan* span_at(uint64_t inst_id) const;

    /// Get the next thread switch after inst_id (or nullptr if none).
    const ThreadSwitchEvent* next_switch_after(uint64_t inst_id) const;

    /// Get the previous thread switch before inst_id (or nullptr if none).
    const ThreadSwitchEvent* prev_switch_before(uint64_t inst_id) const;
};

// ─── Thread collector ─────────────────────────────────────────────────────

/// Collector that tracks thread switch records during a sequential scan.
class ThreadCollector final : public TraceCollector {
public:
    std::string_view name() const override { return "thread_collector"; }

    bool begin(uint64_t start, uint64_t end) override {
        (void)start; (void)end;
        return true;
    }

    void on_thread(uint64_t inst_id, const ThreadView& thread) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void end() override;

    ThreadResult result;

private:
    uint64_t current_thread_id_ = 0;
    uint64_t span_start_ = 0;
    uint64_t span_inst_count_ = 0;
    bool has_initial_thread_ = false;
};

// ─── Thread analysis pass ─────────────────────────────────────────────────

/// Identifies thread context switches and builds per-thread execution timeline.
/// Result type: ThreadResult
class ThreadPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "thread"; }
    std::string_view description() const override {
        return "Thread-aware analysis: context switches, per-thread timelines, and execution spans";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // Standalone — no dependencies
    }

    bool has_scan() const override { return true; }
    std::optional<PassResult> try_load_cached(PassContext& ctx) override;
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    std::unique_ptr<ThreadCollector> collector_;
};

}  // namespace tenet

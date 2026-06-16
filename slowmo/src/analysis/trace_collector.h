#pragma once

#include "io/trace_reader.h"
#include <vector>
#include <string_view>
#include <functional>
#include <cstdint>

namespace tenet {

/// Lightweight callback interface for observing trace records during a single sequential scan.
/// Multiple collectors can run simultaneously on one traversal.
class TraceCollector {
public:
    virtual ~TraceCollector() = default;

    /// Called once before the scan starts. Return false to skip this collector.
    virtual bool begin(uint64_t start_inst_id, uint64_t end_inst_id) {
        (void)start_inst_id; (void)end_inst_id;
        return true;
    }

    /// Called for every Inst record in the range.
    virtual void on_inst(uint64_t inst_id, const InstView& inst) {
        (void)inst_id; (void)inst;
    }

    /// Called for Code records encountered during the scan.
    virtual void on_code(const CodeView& code) { (void)code; }

    /// Called for Svc records.
    virtual void on_svc(uint64_t inst_id, const SvcView& svc) { (void)inst_id; (void)svc; }

    /// Called for Event records.
    virtual void on_event(const EventView& ev) { (void)ev; }

    /// Called once after the scan completes.
    virtual void end() {}

    /// Name of this collector (for debugging).
    virtual std::string_view name() const = 0;
};

/// Engine that performs a single sequential scan and broadcasts to all registered collectors.
class TraceScanEngine {
public:
    TraceScanEngine(const TraceReader& reader, uint64_t inst_count)
        : reader_(reader), inst_count_(inst_count) {}

    /// Register a collector. Must be called before run().
    void add_collector(TraceCollector* collector) {
        collectors_.push_back(collector);
    }

    /// Perform the single-pass scan over [start, end) inst_id range.
    /// Broadcasts records to all active collectors.
    /// Returns the number of instructions processed.
    uint64_t run(uint64_t start_inst_id = 0, uint64_t end_inst_id = UINT64_MAX);

    /// Set a progress callback: (processed_count, total_count)
    using ProgressFn = std::function<void(uint64_t, uint64_t)>;
    void set_progress(ProgressFn fn) { progress_fn_ = std::move(fn); }

    /// Set cancellation check function.
    void set_cancel_check(std::function<bool()> fn) { cancel_fn_ = std::move(fn); }

private:
    const TraceReader& reader_;
    uint64_t inst_count_;
    std::vector<TraceCollector*> collectors_;
    ProgressFn progress_fn_;
    std::function<bool()> cancel_fn_;
};

}  // namespace tenet

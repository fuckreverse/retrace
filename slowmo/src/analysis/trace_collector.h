#pragma once

#include "io/trace_reader.h"
#include <vector>
#include <string_view>
#include <functional>
#include <cstdint>
#include <memory>
#include <utility>

namespace tenet {

class TraceIndex;  // forward declaration

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

    /// Called for Anchor records (full register snapshot).
    /// inst_id is the instruction count at the point of the anchor.
    virtual void on_anchor(uint64_t inst_id, const AnchorView& anchor) {
        (void)inst_id; (void)anchor;
    }

    /// Called for Code records encountered during the scan.
    virtual void on_code(const CodeView& code) { (void)code; }

    /// Called for Svc records.
    virtual void on_svc(uint64_t inst_id, const SvcView& svc) { (void)inst_id; (void)svc; }

    /// Called for Objc records (Objective-C message sends).
    /// inst_id is the current instruction counter at the point of the record.
    virtual void on_objc(uint64_t inst_id, const ObjcView& objc) {
        (void)inst_id; (void)objc;
    }

    /// Called for Thread records (thread context switch).
    virtual void on_thread(uint64_t inst_id, const ThreadView& thread) {
        (void)inst_id; (void)thread;
    }

    /// Called for Event records.
    virtual void on_event(const EventView& ev) { (void)ev; }

    /// Called once after the scan completes.
    virtual void end() {}

    /// Name of this collector (for debugging).
    virtual std::string_view name() const = 0;

    /// Whether this collector supports parallel scanning (must be thread-safe).
    /// If true, the scan engine may call on_inst() from multiple threads
    /// on independent shard clones. Non-INST records (Code, Event, Svc, Thread)
    /// are NOT delivered during parallel scanning.
    virtual bool supports_parallel() const { return false; }

    /// Create a clone of this collector for parallel scanning.
    /// Each shard gets its own clone; after scanning, merge() combines results.
    /// Returns nullptr if parallel scanning is not supported.
    virtual std::unique_ptr<TraceCollector> clone() const { return nullptr; }

    /// Merge results from a parallel shard collector into this one.
    /// Called after all shards finish. `shard` is a clone produced by clone().
    /// Only called when supports_parallel() returns true.
    virtual void merge(TraceCollector& shard) { (void)shard; }
};

/// Engine that performs a single sequential scan and broadcasts to all registered collectors.
class TraceScanEngine {
public:
    TraceScanEngine(const TraceReader& reader, uint64_t inst_count,
                    const TraceIndex* index = nullptr)
        : reader_(reader), inst_count_(inst_count), index_(index) {}

    /// Register a collector. Must be called before run().
    void add_collector(TraceCollector* collector) {
        collectors_.push_back(collector);
    }

    /// Perform the single-pass scan over [start, end) inst_id range.
    /// Broadcasts records to all active collectors.
    /// Returns the number of instructions processed.
    uint64_t run(uint64_t start_inst_id = 0, uint64_t end_inst_id = UINT64_MAX);

    /// Perform a parallel multi-threaded scan.
    ///
    /// Collectors that return supports_parallel()==true and provide a valid clone()
    /// are scanned in parallel using raw pointer parsing (modeled after XrefPass).
    /// Each shard receives only on_inst() callbacks; non-INST records are not
    /// delivered during the parallel phase.
    ///
    /// Collectors that do NOT support parallel scanning are run sequentially
    /// in a separate pass (the normal run() path) so correctness is preserved.
    ///
    /// After all shards complete, merge() is called on each original collector
    /// with each of its shard clones.
    ///
    /// `num_threads` == 0 means auto-detect from hardware_concurrency().
    /// Falls back to sequential run() when the trace is small (<50K insts),
    /// no index is available, or no collectors support parallel scanning.
    ///
    /// Returns the number of instructions processed.
    uint64_t run_parallel(uint64_t start_inst_id = 0, uint64_t end_inst_id = UINT64_MAX,
                          unsigned num_threads = 0);

    /// Set a progress callback: (processed_count, total_count)
    using ProgressFn = std::function<void(uint64_t, uint64_t)>;
    void set_progress(ProgressFn fn) { progress_fn_ = std::move(fn); }

    /// Set cancellation check function.
    void set_cancel_check(std::function<bool()> fn) { cancel_fn_ = std::move(fn); }

    /// Set a lightweight atomic cancellation token for parallel scanning.
    /// When set, parallel shard threads check this flag periodically.
    void set_cancel_token(const std::atomic<bool>* token) { cancel_token_ = token; }

    /// Set PC address ranges to exclude from delivery to collectors.
    /// Instructions whose PC falls in any [start, end) range are silently skipped.
    /// This does NOT affect the trace file or indexing — only analysis visibility.
    void set_exclude_pc_ranges(std::vector<std::pair<uint64_t, uint64_t>> ranges) {
        exclude_pc_ranges_ = std::move(ranges);
    }

private:
    /// Check if a PC is in any excluded range. Inline for hot-path performance.
    bool is_pc_excluded(uint64_t pc) const {
        for (const auto& [start, end] : exclude_pc_ranges_) {
            if (pc >= start && pc < end) return true;
        }
        return false;
    }


    const TraceReader& reader_;
    uint64_t inst_count_;
    const TraceIndex* index_ = nullptr;
    std::vector<TraceCollector*> collectors_;
    std::vector<std::pair<uint64_t, uint64_t>> exclude_pc_ranges_;
    ProgressFn progress_fn_;
    std::function<bool()> cancel_fn_;
    const std::atomic<bool>* cancel_token_ = nullptr;
};

}  // namespace tenet

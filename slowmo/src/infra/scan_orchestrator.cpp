#include "infra/scan_orchestrator.h"
#include "analysis/trace_collector.h"
#include "analysis/pass_manager.h"  // for AnalysisRange

namespace tenet {

ScanOrchestrator::ScanOrchestrator(const TraceReader& reader, uint64_t inst_count,
                                     const TraceIndex* index)
    : reader_(reader), inst_count_(inst_count), index_(index) {}

void ScanOrchestrator::declare(ScanDeclaration decl) {
    declarations_.push_back(std::move(decl));
}

uint64_t ScanOrchestrator::execute_scan(const AnalysisRange& range,
                                          const std::atomic<bool>& cancel_token,
                                          bool no_parallel) {
    if (declarations_.empty()) return 0;
    if (scanned_) return 0;  // already scanned

    // Create the shared scan engine
    TraceScanEngine engine(reader_, inst_count_, index_);

    // Apply exclude PC ranges from AnalysisRange
    if (!range.exclude_pc_ranges.empty()) {
        engine.set_exclude_pc_ranges(range.exclude_pc_ranges);
    }

    // Apply thread include filter from AnalysisRange (multi-thread traces)
    if (!range.include_thread_ids.empty()) {
        engine.set_include_thread_ids(range.include_thread_ids);
    }

    // Set cancellation
    engine.set_cancel_token(&cancel_token);
    engine.set_cancel_check([&cancel_token]() {
        return cancel_token.load(std::memory_order_acquire);
    });

    // Register all declared collectors
    for (const auto& decl : declarations_) {
        engine.add_collector(decl.collector);
    }

    // Always use run_parallel(), which internally separates collectors into
    // parallel-capable (supports_parallel() + clone()) and sequential groups.
    // The parallel group is scanned concurrently across shards; the sequential
    // group is scanned in a single follow-up pass. This avoids the previous
    // all-or-nothing gate that forced the ENTIRE scan to sequential whenever
    // a single collector declared wants_parallel=false.
    //
    // Fallback to run() happens inside run_parallel() itself when:
    //   - no collectors support parallel scanning
    //   - the trace is too small (<50K insts)
    //   - the index is unavailable
    //   - v5/v7 format requires sequential PC reconstruction
    uint64_t processed;
    if (no_parallel) {
        processed = engine.run(range.start_inst_id, range.end_inst_id);
    } else {
        processed = engine.run_parallel(range.start_inst_id, range.end_inst_id);
    }

    scanned_ = true;
    return processed;
}

TraceCollector* ScanOrchestrator::collector_for(std::string_view pass_name) const {
    for (const auto& d : declarations_) {
        if (d.pass_name == pass_name) return d.collector;
    }
    return nullptr;
}

void ScanOrchestrator::reset() {
    declarations_.clear();
    scanned_ = false;
}

}  // namespace tenet

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

    // Set cancellation
    engine.set_cancel_token(&cancel_token);
    engine.set_cancel_check([&cancel_token]() {
        return cancel_token.load(std::memory_order_acquire);
    });

    // Register all declared collectors
    for (const auto& decl : declarations_) {
        engine.add_collector(decl.collector);
    }

    // Determine if all collectors support parallel scanning
    bool all_parallel = !no_parallel;
    if (all_parallel) {
        for (const auto& decl : declarations_) {
            if (!decl.wants_parallel) {
                all_parallel = false;
                break;
            }
        }
    }

    uint64_t processed = 0;
    if (all_parallel) {
        processed = engine.run_parallel(range.start_inst_id, range.end_inst_id);
    } else {
        processed = engine.run(range.start_inst_id, range.end_inst_id);
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

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
    (void)range;
    (void)cancel_token;
    (void)no_parallel;
    // Stub — real implementation in Task 3
    scanned_ = true;
    return 0;
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

#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include <atomic>
#include <string_view>
#include <vector>

namespace tenet {

class TraceIndex;
class TraceCollector;
struct AnalysisRange;

/// Declarative collector requirement — a pass declares what scan data it needs.
struct ScanDeclaration {
    std::string_view pass_name;     ///< declaring pass name
    TraceCollector*  collector;      ///< collector instance (pass owns it)
    bool             wants_parallel; ///< supports parallel scanning
};

/// Unified Scan Fusion orchestrator — one trace scan serves all declared collectors.
///
/// Lifecycle:
///   1. PassManager::run_all() calls each pass's declare_scan() to register collectors
///   2. PassManager calls execute_scan() — single traversal serves all collectors
///   3. Passes read results from their collectors in run()
class ScanOrchestrator {
public:
    explicit ScanOrchestrator(const TraceReader& reader, uint64_t inst_count,
                               const TraceIndex* index = nullptr);

    /// Declare a collector requirement (pass calls during declare_scan phase)
    void declare(ScanDeclaration decl);

    /// Execute unified scan — adds all declared collectors to one TraceScanEngine,
    /// then single run()/run_parallel() serves all.
    /// Returns instructions processed.
    uint64_t execute_scan(const AnalysisRange& range,
                          const std::atomic<bool>& cancel_token,
                          bool no_parallel = false);

    /// Get collector for a pass name (pass reads results after scan)
    TraceCollector* collector_for(std::string_view pass_name) const;

    bool has_declarations() const { return !declarations_.empty(); }

    /// Clear all declarations (call after run_all completes, before next analysis)
    void reset();

private:
    const TraceReader& reader_;
    uint64_t inst_count_;
    const TraceIndex* index_;

    std::vector<ScanDeclaration> declarations_;
    bool scanned_ = false;
};

}  // namespace tenet

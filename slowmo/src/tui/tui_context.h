#pragma once

#include "common/types.h"
#include "common/instruction_row.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

// Forward declarations
class TraceReader;
class TraceIndex;
class CodeTable;
class InstructionDecoder;
class RegisterFile;
class MemoryModel;
class PassManager;
class TenetService;
struct TaintResult;
struct BackwardTaintResult;
struct FunctionResult;
struct XrefResult;
struct StringResult;
struct CallGraphResult;
struct LoopResult;
struct ThreadResult;

// ─── Additional pass result types (Results panel) ──────────────────────────
// These mirror the GUI's xxx_result_ pointers (see gui_app.h) so every
// catalog pass has somewhere to publish its result for TUI consumption.
struct CFGResult;
struct PatternResult;
struct LoopSemanticsResult;
struct AlgorithmSummaryResult;
struct ObjcResult;
struct ObjcCryptoResult;
struct MemoryStringResult;
struct EntropyResult;
struct SyscallInterceptResult;
struct TraceFoldResult;
struct VMAbstractResult;
struct MemSearchResult;
struct MemorySnapshotResult;
struct YaraMemScanResult;
struct CallContextResult;
struct WindowStatsResult;
struct DataflowGraphResult;
struct RegTimelineResult;
struct TraceDiffResult;
struct TaintSourceAnnotationResult;
struct ThreadFilterResult;
struct CFGLayoutResult;

/// Shared context that all TUI panels can read from and write to.
/// Owned by TuiApp; panels hold a reference to it.
///
/// Design:  Public data members for simplicity (panels are trusted internal
///          code, not a plugin boundary). This avoids getter/setter bloat
///          for ~40 fields that panels need to access.
struct TuiContext {
    // ─── Data layer references ────────────────────────────────────────
    TraceReader*        reader = nullptr;
    TraceIndex*         index = nullptr;
    CodeTable*          code_table = nullptr;
    InstructionDecoder* decoder = nullptr;
    RegisterFile*       regfile = nullptr;
    MemoryModel*        memory = nullptr;

    /// If non-null, the shared application service. Panels can use this for
    /// navigation and data access instead of raw backend pointers.
    TenetService* service = nullptr;

    // ─── Navigation state (read/write by panels) ──────────────────────
    uint64_t total_inst = 0;
    uint64_t current_inst = 0;
    uint64_t viewport_top = 0;
    int      viewport_height = 20;

    // ─── Analysis results (written by TuiApp pass wiring, read by panels) ─
    const TaintResult*         taint_result = nullptr;
    const BackwardTaintResult* backward_taint_result = nullptr;
    const FunctionResult*      function_result = nullptr;
    const XrefResult*          xref_result = nullptr;
    const StringResult*        string_result = nullptr;
    const CallGraphResult*     call_graph_result = nullptr;
    const LoopResult*          loop_result = nullptr;
    const ThreadResult*        thread_result = nullptr;

    // ─── Extended analysis results (Results panel) ─────────────────────
    const CFGResult*                     cfg_result = nullptr;
    const CFGLayoutResult*               cfg_layout_result = nullptr;
    const PatternResult*                 pattern_result = nullptr;
    const LoopSemanticsResult*           loop_semantics_result = nullptr;
    const AlgorithmSummaryResult*        algorithm_summary_result = nullptr;
    const ObjcResult*                    objc_result = nullptr;
    const ObjcCryptoResult*              objc_crypto_result = nullptr;
    const MemoryStringResult*            memory_string_result = nullptr;
    const EntropyResult*                 entropy_result = nullptr;
    const SyscallInterceptResult*        syscall_intercept_result = nullptr;
    const TraceFoldResult*               trace_fold_result = nullptr;
    const VMAbstractResult*              vm_abstract_result = nullptr;
    const MemSearchResult*               mem_search_result = nullptr;
    const MemorySnapshotResult*          memory_snapshot_result = nullptr;
    const YaraMemScanResult*             yara_mem_scan_result = nullptr;
    const CallContextResult*             call_context_result = nullptr;
    const WindowStatsResult*             window_stats_result = nullptr;
    const DataflowGraphResult*           dataflow_graph_result = nullptr;
    const RegTimelineResult*             reg_timeline_result = nullptr;
    const TraceDiffResult*               trace_diff_result = nullptr;
    const TaintSourceAnnotationResult*   taint_source_annotation_result = nullptr;
    const ThreadFilterResult*            thread_filter_result = nullptr;

    bool show_taint = false;
    bool show_backward_taint = false;
    bool show_nzcv = true;
    bool show_fpr = false;

    // ─── Bookmarks (shared) ───────────────────────────────────────────
    std::vector<uint64_t> bookmarks;

    // ─── Row fetching (provided by TuiApp) ────────────────────────────
    /// Panels call this to fetch a decoded instruction row by id.
    /// Set by TuiApp to point at its fetch_row method.
    InstructionRow (*fetch_row)(void* self, uint64_t inst_id) = nullptr;
    void* fetch_row_self = nullptr;

    InstructionRow get_row(uint64_t inst_id) const {
        return fetch_row(fetch_row_self, inst_id);
    }

    // ─── Navigation callbacks (provided by TuiApp) ────────────────────
    void (*navigate_to_fn)(void* self, uint64_t inst_id) = nullptr;
    void* navigate_self = nullptr;

    void navigate_to(uint64_t inst_id) const {
        navigate_to_fn(navigate_self, inst_id);
    }

    // ─── Generic pass-run callback (provided by TuiApp) ───────────────
    // Lets panels (e.g. ResultsPanel) request that a catalog pass be run
    // by name without needing direct access to TuiApp/PassManager.
    void (*run_pass_fn)(void* self, std::string_view name) = nullptr;
    void* run_pass_self = nullptr;

    void run_pass(std::string_view name) const {
        if (run_pass_fn) run_pass_fn(run_pass_self, name);
    }

    /// Set by TuiApp before each render so panels can show live pass state
    /// without needing a direct PassManager reference. nullptr = not created
    /// yet (all passes report NotRun).
    PassManager* pass_manager = nullptr;

    // ─── Taint jump list (shared between panels) ──────────────────────
    std::vector<uint64_t> taint_jump_list;
    size_t taint_jump_cursor = 0;

    // ─── Search results (shared) ──────────────────────────────────────
    std::vector<uint64_t> search_results;
    size_t search_current = 0;
    bool search_active = false;
};

}  // namespace tenet

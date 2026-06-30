#pragma once

// Pass Registry — central catalog of all analysis passes.
//
// This module is the single source of truth for the set of passes that exist
// in tenet. It is consumed by all three frontends (CLI / GUI / TUI) so that:
//   • every pass is available in every frontend (no pass is "GUI-only" or
//     "CLI-only");
//   • GUI/TUI activate a curated default subset at startup;
//   • the remaining passes can be triggered on demand from the UI.
//
// Adding a new pass: append an entry to pass_catalog() and a case to
// register_pass_by_name() (+ optionally summarize_pass_result()).

#include "analysis/pass_manager.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tenet {

/// Grouping for UI presentation.
enum class PassCategory : uint8_t {
    Structure,   ///< function / xref / cfg / call_graph / loop / disassembly / index_build
    Taint,       ///< taint / backward_taint / slice / producer_chain / taint_source_annotation
    Crypto,      ///< pattern / constant_materialization / loop_semantics / algorithm_summary / objc_crypto / symbol_annotation
    Memory,      ///< string / memory_string / memory_snapshot / mem_search / entropy / literal_search / yara_mem_scan
    PlatformApi,  ///< objc / syscall_intercept
    Profile,     ///< trace_fold / reg_timeline / call_context / window_stats / cache_sim / trace_diff / dataflow_graph
    Misc,        ///< thread / thread_filter
};

/// Whether a pass should be activated by default in GUI/TUI startup analysis.
enum class PassDefault : uint8_t {
    No,   ///< opt-in only (user must trigger)
    Yes,  ///< registered & run at GUI/TUI startup
};

/// Describes one analysis pass for UI / generic dispatch.
struct PassCatalogEntry {
    std::string_view name;          ///< unique pass name (matches AnalysisPass::name())
    std::string_view display_name;  ///< short UI label
    std::string_view description;   ///< one-line description
    PassCategory    category;
    PassDefault     default_for_ui; ///< run at GUI/TUI startup?
};

/// Runtime context used to derive on-demand pass configs (e.g. from the
/// current cursor position). Fields default to "whole trace / register 0".
struct PassRunCtx {
    uint64_t current_inst = 0;       ///< cursor inst_id (taint/slice/call_context/…)
    uint64_t total_inst   = 0;       ///< total instructions in trace
    uint8_t  current_reg  = 0;       ///< register under cursor (x0..x28,fp,lr,sp,nzcv,pc)
    uint64_t range_start  = 0;       ///< analysis range start
    uint64_t range_end    = UINT64_MAX;  ///< analysis range end (exclusive-ish)
    std::vector<uint64_t> thread_ids;             ///< for thread_filter (empty = all)
    std::vector<std::string> mem_search_patterns; ///< hex patterns for mem_search
    std::vector<uint64_t> literal_search_values;  ///< values for literal_search
    /// Enable full (uncapped) mode for FunctionPass.
    /// When true, all call-event memory caps are removed — use only for small
    /// traces where unbounded RAM usage is acceptable.  Default: false (capped).
    bool function_full_mode = false;
};

// ─── Catalog ───────────────────────────────────────────────────────────────

/// The full, ordered catalog of all passes.
const std::vector<PassCatalogEntry>& pass_catalog();

/// Look up a catalog entry by name. Returns nullptr if unknown.
const PassCatalogEntry* find_pass_catalog_entry(std::string_view name);

/// Whether `name` corresponds to a known pass.
bool is_known_pass(std::string_view name);

/// Names of the passes that should be activated by default in GUI/TUI.
std::vector<std::string_view> default_ui_pass_names();

// ─── Registration helpers ──────────────────────────────────────────────────

/// Register all default-for-UI passes with default configs.
/// Idempotent: passes already present in `pm` are skipped.
void register_default_passes(PassManager& pm);

/// Register *every* pass in the catalog with `ctx`-derived configs.
/// This is the "run everything at startup" entry point used by GUI/TUI
/// when the user wants all analyses available immediately.
/// Passes that need cursor-specific params (taint, slice, reg_timeline, …)
/// are created with whatever `ctx` provides (defaults to inst 0 / reg 0).
/// Idempotent: passes already present in `pm` are skipped.
void register_all_passes(PassManager& pm, const PassRunCtx& ctx = {});

/// Register a single pass by name, deriving its config from `ctx` when the
/// pass needs one. Idempotent for the same `pm` (skips if already present).
/// Returns true if the pass is known and was (or already is) registered.
bool register_pass_by_name(PassManager& pm, std::string_view name,
                           const PassRunCtx& ctx);

/// Convenience: register a pass with a default-constructed PassRunCtx.
inline bool register_pass_by_name(PassManager& pm, std::string_view name) {
    return register_pass_by_name(pm, name, PassRunCtx{});
}

// ─── Result summary ────────────────────────────────────────────────────────

/// Best-effort one-line summary of a pass result (e.g. "5 loops", "42 hits").
/// Returns "ok" / "failed" when no richer summary is available.
std::string summarize_pass_result(std::string_view name, const PassResult& result);

}  // namespace tenet

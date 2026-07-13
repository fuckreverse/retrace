#pragma once
// ═══════════════════════════════════════════════════════════════════════════
// CLI option parsing for tenet
//
// Replaces the 150+ local variables and 270-line strcmp if-else chain
// in main() with a single struct + parse function.
// ═══════════════════════════════════════════════════════════════════════════

#include "cli/trace_dump.h"
#include "io/mcp/mcp_server.h"               // McpHttpConfig
#include "io/mcp/mcp_hub.h"                  // McpHubConfig

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tenet {

/// All CLI options parsed from argv.
struct CliOptions {
    // --- Basic options ---
    std::string trace_path;
    bool batch_mode = false;
    bool force_tui = false;
    uint64_t display_count = 100;
    uint64_t start_id = 0;
    bool show_regs = false;
    bool show_mem = false;
    bool show_index_stats = false;

    // --- Trace dump mode (no RocksDB) ---
    bool opt_dump = false;
    DumpOptions dump_options{};

    // --- Analysis options ---
    std::string export_cfg_path;
    bool opt_taint = false;
    uint8_t taint_reg_index = 0;
    uint64_t taint_source_inst_id = 0;
    std::vector<uint64_t> taint_source_mem_addrs;
    std::vector<uint64_t> taint_stop_pcs;
    uint32_t taint_max_width = 0;
    bool taint_no_calls = false;
    bool taint_no_xref = false;
    bool taint_no_kills = false;
    bool opt_strings = false;
    bool opt_pattern = false;
    bool opt_constants = false;
    uint8_t constants_min_parts = 2;
    std::string call_graph_path;
    bool opt_backward_taint = false;
    uint64_t backward_taint_sink_id = 0;
    uint8_t backward_taint_reg = 0;
    uint64_t backward_taint_max_steps = 0;
    std::string backward_taint_graph_path;
    bool opt_critical_path = false;
    bool opt_trace_diff = false;
    uint64_t trace_diff_a_start = 0, trace_diff_a_end = 0;
    uint64_t trace_diff_b_start = 0, trace_diff_b_end = 0;
    std::string trace_diff_file;               ///< --trace-diff-file: cross-file trace B path
    uint32_t trace_diff_window = 16384;        ///< --trace-diff-window: resync window size
    size_t trace_diff_max_diffs = 100000;      ///< --trace-diff-max-diffs: segment cap
    bool opt_loop_semantics = false;
    bool opt_symbol_annotation = false;
    bool opt_memory_snapshot = false;
    std::vector<uint64_t> memory_snapshot_ids;
    uint32_t memory_snapshot_size = 64;
    bool opt_memory_strings = false;
    size_t memory_strings_max_sites = 0;  // 0 = unlimited
    size_t memory_strings_scan_size = 256;
    bool opt_dataflow_graph = false;
    uint64_t dataflow_start = 0, dataflow_end = 0;
    std::string dataflow_output_path;
    bool opt_algorithm_summary = false;
    bool opt_objc = false;
    std::string objc_class_filter;

    // --- iOS crypto analysis ---
    bool opt_objc_crypto = false;
    bool opt_syscall_intercept = false;
    uint32_t syscall_intercept_capture_bytes = 64;
    bool opt_taint_source_annotation = false;

    // --- Query options ---
    bool opt_memread = false;
    uint64_t memread_addr = 0;
    uint8_t memread_size = 16;
    uint64_t memread_inst_id = 0;
    bool opt_mem_history = false;
    uint64_t mem_history_addr = 0;
    uint8_t mem_history_size = 8;
    bool opt_search_pc = false;
    uint64_t search_pc_addr = 0;
    uint64_t search_pc_limit = 100;

    // --- Additional pass options ---
    bool opt_trace_fold = false;
    uint64_t trace_fold_start = 0, trace_fold_end = 0;
    uint32_t trace_fold_min_iter = 3;
    uint32_t trace_fold_keep_iter = 2;        // TraceFoldConfig::keep_iterations
    uint32_t trace_fold_samples = 6;          // TraceFoldConfig::pattern_sample_points
    bool trace_fold_no_fpr = false;           // disables TraceFoldConfig::include_fpr_summary

    bool opt_reg_timeline = false;
    uint8_t reg_timeline_reg = 0;
    uint64_t reg_timeline_start = 0, reg_timeline_end = 0;

    bool opt_mem_search = false;
    std::string mem_search_pattern;               // --mem-search <hex>: byte pattern
    uint64_t mem_search_start = 0, mem_search_end = 0;
    // Exact-value search (formerly the standalone --literal-search).
    std::vector<uint64_t> mem_search_exact_values; // --mem-search-value <hex> (repeatable)
    bool mem_search_immediates = false;            // --mem-search-immediates: also scan MOVZ/MOVK

    bool opt_call_context = false;
    uint64_t call_context_inst_id = 0;

    bool opt_window_stats = false;
    uint64_t window_stats_start = 0, window_stats_end = 0;
    uint32_t window_stats_size = 1024;

    bool opt_entropy = false;
    uint64_t entropy_start = 0, entropy_end = 0;

    bool opt_no_parallel_scan = false;

    // --- Image fallback and memory access dump ---
    std::string image_path;
    bool opt_dump_memaccess = false;
    uint64_t dump_ma_start = 0;
    uint64_t dump_ma_count = 0;
    bool dump_ma_strings = false;


    // --- P3: YARA memory scan ---
    bool opt_yara_mem_scan = false;
    std::vector<std::string> yara_extra_rules;
    float yara_min_entropy = 0.0f;
    bool yara_scan_code = false;

    // --- P3: Thread filter ---
    bool opt_thread_filter = false;
    std::vector<uint64_t> thread_filter_ids;

    // --- Exclude ranges (analysis-level filtering) ---
    /// PC address ranges to exclude from analysis. Instructions whose PC falls
    /// in any [start, end) range are not delivered to passes. Repeatable.
    std::vector<std::pair<uint64_t, uint64_t>> exclude_pc_ranges;

    // --- VM abstract ---
    // NOTE: vm_abstract is entirely hint-driven — it never scans the trace
    // looking for "VM-shaped" loops. You must supply at least one
    // static-analysis hint (--vm-dispatcher, --vm-handler, --vm-hints <file>, ...).
    bool opt_vm_abstract = false;
    uint64_t vm_dispatcher_pc = 0;         // --vm-dispatcher <hex>
    uint64_t vm_indirect_br_pc = 0;        // --vm-indirect-br <hex>
    std::vector<uint64_t> vm_handler_pcs;  // --vm-handler <hex> (repeatable)
    std::string vm_hints_file;             // --vm-hints <path.json>
    std::string vm_decoder_file;           // --vm-decoder <path.json>

    // --- Suggest excludes (sampling-trace workflow) ---
    // Runs the loop pass and prints candidate --exclude-range spans for the
    // qbditrace re-record (or for --exclude-range on this very trace's other
    // analyses): large, high-iteration loops that are likely noise (memset-
    // style spins, busy-waits, anti-debug delays, etc.) rather than logic
    // worth tracing in full. Intended to be run on a small --sampling trace
    // (see qbditrace_runner.py --sampling) before committing to a full trace.
    bool opt_suggest_excludes = false;
    uint64_t suggest_excludes_min_iterations = 10000;  // --suggest-excludes-min-iter
    size_t suggest_excludes_top_n = 20;                // --suggest-excludes-top <N> (0 = unlimited)
    std::string suggest_excludes_output_path;          // --suggest-excludes-output <file> (.json or .txt); empty = stdout only

    // --- Generic pass runner ---
    bool opt_index_build = false;
    std::vector<std::string> run_pass_names;

    // --- Pass blob cache management ---
    // --cache-list: print all persisted pass blobs (name + size) then exit.
    bool opt_cache_list = false;
    // --cache-delete <pass|all>: delete one or all pass blobs then exit.
    // Special value "all" deletes every blob.  Repeatable.
    std::vector<std::string> cache_delete_blobs;

    // --- P3: RPC server ---
    bool opt_rpc = false;
    std::string rpc_socket_path;

    // --- P3: MCP server ---
    bool opt_mcp = false;

    // --- P3: WebSocket service ---
    uint16_t ws_port = 0;                      ///< --ws-port <port>: start WS service (0 = disabled)

    // --- P3: MCP Streamable HTTP server ---
    bool opt_mcp_http = false;
    McpHttpConfig mcp_http_cfg;

    // --- P3: MCP Hub mode (multi-instance coordination) ---
    bool opt_mcp_hub = false;              ///< --mcp-hub: enable hub/worker mode
    bool opt_mcp_hub_session = false;      ///< --mcp-hub-session: enable session mode (select_instance)
    std::string mcp_hub_name;              ///< --mcp-hub-name <name>: custom instance name
    McpHubConfig mcp_hub_cfg;

    // --- P3: Streaming / live trace ---
    bool opt_streaming = false;

    // --- P3: Stats only ---
    bool opt_stats_only = false;

    // --- Derived ---
    /// True if any analysis option was specified (suppress interactive mode).
    bool has_analysis_option() const;

    /// Parsing status: 0 = OK, 1 = error (already printed), 2 = early exit (e.g. --help).
    int parse_status = 0;
};

/// Parse argv into CliOptions. On --help or --list-passes, prints and sets
/// parse_status = 2 (caller should return 0). On error, sets parse_status = 1.
CliOptions parse_args(int argc, char** argv);

}  // namespace tenet

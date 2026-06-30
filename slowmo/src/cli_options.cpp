#include "cli_options.h"
#include "analysis/pass_registry.h"

#include <fmt/core.h>
#include <string>
#include <cstdlib>

namespace tenet {

// ─── has_analysis_option ──────────────────────────────────────────────────

bool CliOptions::has_analysis_option() const {
    return !export_cfg_path.empty() || opt_taint ||
           opt_strings || opt_pattern || opt_constants ||
           !call_graph_path.empty() ||
           opt_backward_taint || opt_critical_path ||
           opt_trace_diff || opt_loop_semantics ||
           opt_symbol_annotation || opt_memory_snapshot || opt_memory_strings ||
           opt_dataflow_graph || opt_algorithm_summary ||
           opt_objc ||
           opt_memread || opt_mem_history || opt_search_pc ||
           opt_trace_fold || opt_reg_timeline ||
           opt_mem_search || opt_call_context ||
           opt_producer_chain || opt_window_stats ||
           opt_entropy || opt_literal_search ||
           opt_dump_memaccess ||
           // P3 options
           opt_cache_sim || opt_yara_mem_scan || opt_thread_filter ||
           opt_rpc || opt_mcp || opt_mcp_http || opt_streaming || opt_stats_only ||
           opt_objc_crypto || opt_syscall_intercept ||
           opt_taint_source_annotation ||
           opt_index_build ||
           !run_pass_names.empty() ||
           opt_cache_list ||
           !cache_delete_blobs.empty();
}

// ─── print_usage ────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    fmt::print(stderr, "Usage: {} <trace.bin> [options]\n", prog);
    fmt::print(stderr, "\nOptions:\n");
#if TENET_HAS_GUI
    fmt::print(stderr, "  --tui                  Use terminal UI instead of GUI (default: GUI)\n");
#endif
    fmt::print(stderr, "  -c                     Batch mode (non-interactive)\n");
    fmt::print(stderr, "  -n <count>             Number of instructions to display (default: 100)\n");
    fmt::print(stderr, "  -s <inst_id>           Start from instruction ID (default: 0)\n");
    fmt::print(stderr, "  -r                     Show register state\n");
    fmt::print(stderr, "  -m                     Show memory accesses\n");
    fmt::print(stderr, "  -i                     Show index build statistics\n");
    fmt::print(stderr, "  -h                     Show this help\n");
    fmt::print(stderr, "\nAnalysis options (batch mode, suppress interactive):\n");
    fmt::print(stderr, "  --run-pass <name>         Run any catalog pass (repeatable). Names: see --list-passes\n");
    fmt::print(stderr, "  --list-passes             List all available pass names and exit\n");
    fmt::print(stderr, "  --index-build             (Re)build the RocksDB trace index\n");
  fmt::print(stderr, "  --cache-list              List all persisted pass blob caches (name + size)\n");
  fmt::print(stderr, "  --cache-delete <pass|all> Delete a pass blob cache (use 'all' to clear all)\n");
  fmt::print(stderr, "                            Repeatable. Exits after deletion.\n");
    fmt::print(stderr, "  --export-cfg <file.dot>   Export annotated CFG as Graphviz DOT\n");
    fmt::print(stderr, "  --taint <reg_index>       Run taint analysis from register index\n");
    fmt::print(stderr, "  --taint-inst <inst_id>    Start taint from specific instruction ID\n");
    fmt::print(stderr, "  --taint-mem <addr>        Add memory address as taint source (hex)\n");
    fmt::print(stderr, "  --taint-stop-pc <addr>    Stop taint at this PC (hex, repeatable)\n");
    fmt::print(stderr, "  --taint-max-width <N>     Stop when taint width exceeds N registers\n");
    fmt::print(stderr, "  --taint-no-calls          Don't propagate taint through function calls\n");
    fmt::print(stderr, "  --taint-no-xref           Disable XRef acceleration\n");
    fmt::print(stderr, "  --taint-no-kills          Don't emit kill events in output\n");
    fmt::print(stderr, "  --strings                 Discover printable strings in traced memory\n");
    fmt::print(stderr, "  --pattern                 Detect crypto/anti-debug/obfuscation patterns\n");
    fmt::print(stderr, "  --constants               Extract materialized constants (movz+movk)\n");
    fmt::print(stderr, "  --constants-min-parts <N> Min movz+movk parts to report (default: 2)\n");
    fmt::print(stderr, "  --call-graph <file.dot>   Export call graph as Graphviz DOT\n");
    fmt::print(stderr, "  --backward-taint <inst_id> <reg>  Backward taint from sink instruction\n");
    fmt::print(stderr, "  --backward-taint-max-steps <N>    Limit backward walk steps (default: unlimited)\n");
    fmt::print(stderr, "  --backward-taint-graph <file>     Export dataflow graph (.dot or .json)\n");
    fmt::print(stderr, "  --critical-path                   Compute forward+backward intersection\n");
    fmt::print(stderr, "  --trace-diff <a_start> <a_end> <b_start> <b_end>  Differential trace analysis\n");
    fmt::print(stderr, "  --loop-semantics              Identify round functions / crypto loop semantics\n");
    fmt::print(stderr, "  --symbol-annotation           Generate symbol annotations for all PCs\n");
    fmt::print(stderr, "  --memory-snapshot <inst_id>    Capture memory snapshot (repeatable)\n");
    fmt::print(stderr, "  --memory-snapshot-size <N>     Bytes per region in snapshot (default: 64)\n");
    fmt::print(stderr, "  --memory-strings              Time-aware string discovery at call sites\n");
    fmt::print(stderr, "  --memory-strings-max-sites <N> Max call sites to scan (default: unlimited)\n");
    fmt::print(stderr, "  --memory-strings-scan-size <N> Bytes to scan per pointer (default: 256)\n");
    fmt::print(stderr, "  --dataflow-graph <start> <end> Build dataflow graph for instruction range\n");
    fmt::print(stderr, "  --dataflow-graph-output <file> Export dataflow graph (.dot or .json)\n");
    fmt::print(stderr, "  --algorithm-summary           Generate algorithm summary report\n");
    fmt::print(stderr, "  --objc                        Analyze Objective-C message sends\n");
    fmt::print(stderr, "  --objc-class <name>           Filter ObjC messages by class name\n");
    fmt::print(stderr, "  --objc-crypto                 Correlate crypto patterns with ObjC call stack\n");
    fmt::print(stderr, "  --syscall-intercept           Extract crypto/system API call params (auto-selects per platform)\n");
    fmt::print(stderr, "  --syscall-intercept-bytes <N> Bytes to capture per pointer arg (default: 64)\n");
    fmt::print(stderr, "  --taint-source-annotation     Annotate backward taint leaf sources with ObjC getter context\n");
    fmt::print(stderr, "  --image <path>                Load binary image for code/string fallback\n");
    fmt::print(stderr, "  --dump-memaccess <start> <count>  Dump memory reads/writes + register ASCII in inst_id range\n");
    fmt::print(stderr, "  --dump-ma-strings              With --dump-memaccess: only output decoded strings\n");
    fmt::print(stderr, "\nQuery options (JSON output):\n");
    fmt::print(stderr, "  --memread <addr> <size> <inst_id> Read memory at a point in time\n");
    fmt::print(stderr, "  --mem-history <addr> <size>       List all writes to an address\n");
    fmt::print(stderr, "  --search-pc <addr> [limit]        Find all inst_ids visiting a PC\n");
    fmt::print(stderr, "\nP3 feature options:\n");
    fmt::print(stderr, "  --cache-sim                       Run cache simulation (L1D/L2, set-associative)\n");
    fmt::print(stderr, "  --cache-sim-l1-size <KB>          L1D cache size in KiB (default: 128)\n");
    fmt::print(stderr, "  --cache-sim-l2-size <KB>          L2 cache size in KiB (default: 12288)\n");
    fmt::print(stderr, "  --cache-sim-policy <lru|plru|rand> Replacement policy (default: lru)\n");
    fmt::print(stderr, "  --cache-sim-no-sidechannel        Disable timing side-channel detection\n");
    fmt::print(stderr, "  --yara-mem-scan                   Scan memory pages with YARA rules\n");
    fmt::print(stderr, "  --yara-rules <file_or_dir>        Extra YARA rule file/dir (repeatable)\n");
    fmt::print(stderr, "  --yara-min-entropy <N>            Skip pages with Shannon entropy < N (default: 0)\n");
    fmt::print(stderr, "  --yara-scan-code                  Also scan code bytes buffer\n");
    fmt::print(stderr, "  --thread-filter [tid1,tid2,...]   Build per-thread instruction bitmaps\n");
    fmt::print(stderr, "  --rpc [socket_path]               Start JSON-RPC server over Unix socket\n");
    fmt::print(stderr, "                                    (blocks until client disconnects)\n");
    fmt::print(stderr, "  --mcp                             Start MCP server over stdio (JSON-RPC 2.0)\n");
    fmt::print(stderr, "                                    (blocks until stdin closes)\n");
    fmt::print(stderr, "  --mcp-http [host:port]            Start MCP server over Streamable HTTP\n");
    fmt::print(stderr, "                                    Default: 127.0.0.1:7080 (blocks until SIGINT)\n");
    fmt::print(stderr, "  --mcp-host <addr>                 Bind address for --mcp-http (e.g. 0.0.0.0)\n");
    fmt::print(stderr, "  --mcp-port <port>                 Port for --mcp-http (default: 7080)\n");
    fmt::print(stderr, "  --mcp-auth user:pass              Enable Basic Auth for --mcp-http\n");
    fmt::print(stderr, "  --streaming                       Tail a live trace file (real-time indexing)\n");
    fmt::print(stderr, "  --stats                           Print trace statistics as JSON\n");
    fmt::print(stderr, "\nMultiple analysis options can be combined; they execute in order.\n");
}

// ─── parse_args ─────────────────────────────────────────────────────────────

CliOptions parse_args(int argc, char** argv) {
    CliOptions opts;

    if (argc < 2) {
        print_usage(argv[0]);
        opts.parse_status = 1;
        return opts;
    }

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            opts.parse_status = 2;
            return opts;
        } else if (arg == "-c") {
            opts.batch_mode = true;
        } else if (arg == "--tui") {
            opts.force_tui = true;
        } else if (arg == "-n" && i + 1 < argc) {
            opts.display_count = std::stoull(argv[++i]);
        } else if (arg == "-s" && i + 1 < argc) {
            opts.start_id = std::stoull(argv[++i]);
        } else if (arg == "-r") {
            opts.show_regs = true;
        } else if (arg == "-m") {
            opts.show_mem = true;
        } else if (arg == "-i") {
            opts.show_index_stats = true;
        } else if (arg == "--export-cfg" && i + 1 < argc) {
            opts.export_cfg_path = argv[++i];
        } else if (arg == "--taint" && i + 1 < argc) {
            opts.opt_taint = true;
            opts.taint_reg_index = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--taint-inst" && i + 1 < argc) {
            opts.taint_source_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--taint-mem" && i + 1 < argc) {
            opts.taint_source_mem_addrs.push_back(std::stoull(argv[++i], nullptr, 16));
        } else if (arg == "--taint-stop-pc" && i + 1 < argc) {
            opts.taint_stop_pcs.push_back(std::stoull(argv[++i], nullptr, 16));
        } else if (arg == "--taint-max-width" && i + 1 < argc) {
            opts.taint_max_width = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--taint-no-calls") {
            opts.taint_no_calls = true;
        } else if (arg == "--taint-no-xref") {
            opts.taint_no_xref = true;
        } else if (arg == "--taint-no-kills") {
            opts.taint_no_kills = true;
        } else if (arg == "--strings") {
            opts.opt_strings = true;
        } else if (arg == "--pattern") {
            opts.opt_pattern = true;
        } else if (arg == "--constants") {
            opts.opt_constants = true;
        } else if (arg == "--constants-min-parts" && i + 1 < argc) {
            opts.constants_min_parts = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--call-graph" && i + 1 < argc) {
            opts.call_graph_path = argv[++i];
        } else if (arg == "--backward-taint" && i + 2 < argc) {
            opts.opt_backward_taint = true;
            opts.backward_taint_sink_id = std::stoull(argv[++i]);
            opts.backward_taint_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--backward-taint-max-steps" && i + 1 < argc) {
            opts.backward_taint_max_steps = std::stoull(argv[++i]);
        } else if (arg == "--backward-taint-graph" && i + 1 < argc) {
            opts.backward_taint_graph_path = argv[++i];
        } else if (arg == "--critical-path") {
            opts.opt_critical_path = true;
        } else if (arg == "--trace-diff" && i + 4 < argc) {
            opts.opt_trace_diff = true;
            opts.trace_diff_a_start = std::stoull(argv[++i]);
            opts.trace_diff_a_end = std::stoull(argv[++i]);
            opts.trace_diff_b_start = std::stoull(argv[++i]);
            opts.trace_diff_b_end = std::stoull(argv[++i]);
        } else if (arg == "--loop-semantics") {
            opts.opt_loop_semantics = true;
        } else if (arg == "--symbol-annotation") {
            opts.opt_symbol_annotation = true;
        } else if (arg == "--memory-snapshot" && i + 1 < argc) {
            opts.opt_memory_snapshot = true;
            opts.memory_snapshot_ids.push_back(std::stoull(argv[++i]));
        } else if (arg == "--memory-snapshot-size" && i + 1 < argc) {
            opts.memory_snapshot_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--memory-strings") {
            opts.opt_memory_strings = true;
        } else if (arg == "--memory-strings-max-sites" && i + 1 < argc) {
            opts.memory_strings_max_sites = std::stoull(argv[++i]);
        } else if (arg == "--memory-strings-scan-size" && i + 1 < argc) {
            opts.memory_strings_scan_size = std::stoull(argv[++i]);
        } else if (arg == "--dataflow-graph" && i + 2 < argc) {
            opts.opt_dataflow_graph = true;
            opts.dataflow_start = std::stoull(argv[++i]);
            opts.dataflow_end = std::stoull(argv[++i]);
        } else if (arg == "--dataflow-graph-output" && i + 1 < argc) {
            opts.dataflow_output_path = argv[++i];
        } else if (arg == "--algorithm-summary") {
            opts.opt_algorithm_summary = true;
        } else if (arg == "--objc") {
            opts.opt_objc = true;
        } else if (arg == "--objc-class" && i + 1 < argc) {
            opts.opt_objc = true;
            opts.objc_class_filter = argv[++i];
        } else if (arg == "--objc-crypto") {
            opts.opt_objc_crypto = true;
            opts.opt_objc = true;  // objc_crypto depends on objc
        } else if (arg == "--syscall-intercept") {
            opts.opt_syscall_intercept = true;
        } else if (arg == "--syscall-intercept-bytes" && i + 1 < argc) {
            opts.syscall_intercept_capture_bytes = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--taint-source-annotation") {
            opts.opt_taint_source_annotation = true;
        } else if (arg == "--memread" && i + 3 < argc) {
            opts.opt_memread = true;
            opts.memread_addr = std::stoull(argv[++i], nullptr, 16);
            opts.memread_size = static_cast<uint8_t>(std::stoul(argv[++i]));
            opts.memread_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--mem-history" && i + 2 < argc) {
            opts.opt_mem_history = true;
            opts.mem_history_addr = std::stoull(argv[++i], nullptr, 16);
            opts.mem_history_size = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--search-pc" && i + 1 < argc) {
            opts.opt_search_pc = true;
            opts.search_pc_addr = std::stoull(argv[++i], nullptr, 16);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.search_pc_limit = std::stoull(argv[++i]);
            }
        } else if (arg == "--trace-fold" && i + 2 < argc) {
            opts.opt_trace_fold = true;
            opts.trace_fold_start = std::stoull(argv[++i]);
            opts.trace_fold_end = std::stoull(argv[++i]);
        } else if (arg == "--trace-fold-min-iter" && i + 1 < argc) {
            opts.trace_fold_min_iter = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--reg-timeline" && i + 1 < argc) {
            opts.opt_reg_timeline = true;
            opts.reg_timeline_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--reg-timeline-range" && i + 2 < argc) {
            opts.reg_timeline_start = std::stoull(argv[++i]);
            opts.reg_timeline_end = std::stoull(argv[++i]);
        } else if (arg == "--mem-search" && i + 1 < argc) {
            opts.opt_mem_search = true;
            opts.mem_search_pattern = argv[++i];
        } else if (arg == "--mem-search-range" && i + 2 < argc) {
            opts.mem_search_start = std::stoull(argv[++i]);
            opts.mem_search_end = std::stoull(argv[++i]);
        } else if (arg == "--call-context" && i + 1 < argc) {
            opts.opt_call_context = true;
            opts.call_context_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--producer-chain" && i + 2 < argc) {
            opts.opt_producer_chain = true;
            opts.producer_chain_inst_id = std::stoull(argv[++i]);
            opts.producer_chain_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--producer-chain-depth" && i + 1 < argc) {
            opts.producer_chain_depth = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--window-stats" && i + 2 < argc) {
            opts.opt_window_stats = true;
            opts.window_stats_start = std::stoull(argv[++i]);
            opts.window_stats_end = std::stoull(argv[++i]);
        } else if (arg == "--window-stats-size" && i + 1 < argc) {
            opts.window_stats_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--entropy" && i + 2 < argc) {
            opts.opt_entropy = true;
            opts.entropy_start = std::stoull(argv[++i]);
            opts.entropy_end = std::stoull(argv[++i]);
        } else if (arg == "--literal-search" && i + 1 < argc) {
            opts.opt_literal_search = true;
            opts.literal_search_value = std::stoull(argv[++i], nullptr, 16);
        } else if (arg == "--literal-search-range" && i + 2 < argc) {
            opts.literal_search_start = std::stoull(argv[++i]);
            opts.literal_search_end = std::stoull(argv[++i]);
        } else if (arg == "--no-parallel-scan") {
            opts.opt_no_parallel_scan = true;
        } else if (arg == "--image" && i + 1 < argc) {
            opts.image_path = argv[++i];
        } else if (arg == "--dump-memaccess" && i + 2 < argc) {
            opts.opt_dump_memaccess = true;
            opts.dump_ma_start = std::stoull(argv[++i]);
            opts.dump_ma_count = std::stoull(argv[++i]);
        } else if (arg == "--dump-ma-strings") {
            opts.dump_ma_strings = true;
        // ── P3 options ──────────────────────────────────────────────────────
        } else if (arg == "--cache-sim") {
            opts.opt_cache_sim = true;
        } else if (arg == "--cache-sim-l1-size" && i + 1 < argc) {
            opts.cache_sim_l1_size_kb = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--cache-sim-l2-size" && i + 1 < argc) {
            opts.cache_sim_l2_size_kb = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--cache-sim-policy" && i + 1 < argc) {
            std::string pol = argv[++i];
            if (pol == "plru") opts.cache_sim_policy = ReplacementPolicy::PLRU;
            else if (pol == "rand") opts.cache_sim_policy = ReplacementPolicy::RAND;
            else opts.cache_sim_policy = ReplacementPolicy::LRU;
        } else if (arg == "--cache-sim-no-sidechannel") {
            opts.cache_sim_no_sidechannel = true;
        } else if (arg == "--yara-mem-scan") {
            opts.opt_yara_mem_scan = true;
        } else if (arg == "--yara-rules" && i + 1 < argc) {
            opts.yara_extra_rules.push_back(argv[++i]);
        } else if (arg == "--yara-min-entropy" && i + 1 < argc) {
            opts.yara_min_entropy = std::stof(argv[++i]);
        } else if (arg == "--yara-scan-code") {
            opts.yara_scan_code = true;
        } else if (arg == "--thread-filter") {
            opts.opt_thread_filter = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string tids_str = argv[++i];
                std::string tok;
                for (char c : tids_str + ",") {
                    if (c == ',') {
                        if (!tok.empty()) {
                            opts.thread_filter_ids.push_back(std::stoull(tok));
                            tok.clear();
                        }
                    } else {
                        tok.push_back(c);
                    }
                }
            }
        } else if (arg == "--cache-list") {
            opts.opt_cache_list = true;
        } else if (arg == "--cache-delete" && i + 1 < argc) {
            opts.cache_delete_blobs.push_back(argv[++i]);
        } else if (arg == "--index-build") {
            opts.opt_index_build = true;
        } else if (arg == "--run-pass" && i + 1 < argc) {
            opts.run_pass_names.push_back(argv[++i]);
        } else if (arg == "--list-passes") {
            fmt::print("Available passes (for --run-pass <name>):\n");
            for (const auto& e : tenet::pass_catalog()) {
                const char* cat = "Misc";
                switch (e.category) {
                    case tenet::PassCategory::Structure:  cat = "Structure"; break;
                    case tenet::PassCategory::Taint:      cat = "Taint";     break;
                    case tenet::PassCategory::Crypto:     cat = "Crypto";    break;
                    case tenet::PassCategory::Memory:     cat = "Memory";    break;
                    case tenet::PassCategory::PlatformApi:cat = "Platform"; break;
                    case tenet::PassCategory::Profile:    cat = "Profile";   break;
                    case tenet::PassCategory::Misc:       cat = "Misc";      break;
                }
                fmt::print("  {:<24} [{:<10}] {}{}\n", e.name, cat,
                           e.description,
                           e.default_for_ui == tenet::PassDefault::Yes ? "  (default)" : "");
            }
            opts.parse_status = 2;
            return opts;
        } else if (arg == "--rpc") {
            opts.opt_rpc = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.rpc_socket_path = argv[++i];
            }
        } else if (arg == "--mcp") {
            opts.opt_mcp = true;
        } else if (arg == "--mcp-http") {
            opts.opt_mcp_http = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string hostport = argv[++i];
                size_t colon = hostport.rfind(':');
                if (colon != std::string::npos) {
                    opts.mcp_http_cfg.host = hostport.substr(0, colon);
                    opts.mcp_http_cfg.port = static_cast<uint16_t>(std::stoul(hostport.substr(colon + 1)));
                } else {
                    opts.mcp_http_cfg.host = hostport;
                }
            }
        } else if (arg == "--mcp-host" && i + 1 < argc) {
            opts.mcp_http_cfg.host = argv[++i];
        } else if (arg == "--mcp-port" && i + 1 < argc) {
            opts.mcp_http_cfg.port = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if (arg == "--mcp-auth" && i + 1 < argc) {
            std::string auth = argv[++i];
            size_t colon = auth.find(':');
            if (colon != std::string::npos) {
                opts.mcp_http_cfg.username = auth.substr(0, colon);
                opts.mcp_http_cfg.password = auth.substr(colon + 1);
            }
        } else if (arg == "--streaming") {
            opts.opt_streaming = true;
        } else if (arg == "--stats") {
            opts.opt_stats_only = true;
        } else if (arg[0] != '-') {
            opts.trace_path = arg;
        }
    }

    // Validate: trace path is mandatory
    if (opts.trace_path.empty()) {
        fmt::print(stderr, "Error: no trace file specified\n");
        if (opts.opt_mcp) {
            fmt::print(stderr, "  Hint: --mcp requires a trace file, e.g.:\n");
            fmt::print(stderr, "    tenet --mcp trace.bin\n");
        }
        if (opts.opt_mcp_http) {
            fmt::print(stderr, "  Hint: --mcp-http requires a trace file, e.g.:\n");
            fmt::print(stderr, "    tenet --mcp-http 127.0.0.1:7080 trace.bin\n");
        }
        print_usage(argv[0]);
        opts.parse_status = 1;
    }

    return opts;
}

}  // namespace tenet

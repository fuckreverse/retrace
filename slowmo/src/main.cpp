#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "tui/tui_app.h"
#if TENET_HAS_GUI
#include "gui/gui_app.h"
#endif
#include "analysis/pass_manager.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/trace_diff_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"
#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/dataflow_graph_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/reg_timeline_pass.h"
#include "analysis/passes/mem_search_pass.h"
#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/producer_chain_pass.h"
#include "analysis/passes/window_stats_pass.h"
#include "analysis/passes/entropy_pass.h"
#include "analysis/passes/literal_search_pass.h"
#include "analysis/passes/cache_sim_pass.h"
#include "analysis/passes/yara_mem_scan_pass.h"
#include "analysis/passes/thread_filter_pass.h"
#include "io/rpc_server.h"
#include "io/streaming_index.h"
#include "io/recent_files.h"

#include <csignal>

#include "common/logger.h"

#include <fmt/core.h>
#include <fmt/color.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>

using namespace tenet;
using json = nlohmann::json;

// ─── Helper: category to string ────────────────────────────────────────────

static const char* pattern_category_str(PatternCategory cat) {
    switch (cat) {
        case PatternCategory::Crypto:      return "Crypto";
        case PatternCategory::AntiDebug:   return "AntiDebug";
        case PatternCategory::AntiTamper:  return "AntiTamper";
        case PatternCategory::Obfuscation: return "Obfuscation";
        case PatternCategory::Networking:  return "Networking";
        case PatternCategory::KeySchedule: return "KeySchedule";
    }
    return "Unknown";
}

static const char* pattern_confidence_str(PatternConfidence conf) {
    switch (conf) {
        case PatternConfidence::Low:    return "Low";
        case PatternConfidence::Medium: return "Medium";
        case PatternConfidence::High:   return "High";
    }
    return "Unknown";
}

static const char* string_encoding_str(StringRef::Encoding enc) {
    switch (enc) {
        case StringRef::ASCII:  return "ASCII";
        case StringRef::UTF8:   return "UTF8";
        case StringRef::UTF16LE: return "UTF16";
        case StringRef::Wide:   return "Wide";
    }
    return "Unknown";
}

// ─── Batch analysis runners ────────────────────────────────────────────────

static int run_export_cfg(PassManager& pm, InstructionDecoder& decoder,
                          const CodeTable& code_table, const std::string& output_path) {
    const auto& cfg_result_raw = pm.require("cfg_layout");
    if (!cfg_result_raw.ok()) {
        fmt::print(stderr, "[export-cfg] CFG layout pass failed: {}\n",
                   cfg_result_raw.error_message);
        return 1;
    }
    const auto& layout = cfg_result_raw.get<CFGLayoutResult>();

    const auto& cfg_result_raw2 = pm.require("cfg");
    if (!cfg_result_raw2.ok()) {
        fmt::print(stderr, "[export-cfg] CFG pass failed: {}\n",
                   cfg_result_raw2.error_message);
        return 1;
    }
    const auto& cfg = cfg_result_raw2.get<CFGResult>();

    // Use the pre-generated annotated DOT from the layout pass result.
    // Layout is delegated to Graphviz (dot) at render time.
    std::string dot = layout.dot_annotated;

    std::ofstream out(output_path);
    if (!out.is_open()) {
        fmt::print(stderr, "[export-cfg] Cannot open output file: {}\n", output_path);
        return 1;
    }
    out << dot;
    out.close();

    fmt::print(stderr, "[export-cfg] blocks: {}, edges: {} -> {}\n",
               cfg.block_count(), cfg.edge_count(), output_path);
    return 0;
}

static const char* propagation_type_str(PropagationType t) {
    switch (t) {
        case PropagationType::RegToReg:  return "RegToReg";
        case PropagationType::RegToMem:  return "RegToMem";
        case PropagationType::MemToReg:  return "MemToReg";
        case PropagationType::MemToMem:  return "MemToMem";
        case PropagationType::Immediate: return "Immediate";
        case PropagationType::Call:      return "Call";
        case PropagationType::Return:    return "Return";
        case PropagationType::Kill:      return "Kill";
    }
    return "Unknown";
}

static int run_taint(PassManager& pm, uint8_t reg_index) {
    // TaintPass was already registered with the correct config during setup
    const auto& result_raw = pm.require("taint");
    if (!result_raw.ok()) {
        fmt::print(stderr, "[taint] Taint pass failed: {}\n",
                   result_raw.error_message);
        return 1;
    }
    const auto& result = result_raw.get<TaintResult>();

    // Build JSON output using nlohmann/json
    json output;
    output["config"] = {
        {"source_regs", json::array({reg_index})},
        {"source_inst_id", result.config.source_inst_id},
        {"taint_from_memory", result.config.taint_from_memory},
        {"propagate_through_calls", result.config.propagate_through_calls},
        {"use_xref_acceleration", result.config.use_xref_acceleration},
        {"max_taint_width", result.config.max_taint_width}
    };

    // Source memory addresses
    if (!result.config.source_mem_addrs.empty()) {
        json mem_arr = json::array();
        for (auto addr : result.config.source_mem_addrs) {
            mem_arr.push_back(fmt::format("0x{:X}", addr));
        }
        output["config"]["source_mem_addrs"] = std::move(mem_arr);
    }

    // Stop PCs
    if (!result.config.stop_pcs.empty()) {
        json stop_arr = json::array();
        for (auto pc : result.config.stop_pcs) {
            stop_arr.push_back(fmt::format("0x{:X}", pc));
        }
        output["config"]["stop_pcs"] = std::move(stop_arr);
    }

    // Statistics
    output["statistics"] = {
        {"events_count", result.events.size()},
        {"steps_count", result.steps.size()},
        {"instructions_processed", result.instructions_processed},
        {"instructions_skipped_xref", result.instructions_skipped_xref},
        {"kill_events", result.kill_events_count},
        {"call_crossings", result.call_crossings},
        {"return_crossings", result.return_crossings},
        {"tainted_memory_count", result.tainted_memory_count()}
    };

    if (!result.stop_reason.empty()) {
        output["stop_reason"] = result.stop_reason;
    }

    // tainted_regs_final (sorted, extracted from bitmask)
    std::vector<uint8_t> tainted;
    {
        uint64_t remaining = result.tainted_regs;
        while (remaining) {
            tainted.push_back(static_cast<uint8_t>(__builtin_ctzll(remaining)));
            remaining &= remaining - 1;
        }
    }
    output["tainted_regs_final"] = tainted;

    // Propagation steps (detailed, limit to 1000)
    if (!result.steps.empty()) {
        json steps_arr = json::array();
        size_t limit = std::min(result.steps.size(), size_t(1000));
        for (size_t i = 0; i < limit; i++) {
            const auto& s = result.steps[i];
            json step_json = {
                {"inst_id", s.inst_id},
                {"pc", fmt::format("0x{:X}", s.pc)},
                {"type", propagation_type_str(s.type)},
                {"triton_resolved", s.triton_resolved}
            };
            if (s.dst_reg != 0xFF) {
                step_json["dst_reg"] = s.dst_reg;
            }
            if (s.dst_mem_addr != 0) {
                step_json["dst_mem"] = fmt::format("0x{:X}", s.dst_mem_addr);
                step_json["dst_mem_size"] = s.dst_mem_size;
            }
            if (!s.src_regs.empty()) {
                step_json["src_regs"] = s.src_regs;
            }
            if (!s.src_mem_addrs.empty()) {
                json addrs = json::array();
                for (auto a : s.src_mem_addrs) addrs.push_back(fmt::format("0x{:X}", a));
                step_json["src_mem_addrs"] = std::move(addrs);
            }
            if (s.cross_function_pc != 0) {
                step_json["cross_function_pc"] = fmt::format("0x{:X}", s.cross_function_pc);
            }
            steps_arr.push_back(std::move(step_json));
        }
        output["steps"] = std::move(steps_arr);
        if (result.steps.size() > 1000) {
            output["steps_truncated"] = true;
            output["total_steps"] = result.steps.size();
        }
    }

    // Legacy events (for backward compat, limit to 500)
    json events_arr = json::array();
    size_t ev_limit = std::min(result.events.size(), size_t(500));
    for (size_t i = 0; i < ev_limit; i++) {
        const auto& ev = result.events[i];
        events_arr.push_back({
            {"inst_id", ev.inst_id},
            {"pc", fmt::format("0x{:X}", ev.pc)},
            {"dst_reg", ev.dst_reg},
            {"src_regs", ev.src_regs}
        });
    }
    output["events"] = std::move(events_arr);
    if (result.events.size() > 500) {
        output["events_truncated"] = true;
        output["total_events"] = result.events.size();
    }

    fmt::print("{}\n", output.dump(2));
    return 0;
}

static int run_strings(PassManager& pm) {
    const auto& result_raw = pm.require("strings");
    if (!result_raw.ok()) {
        fmt::print(stderr, "[strings] String pass failed: {}\n",
                   result_raw.error_message);
        return 1;
    }
    const auto& result = result_raw.get<StringResult>();

    fmt::print("[strings] Found {} strings\n\n", result.total());
    fmt::print("  {:<18} {:<4}  {:<8} {:<4}  {}\n",
               "ADDR", "LEN", "ENC", "REFS", "CONTENT");

    for (const auto& s : result.strings) {
        fmt::print("  0x{:016X} {:<4}  {:<8} {:<4}  \"{}\"\n",
                   s.addr, s.content.size(),
                   string_encoding_str(s.encoding),
                   s.references.size(), s.content);
    }

    return 0;
}

static int run_pattern(PassManager& pm) {
    const auto& result_raw = pm.require("pattern");
    if (!result_raw.ok()) {
        fmt::print(stderr, "[patterns] Pattern pass failed: {}\n",
                   result_raw.error_message);
        return 1;
    }
    const auto& result = result_raw.get<PatternResult>();

    fmt::print("[patterns] Found {} matches\n\n", result.total());
    fmt::print("  {:<14} {:<10} {:<22} {}\n",
               "CATEGORY", "CONFIDENCE", "INST_RANGE", "PATTERN");

    for (const auto& m : result.matches) {
        fmt::print("  {:<14} {:<10} #{:<5} - #{:<10} {}\n",
                   pattern_category_str(m.category),
                   pattern_confidence_str(m.confidence),
                   m.start_inst_id, m.end_inst_id,
                   m.pattern_name);
    }

    return 0;
}

static int run_call_graph(PassManager& pm, const std::string& output_path) {
    const auto& cg_result_raw = pm.require("call_graph");
    if (!cg_result_raw.ok()) {
        fmt::print(stderr, "[call-graph] Call graph pass failed: {}\n",
                   cg_result_raw.error_message);
        return 1;
    }
    const auto& cg = cg_result_raw.get<CallGraphResult>();

    // Support both DOT and JSON output based on file extension
    bool json_output = (output_path.size() >= 5 &&
                        output_path.substr(output_path.size() - 5) == ".json");

    if (json_output) {
        json output;
        json nodes_arr = json::array();
        for (const auto& [pc, node] : cg.nodes) {
            nodes_arr.push_back({
                {"pc", fmt::format("0x{:X}", pc)},
                {"name", node.name.empty() ? fmt::format("sub_{:X}", pc) : node.name},
                {"total_calls_made", node.total_calls_made},
                {"total_calls_received", node.total_calls_received}
            });
        }
        output["nodes"] = std::move(nodes_arr);

        json edges_arr = json::array();
        for (const auto& edge : cg.edges) {
            edges_arr.push_back({
                {"caller", fmt::format("0x{:X}", edge.caller_pc)},
                {"callee", fmt::format("0x{:X}", edge.callee_pc)},
                {"call_count", edge.call_count}
            });
        }
        output["edges"] = std::move(edges_arr);

        std::ofstream out(output_path);
        if (!out.is_open()) {
            fmt::print(stderr, "[call-graph] Cannot open output file: {}\n", output_path);
            return 1;
        }
        out << output.dump(2) << "\n";
        out.close();
    } else {
        // Generate DOT format
        std::string dot;
        dot += "digraph callgraph {\n";
        dot += "  node [shape=box, style=filled, fillcolor=lightyellow];\n";
        dot += "  edge [color=gray40];\n\n";

        for (const auto& [pc, node] : cg.nodes) {
            std::string label = node.name.empty()
                ? fmt::format("sub_{:X}", pc)
                : node.name;
            dot += fmt::format("  \"0x{:X}\" [label=\"{}\"];\n", pc, label);
        }
        dot += "\n";

        for (const auto& edge : cg.edges) {
            dot += fmt::format("  \"0x{:X}\" -> \"0x{:X}\" [label=\"{}\"];\n",
                               edge.caller_pc, edge.callee_pc, edge.call_count);
        }

        dot += "}\n";

        std::ofstream out(output_path);
        if (!out.is_open()) {
            fmt::print(stderr, "[call-graph] Cannot open output file: {}\n", output_path);
            return 1;
        }
        out << dot;
        out.close();
    }

    // Also report FunctionPass statistics (tail calls, non-local unwinds)
    const auto& func_result_raw = pm.require("function");
    if (func_result_raw.ok()) {
        const auto& fr = func_result_raw.get<FunctionResult>();
        uint64_t tail_calls = 0;
        for (const auto& evt : fr.call_events) {
            if (evt.is_tail_call) tail_calls++;
        }
        fmt::print(stderr, "[call-graph] {} functions, {} edges -> {}\n",
                   cg.nodes.size(), cg.edges.size(), output_path);
        fmt::print(stderr, "[call-graph] {} call events ({} tail calls detected)\n",
                   fr.call_events.size(), tail_calls);
    } else {
        fmt::print(stderr, "[call-graph] {} functions, {} edges -> {}\n",
                   cg.nodes.size(), cg.edges.size(), output_path);
    }
    return 0;
}

static int run_backward_taint(PassManager& pm, uint64_t sink_id, uint8_t sink_reg) {
    const auto& result_raw = pm.require("backward_taint");
    if (!result_raw.ok()) {
        fmt::print(stderr, "[backward-taint] Pass failed: {}\n",
                   result_raw.error_message);
        return 1;
    }
    const auto& result = result_raw.get<BackwardTaintResult>();

    json output;
    output["config"] = {
        {"sink_inst_id", sink_id},
        {"sink_reg", sink_reg},
        {"propagate_through_memory", result.config.propagate_through_memory},
        {"max_steps", result.config.max_steps}
    };
    output["contributing_count"] = result.contributing_count();
    output["max_depth"] = result.max_depth;

    // All involved registers
    std::vector<uint8_t> involved;
    {
        uint64_t remaining = result.all_involved_regs;
        while (remaining) {
            involved.push_back(static_cast<uint8_t>(__builtin_ctzll(remaining)));
            remaining &= remaining - 1;
        }
    }
    output["involved_regs"] = involved;

    // Events (limit to first 500 for JSON output readability)
    json events_arr = json::array();
    size_t limit = std::min(result.events.size(), size_t(500));
    for (size_t i = 0; i < limit; i++) {
        const auto& ev = result.events[i];
        json ev_json = {
            {"inst_id", ev.inst_id},
            {"pc", fmt::format("0x{:X}", ev.pc)},
            {"dst_reg", ev.dst_reg},
            {"src_regs", ev.src_regs}
        };
        if (ev.loads_from_memory) {
            json addrs = json::array();
            for (auto a : ev.src_mem_addrs) addrs.push_back(fmt::format("0x{:X}", a));
            ev_json["loads_from"] = std::move(addrs);
        }
        if (ev.stores_to_memory) {
            ev_json["stores_to"] = fmt::format("0x{:X}", ev.store_addr);
            ev_json["store_size"] = ev.store_size;
        }
        events_arr.push_back(std::move(ev_json));
    }
    output["events"] = std::move(events_arr);
    if (result.events.size() > 500) {
        output["events_truncated"] = true;
        output["total_events"] = result.events.size();
    }

    fmt::print("{}\n", output.dump(2));
    return 0;
}

// ─── Usage ─────────────────────────────────────────────────────────────────

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
    fmt::print(stderr, "  --streaming                       Tail a live trace file (real-time indexing)\n");
    fmt::print(stderr, "  --stats                           Print trace statistics as JSON\n");
    fmt::print(stderr, "\nMultiple analysis options can be combined; they execute in order.\n");
}

// ─── Main ──────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse arguments
    std::string trace_path;
    bool batch_mode = false;
    bool force_tui = false;
    uint64_t display_count = 100;
    uint64_t start_id = 0;
    bool show_regs = false;
    bool show_mem = false;
    bool show_index_stats = false;

    // Analysis options
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
    std::string objc_class_filter;  // --objc-class <ClassName>

    // Query options
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

    // New pass options
    bool opt_trace_fold = false;
    uint64_t trace_fold_start = 0, trace_fold_end = 0;
    uint32_t trace_fold_min_iter = 3;

    bool opt_reg_timeline = false;
    uint8_t reg_timeline_reg = 0;
    uint64_t reg_timeline_start = 0, reg_timeline_end = 0;

    bool opt_mem_search = false;
    std::string mem_search_pattern;   // hex string "AA BB ?? CC"
    uint64_t mem_search_start = 0, mem_search_end = 0;

    bool opt_call_context = false;
    uint64_t call_context_inst_id = 0;

    bool opt_producer_chain = false;
    uint64_t producer_chain_inst_id = 0;
    uint8_t producer_chain_reg = 0;
    uint32_t producer_chain_depth = 32;

    bool opt_window_stats = false;
    uint64_t window_stats_start = 0, window_stats_end = 0;
    uint32_t window_stats_size = 1024;

    bool opt_entropy = false;
    uint64_t entropy_start = 0, entropy_end = 0;

    bool opt_literal_search = false;
    uint64_t literal_search_value = 0;
    uint64_t literal_search_start = 0, literal_search_end = 0;

    bool opt_no_parallel_scan = false;

    // Image fallback and memory access dump
    std::string image_path;          // --image <path>
    bool opt_dump_memaccess = false;  // --dump-memaccess <start> <count>
    uint64_t dump_ma_start = 0;
    uint64_t dump_ma_count = 0;
    bool dump_ma_strings = false;     // --dump-ma-strings

    // P3: Cache simulation
    bool opt_cache_sim = false;
    uint32_t cache_sim_l1_size_kb = 128;
    uint32_t cache_sim_l2_size_kb = 12288;
    ReplacementPolicy cache_sim_policy = ReplacementPolicy::LRU;
    bool cache_sim_no_sidechannel = false;

    // P3: YARA memory scan
    bool opt_yara_mem_scan = false;
    std::vector<std::string> yara_extra_rules;
    float yara_min_entropy = 0.0f;
    bool yara_scan_code = false;

    // P3: Thread filter
    bool opt_thread_filter = false;
    std::vector<uint64_t> thread_filter_ids;

    // P3: RPC server mode
    bool opt_rpc = false;
    std::string rpc_socket_path;

    // P3: Streaming / live trace
    bool opt_streaming = false;

    // P3: Stats only
    bool opt_stats_only = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-c") {
            batch_mode = true;
        } else if (arg == "--tui") {
            force_tui = true;
        } else if (arg == "-n" && i + 1 < argc) {
            display_count = std::stoull(argv[++i]);
        } else if (arg == "-s" && i + 1 < argc) {
            start_id = std::stoull(argv[++i]);
        } else if (arg == "-r") {
            show_regs = true;
        } else if (arg == "-m") {
            show_mem = true;
        } else if (arg == "-i") {
            show_index_stats = true;
        } else if (arg == "--export-cfg" && i + 1 < argc) {
            export_cfg_path = argv[++i];
        } else if (arg == "--taint" && i + 1 < argc) {
            opt_taint = true;
            taint_reg_index = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--taint-inst" && i + 1 < argc) {
            taint_source_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--taint-mem" && i + 1 < argc) {
            taint_source_mem_addrs.push_back(std::stoull(argv[++i], nullptr, 16));
        } else if (arg == "--taint-stop-pc" && i + 1 < argc) {
            taint_stop_pcs.push_back(std::stoull(argv[++i], nullptr, 16));
        } else if (arg == "--taint-max-width" && i + 1 < argc) {
            taint_max_width = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--taint-no-calls") {
            taint_no_calls = true;
        } else if (arg == "--taint-no-xref") {
            taint_no_xref = true;
        } else if (arg == "--taint-no-kills") {
            taint_no_kills = true;
        } else if (arg == "--strings") {
            opt_strings = true;
        } else if (arg == "--pattern") {
            opt_pattern = true;
        } else if (arg == "--constants") {
            opt_constants = true;
        } else if (arg == "--constants-min-parts" && i + 1 < argc) {
            constants_min_parts = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--call-graph" && i + 1 < argc) {
            call_graph_path = argv[++i];
        } else if (arg == "--backward-taint" && i + 2 < argc) {
            opt_backward_taint = true;
            backward_taint_sink_id = std::stoull(argv[++i]);
            backward_taint_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--backward-taint-max-steps" && i + 1 < argc) {
            backward_taint_max_steps = std::stoull(argv[++i]);
        } else if (arg == "--backward-taint-graph" && i + 1 < argc) {
            backward_taint_graph_path = argv[++i];
        } else if (arg == "--critical-path") {
            opt_critical_path = true;
        } else if (arg == "--trace-diff" && i + 4 < argc) {
            opt_trace_diff = true;
            trace_diff_a_start = std::stoull(argv[++i]);
            trace_diff_a_end = std::stoull(argv[++i]);
            trace_diff_b_start = std::stoull(argv[++i]);
            trace_diff_b_end = std::stoull(argv[++i]);
        } else if (arg == "--loop-semantics") {
            opt_loop_semantics = true;
        } else if (arg == "--symbol-annotation") {
            opt_symbol_annotation = true;
        } else if (arg == "--memory-snapshot" && i + 1 < argc) {
            opt_memory_snapshot = true;
            memory_snapshot_ids.push_back(std::stoull(argv[++i]));
        } else if (arg == "--memory-snapshot-size" && i + 1 < argc) {
            memory_snapshot_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--memory-strings") {
            opt_memory_strings = true;
        } else if (arg == "--memory-strings-max-sites" && i + 1 < argc) {
            memory_strings_max_sites = std::stoull(argv[++i]);
        } else if (arg == "--memory-strings-scan-size" && i + 1 < argc) {
            memory_strings_scan_size = std::stoull(argv[++i]);
        } else if (arg == "--dataflow-graph" && i + 2 < argc) {
            opt_dataflow_graph = true;
            dataflow_start = std::stoull(argv[++i]);
            dataflow_end = std::stoull(argv[++i]);
        } else if (arg == "--dataflow-graph-output" && i + 1 < argc) {
            dataflow_output_path = argv[++i];
        } else if (arg == "--algorithm-summary") {
            opt_algorithm_summary = true;
        } else if (arg == "--objc") {
            opt_objc = true;
        } else if (arg == "--objc-class" && i + 1 < argc) {
            opt_objc = true;
            objc_class_filter = argv[++i];
        } else if (arg == "--memread" && i + 3 < argc) {
            opt_memread = true;
            memread_addr = std::stoull(argv[++i], nullptr, 16);
            memread_size = static_cast<uint8_t>(std::stoul(argv[++i]));
            memread_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--mem-history" && i + 2 < argc) {
            opt_mem_history = true;
            mem_history_addr = std::stoull(argv[++i], nullptr, 16);
            mem_history_size = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--search-pc" && i + 1 < argc) {
            opt_search_pc = true;
            search_pc_addr = std::stoull(argv[++i], nullptr, 16);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                search_pc_limit = std::stoull(argv[++i]);
            }
        } else if (arg == "--trace-fold" && i + 2 < argc) {
            opt_trace_fold = true;
            trace_fold_start = std::stoull(argv[++i]);
            trace_fold_end = std::stoull(argv[++i]);
        } else if (arg == "--trace-fold-min-iter" && i + 1 < argc) {
            trace_fold_min_iter = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--reg-timeline" && i + 1 < argc) {
            opt_reg_timeline = true;
            reg_timeline_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--reg-timeline-range" && i + 2 < argc) {
            reg_timeline_start = std::stoull(argv[++i]);
            reg_timeline_end = std::stoull(argv[++i]);
        } else if (arg == "--mem-search" && i + 1 < argc) {
            opt_mem_search = true;
            mem_search_pattern = argv[++i];
        } else if (arg == "--mem-search-range" && i + 2 < argc) {
            mem_search_start = std::stoull(argv[++i]);
            mem_search_end = std::stoull(argv[++i]);
        } else if (arg == "--call-context" && i + 1 < argc) {
            opt_call_context = true;
            call_context_inst_id = std::stoull(argv[++i]);
        } else if (arg == "--producer-chain" && i + 2 < argc) {
            opt_producer_chain = true;
            producer_chain_inst_id = std::stoull(argv[++i]);
            producer_chain_reg = static_cast<uint8_t>(std::stoul(argv[++i]));
        } else if (arg == "--producer-chain-depth" && i + 1 < argc) {
            producer_chain_depth = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--window-stats" && i + 2 < argc) {
            opt_window_stats = true;
            window_stats_start = std::stoull(argv[++i]);
            window_stats_end = std::stoull(argv[++i]);
        } else if (arg == "--window-stats-size" && i + 1 < argc) {
            window_stats_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--entropy" && i + 2 < argc) {
            opt_entropy = true;
            entropy_start = std::stoull(argv[++i]);
            entropy_end = std::stoull(argv[++i]);
        } else if (arg == "--literal-search" && i + 1 < argc) {
            opt_literal_search = true;
            literal_search_value = std::stoull(argv[++i], nullptr, 16);
        } else if (arg == "--literal-search-range" && i + 2 < argc) {
            literal_search_start = std::stoull(argv[++i]);
            literal_search_end = std::stoull(argv[++i]);
        } else if (arg == "--no-parallel-scan") {
            opt_no_parallel_scan = true;
        } else if (arg == "--image" && i + 1 < argc) {
            image_path = argv[++i];
        } else if (arg == "--dump-memaccess" && i + 2 < argc) {
            opt_dump_memaccess = true;
            dump_ma_start = std::stoull(argv[++i]);
            dump_ma_count = std::stoull(argv[++i]);
        } else if (arg == "--dump-ma-strings") {
            dump_ma_strings = true;
        // ── P3 options ──────────────────────────────────────────────────────
        } else if (arg == "--cache-sim") {
            opt_cache_sim = true;
        } else if (arg == "--cache-sim-l1-size" && i + 1 < argc) {
            cache_sim_l1_size_kb = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--cache-sim-l2-size" && i + 1 < argc) {
            cache_sim_l2_size_kb = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--cache-sim-policy" && i + 1 < argc) {
            std::string pol = argv[++i];
            if (pol == "plru") cache_sim_policy = ReplacementPolicy::PLRU;
            else if (pol == "rand") cache_sim_policy = ReplacementPolicy::RAND;
            else cache_sim_policy = ReplacementPolicy::LRU;
        } else if (arg == "--cache-sim-no-sidechannel") {
            cache_sim_no_sidechannel = true;
        } else if (arg == "--yara-mem-scan") {
            opt_yara_mem_scan = true;
        } else if (arg == "--yara-rules" && i + 1 < argc) {
            yara_extra_rules.push_back(argv[++i]);
        } else if (arg == "--yara-min-entropy" && i + 1 < argc) {
            yara_min_entropy = std::stof(argv[++i]);
        } else if (arg == "--yara-scan-code") {
            yara_scan_code = true;
        } else if (arg == "--thread-filter") {
            opt_thread_filter = true;
            // Optional: --thread-filter 1234,5678  (comma-separated TIDs)
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string tids_str = argv[++i];
                std::string tok;
                for (char c : tids_str + ",") {
                    if (c == ',') {
                        if (!tok.empty()) {
                            thread_filter_ids.push_back(std::stoull(tok));
                            tok.clear();
                        }
                    } else {
                        tok.push_back(c);
                    }
                }
            }
        } else if (arg == "--rpc") {
            opt_rpc = true;
            // Optional: --rpc /tmp/my.sock
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                rpc_socket_path = argv[++i];
            }
        } else if (arg == "--streaming") {
            opt_streaming = true;
        } else if (arg == "--stats") {
            opt_stats_only = true;
        } else if (arg[0] != '-') {
            trace_path = arg;
        }
    }

    if (trace_path.empty()) {
        fmt::print(stderr, "Error: no trace file specified\n");
        print_usage(argv[0]);
        return 1;
    }

    // ─── Init logger ────────────────────────────────────────────────────
    tenet::log::init();
    LOG_INFO("tenet starting  pid={}", (int)getpid());

    // Determine if any analysis option was specified → suppress TUI
    bool has_analysis_option = !export_cfg_path.empty() || opt_taint ||
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
                               opt_rpc || opt_streaming || opt_stats_only;

    // ─── Open trace file ────────────────────────────────────────────────
    fmt::print("Opening trace: {}\n", trace_path);
    LOG_INFO("opening trace: {}", trace_path);
    auto t_open = TENET_TIMER_START();

    auto reader_result = TraceReader::open(trace_path);
    if (!reader_result) {
        fmt::print(stderr, "Error: {}\n", reader_result.error().message);
        return 1;
    }
    auto& reader = *reader_result;
    LOG_INFO("trace opened in {:.1f}ms  size={:.2f}MB",
             TENET_TIMER_MS(t_open),
             reader.file_size() / (1024.0 * 1024.0));

    const auto& hdr = reader.header();
    fmt::print("  Magic:     0x{:08X}\n", hdr.magic);
    fmt::print("  Version:   {}\n", hdr.version);
    fmt::print("  Arch:      {}\n", hdr.arch == 1 ? "AArch64" : "x86_64");
    fmt::print("  GPR count: {}\n", hdr.num_gpr);
    fmt::print("  Module:    {}\n", hdr.module_name);
    fmt::print("  Base:      0x{:016X}\n", hdr.module_base);
    fmt::print("  Slide:     0x{:016X}\n", hdr.module_slide);
    fmt::print("  Range:     0x{:016X} - 0x{:016X}\n", hdr.trace_start, hdr.trace_end);
    fmt::print("  File size: {:.2f} MB\n", reader.file_size() / (1024.0 * 1024.0));
    fmt::print("  Flags:     mem={} nzcv={} diff={} code={}\n",
               hdr.has_mem(), hdr.has_nzcv(), hdr.reg_diff(), hdr.has_code());
    fmt::print("\n");
    LOG_DEBUG("trace header: arch={} gpr={} module={} slide=0x{:X}",
              hdr.arch == 1 ? "AArch64" : "x86_64",
              hdr.num_gpr, hdr.module_name, hdr.module_slide);

    // ─── Build/load index ───────────────────────────────────────────────
    fmt::print("Building index...\n");
    LOG_INFO("building/loading RocksDB index");
    auto t_index = TENET_TIMER_START();

    auto index_result = TraceIndex::open_or_build(reader,
        [](uint64_t processed, uint64_t total) {
            if (total > 0) {
                double pct = 100.0 * processed / total;
                fmt::print("\r  Progress: {:.1f}%", pct);
                fflush(stdout);
            }
        });

    if (!index_result) {
        fmt::print(stderr, "\nError building index: {}\n", index_result.error().message);
        return 1;
    }
    auto& index = *index_result;
    fmt::print("\r  Done. {} instructions, {} anchors, built in {:.2f}s\n",
               index.stats().inst_count, index.stats().anchor_count,
               index.stats().build_seconds);
    LOG_INFO("index ready: {} instructions, {} anchors  ({:.1f}ms total)",
             index.stats().inst_count, index.stats().anchor_count,
             TENET_TIMER_MS(t_index));

    // ─── Integrity check ──────────────────────────────────────────────────
    {
        auto integrity = index.verify_integrity(reader);
        if (!integrity.ok) {
            fmt::print(stderr, "\n[WARNING] Index integrity check failed: {}\n",
                       integrity.error);
            fmt::print(stderr, "  The index may be corrupted and will be rebuilt.\n");
            // Integrity failure is non-fatal here: the index was already loaded
            // and is most likely still usable (hash mismatch is a soft warning).
            // A full rebuild would be triggered on the next open_or_build call.
        } else {
            LOG_DEBUG("index integrity OK");
        }
    }

    if (show_index_stats) {
        fmt::print("  Code records: {}\n", index.stats().code_count);
        fmt::print("  Event records: {}\n", index.stats().event_count);
        fmt::print("  Total records: {}\n", index.stats().total_records);
        fmt::print("\n");
    }

    // ─── Populate CodeTable from index (P1.9: zero extra file I/O) ──────
    // The index build already extracted all CODE records into the code_bytes CF
    // during the same single pass. load_code_table() reads from RocksDB instead
    // of scanning the trace file a second time.
    CodeTable code_table;
    fmt::print("Loading code table...\n");
    {
        TENET_SCOPE_TIMER("code_table_load");
        uint64_t loaded = index.load_code_table(code_table);
        if (loaded == 0) {
            // Fallback: old index (schema < v5) without CODE_BYTES CF.
            // Re-scan the trace file to populate the table.
            fmt::print("  (index has no code_bytes CF, falling back to trace scan)\n");
            for (auto it = reader.begin(); it != reader.end(); ++it) {
                auto rec = *it;
                if (rec.kind == RecordKind::Code) {
                    auto code = rec.as_code();
                    if (code.size == 4) {
                        uint32_t opcode = 0;
                        std::memcpy(&opcode, code.bytes, 4);
                        code_table.insert(code.pc, opcode);
                    }
                }
            }
        }
    }
    fmt::print("  Loaded {} distinct PCs\n\n", code_table.size());
    LOG_DEBUG("code table: {} distinct PCs", code_table.size());

    // ─── Record this trace in the recent-files list ──────────────────────
    {
        auto recent = RecentFiles::load();
        // Use absolute path for portability (resolve symlinks / relative paths)
        std::string abs_path = std::filesystem::absolute(trace_path).string();
        recent.push(abs_path, hdr.module_name, index.stats().inst_count);
        recent.save();
    }

    // ─── Load image fallback (optional) ─────────────────────────────
    if (!image_path.empty()) {
        auto img = std::make_shared<ImageFallback>();
        if (img->load(image_path, hdr.module_base)) {
            code_table.set_image_fallback(img);
            fmt::print("  Image fallback: {} segments loaded from {}\n",
                       img->segment_count(), image_path);
        } else {
            fmt::print(stderr, "  Warning: failed to load image fallback: {}\n", image_path);
        }
    }

    // ─── Initialize decoder ─────────────────────────────────────────────
    InstructionDecoder decoder;
    {
        auto t = TENET_TIMER_START();
        if (!decoder.init()) {
            fmt::print(stderr, "Error: failed to initialize Capstone\n");
            return 1;
        }
        LOG_DEBUG("Capstone decoder initialized in {:.1f}ms", TENET_TIMER_MS(t));
    }

    // ─── Initialize RegisterFile and MemoryModel ──────────────────────────
    RegisterFile regfile(reader, index);
    // Use RocksDB-backed MemoryModel for full memory read/write indexing.
    // This enables resolving pointer dereferences (e.g. ObjC selector strings,
    // NSData bytes) that were written by uninstrumented shared-cache code.
    MemoryModel memory(reader, index,
                       index.raw_db(), index.mem_write_cf(), index.mem_read_cf());
    LOG_DEBUG("RegisterFile + MemoryModel ready");

    // ─── Run analysis options (batch mode) ─────────────────────────────────
    if (has_analysis_option) {
        PassManager pm;
        pm.set_reader(&reader);
        pm.set_index(&index);
        pm.set_code_table(&code_table);
        pm.set_regfile(&regfile);
        pm.set_memory(&memory);
        pm.set_decoder(&decoder);
        pm.set_no_parallel_scan(opt_no_parallel_scan);

        // Register passes needed by the requested options
        // --export-cfg needs xref -> cfg -> cfg_layout
        if (!export_cfg_path.empty()) {
            pm.register_pass(std::make_unique<XrefPass>());
            pm.register_pass(std::make_unique<CFGPass>());
            pm.register_pass(std::make_unique<CFGLayoutPass>());
        }

        // --taint needs TaintPass with configured source reg + new options
        if (opt_taint) {
            TaintConfig taint_cfg;
            taint_cfg.add_source_reg(taint_reg_index);
            taint_cfg.source_inst_id = taint_source_inst_id;
            taint_cfg.source_mem_addrs = taint_source_mem_addrs;
            taint_cfg.max_taint_width = taint_max_width;
            taint_cfg.propagate_through_calls = !taint_no_calls;
            taint_cfg.use_xref_acceleration = !taint_no_xref;
            taint_cfg.emit_kill_events = !taint_no_kills;
            taint_cfg.stop_pcs = taint_stop_pcs;
            // XRef acceleration requires xref pass
            if (taint_cfg.use_xref_acceleration) {
                pm.register_pass(std::make_unique<XrefPass>());
            }
            pm.register_pass(std::make_unique<TaintPass>(std::move(taint_cfg)));
        }

        // --strings needs StringPass
        if (opt_strings) {
            pm.register_pass(std::make_unique<StringPass>());
        }

        // --pattern needs PatternPass
        if (opt_pattern) {
            pm.register_pass(std::make_unique<PatternPass>());
        }

        // --constants needs ConstantMaterializationPass
        if (opt_constants) {
            auto cmp = std::make_unique<ConstantMaterializationPass>();
            cmp->set_min_parts(constants_min_parts);
            pm.register_pass(std::move(cmp));
        }

        // --call-graph needs function -> call_graph
        if (!call_graph_path.empty()) {
            pm.register_pass(std::make_unique<FunctionPass>());
            pm.register_pass(std::make_unique<CallGraphPass>());
        }

        // --backward-taint needs BackwardTaintPass
        if (opt_backward_taint || opt_critical_path) {
            BackwardTaintConfig bt_cfg;
            bt_cfg.sink_inst_id = backward_taint_sink_id;
            bt_cfg.add_sink_reg(backward_taint_reg);
            bt_cfg.propagate_through_memory = true;
            bt_cfg.build_dataflow_graph = !backward_taint_graph_path.empty();
            bt_cfg.per_sink_tags = true;
            if (backward_taint_max_steps > 0) {
                bt_cfg.max_steps = backward_taint_max_steps;
            }
            pm.register_pass(std::make_unique<BackwardTaintPass>(std::move(bt_cfg)));
        }

        // --trace-diff
        if (opt_trace_diff) {
            TraceDiffConfig td_cfg;
            td_cfg.trace_a_start = trace_diff_a_start;
            td_cfg.trace_a_end = trace_diff_a_end;
            td_cfg.trace_b_start = trace_diff_b_start;
            td_cfg.trace_b_end = trace_diff_b_end;
            pm.register_pass(std::make_unique<TraceDiffPass>(std::move(td_cfg)));
        }

        // --loop-semantics needs loop pass
        if (opt_loop_semantics) {
            pm.register_pass(std::make_unique<LoopPass>());
            pm.register_pass(std::make_unique<LoopSemanticsPass>());
        }

        // --symbol-annotation needs function, loop, constant_materialization, pattern
        if (opt_symbol_annotation) {
            pm.register_pass(std::make_unique<FunctionPass>());
            pm.register_pass(std::make_unique<LoopPass>());
            pm.register_pass(std::make_unique<ConstantMaterializationPass>());
            pm.register_pass(std::make_unique<PatternPass>());
            pm.register_pass(std::make_unique<SymbolAnnotationPass>());
        }

        // --memory-snapshot
        if (opt_memory_snapshot) {
            MemorySnapshotConfig ms_cfg;
            ms_cfg.snapshot_inst_ids = memory_snapshot_ids;
            ms_cfg.snapshot_size = memory_snapshot_size;
            pm.register_pass(std::make_unique<MemorySnapshotPass>(std::move(ms_cfg)));
        }

        // --memory-strings
        if (opt_memory_strings) {
            MemoryStringConfig mstr_cfg;
            mstr_cfg.max_call_sites = memory_strings_max_sites;
            mstr_cfg.scan_size = memory_strings_scan_size;
            pm.register_pass(std::make_unique<MemoryStringPass>(std::move(mstr_cfg)));
        }

        // --dataflow-graph
        if (opt_dataflow_graph) {
            DataflowGraphConfig dg_cfg;
            dg_cfg.start_inst_id = dataflow_start;
            dg_cfg.end_inst_id = dataflow_end;
            pm.register_pass(std::make_unique<DataflowGraphPass>(std::move(dg_cfg)));
        }

        // --algorithm-summary needs pattern, constant_materialization, loop_semantics, function, call_graph
        if (opt_algorithm_summary) {
            pm.register_pass(std::make_unique<PatternPass>());
            pm.register_pass(std::make_unique<ConstantMaterializationPass>());
            pm.register_pass(std::make_unique<LoopPass>());
            pm.register_pass(std::make_unique<LoopSemanticsPass>());
            pm.register_pass(std::make_unique<FunctionPass>());
            pm.register_pass(std::make_unique<CallGraphPass>());
            pm.register_pass(std::make_unique<AlgorithmSummaryPass>());
        }

        // --objc
        if (opt_objc) {
            auto objc_pass = std::make_unique<ObjcPass>();
            if (!objc_class_filter.empty()) {
                objc_pass->set_class_filter(objc_class_filter);
            }
            pm.register_pass(std::move(objc_pass));
        }

        // --critical-path also needs forward taint
        if (opt_critical_path && !opt_taint) {
            TaintConfig taint_cfg;
            taint_cfg.add_source_reg(backward_taint_reg);
            taint_cfg.source_inst_id = taint_source_inst_id;
            taint_cfg.propagate_through_calls = !taint_no_calls;
            taint_cfg.use_xref_acceleration = !taint_no_xref;
            if (taint_cfg.use_xref_acceleration) {
                pm.register_pass(std::make_unique<XrefPass>());
            }
            pm.register_pass(std::make_unique<TaintPass>(std::move(taint_cfg)));
        }

        // Execute requested analysis passes
        int rc = 0;

        if (!export_cfg_path.empty()) {
            rc |= run_export_cfg(pm, decoder, code_table, export_cfg_path);
        }

        if (opt_taint) {
            rc |= run_taint(pm, taint_reg_index);
        }

        if (opt_strings) {
            rc |= run_strings(pm);
        }

        if (opt_pattern) {
            rc |= run_pattern(pm);
        }

        if (opt_constants) {
            const auto& cm_raw = pm.require("constant_materialization");
            if (!cm_raw.ok()) {
                fmt::print(stderr, "[constants] Constant materialization pass failed: {}\n",
                           cm_raw.error_message);
                rc |= 1;
            } else {
                const auto& cm_result = cm_raw.get<ConstantMaterializationResult>();
                fmt::print("[constants] Found {} materialized constants ({} identified as known)\n\n",
                           cm_result.total(), cm_result.identified_count());

                // Print identified (known) constants first
                if (!cm_result.identified_indices.empty()) {
                    fmt::print("  === Identified Algorithm Constants ===\n");
                    fmt::print("  {:<18} {:<6} {:<12} {:<20} {}\n",
                               "VALUE", "REG", "ALGORITHM", "NAME", "INST_RANGE");
                    for (size_t idx : cm_result.identified_indices) {
                        const auto& c = cm_result.constants[idx];
                        fmt::print("  0x{:016X} x{:<4} {:<12} {:<20} #{}-#{}\n",
                                   c.value, c.dst_reg,
                                   c.known_match->algorithm,
                                   c.known_match->name,
                                   c.first_inst_id, c.last_inst_id);
                    }
                    fmt::print("\n");
                }

                // Summary by algorithm
                if (!cm_result.by_algorithm.empty()) {
                    fmt::print("  === Summary by Algorithm ===\n");
                    for (const auto& [algo, indices] : cm_result.by_algorithm) {
                        fmt::print("  {}: {} constants\n", algo, indices.size());
                    }
                    fmt::print("\n");
                }

                // Print all constants (summary)
                fmt::print("  === All Materialized Constants (top 200) ===\n");
                fmt::print("  {:<18} {:<6} {:<6} {:<14} {}\n",
                           "VALUE", "REG", "PARTS", "INST_RANGE", "KNOWN_AS");
                size_t limit = std::min(cm_result.constants.size(), size_t(200));
                for (size_t i = 0; i < limit; i++) {
                    const auto& c = cm_result.constants[i];
                    std::string known_str = c.known_match
                        ? fmt::format("{} ({})", c.known_match->name, c.known_match->algorithm)
                        : "-";
                    fmt::print("  0x{:016X} x{:<4} {:<6} #{:<5}-#{:<5} {}\n",
                               c.value, c.dst_reg, c.num_parts,
                               c.first_inst_id, c.last_inst_id, known_str);
                }
                if (cm_result.constants.size() > 200) {
                    fmt::print("  ... and {} more\n", cm_result.constants.size() - 200);
                }
            }
        }

        if (!call_graph_path.empty()) {
            rc |= run_call_graph(pm, call_graph_path);
        }

        if (opt_backward_taint) {
            rc |= run_backward_taint(pm, backward_taint_sink_id, backward_taint_reg);

            // Export dataflow graph if requested
            if (!backward_taint_graph_path.empty()) {
                const auto& bt_raw = pm.require("backward_taint");
                if (bt_raw.ok()) {
                    const auto& bt_result = bt_raw.get<BackwardTaintResult>();
                    bool is_json = (backward_taint_graph_path.size() >= 5 &&
                        backward_taint_graph_path.substr(
                            backward_taint_graph_path.size() - 5) == ".json");
                    std::ofstream gout(backward_taint_graph_path);
                    if (gout.is_open()) {
                        if (is_json) {
                            gout << bt_result.to_graph_json();
                        } else {
                            gout << bt_result.to_dot();
                        }
                        gout.close();
                        fmt::print(stderr, "[backward-taint-graph] {} nodes, {} edges -> {}\n",
                                   bt_result.events.size(), bt_result.dataflow_edges.size(),
                                   backward_taint_graph_path);
                    }
                }
            }
        }

        // --critical-path: intersect forward and backward taint
        if (opt_critical_path && opt_backward_taint) {
            const auto& bt_raw = pm.require("backward_taint");
            const auto& ft_raw = pm.require("taint");
            if (bt_raw.ok() && ft_raw.ok()) {
                const auto& bt_result = bt_raw.get<BackwardTaintResult>();
                const auto& ft_result = ft_raw.get<TaintResult>();
                auto cp = bt_result.critical_path(ft_result);
                json cp_output;
                cp_output["critical_path_count"] = cp.cardinality();
                cp_output["backward_count"] = bt_result.contributing_count();
                cp_output["forward_count"] = ft_result.tainted_inst_count();
                // List first 200 critical path instruction IDs
                json ids_arr = json::array();
                uint64_t count = 0;
                for (auto it = cp.begin(); it != cp.end() && count < 200; ++it, ++count) {
                    ids_arr.push_back(*it);
                }
                cp_output["instruction_ids"] = std::move(ids_arr);
                if (cp.cardinality() > 200) cp_output["truncated"] = true;
                fmt::print("{}\n", cp_output.dump(2));
            }
        }

        // --trace-diff: output JSON
        if (opt_trace_diff) {
            const auto& td_raw = pm.require("trace_diff");
            if (!td_raw.ok()) {
                fmt::print(stderr, "[trace-diff] Pass failed: {}\n", td_raw.error_message);
                rc |= 1;
            } else {
                const auto& td_result = td_raw.get<TraceDiffResult>();
                fmt::print(stderr, "[trace-diff] {} diverged, {} register diffs, {} control-flow diffs\n",
                           td_result.diverged_count, td_result.register_value_diffs().size(),
                           td_result.control_flow_diffs().size());
                json td_json;
                td_json["diverged_count"] = td_result.diverged_count;
                td_json["matched_count"] = td_result.matched_count;
                td_json["has_divergence"] = td_result.has_divergence();
                json diffs_arr = json::array();
                size_t limit = std::min(td_result.diffs.size(), size_t(500));
                for (size_t i = 0; i < limit; i++) {
                    const auto& d = td_result.diffs[i];
                    diffs_arr.push_back({
                        {"pc", fmt::format("0x{:X}", d.pc)},
                        {"offset_a", d.inst_offset_a},
                        {"offset_b", d.inst_offset_b},
                        {"type", static_cast<int>(d.type)},
                        {"detail", d.detail}
                    });
                }
                td_json["diffs"] = std::move(diffs_arr);
                if (td_result.diffs.size() > 500) td_json["truncated"] = true;
                fmt::print("{}\n", td_json.dump(2));
            }
        }

        // --loop-semantics
        if (opt_loop_semantics) {
            const auto& ls_raw = pm.require("loop_semantics");
            if (!ls_raw.ok()) {
                fmt::print(stderr, "[loop-semantics] Pass failed: {}\n", ls_raw.error_message);
                rc |= 1;
            } else {
                const auto& ls_result = ls_raw.get<LoopSemanticsResult>();
                fmt::print(stderr, "[loop-semantics] {} loops analyzed, {} Feistel, {} crypto\n",
                           ls_result.loop_semantics.size(),
                           ls_result.feistel_loops().size(),
                           ls_result.crypto_loops().size());
                json ls_json;
                json loops_arr = json::array();
                for (const auto& l : ls_result.loop_semantics) {
                    json lj;
                    lj["pc"] = fmt::format("0x{:X}", l.header_pc);
                    lj["iteration_count"] = l.iteration_count;
                    lj["kind"] = loop_kind_name(l.kind);
                    lj["confidence"] = l.confidence;
                    lj["description"] = l.description;
                    lj["body_instruction_count"] = l.body_instruction_count;
                    lj["has_sbox_pattern"] = l.has_sbox_pattern;
                    lj["has_xor_mix"] = l.has_xor_mix;
                    lj["has_shift_rotate"] = l.has_shift_rotate;
                    loops_arr.push_back(std::move(lj));
                }
                ls_json["loops"] = std::move(loops_arr);
                fmt::print("{}\n", ls_json.dump(2));
            }
        }

        // --symbol-annotation
        if (opt_symbol_annotation) {
            const auto& sa_raw = pm.require("symbol_annotation");
            if (!sa_raw.ok()) {
                fmt::print(stderr, "[symbol-annotation] Pass failed: {}\n", sa_raw.error_message);
                rc |= 1;
            } else {
                const auto& sa_result = sa_raw.get<AnnotationResult>();
                fmt::print(stderr, "[symbol-annotation] {} PCs annotated\n",
                           sa_result.by_pc.size());
                json sa_json;
                json ann_arr = json::array();
                size_t count = 0;
                for (const auto& [pc, annotations] : sa_result.by_pc) {
                    if (count >= 1000) break;
                    for (const auto& a : annotations) {
                        ann_arr.push_back({
                            {"pc", fmt::format("0x{:X}", pc)},
                            {"label", a.label},
                            {"detail", a.detail},
                            {"kind", static_cast<int>(a.kind)}
                        });
                    }
                    count++;
                }
                sa_json["annotations"] = std::move(ann_arr);
                sa_json["total_pcs"] = sa_result.by_pc.size();
                if (sa_result.by_pc.size() > 1000) sa_json["truncated"] = true;
                fmt::print("{}\n", sa_json.dump(2));
            }
        }

        // --memory-snapshot
        if (opt_memory_snapshot) {
            const auto& ms_raw = pm.require("memory_snapshot");
            if (!ms_raw.ok()) {
                fmt::print(stderr, "[memory-snapshot] Pass failed: {}\n", ms_raw.error_message);
                rc |= 1;
            } else {
                const auto& ms_result = ms_raw.get<MemorySnapshotResult>();
                fmt::print(stderr, "[memory-snapshot] {} snapshots captured\n", ms_result.total());
                json ms_json;
                json snaps_arr = json::array();
                for (const auto& r : ms_result.snapshots) {
                    snaps_arr.push_back({
                        {"addr", fmt::format("0x{:X}", r.addr)},
                        {"at_inst_id", r.at_inst_id},
                        {"label", r.label},
                        {"hex", MemorySnapshotResult::hex_dump(r)}
                    });
                }
                ms_json["snapshots"] = std::move(snaps_arr);
                ms_json["total"] = ms_result.total();
                fmt::print("{}\n", ms_json.dump(2));
            }
        }

        // --memory-strings
        if (opt_memory_strings) {
            const auto& mstr_raw = pm.require("memory_strings");
            if (!mstr_raw.ok()) {
                fmt::print(stderr, "[memory-strings] Pass failed: {}\n", mstr_raw.error_message);
                rc |= 1;
            } else {
                const auto& mstr_result = mstr_raw.get<MemoryStringResult>();
                fmt::print(stderr, "[memory-strings] {} strings ({} unique content)\n",
                           mstr_result.total(), mstr_result.unique_count());

                json mstr_json;
                json strings_arr = json::array();
                for (const auto& s : mstr_result.strings) {
                    json entry;
                    entry["addr"] = fmt::format("0x{:X}", s.addr);
                    entry["content"] = s.content;
                    entry["length"] = s.content.size();
                    entry["discovered_at"] = s.discovered_at;
                    entry["call_site_inst_id"] = s.call_site_inst_id;
                    entry["call_site_pc"] = fmt::format("0x{:X}", s.call_site_pc);
                    entry["encoding"] = (s.encoding == MemoryString::ASCII ? "ascii" :
                                         s.encoding == MemoryString::UTF8 ? "utf8" : "utf16le");
                    entry["source"] = (s.source == MemoryString::RegPointer ? "reg_pointer" :
                                       s.source == MemoryString::StackLocal ? "stack_local" :
                                       s.source == MemoryString::DeepProbe ? "deep_probe" :
                                       "page_scan");
                    if (s.source_reg < 8) {
                        entry["source_reg"] = fmt::format("x{}", s.source_reg);
                    } else if (s.source_reg == 31) {
                        entry["source_reg"] = "sp";
                    }
                    strings_arr.push_back(std::move(entry));
                }
                mstr_json["strings"] = std::move(strings_arr);
                mstr_json["total"] = mstr_result.total();
                mstr_json["unique_count"] = mstr_result.unique_count();
                fmt::print("{}\n", mstr_json.dump(2));
            }
        }

        // --dataflow-graph
        if (opt_dataflow_graph) {
            const auto& dg_raw = pm.require("dataflow_graph");
            if (!dg_raw.ok()) {
                fmt::print(stderr, "[dataflow-graph] Pass failed: {}\n", dg_raw.error_message);
                rc |= 1;
            } else {
                const auto& dg_result = dg_raw.get<DataflowGraphResult>();
                fmt::print(stderr, "[dataflow-graph] {} nodes, {} edges\n",
                           dg_result.nodes.size(), dg_result.edges.size());
                if (!dataflow_output_path.empty()) {
                    bool is_json = (dataflow_output_path.size() >= 5 &&
                        dataflow_output_path.substr(dataflow_output_path.size() - 5) == ".json");
                    std::ofstream dg_out(dataflow_output_path);
                    if (dg_out.is_open()) {
                        if (is_json) {
                            dg_out << dg_result.to_json();
                        } else {
                            dg_out << dg_result.to_dot();
                        }
                        dg_out.close();
                        fmt::print(stderr, "[dataflow-graph] -> {}\n", dataflow_output_path);
                    }
                } else {
                    fmt::print("{}\n", dg_result.to_json());
                }
            }
        }

        // --algorithm-summary
        if (opt_algorithm_summary) {
            const auto& as_raw = pm.require("algorithm_summary");
            if (!as_raw.ok()) {
                fmt::print(stderr, "[algorithm-summary] Pass failed: {}\n", as_raw.error_message);
                rc |= 1;
            } else {
                const auto& as_result = as_raw.get<AlgorithmSummaryResult>();
                fmt::print(stderr, "[algorithm-summary] {} algorithms detected, has_crypto={}\n",
                           as_result.total(), as_result.has_crypto());
                fmt::print("{}\n", as_result.summary_json.dump(2));
            }
        }

        // --objc
        if (opt_objc) {
            const auto& oc_raw = pm.require("objc");
            if (!oc_raw.ok()) {
                fmt::print(stderr, "[objc] Pass failed: {}\n", oc_raw.error_message);
                rc |= 1;
            } else {
                const auto& oc_result = oc_raw.get<ObjcResult>();
                fmt::print(stderr, "[objc] {} messages, {} classes\n",
                           oc_result.total_messages(), oc_result.unique_classes());
                fmt::print("{}\n", oc_result.to_json().dump(2));
            }
        }

        // --memread: read memory at a specific point in time
        if (opt_memread) {
            auto mem_result = memory.read(memread_addr, memread_size, memread_inst_id);
            json output;
            output["addr"] = fmt::format("0x{:X}", memread_addr);
            output["size"] = memread_size;
            output["at_inst_id"] = memread_inst_id;

            // Build hex string and per-byte info
            std::string hex_str;
            json bytes_arr = json::array();
            for (uint8_t i = 0; i < memread_size; i++) {
                json byte_info;
                byte_info["offset"] = i;
                byte_info["addr"] = fmt::format("0x{:X}", memread_addr + i);
                if (mem_result.known[i]) {
                    byte_info["value"] = fmt::format("0x{:02X}", mem_result.data[i]);
                    byte_info["writer_inst_id"] = mem_result.writer_id[i];
                    hex_str += fmt::format("{:02X} ", mem_result.data[i]);
                } else {
                    byte_info["value"] = "??";
                    hex_str += "?? ";
                }
                bytes_arr.push_back(std::move(byte_info));
            }
            output["hex"] = hex_str;
            output["bytes"] = std::move(bytes_arr);
            fmt::print("{}\n", output.dump(2));
        }

        // --mem-history: find all writes to an address
        if (opt_mem_history) {
            auto history = memory.write_history(mem_history_addr, mem_history_size);
            json output;
            output["addr"] = fmt::format("0x{:X}", mem_history_addr);
            output["size"] = mem_history_size;
            output["write_count"] = history.size();

            json writes_arr = json::array();
            size_t limit = std::min(history.size(), size_t(500));
            for (size_t i = 0; i < limit; i++) {
                json w;
                w["inst_id"] = history[i];
                // Get the PC at this instruction via offset_of_with_pc + record_at
                auto [off, seed_pc_w] = index.offset_of_with_pc(history[i], reader);
                if (off != 0) {
                    auto rec = reader.record_at(off, seed_pc_w);
                    if (rec.kind == RecordKind::Inst) {
                        auto inst = rec.as_inst();
                        w["pc"] = fmt::format("0x{:X}", inst.pc);
                    }
                }
                writes_arr.push_back(std::move(w));
            }
            output["writes"] = std::move(writes_arr);
            if (history.size() > 500) {
                output["truncated"] = true;
                output["total_writes"] = history.size();
            }
            fmt::print("{}\n", output.dump(2));
        }

        // --search-pc: find all instructions visiting a PC (linear scan with index assist)
        if (opt_search_pc) {
            json output;
            output["pc"] = fmt::format("0x{:X}", search_pc_addr);

            // Linear scan through trace to find matching PCs
            // (uses mmap sequential access — efficient for this query)
            std::vector<uint64_t> inst_ids;
            uint64_t inst_id = 0;
            reader.advise_sequential();
            for (auto it = reader.begin(); it != reader.end(); ++it) {
                auto rec = *it;
                if (rec.kind == RecordKind::Inst) {
                    auto inst = rec.as_inst();
                    if (inst.pc == search_pc_addr) {
                        inst_ids.push_back(inst_id);
                        if (inst_ids.size() >= search_pc_limit) break;
                    }
                    inst_id++;
                }
            }
            reader.advise_random();

            output["hit_count"] = inst_ids.size();
            json ids_arr = json::array();
            for (auto id : inst_ids) {
                ids_arr.push_back(id);
            }
            output["instruction_ids"] = std::move(ids_arr);
            if (inst_ids.size() >= search_pc_limit) {
                output["limit_reached"] = true;
            }
            fmt::print("{}\n", output.dump(2));
        }

        // --dump-memaccess: dump memory reads/writes + register ASCII in inst_id range
        //
        // Scans trace INST and ANCHOR records in [start, start+count) and extracts:
        // 1. Every memory access (read/write) with its data bytes
        // 2. Every register value that decodes as ASCII (≥4 printable chars)
        //
        // Key design: register state is tracked CONTINUOUSLY from the beginning
        // of the trace (not just within the range). ANCHOR records provide full
        // GPR snapshots when returning from uninstrumented code (shared cache),
        // and reg_diffs provide deltas. This captures ASCII fragments set by
        // shared-cache code (e.g. ObjC method return values, JSON fragments in
        // argument registers) even when the ANCHOR appears before the range.
        if (opt_dump_memaccess) {
            uint64_t ma_end = dump_ma_start + dump_ma_count;
            json output;
            output["start_inst"] = dump_ma_start;
            output["end_inst"] = ma_end;

            struct MemAccEntry {
                uint64_t inst_id;
                uint64_t addr;
                uint16_t size;
                uint8_t  type;
                uint8_t  data[16];
            };
            std::vector<MemAccEntry> entries;

            struct RegStrEntry {
                uint64_t inst_id;
                uint8_t  reg_index;
                uint64_t value;
                std::string str;
            };
            std::vector<RegStrEntry> reg_strings;

            // Continuous register state tracker
            constexpr uint32_t MAX_REGS = 34;
            uint64_t tracked_regs[MAX_REGS] = {};
            bool regs_valid = false;
            uint64_t last_emitted_val[MAX_REGS] = {};
            bool last_emitted_ok[MAX_REGS] = {};

            auto try_decode_ascii = [](uint64_t value) -> std::optional<std::string> {
                uint8_t bytes[8];
                std::memcpy(bytes, &value, 8);
                std::string str;
                for (int b = 0; b < 8; b++) {
                    if (bytes[b] >= 0x20 && bytes[b] <= 0x7e)
                        str.push_back(static_cast<char>(bytes[b]));
                    else if (bytes[b] == 0) break;
                    else break;
                }
                if (str.size() < 4) return std::nullopt;
                return str;
            };

            auto emit_if_ascii = [&](uint64_t inst, uint8_t idx, uint64_t val) {
                if (idx >= 32) return;
                if (last_emitted_ok[idx] && last_emitted_val[idx] == val) return;
                auto s = try_decode_ascii(val);
                if (s) {
                    reg_strings.push_back({inst, idx, val, *s});
                    last_emitted_val[idx] = val;
                    last_emitted_ok[idx] = true;
                }
            };

            uint64_t cur_inst = 0;
            reader.advise_sequential();
            for (auto it = reader.begin(); it != reader.end(); ++it) {
                auto rec = *it;
                if (rec.kind == RecordKind::Inst) {
                    if (cur_inst >= ma_end) break;
                    auto inst = rec.as_inst();

                    // Apply reg_diffs to tracked state (always)
                    for (uint8_t r = 0; r < inst.reg_diff_count; r++) {
                        auto rd = inst.reg_diff(r);
                        if (rd.index < MAX_REGS) tracked_regs[rd.index] = rd.value;
                    }
                    regs_valid = true;

                    if (cur_inst >= dump_ma_start) {
                        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                            auto ma = inst.mem_access(m);
                            if (ma.flags & 0x4) continue;
                            MemAccEntry e;
                            e.inst_id = cur_inst;
                            e.addr = ma.addr;
                            e.size = ma.size;
                            e.type = ma.type;
                            uint16_t csz = std::min((uint16_t)16, ma.size);
                            std::memcpy(e.data, &ma.value, std::min((uint16_t)8, csz));
                            if (csz > 8) std::memcpy(e.data + 8, &ma.value_hi, csz - 8);
                            entries.push_back(e);
                        }
                        if (regs_valid) {
                            for (uint32_t g = 0; g < 32 && g < hdr.num_gpr; g++)
                                emit_if_ascii(cur_inst, (uint8_t)g, tracked_regs[g]);
                        }
                    }
                    cur_inst++;
                } else if (rec.kind == RecordKind::Anchor) {
                    auto anchor = rec.as_anchor(hdr.num_gpr);
                    for (uint32_t g = 0; g < anchor.num_gpr && g < MAX_REGS; g++)
                        tracked_regs[g] = anchor.gpr_values[g];
                    regs_valid = true;
                    if (cur_inst >= dump_ma_start && cur_inst < ma_end && regs_valid) {
                        for (uint32_t g = 0; g < 32 && g < hdr.num_gpr; g++)
                            emit_if_ascii(cur_inst, (uint8_t)g, tracked_regs[g]);
                    }
                }
            }
            reader.advise_random();

            output["access_count"] = entries.size();

            // Build memory snapshot from writes, overlay reads
            std::map<uint64_t, uint8_t> mem_snap;
            for (auto& e : entries) {
                bool is_w = (e.type & 0x2), is_r = (e.type & 0x1);
                if (!is_w && !is_r) continue;
                for (uint16_t i = 0; i < e.size && i < 16; i++) {
                    if (is_w) mem_snap[e.addr + i] = e.data[i];
                    else if (is_r && mem_snap.find(e.addr + i) == mem_snap.end())
                        mem_snap[e.addr + i] = e.data[i];
                }
            }

            // Extract contiguous regions and decode strings
            json regions_arr = json::array();
            if (!mem_snap.empty()) {
                auto it = mem_snap.begin();
                while (it != mem_snap.end()) {
                    uint64_t start = it->first;
                    std::vector<uint8_t> data;
                    data.push_back(it->second);
                    ++it;
                    while (it != mem_snap.end() && it->first == start + data.size()) {
                        data.push_back(it->second);
                        ++it;
                    }
                    if (data.size() < 4) continue;
                    json r;
                    r["addr"] = fmt::format("0x{:X}", start);
                    r["size"] = data.size();
                    std::string hex;
                    for (uint8_t b : data) hex += fmt::format("{:02x}", b);
                    r["hex"] = hex;
                    std::string ascii;
                    bool ok = true;
                    int pc = 0;
                    for (uint8_t b : data) {
                        if (b >= 0x20 && b <= 0x7e) { ascii.push_back((char)b); pc++; }
                        else if (b == 0) break;
                        else { ok = false; break; }
                    }
                    if (ok && pc >= 4) r["string"] = ascii;
                    regions_arr.push_back(std::move(r));
                }
            }

            if (dump_ma_strings) {
                json sa = json::array();
                for (auto& r : regions_arr) if (r.contains("string")) sa.push_back(r);
                json ra = json::array();
                for (auto& rs : reg_strings) {
                    ra.push_back({{"inst_id", rs.inst_id},
                                  {"reg", fmt::format("x{}", rs.reg_index)},
                                  {"value", fmt::format("0x{:x}", rs.value)},
                                  {"string", rs.str}});
                }
                output["mem_strings"] = std::move(sa);
                output["mem_string_count"] = output["mem_strings"].size();
                output["reg_strings"] = std::move(ra);
                output["reg_string_count"] = output["reg_strings"].size();
            } else {
                json aa = json::array();
                for (auto& e : entries) {
                    json a;
                    a["inst_id"] = e.inst_id;
                    a["addr"] = fmt::format("0x{:X}", e.addr);
                    a["size"] = e.size;
                    std::string ts;
                    if (e.type & 0x1) ts += "R";
                    if (e.type & 0x2) ts += "W";
                    a["type"] = ts;
                    std::string hex;
                    for (uint16_t i = 0; i < e.size && i < 16; i++)
                        hex += fmt::format("{:02x}", e.data[i]);
                    a["hex"] = hex;
                    aa.push_back(std::move(a));
                }
                output["accesses"] = std::move(aa);
                output["regions"] = std::move(regions_arr);
            }
            fmt::print("{}\n", output.dump(2));
        }

        // --trace-fold: fold repetitive loop iterations
        if (opt_trace_fold) {
            pm.register_pass(std::make_unique<LoopPass>());
            pm.register_pass(std::make_unique<XrefPass>());
            TraceFoldConfig tf_cfg;
            tf_cfg.min_iterations_to_fold = trace_fold_min_iter;
            pm.register_pass(std::make_unique<TraceFoldPass>(std::move(tf_cfg)));
            const auto& tf_raw = pm.require("trace_fold");
            if (!tf_raw.ok()) {
                fmt::print(stderr, "[trace-fold] Pass failed: {}\n", tf_raw.error_message);
                rc |= 1;
            } else {
                const auto& tf_result = tf_raw.get<TraceFoldResult>();
                fmt::print(stderr, "[trace-fold] {} foldable regions, {} total folded instructions\n",
                           tf_result.folded_regions.size(), tf_result.total_instructions_removed);
                json tf_json;
                json regions_arr = json::array();
                for (const auto& r : tf_result.folded_regions) {
                    regions_arr.push_back({
                        {"loop_header_pc", fmt::format("0x{:X}", r.header_pc)},
                        {"iteration_count", r.total_iterations},
                        {"first_inst_id", r.first_inst_id},
                        {"last_inst_id", r.last_inst_id},
                        {"instructions_per_iteration", r.instructions_per_iteration}
                    });
                }
                tf_json["regions"] = std::move(regions_arr);
                tf_json["total_folded"] = tf_result.total_instructions_removed;
                fmt::print("{}\n", tf_json.dump(2));
            }
        }

        // --reg-timeline: track register value changes over time
        if (opt_reg_timeline) {
            RegTimelineConfig rt_cfg;
            rt_cfg.target_reg = reg_timeline_reg;
            rt_cfg.start_inst_id = reg_timeline_start;
            rt_cfg.end_inst_id = reg_timeline_end;
            pm.register_pass(std::make_unique<RegTimelinePass>(std::move(rt_cfg)));
            const auto& rt_raw = pm.require("reg_timeline");
            if (!rt_raw.ok()) {
                fmt::print(stderr, "[reg-timeline] Pass failed: {}\n", rt_raw.error_message);
                rc |= 1;
            } else {
                const auto& rt_result = rt_raw.get<RegTimelineResult>();
                fmt::print(stderr, "[reg-timeline] x{}: {} change events\n",
                           reg_timeline_reg, rt_result.entries.size());
                json rt_json;
                json events_arr = json::array();
                size_t limit = std::min(rt_result.entries.size(), size_t(2000));
                for (size_t i = 0; i < limit; i++) {
                    const auto& e = rt_result.entries[i];
                    events_arr.push_back({
                        {"inst_id", e.inst_id},
                        {"pc", fmt::format("0x{:X}", e.pc)},
                        {"old_value", fmt::format("0x{:X}", e.old_value)},
                        {"new_value", fmt::format("0x{:X}", e.new_value)}
                    });
                }
                rt_json["register"] = reg_timeline_reg;
                rt_json["events"] = std::move(events_arr);
                rt_json["total_changes"] = rt_result.entries.size();
                if (rt_result.entries.size() > 2000) rt_json["truncated"] = true;
                fmt::print("{}\n", rt_json.dump(2));
            }
        }

        // --mem-search: Boyer-Moore-Horspool multi-pattern memory search
        if (opt_mem_search) {
            MemSearchConfig ms_cfg;
            // Parse hex pattern string into bytes and add as a Pattern
            {
                std::vector<uint8_t> pat_bytes;
                std::string hex = mem_search_pattern;
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    pat_bytes.push_back((uint8_t)std::stoul(hex.substr(i, 2), nullptr, 16));
                }
                ms_cfg.patterns.emplace_back(std::move(pat_bytes), mem_search_pattern);
            }
            ms_cfg.start_inst_id = mem_search_start;
            ms_cfg.end_inst_id = mem_search_end;
            pm.register_pass(std::make_unique<MemSearchPass>(std::move(ms_cfg)));
            const auto& ms_raw = pm.require("mem_search");
            if (!ms_raw.ok()) {
                fmt::print(stderr, "[mem-search] Pass failed: {}\n", ms_raw.error_message);
                rc |= 1;
            } else {
                const auto& ms_result = ms_raw.get<MemSearchResult>();
                fmt::print(stderr, "[mem-search] {} matches found\n", ms_result.matches.size());
                json ms_json;
                json matches_arr = json::array();
                size_t limit = std::min(ms_result.matches.size(), size_t(500));
                for (size_t i = 0; i < limit; i++) {
                    const auto& m = ms_result.matches[i];
                    matches_arr.push_back({
                        {"addr", fmt::format("0x{:X}", m.addr)},
                        {"inst_id", m.inst_id},
                        {"pc", fmt::format("0x{:X}", m.pc)},
                        {"source", m.source == MemSearchMatch::MemWrite ? "mem" : "reg"}
                    });
                }
                ms_json["matches"] = std::move(matches_arr);
                ms_json["total"] = ms_result.matches.size();
                if (ms_result.matches.size() > 500) ms_json["truncated"] = true;
                fmt::print("{}\n", ms_json.dump(2));
            }
        }

        // --call-context: reconstruct call stack at a specific instruction
        if (opt_call_context) {
            pm.register_pass(std::make_unique<LoopPass>());
            CallContextConfig cc_cfg;
            cc_cfg.target_inst_id = call_context_inst_id;
            pm.register_pass(std::make_unique<CallContextPass>(std::move(cc_cfg)));
            const auto& cc_raw = pm.require("call_context");
            if (!cc_raw.ok()) {
                fmt::print(stderr, "[call-context] Pass failed: {}\n", cc_raw.error_message);
                rc |= 1;
            } else {
                const auto& cc_result = cc_raw.get<CallContextResult>();
                fmt::print(stderr, "[call-context] stack depth={}\n", cc_result.call_stack.size());
                json cc_json;
                json frames_arr = json::array();
                for (const auto& f : cc_result.call_stack) {
                    frames_arr.push_back({
                        {"call_site_pc", fmt::format("0x{:X}", f.call_site_pc)},
                        {"callee_pc", fmt::format("0x{:X}", f.callee_pc)},
                        {"call_inst_id", f.call_inst_id},
                        {"return_addr", fmt::format("0x{:X}", f.return_addr)}
                    });
                }
                cc_json["target_inst_id"] = call_context_inst_id;
                cc_json["frames"] = std::move(frames_arr);
                cc_json["depth"] = cc_result.call_stack.size();
                fmt::print("{}\n", cc_json.dump(2));
            }
        }

        // --producer-chain: backward reg_diff chain tracing
        if (opt_producer_chain) {
            ProducerChainConfig pc_cfg;
            pc_cfg.start_inst_id = producer_chain_inst_id;
            pc_cfg.start_reg = producer_chain_reg;
            pc_cfg.max_depth = producer_chain_depth;
            pm.register_pass(std::make_unique<ProducerChainPass>(std::move(pc_cfg)));
            const auto& pc_raw = pm.require("producer_chain");
            if (!pc_raw.ok()) {
                fmt::print(stderr, "[producer-chain] Pass failed: {}\n", pc_raw.error_message);
                rc |= 1;
            } else {
                const auto& pc_result = pc_raw.get<ProducerChainResult>();
                fmt::print(stderr, "[producer-chain] {} nodes in chain\n", pc_result.chain.size());
                json pc_json;
                json chain_arr = json::array();
                for (const auto& n : pc_result.chain) {
                    chain_arr.push_back({
                        {"inst_id", n.inst_id},
                        {"pc", fmt::format("0x{:X}", n.pc)},
                        {"reg", n.produced_reg},
                        {"value", fmt::format("0x{:X}", n.value)}
                    });
                }
                pc_json["chain"] = std::move(chain_arr);
                pc_json["depth"] = pc_result.chain.size();
                fmt::print("{}\n", pc_json.dump(2));
            }
        }

        // --window-stats: sliding window instruction metrics
        if (opt_window_stats) {
            WindowStatsConfig ws_cfg;
            ws_cfg.window_size = window_stats_size;
            pm.register_pass(std::make_unique<WindowStatsPass>(std::move(ws_cfg)));
            const auto& ws_raw = pm.require("window_stats");
            if (!ws_raw.ok()) {
                fmt::print(stderr, "[window-stats] Pass failed: {}\n", ws_raw.error_message);
                rc |= 1;
            } else {
                const auto& ws_result = ws_raw.get<WindowStatsResult>();
                fmt::print(stderr, "[window-stats] {} windows analyzed\n", ws_result.windows.size());
                json ws_json;
                json windows_arr = json::array();
                size_t limit = std::min(ws_result.windows.size(), size_t(500));
                for (size_t i = 0; i < limit; i++) {
                    const auto& w = ws_result.windows[i];
                    windows_arr.push_back({
                        {"start_inst_id", w.start_inst_id},
                        {"end_inst_id", w.end_inst_id},
                        {"instruction_count", w.instruction_count}
                    });
                }
                ws_json["windows"] = std::move(windows_arr);
                ws_json["total_windows"] = ws_result.windows.size();
                if (ws_result.windows.size() > 500) ws_json["truncated"] = true;
                fmt::print("{}\n", ws_json.dump(2));
            }
        }

        // --entropy: Shannon entropy analysis on memory writes
        if (opt_entropy) {
            EntropyConfig ent_cfg;
            ent_cfg.at_inst_id = entropy_start;  // use start as sample point
            pm.register_pass(std::make_unique<EntropyPass>(std::move(ent_cfg)));
            const auto& ent_raw = pm.require("entropy");
            if (!ent_raw.ok()) {
                fmt::print(stderr, "[entropy] Pass failed: {}\n", ent_raw.error_message);
                rc |= 1;
            } else {
                const auto& ent_result = ent_raw.get<EntropyResult>();
                fmt::print(stderr, "[entropy] classification={}, entropy={:.4f}\n",
                           static_cast<int>(ent_result.classification), ent_result.overall_entropy);
                json ent_json;
                ent_json["overall_entropy"] = ent_result.overall_entropy;
                ent_json["classification"] = static_cast<int>(ent_result.classification);
                json blocks_arr = json::array();
                size_t limit = std::min(ent_result.blocks.size(), size_t(200));
                for (size_t i = 0; i < limit; i++) {
                    const auto& b = ent_result.blocks[i];
                    blocks_arr.push_back({
                        {"offset", b.offset},
                        {"entropy", b.entropy},
                        {"size", b.size}
                    });
                }
                ent_json["blocks"] = std::move(blocks_arr);
                if (ent_result.blocks.size() > 200) ent_json["truncated"] = true;
                fmt::print("{}\n", ent_json.dump(2));
            }
        }

        // --literal-search: find a specific value in registers and memory
        if (opt_literal_search) {
            LiteralSearchConfig ls_cfg;
            ls_cfg.search_values.push_back(literal_search_value);
            pm.register_pass(std::make_unique<LiteralSearchPass>(std::move(ls_cfg)));
            const auto& ls_raw = pm.require("literal_search");
            if (!ls_raw.ok()) {
                fmt::print(stderr, "[literal-search] Pass failed: {}\n", ls_raw.error_message);
                rc |= 1;
            } else {
                const auto& ls_result = ls_raw.get<LiteralSearchResult>();
                fmt::print(stderr, "[literal-search] {} hits for 0x{:X}\n",
                           ls_result.hits.size(), literal_search_value);
                json ls_json;
                json hits_arr = json::array();
                size_t limit = std::min(ls_result.hits.size(), size_t(1000));
                for (size_t i = 0; i < limit; i++) {
                    const auto& h = ls_result.hits[i];
                    hits_arr.push_back({
                        {"inst_id", h.inst_id},
                        {"pc", fmt::format("0x{:X}", h.pc)},
                        {"matched_value", fmt::format("0x{:X}", h.matched_value)},
                        {"source", h.source == LiteralHit::RegDiff ? "reg" :
                                   h.source == LiteralHit::MemWrite ? "mem" : "imm"}
                    });
                }
                ls_json["value"] = fmt::format("0x{:X}", literal_search_value);
                ls_json["hits"] = std::move(hits_arr);
                ls_json["total"] = ls_result.hits.size();
                if (ls_result.hits.size() > 1000) ls_json["truncated"] = true;
                fmt::print("{}\n", ls_json.dump(2));
            }
        }

        // ── P3: --stats ────────────────────────────────────────────────────
        // Output trace statistics as JSON (also useful for Python bindings).
        if (opt_stats_only) {
            const auto& stats = index.stats();
            json st_json;
            st_json["inst_count"]    = stats.inst_count;
            st_json["anchor_count"]  = stats.anchor_count;
            st_json["code_count"]    = stats.code_count;
            st_json["event_count"]   = stats.event_count;
            st_json["total_records"] = stats.total_records;
            st_json["build_seconds"] = stats.build_seconds;
            st_json["module_name"]   = hdr.module_name;
            st_json["module_base"]   = fmt::format("0x{:X}", hdr.module_base);
            st_json["module_slide"]  = fmt::format("0x{:X}", hdr.module_slide);
            st_json["file_size"]     = reader.file_size();
            st_json["arch"]          = hdr.arch == 1 ? "aarch64" : "x86_64";
            st_json["version"]       = hdr.version;
            st_json["flags"] = {
                {"has_mem",       hdr.has_mem()},
                {"has_code",      hdr.has_code()},
                {"reg_diff",      hdr.reg_diff()},
                {"has_nzcv",      hdr.has_nzcv()},
            };
            fmt::print("{}\n", st_json.dump(2));
        }

        // ── P3: --cache-sim ────────────────────────────────────────────────
        if (opt_cache_sim) {
            CacheSimConfig cs_cfg;
            // Override L1D and L2 sizes
            cs_cfg.levels[0].size_kb = cache_sim_l1_size_kb;
            if (cs_cfg.levels.size() >= 2) {
                cs_cfg.levels[1].size_kb = cache_sim_l2_size_kb;
            }
            cs_cfg.policy = cache_sim_policy;
            cs_cfg.detect_timing_sidechannel = !cache_sim_no_sidechannel;

            // Register optional FunctionPass for per-function stats
            pm.register_pass(std::make_unique<FunctionPass>());
            pm.register_pass(std::make_unique<CacheSimPass>(std::move(cs_cfg)));

            const auto& cs_raw = pm.require("cache_sim");
            if (!cs_raw.ok()) {
                fmt::print(stderr, "[cache-sim] Pass failed: {}\n", cs_raw.error_message);
                rc |= 1;
            } else {
                const auto& cs_result = cs_raw.get<CacheSimResult>();
                fmt::print(stderr, "[cache-sim] %s\n", cs_result.summary().c_str());

                json cs_json;
                cs_json["total_instructions"] = cs_result.total_instructions;
                cs_json["summary"] = cs_result.summary();

                // Level stats
                json levels_arr = json::array();
                for (const auto& ls : cs_result.level_stats) {
                    levels_arr.push_back({
                        {"name",           ls.name},
                        {"total_accesses", ls.total_accesses},
                        {"hits",           ls.hits},
                        {"misses",         ls.misses},
                        {"miss_rate",      ls.miss_rate()},
                        {"hit_rate",       ls.hit_rate()},
                        {"read_accesses",  ls.read_accesses},
                        {"write_accesses", ls.write_accesses},
                        {"evictions",      ls.evictions}
                    });
                }
                cs_json["level_stats"] = std::move(levels_arr);

                // Per-function stats (top 50)
                json fn_arr = json::array();
                size_t fn_limit = std::min(cs_result.function_stats.size(), size_t(50));
                for (size_t i = 0; i < fn_limit; i++) {
                    const auto& fs = cs_result.function_stats[i];
                    fn_arr.push_back({
                        {"pc",               fmt::format("0x{:X}", fs.entry_pc)},
                        {"name",             fs.name},
                        {"total_calls",      fs.total_calls},
                        {"mean_l1d_misses",  fs.mean_l1d_misses()},
                        {"stddev_l1d_misses",fs.stddev_l1d_misses()},
                        {"cv",               fs.cv_l1d_misses()},
                        {"max_misses",       fs.max_l1d_misses()},
                        {"min_misses",       fs.min_l1d_misses()}
                    });
                }
                cs_json["function_stats"] = std::move(fn_arr);
                if (cs_result.function_stats.size() > 50) cs_json["function_stats_truncated"] = true;

                // Timing side-channel suspects
                json sc_arr = json::array();
                for (const auto& sc : cs_result.sidechannels) {
                    sc_arr.push_back({
                        {"pc",           fmt::format("0x{:X}", sc.entry_pc)},
                        {"name",         sc.function_name},
                        {"cv",           sc.cv},
                        {"min_misses",   sc.min_misses},
                        {"max_misses",   sc.max_misses},
                        {"total_calls",  sc.total_calls},
                        {"reason",       sc.reason}
                    });
                }
                cs_json["sidechannels"] = std::move(sc_arr);
                cs_json["sidechannel_count"] = cs_result.sidechannels.size();

                // Hottest cache lines
                json hot_arr = json::array();
                size_t hot_limit = std::min(cs_result.hottest_lines.size(), size_t(20));
                for (size_t i = 0; i < hot_limit; i++) {
                    const auto& hl = cs_result.hottest_lines[i];
                    hot_arr.push_back({
                        {"addr",   fmt::format("0x{:X}", hl.addr)},
                        {"misses", hl.misses},
                        {"hits",   hl.hits}
                    });
                }
                cs_json["hottest_cache_lines"] = std::move(hot_arr);

                fmt::print("{}\n", cs_json.dump(2));
            }
        }

        // ── P3: --yara-mem-scan ────────────────────────────────────────────
        if (opt_yara_mem_scan) {
            YaraMemScanConfig yms_cfg;
            yms_cfg.min_entropy_threshold = yara_min_entropy;
            yms_cfg.scan_code_buffer = yara_scan_code;
            for (const auto& r : yara_extra_rules) {
                yms_cfg.extra_rules.push_back(r);
            }
            pm.register_pass(std::make_unique<YaraMemScanPass>(std::move(yms_cfg)));
            const auto& yms_raw = pm.require("yara_mem_scan");
            if (!yms_raw.ok()) {
                fmt::print(stderr, "[yara-mem-scan] Pass failed: {}\n", yms_raw.error_message);
                rc |= 1;
            } else {
                const auto& yms_result = yms_raw.get<YaraMemScanResult>();
                fmt::print(stderr, "[yara-mem-scan] {} matches, {} pages scanned ({} bytes)\n",
                           yms_result.matches.size(),
                           yms_result.pages_scanned,
                           yms_result.bytes_scanned);

                json yms_json;
                yms_json["total_matches"]          = yms_result.matches.size();
                yms_json["pages_scanned"]          = yms_result.pages_scanned;
                yms_json["bytes_scanned"]          = yms_result.bytes_scanned;
                yms_json["pages_skipped_entropy"]  = yms_result.pages_skipped_entropy;

                json matches_arr = json::array();
                for (const auto& m : yms_result.matches) {
                    matches_arr.push_back({
                        {"rule_name",    m.rule_name},
                        {"category",     pattern_category_str(m.category)},
                        {"confidence",   pattern_confidence_str(m.confidence)},
                        {"description",  m.description},
                        {"scan_addr",    fmt::format("0x{:X}", m.scan_addr)},
                        {"match_addr",   fmt::format("0x{:X}", m.match_addr)},
                        {"match_offset", m.match_offset},
                        {"match_length", m.match_length},
                        {"at_inst_id",   m.at_inst_id},
                        {"scan_label",   m.scan_label}
                    });
                }
                yms_json["matches"] = std::move(matches_arr);
                fmt::print("{}\n", yms_json.dump(2));
            }
        }

        // ── P3: --thread-filter ────────────────────────────────────────────
        if (opt_thread_filter) {
            // thread pass is a dependency
            pm.register_pass(std::make_unique<tenet::ThreadPass>());
            ThreadFilterConfig tf_cfg;
            tf_cfg.include_thread_ids = thread_filter_ids;
            tf_cfg.build_bitmaps = true;
            pm.register_pass(std::make_unique<ThreadFilterPass>(std::move(tf_cfg)));
            const auto& tf_raw = pm.require("thread_filter");
            if (!tf_raw.ok()) {
                fmt::print(stderr, "[thread-filter] Pass failed: {}\n", tf_raw.error_message);
                rc |= 1;
            } else {
                const auto& tf_result = tf_raw.get<ThreadFilterResult>();
                fmt::print(stderr, "[thread-filter] %zu threads, filtered=%s\n",
                           tf_result.thread_count,
                           tf_result.is_filtered ? "yes" : "no");

                json tf_json;
                tf_json["thread_count"] = tf_result.thread_count;
                tf_json["is_filtered"]  = tf_result.is_filtered;
                tf_json["included_inst_count"] = tf_result.included_inst_ids.cardinality();

                json threads_arr = json::array();
                for (const auto& [tid, bm] : tf_result.thread_inst_bitmaps) {
                    threads_arr.push_back({
                        {"thread_id",  tid},
                        {"inst_count", bm.cardinality()}
                    });
                }
                tf_json["threads"] = std::move(threads_arr);
                fmt::print("{}\n", tf_json.dump(2));
            }
        }

        // ── P3: --rpc server mode ──────────────────────────────────────────
        // In RPC mode, start the JSON-RPC server and block until SIGINT.
        if (opt_rpc) {
            TenetRpcService rpc_service(reader, index, regfile, memory, &pm);
            if (!rpc_service.start(rpc_socket_path)) {
                fmt::print(stderr, "[rpc] Failed to start RPC server\n");
                rc |= 1;
            } else {
                fmt::print(stderr, "[rpc] Listening on: {}\n", rpc_service.socket_path());
                fmt::print(stderr, "[rpc] Press Ctrl+C to stop\n");

                // Block until SIGINT or SIGTERM
                static std::atomic<bool> rpc_stop{false};
                auto old_sigint  = std::signal(SIGINT,  [](int) { rpc_stop.store(true); });
                auto old_sigterm = std::signal(SIGTERM, [](int) { rpc_stop.store(true); });
                while (!rpc_stop.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                std::signal(SIGINT,  old_sigint);
                std::signal(SIGTERM, old_sigterm);
                rpc_service.stop();
                fmt::print(stderr, "[rpc] Server stopped.\n");
            }
        }

        // ── P3: --streaming ────────────────────────────────────────────────
        // Tail a live / growing trace file, printing progress until complete.
        if (opt_streaming) {
            StreamingIndex streaming;
            StreamingIndex::Config stream_cfg;
            stream_cfg.batch_size       = 5000;
            stream_cfg.poll_interval_ms = 200;
            stream_cfg.idle_timeout_ms  = 5000;

            bool started = streaming.start(
                trace_path, index,
                [](uint64_t indexed, uint64_t file_bytes) {
                    fmt::print(stderr, "\r[streaming] {} insts indexed, {:.1f} MB ...",
                               indexed, file_bytes / (1024.0 * 1024.0));
                    fflush(stderr);
                },
                []() {
                    fmt::print(stderr, "\n[streaming] Recording complete.\n");
                });

            if (!started) {
                fmt::print(stderr, "[streaming] Failed to start tail thread\n");
                rc |= 1;
            } else {
                // Wait for completion (idle timeout or SIGINT)
                static std::atomic<bool> stream_stop{false};
                auto old_sig = std::signal(SIGINT, [](int) { stream_stop.store(true); });
                while (!streaming.is_complete() && !stream_stop.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                std::signal(SIGINT, old_sig);
                streaming.stop();

                // Emit final stats
                json stream_json;
                stream_json["final_inst_count"]  = streaming.inst_count();
                stream_json["file_bytes_seen"]   = streaming.file_bytes_seen();
                stream_json["is_complete"]        = streaming.is_complete();
                fmt::print("{}\n", stream_json.dump(2));
            }
        }

        return rc;
    }

    // ─── Run interactive mode (GUI / TUI) or batch mode ──────────────────
    if (batch_mode) {
        TuiApp app(reader, index, code_table, decoder, regfile, memory);
        return app.batch_mode(start_id, display_count, show_regs, show_mem);
    }

#if TENET_HAS_GUI
    if (!force_tui) {
        GuiApp gui(reader, index, code_table, decoder, regfile, memory);
        return gui.run();
    }
#else
    (void)force_tui;
#endif

    // Fallback to TUI (or --tui explicitly requested)
    TuiApp app(reader, index, code_table, decoder, regfile, memory);
    return app.run();
}

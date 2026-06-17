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
#include "analysis/passes/dataflow_graph_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/thread_pass.h"

#include <fmt/core.h>
#include <fmt/color.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

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

    // tainted_regs_final (sorted)
    std::vector<uint8_t> tainted(result.tainted_regs.begin(),
                                 result.tainted_regs.end());
    std::sort(tainted.begin(), tainted.end());
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
    std::vector<uint8_t> involved(result.all_involved_regs.begin(),
                                  result.all_involved_regs.end());
    std::sort(involved.begin(), involved.end());
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
    fmt::print(stderr, "  --dataflow-graph <start> <end> Build dataflow graph for instruction range\n");
    fmt::print(stderr, "  --dataflow-graph-output <file> Export dataflow graph (.dot or .json)\n");
    fmt::print(stderr, "  --algorithm-summary           Generate algorithm summary report\n");
    fmt::print(stderr, "  --objc                        Analyze Objective-C message sends\n");
    fmt::print(stderr, "\nQuery options (JSON output):\n");
    fmt::print(stderr, "  --memread <addr> <size> <inst_id> Read memory at a point in time\n");
    fmt::print(stderr, "  --mem-history <addr> <size>       List all writes to an address\n");
    fmt::print(stderr, "  --search-pc <addr> [limit]        Find all inst_ids visiting a PC\n");
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
    bool opt_dataflow_graph = false;
    uint64_t dataflow_start = 0, dataflow_end = 0;
    std::string dataflow_output_path;
    bool opt_algorithm_summary = false;
    bool opt_objc = false;

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
        } else if (arg[0] != '-') {
            trace_path = arg;
        }
    }

    if (trace_path.empty()) {
        fmt::print(stderr, "Error: no trace file specified\n");
        print_usage(argv[0]);
        return 1;
    }

    // Determine if any analysis option was specified → suppress TUI
    bool has_analysis_option = !export_cfg_path.empty() || opt_taint ||
                               opt_strings || opt_pattern || opt_constants ||
                               !call_graph_path.empty() ||
                               opt_backward_taint || opt_critical_path ||
                               opt_trace_diff || opt_loop_semantics ||
                               opt_symbol_annotation || opt_memory_snapshot ||
                               opt_dataflow_graph || opt_algorithm_summary ||
                               opt_objc ||
                               opt_memread || opt_mem_history || opt_search_pc;

    // ─── Open trace file ────────────────────────────────────────────────
    fmt::print("Opening trace: {}\n", trace_path);

    auto reader_result = TraceReader::open(trace_path);
    if (!reader_result) {
        fmt::print(stderr, "Error: {}\n", reader_result.error().message);
        return 1;
    }
    auto& reader = *reader_result;

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

    // ─── Build/load index ───────────────────────────────────────────────
    fmt::print("Building index...\n");

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

    if (show_index_stats) {
        fmt::print("  Code records: {}\n", index.stats().code_count);
        fmt::print("  Event records: {}\n", index.stats().event_count);
        fmt::print("  Total records: {}\n", index.stats().total_records);
        fmt::print("\n");
    }

    // ─── Populate CodeTable from trace ──────────────────────────────────
    CodeTable code_table;
    fmt::print("Loading code table...\n");
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
    fmt::print("  Loaded {} distinct PCs\n\n", code_table.size());

    // ─── Initialize decoder ─────────────────────────────────────────────
    InstructionDecoder decoder;
    if (!decoder.init()) {
        fmt::print(stderr, "Error: failed to initialize Capstone\n");
        return 1;
    }

    // ─── Initialize RegisterFile and MemoryModel ──────────────────────────
    RegisterFile regfile(reader, index);
    MemoryModel memory(reader, index);

    // ─── Run analysis options (batch mode) ─────────────────────────────────
    if (has_analysis_option) {
        PassManager pm;
        pm.set_reader(&reader);
        pm.set_index(&index);
        pm.set_code_table(&code_table);
        pm.set_regfile(&regfile);
        pm.set_memory(&memory);
        pm.set_decoder(&decoder);

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
            taint_cfg.source_regs.insert(taint_reg_index);
            taint_cfg.source_inst_id = taint_source_inst_id;
            taint_cfg.source_mem_addrs = taint_source_mem_addrs;
            taint_cfg.max_taint_width = taint_max_width;
            taint_cfg.propagate_through_calls = !taint_no_calls;
            taint_cfg.use_xref_acceleration = !taint_no_xref;
            taint_cfg.emit_kill_events = !taint_no_kills;
            for (uint64_t pc : taint_stop_pcs) {
                taint_cfg.stop_pcs.insert(pc);
            }
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
            bt_cfg.sink_regs.insert(backward_taint_reg);
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
            pm.register_pass(std::make_unique<ObjcPass>());
        }

        // --critical-path also needs forward taint
        if (opt_critical_path && !opt_taint) {
            TaintConfig taint_cfg;
            taint_cfg.source_regs.insert(backward_taint_reg);
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
                // Get the PC at this instruction via offset_of + record_at
                uint64_t off = index.offset_of(history[i], reader);
                if (off != 0) {
                    auto rec = reader.record_at(off);
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

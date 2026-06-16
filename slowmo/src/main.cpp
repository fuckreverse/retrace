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
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"

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
    fmt::print(stderr, "  --call-graph <file.dot>   Export call graph as Graphviz DOT\n");
    fmt::print(stderr, "  --backward-taint <inst_id> <reg>  Backward taint from sink instruction\n");
    fmt::print(stderr, "  --backward-taint-max-steps <N>    Limit backward walk steps (default: unlimited)\n");
    fmt::print(stderr, "  --backward-taint-graph <file>     Export dataflow graph (.dot or .json)\n");
    fmt::print(stderr, "  --critical-path                   Compute forward+backward intersection\n");
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
    std::string call_graph_path;
    bool opt_backward_taint = false;
    uint64_t backward_taint_sink_id = 0;
    uint8_t backward_taint_reg = 0;
    uint64_t backward_taint_max_steps = 0;
    std::string backward_taint_graph_path;
    bool opt_critical_path = false;

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
                               opt_strings || opt_pattern ||
                               !call_graph_path.empty() ||
                               opt_backward_taint || opt_critical_path;

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

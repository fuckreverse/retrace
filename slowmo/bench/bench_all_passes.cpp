/// bench_all_passes.cpp — Benchmark ALL Tenet analysis passes individually
///
/// Strategy: Uses a SINGLE PassManager instance. Registers all passes, then
/// runs each one sequentially via require(). For each pass, we measure the
/// incremental time (since deps are already computed from prior require() calls).
/// This avoids redundant trace scans and gives realistic "marginal cost" numbers.
///
/// Usage: bench_all_passes <trace_file> [--output file.json] [--quiet]

#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"

// All passes
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/memory/string_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"  // also defines ConstantMaterializationResult
#include "analysis/passes/profile/trace_diff_pass.h"
#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/misc/thread_pass.h"

#include <fmt/core.h>
#include <fmt/color.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>

using namespace tenet;
using json = nlohmann::json;
namespace fs = std::filesystem;

// ─── Timer ──────────────────────────────────────────────────────────────────

struct Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start_;
    void start() { start_ = Clock::now(); }
    double elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(Clock::now() - start_).count();
    }
};

// ─── Pass benchmark entry ───────────────────────────────────────────────────

struct PassBenchEntry {
    std::string name;
    std::string category;      // "root", "derived", "composite"
    std::vector<std::string> deps;
    double own_ms = 0;         // Incremental time (deps already satisfied)
    double total_ms = 0;       // Total time if run from scratch (sum of own + dep own times)
    bool success = false;
    std::string error;

    json to_json() const {
        json j;
        j["name"] = name;
        j["category"] = category;
        j["dependencies"] = deps;
        j["own_ms"] = own_ms;
        j["total_ms"] = total_ms;
        j["success"] = success;
        if (!error.empty()) j["error"] = error;
        return j;
    }
};

// ─── Pass descriptor (name, category, deps) ─────────────────────────────────

struct PassDesc {
    std::string name;
    std::string category;
    std::vector<std::string> deps;
};

// ─── Main ───────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: {} <trace_file> [--output file.json] [--quiet]\n", argv[0]);
        return 1;
    }

    std::string trace_path;
    std::string output_path;
    bool verbose = true;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--quiet") {
            verbose = false;
        } else if (arg == "-h" || arg == "--help") {
            fmt::print(stderr, "Usage: {} <trace_file> [--output file.json] [--quiet]\n", argv[0]);
            return 0;
        } else if (arg[0] != '-') {
            trace_path = arg;
        }
    }

    if (trace_path.empty()) {
        fmt::print(stderr, "Error: no trace file specified\n");
        return 1;
    }

    // ── Open trace ───────────────────────────────────────────────────────
    if (verbose) fmt::print(stderr, "Opening: {}\n", trace_path);

    auto reader_res = TraceReader::open(trace_path);
    if (!reader_res) {
        fmt::print(stderr, "Error: {}\n", reader_res.error().message);
        return 1;
    }
    auto& reader = *reader_res;

    if (verbose) {
        fmt::print(stderr, "  Size: {:.2f} MB\n", reader.file_size() / (1024.0*1024.0));
    }

    // ── Build index ──────────────────────────────────────────────────────
    Timer timer;
    timer.start();
    auto index_res = TraceIndex::open_or_build(reader);
    double index_ms = timer.elapsed_ms();

    if (!index_res) {
        fmt::print(stderr, "Error building index: {}\n", index_res.error().message);
        return 1;
    }
    auto& index = *index_res;

    if (verbose) {
        fmt::print(stderr, "  Index: {} insts, {} anchors ({:.1f} ms)\n",
                   index.inst_count(), index.stats().anchor_count, index_ms);
    }

    // ── Load CodeTable ───────────────────────────────────────────────────
    CodeTable code_table;
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

    if (verbose) {
        fmt::print(stderr, "  CodeTable: {} PCs\n", code_table.size());
    }

    // ── Init core ────────────────────────────────────────────────────────
    RegisterFile regfile(reader, index);
    InstructionDecoder decoder;
    decoder.init();
    MemoryModel memory(reader, index,
                       index.raw_db(), index.mem_write_cf(), index.mem_read_cf());
    timer.start();
    memory.build();
    double mem_build_ms = timer.elapsed_ms();

    if (verbose) {
        fmt::print(stderr, "  Memory build: {:.1f} ms\n\n", mem_build_ms);
    }

    // ── Register all passes into a SINGLE PassManager ────────────────────
    PassManager pm;
    pm.set_reader(&reader);
    pm.set_index(&index);
    pm.set_code_table(&code_table);
    pm.set_regfile(&regfile);
    pm.set_memory(&memory);
    pm.set_decoder(&decoder);

    // Register root passes
    pm.register_pass(std::make_unique<XrefPass>());
    pm.register_pass(std::make_unique<FunctionPass>());
    pm.register_pass(std::make_unique<LoopPass>());
    // "constant_materialization" was merged into "pattern" (see
    // PatternResult::constants), so only PatternPass needs to be registered.
    pm.register_pass(std::make_unique<PatternPass>());
    pm.register_pass(std::make_unique<StringPass>());
    pm.register_pass(std::make_unique<ObjcPass>());
    pm.register_pass(std::make_unique<ThreadPass>());

    // backward_taint with config
    {
        BackwardTaintConfig bt_cfg;
        bt_cfg.sink_inst_id = std::min(uint64_t(100), index.inst_count() - 1);
        bt_cfg.add_sink_reg(0);  // X0
        bt_cfg.max_steps = 10000;
        pm.register_pass(std::make_unique<BackwardTaintPass>(std::move(bt_cfg)));
    }

    // trace_diff with config
    {
        TraceDiffConfig td_cfg;
        td_cfg.trace_a_start = 0;
        td_cfg.trace_a_end = std::min(uint64_t(500), index.inst_count() / 2);
        td_cfg.trace_b_start = std::min(uint64_t(500), index.inst_count() / 2);
        td_cfg.trace_b_end = std::min(uint64_t(1000), index.inst_count());
        pm.register_pass(std::make_unique<TraceDiffPass>(std::move(td_cfg)));
    }

    // memory_snapshot with config
    {
        MemorySnapshotConfig ms_cfg;
        uint64_t n = index.inst_count();
        ms_cfg.snapshot_inst_ids = {0, n/4, n/2, 3*n/4};
        ms_cfg.snapshot_size = 64;
        pm.register_pass(std::make_unique<MemorySnapshotPass>(std::move(ms_cfg)));
    }

    // dataflow_graph with config
    {
        DataflowGraphConfig dg_cfg;
        dg_cfg.start_inst_id = 0;
        dg_cfg.end_inst_id = std::min(uint64_t(1000), index.inst_count());
        pm.register_pass(std::make_unique<DataflowGraphPass>(std::move(dg_cfg)));
    }

    // Register derived passes
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<CFGLayoutPass>());
    {
        TaintConfig taint_cfg;
        taint_cfg.add_source_reg(0);  // X0
        taint_cfg.source_inst_id = 0;
        taint_cfg.propagate_through_calls = true;
        taint_cfg.use_xref_acceleration = true;
        pm.register_pass(std::make_unique<TaintPass>(std::move(taint_cfg)));
    }
    pm.register_pass(std::make_unique<CallGraphPass>());
    pm.register_pass(std::make_unique<LoopSemanticsPass>());

    // Register composite passes
    // Note: symbol_annotation was demoted from a pass to a plain aggregation
    // helper (build_annotation_view()) — it does no analysis of its own, so
    // it is no longer part of the PassManager benchmark loop.
    pm.register_pass(std::make_unique<AlgorithmSummaryPass>());

    // ── Define pass execution order (topological) ─────────────────────────
    // Root passes first, then derived, then composite
    std::vector<PassDesc> pass_order = {
        // Root passes (no dependencies)
        {"xref",                     "root", {}},
        {"function",                 "root", {}},
        {"loop",                     "root", {}},
        {"pattern",                  "root", {}},
        {"strings",                  "root", {}},
        {"objc",                     "root", {}},
        {"thread",                   "root", {}},
        {"backward_taint",           "root", {}},
        {"trace_diff",               "root", {}},
        {"memory_snapshot",          "derived", {"function"}},
        {"dataflow_graph",           "root", {}},
        // Derived passes
        {"cfg",            "derived", {"xref"}},
        {"cfg_layout",     "derived", {"xref", "cfg"}},
        {"taint",          "derived", {"xref"}},
        {"call_graph",     "derived", {"function"}},
        {"loop_semantics", "derived", {"loop"}},
    // Composite passes
    // "constant_materialization" was merged into "pattern" — see
    // PatternResult::constants.
    {"algorithm_summary",  "composite", {"pattern", "loop_semantics", "function", "call_graph"}},
    };

    // ── Run each pass and measure incremental time ────────────────────────
    std::vector<PassBenchEntry> results;

    if (verbose) {
        fmt::print(stderr, "{:<28} {:>10} {:>8}\n", "PASS", "OWN (ms)", "STATUS");
        fmt::print(stderr, "{}\n", std::string(50, '-'));
    }

    for (const auto& desc : pass_order) {
        PassBenchEntry entry;
        entry.name = desc.name;
        entry.category = desc.category;
        entry.deps = desc.deps;

        // Measure incremental time: deps are already computed from previous iterations
        timer.start();
        const auto& result = pm.require(desc.name);
        entry.own_ms = timer.elapsed_ms();
        entry.success = result.ok();
        if (!result.ok()) entry.error = result.error_message;

        // total_ms = own_ms + sum of dependency own_ms (computed after all runs)
        entry.total_ms = entry.own_ms;  // will be recomputed below

        results.push_back(std::move(entry));

        if (verbose) {
            fmt::print(stderr, "{:<28} {:>9.2f} {:>8}\n",
                       desc.name, results.back().own_ms,
                       results.back().success ? "OK" : "FAIL");
            fflush(stderr);
        }
    }

    // ── Compute total_ms (own + transitive dep costs) ─────────────────────
    // Build a map: name -> own_ms
    ankerl::unordered_dense::map<std::string, double> own_map;
    for (const auto& r : results) {
        own_map[r.name] = r.own_ms;
    }
    // Recompute total_ms = own_ms + sum(dep.total_ms)
    // Since passes are in topological order, deps always come before
    ankerl::unordered_dense::map<std::string, double> total_map;
    for (auto& r : results) {
        double dep_total = 0;
        for (const auto& dep : r.deps) {
            auto it = total_map.find(dep);
            if (it != total_map.end()) dep_total += it->second;
        }
        r.total_ms = r.own_ms + dep_total;
        total_map[r.name] = r.total_ms;
    }

    // ── Print summary ─────────────────────────────────────────────────────
    if (verbose) {
        fmt::print(stderr, "{}\n", std::string(50, '-'));

        double total_root = 0, total_derived = 0, total_composite = 0;
        for (const auto& r : results) {
            if (r.category == "root") total_root += r.own_ms;
            else if (r.category == "derived") total_derived += r.own_ms;
            else total_composite += r.own_ms;
        }
        fmt::print(stderr, "\n  Root passes total:      {:.1f} ms\n", total_root);
        fmt::print(stderr, "  Derived passes (own):   {:.1f} ms\n", total_derived);
        fmt::print(stderr, "  Composite passes (own): {:.1f} ms\n", total_composite);
        fmt::print(stderr, "  Grand total (all own):  {:.1f} ms\n",
                   total_root + total_derived + total_composite);

        // Top 5 slowest
        auto sorted = results;
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.own_ms > b.own_ms; });
        fmt::print(stderr, "\n  Top 5 slowest (own time):\n");
        for (size_t i = 0; i < std::min(size_t(5), sorted.size()); i++) {
            fmt::print(stderr, "    {:2}. {:<24} {:.2f} ms\n",
                       i+1, sorted[i].name, sorted[i].own_ms);
        }
    }

    // ── JSON output ──────────────────────────────────────────────────────
    json output;
    output["benchmark"] = "tenet_all_passes";
    output["trace"] = fs::path(trace_path).stem().string();
    output["trace_info"] = {
        {"file_size_mb", reader.file_size() / (1024.0*1024.0)},
        {"inst_count", index.inst_count()},
        {"anchor_count", index.stats().anchor_count},
        {"unique_pcs", code_table.size()},
        {"index_build_ms", index_ms},
        {"memory_build_ms", mem_build_ms},
    };

    json passes_arr = json::array();
    for (const auto& r : results) {
        passes_arr.push_back(r.to_json());
    }
    output["passes"] = std::move(passes_arr);

    // Compute summary
    double sum_own = 0;
    int pass_ok = 0, pass_fail = 0;
    for (const auto& r : results) {
        sum_own += r.own_ms;
        if (r.success) pass_ok++; else pass_fail++;
    }
    output["summary"] = {
        {"total_passes", results.size()},
        {"passed", pass_ok},
        {"failed", pass_fail},
        {"sum_own_ms", sum_own},
    };

    std::string json_str = output.dump(2);

    if (!output_path.empty()) {
        std::ofstream out(output_path);
        out << json_str << "\n";
        out.close();
        if (verbose) fmt::print(stderr, "\nResults written to: {}\n", output_path);
    } else {
        fmt::print("{}\n", json_str);
    }

    return 0;
}

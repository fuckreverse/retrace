/// bench_tenet.cpp — Tenet performance benchmark harness
///
/// Measures end-to-end throughput and latency for each subsystem:
///   - Index build (TraceIndex::open_or_build)
///   - Memory build (MemoryModel::build)
///   - Analysis passes (XRef, CFG, Taint, CallGraph, Function)
///   - Random seek (RegisterFile::state_before, random inst_ids)
///   - Memory query (MemoryModel::read, random addresses)
///   - IO scan throughput (raw record iteration)
///
/// Output: JSON per-trace benchmark results to stdout.
/// Usage:  bench_tenet <trace_dir> [--warmup N] [--seek-samples N] [--json]

#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/function_pass.h"

#include <fmt/core.h>
#include <fmt/color.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <random>
#include <string>
#include <vector>
#include <algorithm>

#ifdef __APPLE__
#include <sys/resource.h>
#endif

using namespace tenet;
using json = nlohmann::json;
namespace fs = std::filesystem;

// ─── Timing utility ─────────────────────────────────────────────────────────

struct Timer {
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;

    TimePoint start_;

    void start() { start_ = Clock::now(); }

    double elapsed_ms() const {
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }

    double elapsed_us() const {
        auto end = Clock::now();
        return std::chrono::duration<double, std::micro>(end - start_).count();
    }
};

// ─── Latency statistics ─────────────────────────────────────────────────────

struct LatencyStats {
    double min_us = 0;
    double max_us = 0;
    double mean_us = 0;
    double p50_us = 0;
    double p95_us = 0;
    double p99_us = 0;
    uint64_t samples = 0;

    static LatencyStats from_samples(std::vector<double>& latencies) {
        LatencyStats s;
        if (latencies.empty()) return s;

        std::sort(latencies.begin(), latencies.end());
        s.samples = latencies.size();
        s.min_us = latencies.front();
        s.max_us = latencies.back();

        double sum = 0;
        for (double v : latencies) sum += v;
        s.mean_us = sum / latencies.size();

        auto percentile = [&](double p) -> double {
            size_t idx = static_cast<size_t>(p * (latencies.size() - 1));
            return latencies[idx];
        };
        s.p50_us = percentile(0.50);
        s.p95_us = percentile(0.95);
        s.p99_us = percentile(0.99);
        return s;
    }

    json to_json() const {
        return {
            {"samples", samples},
            {"min_us", min_us},
            {"max_us", max_us},
            {"mean_us", mean_us},
            {"p50_us", p50_us},
            {"p95_us", p95_us},
            {"p99_us", p99_us}
        };
    }
};

// ─── Benchmark configuration ────────────────────────────────────────────────

struct BenchConfig {
    uint32_t warmup_iters = 1;       // Warmup iterations before measurement
    uint32_t seek_samples = 1000;    // Random seek samples
    uint32_t mem_query_samples = 500; // Memory read samples
    bool json_output = true;          // Always JSON for machine consumption
    bool verbose = true;              // Also print human-readable to stderr
};

// ─── Single trace benchmark ─────────────────────────────────────────────────

struct TraceBenchResult {
    std::string trace_name;
    uint64_t file_size_bytes = 0;
    uint64_t inst_count = 0;
    uint64_t anchor_count = 0;
    uint64_t unique_pcs = 0;

    // Timings (ms)
    double index_build_ms = 0;
    double code_table_load_ms = 0;
    double memory_build_ms = 0;

    // IO throughput
    double io_scan_ms = 0;
    double io_throughput_mb_per_sec = 0;
    double io_throughput_minst_per_sec = 0;

    // Pass execution (ms)
    double xref_pass_ms = 0;
    double cfg_pass_ms = 0;
    double taint_pass_ms = 0;
    double function_pass_ms = 0;
    double call_graph_pass_ms = 0;

    // Random seek latency
    LatencyStats seek_latency;

    // Memory query latency
    LatencyStats mem_read_latency;

    // Checkpoint stats
    uint64_t regfile_ckpt_queries = 0;
    uint64_t regfile_ckpt_fallbacks = 0;
    uint64_t mem_cache_hits = 0;
    uint64_t mem_rocksdb_reads = 0;

    json to_json() const {
        json j;
        j["trace"] = trace_name;
        j["file_size_bytes"] = file_size_bytes;
        j["file_size_mb"] = file_size_bytes / (1024.0 * 1024.0);
        j["inst_count"] = inst_count;
        j["anchor_count"] = anchor_count;
        j["unique_pcs"] = unique_pcs;

        j["timing_ms"] = {
            {"index_build", index_build_ms},
            {"code_table_load", code_table_load_ms},
            {"memory_build", memory_build_ms},
            {"io_scan", io_scan_ms},
        };

        j["throughput"] = {
            {"io_mb_per_sec", io_throughput_mb_per_sec},
            {"io_minst_per_sec", io_throughput_minst_per_sec},
        };

        j["pass_ms"] = {
            {"xref", xref_pass_ms},
            {"cfg", cfg_pass_ms},
            {"taint", taint_pass_ms},
            {"function", function_pass_ms},
            {"call_graph", call_graph_pass_ms},
        };

        j["seek_latency"] = seek_latency.to_json();
        j["mem_read_latency"] = mem_read_latency.to_json();

        j["cache_stats"] = {
            {"regfile_ckpt_queries", regfile_ckpt_queries},
            {"regfile_ckpt_fallbacks", regfile_ckpt_fallbacks},
            {"regfile_fallback_rate", (regfile_ckpt_queries > 0)
                ? (double)regfile_ckpt_fallbacks / (double)regfile_ckpt_queries
                : 0.0},
            {"mem_cache_hits", mem_cache_hits},
            {"mem_rocksdb_reads", mem_rocksdb_reads},
        };

        return j;
    }
};

// ─── Run benchmark on a single trace ────────────────────────────────────────

static TraceBenchResult benchmark_trace(const fs::path& trace_path,
                                         const BenchConfig& cfg) {
    TraceBenchResult result;
    result.trace_name = trace_path.stem().string();
    Timer timer;

    if (cfg.verbose) {
        fmt::print(stderr, "\n{}\n", std::string(70, '='));
        fmt::print(stderr, "  Benchmarking: {}\n", result.trace_name);
        fmt::print(stderr, "{}\n", std::string(70, '='));
    }

    // ── 1. Open trace ────────────────────────────────────────────────────
    auto reader_res = TraceReader::open(trace_path);
    if (!reader_res) {
        fmt::print(stderr, "  ERROR: Cannot open trace: {}\n",
                   reader_res.error().message);
        return result;
    }
    auto& reader = *reader_res;
    result.file_size_bytes = reader.file_size();

    if (cfg.verbose) {
        fmt::print(stderr, "  File size: {:.2f} MB\n",
                   result.file_size_bytes / (1024.0 * 1024.0));
    }

    // ── 2. Build index ───────────────────────────────────────────────────
    // Delete existing index to force rebuild for accurate measurement
    {
        auto idx_path = trace_path;
        idx_path.replace_extension(".tenet_idx");
        fs::remove_all(idx_path);
    }

    timer.start();
    auto index_res = TraceIndex::open_or_build(reader);
    result.index_build_ms = timer.elapsed_ms();

    if (!index_res) {
        fmt::print(stderr, "  ERROR: Cannot build index: {}\n",
                   index_res.error().message);
        return result;
    }
    auto& index = *index_res;
    result.inst_count = index.inst_count();
    result.anchor_count = index.stats().anchor_count;

    if (cfg.verbose) {
        fmt::print(stderr, "  Index build: {:.1f} ms ({} insts, {} anchors)\n",
                   result.index_build_ms, result.inst_count, result.anchor_count);
    }

    // ── 3. Load CodeTable ────────────────────────────────────────────────
    CodeTable code_table;
    timer.start();
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
    result.code_table_load_ms = timer.elapsed_ms();
    result.unique_pcs = code_table.size();

    if (cfg.verbose) {
        fmt::print(stderr, "  CodeTable: {:.1f} ms ({} PCs)\n",
                   result.code_table_load_ms, result.unique_pcs);
    }

    // ── 4. IO scan throughput ────────────────────────────────────────────
    reader.advise_sequential();
    uint64_t record_count = 0;
    timer.start();
    for (auto it = reader.begin(); it != reader.end(); ++it) {
        ++record_count;
    }
    result.io_scan_ms = timer.elapsed_ms();
    reader.advise_random();

    result.io_throughput_mb_per_sec =
        (result.file_size_bytes / (1024.0 * 1024.0)) / (result.io_scan_ms / 1000.0);
    result.io_throughput_minst_per_sec =
        (result.inst_count / 1e6) / (result.io_scan_ms / 1000.0);

    if (cfg.verbose) {
        fmt::print(stderr, "  IO scan: {:.1f} ms ({:.0f} MB/s, {:.1f} Minst/s)\n",
                   result.io_scan_ms, result.io_throughput_mb_per_sec,
                   result.io_throughput_minst_per_sec);
    }

    // ── 5. Initialize core layers ────────────────────────────────────────
    RegisterFile regfile(reader, index);
    // Build checkpoints so seek latency measures the real O(K) checkpoint
    // replay path, not the empty-state early return.
    regfile.build_checkpoints();
    InstructionDecoder decoder;
    decoder.init();

    // MemoryModel build (RocksDB-backed for accurate benchmarking)
    MemoryModel memory(reader, index,
                       index.raw_db(), index.mem_write_cf(), index.mem_read_cf());
    timer.start();
    memory.build();
    result.memory_build_ms = timer.elapsed_ms();

    if (cfg.verbose) {
        fmt::print(stderr, "  Memory build: {:.1f} ms\n", result.memory_build_ms);
    }

    // ── 6. Random seek benchmark ─────────────────────────────────────────
    if (result.inst_count > 0 && cfg.seek_samples > 0) {
        // Generate random inst_ids
        std::mt19937_64 rng(42);  // fixed seed for reproducibility
        std::uniform_int_distribution<uint64_t> dist(0, result.inst_count - 1);

        std::vector<uint64_t> seek_targets(cfg.seek_samples);
        for (auto& t : seek_targets) t = dist(rng);

        // Warmup
        for (uint32_t w = 0; w < cfg.warmup_iters; w++) {
            for (uint32_t i = 0; i < std::min(cfg.seek_samples, 10u); i++) {
                (void)regfile.state_before(seek_targets[i]);
            }
        }

        // Measurement
        std::vector<double> latencies(cfg.seek_samples);
        for (uint32_t i = 0; i < cfg.seek_samples; i++) {
            timer.start();
            (void)regfile.state_before(seek_targets[i]);
            latencies[i] = timer.elapsed_us();
        }

        result.seek_latency = LatencyStats::from_samples(latencies);
        auto cs = regfile.cache_stats();
        result.regfile_ckpt_queries   = cs.ckpt_queries;
        result.regfile_ckpt_fallbacks = cs.ckpt_fallbacks;

        if (cfg.verbose) {
            fmt::print(stderr, "  Seek ({} samples): p50={:.1f}us p95={:.1f}us p99={:.1f}us\n",
                       cfg.seek_samples, result.seek_latency.p50_us,
                       result.seek_latency.p95_us, result.seek_latency.p99_us);
            fmt::print(stderr, "    Checkpoints: {} queries / {} fallbacks\n",
                       result.regfile_ckpt_queries, result.regfile_ckpt_fallbacks);
        }
    }

    // ── 7. Memory read benchmark ─────────────────────────────────────────
    if (result.inst_count > 0 && cfg.mem_query_samples > 0) {
        // Collect some memory addresses from the trace
        std::vector<std::pair<uint64_t, uint64_t>> mem_targets;  // (addr, inst_id)
        uint64_t scan_inst_id = 0;
        for (auto it = reader.begin(); it != reader.end() && mem_targets.size() < 10000; ++it) {
            auto rec = *it;
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto ma = inst.mem_access(m);
                    mem_targets.emplace_back(ma.addr, scan_inst_id);
                }
                scan_inst_id++;
            }
        }

        if (!mem_targets.empty()) {
            std::mt19937_64 rng(123);
            std::uniform_int_distribution<size_t> dist(0, mem_targets.size() - 1);

            uint32_t actual_samples = std::min(cfg.mem_query_samples,
                                                (uint32_t)mem_targets.size());
            std::vector<double> latencies(actual_samples);

            for (uint32_t i = 0; i < actual_samples; i++) {
                auto [addr, inst_id] = mem_targets[dist(rng)];
                timer.start();
                (void)memory.read(addr, 8, inst_id);
                latencies[i] = timer.elapsed_us();
            }

            result.mem_read_latency = LatencyStats::from_samples(latencies);
            auto mcs = memory.cache_stats();
            result.mem_cache_hits = mcs.cache_hits;
            result.mem_rocksdb_reads = mcs.rocksdb_reads;

            if (cfg.verbose) {
                fmt::print(stderr, "  MemRead ({} samples): p50={:.1f}us p95={:.1f}us p99={:.1f}us\n",
                           actual_samples, result.mem_read_latency.p50_us,
                           result.mem_read_latency.p95_us, result.mem_read_latency.p99_us);
            }
        }
    }

    // ── 8. Analysis pass benchmarks ──────────────────────────────────────
    {
        PassManager pm;
        pm.set_reader(&reader);
        pm.set_index(&index);
        pm.set_code_table(&code_table);
        pm.set_regfile(&regfile);
        pm.set_memory(&memory);
        pm.set_decoder(&decoder);

        // XRef pass
        pm.register_pass(std::make_unique<XrefPass>());
        timer.start();
        pm.require("xref");
        result.xref_pass_ms = timer.elapsed_ms();

        // CFG pass (depends on xref)
        pm.register_pass(std::make_unique<CFGPass>());
        timer.start();
        pm.require("cfg");
        result.cfg_pass_ms = timer.elapsed_ms();

        // Function pass
        pm.register_pass(std::make_unique<FunctionPass>());
        timer.start();
        pm.require("function");
        result.function_pass_ms = timer.elapsed_ms();

        // CallGraph pass (depends on function)
        pm.register_pass(std::make_unique<CallGraphPass>());
        timer.start();
        pm.require("call_graph");
        result.call_graph_pass_ms = timer.elapsed_ms();

        // Taint pass (forward, from X0 at inst 0)
        TaintConfig taint_cfg;
        taint_cfg.add_source_reg(0);  // X0
        taint_cfg.source_inst_id = 0;
        taint_cfg.propagate_through_calls = true;
        taint_cfg.use_xref_acceleration = true;
        pm.register_pass(std::make_unique<TaintPass>(std::move(taint_cfg)));
        timer.start();
        pm.require("taint");
        result.taint_pass_ms = timer.elapsed_ms();

        if (cfg.verbose) {
            fmt::print(stderr, "  Passes: xref={:.1f}ms cfg={:.1f}ms func={:.1f}ms "
                       "cg={:.1f}ms taint={:.1f}ms\n",
                       result.xref_pass_ms, result.cfg_pass_ms,
                       result.function_pass_ms, result.call_graph_pass_ms,
                       result.taint_pass_ms);
        }
    }

    return result;
}

// ─── Main ───────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    fmt::print(stderr, "Usage: {} <trace_dir_or_file> [options]\n", prog);
    fmt::print(stderr, "\nOptions:\n");
    fmt::print(stderr, "  --warmup <N>          Warmup iterations (default: 1)\n");
    fmt::print(stderr, "  --seek-samples <N>    Random seek samples (default: 1000)\n");
    fmt::print(stderr, "  --mem-samples <N>     Memory read samples (default: 500)\n");
    fmt::print(stderr, "  --output <file.json>  Write results to file (default: stdout)\n");
    fmt::print(stderr, "  --quiet               Suppress stderr progress output\n");
    fmt::print(stderr, "  -h, --help            Show this help\n");
    fmt::print(stderr, "\nExamples:\n");
    fmt::print(stderr, "  {} ./traces/perf/\n", prog);
    fmt::print(stderr, "  {} ./traces/perf/perf_heavy_memory.trace --seek-samples 5000\n", prog);
    fmt::print(stderr, "  {} ./traces/perf/ --output baseline_2025.json\n", prog);
}

int main(int argc, char** argv) {
#ifdef __APPLE__
    { struct rlimit rl; if (getrlimit(RLIMIT_NOFILE, &rl) == 0) { rl.rlim_cur = std::min<rlim_t>(rl.rlim_max, 65536); setrlimit(RLIMIT_NOFILE, &rl); } }
#endif
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    BenchConfig cfg;
    std::string input_path;
    std::string output_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--warmup" && i + 1 < argc) {
            cfg.warmup_iters = std::stoul(argv[++i]);
        } else if (arg == "--seek-samples" && i + 1 < argc) {
            cfg.seek_samples = std::stoul(argv[++i]);
        } else if (arg == "--mem-samples" && i + 1 < argc) {
            cfg.mem_query_samples = std::stoul(argv[++i]);
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--quiet") {
            cfg.verbose = false;
        } else if (arg[0] != '-') {
            input_path = arg;
        }
    }

    if (input_path.empty()) {
        fmt::print(stderr, "Error: no trace path specified\n");
        return 1;
    }

    // Collect trace files
    std::vector<fs::path> trace_files;
    fs::path input(input_path);

    if (fs::is_directory(input)) {
        for (const auto& entry : fs::directory_iterator(input)) {
            if (entry.path().extension() == ".trace") {
                trace_files.push_back(entry.path());
            }
        }
        std::sort(trace_files.begin(), trace_files.end());
    } else if (fs::is_regular_file(input)) {
        trace_files.push_back(input);
    } else {
        fmt::print(stderr, "Error: path does not exist: {}\n", input_path);
        return 1;
    }

    if (trace_files.empty()) {
        fmt::print(stderr, "Error: no .trace files found in {}\n", input_path);
        return 1;
    }

    if (cfg.verbose) {
        fmt::print(stderr, "Tenet Benchmark Harness\n");
        fmt::print(stderr, "  Traces: {} files\n", trace_files.size());
        fmt::print(stderr, "  Seek samples: {}\n", cfg.seek_samples);
        fmt::print(stderr, "  Mem samples: {}\n", cfg.mem_query_samples);
        fmt::print(stderr, "  Warmup: {}\n", cfg.warmup_iters);
    }

    // Run benchmarks
    json all_results = json::array();
    double total_time_ms = 0;

    Timer overall;
    overall.start();

    for (const auto& trace_path : trace_files) {
        auto result = benchmark_trace(trace_path, cfg);
        all_results.push_back(result.to_json());
    }

    total_time_ms = overall.elapsed_ms();

    // Build final output
    json output;
    output["benchmark"] = "tenet";
    output["version"] = "1.0";
    output["total_time_ms"] = total_time_ms;
    output["config"] = {
        {"warmup_iters", cfg.warmup_iters},
        {"seek_samples", cfg.seek_samples},
        {"mem_query_samples", cfg.mem_query_samples},
    };

    // System info
    output["system"] = {
        {"arch", "aarch64"},
#ifdef __APPLE__
        {"os", "macOS"},
#else
        {"os", "Linux"},
#endif
    };

    output["results"] = std::move(all_results);

    // Compute summary statistics across all traces
    if (output["results"].size() > 1) {
        json summary;
        double total_insts = 0;
        double total_index_ms = 0;
        double total_xref_ms = 0;
        double total_cfg_ms = 0;
        double total_taint_ms = 0;

        for (const auto& r : output["results"]) {
            total_insts += r["inst_count"].get<uint64_t>();
            total_index_ms += r["timing_ms"]["index_build"].get<double>();
            total_xref_ms += r["pass_ms"]["xref"].get<double>();
            total_cfg_ms += r["pass_ms"]["cfg"].get<double>();
            total_taint_ms += r["pass_ms"]["taint"].get<double>();
        }

        summary["total_instructions"] = static_cast<uint64_t>(total_insts);
        summary["avg_index_build_ms"] = total_index_ms / output["results"].size();
        summary["avg_xref_pass_ms"] = total_xref_ms / output["results"].size();
        summary["avg_cfg_pass_ms"] = total_cfg_ms / output["results"].size();
        summary["avg_taint_pass_ms"] = total_taint_ms / output["results"].size();
        output["summary"] = std::move(summary);
    }

    // Output results
    std::string json_str = output.dump(2);

    if (!output_path.empty()) {
        std::ofstream out(output_path);
        if (!out.is_open()) {
            fmt::print(stderr, "Error: cannot open output file: {}\n", output_path);
            return 1;
        }
        out << json_str << "\n";
        out.close();
        if (cfg.verbose) {
            fmt::print(stderr, "\nResults written to: {}\n", output_path);
        }
    } else {
        fmt::print("{}\n", json_str);
    }

    if (cfg.verbose) {
        fmt::print(stderr, "\nTotal benchmark time: {:.1f}s\n", total_time_ms / 1000.0);
    }

    return 0;
}

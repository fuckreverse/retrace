/// bench_loop_only.cpp — Benchmark ONLY xref + cfg + loop passes
///
/// For GB-scale traces where running all 20 passes would take too long.
/// This isolates the loop pass performance by only running its dependency chain.
///
/// Usage: bench_loop_only <trace_file>

#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"

#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"

#include <fmt/core.h>
#include <chrono>
#include <cstdint>
#include <cstring>

using namespace tenet;

struct Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start_;
    void start() { start_ = Clock::now(); }
    double elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(Clock::now() - start_).count();
    }
};

int main(int argc, char** argv) {
    if (argc < 2) {
        fmt::print(stderr, "Usage: {} <trace_file>\n", argv[0]);
        return 1;
    }

    const char* trace_path = argv[1];
    fmt::print(stderr, "Opening: {}\n", trace_path);

    auto reader_res = TraceReader::open(trace_path);
    if (!reader_res) {
        fmt::print(stderr, "Error: {}\n", reader_res.error().message);
        return 1;
    }
    auto& reader = *reader_res;
    fmt::print(stderr, "  Size: {:.2f} GB ({:.0f} MB)\n",
               reader.file_size() / (1024.0*1024.0*1024.0),
               reader.file_size() / (1024.0*1024.0));

    // Build index
    Timer timer;
    timer.start();
    auto index_res = TraceIndex::open_or_build(reader);
    double index_ms = timer.elapsed_ms();
    if (!index_res) {
        fmt::print(stderr, "Index error: {}\n", index_res.error().message);
        return 1;
    }
    auto& index = *index_res;
    fmt::print(stderr, "  Index: {} insts ({:.1f}M), {} anchors ({:.1f} ms)\n",
               index.inst_count(), index.inst_count() / 1e6,
               index.stats().anchor_count, index_ms);

    // Load code table
    timer.start();
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
    double code_ms = timer.elapsed_ms();
    fmt::print(stderr, "  CodeTable: {} PCs ({:.1f} ms)\n", code_table.size(), code_ms);

    // Init core
    RegisterFile regfile(reader, index);
    InstructionDecoder decoder;
    decoder.init();
    MemoryModel memory(reader, index);
    timer.start();
    memory.build();
    double mem_ms = timer.elapsed_ms();
    fmt::print(stderr, "  Memory build: {:.1f} ms\n\n", mem_ms);

    // Setup PassManager with ONLY the loop chain: xref → cfg → loop
    PassManager pm;
    pm.set_reader(&reader);
    pm.set_index(&index);
    pm.set_code_table(&code_table);
    pm.set_regfile(&regfile);
    pm.set_memory(&memory);
    pm.set_decoder(&decoder);

    pm.register_pass(std::make_unique<XrefPass>());
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<LoopPass>());

    // Only register loop_semantics if explicitly requested (it's O(N) on full trace)
    bool run_semantics = (argc >= 3 && std::string(argv[2]) == "--with-semantics");
    if (run_semantics) {
        pm.register_pass(std::make_unique<LoopSemanticsPass>());
    }

    // Benchmark each pass individually
    fmt::print(stderr, "{:<20} {:>10}   {}\n", "PASS", "TIME (ms)", "STATUS");
    fmt::print(stderr, "{}\n", std::string(50, '-'));

    // 1. xref
    timer.start();
    const auto& xref_result = pm.require("xref");
    double xref_ms = timer.elapsed_ms();
    fmt::print(stderr, "{:<20} {:>10.1f}   {}\n", "xref", xref_ms,
               xref_result.ok() ? "OK" : "FAIL");

    // 2. cfg
    timer.start();
    const auto& cfg_result = pm.require("cfg");
    double cfg_ms = timer.elapsed_ms();
    fmt::print(stderr, "{:<20} {:>10.1f}   {}\n", "cfg", cfg_ms,
               cfg_result.ok() ? "OK" : "FAIL");

    if (cfg_result.ok()) {
        const auto& cfg = cfg_result.get<CFGResult>();
        fmt::print(stderr, "    (blocks={}, edges={})\n", cfg.blocks.size(), cfg.edges.size());
    }

    // 3. loop (the target!)
    timer.start();
    const auto& loop_result = pm.require("loop");
    double loop_ms = timer.elapsed_ms();
    fmt::print(stderr, "{:<20} {:>10.1f}   {}\n", "loop", loop_ms,
               loop_result.ok() ? "OK" : "FAIL");

    if (loop_result.ok()) {
        const auto& loops = loop_result.get<LoopResult>();
        fmt::print(stderr, "    (loops={}, max_nesting={}, back_edges={}, loop_pcs={})\n",
                   loops.loops.size(), loops.max_nesting_depth,
                   loops.total_back_edges, loops.pc_loop_depth.size());
    }

    // 4. loop_semantics (optional, very slow on large traces)
    double sem_ms = 0;
    if (run_semantics) {
        timer.start();
        const auto& sem_result = pm.require("loop_semantics");
        sem_ms = timer.elapsed_ms();
        fmt::print(stderr, "{:<20} {:>10.1f}   {}\n", "loop_semantics", sem_ms,
                   sem_result.ok() ? "OK" : "FAIL");
    } else {
        fmt::print(stderr, "{:<20} {:>10}   {}\n", "loop_semantics", "SKIPPED",
                   "(use --with-semantics to enable)");
    }

    // Summary
    fmt::print(stderr, "{}\n", std::string(50, '-'));
    fmt::print(stderr, "\n  TOTAL (xref+cfg+loop):      {:.1f} ms\n", xref_ms + cfg_ms + loop_ms);
    fmt::print(stderr, "  Loop pass ONLY:             {:.1f} ms\n", loop_ms);
    fmt::print(stderr, "  Throughput:                 {:.1f}M insts/sec (loop pass)\n",
               index.inst_count() / (loop_ms / 1000.0) / 1e6);
    fmt::print(stderr, "  File throughput:            {:.1f} GB/sec (loop pass)\n",
               reader.file_size() / (loop_ms / 1000.0) / (1024.0*1024.0*1024.0));

    return 0;
}

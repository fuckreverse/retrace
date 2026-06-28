/// bench_memory_snapshot.cpp — Targeted benchmark for memory_snapshot pass only.
/// Only runs function + memory_snapshot (and their deps) for fast iteration.
///
/// Usage: bench_memory_snapshot <trace_file>

#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/memory_snapshot_pass.h"

#include <fmt/core.h>
#include <chrono>
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
    fmt::print(stderr, "  Size: {:.2f} MB\n", reader.file_size() / (1024.0*1024.0));

    // Index
    Timer timer;
    timer.start();
    auto index_res = TraceIndex::open_or_build(reader);
    double index_ms = timer.elapsed_ms();
    if (!index_res) {
        fmt::print(stderr, "Error building index: {}\n", index_res.error().message);
        return 1;
    }
    auto& index = *index_res;
    fmt::print(stderr, "  Index: {} insts, {} anchors ({:.1f} ms)\n",
               index.inst_count(), index.stats().anchor_count, index_ms);

    // CodeTable
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
    fmt::print(stderr, "  CodeTable: {} PCs\n", code_table.size());

    // Core
    RegisterFile regfile(reader, index);
    InstructionDecoder decoder;
    decoder.init();
    // Use RocksDB-backed MemoryModel (same as production code) for accurate benchmarking.
    MemoryModel memory(reader, index,
                       index.raw_db(), index.mem_write_cf(), index.mem_read_cf());
    timer.start();
    memory.build();
    fmt::print(stderr, "  Memory build: {:.1f} ms\n\n", timer.elapsed_ms());

    // PassManager — only register function + memory_snapshot
    PassManager pm;
    pm.set_reader(&reader);
    pm.set_index(&index);
    pm.set_code_table(&code_table);
    pm.set_regfile(&regfile);
    pm.set_memory(&memory);
    pm.set_decoder(&decoder);

    pm.register_pass(std::make_unique<FunctionPass>());

    MemorySnapshotConfig ms_cfg;
    uint64_t n = index.inst_count();
    ms_cfg.snapshot_inst_ids = {0, n/4, n/2, 3*n/4};
    ms_cfg.snapshot_size = 64;
    pm.register_pass(std::make_unique<MemorySnapshotPass>(std::move(ms_cfg)));

    // Run function pass
    timer.start();
    pm.require("function");
    double func_ms = timer.elapsed_ms();
    fmt::print(stderr, "  function pass: {:.1f} ms\n", func_ms);

    // Run memory_snapshot pass
    timer.start();
    pm.require("memory_snapshot");
    double ms_ms = timer.elapsed_ms();
    fmt::print(stderr, "  memory_snapshot pass: {:.1f} ms\n", ms_ms);

    fmt::print(stderr, "\n  TOTAL (function + memory_snapshot): {:.1f} ms\n", func_ms + ms_ms);

    return 0;
}

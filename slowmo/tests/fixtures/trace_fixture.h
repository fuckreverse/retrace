/*
 * trace_fixture.h — Shared Catch2 test fixture for Tenet analysis passes.
 *
 * Generates a synthetic AArch64 trace to a temp directory, then assembles the
 * full IO + Core + PassManager stack exactly as main.cpp does, so each test
 * can run any analysis pass against a known-good trace with one line of setup.
 *
 * Usage:
 *   #include "fixtures/trace_fixture.h"
 *   using namespace tenet::test;
 *
 *   TEST_CASE("XrefPass indexes PCs") {
 *       auto env = make_env([](TraceWriter& tw) {
 *           tw.write_header();
 *           MachineState ms; ms.sp() = 0x16F000000ULL;
 *           tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
 *           tw.emit(ms, 0x1004, enc::add_imm(0,0,1), {{0,1ULL},{33,tw.rt(0x1008)}}, {});
 *           tw.emit_anchor(ms);
 *       }, "xref_basic");
 *
 *       auto pm = make_pm(*env);
 *       pm->register_pass(std::make_unique<XrefPass>());
 *       auto& xr = pm->require("xref").get<XrefResult>();
 *       REQUIRE(xr.unique_pc_count == 2);
 *   }
 */
#ifndef TENET_TEST_TRACE_FIXTURE_H
#define TENET_TEST_TRACE_FIXTURE_H

#include "fixtures/trace_writer.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <unistd.h>   // getpid()

namespace tenet::test {

/// Owns the full IO + Core layer stack for a single test trace.
/// Non-copyable, non-movable (RegisterFile/MemoryModel hold references).
struct TraceEnv {
    std::filesystem::path temp_dir;
    std::filesystem::path trace_path;

    std::unique_ptr<TraceReader>    reader;
    std::unique_ptr<TraceIndex>     index;
    CodeTable                        code_table;
    InstructionDecoder               decoder;
    std::unique_ptr<RegisterFile>   regfile;
    std::unique_ptr<MemoryModel>    memory;

    ~TraceEnv() {
        // Destruction order: memory → regfile → decoder → code_table → index → reader
        // (regfile/memory hold references to reader+index, so must die first)
        memory.reset();
        regfile.reset();
        index.reset();
        reader.reset();
        std::filesystem::remove_all(temp_dir);
    }
};

/// Generate a trace using `gen`, then load it and build the full stack.
/// `gen` receives an open TraceWriter with header NOT yet written; it must
/// call tw.write_header(), emit records, then the writer is closed automatically.
inline std::unique_ptr<TraceEnv> make_env(
        std::function<void(TraceWriter&)> gen,
        const char* name = "test") {

    // ── Create a unique temp directory ──────────────────────────────────
    std::string dir_name = std::string("tenet_test_") + name + "_" +
                           std::to_string(getpid()) + "_" +
                           std::to_string(reinterpret_cast<uintptr_t>(&gen));
    auto temp_dir = std::filesystem::temp_directory_path() / dir_name;
    std::filesystem::remove_all(temp_dir);
    std::filesystem::create_directories(temp_dir);

    auto trace_path = temp_dir / (std::string(name) + ".trace");

    // ── Generate the trace ──────────────────────────────────────────────
    {
        TraceWriter tw;
        tw.module_name = name;
        if (!tw.open(trace_path.c_str())) return nullptr;
        gen(tw);
        tw.close();
    }

    auto env = std::make_unique<TraceEnv>();
    env->temp_dir = temp_dir;
    env->trace_path = trace_path;

    // ── Open TraceReader ────────────────────────────────────────────────
    auto reader_result = TraceReader::open(trace_path);
    if (!reader_result) {
        std::filesystem::remove_all(temp_dir);
        return nullptr;
    }
    env->reader = std::make_unique<TraceReader>(std::move(*reader_result));

    // ── Build TraceIndex (RocksDB, cached in temp_dir) ──────────────────
    auto index_result = TraceIndex::open_or_build(*env->reader, nullptr);
    if (!index_result) {
        std::filesystem::remove_all(temp_dir);
        return nullptr;
    }
    env->index = std::make_unique<TraceIndex>(std::move(*index_result));

    // ── Populate CodeTable from trace CODE records ──────────────────────
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Code) {
            auto code = rec.as_code();
            if (code.size == 4) {
                uint32_t opcode = 0;
                std::memcpy(&opcode, code.bytes, 4);
                env->code_table.insert(code.pc, opcode);
            }
        }
    }

    // ── Initialize Capstone decoder ─────────────────────────────────────
    env->decoder.init();

    // ── Create RegisterFile + MemoryModel ───────────────────────────────
    env->regfile = std::make_unique<RegisterFile>(*env->reader, *env->index);
    env->memory  = std::make_unique<MemoryModel>(*env->reader, *env->index);

    return env;
}

/// Create a PassManager wired to the env's IO/Core layers.
inline std::unique_ptr<PassManager> make_pm(TraceEnv& env) {
    auto pm = std::make_unique<PassManager>();
    pm->set_reader(&*env.reader);
    pm->set_index(&*env.index);
    pm->set_code_table(&env.code_table);
    pm->set_regfile(&*env.regfile);
    pm->set_memory(&*env.memory);
    pm->set_decoder(&env.decoder);
    return pm;
}

/// Convenience: runtime PC for a static PC, using the fixture's default slide.
inline uint64_t rt_pc(uint64_t static_pc, uint64_t slide = 0x4000ULL) {
    return static_pc + slide;
}

} // namespace tenet::test

#endif // TENET_TEST_TRACE_FIXTURE_H

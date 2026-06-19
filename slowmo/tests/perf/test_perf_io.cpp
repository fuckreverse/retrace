/*
 * test_perf_io.cpp — Performance regression tests for Tenet IO layer.
 *
 * Measures and asserts minimum throughput for:
 *   - TraceReader sequential scan (MB/s, Minst/s)
 *   - CodeTable load from CODE records
 *   - TraceIndex build (RocksDB first-open)
 *
 * Traces are generated at moderate scale (200K-500K insts) so each test
 * completes in < 5 s on any modern machine.  Thresholds default to ~1/10
 * of typical M1 performance and are env-overridable.
 *
 * Run:  ctest -R 'perf.*io' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>

#include "perf/perf_utils.h"
#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"

using namespace tenet;
using namespace tenet::test;
using namespace tenet::test::perf;

// ═══════════════════════════════════════════════════════════════════════════════
// TraceReader sequential scan throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("IO scan throughput: 200K linear trace", "[perf][io]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_linear_trace, N), "perf_io_scan");
    REQUIRE(env != nullptr);

    // Warmup: first scan pages in the mmap
    {
        uint64_t cnt = 0;
        for (auto it = env->reader->begin(); it != env->reader->end(); ++it) ++cnt;
    }

    // Measured scan
    Timer t;
    t.start();
    uint64_t record_count = 0;
    env->reader->advise_sequential();
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        ++record_count;
    }
    double ms = t.elapsed_ms();

    REQUIRE(record_count > 0);
    PERF_CHECK_MBPS(ms, env->reader->file_size(), 50);      // > 50 MB/s
    PERF_CHECK_MINST(ms, N, 0.5);                            // > 500K inst/s
}

TEST_CASE("IO scan throughput: 200K memory trace", "[perf][io]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_memory_trace, N), "perf_io_mem");
    REQUIRE(env != nullptr);

    // Warmup
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {}

    Timer t;
    t.start();
    uint64_t record_count = 0;
    env->reader->advise_sequential();
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        ++record_count;
    }
    double ms = t.elapsed_ms();

    REQUIRE(record_count > 0);
    // Memory trace records are larger (each INST has a memacc), so MB/s is
    // the more meaningful metric here.
    PERF_CHECK_MBPS(ms, env->reader->file_size(), 50);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CodeTable load throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CodeTable load: 200K trace with unique PCs", "[perf][io]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_branchy_trace, N), "perf_io_codetable");
    REQUIRE(env != nullptr);

    // The fixture already loads CodeTable, but we rebuild it here to measure
    // just the CODE-record scan + insert path.
    CodeTable code_table;
    Timer t;
    t.start();
    uint64_t code_records = 0;
    for (auto it = env->reader->begin(); it != env->reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Code) {
            auto code = rec.as_code();
            if (code.size == 4) {
                uint32_t opcode = 0;
                std::memcpy(&opcode, code.bytes, 4);
                code_table.insert(code.pc, opcode);
                ++code_records;
            }
        }
    }
    double ms = t.elapsed_ms();

    REQUIRE(code_records > 0);
    REQUIRE(code_table.size() > 0);
    // Should complete in reasonable time (generous threshold for CI)
    PERF_CHECK_MAX_MS(ms, 3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TraceIndex build (RocksDB first-open, no cache)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Index build: 200K linear trace", "[perf][io]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_linear_trace, N), "perf_io_index");
    REQUIRE(env != nullptr);

    // The fixture already built an index.  To measure a cold build, we
    // delete the RocksDB directory and rebuild from scratch.
    // Must release the env's index handle first — RocksDB holds file locks
    // on macOS that prevent removing the directory.
    env->index.reset();
    env->regfile.reset();
    env->memory.reset();
    auto idx_path = env->trace_path;
    idx_path.replace_extension(".tenet_idx");
    std::filesystem::remove_all(idx_path);

    // Cold build: measure first-open time.
    double ms;
    {
        Timer t;
        t.start();
        auto idx_res = TraceIndex::open_or_build(*env->reader);
        ms = t.elapsed_ms();

        REQUIRE(idx_res.has_value());
        REQUIRE(idx_res->inst_count() == N);
        // idx_res destructs here, releasing the RocksDB file lock.
    }

    // Cold index build for 200K insts should be < 10s even on slow CI.
    PERF_CHECK_MAX_MS(ms, 10000);

    // Second build should be near-instant (cached).
    Timer t2;
    t2.start();
    auto idx2 = TraceIndex::open_or_build(*env->reader);
    double cached_ms = t2.elapsed_ms();
    REQUIRE(idx2.has_value());
    PERF_CHECK_MAX_MS(cached_ms, 2000);
}

TEST_CASE("Index build: 200K memory trace", "[perf][io]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_memory_trace, N), "perf_io_index_mem");
    REQUIRE(env != nullptr);

    // Release handles before deleting the RocksDB directory (see above).
    env->index.reset();
    env->regfile.reset();
    env->memory.reset();
    auto idx_path = env->trace_path;
    idx_path.replace_extension(".tenet_idx");
    std::filesystem::remove_all(idx_path);

    Timer t;
    t.start();
    auto idx_res = TraceIndex::open_or_build(*env->reader);
    double ms = t.elapsed_ms();

    REQUIRE(idx_res.has_value());
    REQUIRE(idx_res->inst_count() == N);
    // Memory traces have more data to index; allow more time.
    PERF_CHECK_MAX_MS(ms, 15000);
}

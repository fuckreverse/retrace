/*
 * test_perf_passes.cpp — Performance regression tests for Tenet analysis passes.
 *
 * Measures and asserts minimum throughput for:
 *   - XrefPass  (root pass, full trace scan)
 *   - CFGPass   (derived from xref, builds basic blocks + edges)
 *   - FunctionPass (root pass, detects call/return events)
 *   - CallGraphPass (derived from function)
 *   - LoopPass  (derived from cfg, detects back-edges + loop nesting)
 *   - TaintPass (derived from xref, forward propagation)
 *
 * Each pass is measured as the incremental time from pm.require() after
 * dependencies are already satisfied, consistent with bench_all_passes.cpp.
 *
 * Run:  ctest -R 'perf.*pass' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "perf/perf_utils.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/disassembly_pass.h"

using namespace tenet;
using namespace tenet::test;
using namespace tenet::test::perf;

// ═══════════════════════════════════════════════════════════════════════════════
// XrefPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("XrefPass throughput: 200K linear trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_linear_trace, N), "perf_pass_xref_lin");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());

    Timer t;
    t.start();
    auto& r = pm->require("xref");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& xr = r.get<XrefResult>();
    REQUIRE(xr.total_indexed == N);

    PERF_CHECK_MINST(ms, N, 0.3);  // > 300K inst/s
}

TEST_CASE("XrefPass throughput: 200K memory trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_memory_trace, N), "perf_pass_xref_mem");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());

    Timer t;
    t.start();
    auto& r = pm->require("xref");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& xr = r.get<XrefResult>();
    REQUIRE(xr.total_indexed == N);

    PERF_CHECK_MINST(ms, N, 0.2);  // > 200K inst/s (memory trace is heavier)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFGPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("CFGPass throughput: 200K branchy trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_branchy_trace, N), "perf_pass_cfg");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    // Pre-run xref so we measure only cfg's incremental cost
    pm->require("xref");

    Timer t;
    t.start();
    auto& r = pm->require("cfg");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& cfg = r.get<CFGResult>();
    REQUIRE(cfg.block_count() > 0);

    PERF_CHECK_MINST(ms, N, 0.15);  // > 150K inst/s
}

// ═══════════════════════════════════════════════════════════════════════════════
// FunctionPass + CallGraphPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("FunctionPass throughput: 200K calls trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_calls_trace, N), "perf_pass_func");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());

    Timer t;
    t.start();
    auto& r = pm->require("function");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& fr = r.get<FunctionResult>();
    REQUIRE(fr.call_events.size() > 0);

    PERF_CHECK_MINST(ms, N, 0.15);
}

TEST_CASE("CallGraphPass throughput: 200K calls trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_calls_trace, N), "perf_pass_cg");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    pm->require("function");  // pre-run dep

    Timer t;
    t.start();
    auto& r = pm->require("call_graph");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    PERF_CHECK_MAX_MS(ms, 3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LoopPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("LoopPass throughput: 200K branchy trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_branchy_trace, N), "perf_pass_loop");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    pm->require("xref");
    pm->require("cfg");

    Timer t;
    t.start();
    auto& r = pm->require("loop");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    PERF_CHECK_MINST(ms, N, 0.1);  // > 100K inst/s
}

// ═══════════════════════════════════════════════════════════════════════════════
// TaintPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TaintPass throughput: 100K taint chain", "[perf][pass]") {
    const uint64_t N = 100000;
    auto env = make_env(wrap_gen(gen_taint_trace, N), "perf_pass_taint");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());

    TaintConfig taint_cfg;
    taint_cfg.add_source_reg(0);  // x0
    taint_cfg.source_inst_id = 0;
    taint_cfg.propagate_through_calls = true;
    taint_cfg.use_xref_acceleration = true;
    pm->register_pass(std::make_unique<TaintPass>(std::move(taint_cfg)));

    pm->require("xref");  // pre-run dep

    Timer t;
    t.start();
    auto& r = pm->require("taint");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& tr = r.get<TaintResult>();
    REQUIRE(tr.instructions_processed > 0);

    PERF_CHECK_MINST(ms, N, 0.1);  // > 100K inst/s
}

// ═══════════════════════════════════════════════════════════════════════════════
// DisassemblyPass throughput
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("DisassemblyPass throughput: 200K linear trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_linear_trace, N), "perf_pass_disasm");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<DisassemblyPass>());

    Timer t;
    t.start();
    auto& r = pm->require("disassembly");
    double ms = t.elapsed_ms();

    REQUIRE(r.ok());
    auto& dt = r.get<DisasmTable>();
    REQUIRE(dt.unique_pc_count() > 0);

    PERF_CHECK_MINST(ms, N, 0.2);  // > 200K inst/s
}

// ═══════════════════════════════════════════════════════════════════════════════
// End-to-end pipeline throughput (xref → cfg → loop → function)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Full pipeline throughput: 200K mixed trace", "[perf][pass]") {
    const uint64_t N = 200000;
    auto env = make_env(wrap_gen(gen_branchy_trace, N), "perf_pass_pipeline");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<DisassemblyPass>());

    Timer t;
    t.start();
    pm->run_all(1);  // single-threaded, all registered passes
    double ms = t.elapsed_ms();

    REQUIRE(pm->state("xref") == PassManager::PassState::Completed);
    REQUIRE(pm->state("cfg") == PassManager::PassState::Completed);
    REQUIRE(pm->state("loop") == PassManager::PassState::Completed);

    // Full pipeline for 200K insts should complete in < 15s
    PERF_CHECK_MAX_MS(ms, 15000);
}

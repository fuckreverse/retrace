/*
 * test_pass_call_context.cpp — Unit tests for tenet::CallContextPass
 *
 * CallContextPass is a thin aggregation layer: the call stack is derived
 * from FunctionResult::call_stack_at() (not re-derived by scanning
 * BL/BLR/RET opcodes independently), and loop membership is derived from
 * LoopResult. These tests verify:
 *   - target_inst_id == 0 is treated as "not configured" (skipped).
 *   - target_inst_id beyond the trace length fails cleanly.
 *   - The reconstructed call stack matches FunctionPass's call_stack_at()
 *     for a simple 3-level call chain (main → foo → bar).
 *   - callee_pc / call_inst_id / return_inst_id / is_tail_call are all
 *     populated from the CallEvent (not left as stubs).
 *   - The instruction window (context_before/context_after) is correctly
 *     bounded and includes the target instruction exactly once.
 *   - Loop context correctly reports header_pc/nesting_depth/iteration_count
 *     for a target instruction inside a loop body, and is empty outside
 *     any loop.
 *
 * NOTE on inst_id numbering: CallContextConfig::target_inst_id and
 * CallContextResult (instructions[].inst_id, call_stack[].call_inst_id /
 * return_inst_id) all use CallContextPass's 1-based convention, where
 * inst_id 1 is the trace's first instruction and 0 is reserved as the
 * "not configured" sentinel. This differs from FunctionResult's
 * CallEvent::call_inst_id/return_inst_id, which are 0-based (matching
 * TraceScanEngine::on_inst()) — CallContextPass converts between the two
 * internally (see run()). Tests that call fn.call_stack_at() directly to
 * cross-check therefore pass 0-based ids (target_inst_id - 1).
 *
 * Run:  ctest -R 'call_context' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/call_context_pass.h"

using namespace tenet;
using namespace tenet::test;

namespace {

/// Register the full dependency chain (xref → cfg → loop, function) that
/// CallContextPass needs. Mirrors what register_pass_by_name() does
/// automatically in production (see pass_registry.cpp); tests must wire
/// this manually since they construct PassManager directly.
void register_call_context_deps(PassManager& pm) {
    pm.register_pass(std::make_unique<XrefPass>());
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<LoopPass>());
    pm.register_pass(std::make_unique<FunctionPass>());
}

}  // namespace

// ─── Shared trace builders ──────────────────────────────────────────────────

// 3-level call chain: main @0x1000 → foo @0x2000 → bar @0x3000, both return.
// inst_id is 1-based (CallContextPass convention):
//   inst 1: main:  bl foo         (call site 0x1000)
//   inst 2: foo:   bl bar         (call site 0x2000)
//   inst 3: bar:   ret
//   inst 4: foo:   ret  (0x2004)
//   inst 5: main:  ret  (0x1004)
static void gen_call_chain(TraceWriter& tw) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
    tw.emit(ms, 0x2000, enc::bl(0x3000 - 0x2000), {{30, tw.rt(0x2004)}, {33, tw.rt(0x3000)}}, {});
    tw.emit(ms, 0x3000, enc::ret(), {{33, tw.rt(0x2004)}}, {});
    tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

// A loop that runs `iterations` times, matching the pattern used by
// test_pass_loop.cpp's gen_simple_loop (so LoopPass reliably detects it).
//   0x1000: setup
//   0x1008: b 0x1010                (forces a BB boundary before the loop)
//   0x1010: cmp x0, #iterations     (loop header)
//   0x1014: b.ge 0x1020             (exit branch)
//   0x1018: add x0, x0, #1          (loop body)
//   0x101C: b 0x1010                (back-edge)
//   0x1020: ret
static void gen_simple_loop(TraceWriter& tw, int iterations) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    uint64_t loop_top    = 0x1010;
    uint64_t loop_branch = 0x1014;
    uint64_t loop_body   = 0x1018;
    uint64_t loop_back   = 0x101C;
    uint64_t loop_exit   = 0x1020;

    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::b((int32_t)(loop_top - 0x1008)), {{33, tw.rt(loop_top)}}, {});

    for (int i = 0; i < iterations; i++) {
        tw.emit(ms, loop_top, enc::cmp_imm(0, (uint16_t)iterations),
                {{33, tw.rt(loop_branch)}}, {}, 0x8);
        tw.emit(ms, loop_branch, enc::b_ge((int32_t)(loop_exit - loop_branch)),
                {{33, tw.rt(loop_body)}}, {}, 0x8);
        tw.emit(ms, loop_body, enc::add_imm(0, 0, 1),
                {{0, (uint64_t)(i + 1)}, {33, tw.rt(loop_back)}}, {});
        tw.emit(ms, loop_back, enc::b((int32_t)(loop_top - loop_back)),
                {{33, tw.rt(loop_top)}}, {});
    }
    // Final header evaluation exits the loop.
    tw.emit(ms, loop_top, enc::cmp_imm(0, (uint16_t)iterations),
            {{33, tw.rt(loop_branch)}}, {}, 0x6);
    tw.emit(ms, loop_branch, enc::b_ge((int32_t)(loop_exit - loop_branch)),
            {{33, tw.rt(loop_exit)}}, {}, 0x6);

    tw.emit(ms, loop_exit, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

// ─── Configuration edge cases ───────────────────────────────────────────────

TEST_CASE("CallContextPass: target_inst_id == 0 is skipped", "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_skip");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    CallContextConfig cfg;
    cfg.target_inst_id = 0;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& raw = pm->require("call_context");
    REQUIRE_FALSE(raw.ok());  // skipped() is not ok()
}

TEST_CASE("CallContextPass: target_inst_id beyond trace length fails",
          "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_oob");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    CallContextConfig cfg;
    cfg.target_inst_id = 1000000;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& raw = pm->require("call_context");
    REQUIRE_FALSE(raw.ok());
}

// ─── Call stack: derived from FunctionResult ────────────────────────────────

TEST_CASE("CallContextPass: call stack at innermost frame matches FunctionResult",
          "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_stack_inner");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    // inst 3 (1-based) is the `ret` inside bar — at this point both
    // main→foo and foo→bar calls are still open (2 frames on the stack).
    CallContextConfig cfg;
    cfg.target_inst_id = 3;
    cfg.context_before = 2;
    cfg.context_after = 0;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& raw = pm->require("call_context");
    REQUIRE(raw.ok());
    auto& result = raw.get<CallContextResult>();

    // Cross-check directly against FunctionResult::call_stack_at(), which
    // uses 0-based inst_id — subtract 1 to translate from this pass's
    // 1-based target_inst_id.
    auto& fn = pm->require("function").get<FunctionResult>();
    auto expected = fn.call_stack_at(cfg.target_inst_id - 1);

    SECTION("stack depth matches FunctionResult") {
        REQUIRE(result.call_stack.size() == expected.size());
        REQUIRE(result.call_stack.size() == 2);
    }
    SECTION("frame fields are populated from CallEvent (not left as stubs)") {
        for (size_t i = 0; i < result.call_stack.size(); i++) {
            const auto& frame = result.call_stack[i];
            const auto* evt = expected[i];
            REQUIRE(frame.call_site_pc == evt->call_site_pc);
            REQUIRE(frame.callee_pc == evt->target_pc);
            // CallContextPass reports 1-based ids; FunctionResult's raw
            // CallEvent is 0-based, hence the +1 here.
            REQUIRE(frame.call_inst_id == evt->call_inst_id + 1);
            REQUIRE(frame.return_inst_id == evt->return_inst_id + 1);
            REQUIRE(frame.is_tail_call == evt->is_tail_call);
        }
    }
    SECTION("callee_pc is non-zero (regression check: old impl always left this 0)") {
        for (const auto& frame : result.call_stack) {
            REQUIRE(frame.callee_pc != 0);
        }
    }
    SECTION("outermost frame first (main's call to foo)") {
        REQUIRE(result.call_stack.front().callee_pc == rt_pc(0x2000));
    }
    SECTION("innermost frame last (foo's call to bar)") {
        REQUIRE(result.call_stack.back().callee_pc == rt_pc(0x3000));
    }
}

TEST_CASE("CallContextPass: call stack is empty after all functions return",
          "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_stack_empty");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    // inst 5 (1-based) is main's final `ret` — by this point both calls
    // have returned.
    CallContextConfig cfg;
    cfg.target_inst_id = 5;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& result = pm->require("call_context").get<CallContextResult>();
    REQUIRE(result.call_stack.empty());
}

// ─── Instruction window ──────────────────────────────────────────────────

TEST_CASE("CallContextPass: instruction window is bounded and includes target once",
          "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_window");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    CallContextConfig cfg;
    cfg.target_inst_id = 3;
    cfg.context_before = 1;
    cfg.context_after = 1;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& result = pm->require("call_context").get<CallContextResult>();

    SECTION("window has exactly context_before + 1 + context_after entries") {
        REQUIRE(result.instructions.size() == 3);  // insts 2, 3, 4
    }
    SECTION("exactly one instruction is marked as target") {
        size_t target_count = 0;
        for (const auto& ci : result.instructions) {
            if (ci.is_target) target_count++;
        }
        REQUIRE(target_count == 1);
    }
    SECTION("target_pc matches the target instruction's pc") {
        for (const auto& ci : result.instructions) {
            if (ci.is_target) {
                REQUIRE(ci.pc == result.target_pc);
                REQUIRE(ci.inst_id == 3);
            }
        }
    }
    SECTION("disassembly is populated for every instruction") {
        for (const auto& ci : result.instructions) {
            REQUIRE_FALSE(ci.disassembly.empty());
        }
    }
    SECTION("instructions are in ascending inst_id order") {
        for (size_t i = 1; i < result.instructions.size(); i++) {
            REQUIRE(result.instructions[i].inst_id > result.instructions[i - 1].inst_id);
        }
    }
}

TEST_CASE("CallContextPass: window clamps at trace start", "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_window_clamp_start");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    // Target is the very first instruction; context_before=10 should clamp
    // to inst_id 1 rather than underflowing.
    CallContextConfig cfg;
    cfg.target_inst_id = 1;
    cfg.context_before = 10;
    cfg.context_after = 1;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& raw = pm->require("call_context");
    REQUIRE(raw.ok());
    auto& result = raw.get<CallContextResult>();

    SECTION("no instruction has inst_id < 1") {
        for (const auto& ci : result.instructions) {
            REQUIRE(ci.inst_id >= 1);
        }
    }
    SECTION("first instruction in window is inst_id 1") {
        REQUIRE_FALSE(result.instructions.empty());
        REQUIRE(result.instructions.front().inst_id == 1);
    }
}

TEST_CASE("CallContextPass: window clamps at trace end", "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_window_clamp_end");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    CallContextConfig cfg;
    cfg.target_inst_id = 5;   // last instruction in the 5-inst (1..5) trace
    cfg.context_before = 1;
    cfg.context_after = 10;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& result = pm->require("call_context").get<CallContextResult>();

    SECTION("no instruction has inst_id beyond the trace length") {
        for (const auto& ci : result.instructions) {
            REQUIRE(ci.inst_id <= 5);
        }
    }
    SECTION("last instruction in window is inst_id 5") {
        REQUIRE_FALSE(result.instructions.empty());
        REQUIRE(result.instructions.back().inst_id == 5);
    }
}

// ─── Loop context ────────────────────────────────────────────────────────

TEST_CASE("CallContextPass: loop context reports header/depth/iterations for in-loop target",
          "[unit][pass][call_context]") {
    auto env = make_env([](TraceWriter& tw) { gen_simple_loop(tw, 5); }, "cc_loop");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    // Locate a loop-body instruction using CallContextPass's 1-based
    // inst_id numbering:
    //   inst 1: movz (setup)
    //   inst 2: b            (forces a BB boundary before the loop)
    //   inst 3: cmp          (loop header, 1st iteration)
    //   inst 4: b.ge         (exit branch, 1st iteration)
    //   inst 5: add          (loop body, 1st iteration)  <- target
    //   inst 6: b            (back-edge, 1st iteration)
    //   ...
    uint64_t target = 5;

    CallContextConfig cfg;
    cfg.target_inst_id = target;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& raw = pm->require("call_context");
    REQUIRE(raw.ok());
    auto& result = raw.get<CallContextResult>();

    // Confirm this inst_id is really inside the loop before asserting on it,
    // so the test doesn't silently pass if instruction numbering ever shifts.
    auto& loops = pm->require("loop").get<LoopResult>();
    bool target_in_loop = loops.is_in_loop(result.target_pc);
    REQUIRE(target_in_loop);

    SECTION("loop_contexts is non-empty for an in-loop instruction") {
        REQUIRE_FALSE(result.loop_contexts.empty());
    }
    SECTION("reported header_pc matches a real loop header") {
        bool matched = false;
        for (const auto& lc : result.loop_contexts) {
            if (loops.is_loop_header(lc.header_pc)) matched = true;
        }
        REQUIRE(matched);
    }
    SECTION("total_iterations is positive") {
        for (const auto& lc : result.loop_contexts) {
            REQUIRE(lc.total_iterations > 0);
        }
    }
}

TEST_CASE("CallContextPass: loop context is empty for target outside any loop",
          "[unit][pass][call_context]") {
    auto env = make_env(gen_call_chain, "cc_no_loop");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    register_call_context_deps(*pm);

    CallContextConfig cfg;
    cfg.target_inst_id = 1;
    pm->register_pass(std::make_unique<CallContextPass>(cfg));

    auto& result = pm->require("call_context").get<CallContextResult>();
    REQUIRE(result.loop_contexts.empty());
}

// ─── Dependency wiring ───────────────────────────────────────────────────

TEST_CASE("CallContextPass: declares function and loop as dependencies",
          "[unit][pass][call_context]") {
    // register_pass_by_name() (production entry point, see pass_registry.cpp)
    // relies on AnalysisPass::dependencies() to auto-pull "function" and
    // "loop" — verify the declared list still matches what run() actually
    // requires, so the pass never silently regresses to a hidden dependency.
    CallContextPass pass;
    auto deps = pass.dependencies();
    bool has_function = false, has_loop = false;
    for (auto d : deps) {
        if (d == "function") has_function = true;
        if (d == "loop") has_loop = true;
    }
    REQUIRE(has_function);
    REQUIRE(has_loop);
}

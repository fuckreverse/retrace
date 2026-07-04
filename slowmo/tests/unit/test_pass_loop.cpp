/*
 * test_pass_loop.cpp — Unit tests for tenet::LoopPass
 *
 * Verifies: loop header detection, back-edge identification, iteration
 * counting, loop body membership, and nesting depth.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"

using namespace tenet;
using namespace tenet::test;

// Helper: generate a simple loop that executes N iterations.
//
// Layout:
//   0x1000: movz x0, #0          (setup)
//   0x1004: movz x1, #N          (setup)
//   0x1008: b 0x1010             (unconditional branch — forces BB boundary
//                                 so setup is NOT merged with the loop top)
//   0x1010: cmp x0, x1           (loop header)
//   0x1014: b.ge 0x1020          (exit when x0 >= x1)
//   0x1018: add x0, x0, #1       (loop body)
//   0x101C: b 0x1010             (unconditional back-edge)
//   0x1020: ret                  (exit)
//
// The unconditional `b` at 0x1008 separates setup from the loop so the CFG
// pass does not merge them into one basic block (which would make the loop
// header land at 0x1000). The explicit unconditional back-edge at 0x101C is
// taken on every iteration, so iteration_count == N.
static void gen_simple_loop(TraceWriter& tw, int iterations) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    // Setup
    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::movz(1, (uint16_t)iterations),
            {{1, (uint64_t)iterations}, {33, tw.rt(0x1008)}}, {});

    uint64_t loop_top    = 0x1010;
    uint64_t loop_branch = 0x1014;
    uint64_t loop_body   = 0x1018;
    uint64_t loop_back   = 0x101C;
    uint64_t loop_exit   = 0x1020;

    // Unconditional branch: setup → loop top (forces BB boundary)
    tw.emit(ms, 0x1008, enc::b((int32_t)(loop_top - 0x1008)),
            {{33, tw.rt(loop_top)}}, {});

    // N iterations, each ending with an unconditional back-edge.
    for (int i = 0; i < iterations; i++) {
        // 0x1010: cmp x0, x1  (x0 < iterations → GE not set)
        tw.emit(ms, loop_top, enc::cmp_imm(0, (uint16_t)iterations),
                {{33, tw.rt(loop_branch)}}, {}, 0x8);
        // 0x1014: b.ge exit (not taken → fall through to body)
        tw.emit(ms, loop_branch, enc::b_ge((int32_t)(loop_exit - loop_branch)),
                {{33, tw.rt(loop_body)}}, {}, 0x8);
        // 0x1018: add x0, x0, #1
        tw.emit(ms, loop_body, enc::add_imm(0, 0, 1),
                {{0, (uint64_t)(i + 1)}, {33, tw.rt(loop_back)}}, {});
        // 0x101C: b loop_top (unconditional back-edge)
        tw.emit(ms, loop_back, enc::b((int32_t)(loop_top - loop_back)),
                {{33, tw.rt(loop_top)}}, {});
    }

    // Final entry: x0 == iterations → GE set, b.ge taken → exit
    tw.emit(ms, loop_top, enc::cmp_imm(0, (uint16_t)iterations),
            {{33, tw.rt(loop_branch)}}, {}, 0x6);
    tw.emit(ms, loop_branch, enc::b_ge((int32_t)(loop_exit - loop_branch)),
            {{33, tw.rt(loop_exit)}}, {}, 0x6);

    // Exit
    tw.emit(ms, loop_exit, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

TEST_CASE("LoopPass detects simple loop", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) { gen_simple_loop(tw, 5); }, "loop_simple");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& result_raw = pm->require("loop");
    REQUIRE(result_raw.ok());
    auto& lr = result_raw.get<LoopResult>();

    SECTION("at least one loop detected") {
        REQUIRE(lr.loops.size() >= 1);
    }

    SECTION("loop header is the back-edge target") {
        if (!lr.loops.empty()) {
            const auto& loop = lr.loops[0];
            REQUIRE(loop.header_pc == rt_pc(0x1010));
            REQUIRE(loop.iteration_count == 5);
        }
    }

    SECTION("loop body contains loop PCs") {
        if (!lr.loops.empty()) {
            const auto& loop = lr.loops[0];
            // The loop body should contain the header and the back-edge source
            bool has_loop_top = false, has_back = false;
            for (uint64_t pc : loop.body_pcs) {
                if (pc == rt_pc(0x1010)) has_loop_top = true;
                if (pc == rt_pc(0x101C)) has_back = true;
            }
            REQUIRE(has_loop_top);
            REQUIRE(has_back);
        }
    }
}

TEST_CASE("LoopPass is_loop_header query", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) { gen_simple_loop(tw, 3); }, "loop_header_q");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& lr = pm->require("loop").get<LoopResult>();

    SECTION("loop header PC is recognized") {
        REQUIRE(lr.is_loop_header(rt_pc(0x1010)));
    }

    SECTION("non-header PC is not a loop header") {
        REQUIRE_FALSE(lr.is_loop_header(rt_pc(0x1000)));
        REQUIRE_FALSE(lr.is_loop_header(rt_pc(0x1020)));
    }
}

TEST_CASE("LoopPass is_in_loop and loop_depth_at", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) { gen_simple_loop(tw, 4); }, "loop_depth");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& lr = pm->require("loop").get<LoopResult>();

    SECTION("loop body PCs are in a loop") {
        REQUIRE(lr.is_in_loop(rt_pc(0x1010)));
        REQUIRE(lr.is_in_loop(rt_pc(0x1014)));
        REQUIRE(lr.is_in_loop(rt_pc(0x1018)));
    }

    SECTION("non-loop PCs are not in a loop") {
        REQUIRE_FALSE(lr.is_in_loop(rt_pc(0x1000)));
        REQUIRE_FALSE(lr.is_in_loop(rt_pc(0x1020)));
    }

    SECTION("loop depth is 1 for single loop") {
        REQUIRE(lr.loop_depth_at(rt_pc(0x1010)) == 1);
        REQUIRE(lr.loop_depth_at(rt_pc(0x1000)) == 0);
    }
}

TEST_CASE("LoopPass no loops in linear trace", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Pure linear, no back-edges
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "loop_none");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& lr = pm->require("loop").get<LoopResult>();

    SECTION("no loops detected") {
        REQUIRE(lr.loops.empty());
        REQUIRE(lr.total_back_edges == 0);
    }

    SECTION("max nesting depth is 0") {
        REQUIRE(lr.max_nesting_depth == 0);
    }
}

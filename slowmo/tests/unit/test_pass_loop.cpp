/*
 * test_pass_loop.cpp — Unit tests for tenet::LoopPass
 *
 * Verifies: loop header detection, back-edge identification, iteration
 * counting, loop body membership, and nesting depth.
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>

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

    SECTION("exactly one loop detected") {
        // Precise count, not just "at least one" — this fixture has a
        // single unconditional back-edge, so exactly one LoopInfo must be
        // produced. A regression that starts over/under-merging back-edges
        // would silently pass a ">= 1" check but not this one.
        REQUIRE(lr.loops.size() == 1);
    }

    SECTION("loop header is the back-edge target") {
        // REQUIRE (not a size-guarded "if"): if loop detection ever
        // regresses to finding zero loops, this must FAIL the test, not
        // silently skip the assertion inside an `if (!empty())` guard.
        REQUIRE(lr.loops.size() == 1);
        const auto& loop = lr.loops[0];
        REQUIRE(loop.header_pc == rt_pc(0x1010));
        REQUIRE(loop.iteration_count == 5);
    }

    SECTION("loop body contains loop PCs") {
        REQUIRE(lr.loops.size() == 1);
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

// Helper: generate a nested loop — an outer loop (OUTER_N iterations) whose
// body contains a complete inner loop (INNER_N iterations per outer
// iteration).
//
// Layout:
//   0x1000: movz x0, #0            (outer counter init)
//   0x1004: b 0x1010               (force BB boundary)
//   0x1010: outer_header: cmp x0, #OUTER_N
//   0x1014: b.ge 0x103C            (outer exit)
//   0x1018: movz x1, #0            (inner counter init, start of outer body)
//   0x101C: b 0x1024               (force BB boundary)
//   0x1024: inner_header: cmp x1, #INNER_N
//   0x1028: b.ge 0x1034            (inner exit)
//   0x102C: add x1, x1, #1         (inner body)
//   0x1030: b 0x1024               (inner back-edge)
//   0x1034: inner_exit: add x0, x0, #1   (outer body continues)
//   0x1038: b 0x1010               (outer back-edge)
//   0x103C: outer_exit: ret
//
// The inner loop's header (0x1024) is only reachable through the outer
// loop's body, so it must be detected as nested one level inside the outer
// loop (0x1010), with iteration_count == OUTER_N * INNER_N for the inner
// loop and == OUTER_N for the outer loop.
static void gen_nested_loop(TraceWriter& tw, int outer_n, int inner_n) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    uint64_t outer_header = 0x1010;
    uint64_t outer_branch = 0x1014;
    uint64_t inner_setup  = 0x1018;
    uint64_t inner_header = 0x1024;
    uint64_t inner_branch = 0x1028;
    uint64_t inner_body   = 0x102C;
    uint64_t inner_back   = 0x1030;
    uint64_t inner_exit   = 0x1034;
    uint64_t outer_back   = 0x1038;
    uint64_t outer_exit   = 0x103C;

    // Setup outer counter
    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::b((int32_t)(outer_header - 0x1004)),
            {{33, tw.rt(outer_header)}}, {});

    for (int oi = 0; oi < outer_n; oi++) {
        // outer_header: cmp x0, outer_n (not taken -> enter body)
        tw.emit(ms, outer_header, enc::cmp_imm(0, (uint16_t)outer_n),
                {{33, tw.rt(outer_branch)}}, {}, 0x8);
        tw.emit(ms, outer_branch, enc::b_ge((int32_t)(outer_exit - outer_branch)),
                {{33, tw.rt(inner_setup)}}, {}, 0x8);

        // Inner counter setup
        tw.emit(ms, inner_setup, enc::movz(1, 0), {{1, 0ULL}, {33, tw.rt(0x101C)}}, {});
        tw.emit(ms, 0x101C, enc::b((int32_t)(inner_header - 0x101C)),
                {{33, tw.rt(inner_header)}}, {});

        for (int ii = 0; ii < inner_n; ii++) {
            tw.emit(ms, inner_header, enc::cmp_imm(1, (uint16_t)inner_n),
                    {{33, tw.rt(inner_branch)}}, {}, 0x8);
            tw.emit(ms, inner_branch, enc::b_ge((int32_t)(inner_exit - inner_branch)),
                    {{33, tw.rt(inner_body)}}, {}, 0x8);
            tw.emit(ms, inner_body, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(ii + 1)}, {33, tw.rt(inner_back)}}, {});
            tw.emit(ms, inner_back, enc::b((int32_t)(inner_header - inner_back)),
                    {{33, tw.rt(inner_header)}}, {});
        }
        // Final inner check: x1 == inner_n -> GE set -> exit inner loop
        tw.emit(ms, inner_header, enc::cmp_imm(1, (uint16_t)inner_n),
                {{33, tw.rt(inner_branch)}}, {}, 0x6);
        tw.emit(ms, inner_branch, enc::b_ge((int32_t)(inner_exit - inner_branch)),
                {{33, tw.rt(inner_exit)}}, {}, 0x6);

        // Outer body continues after inner loop
        tw.emit(ms, inner_exit, enc::add_imm(0, 0, 1),
                {{0, (uint64_t)(oi + 1)}, {33, tw.rt(outer_back)}}, {});
        tw.emit(ms, outer_back, enc::b((int32_t)(outer_header - outer_back)),
                {{33, tw.rt(outer_header)}}, {});
    }

    // Final outer check: x0 == outer_n -> GE set -> exit outer loop
    tw.emit(ms, outer_header, enc::cmp_imm(0, (uint16_t)outer_n),
            {{33, tw.rt(outer_branch)}}, {}, 0x6);
    tw.emit(ms, outer_branch, enc::b_ge((int32_t)(outer_exit - outer_branch)),
            {{33, tw.rt(outer_exit)}}, {}, 0x6);

    tw.emit(ms, outer_exit, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

TEST_CASE("LoopPass detects nested loops with correct nesting depth", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) { gen_nested_loop(tw, 2, 3); }, "loop_nested");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& result_raw = pm->require("loop");
    REQUIRE(result_raw.ok());
    auto& lr = result_raw.get<LoopResult>();

    SECTION("exactly two loops are detected") {
        REQUIRE(lr.loops.size() == 2);
    }

    SECTION("outer loop header is at 0x1010 with depth 0 and inner at 0x1024 with depth 1") {
        REQUIRE(lr.loops.size() == 2);
        const LoopInfo* outer = nullptr;
        const LoopInfo* inner = nullptr;
        for (const auto& loop : lr.loops) {
            if (loop.header_pc == rt_pc(0x1010)) outer = &loop;
            if (loop.header_pc == rt_pc(0x1024)) inner = &loop;
        }
        REQUIRE(outer != nullptr);
        REQUIRE(inner != nullptr);
        REQUIRE(outer->nesting_depth == 0);
        REQUIRE(inner->nesting_depth == 1);
    }

    SECTION("outer loop iterates 2 times, inner loop iterates 2*3=6 times total") {
        REQUIRE(lr.loops.size() == 2);
        for (const auto& loop : lr.loops) {
            if (loop.header_pc == rt_pc(0x1010)) {
                REQUIRE(loop.iteration_count == 2);
            } else if (loop.header_pc == rt_pc(0x1024)) {
                REQUIRE(loop.iteration_count == 6);
            }
        }
    }

    SECTION("inner header PC has loop_depth_at == 2 (nested one level inside outer)") {
        REQUIRE(lr.loop_depth_at(rt_pc(0x1024)) == 2);
        REQUIRE(lr.loop_depth_at(rt_pc(0x1010)) == 1);
    }

    SECTION("innermost_loop_at(inner header) resolves to the inner loop, not the outer one") {
        const LoopInfo* innermost = lr.innermost_loop_at(rt_pc(0x1024));
        REQUIRE(innermost != nullptr);
        REQUIRE(innermost->header_pc == rt_pc(0x1024));
    }

    SECTION("outer-only body PC (outer back-edge site) is depth 1, not 2") {
        // 0x1038 (outer_back) is only ever reached after the inner loop has
        // exited, so it belongs to the outer loop's body but NOT the inner
        // loop's — it must report nesting depth 1, confirming the two loop
        // bodies aren't conflated into a single flat region.
        REQUIRE(lr.loop_depth_at(rt_pc(0x1038)) == 1);
        REQUIRE_FALSE(lr.is_loop_header(rt_pc(0x1038)));
    }

    SECTION("max_nesting_depth is 1 (one level of nesting)") {
        REQUIRE(lr.max_nesting_depth == 1);
    }
}

// Helper: generate a loop with TWO distinct back-edges into the same
// header — i.e. an if/else inside the loop body where either branch jumps
// straight back to the header (a common "continue"-style shape). LoopPass
// must merge these into a SINGLE LoopInfo (same header_pc), summing both
// back-edges' taken counts into iteration_count and unioning both paths'
// PCs into one body.
//
// Layout:
//   0x1000: movz x0, #0             (counter init)
//   0x1004: b 0x1010                (force BB boundary)
//   0x1010: header: cmp x0, #N
//   0x1014: b.ge 0x1030             (exit)
//   0x1018: cmp x0, #SPLIT          (which path to take this iteration)
//   0x101C: b.eq 0x1028             (branch to path_b)
//   0x1020: path_a: add x0, x0, #1
//   0x1024: b 0x1010                (back-edge #1, from path_a)
//   0x1028: path_b: add x0, x0, #1
//   0x102C: b 0x1010                (back-edge #2, from path_b, SAME header)
//   0x1030: exit: ret
//
// With N=4 and SPLIT=2: iterations 0,1,3 take path_a (3 times), iteration 2
// takes path_b (1 time) — so header@0x1010 must be reported exactly ONCE
// with iteration_count == 4 (3 + 1), not as two separate loops.
static void gen_multi_latch_loop(TraceWriter& tw, int n, int split_at) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    uint64_t header  = 0x1010;
    uint64_t branch  = 0x1014;
    uint64_t split_cmp = 0x1018;
    uint64_t split_b   = 0x101C;
    uint64_t path_a    = 0x1020;
    uint64_t back_a    = 0x1024;
    uint64_t path_b    = 0x1028;
    uint64_t back_b    = 0x102C;
    uint64_t exit_pc   = 0x1030;

    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::b((int32_t)(header - 0x1004)), {{33, tw.rt(header)}}, {});

    for (int i = 0; i < n; i++) {
        // header: cmp x0, n (not taken -> continue)
        tw.emit(ms, header, enc::cmp_imm(0, (uint16_t)n), {{33, tw.rt(branch)}}, {}, 0x8);
        tw.emit(ms, branch, enc::b_ge((int32_t)(exit_pc - branch)),
                {{33, tw.rt(split_cmp)}}, {}, 0x8);

        bool take_b = (i == split_at);
        // cmp x0, split_at
        tw.emit(ms, split_cmp, enc::cmp_imm(0, (uint16_t)split_at),
                {{33, tw.rt(split_b)}}, {}, take_b ? 0x6 : 0x0);
        tw.emit(ms, split_b, enc::b_eq((int32_t)(path_b - split_b)),
                {{33, tw.rt(take_b ? path_b : path_a)}}, {}, take_b ? 0x6 : 0x0);

        if (!take_b) {
            tw.emit(ms, path_a, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(back_a)}}, {});
            tw.emit(ms, back_a, enc::b((int32_t)(header - back_a)), {{33, tw.rt(header)}}, {});
        } else {
            tw.emit(ms, path_b, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(back_b)}}, {});
            tw.emit(ms, back_b, enc::b((int32_t)(header - back_b)), {{33, tw.rt(header)}}, {});
        }
    }

    // Final check: x0 == n -> GE set -> exit
    tw.emit(ms, header, enc::cmp_imm(0, (uint16_t)n), {{33, tw.rt(branch)}}, {}, 0x6);
    tw.emit(ms, branch, enc::b_ge((int32_t)(exit_pc - branch)), {{33, tw.rt(exit_pc)}}, {}, 0x6);

    tw.emit(ms, exit_pc, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

TEST_CASE("LoopPass merges multiple back-edges into the same header into one loop",
          "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) { gen_multi_latch_loop(tw, 4, 2); },
                         "loop_multi_latch");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    auto& result_raw = pm->require("loop");
    REQUIRE(result_raw.ok());
    auto& lr = result_raw.get<LoopResult>();

    SECTION("exactly one loop is reported (both latches merged)") {
        REQUIRE(lr.loops.size() == 1);
        REQUIRE(lr.loops[0].header_pc == rt_pc(0x1010));
    }

    SECTION("iteration_count sums both back-edges' taken counts (3 + 1 = 4)") {
        REQUIRE(lr.loops.size() == 1);
        REQUIRE(lr.loops[0].iteration_count == 4);
    }

    SECTION("merged body includes PCs from BOTH path_a and path_b") {
        REQUIRE(lr.loops.size() == 1);
        const auto& body = lr.loops[0].body_pcs;
        auto contains = [&](uint64_t pc) {
            return std::find(body.begin(), body.end(), pc) != body.end();
        };
        // path_a (0x1020/0x1024) and path_b (0x1028/0x102C) must BOTH be
        // present — if the pass only kept the last-seen latch's body
        // (instead of unioning), one of these would be missing.
        REQUIRE(contains(rt_pc(0x1020)));
        REQUIRE(contains(rt_pc(0x1024)));
        REQUIRE(contains(rt_pc(0x1028)));
        REQUIRE(contains(rt_pc(0x102C)));
    }

    SECTION("total_back_edges counts both latches separately (pre-merge count == 2)") {
        REQUIRE(lr.total_back_edges == 2);
    }

    SECTION("no spurious nesting: the single merged loop has nesting_depth 0") {
        REQUIRE(lr.loops.size() == 1);
        REQUIRE(lr.loops[0].nesting_depth == 0);
        REQUIRE(lr.max_nesting_depth == 0);
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

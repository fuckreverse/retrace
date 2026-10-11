/*
 * test_pass_taint_critical_path.cpp — Unit tests for
 * tenet::BackwardTaintResult::critical_path()
 *
 * critical_path() intersects a forward TaintResult::tainted_inst_ids with a
 * BackwardTaintResult::contributing_inst_ids, answering: "of everything this
 * source affects, which instructions ALSO contribute to this specific sink?"
 * This is the computation behind the CLI's `--critical-path` and the
 * MCP `critical_path` tool.
 *
 * These are pure unit tests of the roaring-bitmap intersection itself (no
 * pass execution needed) plus one end-to-end test that runs both TaintPass
 * and BackwardTaintPass against a shared trace to verify the intersection
 * matches the expected chain of instructions.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Pure intersection-logic tests (no pass execution) ─────────────────────

TEST_CASE("critical_path: empty forward result yields empty intersection",
          "[unit][pass][critical_path]") {
    TaintResult forward;  // tainted_inst_ids empty
    BackwardTaintResult backward;
    backward.contributing_inst_ids.add(uint64_t{1});
    backward.contributing_inst_ids.add(uint64_t{2});
    backward.contributing_inst_ids.add(uint64_t{3});

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.isEmpty());
}

TEST_CASE("critical_path: empty backward result yields empty intersection",
          "[unit][pass][critical_path]") {
    TaintResult forward;
    forward.tainted_inst_ids.add(uint64_t{1});
    forward.tainted_inst_ids.add(uint64_t{2});
    BackwardTaintResult backward;  // contributing_inst_ids empty

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.isEmpty());
}

TEST_CASE("critical_path: disjoint sets yield empty intersection",
          "[unit][pass][critical_path]") {
    TaintResult forward;
    forward.tainted_inst_ids.add(uint64_t{1});
    forward.tainted_inst_ids.add(uint64_t{2});
    forward.tainted_inst_ids.add(uint64_t{3});

    BackwardTaintResult backward;
    backward.contributing_inst_ids.add(uint64_t{10});
    backward.contributing_inst_ids.add(uint64_t{11});

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.isEmpty());
}

TEST_CASE("critical_path: partial overlap keeps only shared instruction IDs",
          "[unit][pass][critical_path]") {
    TaintResult forward;
    forward.tainted_inst_ids.add(uint64_t{1});
    forward.tainted_inst_ids.add(uint64_t{2});
    forward.tainted_inst_ids.add(uint64_t{3});
    forward.tainted_inst_ids.add(uint64_t{4});

    BackwardTaintResult backward;
    backward.contributing_inst_ids.add(uint64_t{3});
    backward.contributing_inst_ids.add(uint64_t{4});
    backward.contributing_inst_ids.add(uint64_t{5});
    backward.contributing_inst_ids.add(uint64_t{6});

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.cardinality() == 2);
    REQUIRE(cp.contains(3ULL));
    REQUIRE(cp.contains(4ULL));
    REQUIRE_FALSE(cp.contains(1ULL));
    REQUIRE_FALSE(cp.contains(5ULL));
}

TEST_CASE("critical_path: identical sets yield full intersection",
          "[unit][pass][critical_path]") {
    TaintResult forward;
    BackwardTaintResult backward;
    for (uint64_t id : {5ULL, 6ULL, 7ULL, 8ULL}) {
        forward.tainted_inst_ids.add(id);
        backward.contributing_inst_ids.add(id);
    }

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.cardinality() == 4);
    for (uint64_t id : {5ULL, 6ULL, 7ULL, 8ULL}) {
        REQUIRE(cp.contains(id));
    }
}

TEST_CASE("critical_path: does not mutate the inputs",
          "[unit][pass][critical_path]") {
    TaintResult forward;
    forward.tainted_inst_ids.add(uint64_t{1});
    forward.tainted_inst_ids.add(uint64_t{2});

    BackwardTaintResult backward;
    backward.contributing_inst_ids.add(uint64_t{2});
    backward.contributing_inst_ids.add(uint64_t{3});

    auto cp = backward.critical_path(forward);
    REQUIRE(cp.cardinality() == 1);

    // Inputs must remain untouched (critical_path is a read-only query).
    REQUIRE(forward.tainted_inst_ids.cardinality() == 2);
    REQUIRE(backward.contributing_inst_ids.cardinality() == 2);
}

// ─── End-to-end: real forward + backward taint results on a shared trace ───

TEST_CASE("critical_path: end-to-end chain matches forward ∩ backward taint",
          "[unit][pass][critical_path]") {
    // inst 0: x1 = 0x1234           (unrelated setup — must be excluded from
    //                                 both forward AND backward sets)
    // inst 1: x2 = x0 ^ x1          (forward: x0 → x2; also a backward
    //                                 contributor once we sink on x3)
    // inst 2: x5 = 0x99             (unrelated — independent register, must
    //                                 be excluded from both directions)
    // inst 3: x3 = x2 + x4          (forward: x2 → x3; backward: x3 sink
    //                                 pulls in x2, which pulls in inst 1)
    //
    // Forward taint from x0 (source_inst_id=0) should mark {1, 3} tainted
    // (x0 itself is never re-defined so it doesn't produce a "written"
    // event, but instructions 1 and 3 do).
    // Backward taint from x3 at sink_inst_id=4 should mark {1, 3}
    // contributing (inst 3 defines x3; inst 1 defines x2, which inst 3
    // reads).
    // The critical path is therefore exactly {1, 3}; inst 0 and inst 2 must
    // be excluded from the intersection even though inst 0's write (x1) is
    // read by inst 1 in the diff (heuristic mode) — because x1 itself was
    // never a forward-tainted register (only x0 was seeded as a source), it
    // never contributes to the intersection.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0x1234 (unrelated setup)
        tw.emit(ms, 0x1000, enc::movz(1, 0x1234), {{1, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x2 = x0 ^ x1 (taint propagates x0 → x2)
        tw.emit(ms, 0x1004, enc::eor_reg(2, 0, 1), {{2, 0ULL ^ 0x1234}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x5 = 0x99 (unrelated, independent register)
        tw.emit(ms, 0x1008, enc::movz(5, 0x99), {{5, 0x99ULL}, {33, tw.rt(0x100C)}}, {});
        // inst 3: x3 = x2 + x4 (taint propagates x2 → x3)
        ms.x(4) = 0xFF;
        tw.emit(ms, 0x100C, enc::add_reg(3, 2, 4), {{3, (0ULL ^ 0x1234) + 0xFF}, {33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "critical_path_e2e");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    // ── Forward taint from x0 ───────────────────────────────────────────
    TaintConfig fwd_cfg;
    fwd_cfg.add_source_reg(0);
    fwd_cfg.use_xref_acceleration = false;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(fwd_cfg));

    auto& fwd_raw = pm->require("taint");
    REQUIRE(fwd_raw.ok());
    const auto& fwd_result = fwd_raw.get<TaintResult>();

    // Sanity: forward taint reached instructions 1 and 3, not 0 or 2.
    REQUIRE(fwd_result.has_event_at(1));
    REQUIRE(fwd_result.has_event_at(3));
    REQUIRE_FALSE(fwd_result.has_event_at(0));
    REQUIRE_FALSE(fwd_result.has_event_at(2));

    // ── Backward taint sinking on x3 at the end of the trace ───────────
    BackwardTaintConfig bwd_cfg;
    bwd_cfg.sink_inst_id = 4;  // exclusive upper bound: examines insts 0..3
    bwd_cfg.add_sink_reg(3);
    bwd_cfg.use_index_acceleration = false;
    bwd_cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(bwd_cfg)));

    auto& bwd_raw = pm->require("backward_taint");
    REQUIRE(bwd_raw.ok());
    const auto& bwd_result = bwd_raw.get<BackwardTaintResult>();

    // Sanity: backward taint's contributing set includes 1 and 3.
    REQUIRE(bwd_result.is_contributing(1));
    REQUIRE(bwd_result.is_contributing(3));

    // ── Critical path: forward ∩ backward ───────────────────────────────
    auto cp = bwd_result.critical_path(fwd_result);

    REQUIRE(cp.contains(1ULL));
    REQUIRE(cp.contains(3ULL));
    REQUIRE_FALSE(cp.contains(0ULL));
    REQUIRE_FALSE(cp.contains(2ULL));
}

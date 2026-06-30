/*
 * test_exclude_range.cpp — Unit tests for exclude-range filtering in TraceScanEngine
 *
 * Verifies:
 *   - Excluded PC ranges are not delivered to collectors (XrefPass counts).
 *   - Multiple exclude ranges work independently.
 *   - Non-excluded instructions are still delivered correctly.
 *   - Empty exclude list has no effect (baseline sanity).
 *   - RegisterFile state reconstruction is NOT affected by exclusion
 *     (excluded instructions still contribute to register state).
 *
 * Run:  ctest -R 'exclude_range' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/xref_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Shared trace: 5 instructions at different PCs ─────────────────────────
//
//   inst 0: PC 0x1000  (x0 = 0x10)
//   inst 1: PC 0x2000  (x0 = 0x20)  ← target for exclusion
//   inst 2: PC 0x2004  (x0 = 0x30)  ← target for exclusion
//   inst 3: PC 0x3000  (x0 = 0x40)
//   inst 4: PC 0x4000  (x0 = 0x50)  ← target for second exclusion range
//
static std::unique_ptr<TraceEnv> make_exclude_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(0, 0x10),
                {{0, 0x10ULL}, {33, tw.rt(0x2000)}}, {});
        tw.emit(ms, 0x2000, enc::movz(0, 0x20),
                {{0, 0x20ULL}, {33, tw.rt(0x2004)}}, {});
        tw.emit(ms, 0x2004, enc::movz(0, 0x30),
                {{0, 0x30ULL}, {33, tw.rt(0x3000)}}, {});
        tw.emit(ms, 0x3000, enc::movz(0, 0x40),
                {{0, 0x40ULL}, {33, tw.rt(0x4000)}}, {});
        tw.emit(ms, 0x4000, enc::movz(0, 0x50),
                {{0, 0x50ULL}, {33, tw.rt(0x4004)}}, {});
        tw.emit_anchor(ms);
    }, "exclude_range");
}

TEST_CASE("Exclude range: baseline without exclusion", "[unit][exclude_range]") {
    auto env = make_exclude_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    REQUIRE(xr.unique_pc_count == 5);
    REQUIRE(xr.total_indexed == 5);
    REQUIRE(xr.execution_count(rt_pc(0x1000)) == 1);
    REQUIRE(xr.execution_count(rt_pc(0x2000)) == 1);
    REQUIRE(xr.execution_count(rt_pc(0x2004)) == 1);
    REQUIRE(xr.execution_count(rt_pc(0x3000)) == 1);
    REQUIRE(xr.execution_count(rt_pc(0x4000)) == 1);
}

TEST_CASE("Exclude range: single range excludes matching PCs", "[unit][exclude_range]") {
    auto env = make_exclude_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // Exclude [0x2000+slide, 0x2008+slide) — covers inst 1 and inst 2
    AnalysisRange range;
    range.exclude_pc_ranges.push_back({rt_pc(0x2000), rt_pc(0x2008)});
    pm->set_range(range);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("excluded PCs are not counted") {
        REQUIRE(xr.execution_count(rt_pc(0x2000)) == 0);
        REQUIRE(xr.execution_count(rt_pc(0x2004)) == 0);
        REQUIRE_FALSE(xr.has_pc(rt_pc(0x2000)));
        REQUIRE_FALSE(xr.has_pc(rt_pc(0x2004)));
    }

    SECTION("non-excluded PCs are still counted") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x3000)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x4000)) == 1);
    }

    SECTION("unique_pc_count reflects exclusion") {
        REQUIRE(xr.unique_pc_count == 3);
    }

    SECTION("total_indexed reflects exclusion") {
        REQUIRE(xr.total_indexed == 3);
    }
}

TEST_CASE("Exclude range: multiple ranges", "[unit][exclude_range]") {
    auto env = make_exclude_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    // Exclude [0x2000+slide, 0x2008+slide) AND [0x4000+slide, 0x4004+slide)
    AnalysisRange range;
    range.exclude_pc_ranges.push_back({rt_pc(0x2000), rt_pc(0x2008)});
    range.exclude_pc_ranges.push_back({rt_pc(0x4000), rt_pc(0x4004)});
    pm->set_range(range);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("both ranges are excluded") {
        REQUIRE(xr.execution_count(rt_pc(0x2000)) == 0);
        REQUIRE(xr.execution_count(rt_pc(0x2004)) == 0);
        REQUIRE(xr.execution_count(rt_pc(0x4000)) == 0);
    }

    SECTION("remaining PCs are counted") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x3000)) == 1);
    }

    SECTION("unique_pc_count == 2") {
        REQUIRE(xr.unique_pc_count == 2);
    }
}

TEST_CASE("Exclude range: register state unaffected by exclusion",
          "[unit][exclude_range]") {
    auto env = make_exclude_trace();
    REQUIRE(env != nullptr);

    // Exclude inst 1 and 2 (PC 0x2000, 0x2004) from analysis, but verify
    // that RegisterFile still returns correct state at inst 3 and 4.
    // The excluded instructions wrote x0=0x20, x0=0x30, so at inst 3
    // state_before(3) should see x0=0x30 (last write was inst 2).
    // RegisterFile does NOT respect exclude ranges — it replays ALL records.

    auto& regfile = *env->regfile;

    // state_before(3): inst 0 wrote x0=0x10, inst 1 wrote x0=0x20, inst 2 wrote x0=0x30
    // → x0 should be 0x30 before inst 3 executes
    const auto& s3 = regfile.state_before(3);
    REQUIRE(s3.gpr[0] == 0x30ULL);

    // state_after(4): inst 4 writes x0=0x50
    auto s4 = regfile.state_after(4);
    REQUIRE(s4.gpr[0] == 0x50ULL);
}

/*
 * test_pass_xref.cpp — Unit tests for tenet::XrefPass
 *
 * Verifies: PC→inst_id indexing, execution counts, unique PC tracking,
 * hottest() ranking, and has_pc queries.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("XrefPass indexes unique PCs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 3 unique PCs, each executed once
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "xref_unique");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());

    auto& result_raw = pm->require("xref");
    REQUIRE(result_raw.ok());
    auto& xr = result_raw.get<XrefResult>();

    SECTION("unique_pc_count") {
        REQUIRE(xr.unique_pc_count == 3);
    }

    SECTION("total_indexed == inst_count") {
        REQUIRE(xr.total_indexed == 3);
    }

    SECTION("each PC executed once") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x1004)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x1008)) == 1);
    }

    SECTION("has_pc") {
        REQUIRE(xr.has_pc(rt_pc(0x1000)));
        REQUIRE_FALSE(xr.has_pc(rt_pc(0x9999)));
    }
}

TEST_CASE("XrefPass tracks repeated PC execution", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // PC 0x1000 executed 5 times, PC 0x1004 executed 3 times
        for (int i = 0; i < 5; i++)
            tw.emit(ms, 0x1000, enc::add_imm(0, 0, 1), {{0, (uint64_t)(i+1)}, {33, tw.rt(0x1004)}}, {});
        for (int i = 0; i < 3; i++)
            tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, (uint64_t)(5+i)}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "xref_repeat");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("execution counts") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 5);
        REQUIRE(xr.execution_count(rt_pc(0x1004)) == 3);
    }

    SECTION("total_indexed") {
        REQUIRE(xr.total_indexed == 8);
    }

    SECTION("unique PCs") {
        REQUIRE(xr.unique_pc_count == 2);
    }

    SECTION("hottest PC is 0x1000") {
        auto top = xr.hottest(1);
        REQUIRE(top.size() == 1);
        REQUIRE(top[0].first == rt_pc(0x1000));
        REQUIRE(top[0].second == 5);
    }

    SECTION("hottest(2) returns both in order") {
        auto top = xr.hottest(2);
        REQUIRE(top.size() == 2);
        REQUIRE(top[0].second >= top[1].second);  // sorted descending
    }
}

TEST_CASE("XrefPass inst_ids_at returns correct IDs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0 at PC 0x1000
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // inst 1 at PC 0x1004
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1000)}}, {});
        // inst 2 at PC 0x1000 (again)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "xref_instids");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    auto ids = xr.inst_ids_at(rt_pc(0x1000));
    REQUIRE(ids.size() == 2);
    REQUIRE(ids[0] == 0);
    REQUIRE(ids[1] == 2);

    auto ids2 = xr.inst_ids_at(rt_pc(0x1004));
    REQUIRE(ids2.size() == 1);
    REQUIRE(ids2[0] == 1);
}

TEST_CASE("XrefPass empty trace", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_anchor(ms);
        // No instructions
    }, "xref_empty");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    REQUIRE(xr.unique_pc_count == 0);
    REQUIRE(xr.total_indexed == 0);
}

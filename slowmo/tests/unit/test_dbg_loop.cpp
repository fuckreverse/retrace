/*
 * test_dbg_loop.cpp — Unit test for loop detection in single-block loops.
 *
 * Verifies that CFGPass correctly identifies self-loop back edges when a
 * loop body consists of a single basic block (e.g. add; cmp; b.lt back).
 * Without the self-loop edge, LoopPass cannot detect these loops.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("Loop: single-block counter loop", "[unit][pass][loop]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;

        tw.emit(ms, 0x1000, enc::movz(0, 0),
                {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});

        const int N = 8;
        for (int i = 0; i < N; i++) {
            tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1008)}}, {});
            uint8_t nzcv = (i + 1 < N) ? 0x8 : 0x4;
            tw.emit(ms, 0x1008, enc::cmp_imm(0, (uint16_t)N),
                    {{33, tw.rt(0x100C)}}, {}, nzcv);
            if (i + 1 < N) {
                tw.emit(ms, 0x100C, enc::b_lt(-8),
                        {{33, tw.rt(0x1004)}}, {});
            } else {
                tw.emit(ms, 0x100C, enc::b_lt(-8),
                        {{33, tw.rt(0x1010)}}, {});
            }
        }
        tw.emit(ms, 0x1010, enc::nop(), {{33, tw.rt(0x1014)}}, {});
        tw.emit_anchor(ms);
    }, "dbg_loop");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<XrefPass>());
    auto& xref_raw = pm->require("xref");
    REQUIRE(xref_raw.ok());
    auto& xref = xref_raw.get<XrefResult>();
    INFO("xref unique_pc_count = " << xref.unique_pc_count);
    REQUIRE(xref.unique_pc_count > 0);

    pm->register_pass(std::make_unique<CFGPass>());
    auto& cfg_raw = pm->require("cfg");
    REQUIRE(cfg_raw.ok());
    auto& cfg = cfg_raw.get<CFGResult>();
    INFO("cfg blocks=" << cfg.blocks.size() << " edges=" << cfg.edges.size());

    for (const auto& e : cfg.edges) {
        UNSCOPED_INFO("edge 0x" << std::hex << e.from_block
                      << " -> 0x" << e.to_block << " count=" << e.taken_count);
    }

    pm->register_pass(std::make_unique<LoopPass>());
    auto& loop_raw = pm->require("loop");
    REQUIRE(loop_raw.ok());
    auto& lp = loop_raw.get<LoopResult>();
    INFO("loop count=" << lp.loops.size());
    for (const auto& l : lp.loops) {
        UNSCOPED_INFO("loop header_pc=0x" << std::hex << l.header_pc
                      << " iter=" << l.iteration_count);
    }

    CHECK(cfg.edges.size() >= 1);
    CHECK(lp.loops.size() >= 1);
}

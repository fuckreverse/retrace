/*
 * test_pass_function.cpp — Unit tests for tenet::FunctionPass
 *
 * Verifies: call/return pairing (BL→RET), call event recording,
 * function identification by entry PC, and call stack depth tracking.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/function_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("FunctionPass detects BL/RET pairing", "[unit][pass][function]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // 0x1000: mov x0, #1
        tw.emit(ms, 0x1000, enc::movz(0, 1), {{0, 1ULL}, {33, tw.rt(0x1004)}}, {});
        // 0x1004: bl 0x2000
        tw.emit(ms, 0x1004, enc::bl(0x2000 - 0x1004), {{30, tw.rt(0x1008)}, {33, tw.rt(0x2000)}}, {});
        // 0x2000: add x0, x0, #1  (callee entry)
        tw.emit(ms, 0x2000, enc::add_imm(0, 0, 1), {{0, 2ULL}, {33, tw.rt(0x2004)}}, {});
        // 0x2004: ret
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1008)}}, {});
        // 0x1008: ret (caller return)
        tw.emit(ms, 0x1008, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "func_bl_ret");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());

    auto& result_raw = pm->require("function");
    REQUIRE(result_raw.ok());
    auto& fr = result_raw.get<FunctionResult>();

    SECTION("call event recorded") {
        REQUIRE(fr.call_events.size() >= 1);

        const auto& ce = fr.call_events[0];
        REQUIRE(ce.call_site_pc == rt_pc(0x1004));
        REQUIRE(ce.target_pc == rt_pc(0x2000));
    }

    SECTION("function identified") {
        // The callee at 0x2000 should be in the functions map
        REQUIRE(fr.functions.count(rt_pc(0x2000)) >= 1);
        const auto& fi = fr.functions.at(rt_pc(0x2000));
        REQUIRE(fi.total_calls == 1);
    }
}

TEST_CASE("FunctionPass tracks nested calls", "[unit][pass][function]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // main @ 0x1000: bl foo @ 0x2000
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        // foo @ 0x2000: nop (prologue — FunctionPass resolves the previous
        // call's target_pc from the *next* instruction; a non-call instruction
        // at the callee entry is required so the fill-in fires before foo
        // itself issues a nested BL)
        tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
        // foo @ 0x2004: bl bar @ 0x3000
        tw.emit(ms, 0x2004, enc::bl(0x3000 - 0x2004), {{30, tw.rt(0x2008)}, {33, tw.rt(0x3000)}}, {});
        // bar @ 0x3000: ret
        tw.emit(ms, 0x3000, enc::ret(), {{33, tw.rt(0x2008)}}, {});
        // foo @ 0x2008: ret
        tw.emit(ms, 0x2008, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        // main @ 0x1004: ret
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "func_nested");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    auto& fr = pm->require("function").get<FunctionResult>();

    SECTION("two call events") {
        REQUIRE(fr.call_events.size() >= 2);
    }

    SECTION("call depth increases") {
        // First call (main→foo) has depth 0, second call (foo→bar) has depth 1
        REQUIRE(fr.call_events.size() >= 2);
        REQUIRE(fr.call_events[0].depth == 0);
        REQUIRE(fr.call_events[1].depth == 1);
    }

    SECTION("both callee functions identified") {
        // main→foo call targets foo at 0x2000
        REQUIRE(fr.call_events[0].target_pc == rt_pc(0x2000));
        // foo→bar call targets bar at 0x3000
        REQUIRE(fr.call_events[1].target_pc == rt_pc(0x3000));

        // Both functions registered with total_calls == 1
        REQUIRE(fr.functions.count(rt_pc(0x2000)) >= 1);
        REQUIRE(fr.functions.at(rt_pc(0x2000)).total_calls == 1);
        REQUIRE(fr.functions.count(rt_pc(0x3000)) >= 1);
        REQUIRE(fr.functions.at(rt_pc(0x3000)).total_calls == 1);
    }
}

TEST_CASE("FunctionPass detects repeated calls to same function", "[unit][pass][function]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Call foo twice
        for (int i = 0; i < 2; i++) {
            uint64_t call_pc = 0x1000 + i * 8;
            tw.emit(ms, call_pc, enc::bl(0x2000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x2000)}}, {});
            tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
            tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "func_repeated");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    auto& fr = pm->require("function").get<FunctionResult>();

    SECTION("foo called twice") {
        REQUIRE(fr.functions.count(rt_pc(0x2000)) >= 1);
        REQUIRE(fr.functions.at(rt_pc(0x2000)).total_calls == 2);
    }

    SECTION("two call events") {
        REQUIRE(fr.call_events.size() >= 2);
    }
}

TEST_CASE("FunctionPass call_at and return_at queries", "[unit][pass][function]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: bl 0x2000
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        // inst 1: ret (callee)
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "func_queries");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    auto& fr = pm->require("function").get<FunctionResult>();

    // inst 0 is a call site
    auto* call = fr.call_at(0);
    REQUIRE(call != nullptr);
    REQUIRE(call->target_pc == rt_pc(0x2000));

    // inst 1 is a return site
    auto* ret = fr.return_at(1);
    REQUIRE(ret != nullptr);
}

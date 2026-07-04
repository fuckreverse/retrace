/*
 * test_pass_function.cpp — Unit tests for tenet::FunctionPass
 *
 * Verifies: call/return pairing (BL→RET), call event recording,
 * function identification by entry PC, and call stack depth tracking.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/function_pass.h"

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

// ─── HF_BRANCH_HINT tests ─────────────────────────────────────────────────────

// Helper: compute the branch-hint nibble for a given opcode (mirrors the
// qbditrace logic so tests are self-consistent).
static uint8_t hint_for_opcode(uint32_t op) {
    // BL
    if ((op & 0xFC000000u) == 0x94000000u) return 1;
    // BLR
    if ((op & 0xFFFFFC00u) == 0xD63F0000u) return 1;
    // RET
    if ((op & 0xFFFFFC00u) == 0xD65F0000u) return 2;
    // B
    if ((op & 0xFC000000u) == 0x14000000u) return 4;
    // BR
    if ((op & 0xFFFFFC00u) == 0xD61F0000u) return 4;
    return 0;
}

TEST_CASE("InstView::branch_hint extracts high nibble", "[unit][pass][function][branch_hint]") {
    // Verify the accessor decodes high nibble correctly regardless of trace flag.
    // Build a minimal InstView by hand.
    auto make_view = [](uint8_t full_nzcv) -> InstView {
        InstView v;
        v.nzcv = full_nzcv;
        v.reg_diff_count = 0;
        v.fpr_diff_count = 0;
        v.mem_access_count = 0;
        v.raw_diffs = nullptr;
        v.raw_fprdiffs = nullptr;
        v.raw_mems = nullptr;
        v.pc = 0;
        return v;
    };

    SECTION("ordinary instruction — hint == 0") {
        auto v = make_view(0x0A);  // nzcv flags=0xA, hint=0
        REQUIRE(v.branch_hint() == 0);
        REQUIRE(v.nzcv_flags() == 0xA);
    }

    SECTION("CALL hint (1) — high nibble") {
        auto v = make_view((uint8_t)((1u << 4) | 0x5));  // hint=1, nzcv=0x5
        REQUIRE(v.branch_hint() == 1);
        REQUIRE(v.nzcv_flags() == 0x5);
    }

    SECTION("RET hint (2) — high nibble") {
        auto v = make_view((uint8_t)((2u << 4) | 0x0));
        REQUIRE(v.branch_hint() == 2);
        REQUIRE(v.nzcv_flags() == 0x0);
    }

    SECTION("BRANCH hint (4) — high nibble") {
        auto v = make_view((uint8_t)((4u << 4) | 0xF));
        REQUIRE(v.branch_hint() == 4);
        REQUIRE(v.nzcv_flags() == 0xF);
    }
}

TEST_CASE("FunctionPass works with HF_BRANCH_HINT trace", "[unit][pass][function][branch_hint]") {
    // Build a trace identical to the BL/RET test but using write_header_branch_hint
    // so the reader sets has_branch_hint() = true, and INST records carry the
    // branch class in the high nibble of nzcv.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_branch_hint();  // sets HF_BRANCH_HINT
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Encode nzcv with branch-hint nibble for each instruction.
        auto hint_nzcv = [](uint32_t opcode, uint8_t nzcv_flags) -> uint8_t {
            return (uint8_t)((hint_for_opcode(opcode) << 4) | (nzcv_flags & 0xF));
        };

        uint32_t bl_op  = enc::bl(0x2000 - 0x1004);
        uint32_t nop_op = enc::nop();
        uint32_t ret_op = enc::ret();

        // 0x1000: mov x0, #1
        tw.emit(ms, 0x1000, enc::movz(0, 1), {{0, 1ULL}, {33, tw.rt(0x1004)}}, {},
                hint_nzcv(enc::movz(0, 1), 0));
        // 0x1004: bl 0x2000  → hint = CALL(1)
        tw.emit(ms, 0x1004, bl_op,
                {{30, tw.rt(0x1008)}, {33, tw.rt(0x2000)}}, {},
                hint_nzcv(bl_op, 0));
        // 0x2000: nop  → hint = 0
        tw.emit(ms, 0x2000, nop_op, {{33, tw.rt(0x2004)}}, {},
                hint_nzcv(nop_op, 0));
        // 0x2004: ret  → hint = RET(2)
        tw.emit(ms, 0x2004, ret_op, {{33, tw.rt(0x1008)}}, {},
                hint_nzcv(ret_op, 0));
        // 0x1008: ret  → hint = RET(2)
        tw.emit(ms, 0x1008, ret_op, {{33, 0ULL}}, {},
                hint_nzcv(ret_op, 0));
        tw.emit_anchor(ms);
    }, "func_branch_hint");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());

    auto& result_raw = pm->require("function");
    REQUIRE(result_raw.ok());
    auto& fr = result_raw.get<FunctionResult>();

    SECTION("HF_BRANCH_HINT detected in header") {
        REQUIRE(env->reader->header().has_branch_hint() == true);
    }

    SECTION("call event recorded via hint path") {
        REQUIRE(fr.call_events.size() >= 1);
        const auto& ce = fr.call_events[0];
        REQUIRE(ce.call_site_pc == rt_pc(0x1004));
        REQUIRE(ce.target_pc == rt_pc(0x2000));
    }

    SECTION("function identified via hint path") {
        REQUIRE(fr.functions.count(rt_pc(0x2000)) >= 1);
        const auto& fi = fr.functions.at(rt_pc(0x2000));
        REQUIRE(fi.total_calls == 1);
    }
}

TEST_CASE("FunctionPass hint path == non-hint path for same trace structure",
          "[unit][pass][function][branch_hint]") {
    // Run the same call sequence through both the legacy (binary search) and
    // new (branch_hint) code paths and verify that the results are identical.
    const uint32_t bl_op  = enc::bl(0x2000 - 0x1000);
    const uint32_t nop_op = enc::nop();
    const uint32_t ret_op = enc::ret();

    auto hint_nzcv = [](uint32_t opcode, uint8_t nzcv_flags) -> uint8_t {
        return (uint8_t)((hint_for_opcode(opcode) << 4) | (nzcv_flags & 0xF));
    };

    // Build legacy trace (no HF_BRANCH_HINT)
    auto env_old = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();          // no HF_BRANCH_HINT
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, bl_op,  {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {}, 0);
        tw.emit(ms, 0x2000, nop_op, {{33, tw.rt(0x2004)}}, {}, 0);
        tw.emit(ms, 0x2004, ret_op, {{33, tw.rt(0x1004)}}, {}, 0);
        tw.emit_anchor(ms);
    }, "func_hint_compare_old");

    // Build new trace (with HF_BRANCH_HINT)
    auto env_new = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_branch_hint();  // has HF_BRANCH_HINT
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, bl_op,  {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {},
                hint_nzcv(bl_op, 0));
        tw.emit(ms, 0x2000, nop_op, {{33, tw.rt(0x2004)}}, {},
                hint_nzcv(nop_op, 0));
        tw.emit(ms, 0x2004, ret_op, {{33, tw.rt(0x1004)}}, {},
                hint_nzcv(ret_op, 0));
        tw.emit_anchor(ms);
    }, "func_hint_compare_new");

    auto pm_old = make_pm(*env_old);
    pm_old->register_pass(std::make_unique<FunctionPass>());
    auto& fr_old = pm_old->require("function").get<FunctionResult>();

    auto pm_new = make_pm(*env_new);
    pm_new->register_pass(std::make_unique<FunctionPass>());
    auto& fr_new = pm_new->require("function").get<FunctionResult>();

    SECTION("same number of call events") {
        REQUIRE(fr_old.call_events.size() == fr_new.call_events.size());
    }

    SECTION("same call site PC") {
        REQUIRE(!fr_old.call_events.empty());
        REQUIRE(!fr_new.call_events.empty());
        REQUIRE(fr_old.call_events[0].call_site_pc == fr_new.call_events[0].call_site_pc);
    }

    SECTION("same target PC") {
        REQUIRE(fr_old.call_events[0].target_pc == fr_new.call_events[0].target_pc);
    }

    SECTION("same function count") {
        REQUIRE(fr_old.functions.size() == fr_new.functions.size());
    }
}

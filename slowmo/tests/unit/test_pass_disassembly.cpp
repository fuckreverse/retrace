/*
 * test_pass_disassembly.cpp — Unit tests for tenet::DisassemblyPass
 *
 * Verifies: PC-indexed disassembly table construction, inst_id→PC
 * mapping, lookup() correctness, and per-PC entry deduplication.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/disassembly_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("DisassemblyPass builds PC-indexed table", "[unit][pass][disassembly]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "disasm_basic");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<DisassemblyPass>());

    auto& result_raw = pm->require("disassembly");
    REQUIRE(result_raw.ok());
    auto& dt = result_raw.get<DisasmTable>();

    SECTION("unique PC count") {
        REQUIRE(dt.unique_pc_count() == 3);
    }

    SECTION("inst count") {
        REQUIRE(dt.inst_count() == 3);
    }

    SECTION("pc_of returns correct PC for each inst_id") {
        REQUIRE(dt.pc_of(0) == rt_pc(0x1000));
        REQUIRE(dt.pc_of(1) == rt_pc(0x1004));
        REQUIRE(dt.pc_of(2) == rt_pc(0x1008));
    }

    SECTION("lookup returns decoded instruction") {
        auto e = dt.lookup(0);
        REQUIRE(e.has_value());
        REQUIRE(e->pc == rt_pc(0x1000));
        REQUIRE(e->mnemonic == "nop");
        REQUIRE(e->is_branch == false);
        REQUIRE(e->is_return == false);

        auto e2 = dt.lookup(2);
        REQUIRE(e2.has_value());
        REQUIRE(e2->mnemonic == "ret");
        REQUIRE(e2->is_return == true);
    }
}

TEST_CASE("DisassemblyPass deduplicates by PC", "[unit][pass][disassembly]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // PC 0x1000 executed 3 times, PC 0x1004 once
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1000)}}, {});
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "disasm_dedup");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<DisassemblyPass>());
    auto& dt = pm->require("disassembly").get<DisasmTable>();

    SECTION("only 2 unique PCs despite 4 instructions") {
        REQUIRE(dt.unique_pc_count() == 2);
        REQUIRE(dt.inst_count() == 4);
    }

    SECTION("pc_entry returns same entry for repeated PC") {
        auto* e1 = dt.pc_entry(rt_pc(0x1000));
        auto* e2 = dt.pc_entry(rt_pc(0x1000));
        REQUIRE(e1 != nullptr);
        REQUIRE(e2 != nullptr);
        REQUIRE(e1 == e2);  // same pointer (deduplicated)
    }
}

TEST_CASE("DisassemblyPass lookup out of range returns nullopt", "[unit][pass][disassembly]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "disasm_oor");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<DisassemblyPass>());
    auto& dt = pm->require("disassembly").get<DisasmTable>();

    // inst_id 0 exists, inst_id 99 does not
    REQUIRE(dt.lookup(0).has_value());
    REQUIRE_FALSE(dt.lookup(99).has_value());

    // pc_of returns 0 for unknown inst_id
    REQUIRE(dt.pc_of(99) == 0);
}

TEST_CASE("DisassemblyPass classifies branch/call/return/memory", "[unit][pass][disassembly]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // bl (call)
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        // ret (return)
        tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        // b (branch)
        tw.emit(ms, 0x1004, enc::b(0x100C - 0x1004), {{33, tw.rt(0x100C)}}, {});
        // ldr (load)
        tw.emit(ms, 0x100C, enc::ldr_imm(0, 31, 0), {{0, 0ULL}, {33, tw.rt(0x1010)}}, {{0, 8, 0x16F000000ULL, 0}});
        // str (store)
        tw.emit(ms, 0x1010, enc::str_imm(0, 31, 0), {{33, tw.rt(0x1014)}}, {{1, 8, 0x16F000000ULL, 0}});
        tw.emit_anchor(ms);
    }, "disasm_classify");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<DisassemblyPass>());
    auto& dt = pm->require("disassembly").get<DisasmTable>();

    auto call = dt.lookup(0);
    REQUIRE(call->is_call == true);

    auto ret = dt.lookup(1);
    REQUIRE(ret->is_return == true);

    auto branch = dt.lookup(2);
    REQUIRE(branch->is_branch == true);

    auto load = dt.lookup(3);
    REQUIRE(load->is_load == true);

    auto store = dt.lookup(4);
    REQUIRE(store->is_store == true);
}

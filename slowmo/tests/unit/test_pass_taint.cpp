/*
 * test_pass_taint.cpp — Unit tests for tenet::TaintPass
 *
 * Verifies: forward taint propagation (RegToReg, RegToMem, MemToReg),
 * kill semantics on immediate overwrite, and tainted register tracking.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/taint/taint_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("TaintResult exposes ordered event IDs without scanning the trace",
          "[unit][pass][taint][navigation]") {
    TaintResult result;
    result.tainted_inst_ids.add(uint64_t(42));
    result.tainted_inst_ids.add(uint64_t(3));
    result.tainted_inst_ids.add(uint64_t(17));

    const auto ids = result.ordered_event_inst_ids();

    REQUIRE(ids == std::vector<uint64_t>{3, 17, 42});
}

TEST_CASE("TaintPass propagates RegToReg", "[unit][pass][taint]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: x1 = 0x1234 (setup, don't touch x0 — the taint source)
        tw.emit(ms, 0x1000, enc::movz(1, 0x1234), {{1, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x2 = x0 ^ x1 (taint propagates x0 → x2)
        tw.emit(ms, 0x1004, enc::eor_reg(2, 0, 1), {{2, 0ULL ^ 0x1234}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x3 = x2 + x4 (taint propagates x2 → x3)
        ms.x(4) = 0xFF;
        tw.emit(ms, 0x1008, enc::add_reg(3, 2, 4), {{3, (0ULL ^ 0x1234) + 0xFF}, {33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "taint_regtoreg");

    auto pm = make_pm(*env);

    TaintConfig cfg;
    cfg.add_source_reg(0);  // x0 is the source
    cfg.use_xref_acceleration = false;  // simpler for small traces
    cfg.emit_propagation_steps = true;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(std::move(cfg)));

    auto& result_raw = pm->require("taint");
    REQUIRE(result_raw.ok());
    auto& tr = result_raw.get<TaintResult>();

    SECTION("x0 starts tainted") {
        // After processing, x2 and x3 should also be tainted
        REQUIRE(tr.is_tainted(0));  // x0 (never overwritten)
        REQUIRE(tr.is_tainted(2));  // x2 (from x0 via eor)
        REQUIRE(tr.is_tainted(3));  // x3 (from x2 via add)
    }

    SECTION("events recorded") {
        REQUIRE(tr.events.size() > 0);
    }

    SECTION("instructions processed") {
        REQUIRE(tr.instructions_processed == 3);
    }
}

TEST_CASE("TaintPass propagates RegToMem and MemToReg", "[unit][pass][taint]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        uint64_t buf = 0x1000ULL;

        // inst 0: x10 = 0x1000 (set up base address register so Triton
        // learns its concrete value for store/load address computation)
        tw.emit(ms, 0x1000, enc::movz(10, 0x1000), {{10, buf}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x1 = 0xDEAD (setup, don't touch x0 — the taint source)
        tw.emit(ms, 0x1004, enc::movz(1, 0xDEAD), {{1, 0xDEADULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: str x0, [x10]  (taint: x0 → mem)
        tw.emit(ms, 0x1008, enc::str_imm(0, 10, 0), {{33, tw.rt(0x100C)}}, {{2, 8, buf, 0ULL}});
        // inst 3: ldr x2, [x10]  (taint: mem → x2)
        tw.emit(ms, 0x100C, enc::ldr_imm(2, 10, 0), {{2, 0ULL}, {33, tw.rt(0x1010)}}, {{1, 8, buf, 0ULL}});
        tw.emit_anchor(ms);
    }, "taint_regmem");

    auto pm = make_pm(*env);

    TaintConfig cfg;
    cfg.add_source_reg(0);
    cfg.use_xref_acceleration = false;
    cfg.track_memory_sinks = true;
    cfg.taint_from_memory = true;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(std::move(cfg)));

    auto& tr = pm->require("taint").get<TaintResult>();

    SECTION("x0 tainted") {
        REQUIRE(tr.is_tainted(0));
    }

    SECTION("memory address tainted after store") {
        REQUIRE(tr.is_memory_addr_tainted(0x1000ULL));
    }

    SECTION("x2 tainted after load from tainted memory") {
        REQUIRE(tr.is_tainted(2));
    }

    SECTION("tainted memory count") {
        REQUIRE(tr.tainted_memory_count() >= 1);
    }
}

TEST_CASE("TaintPass kill on immediate overwrite", "[unit][pass][taint]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: x0 = 0xBEEF (source)
        tw.emit(ms, 0x1000, enc::movz(0, 0xBEEF), {{0, 0xBEEFULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x0 = 0x1234 (immediate overwrite → kills taint)
        tw.emit(ms, 0x1004, enc::movz(0, 0x1234), {{0, 0x1234ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "taint_kill");

    auto pm = make_pm(*env);

    TaintConfig cfg;
    cfg.add_source_reg(0);
    cfg.use_xref_acceleration = false;
    cfg.emit_kill_events = true;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(std::move(cfg)));

    auto& tr = pm->require("taint").get<TaintResult>();

    SECTION("x0 untainted after immediate overwrite") {
        REQUIRE_FALSE(tr.is_tainted(0));
    }

    SECTION("kill event recorded") {
        REQUIRE(tr.kill_events_count >= 1);
    }
}

TEST_CASE("TaintPass with no propagation path", "[unit][pass][taint]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // x1 = 0x1234 (setup, don't touch x0 — the taint source)
        tw.emit(ms, 0x1000, enc::movz(1, 0x1234), {{1, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        // x2 = 0x5678 (independent, unrelated to x0)
        tw.emit(ms, 0x1004, enc::movz(2, 0x5678), {{2, 0x5678ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "taint_no_prop");

    auto pm = make_pm(*env);

    TaintConfig cfg;
    cfg.add_source_reg(0);
    cfg.use_xref_acceleration = false;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(std::move(cfg)));

    auto& tr = pm->require("taint").get<TaintResult>();

    SECTION("only x0 is tainted") {
        REQUIRE(tr.is_tainted(0));
        REQUIRE_FALSE(tr.is_tainted(1));
        REQUIRE(tr.tainted_reg_count() == 1);
    }
}

TEST_CASE("TaintPass propagates through function calls", "[unit][pass][taint]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: x1 = 0xBEEF (setup, don't touch x0 — the taint source)
        tw.emit(ms, 0x1000, enc::movz(1, 0xBEEF), {{1, 0xBEEFULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: bl 0x2000 (call, x0 is argument)
        tw.emit(ms, 0x1004, enc::bl(0x2000 - 0x1004), {{30, tw.rt(0x1008)}, {33, tw.rt(0x2000)}}, {});
        // inst 2 (callee): x2 = x0 (taint crosses into callee)
        tw.emit(ms, 0x2000, enc::mov_reg(2, 0), {{2, 0ULL}, {33, tw.rt(0x2004)}}, {});
        // inst 3: ret
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "taint_call");

    auto pm = make_pm(*env);

    TaintConfig cfg;
    cfg.add_source_reg(0);
    cfg.use_xref_acceleration = false;
    cfg.propagate_through_calls = true;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(std::move(cfg)));

    auto& tr = pm->require("taint").get<TaintResult>();

    SECTION("taint propagates into callee") {
        REQUIRE(tr.is_tainted(0));
        REQUIRE(tr.is_tainted(2));  // x2 = x0 in callee
    }

    SECTION("call crossing counted") {
        REQUIRE(tr.call_crossings >= 1);
    }
}

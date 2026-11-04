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

TEST_CASE("TaintPass tracks interior bytes and kills clean partial overwrites",
          "[unit][pass][taint][regression]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        tw.emit(ms, 0x1000, enc::movz(10, 0x2000), {{10, 0x2000}}, {});
        tw.emit(ms, 0x1004, enc::str_imm(0, 10, 0), {}, {{2, 8, 0x2000, 1}});
        // Reuse the clean-store PC so learned-PC acceleration must also kill.
        tw.emit(ms, 0x1020, enc::movz(10, 0x3000), {{10, 0x3000}}, {});
        tw.emit(ms, 0x1008, 0xB9000541u /*str w1,[x10,#4]*/, {}, {{2, 4, 0x3004, 0}});
        tw.emit(ms, 0x1024, enc::movz(10, 0x2000), {{10, 0x2000}}, {});
        tw.emit(ms, 0x100C, 0xB9400542u /*ldr w2,[x10,#4]*/, {{2, 1}}, {{1, 4, 0x2004, 1}});
        tw.emit(ms, 0x1008, 0xB9000541u, {}, {{2, 4, 0x2004, 0}});
        tw.emit(ms, 0x1010, 0xB9400543u /*ldr w3,[x10,#4]*/, {{3, 0}}, {{1, 4, 0x2004, 0}});
        tw.emit(ms, 0x1014, 0xB9400144u /*ldr w4,[x10]*/, {{4, 1}}, {{1, 4, 0x2000, 1}});
        tw.emit_anchor(ms);
    }, "taint_partial_overwrite");
    REQUIRE(env);
    auto pm = make_pm(*env);
    TaintConfig cfg;
    cfg.add_source_reg(0);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<TaintPass>(cfg));
    const auto& raw = pm->require("taint");
    REQUIRE(raw.ok());
    const auto& result = raw.get<TaintResult>();
    REQUIRE(result.is_tainted(2));
    REQUIRE_FALSE(result.is_tainted(3));
    REQUIRE(result.is_tainted(4));
    REQUIRE(result.tainted_memory.contains(uint64_t(0x2003)));
    REQUIRE_FALSE(result.tainted_memory.contains(uint64_t(0x2004)));
}

TEST_CASE("Forward taint can follow CMP to CSEL through flags", "[unit][pass][taint][semantics]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        tw.emit(ms, 0x1000, 0xf100041fu, {{33, tw.rt(0x1004)}}, {}); // cmp x0, #1, no reg_diff for NZCV
        tw.emit(ms, 0x1004, 0x9a840062u, {{2, 7}, {33, tw.rt(0x1008)}}, {}); // csel x2, x3, x4, eq
    }, "taint_flag_chain");
    REQUIRE(env != nullptr);
    for (bool flags : {false, true}) {
        auto pm = make_pm(*env);
        TaintConfig cfg; cfg.add_source_reg(0); cfg.include_flags = flags;
        cfg.use_xref_acceleration = false;
        pm->register_pass(std::make_unique<TaintPass>(cfg));
        const auto& r = pm->require("taint").get<TaintResult>();
        REQUIRE(r.is_tainted(2) == flags);
        if (flags) {
            REQUIRE(r.is_tainted(IDX_NZCV));
            REQUIRE(r.quality.engine == "heuristic");
            REQUIRE(r.quality.instructions_examined == 2);
            REQUIRE_FALSE(r.quality.has_gaps());
        }
    }
}

TEST_CASE("Forward taint reports unsupported SIMD and early termination", "[unit][pass][taint][semantics]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        tw.emit(ms, 0x1000, 0x6e221c20u, {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
    }, "taint_quality");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    TaintConfig cfg; cfg.add_source_reg(0); cfg.include_flags = true;
    cfg.max_instructions = 1; cfg.use_xref_acceleration = false;
    pm->register_pass(std::make_unique<TaintPass>(cfg));
    const auto& r = pm->require("taint").get<TaintResult>();
    REQUIRE(r.quality.unsupported_register_instructions == 1);
    REQUIRE(r.quality.truncated);
    REQUIRE(r.quality.termination_reason == "max_instructions reached");
    REQUIRE(r.quality.has_gaps());
}

TEST_CASE("Forward taint keeps load values separate from base writeback", "[unit][pass][taint][semantics]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        tw.emit(ms, 0x1000, 0xf8408420u, {{0, 7}, {1, 0x9008}, {33, tw.rt(0x1004)}},
                {{1, 8, 0x9000, 7}}); // ldr x0, [x1], #8
    }, "taint_writeback_sources");
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    TaintConfig cfg; cfg.source_mem_addrs = {0x9000}; cfg.include_flags = true;
    cfg.use_xref_acceleration = false;
    pm->register_pass(std::make_unique<TaintPass>(cfg));
    const auto& r = pm->require("taint").get<TaintResult>();
    REQUIRE(r.is_tainted(0));
    REQUIRE_FALSE(r.is_tainted(1));
}

TEST_CASE("Forward taint distinguishes missing bytes from undecodable bytes", "[unit][pass][taint][semantics]") {
    for (bool missing : {false, true}) {
        auto env = make_env([](TraceWriter& tw) {
            tw.write_header(); MachineState ms;
            tw.emit(ms, 0x1000, 0xffffffffu, {{1, 7}, {33, tw.rt(0x1004)}}, {});
        }, "taint_decode_gaps");
        REQUIRE(env != nullptr);
        if (missing) env->code_table = CodeTable{};
        auto pm = make_pm(*env);
        TaintConfig cfg; cfg.add_source_reg(0); cfg.include_flags = true;
        cfg.use_xref_acceleration = false;
        pm->register_pass(std::make_unique<TaintPass>(cfg));
        const auto& raw = pm->require("taint");
        REQUIRE(raw.ok());
        const auto& r = raw.get<TaintResult>();
        REQUIRE(r.quality.missing_code == (missing ? 1 : 0));
        REQUIRE(r.quality.undecoded_instructions == (missing ? 0 : 1));
        REQUIRE(r.quality.has_gaps());
    }
}

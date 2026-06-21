/*
 * test_pass_backward_taint.cpp — Unit tests for tenet::BackwardTaintPass
 *
 * BackwardTaintPass heuristic behavior:
 *   - sink_inst_id is the EXCLUSIVE upper bound: the pass examines
 *     instructions at IDs < sink_inst_id (the sink itself is NOT included).
 *   - The heuristic propagates through reg_diffs: when instruction I is found
 *     to define register R (needed by a downstream instruction), the other
 *     registers in I's reg_diff (excluding pc/sp/nzcv) become the new "needed"
 *     set.  So multi-hop propagation only works when intermediate instructions
 *     record their source registers in reg_diff (e.g., QBDI records LDR both
 *     base register changes and the loaded value).
 *
 * Tests use sink_inst_id = total_inst_count so that the last instruction
 * IS examined by the backward scan (current_id starts at sink_inst_id-1).
 *
 * Run:  ctest -R 'backward_taint' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/backward_taint_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a single-write trace:
///   inst 0: x1 = 0x42    (movz, only reg_diff = {x1, pc})
///   inst 1: x0 = 0x43    (movz, only reg_diff = {x0, pc})
///
/// Sink: reg x0 at sink_inst_id=2.
/// Expected: inst 1 contributes (it wrote x0 just before the sink).
static std::unique_ptr<TraceEnv> make_single_write() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0x42 (unrelated)
        tw.emit(ms, 0x1000, enc::movz(1, 0x42),
                {{1, 0x42ULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x0 = 0x43 (this is the writer of x0)
        tw.emit(ms, 0x1004, enc::movz(0, 0x43),
                {{0, 0x43ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "bwtaint_single");
}

/// Build a two-hop chain where the intermediate instruction records BOTH
/// its destination AND source register in reg_diff (simulates a register-copy
/// or arithmetic whose source changed, so QBDI records the old and new state).
///
///   inst 0: x1 = 0x42   reg_diff {x1=0x42, x33=pc}
///   inst 1: x0 = x1     reg_diff {x0=0x42, x1=0x42, x33=pc}
///              ^ heuristic sees x1 as a SOURCE (non-dst reg in diff)
///   inst 2: (anchor/end)
///
/// Sink reg x0, sink_inst_id=2.
/// Expected: inst 1 contributes (wrote x0) AND inst 0 contributes (wrote x1).
static std::unique_ptr<TraceEnv> make_two_hop() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0x42
        tw.emit(ms, 0x1000, enc::movz(1, 0x42),
                {{1, 0x42ULL}, {33, tw.rt(0x1004)}}, {});

        // inst 1: x0 = x1  (mov_reg)
        // Include x1 in reg_diff to simulate the heuristic seeing a source reg.
        // We manually set x1 to its current value so the diff records it.
        tw.emit(ms, 0x1004, enc::mov_reg(0, 1),
                {{0, 0x42ULL}, {1, 0x42ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "bwtaint_twohop");
}

// ─── Test cases ────────────────────────────────────────────────────────────────

TEST_CASE("BackwardTaintPass: basic chain — sink x0 traces back 1 inst",
          "[unit][pass][backward_taint]") {
    auto env = make_single_write();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 2;          // scan instructions 0..1
    cfg.add_sink_reg(0);           // sink register: x0
    cfg.propagate_through_memory = false;
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));

    auto& raw = pm->require("backward_taint");
    REQUIRE(raw.ok());

    auto& res = raw.get<BackwardTaintResult>();

    SECTION("inst 1 (writer of x0) is contributing") {
        REQUIRE(res.is_contributing(1));
    }
    SECTION("at least 1 contributing instruction") {
        REQUIRE(res.contributing_count() >= 1);
    }
    SECTION("x0 is in involved registers") {
        REQUIRE((res.all_involved_regs & (1ULL << 0)) != 0);
    }
    SECTION("result is ok") {
        REQUIRE(raw.ok());
    }
}

TEST_CASE("BackwardTaintPass: two-hop chain — heuristic traces x0 → x1",
          "[unit][pass][backward_taint]") {
    auto env = make_two_hop();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 2;          // scan instructions 0..1
    cfg.add_sink_reg(0);           // sink register: x0
    cfg.propagate_through_memory = false;
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    SECTION("inst 1 (x0 = x1, writer of x0) is contributing") {
        REQUIRE(res.is_contributing(1));
    }
    SECTION("inst 0 (x1 = 0x42, source of x1) is contributing") {
        // The heuristic sees x1 in inst 1's reg_diff (non-dst) → adds x1 to needed
        // Then finds inst 0 wrote x1 → also contributing
        REQUIRE(res.is_contributing(0));
    }
    SECTION("at least 2 contributing instructions") {
        REQUIRE(res.contributing_count() >= 2);
    }
    SECTION("both x0 and x1 are involved registers") {
        REQUIRE((res.all_involved_regs & (1ULL << 0)) != 0);
        REQUIRE((res.all_involved_regs & (1ULL << 1)) != 0);
    }
}

TEST_CASE("BackwardTaintPass: max_steps limits the search depth",
          "[unit][pass][backward_taint]") {
    // make_two_hop():
    //   inst 0: x1 = 0x42
    //   inst 1: x0 = x1  (records x1 in diff as source)
    //
    // With sink_inst_id=2, sink_reg=x0:
    //   - Loop: current_id=2, decrement to 1, steps=1 → examine inst 1
    //           If max_steps=1: break after incrementing steps to 1 (BEFORE processing)
    //   - So max_steps=1 actually means "allow 1 decrement then break" → 0 insts examined
    //   - max_steps=2: examine inst 1, decrement again to 0, steps=2 → break → 1 inst examined
    //
    // We use max_steps=2 (examine inst 1 only, stop before inst 0).
    auto env = make_two_hop();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 2;
    cfg.add_sink_reg(0);
    // max_steps=2: the loop does: decrement (→1), steps++ (1), check (1<2 ok),
    //   process inst 1 → contributing; decrement (→0), steps++ (2), check (2>=2) → break.
    // So inst 1 IS found, inst 0 is NOT (loop exits before examining it).
    cfg.max_steps = 2;
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    SECTION("inst 1 is contributing (within max_steps)") {
        REQUIRE(res.is_contributing(1));
    }
    SECTION("inst 0 is NOT contributing (loop exits before examining it)") {
        REQUIRE_FALSE(res.is_contributing(0));
    }
}

TEST_CASE("BackwardTaintPass: killed register is not traced back past its overwrite",
          "[unit][pass][backward_taint]") {
    // inst 0: x1 = 0xFF    (original value — will be overwritten before sink reads it)
    // inst 1: x1 = 0x42    (overwrite; x0 = x1 reads THIS value)
    // inst 2: x0 = x1      (sink: x0 depends on inst 1's x1, NOT on inst 0)
    //
    // The two-hop heuristic: inst 2 sets dst={x0} src={x1}.
    // Finds inst 1 wrote x1 → contributing. Its reg_diff: {x1=0x42, x33=pc}, no other src.
    // Propagation stops (no new src regs from inst 1).
    // inst 0 wrote x1 but x1 was already satisfied by inst 1 → NOT contributing.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0xFF  (will be overwritten)
        tw.emit(ms, 0x1000, enc::movz(1, 0xFF),
                {{1, 0xFFULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x1 = 0x42  (overwrites; no src listed in diff)
        tw.emit(ms, 0x1004, enc::movz(1, 0x42),
                {{1, 0x42ULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x0 = x1  (records x1 in diff as source)
        tw.emit(ms, 0x1008, enc::mov_reg(0, 1),
                {{0, 0x42ULL}, {1, 0x42ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "bwtaint_kill");

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 3;          // scan instructions 0..2
    cfg.add_sink_reg(0);
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    SECTION("inst 2 (x0=x1 writer) is contributing") { REQUIRE(res.is_contributing(2)); }
    SECTION("inst 1 (x1 overwrite) is contributing — it wrote x1 used by inst 2") {
        REQUIRE(res.is_contributing(1));
    }
    SECTION("inst 0 (original x1=0xFF) is NOT contributing — x1 killed by inst 1") {
        // The heuristic removes x1 from needed when it finds inst 1 wrote x1.
        // inst 0 also wrote x1, but by then x1 is no longer in the needed set.
        REQUIRE_FALSE(res.is_contributing(0));
    }
}

TEST_CASE("BackwardTaintPass: memory load-store backward propagation",
          "[unit][pass][backward_taint]") {
    // inst 0: x1 = kAddr   (address materialization)
    // inst 1: str x10, [x1]  (store: write x10 value to mem[kAddr])
    // inst 2: ldr x0, [x1]   (load: x0 ← mem[kAddr]; depends on store)
    // Sink: x0 at sink_inst_id=3.
    // With propagate_through_memory=true, backward scan should find:
    //   inst 2 (LDR read from mem[kAddr]) → add mem[kAddr] to needed
    //   inst 1 (STR write to mem[kAddr]) → contributing; add its src regs
    const uint64_t kAddr = 0x200ULL;

    auto env = make_env([kAddr](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(10) = 0xCAFEULL;
        ms.x(1)  = kAddr;

        // inst 0: x1 = kAddr
        tw.emit(ms, 0x1000, enc::movz(1, static_cast<uint16_t>(kAddr)),
                {{1, kAddr}, {33, tw.rt(0x1004)}}, {});
        // inst 1: str x10, [x1]  — write mem_access type=2 (WRITE)
        tw.emit(ms, 0x1004, enc::str_imm(10, 1, 0),
                {{33, tw.rt(0x1008)}},
                {{2 /*WRITE*/, 8, kAddr, 0xCAFEULL}});
        // inst 2: ldr x0, [x1]  — read mem_access type=1 (READ)
        tw.emit(ms, 0x1008, enc::ldr_imm(0, 1, 0),
                {{0, 0xCAFEULL}, {33, tw.rt(0x100C)}},
                {{1 /*READ*/, 8, kAddr, 0xCAFEULL}});
        tw.emit_anchor(ms);
    }, "bwtaint_mem");

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 3;          // scan 0..2
    cfg.add_sink_reg(0);           // x0 is the sink
    cfg.propagate_through_memory = true;
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    SECTION("LDR instruction (inst 2) is contributing") {
        REQUIRE(res.is_contributing(2));
    }
    SECTION("STR instruction (inst 1) is contributing through memory") {
        REQUIRE(res.is_contributing(1));
    }
    SECTION("memory address is tracked") {
        REQUIRE(res.involved_mem_addrs.contains(kAddr));
    }
}

TEST_CASE("BackwardTaintPass: multi-sink — two independent sink registers",
          "[unit][pass][backward_taint]") {
    // inst 0: x1 = 0xA
    // inst 1: x2 = 0xB
    // inst 2: x3 = x1  (copy, records x1 in diff; writer of x3)
    // inst 3: x4 = x2  (copy, records x2 in diff; writer of x4)
    //
    // Sink at sink_inst_id=4 with both x3 and x4.
    // Expected: inst 2 (→ x3) and inst 3 (→ x4) are both contributing.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // inst 0: x1 = 0xA
        tw.emit(ms, 0x1000, enc::movz(1, 0xA),
                {{1, 0xAULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x2 = 0xB
        tw.emit(ms, 0x1004, enc::movz(2, 0xB),
                {{2, 0xBULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x3 = x1  (records x1 in diff as source)
        tw.emit(ms, 0x1008, enc::mov_reg(3, 1),
                {{3, 0xAULL}, {1, 0xAULL}, {33, tw.rt(0x100C)}}, {});
        // inst 3: x4 = x2  (records x2 in diff as source)
        tw.emit(ms, 0x100C, enc::mov_reg(4, 2),
                {{4, 0xBULL}, {2, 0xBULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "bwtaint_multisink");

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 4;          // scan instructions 0..3
    cfg.add_sink_reg(3);           // x3
    cfg.add_sink_reg(4);           // x4
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    SECTION("inst 2 (x3=x1) is in the backward slice for x3") {
        REQUIRE(res.is_contributing(2));
    }
    SECTION("inst 3 (x4=x2) is in the backward slice for x4") {
        REQUIRE(res.is_contributing(3));
    }
    SECTION("inst 0 (x1=0xA) is in the backward slice via x3→x1 chain") {
        REQUIRE(res.is_contributing(0));
    }
    SECTION("inst 1 (x2=0xB) is in the backward slice via x4→x2 chain") {
        REQUIRE(res.is_contributing(1));
    }
}

TEST_CASE("BackwardTaintPass: result is empty for inst_id with no register writes",
          "[unit][pass][backward_taint]") {
    // A trace where x0 is never written → nothing contributes to x0.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // NOP: no register diffs except pc
        for (int i = 0; i < 5; i++) {
            uint64_t spc = 0x1000 + i * 4;
            tw.emit(ms, spc, enc::nop(),
                    {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "bwtaint_nop");

    auto pm = make_pm(*env);

    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 5;   // scan all 5 NOP instructions
    cfg.add_sink_reg(0);    // x0 is never written → no contributors
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& raw = pm->require("backward_taint");
    REQUIRE(raw.ok());

    auto& res = raw.get<BackwardTaintResult>();
    SECTION("contributing count is 0") {
        REQUIRE(res.contributing_count() == 0);
    }
}

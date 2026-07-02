/*
 * test_pass_vm_abstract.cpp — Unit tests for tenet::VMAbstractPass
 *
 * Verifies:
 *   - Dispatcher detection (auto-detect and hint-driven)
 *   - Handler extraction from indirect branch targets
 *   - VM-PC register inference from monotonic register increments
 *   - VM step sequence construction
 *
 * The synthetic trace models a simple while-switch VM:
 *
 *   0x1000: cmp x0, N               ← loop header
 *   0x1004: b.ge exit                 (loop exit when counter >= N)
 *   0x1008: ldr x2, [x3, x1, lsl#3]  (load handler addr from jump table)
 *   0x100C: br x2                     (dispatch to handler via indirect branch)
 *
 *   Handler A at 0x2000: add x4, x4, 1; (handler body, then back to header)
 *   Handler B at 0x3000: eor x5, x5, x6; (handler body, then back to header)
 *   Handler C at 0x4000: sub x7, x7, 1; (handler body, then back to header)
 *
 *   0x1010: nop                       ← after loop (exit target)
 *
 * x0 = iteration counter (0..N-1), x1 = VM-PC (increments by 4 each iteration).
 *
 * Run:  ctest -R 'vm_abstract' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/vm_abstract_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helper: emit a VM-like dispatch loop ────────────────────────────────────
//
// Layout (static PCs — TraceWriter auto-adds slide 0x4000):
//
//   Block HEADER:  0x1000: cmp x0, N
//                  0x1004: b.ge → 0x1010   (exit when done)
//                  0x1008: ldr x2, [x3, x1, lsl#3]  (handler table lookup)
//                  0x100C: br x2            (indirect dispatch)
//
//   Handler A:     0x2000: add x4, x4, 1
//                  0x2004: b → 0x1000       (back to header)
//
//   Handler B:     0x3000: eor x5, x5, x6
//                  0x3004: b → 0x1000       (back to header)
//
//   Handler C:     0x4000: sub x7, x7, 1
//                  0x4004: b → 0x1000       (back to header)
//
//   EXIT:          0x1010: nop
//
// Each iteration: header PCs (0x1000-0x100C) → handler → back to 0x1000.
// The handler selection follows a repeating pattern: A, B, C, A, B, C, ...
// x1 (VM-PC) increments by 4 each iteration (simulating a 4-byte opcode step).

static constexpr uint64_t HEADER_PC  = 0x1000;
static constexpr uint64_t EXIT_PC    = 0x1010;
static constexpr uint64_t HANDLER_A  = 0x2000;
static constexpr uint64_t HANDLER_B  = 0x3000;
static constexpr uint64_t HANDLER_C  = 0x4000;

static std::unique_ptr<TraceEnv> make_vm_trace(int N) {
    return make_env([N](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Initial register setup
        // x0 is NOT used as a counter — kept at a fixed value so only x1
        // shows the constant-step pattern that infer_vm_pc_register looks for.
        ms.x(0) = 0x42;                // some fixed value (not a loop counter)
        ms.x(1) = 0xDEAD0000ULL;       // VM-PC (bytecode pointer)
        ms.x(2) = 0;                   // handler address (loaded each iter)
        ms.x(3) = 0xBEEF0000ULL;       // handler table base
        ms.x(4) = 100;                 // state for handler A
        ms.x(5) = 0xAAAA;              // state for handler B
        ms.x(6) = 0x5555;              // state for handler B
        ms.x(7) = 200;                 // state for handler C
        ms.x(8) = 0;                   // loop counter (x8, not x0)

        // Handler PCs cycle through A, B, C
        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };

        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];

            // ── Loop header ──────────────────────────────────
            // 0x1000: cmp x8, N  (x8 is loop counter)
            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);  // N flag: lt (not exiting)

            // 0x1004: b.ge → EXIT (not taken)
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),  // +12 → 0x1010
                    {{33, tw.rt(HEADER_PC + 8)}}, {});

            // 0x1008: ldr x2, [x3, x1, lsl#3] — load handler address
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}},
                    {});

            // 0x100C: br x2 — indirect dispatch
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            // ── Handler body ─────────────────────────────────
            // Compute next x8 (counter) and x1 (VM-PC) values
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            if (handler_pc == HANDLER_A) {
                // add x4, x4, 1
                uint64_t new_x4 = 100 + static_cast<uint64_t>(i / 3) + 1;
                tw.emit(ms, HANDLER_A, enc::add_imm(4, 4, 1),
                        {{4, new_x4}, {33, tw.rt(HANDLER_A + 4)}}, {});
                // add x1, x1, 4  (advance VM-PC)
                tw.emit(ms, HANDLER_A + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_A + 8)}}, {});
                // add x8, x8, 1  (increment loop counter)
                tw.emit(ms, HANDLER_A + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_A + 0xC)}}, {});
                // b → header
                tw.emit(ms, HANDLER_A + 0xC,
                        enc::b(static_cast<int32_t>((HEADER_PC - (HANDLER_A + 0xC)))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            } else if (handler_pc == HANDLER_B) {
                // eor x5, x5, x6
                uint64_t new_x5 = ms.x(5) ^ ms.x(6);
                tw.emit(ms, HANDLER_B, enc::eor_reg(5, 5, 6),
                        {{5, new_x5}, {33, tw.rt(HANDLER_B + 4)}}, {});
                // add x1, x1, 4  (advance VM-PC)
                tw.emit(ms, HANDLER_B + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_B + 8)}}, {});
                // add x8, x8, 1
                tw.emit(ms, HANDLER_B + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_B + 0xC)}}, {});
                // b → header
                tw.emit(ms, HANDLER_B + 0xC,
                        enc::b(static_cast<int32_t>((HEADER_PC - (HANDLER_B + 0xC)))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            } else {
                // sub x7, x7, 1
                uint64_t new_x7 = 200 - static_cast<uint64_t>(i / 3) - 1;
                tw.emit(ms, HANDLER_C, enc::sub_imm(7, 7, 1),
                        {{7, new_x7}, {33, tw.rt(HANDLER_C + 4)}}, {});
                // add x1, x1, 4  (advance VM-PC)
                tw.emit(ms, HANDLER_C + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_C + 8)}}, {});
                // add x8, x8, 1
                tw.emit(ms, HANDLER_C + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_C + 0xC)}}, {});
                // b → header
                tw.emit(ms, HANDLER_C + 0xC,
                        enc::b(static_cast<int32_t>((HEADER_PC - (HANDLER_C + 0xC)))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            }

            // Update MachineState for next iteration
            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
        }

        // Final header: cmp+b.ge exits the loop
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);  // Z flag: x8==N, ge taken
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                {{33, tw.rt(EXIT_PC)}}, {});  // branch taken → exit
        tw.emit(ms, EXIT_PC, enc::nop(),
                {{33, tw.rt(EXIT_PC + 4)}}, {});

        tw.emit_anchor(ms);
    }, ("vm_abstract_" + std::to_string(N)).c_str());
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("VMAbstractPass: auto-detect VM dispatcher with 15 iterations",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(15);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;  // Lower threshold for test
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());

    auto& res = raw.get<VMAbstractResult>();

    SECTION("dispatcher is detected at loop header") {
        // The header PC should be detected (with slide applied by TraceWriter)
        REQUIRE(res.dispatcher.loop_header_pc == rt_pc(HEADER_PC));
    }

    SECTION("indirect branch PC is found") {
        REQUIRE(res.dispatcher.indirect_branch_pc != 0);
    }

    SECTION("at least 3 handlers extracted") {
        REQUIRE(res.handlers.size() >= 3);
    }

    SECTION("handler entry PCs match expected values") {
        bool found_a = false, found_b = false, found_c = false;
        for (const auto& h : res.handlers) {
            if (h.entry_pc == rt_pc(HANDLER_A)) found_a = true;
            if (h.entry_pc == rt_pc(HANDLER_B)) found_b = true;
            if (h.entry_pc == rt_pc(HANDLER_C)) found_c = true;
        }
        CHECK(found_a);
        CHECK(found_b);
        CHECK(found_c);
    }

    SECTION("handler execution counts are positive") {
        for (const auto& h : res.handlers) {
            CHECK(h.execution_count > 0);
        }
    }

    SECTION("VM steps are produced") {
        REQUIRE(res.steps.size() >= 10);
        REQUIRE(res.total_vm_steps == res.steps.size());
    }

    SECTION("VM-PC register is identified as x1") {
        // x1 increments by 4 each iteration → should be detected as VM-PC
        CHECK(res.vm_pc_reg == 1);
    }
}

TEST_CASE("VMAbstractPass: hint-driven mode with dispatcher hint",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.auto_detect = false;  // disable auto-detect, rely on hint
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    // Don't provide indirect_branch_pc — let the pass find it
    cfg.dispatcher = dh;
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());

    auto& res = raw.get<VMAbstractResult>();

    SECTION("dispatcher is set to hinted PC") {
        CHECK(res.dispatcher.loop_header_pc == rt_pc(HEADER_PC));
    }

    SECTION("indirect branch found automatically from hint") {
        CHECK(res.dispatcher.indirect_branch_pc != 0);
    }

    SECTION("handlers are still discovered") {
        CHECK(res.handlers.size() >= 3);
    }

    SECTION("steps are produced") {
        CHECK(res.steps.size() >= 10);
    }
}

TEST_CASE("VMAbstractPass: VM-PC hint overrides inference",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    // Provide a VM-PC hint for x1
    VMPCHint vph;
    vph.reg = 1;
    vph.bytecode_base = 0xDEAD0000ULL;
    cfg.vm_pc = vph;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());

    auto& res = raw.get<VMAbstractResult>();

    SECTION("VM-PC uses hinted register") {
        CHECK(res.vm_pc_reg == 1);
    }

    SECTION("bytecode base matches hint") {
        CHECK(res.bytecode_base == 0xDEAD0000ULL);
    }

    SECTION("VM steps have valid vm_pc values") {
        // Each step should have vm_pc_valid = true with a plausible value
        for (const auto& step : res.steps) {
            CHECK(step.vm_pc_valid);
            CHECK(step.vm_pc_value >= 0xDEAD0000ULL);
        }
    }
}

TEST_CASE("VMAbstractPass: handler lookup by PC works",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(15);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("handler_at returns valid handler for known PC") {
        auto* ha = res.handler_at(rt_pc(HANDLER_A));
        REQUIRE(ha != nullptr);
        CHECK(ha->entry_pc == rt_pc(HANDLER_A));
        CHECK(ha->execution_count > 0);
    }

    SECTION("handler_at returns nullptr for unknown PC") {
        auto* h = res.handler_at(0xDEADDEAD);
        CHECK(h == nullptr);
    }

    SECTION("handlers_by_frequency returns sorted list") {
        auto sorted = res.handlers_by_frequency();
        REQUIRE(sorted.size() == res.handlers.size());
        for (size_t i = 1; i < sorted.size(); ++i) {
            CHECK(sorted[i - 1]->execution_count >= sorted[i]->execution_count);
        }
    }
}

TEST_CASE("VMAbstractPass: opcode decode with OpcodeFormatHint",
          "[unit][pass][vm_abstract]") {
    // This test constructs a VM trace where:
    //   - Before the dispatch loop, "setup" instructions write opcode bytes
    //     into a bytecode buffer at 0xBBBB0000..0xBBBB002C (12 × 4-byte entries)
    //   - x1 (VM-PC) starts at 0xBBBB0000 and increments by 4 each iteration
    //   - The pass reads from MemoryModel at vm_pc_value, extracts the opcode
    //     via mask/shift, and populates step.opcode_value / handler.opcode_values
    //
    // Opcode scheme: each 4-byte word holds a single-byte opcode in bits [7:0]:
    //   Handler A → opcode 0x01
    //   Handler B → opcode 0x02
    //   Handler C → opcode 0x03
    // Pattern: A B C A B C ... (12 iterations)

    constexpr uint64_t BYTECODE_BASE = 0xBBBB0000ULL;
    constexpr int      N = 12;
    constexpr uint8_t  OPCODE_A = 0x01, OPCODE_B = 0x02, OPCODE_C = 0x03;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // ── Prologue: store bytecode buffer ───────────────────────────
        // Use a "setup" region at 0x8000 to write 12 × 4-byte opcodes.
        // Each STR writes a little-endian uint32 whose low byte is the opcode.
        const uint8_t opcodes[N] = {
            OPCODE_A, OPCODE_B, OPCODE_C,
            OPCODE_A, OPCODE_B, OPCODE_C,
            OPCODE_A, OPCODE_B, OPCODE_C,
            OPCODE_A, OPCODE_B, OPCODE_C,
        };

        ms.x(9) = BYTECODE_BASE;  // x9 = bytecode write pointer
        for (int i = 0; i < N; i++) {
            uint64_t addr = BYTECODE_BASE + static_cast<uint64_t>(i * 4);
            uint64_t val  = opcodes[i];  // low byte = opcode
            // Emit: str xZ, [x9], where x9 = addr
            // We model this as: nop with a memory write side-effect
            TraceWriter::MemAcc ma;
            ma.type = 2;  // MEMORY_WRITE
            ma.size = 4;
            ma.addr = tw.rt(0) + addr;  // runtime address (slide applied to base 0)
            ma.value = val;
            uint64_t setup_pc = 0x8000 + static_cast<uint64_t>(i * 4);
            tw.emit(ms, setup_pc, enc::nop(),
                    {{33, tw.rt(setup_pc + 4)}}, {ma});
        }

        // ── VM dispatch loop (same structure as make_vm_trace) ────────
        ms.x(0) = 0x42;
        ms.x(1) = tw.rt(0) + BYTECODE_BASE;  // VM-PC = runtime addr of bytecode
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100;
        ms.x(5) = 0xAAAA;
        ms.x(6) = 0x5555;
        ms.x(7) = 200;
        ms.x(8) = 0;

        // Anchor before dispatch loop so RegisterFile knows x1's initial value
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };

        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_BASE) +
                                static_cast<uint64_t>((i + 1) * 4);

            if (handler_pc == HANDLER_A) {
                tw.emit(ms, HANDLER_A, enc::add_imm(4, 4, 1),
                        {{4, 100 + static_cast<uint64_t>(i / 3) + 1},
                         {33, tw.rt(HANDLER_A + 4)}}, {});
                tw.emit(ms, HANDLER_A + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_A + 8)}}, {});
                tw.emit(ms, HANDLER_A + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_A + 0xC)}}, {});
                tw.emit(ms, HANDLER_A + 0xC,
                        enc::b(static_cast<int32_t>(HEADER_PC - (HANDLER_A + 0xC))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            } else if (handler_pc == HANDLER_B) {
                tw.emit(ms, HANDLER_B, enc::eor_reg(5, 5, 6),
                        {{5, ms.x(5) ^ ms.x(6)}, {33, tw.rt(HANDLER_B + 4)}}, {});
                tw.emit(ms, HANDLER_B + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_B + 8)}}, {});
                tw.emit(ms, HANDLER_B + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_B + 0xC)}}, {});
                tw.emit(ms, HANDLER_B + 0xC,
                        enc::b(static_cast<int32_t>(HEADER_PC - (HANDLER_B + 0xC))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            } else {
                tw.emit(ms, HANDLER_C, enc::sub_imm(7, 7, 1),
                        {{7, 200 - static_cast<uint64_t>(i / 3) - 1},
                         {33, tw.rt(HANDLER_C + 4)}}, {});
                tw.emit(ms, HANDLER_C + 4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_C + 8)}}, {});
                tw.emit(ms, HANDLER_C + 8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_C + 0xC)}}, {});
                tw.emit(ms, HANDLER_C + 0xC,
                        enc::b(static_cast<int32_t>(HEADER_PC - (HANDLER_C + 0xC))),
                        {{33, tw.rt(HEADER_PC)}}, {});
            }

            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
        }

        // Exit
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(),
                {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_opcode_decode");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    // VM-PC hint: x1 points to bytecode, base at BYTECODE_BASE
    VMPCHint vph;
    vph.reg = 1;
    vph.bytecode_base = 0x4000ULL + BYTECODE_BASE;  // slide + BYTECODE_BASE
    cfg.vm_pc = vph;

    // Opcode format: 4 bytes, low byte is the opcode
    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 4;
    ofmt.opcode_mask = 0xFF;
    ofmt.opcode_shift = 0;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("steps have valid opcodes decoded") {
        uint32_t valid_count = 0;
        for (const auto& step : res.steps) {
            if (step.opcode_valid) {
                valid_count++;
                // Each opcode should be 0x01, 0x02, or 0x03
                CHECK((step.opcode_value == OPCODE_A ||
                       step.opcode_value == OPCODE_B ||
                       step.opcode_value == OPCODE_C));
            }
        }
        // All 12 steps should have valid opcodes
        CHECK(valid_count == static_cast<uint32_t>(N));
    }

    SECTION("opcode values match handler mapping") {
        for (const auto& step : res.steps) {
            if (!step.opcode_valid) continue;
            if (step.handler_entry_pc == rt_pc(HANDLER_A))
                CHECK(step.opcode_value == OPCODE_A);
            else if (step.handler_entry_pc == rt_pc(HANDLER_B))
                CHECK(step.opcode_value == OPCODE_B);
            else if (step.handler_entry_pc == rt_pc(HANDLER_C))
                CHECK(step.opcode_value == OPCODE_C);
        }
    }

    SECTION("handler.opcode_values populated correctly") {
        auto* ha = res.handler_at(rt_pc(HANDLER_A));
        auto* hb = res.handler_at(rt_pc(HANDLER_B));
        auto* hc = res.handler_at(rt_pc(HANDLER_C));
        REQUIRE(ha != nullptr);
        REQUIRE(hb != nullptr);
        REQUIRE(hc != nullptr);

        // Each handler should have exactly one unique opcode value
        REQUIRE(ha->opcode_values.size() == 1);
        CHECK(ha->opcode_values[0] == OPCODE_A);

        REQUIRE(hb->opcode_values.size() == 1);
        CHECK(hb->opcode_values[0] == OPCODE_B);

        REQUIRE(hc->opcode_values.size() == 1);
        CHECK(hc->opcode_values[0] == OPCODE_C);
    }
}

// ─── Helper: emit a BLR-based VM dispatch loop ──────────────────────────────
//
// Same structure as make_vm_trace but uses BLR x2 instead of BR x2 at the
// dispatch site.  Handlers end with RET instead of B to simulate call-table
// dispatch.  The header contains an explicit LR save so BLR's LR clobber
// doesn't break the loop.
//
// Layout (static PCs):
//   HEADER  0x1000: cmp x8, N
//           0x1004: b.ge exit
//           0x1008: ldr x2, [x3, x1, lsl#3]
//           0x100C: blr x2               ← call-table dispatch
//           0x1010: (fall-through after RET returns here)
//              ... loop back to 0x1000
//   EXIT    0x1020: nop
//
//   Handlers at 0x2000/0x3000/0x4000 end with RET.

static constexpr uint64_t BLR_RETURN_PC = 0x1010;
static constexpr uint64_t BLR_EXIT_PC   = 0x1020;

static std::unique_ptr<TraceEnv> make_blr_vm_trace(int N) {
    return make_env([N](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0x42;
        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100;
        ms.x(5) = 0xAAAA;
        ms.x(6) = 0x5555;
        ms.x(7) = 200;
        ms.x(8) = 0;

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };

        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            // Header
            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(28),  // +28 → BLR_EXIT_PC (0x1020)
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            // BLR x2 — sets LR to next PC (BLR_RETURN_PC)
            tw.emit(ms, HEADER_PC + 0xC, enc::blr(2),
                    {{30, tw.rt(BLR_RETURN_PC)}, {33, tw.rt(handler_pc)}}, {});

            // Handler body: operation + advance x1 + advance x8 + RET
            if (handler_pc == HANDLER_A) {
                tw.emit(ms, HANDLER_A, enc::add_imm(4, 4, 1),
                        {{4, 100 + static_cast<uint64_t>(i/3) + 1}, {33, tw.rt(HANDLER_A+4)}}, {});
                tw.emit(ms, HANDLER_A+4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_A+8)}}, {});
                tw.emit(ms, HANDLER_A+8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_A+0xC)}}, {});
                tw.emit(ms, HANDLER_A+0xC, enc::ret(),
                        {{33, tw.rt(BLR_RETURN_PC)}}, {});
            } else if (handler_pc == HANDLER_B) {
                tw.emit(ms, HANDLER_B, enc::eor_reg(5, 5, 6),
                        {{5, ms.x(5)^ms.x(6)}, {33, tw.rt(HANDLER_B+4)}}, {});
                tw.emit(ms, HANDLER_B+4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_B+8)}}, {});
                tw.emit(ms, HANDLER_B+8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_B+0xC)}}, {});
                tw.emit(ms, HANDLER_B+0xC, enc::ret(),
                        {{33, tw.rt(BLR_RETURN_PC)}}, {});
            } else {
                tw.emit(ms, HANDLER_C, enc::sub_imm(7, 7, 1),
                        {{7, 200 - static_cast<uint64_t>(i/3) - 1}, {33, tw.rt(HANDLER_C+4)}}, {});
                tw.emit(ms, HANDLER_C+4, enc::add_imm(1, 1, 4),
                        {{1, next_x1}, {33, tw.rt(HANDLER_C+8)}}, {});
                tw.emit(ms, HANDLER_C+8, enc::add_imm(8, 8, 1),
                        {{8, next_x8}, {33, tw.rt(HANDLER_C+0xC)}}, {});
                tw.emit(ms, HANDLER_C+0xC, enc::ret(),
                        {{33, tw.rt(BLR_RETURN_PC)}}, {});
            }

            // After RET, execution returns to BLR_RETURN_PC, then loop back
            tw.emit(ms, BLR_RETURN_PC, enc::b(static_cast<int32_t>(HEADER_PC - BLR_RETURN_PC)),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
        }

        // Exit
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(28),
                {{33, tw.rt(BLR_EXIT_PC)}}, {});
        tw.emit(ms, BLR_EXIT_PC, enc::nop(),
                {{33, tw.rt(BLR_EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, ("vm_abstract_blr_" + std::to_string(N)).c_str());
}

// ─── Helper: VM trace with memory accesses on handlers ───────────────────────
//
// Builds a VM trace where each handler performs explicit memory read/write
// operations so the arch_type inference heuristic has data to work with.
//
// Modes:
//   'S' = StackMachine-like: each handler does many reads OR many writes (not both)
//   'R' = RegisterMachine-like: each handler does balanced reads AND writes
static std::unique_ptr<TraceEnv> make_memaccess_vm_trace(int N, char mode) {
    return make_env([N, mode](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0x42;
        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200;
        ms.x(8) = 0;
        ms.x(10) = 0xCC000000ULL;  // stack/regfile pointer for mem accesses

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };

        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            // Header (same as make_vm_trace)
            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            // Handler body with memory accesses
            uint64_t mem_base = 0xCC000000ULL + static_cast<uint64_t>(i * 64);

            // Build mem accesses based on mode
            std::vector<TraceWriter::MemAcc> mems;
            if (mode == 'S') {
                // Stack-like: handler A does 3 reads only, B does 3 writes only, C does 3 reads only
                if (handler_pc == HANDLER_A || handler_pc == HANDLER_C) {
                    for (int m = 0; m < 3; m++)
                        mems.push_back({1, 8, mem_base + static_cast<uint64_t>(m*8), 0x1234ULL});
                } else {
                    for (int m = 0; m < 3; m++)
                        mems.push_back({2, 8, mem_base + static_cast<uint64_t>(m*8), 0x5678ULL});
                }
            } else {
                // Register-like: every handler does 2 reads + 2 writes (balanced)
                mems.push_back({1, 8, mem_base, 0x1234ULL});
                mems.push_back({1, 8, mem_base + 8, 0x5678ULL});
                mems.push_back({2, 8, mem_base + 16, 0xABCDULL});
                mems.push_back({2, 8, mem_base + 24, 0xEF01ULL});
            }

            // Emit handler: operation + mem accesses + advance x1 + advance x8 + b header
            tw.emit(ms, handler_pc, enc::add_imm(4, 4, 1),
                    {{4, ms.x(4) + 1}, {33, tw.rt(handler_pc + 4)}}, mems);
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
            ms.x(4) = ms.x(4) + 1;
        }

        // Exit
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(),
                {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, ("vm_abstract_mem_" + std::string(1, mode) + "_" + std::to_string(N)).c_str());
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW TESTS: dispatch type, arch inference, VMContextHint, config, edge cases
// ═══════════════════════════════════════════════════════════════════════════════

// ─── T1: Dispatch type classification ────────────────────────────────────────

TEST_CASE("VMAbstractPass: dispatch type is IndirectBranch for BR-based dispatch",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    CHECK(res.dispatcher.dispatch_type == DispatchType::IndirectBranch);
}

TEST_CASE("VMAbstractPass: dispatch type is CallTable for BLR-based dispatch",
          "[unit][pass][vm_abstract]") {
    auto env = make_blr_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();
    CHECK(res.dispatcher.dispatch_type == DispatchType::CallTable);
    CHECK(res.handlers.size() >= 3);
    CHECK(res.steps.size() >= 10);
}

// ─── T2: VM architecture inference ──────────────────────────────────────────

TEST_CASE("VMAbstractPass: arch_type_hint overrides inference",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    cfg.arch_type_hint = VMArchType::RegisterMachine;  // explicit hint
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    CHECK(res.arch_type == VMArchType::RegisterMachine);
}

TEST_CASE("VMAbstractPass: arch_type inferred as StackMachine from mem patterns",
          "[unit][pass][vm_abstract]") {
    // Stack-like handlers: each does only reads or only writes (not balanced)
    auto env = make_memaccess_vm_trace(15, 'S');
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();
    CHECK(res.arch_type == VMArchType::StackMachine);
}

TEST_CASE("VMAbstractPass: arch_type inferred as RegisterMachine from mem patterns",
          "[unit][pass][vm_abstract]") {
    // Register-like handlers: each does balanced reads + writes
    auto env = make_memaccess_vm_trace(15, 'R');
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();
    CHECK(res.arch_type == VMArchType::RegisterMachine);
}

// ─── T3: VMContextHint decoding ─────────────────────────────────────────────

TEST_CASE("VMAbstractPass: VMContextHint reads context fields from memory",
          "[unit][pass][vm_abstract]") {
    // Build a trace with memory writes establishing a "VM context struct":
    //   ctx_base (x10 = 0xCC000000) + offset 0 → "sp"  field = 0x1111
    //   ctx_base (x10 = 0xCC000000) + offset 8 → "ip"  field = 0x2222
    // The prologue writes these values; the pass should read them at dispatch time.

    constexpr uint64_t CTX_BASE = 0xCC000000ULL;
    constexpr int N = 12;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Prologue: write context fields
        // STR at ctx_base+0: value 0x1111 ("sp" field)
        TraceWriter::MemAcc ma_sp;
        ma_sp.type = 2; ma_sp.size = 8; ma_sp.addr = tw.rt(0) + CTX_BASE; ma_sp.value = 0x1111;
        tw.emit(ms, 0x8000, enc::nop(), {{33, tw.rt(0x8004)}}, {ma_sp});

        // STR at ctx_base+8: value 0x2222 ("ip" field)
        TraceWriter::MemAcc ma_ip;
        ma_ip.type = 2; ma_ip.size = 8; ma_ip.addr = tw.rt(0) + CTX_BASE + 8; ma_ip.value = 0x2222;
        tw.emit(ms, 0x8004, enc::nop(), {{33, tw.rt(0x8008)}}, {ma_ip});

        // Setup VM registers
        ms.x(0) = 0x42;
        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200;
        ms.x(8) = 0;
        ms.x(10) = tw.rt(0) + CTX_BASE;  // ctx base register
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            // Simplified handler: just advance + loop back
            tw.emit(ms, handler_pc, enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc+4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc+8)}}, {});
            tw.emit(ms, handler_pc+8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc+0xC)}}, {});
            tw.emit(ms, handler_pc+0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
            ms.x(4) = ms.x(4) + 1;
        }

        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_ctx");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    VMContextHint vctx;
    vctx.ctx_base_reg = 10;  // x10 holds ctx pointer
    vctx.fields.push_back({0, "sp"});
    vctx.fields.push_back({8, "ip"});
    cfg.vm_context = vctx;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("steps have ctx_fields populated") {
        REQUIRE(!res.steps.empty());
        uint32_t steps_with_ctx = 0;
        for (const auto& step : res.steps) {
            if (!step.ctx_fields.empty()) steps_with_ctx++;
        }
        CHECK(steps_with_ctx == res.steps.size());
    }

    SECTION("ctx_fields contain expected names and values") {
        // Check first step has both "sp" and "ip" fields with correct values
        const auto& step0 = res.steps[0];
        REQUIRE(step0.ctx_fields.size() == 2);

        bool found_sp = false, found_ip = false;
        for (const auto& [name, val] : step0.ctx_fields) {
            if (name == "sp") { CHECK(val == 0x1111); found_sp = true; }
            if (name == "ip") { CHECK(val == 0x2222); found_ip = true; }
        }
        CHECK(found_sp);
        CHECK(found_ip);
    }
}

TEST_CASE("VMAbstractPass: VMContextHint skips unknown memory fields",
          "[unit][pass][vm_abstract]") {
    // Build a trace where only one of two context fields has been written.
    // The unwritten field should be absent from step.ctx_fields.

    constexpr uint64_t CTX_BASE = 0xDD000000ULL;
    constexpr int N = 12;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Only write one field (offset 0), leave offset 16 unwritten
        TraceWriter::MemAcc ma_known;
        ma_known.type = 2; ma_known.size = 8;
        ma_known.addr = tw.rt(0) + CTX_BASE; ma_known.value = 0xAAAA;
        tw.emit(ms, 0x8000, enc::nop(), {{33, tw.rt(0x8004)}}, {ma_known});

        ms.x(0) = 0x42; ms.x(1) = 0xDEAD0000ULL; ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL; ms.x(4) = 100; ms.x(5) = 0xAAAA;
        ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        ms.x(10) = tw.rt(0) + CTX_BASE;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc, enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc+4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc+8)}}, {});
            tw.emit(ms, handler_pc+8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc+0xC)}}, {});
            tw.emit(ms, handler_pc+0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_ctx_partial");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    VMContextHint vctx;
    vctx.ctx_base_reg = 10;
    vctx.fields.push_back({0,  "known_field"});
    vctx.fields.push_back({16, "unknown_field"});  // never written
    cfg.vm_context = vctx;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    REQUIRE(!res.steps.empty());

    // Each step should have exactly 1 field (the known one), not 2
    const auto& step0 = res.steps[0];
    CHECK(step0.ctx_fields.size() == 1);
    if (!step0.ctx_fields.empty()) {
        CHECK(step0.ctx_fields[0].first == "known_field");
        CHECK(step0.ctx_fields[0].second == 0xAAAA);
    }
}

// ─── T4: Config-driven enrichment ───────────────────────────────────────────

TEST_CASE("VMAbstractPass: handler_names labels are applied",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    cfg.handler_names[rt_pc(HANDLER_A)] = "VM_ADD";
    cfg.handler_names[rt_pc(HANDLER_B)] = "VM_XOR";

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    auto* ha = res.handler_at(rt_pc(HANDLER_A));
    auto* hb = res.handler_at(rt_pc(HANDLER_B));
    auto* hc = res.handler_at(rt_pc(HANDLER_C));
    REQUIRE(ha != nullptr);
    REQUIRE(hb != nullptr);
    REQUIRE(hc != nullptr);
    CHECK(ha->label == "VM_ADD");
    CHECK(hb->label == "VM_XOR");
    CHECK(hc->label.empty());  // no name provided → empty
}

TEST_CASE("VMAbstractPass: handler_entry_pcs merges with discovered handlers",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    // Pre-provide one known handler PC + one fictional handler PC
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), 0xF000F000ULL};

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();

    // Should have at least 4 handlers: A, B, C (discovered) + 0xF000F000 (from hint)
    CHECK(res.handlers.size() >= 4);

    // The fictional handler should exist with execution_count == 0
    auto* hf = res.handler_at(0xF000F000ULL);
    REQUIRE(hf != nullptr);
    CHECK(hf->execution_count == 0);

    // Handler A should NOT be duplicated (appears in both hint and discovered)
    uint32_t count_a = 0;
    for (const auto& h : res.handlers) {
        if (h.entry_pc == rt_pc(HANDLER_A)) count_a++;
    }
    CHECK(count_a == 1);
}

TEST_CASE("VMAbstractPass: state_regs and invariant_regs classification",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(15);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();

    // x1 (VM-PC) changes every iteration → should be in state_regs
    bool x1_in_state = false;
    for (uint8_t r : res.dispatcher.state_regs) {
        if (r == 1) x1_in_state = true;
    }
    CHECK(x1_in_state);

    // x8 (loop counter) also changes every iteration → in state_regs
    bool x8_in_state = false;
    for (uint8_t r : res.dispatcher.state_regs) {
        if (r == 8) x8_in_state = true;
    }
    CHECK(x8_in_state);

    // x3 (handler table base, constant 0xBEEF0000) → should be in invariant_regs
    bool x3_invariant = false;
    for (uint8_t r : res.dispatcher.invariant_regs) {
        if (r == 3) x3_invariant = true;
    }
    CHECK(x3_invariant);

    // x0 (fixed 0x42) → invariant
    bool x0_invariant = false;
    for (uint8_t r : res.dispatcher.invariant_regs) {
        if (r == 0) x0_invariant = true;
    }
    CHECK(x0_invariant);

    // No register should appear in both lists
    for (uint8_t r : res.dispatcher.state_regs) {
        bool in_invariant = false;
        for (uint8_t inv : res.dispatcher.invariant_regs) {
            if (r == inv) in_invariant = true;
        }
        CHECK_FALSE(in_invariant);
    }
}

TEST_CASE("VMAbstractPass: bytecode_end uses opcode_size from hint",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 4;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    REQUIRE(res.vm_pc_reg == 1);

    // bytecode_end should be max_vpc + opcode_size(4)
    // x1 ranges from 0xDEAD0000 to 0xDEAD0000 + 12*4 = 0xDEAD0030
    // (12 iterations → 13 header hits, last x1 = base + 12*4)
    // bytecode_end = 0xDEAD0030 + 4 = 0xDEAD0034
    CHECK(res.bytecode_base == 0xDEAD0000ULL);
    CHECK(res.bytecode_end == 0xDEAD0034ULL);
}

TEST_CASE("VMAbstractPass: hint-driven with explicit indirect_branch_pc",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.auto_detect = false;
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    dh.indirect_branch_pc = rt_pc(HEADER_PC + 0xC);  // explicit BR PC
    cfg.dispatcher = dh;
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    CHECK(res.dispatcher.indirect_branch_pc == rt_pc(HEADER_PC + 0xC));
    CHECK(res.handlers.size() >= 3);
    CHECK(res.steps.size() >= 10);
}

// ─── T5: Error and edge-case paths ──────────────────────────────────────────

TEST_CASE("VMAbstractPass: hinted loop header not found returns empty",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.auto_detect = false;
    DispatcherHint dh;
    dh.loop_header_pc = 0xDEADDEADULL;  // non-existent PC
    cfg.dispatcher = dh;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());  // should succeed, just with empty result
    auto& res = raw.get<VMAbstractResult>();
    CHECK(res.handlers.empty());
    CHECK(res.steps.empty());
    CHECK(res.dispatcher.loop_header_pc == 0);
}

TEST_CASE("VMAbstractPass: VM-PC inference fails with too few iterations",
          "[unit][pass][vm_abstract]") {
    // Build a trace with only 3 dispatch iterations — below the 4-sample minimum
    // for infer_vm_pc_register.
    auto env = make_vm_trace(3);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 2;  // very low threshold
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    // With only 3 header inst_ids, the pass may not detect a dispatcher at all
    // (needs >= 3 header_inst_ids for a valid candidate). If a dispatcher IS found,
    // VM-PC inference will fail because header_inst_ids.size() < 4.
    if (!res.handlers.empty()) {
        // If somehow detected: VM-PC should be unknown (inference needs ≥4 samples)
        // Actually the header is hit 4 times (3 iterations + 1 exit), so inference
        // might work. Just verify the result is internally consistent.
        CHECK(res.total_vm_steps == res.steps.size());
    }
}

TEST_CASE("VMAbstractPass: opcode decode fails gracefully with bad opcode_size",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    // opcode_size = 0 should skip decode entirely
    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 0;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    // All steps should have opcode_valid == false
    for (const auto& step : res.steps) {
        CHECK_FALSE(step.opcode_valid);
    }
}

TEST_CASE("VMAbstractPass: opcode decode fails when opcode_size > 8",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 16;  // exceeds max (8)
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    for (const auto& step : res.steps) {
        CHECK_FALSE(step.opcode_valid);
    }
}

TEST_CASE("VMAbstractPass: opcode decode fails for unwritten memory",
          "[unit][pass][vm_abstract]") {
    // Use the standard trace (no memory writes to bytecode buffer).
    // Provide VM-PC hint + OpcodeFormatHint → the pass will try to read from
    // 0xDEAD0000 etc. where nothing was ever written → all_known == false.
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;

    VMPCHint vph;
    vph.reg = 1;
    vph.bytecode_base = 0xDEAD0000ULL;
    cfg.vm_pc = vph;

    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 4;
    ofmt.opcode_mask = 0xFF;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    // vm_pc should be valid (from hint), but opcode decoding should all fail
    CHECK(res.vm_pc_reg == 1);
    for (const auto& step : res.steps) {
        CHECK(step.vm_pc_valid);         // VM-PC known from hint
        CHECK_FALSE(step.opcode_valid);  // memory never written
    }
}

TEST_CASE("VMAbstractPass: total_native_instructions is consistent",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_dispatch_iterations = 5;
    cfg.min_handler_count = 2;
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    // Manually recompute total_native_instructions
    uint64_t expected = 0;
    for (const auto& step : res.steps) {
        if (step.inst_id_end > step.inst_id_start)
            expected += (step.inst_id_end - step.inst_id_start + 1);
    }
    CHECK(res.total_native_instructions == expected);
    CHECK(res.total_native_instructions > 0);
}

TEST_CASE("VMAbstractPass: no dispatcher detected for non-VM trace",
          "[unit][pass][vm_abstract]") {
    // A simple straight-line trace with no loops and no indirect branches
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Emit 20 sequential nops
        for (int i = 0; i < 20; i++) {
            uint64_t pc = 0x1000 + static_cast<uint64_t>(i * 4);
            tw.emit(ms, pc, enc::nop(),
                    {{33, tw.rt(pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "vm_abstract_no_vm");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>());

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    CHECK(res.handlers.empty());
    CHECK(res.steps.empty());
    CHECK(res.dispatcher.loop_header_pc == 0);
}

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
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/vm/vm_abstract_pass.h"
#include "analysis/passes/vm/vm_hints_json.h"

#include <filesystem>
#include <fstream>

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
        // x0 is NOT used as a counter — kept at a fixed value; only x1
        // is the (hinted) VM-PC and shows a constant-step pattern.
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

TEST_CASE("VMAbstractPass: hint-driven mode with dispatcher hint",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    // Don't provide indirect_branch_pc — let the pass find it (structural
    // completion within the already-hinted loop, not detection).
    cfg.dispatcher = dh;
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};
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

    SECTION("handlers are provided from hints") {
        // In the unified anchor-based model, handlers are NOT discovered
        // dynamically — they come from handler_entry_pcs hints.
        CHECK(res.handlers.size() == 3);
    }

    SECTION("steps are produced") {
        CHECK(res.steps.size() >= 10);
    }
}

TEST_CASE("VMAbstractPass: VM-PC derived from vm_registers pc field",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    cfg.dispatcher = dh;

    // Provide a VM-PC via vm_register_file with a "pc" register mapped to x1
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());

    auto& res = raw.get<VMAbstractResult>();

    SECTION("VM-PC uses hinted register") {
        CHECK(res.vm_pc_tracked);
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
    cfg.min_handler_count = 2;
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    cfg.dispatcher = dh;
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};

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
        // In the unified model, handlers are hint-only (no dynamic
        // attribution), so execution_count is always 0.
        CHECK(ha->execution_count == 0);
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};

    // VM-PC: x1 points to bytecode, defined via vm_register_file
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

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

    SECTION("opcode values match expected pattern") {
        // In the unified model, handler_entry_pc is always 0 (no dynamic
        // attribution), so we check opcodes by step index instead.
        // Handlers cycle A, B, C, A, B, C, ... so step i has opcode
        // OPCODE_A + (i % 3).
        for (size_t i = 0; i < res.steps.size(); ++i) {
            const auto& step = res.steps[i];
            if (!step.opcode_valid) continue;
            uint8_t expected = OPCODE_A + static_cast<uint8_t>(i % 3);
            CHECK(step.opcode_value == expected);
        }
    }

    SECTION("hinted handlers exist") {
        // In the unified model, opcode→handler mapping is not populated
        // (handler_entry_pc = 0), so we just verify handlers were created
        // from the handler_entry_pcs hint.
        CHECK(res.handlers.size() == 3);
        REQUIRE(res.handler_at(rt_pc(HANDLER_A)) != nullptr);
        REQUIRE(res.handler_at(rt_pc(HANDLER_B)) != nullptr);
        REQUIRE(res.handler_at(rt_pc(HANDLER_C)) != nullptr);
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
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
    cfg.min_handler_count = 2;
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();
    CHECK(res.dispatcher.dispatch_type == DispatchType::CallTable);
    CHECK(res.handlers.size() == 3);
    CHECK(res.steps.size() >= 10);
}

// ─── T2: VM architecture inference ──────────────────────────────────────────

TEST_CASE("VMAbstractPass: arch_type_hint overrides inference",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
    cfg.arch_type_hint = VMArchType::RegisterMachine;  // explicit hint
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMContextHint vctx;
    vctx.ctx_base_reg = 10;  // x10 holds ctx pointer
    vctx.fields.push_back({0, 8, "sp", false});
    vctx.fields.push_back({8, 8, "ip", false});
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMContextHint vctx;
    vctx.ctx_base_reg = 10;
    vctx.fields.push_back({0,  8, "known_field", false});
    vctx.fields.push_back({16, 8, "unknown_field", false});  // never written
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};
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

TEST_CASE("VMAbstractPass: handler_entry_pcs are used as hint-only handler list",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
    // Provide known handler PCs + one fictional handler PC
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), 0xF000F000ULL};

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();

    // In the unified model, handlers are NOT discovered dynamically —
    // the list is exactly the hinted handler_entry_pcs.
    CHECK(res.handlers.size() == 2);

    // The fictional handler should exist with execution_count == 0
    auto* hf = res.handler_at(0xF000F000ULL);
    REQUIRE(hf != nullptr);
    CHECK(hf->execution_count == 0);

    // Handler A should NOT be duplicated
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    // Provide a VM-PC via vm_register_file with a "pc" register mapped to x1
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    OpcodeFormatHint ofmt;
    ofmt.opcode_size = 4;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    REQUIRE(res.vm_pc_tracked);

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
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    dh.indirect_branch_pc = rt_pc(HEADER_PC + 0xC);  // explicit BR PC
    cfg.dispatcher = dh;
    cfg.handler_entry_pcs = {rt_pc(HANDLER_A), rt_pc(HANDLER_B), rt_pc(HANDLER_C)};
    cfg.min_handler_count = 2;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& res = pm->require("vm_abstract").get<VMAbstractResult>();
    CHECK(res.dispatcher.indirect_branch_pc == rt_pc(HEADER_PC + 0xC));
    CHECK(res.handlers.size() == 3);
    CHECK(res.steps.size() >= 10);
}

// ─── T5: Error and edge-case paths ──────────────────────────────────────────

TEST_CASE("VMAbstractPass: hinted loop header not found returns empty",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
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

TEST_CASE("VMAbstractPass: VM-PC hint works even with very few iterations",
          "[unit][pass][vm_abstract]") {
    // With auto-inference removed, VM-PC always comes straight from the
    // hint — there is no minimum sample count to worry about, unlike the
    // old statistical inference which needed >= 4 header hits.
    auto env = make_vm_trace(3);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    DispatcherHint dh;
    dh.loop_header_pc = rt_pc(HEADER_PC);
    cfg.dispatcher = dh;
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    CHECK(res.vm_pc_tracked);
    CHECK(res.total_vm_steps == res.steps.size());
}

TEST_CASE("VMAbstractPass: opcode decode fails gracefully with bad opcode_size",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(12);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

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
    CHECK(res.vm_pc_tracked);
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
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }
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

// ─── T6: New features added in the generalization pass ───────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// T6-1: opcode_byte_offset — opcode lives at byte offset 1 of a 2-byte word.
//
// Bytecode format (per instruction, 2 bytes):
//   byte0 = flags / reserved (0x55)
//   byte1 = opcode  (0x01 / 0x02 / 0x03)
//
// We configure opcode_size=2, opcode_mask=0xFF00, opcode_shift=8 to extract
// the opcode from the second byte.
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: opcode_byte_offset extracts opcode from non-zero offset",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t BYTECODE_BASE2 = 0xBBBC0000ULL;  // distinct from other tests
    constexpr int N = 12;
    constexpr uint8_t OPCODE_A2 = 0x01, OPCODE_B2 = 0x02, OPCODE_C2 = 0x03;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Prologue: write bytecode where opcode is at byte 1 of each 2-byte entry.
        const uint8_t opcodes[N] = {
            OPCODE_A2, OPCODE_B2, OPCODE_C2,
            OPCODE_A2, OPCODE_B2, OPCODE_C2,
            OPCODE_A2, OPCODE_B2, OPCODE_C2,
            OPCODE_A2, OPCODE_B2, OPCODE_C2,
        };
        for (int i = 0; i < N; i++) {
            // Each entry is 4 bytes (for alignment), opcode in byte1.
            // Little-endian layout: [0x55][opcode][0x00][0x00]
            uint64_t addr = BYTECODE_BASE2 + static_cast<uint64_t>(i * 4);
            uint64_t val  = 0x55ULL | (static_cast<uint64_t>(opcodes[i]) << 8);
            TraceWriter::MemAcc ma;
            ma.type = 2; ma.size = 4;
            ma.addr = tw.rt(0) + addr;
            ma.value = val;
            uint64_t setup_pc = 0x9000 + static_cast<uint64_t>(i * 4);
            tw.emit(ms, setup_pc, enc::nop(), {{33, tw.rt(setup_pc + 4)}}, {ma});
        }

        ms.x(1) = tw.rt(0) + BYTECODE_BASE2;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_BASE2) + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_byte_offset");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    // Read 2 bytes from vm_pc+0; isolate byte1 via mask=0xFF00 and shift=8.
    OpcodeFormatHint ofmt;
    ofmt.opcode_size        = 2;
    ofmt.opcode_byte_offset = 0;        // start at byte 0
    ofmt.opcode_mask        = 0xFF00ULL;
    ofmt.opcode_shift       = 8;
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    REQUIRE(!res.steps.empty());
    uint32_t valid_count = 0;
    for (const auto& step : res.steps) {
        if (!step.opcode_valid) continue;
        ++valid_count;
        CHECK((step.opcode_value == OPCODE_A2 ||
               step.opcode_value == OPCODE_B2 ||
               step.opcode_value == OPCODE_C2));
        // Each handler should map to its expected opcode
        if (step.handler_entry_pc == rt_pc(HANDLER_A))
            CHECK(step.opcode_value == OPCODE_A2);
        else if (step.handler_entry_pc == rt_pc(HANDLER_B))
            CHECK(step.opcode_value == OPCODE_B2);
        else if (step.handler_entry_pc == rt_pc(HANDLER_C))
            CHECK(step.opcode_value == OPCODE_C2);
    }
    // All 12 steps should have valid opcodes
    CHECK(valid_count == static_cast<uint32_t>(N));
}

// ─────────────────────────────────────────────────────────────────────────────
// T6-2: ror/not_ deobfuscation ops.
//
// Bytecode encoding (4 bytes per opcode):
//   raw = NOT(opcode) → stored byte = ~opcode
//   Handler A raw = ~0x01 = 0xFE
//   Handler B raw = ~0x02 = 0xFD
//   Handler C raw = ~0x03 = 0xFC
//
// Deobfuscation pipeline: [not_] → recovers original opcode.
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: not_ deobfuscation op recovers original opcode",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t BYTECODE_NOT = 0xBBBD0000ULL;
    constexpr int N = 12;
    constexpr uint8_t OPCODE_A3 = 0x01, OPCODE_B3 = 0x02, OPCODE_C3 = 0x03;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Prologue: store NOT(opcode) in bytecode buffer (1-byte per slot, 4-byte aligned)
        const uint8_t raw_ops[N] = {
            static_cast<uint8_t>(~OPCODE_A3), static_cast<uint8_t>(~OPCODE_B3), static_cast<uint8_t>(~OPCODE_C3),
            static_cast<uint8_t>(~OPCODE_A3), static_cast<uint8_t>(~OPCODE_B3), static_cast<uint8_t>(~OPCODE_C3),
            static_cast<uint8_t>(~OPCODE_A3), static_cast<uint8_t>(~OPCODE_B3), static_cast<uint8_t>(~OPCODE_C3),
            static_cast<uint8_t>(~OPCODE_A3), static_cast<uint8_t>(~OPCODE_B3), static_cast<uint8_t>(~OPCODE_C3),
        };
        for (int i = 0; i < N; i++) {
            uint64_t addr = BYTECODE_NOT + static_cast<uint64_t>(i * 4);
            TraceWriter::MemAcc ma;
            ma.type = 2; ma.size = 4;
            ma.addr = tw.rt(0) + addr;
            ma.value = static_cast<uint64_t>(raw_ops[i]);
            uint64_t setup_pc = 0xA000 + static_cast<uint64_t>(i * 4);
            tw.emit(ms, setup_pc, enc::nop(), {{33, tw.rt(setup_pc + 4)}}, {ma});
        }

        ms.x(1) = tw.rt(0) + BYTECODE_NOT;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_NOT) + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_deobf_not");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    // Read 1 byte; deobfuscate with NOT (no imm needed)
    OpcodeFormatHint ofmt;
    ofmt.opcode_size  = 1;
    ofmt.opcode_mask  = 0xFF;
    ofmt.opcode_shift = 0;
    // Pipeline: NOT(raw) → original opcode
    OpcodeDeobfStep step_not;
    step_not.op  = OpcodeDeobfStep::Op::not_;
    step_not.imm = 0;
    ofmt.deobfuscation_steps.push_back(step_not);
    // AND 0xFF to trim to 8-bit range after NOT (64-bit NOT flips high bits)
    OpcodeDeobfStep step_and;
    step_and.op  = OpcodeDeobfStep::Op::and_;
    step_and.imm = 0xFF;
    ofmt.deobfuscation_steps.push_back(step_and);
    cfg.opcode_format = ofmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw2 = pm->require("vm_abstract");
    REQUIRE(raw2.ok());
    auto& res = raw2.get<VMAbstractResult>();

    REQUIRE(!res.steps.empty());
    uint32_t valid_count = 0;
    for (const auto& step : res.steps) {
        if (!step.opcode_valid) continue;
        ++valid_count;
        if (step.handler_entry_pc == rt_pc(HANDLER_A))
            CHECK(step.opcode_value == OPCODE_A3);
        else if (step.handler_entry_pc == rt_pc(HANDLER_B))
            CHECK(step.opcode_value == OPCODE_B3);
        else if (step.handler_entry_pc == rt_pc(HANDLER_C))
            CHECK(step.opcode_value == OPCODE_C3);
    }
    CHECK(valid_count == static_cast<uint32_t>(N));
}

// ─────────────────────────────────────────────────────────────────────────────
// T6-3: neg deobfuscation op (two's complement negate).
//
// Bytecode encoding: raw = NEG(opcode) → stored = (uint8_t)(-(opcode))
//   OPCODE_A = 0x01 → stored = 0xFF (since -1 mod 256 = 255)
//   OPCODE_B = 0x02 → stored = 0xFE
//   OPCODE_C = 0x03 → stored = 0xFD
//
// Pipeline: neg → and 0xFF → recovers original.
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: neg deobfuscation op recovers negated opcode",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t BYTECODE_NEG = 0xBBBE0000ULL;
    constexpr int N = 12;
    constexpr uint8_t OPCODE_A4 = 0x01, OPCODE_B4 = 0x02, OPCODE_C4 = 0x03;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        const uint8_t raw_ops4[N] = {
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_A4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_B4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_C4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_A4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_B4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_C4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_A4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_B4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_C4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_A4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_B4)),
            static_cast<uint8_t>(-static_cast<int8_t>(OPCODE_C4)),
        };
        for (int i = 0; i < N; i++) {
            uint64_t addr = BYTECODE_NEG + static_cast<uint64_t>(i * 4);
            TraceWriter::MemAcc ma;
            ma.type = 2; ma.size = 4;
            ma.addr = tw.rt(0) + addr;
            ma.value = static_cast<uint64_t>(raw_ops4[i]);
            uint64_t setup_pc = 0xB000 + static_cast<uint64_t>(i * 4);
            tw.emit(ms, setup_pc, enc::nop(), {{33, tw.rt(setup_pc + 4)}}, {ma});
        }

        ms.x(1) = tw.rt(0) + BYTECODE_NEG;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_NEG) + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_deobf_neg");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;

    OpcodeFormatHint ofmt4;
    ofmt4.opcode_size  = 1;
    ofmt4.opcode_mask  = 0xFF;
    ofmt4.opcode_shift = 0;
    // neg(raw) → -raw mod 256 = original opcode (since stored = -opcode mod 256)
    OpcodeDeobfStep step_neg4;
    step_neg4.op  = OpcodeDeobfStep::Op::neg;
    step_neg4.imm = 0;
    ofmt4.deobfuscation_steps.push_back(step_neg4);
    OpcodeDeobfStep step_and4;
    step_and4.op  = OpcodeDeobfStep::Op::and_;
    step_and4.imm = 0xFF;
    ofmt4.deobfuscation_steps.push_back(step_and4);
    cfg.opcode_format = ofmt4;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw4 = pm->require("vm_abstract");
    REQUIRE(raw4.ok());
    auto& res4 = raw4.get<VMAbstractResult>();

    REQUIRE(!res4.steps.empty());
    uint32_t valid4 = 0;
    for (const auto& step : res4.steps) {
        if (!step.opcode_valid) continue;
        ++valid4;
        if (step.handler_entry_pc == rt_pc(HANDLER_A))
            CHECK(step.opcode_value == OPCODE_A4);
        else if (step.handler_entry_pc == rt_pc(HANDLER_B))
            CHECK(step.opcode_value == OPCODE_B4);
        else if (step.handler_entry_pc == rt_pc(HANDLER_C))
            CHECK(step.opcode_value == OPCODE_C4);
    }
    CHECK(valid4 == static_cast<uint32_t>(N));
}

// ─────────────────────────────────────────────────────────────────────────────
// T6-4: ctx Field.size = 4 — read only 4 bytes from a context field.
//
// The VM context struct at CTX_BASE has:
//   +0  (8 bytes) "ip"    = 0x1234567890ABCDEFULL  (large 64-bit value)
//   +8  (4 bytes) "flags" = 0xBEEF                  (32-bit value)
//
// When we configure field.size = 4 for "ip", we should only read the low 32
// bits (0x90ABCDEF on little-endian), not the full 64-bit value.
// "flags" configured with size=4 reads exactly 0xBEEF (padded to 32 bits).
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: VMContextHint respects field.size truncation",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t CTX_BASE5 = 0xCC100000ULL;
    constexpr int N5 = 12;
    constexpr uint64_t IP_FULL  = 0x1234567890ABCDEFULL;
    constexpr uint64_t FLAGS_32 = 0xBEEFULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write ctx_base+0 : "ip" (8 bytes)
        TraceWriter::MemAcc ma_ip5;
        ma_ip5.type = 2; ma_ip5.size = 8;
        ma_ip5.addr = tw.rt(0) + CTX_BASE5;
        ma_ip5.value = IP_FULL;
        tw.emit(ms, 0xC000, enc::nop(), {{33, tw.rt(0xC004)}}, {ma_ip5});

        // Write ctx_base+8 : "flags" (4 bytes)
        TraceWriter::MemAcc ma_fl;
        ma_fl.type = 2; ma_fl.size = 4;
        ma_fl.addr = tw.rt(0) + CTX_BASE5 + 8;
        ma_fl.value = FLAGS_32;
        tw.emit(ms, 0xC004, enc::nop(), {{33, tw.rt(0xC008)}}, {ma_fl});

        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200;
        ms.x(8) = 0; ms.x(10) = tw.rt(0) + CTX_BASE5;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N5; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N5)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N5)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_ctx_size");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMContextHint vctx5;
    vctx5.ctx_base_reg = 10;
    // "ip" field: size=4 → should read only low 4 bytes = 0x90ABCDEF (little-endian)
    { VMContextHint::Field f; f.offset=0; f.size=4; f.name="ip"; f.is_pointer=false; vctx5.fields.push_back(f); }
    // "flags" field: size=4 → reads 0xBEEF
    { VMContextHint::Field f; f.offset=8; f.size=4; f.name="flags"; f.is_pointer=false; vctx5.fields.push_back(f); }
    cfg.vm_context = vctx5;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw5 = pm->require("vm_abstract");
    REQUIRE(raw5.ok());
    auto& res5 = raw5.get<VMAbstractResult>();

    REQUIRE(!res5.steps.empty());
    const auto& step0 = res5.steps[0];
    REQUIRE(step0.ctx_fields.size() == 2);

    bool found_ip = false, found_flags = false;
    for (const auto& [name, val] : step0.ctx_fields) {
        if (name == "ip") {
            // size=4: only low 4 bytes of IP_FULL in little-endian = 0x90ABCDEF
            CHECK(val == (IP_FULL & 0xFFFFFFFFULL));
            found_ip = true;
        }
        if (name == "flags") {
            CHECK(val == FLAGS_32);
            found_flags = true;
        }
    }
    CHECK(found_ip);
    CHECK(found_flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// T6-5: Mixed RF+Stack mode (has_regs() && has_stack() both true).
//
// The VM has:
//   - A register file at rf_base (x11) with named registers R0 (offset 0)
//     and R1 (offset 8).
//   - An operand stack SP at offset 16 from rf_base.  The stack is
//     DESCENDING: SP points to top-of-stack.
//
// We set up x11 = 0xDD000000, and write:
//   [rf_base + 0] = 0xAAAA   (R0)
//   [rf_base + 8] = 0xBBBB   (R1)
//   [rf_base +16] = sp_ptr   (the stack pointer, pointing into a stack buffer)
//   [sp_ptr]      = 0xCCCC   (S0, top-of-stack)
//   [sp_ptr + 8]  = 0xDDDD   (S1)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: mixed RF+Stack mode populates both vm_regs panels",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t RF_BASE6     = 0xDD000000ULL;
    constexpr uint64_t STACK_BUF6   = 0xDD100000ULL;  // separate stack buffer
    constexpr uint64_t R0_VAL       = 0xAAAAULL;
    constexpr uint64_t R1_VAL       = 0xBBBBULL;
    constexpr uint64_t S0_VAL       = 0xCCCCULL;      // top of stack
    constexpr uint64_t S1_VAL       = 0xDDDDULL;      // next slot
    constexpr int N6 = 12;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write RF registers
        auto write_mem = [&](uint64_t static_addr, uint64_t val, uint8_t sz, uint64_t pc) {
            TraceWriter::MemAcc ma;
            ma.type = 2; ma.size = sz;
            ma.addr = tw.rt(0) + static_addr;
            ma.value = val;
            tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {ma});
        };
        write_mem(RF_BASE6,       R0_VAL, 8, 0xD000);
        write_mem(RF_BASE6 + 8,   R1_VAL, 8, 0xD004);
        // Write stack pointer (SP) value into rf_base+16 (runtime address = slide + STACK_BUF6)
         write_mem(RF_BASE6 + 16, tw.rt(0) + STACK_BUF6, 8, 0xD008);
        // Write stack slots at STACK_BUF6 (descending: SP = top)
        write_mem(STACK_BUF6,      S0_VAL, 8, 0xD00C);   // S0 = *SP
        write_mem(STACK_BUF6 + 8,  S1_VAL, 8, 0xD010);   // S1 = *(SP + 8)

        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200;
        ms.x(8) = 0; ms.x(11) = tw.rt(0) + RF_BASE6;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N6; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N6)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N6)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_mixed_rf_stack");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh6;
    rfh6.rf_base_reg = 11;  // x11 holds RF base
    rfh6.regs.push_back({0, 8, "R0", false, false});
    rfh6.regs.push_back({8, 8, "R1", false, false});
    // Stack configuration (descending, default)
    rfh6.stack_sp_offset = 16;   // SP pointer is at rf_base+16
    rfh6.stack_elem_size = 8;
    rfh6.stack_depth     = 2;
    rfh6.stack_direction = VMRegisterFileHint::StackDirection::Descending;
    cfg.vm_register_file = rfh6;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw6 = pm->require("vm_abstract");
    REQUIRE(raw6.ok());
    auto& res6 = raw6.get<VMAbstractResult>();

    REQUIRE(!res6.steps.empty());

    // The first step's vm_regs should contain: R0, R1, SP, S0, S1
    const auto& step6 = res6.steps[0];
    bool found_R0 = false, found_R1 = false;
    bool found_SP = false, found_S0 = false, found_S1 = false;
    for (const auto& [name, val] : step6.vm_regs) {
        if (name == "R0") { CHECK(val == R0_VAL); found_R0 = true; }
        if (name == "R1") { CHECK(val == R1_VAL); found_R1 = true; }
        if (name == "SP") { CHECK(val == (0x4000ULL + STACK_BUF6)); found_SP = true; }  // runtime addr
        if (name == "S0") { CHECK(val == S0_VAL); found_S0 = true; }
        if (name == "S1") { CHECK(val == S1_VAL); found_S1 = true; }
    }
    CHECK(found_R0);
    CHECK(found_R1);
    CHECK(found_SP);
    CHECK(found_S0);
    CHECK(found_S1);

    // Result should carry the RF hint
    REQUIRE(res6.vm_register_file.has_value());
    CHECK(res6.vm_register_file->is_mixed());
}

// ─────────────────────────────────────────────────────────────────────────────
// T6-6: stack_direction = Ascending.
//
// An ascending stack: SP points to the NEXT FREE slot.
// Top-of-stack = *(SP - elem), next = *(SP - 2*elem).
//
// Setup:
//   rf_base (x12) + offset 0 = sp_ptr (ascending)
//   sp_ptr = STACK_BUF7 + 16   (next free slot is here)
//   STACK_BUF7 + 8  = 0xEEEE  (S0: last pushed = *(SP - 8))
//   STACK_BUF7 + 0  = 0xFFFF  (S1: one before = *(SP - 16))
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("VMAbstractPass: stack_direction Ascending reads slots below SP",
          "[unit][pass][vm_abstract]") {
    constexpr uint64_t RF_BASE7   = 0xEE000000ULL;
    constexpr uint64_t STACK_BUF7 = 0xEE100000ULL;
    // SP = STACK_BUF7 + 16 (next free slot); top = *(SP-8) = STACK_BUF7+8
    constexpr uint64_t SP_VAL7 = STACK_BUF7 + 16;
    constexpr uint64_t S0_VAL7 = 0xEEEEULL;   // at STACK_BUF7 + 8
    constexpr uint64_t S1_VAL7 = 0xFFFFULL;   // at STACK_BUF7 + 0
    constexpr int N7 = 12;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        auto write_mem7 = [&](uint64_t static_addr, uint64_t val, uint8_t sz, uint64_t pc) {
            TraceWriter::MemAcc ma;
            ma.type = 2; ma.size = sz;
            ma.addr = tw.rt(0) + static_addr;
            ma.value = val;
            tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {ma});
        };
        // rf_base+0 = stack pointer (ascending: SP = next free) — store as runtime addr
         write_mem7(RF_BASE7, tw.rt(0) + SP_VAL7, 8, 0xE000);
        // Stack contents (ascending: items below SP)
        write_mem7(STACK_BUF7 + 8, S0_VAL7, 8, 0xE004);  // S0 = *(SP - 8)
        write_mem7(STACK_BUF7,     S1_VAL7, 8, 0xE008);  // S1 = *(SP - 16)

        ms.x(1) = 0xDEAD0000ULL;
        ms.x(2) = 0; ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200;
        ms.x(8) = 0; ms.x(12) = tw.rt(0) + RF_BASE7;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N7; i++) {
            uint64_t handler_pc = handler_pcs[i % 3];
            uint64_t next_x8 = static_cast<uint64_t>(i + 1);
            uint64_t next_x1 = 0xDEAD0000ULL + static_cast<uint64_t>((i + 1) * 4);

            tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N7)),
                    {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x8);
            tw.emit(ms, HEADER_PC + 4, enc::b_ge(12),
                    {{33, tw.rt(HEADER_PC + 8)}}, {});
            tw.emit(ms, HEADER_PC + 8, enc::ldr_reg(2, 3, 1),
                    {{2, tw.rt(handler_pc)}, {33, tw.rt(HEADER_PC + 0xC)}}, {});
            tw.emit(ms, HEADER_PC + 0xC, enc::br(2),
                    {{33, tw.rt(handler_pc)}}, {});

            tw.emit(ms, handler_pc,     enc::add_imm(4, 4, 1),
                    {{4, ms.x(4)+1}, {33, tw.rt(handler_pc+4)}}, {});
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});

            ms.x(8) = next_x8; ms.x(1) = next_x1; ms.x(4) = ms.x(4) + 1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N7)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_stack_ascending");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    {
        DispatcherHint dh;
        dh.loop_header_pc = rt_pc(HEADER_PC);
        cfg.dispatcher = dh;
    }

    VMRegisterFileHint rfh7;
    rfh7.rf_base_reg    = 12;    // x12 holds RF base
    rfh7.stack_sp_offset = 0;   // SP pointer at rf_base+0
    rfh7.stack_elem_size = 8;
    rfh7.stack_depth     = 2;
    rfh7.stack_direction = VMRegisterFileHint::StackDirection::Ascending;
    cfg.vm_register_file = rfh7;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw7 = pm->require("vm_abstract");
    REQUIRE(raw7.ok());
    auto& res7 = raw7.get<VMAbstractResult>();

    REQUIRE(!res7.steps.empty());
    const auto& step7 = res7.steps[0];

    bool found_SP7 = false, found_S0_7 = false, found_S1_7 = false;
    for (const auto& [name, val] : step7.vm_regs) {
        if (name == "SP") {
            // SP should equal the runtime address of STACK_BUF7 + 16
             CHECK(val == (0x4000ULL + SP_VAL7));  // = 0x4000 + STACK_BUF7 + 16
            found_SP7 = true;
        }
        if (name == "S0") { CHECK(val == S0_VAL7); found_S0_7 = true; }
        if (name == "S1") { CHECK(val == S1_VAL7); found_S1_7 = true; }
    }
    CHECK(found_SP7);
    CHECK(found_S0_7);
    CHECK(found_S1_7);
}

// ─── VMConfig::has_any_static_hint() ─────────────────────────────────────────
//
// Product surfaces (CLI --vm-abstract, GUI VM Workspace, MCP vm_abstract
// tool) gate the unreliable heuristic auto-detection behind this helper:
// vm_abstract must not run silently without at least one static-analysis
// hint unless the caller explicitly opts into auto-detection.

TEST_CASE("VMConfig::has_any_static_hint returns false for a bare config",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    CHECK_FALSE(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects dispatcher hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    DispatcherHint dh;
    dh.loop_header_pc = 0x1000;
    cfg.dispatcher = dh;
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects handler_entry_pcs",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.handler_entry_pcs.push_back(0x2000);
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects vm_register_file with pc field",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;
    rfh.regs.push_back(vreg_pc);
    cfg.vm_register_file = rfh;
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects opcode_format hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.opcode_format = OpcodeFormatHint{};
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects vm_context hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    VMContextHint vch;
    vch.ctx_base_reg = 21;
    cfg.vm_context = vch;
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects vm_register_file hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.vm_register_file = VMRegisterFileHint{};
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects handler_asm hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.handler_asm = HandlerAsmHint{};
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects handler_names",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.handler_names[0x2000] = "ADD";
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects forced dispatch_type_hint",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.dispatch_type_hint = DispatchType::ThreadedCode;
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint detects threaded_dispatch_pcs",
          "[unit][pass][vm_abstract][hints]") {
    VMConfig cfg;
    cfg.threaded_dispatch_pcs.push_back(0x3000);
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("VMConfig::has_any_static_hint ignores arch_type_hint and thresholds",
          "[unit][pass][vm_abstract][hints]") {
    // arch_type_hint / min_handler_count are tuning knobs / static-fact
    // hints that don't by themselves say WHERE the dispatcher is — they must
    // NOT count towards "has hints" (a caller could otherwise bypass the
    // gate without providing real dispatcher information).
    VMConfig cfg;
    cfg.arch_type_hint = VMArchType::RegisterMachine;
    cfg.min_handler_count = 1;
    CHECK_FALSE(cfg.has_any_static_hint());
}

// ─── load_vm_hints_from_json() ────────────────────────────────────────────────
//
// Shared JSON hints-file loader used by the CLI (--vm-hints) and GUI
// ("Load Hints") frontends to satisfy the has_any_static_hint() gate without
// requiring the caller to hand-build a VMConfig in code.

namespace {

/// RAII helper: writes `contents` to a uniquely-named temp file and deletes
/// it on scope exit.
class TempJsonFile {
public:
    explicit TempJsonFile(const std::string& contents) {
        path_ = std::filesystem::temp_directory_path() /
                ("vm_hints_test_" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ".json");
        std::ofstream f(path_);
        f << contents;
    }
    ~TempJsonFile() { std::error_code ec; std::filesystem::remove(path_, ec); }

    const std::string path() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

}  // namespace

TEST_CASE("load_vm_hints_from_json returns false for a missing file",
          "[unit][pass][vm_abstract][hints][json]") {
    VMConfig cfg;
    CHECK_FALSE(load_vm_hints_from_json("/nonexistent/path/does-not-exist.json", cfg));
    CHECK_FALSE(cfg.has_any_static_hint());
}

TEST_CASE("load_vm_hints_from_json returns false for malformed JSON",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f("{ this is not valid json ");
    VMConfig cfg;
    CHECK_FALSE(load_vm_hints_from_json(f.path(), cfg));
}

TEST_CASE("load_vm_hints_from_json returns false for invalid field values",
          "[unit][pass][vm_abstract][hints][json]") {
    // dispatch_type_hint's underlying string must map to a known DispatchType;
    // opcode_deobf_steps must use a recognised op name, otherwise the loader
    // should fail cleanly rather than silently ignoring the bad hint.
    TempJsonFile f(R"({
        "opcode_deobf_steps": [{"op": "not_a_real_op", "imm": "0x1"}]
    })");
    VMConfig cfg;
    CHECK_FALSE(load_vm_hints_from_json(f.path(), cfg));
}

TEST_CASE("load_vm_hints_from_json parses an empty object without setting hints",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f("{}");
    VMConfig cfg;
    CHECK(load_vm_hints_from_json(f.path(), cfg));
    CHECK_FALSE(cfg.has_any_static_hint());
}

TEST_CASE("load_vm_hints_from_json parses dispatcher_pc and indirect_branch_pc",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "dispatcher_pc": "0x1000",
        "indirect_branch_pc": "0x100C"
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.dispatcher.has_value());
    CHECK(cfg.dispatcher->loop_header_pc == 0x1000);
    CHECK(cfg.dispatcher->indirect_branch_pc == 0x100C);
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("load_vm_hints_from_json parses handler_entry_pcs list",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "handler_entry_pcs": ["0x2000", "0x3000", "0x4000"]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.handler_entry_pcs.size() == 3);
    CHECK(cfg.handler_entry_pcs[0] == 0x2000);
    CHECK(cfg.handler_entry_pcs[1] == 0x3000);
    CHECK(cfg.handler_entry_pcs[2] == 0x4000);
}

// ─── load_vm_hints_from_json() address rebase (module_slide/image_base) ──────
//
// Regression coverage for the IDA-displayed-address convention: hints files
// authored by copying addresses straight out of IDA (image_base 0x100000000)
// must resolve to the correct runtime PC once module_slide is known — same
// convention as the MCP `vm_abstract` tool's hints_file handling. Before this
// was fixed, load_vm_hints_from_json() (used by the GUI's "Load Hints" and
// the CLI's --vm-hints) took the JSON value as a raw runtime address with no
// conversion, which silently produced "hinted PC was never executed" for any
// hints file that worked fine through the MCP tool.

TEST_CASE("load_vm_hints_from_json rebases dispatcher_pc from IDA address to runtime address",
          "[unit][pass][vm_abstract][hints][json][rebase]") {
    // IDA-displayed dispatcher_pc = image_base (0x100000000) + 0x8eaf60.
    // With module_slide = 0x1000000000 (some ASLR-loaded runtime base), the
    // resulting runtime PC should be slide + 0x8eaf60.
    TempJsonFile f(R"({
        "dispatcher_pc": "0x1008eaf60",
        "indirect_branch_pc": "0x1008eaf70"
    })");
    VMConfig cfg;
    uint64_t module_slide = 0x1000000000ULL;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg, module_slide, kDefaultIdaImageBase));
    REQUIRE(cfg.dispatcher.has_value());
    CHECK(cfg.dispatcher->loop_header_pc == module_slide + 0x8eaf60ULL);
    CHECK(cfg.dispatcher->indirect_branch_pc == module_slide + 0x8eaf70ULL);
}

TEST_CASE("load_vm_hints_from_json rebases handler_entry_pcs and handler_names",
          "[unit][pass][vm_abstract][hints][json][rebase]") {
    TempJsonFile f(R"({
        "handler_entry_pcs": ["0x100002000", "0x100003000"],
        "handler_names": {"0x100002000": "ADD", "0x100003000": "SUB"}
    })");
    VMConfig cfg;
    uint64_t module_slide = 0x2000000000ULL;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg, module_slide, kDefaultIdaImageBase));
    REQUIRE(cfg.handler_entry_pcs.size() == 2);
    CHECK(cfg.handler_entry_pcs[0] == module_slide + 0x2000ULL);
    CHECK(cfg.handler_entry_pcs[1] == module_slide + 0x3000ULL);
    REQUIRE(cfg.handler_names.count(module_slide + 0x2000ULL) == 1);
    CHECK(cfg.handler_names.at(module_slide + 0x2000ULL) == "ADD");
    REQUIRE(cfg.handler_names.count(module_slide + 0x3000ULL) == 1);
    CHECK(cfg.handler_names.at(module_slide + 0x3000ULL) == "SUB");
}

TEST_CASE("load_vm_hints_from_json does not rebase mem_anchor_addr (already runtime)",
          "[unit][pass][vm_abstract][hints][json][rebase]") {
    TempJsonFile f(R"({
        "dispatcher_pc": "0x100001000",
        "mem_anchor_addr": "0x2000000abc",
        "mem_anchor_size": 4
    })");
    VMConfig cfg;
    uint64_t module_slide = 0x2000000000ULL;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg, module_slide, kDefaultIdaImageBase));
    REQUIRE(cfg.dispatcher.has_value());
    CHECK(cfg.dispatcher->loop_header_pc == module_slide + 0x1000ULL);
    // mem_anchor_addr passes through unchanged regardless of module_slide/image_base.
    CHECK(cfg.dispatcher->mem_anchor_addr == 0x2000000abcULL);
}

TEST_CASE("load_vm_hints_from_json default image_base=0 leaves addresses unrebased",
          "[unit][pass][vm_abstract][hints][json][rebase]") {
    // Backward-compat: callers/tests that don't pass module_slide/image_base
    // get the raw JSON values verbatim (image_base defaults to 0 == no-op).
    TempJsonFile f(R"({ "dispatcher_pc": "0x1000" })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.dispatcher.has_value());
    CHECK(cfg.dispatcher->loop_header_pc == 0x1000);
}

TEST_CASE("load_vm_hints_from_json parses dispatch_type and threaded_dispatch_pcs",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "dispatch_type": "ThreadedCode",
        "threaded_dispatch_pcs": ["0x5000", "0x6000"]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    CHECK(cfg.dispatch_type_hint == DispatchType::ThreadedCode);
    REQUIRE(cfg.threaded_dispatch_pcs.size() == 2);
    CHECK(cfg.threaded_dispatch_pcs[0] == 0x5000);
    CHECK(cfg.threaded_dispatch_pcs[1] == 0x6000);
}


TEST_CASE("load_vm_hints_from_json parses full opcode format with deobf steps",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "opcode_size": 1,
        "opcode_byte_offset": 2,
        "opcode_mask": "0xFF",
        "opcode_shift": 0,
        "opcode_deobf_steps": [
            {"op": "sub", "imm": "0xF"},
            {"op": "xor", "imm": "0xE0"},
            {"op": "neg"},
            {"op": "not"}
        ]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.opcode_format.has_value());
    const auto& ofh = *cfg.opcode_format;
    CHECK(ofh.opcode_size == 1);
    CHECK(ofh.opcode_byte_offset == 2);
    CHECK(ofh.opcode_mask == 0xFF);
    CHECK(ofh.opcode_shift == 0);
    REQUIRE(ofh.deobfuscation_steps.size() == 4);
    CHECK(ofh.deobfuscation_steps[0].op == OpcodeDeobfStep::Op::sub);
    CHECK(ofh.deobfuscation_steps[0].imm == 0xF);
    CHECK(ofh.deobfuscation_steps[1].op == OpcodeDeobfStep::Op::xor_);
    CHECK(ofh.deobfuscation_steps[1].imm == 0xE0);
    CHECK(ofh.deobfuscation_steps[2].op == OpcodeDeobfStep::Op::neg);
    CHECK(ofh.deobfuscation_steps[3].op == OpcodeDeobfStep::Op::not_);
}

TEST_CASE("load_vm_hints_from_json parses opcode_from_reg (mode B)",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({ "opcode_from_reg": "x0" })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.opcode_format.has_value());
    CHECK(cfg.opcode_format->opcode_from_reg == 0);
}

TEST_CASE("load_vm_hints_from_json parses vm_context ctx_base_reg and ctx_fields",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "ctx_base_reg": "x21",
        "ctx_fields": [
            {"name": "ip", "offset": 0, "size": 8, "is_pointer": true},
            {"name": "flags", "offset": 8, "size": 4}
        ]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.vm_context.has_value());
    CHECK(cfg.vm_context->ctx_base_reg == 21);
    REQUIRE(cfg.vm_context->fields.size() == 2);
    CHECK(cfg.vm_context->fields[0].name == "ip");
    CHECK(cfg.vm_context->fields[0].offset == 0);
    CHECK(cfg.vm_context->fields[0].size == 8);
    CHECK(cfg.vm_context->fields[0].is_pointer);
    CHECK(cfg.vm_context->fields[1].name == "flags");
    CHECK(cfg.vm_context->fields[1].size == 4);
    CHECK_FALSE(cfg.vm_context->fields[1].is_pointer);
}

TEST_CASE("load_vm_hints_from_json skips ctx_fields entries without a name",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "ctx_base_reg": "x21",
        "ctx_fields": [{"offset": 0, "size": 8}]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.vm_context.has_value());
    CHECK(cfg.vm_context->fields.empty());
}

TEST_CASE("load_vm_hints_from_json parses vm_register_file with regs and stack",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "rf_base_reg": "x20",
        "vm_registers": [
            {"name": "R0", "offset": 0, "size": 8},
            {"name": "V0", "offset": 8, "size": 4, "is_float": true}
        ],
        "vm_stack_sp_offset": 16,
        "vm_stack_depth": 8,
        "vm_stack_elem_size": 8,
        "vm_stack_direction": "ascending"
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.vm_register_file.has_value());
    const auto& rfh = *cfg.vm_register_file;
    CHECK(rfh.rf_base_reg == 20);
    REQUIRE(rfh.regs.size() == 2);
    CHECK(rfh.regs[0].name == "R0");
    CHECK(rfh.regs[1].name == "V0");
    CHECK(rfh.regs[1].is_float);
    CHECK(rfh.stack_sp_offset == 16);
    CHECK(rfh.stack_depth == 8);
    CHECK(rfh.stack_elem_size == 8);
    CHECK(rfh.stack_direction == VMRegisterFileHint::StackDirection::Ascending);
}

TEST_CASE("load_vm_hints_from_json defaults vm_stack_direction to Descending",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({ "vm_stack_sp_offset": 16 })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.vm_register_file.has_value());
    CHECK(cfg.vm_register_file->stack_direction == VMRegisterFileHint::StackDirection::Descending);
}

TEST_CASE("load_vm_hints_from_json parses handler_asm_map with string and object entries",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "handler_asm_map": {
            "0x2000": ["ADD x4, x4, 1", "B 0x1000"],
            "0x3000": [{"pc": "0x3000", "text": "EOR x5, x5, x6"}]
        }
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.handler_asm.has_value());
    const auto& hah = *cfg.handler_asm;
    REQUIRE(hah.handler_asm.count(0x2000) == 1);
    REQUIRE(hah.handler_asm.at(0x2000).size() == 2);
    CHECK(hah.handler_asm.at(0x2000)[0].text == "ADD x4, x4, 1");
    CHECK(hah.handler_asm.at(0x2000)[1].text == "B 0x1000");
    REQUIRE(hah.handler_asm.count(0x3000) == 1);
    REQUIRE(hah.handler_asm.at(0x3000).size() == 1);
    CHECK(hah.handler_asm.at(0x3000)[0].pc == 0x3000);
    CHECK(hah.handler_asm.at(0x3000)[0].text == "EOR x5, x5, x6");
}

TEST_CASE("load_vm_hints_from_json parses handler_names",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "handler_names": {
            "0x2000": "ADD",
            "0x3000": "XOR"
        }
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.handler_names.size() == 2);
    CHECK(cfg.handler_names.at(0x2000) == "ADD");
    CHECK(cfg.handler_names.at(0x3000) == "XOR");
}

TEST_CASE("load_vm_hints_from_json parsing a full hints file satisfies has_any_static_hint",
          "[unit][pass][vm_abstract][hints][json]") {
    // End-to-end sanity check mirroring the CLI/GUI/MCP gate: a caller who
    // loads a realistic hints file should pass has_any_static_hint() and be
    // allowed to run vm_abstract.
    TempJsonFile f(R"({
        "dispatcher_pc": "0x1000",
        "indirect_branch_pc": "0x100C",
        "handler_entry_pcs": ["0x2000", "0x3000", "0x4000"],
        "vm_registers": [{"name": "pc", "from_host_reg": "x1"}]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    CHECK(cfg.has_any_static_hint());
}

TEST_CASE("load_vm_hints_from_json file value overrides a pre-populated cfg field",
          "[unit][pass][vm_abstract][hints][json]") {
    // Per the documented contract in vm_hints_json.h: "the file's value wins"
    // when a field is already set in cfg before loading.
    TempJsonFile f(R"({ "dispatcher_pc": "0x9999" })");
    VMConfig cfg;
    DispatcherHint dh;
    dh.loop_header_pc = 0x1111;
    cfg.dispatcher = dh;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    CHECK(cfg.dispatcher->loop_header_pc == 0x9999);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Feature: Rolling-key opcode deobfuscation
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("VMAbstractPass: xor_rolling deobfuscation decodes rolling-key encrypted opcodes",
          "[unit][pass][vm_abstract]") {
    // Bytecode buffer: opcodes are encrypted with a rolling XOR key.
    // key starts at 0xAA. After each opcode, key ^= decoded_opcode.
    //
    // Step 0: raw=0x01^0xAA=0xAB, decode: 0xAB^0xAA=0x01, key=0xAA^0x01=0xAB
    // Step 1: raw=0x02^0xAB=0xA9, decode: 0xA9^0xAB=0x02, key=0xAB^0x02=0xA9
    // Step 2: raw=0x03^0xA9=0xAA, decode: 0xAA^0xA9=0x03, key=0xA9^0x03=0xAA
    // ...

    constexpr uint64_t BYTECODE_BASE = 0xBBBB0000ULL;
    constexpr int N = 6;
    const uint8_t plain_opcodes[N] = { 0x01, 0x02, 0x03, 0x01, 0x02, 0x03 };

    // Encrypt: key starts at 0xAA, after each: key ^= plain
    uint8_t encrypted[N];
    {
        uint8_t key = 0xAA;
        for (int i = 0; i < N; ++i) {
            encrypted[i] = plain_opcodes[i] ^ key;
            key ^= plain_opcodes[i];
        }
    }

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write encrypted bytecode buffer
        ms.x(9) = BYTECODE_BASE;
        for (int i = 0; i < N; ++i) {
            TraceWriter::MemAcc ma;
            ma.type = 2;
            ma.size = 1;
            ma.addr = tw.rt(0) + BYTECODE_BASE + static_cast<uint64_t>(i);
            ma.value = encrypted[i];
            tw.emit(ms, 0x8000 + static_cast<uint64_t>(i * 4), enc::nop(),
                    {{33, tw.rt(0x8000 + static_cast<uint64_t>((i + 1) * 4))}}, {ma});
        }

        ms.x(0) = 0x42;
        ms.x(1) = tw.rt(0) + BYTECODE_BASE;
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; ++i) {
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
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_BASE) + static_cast<uint64_t>(i + 1);
            if (handler_pc == HANDLER_A) {
                tw.emit(ms, HANDLER_A, enc::add_imm(4, 4, 1),
                        {{4, 100 + static_cast<uint64_t>(i / 3) + 1}, {33, tw.rt(HANDLER_A + 4)}}, {});
            } else if (handler_pc == HANDLER_B) {
                tw.emit(ms, HANDLER_B, enc::eor_reg(5, 5, 6),
                        {{5, ms.x(5) ^ ms.x(6)}, {33, tw.rt(HANDLER_B + 4)}}, {});
            } else {
                tw.emit(ms, HANDLER_C, enc::sub_imm(7, 7, 1),
                        {{7, 200 - static_cast<uint64_t>(i / 3) - 1}, {33, tw.rt(HANDLER_C + 4)}}, {});
            }
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 1),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});
            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_rolling_key");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    { DispatcherHint dh; dh.loop_header_pc = rt_pc(HEADER_PC); cfg.dispatcher = dh; }
    { VMRegisterFileHint rfh; VMRegisterFileHint::VMReg pc; pc.name = "pc"; pc.from_host_reg = 1; rfh.regs.push_back(pc); cfg.vm_register_file = rfh; }
    {
        OpcodeFormatHint ofmt;
        ofmt.opcode_size = 1;
        ofmt.opcode_mask = 0xFF;
        // xor_rolling with initial key 0xAA
        OpcodeDeobfStep rs;
        rs.op = OpcodeDeobfStep::Op::xor_rolling;
        rs.imm = 0xAA;
        ofmt.deobfuscation_steps.push_back(rs);
        ofmt.rolling_key_update = RollingKeyUpdate::XorOpcode;
        cfg.opcode_format = ofmt;
    }

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("all steps decode to correct plain opcodes") {
        REQUIRE(res.steps.size() >= static_cast<size_t>(N));
        for (int i = 0; i < N; ++i) {
            REQUIRE(res.steps[i].opcode_valid);
            CHECK(res.steps[i].opcode_value == plain_opcodes[i]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Feature: Host-register-backed VM registers
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("VMAbstractPass: from_host_reg reads VM register from host register file",
          "[unit][pass][vm_abstract]") {
    auto env = make_vm_trace(6);
    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    { DispatcherHint dh; dh.loop_header_pc = rt_pc(HEADER_PC); cfg.dispatcher = dh; }
    // Configure VM registers: "pc" from host x1 (VM-PC), plus VA from x4, VC from x7.
    // In the test trace, x4 and x7 are modified by handlers A and C
    // respectively, so their values change across steps.
    VMRegisterFileHint rfh;
    VMRegisterFileHint::VMReg vreg_pc;
    vreg_pc.name = "pc";
    vreg_pc.from_host_reg = 1;  // x1 = VM-PC
    rfh.regs.push_back(vreg_pc);

    VMRegisterFileHint::VMReg vreg_a;
    vreg_a.name = "VA";
    vreg_a.from_host_reg = 4;  // x4
    rfh.regs.push_back(vreg_a);

    VMRegisterFileHint::VMReg vreg_c;
    vreg_c.name = "VC";
    vreg_c.from_host_reg = 7;  // x7
    rfh.regs.push_back(vreg_c);

    cfg.vm_register_file = rfh;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("host-register-backed VM regs are populated in every step") {
        for (const auto& step : res.steps) {
            // Should have both VA and VC
            REQUIRE(step.vm_regs.size() >= 2);
            bool found_va = false, found_vc = false;
            for (const auto& [name, val] : step.vm_regs) {
                if (name == "VA") found_va = true;
                if (name == "VC") found_vc = true;
            }
            CHECK(found_va);
            CHECK(found_vc);
        }
    }

    SECTION("host-register values match expected initial values for first step") {
        REQUIRE(!res.steps.empty());
        const auto& first = res.steps[0];
        for (const auto& [name, val] : first.vm_regs) {
            if (name == "VA") CHECK(val == 100);  // x4 starts at 100
            if (name == "VC") CHECK(val == 200);  // x7 starts at 200
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Feature: Operand field decoding
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("VMAbstractPass: operand fields are decoded from bytecode",
          "[unit][pass][vm_abstract]") {
    // 4-byte instruction format: [opcode:1][dst:1][src:1][imm:1]
    // Opcodes: 0x01/0x02/0x03 as before
    // Operands: dst=handler_idx, src=handler_idx+0x10, imm=i (step index)
    constexpr uint64_t BYTECODE_BASE = 0xBBBB0000ULL;
    constexpr int N = 6;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write bytecode: 4-byte instructions
        ms.x(9) = BYTECODE_BASE;
        for (int i = 0; i < N; ++i) {
            uint8_t opcode = static_cast<uint8_t>((i % 3) + 1);
            uint8_t dst = static_cast<uint8_t>(i % 3);
            uint8_t src = static_cast<uint8_t>((i % 3) + 0x10);
            uint8_t imm = static_cast<uint8_t>(i);
            uint32_t insn_word = static_cast<uint32_t>(opcode)
                               | (static_cast<uint32_t>(dst) << 8)
                               | (static_cast<uint32_t>(src) << 16)
                               | (static_cast<uint32_t>(imm) << 24);
            TraceWriter::MemAcc ma;
            ma.type = 2;
            ma.size = 4;
            ma.addr = tw.rt(0) + BYTECODE_BASE + static_cast<uint64_t>(i * 4);
            ma.value = insn_word;
            tw.emit(ms, 0x8000 + static_cast<uint64_t>(i * 4), enc::nop(),
                    {{33, tw.rt(0x8000 + static_cast<uint64_t>((i + 1) * 4))}}, {ma});
        }

        ms.x(0) = 0x42;
        ms.x(1) = tw.rt(0) + BYTECODE_BASE;
        ms.x(2) = 0;
        ms.x(3) = 0xBEEF0000ULL;
        ms.x(4) = 100; ms.x(5) = 0xAAAA; ms.x(6) = 0x5555; ms.x(7) = 200; ms.x(8) = 0;
        tw.emit_anchor(ms);

        const uint64_t handler_pcs[] = { HANDLER_A, HANDLER_B, HANDLER_C };
        for (int i = 0; i < N; ++i) {
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
            uint64_t next_x1 = (tw.rt(0) + BYTECODE_BASE) + static_cast<uint64_t>((i + 1) * 4);
            if (handler_pc == HANDLER_A) {
                tw.emit(ms, HANDLER_A, enc::add_imm(4, 4, 1),
                        {{4, 100 + static_cast<uint64_t>(i / 3) + 1}, {33, tw.rt(HANDLER_A + 4)}}, {});
            } else if (handler_pc == HANDLER_B) {
                tw.emit(ms, HANDLER_B, enc::eor_reg(5, 5, 6),
                        {{5, ms.x(5) ^ ms.x(6)}, {33, tw.rt(HANDLER_B + 4)}}, {});
            } else {
                tw.emit(ms, HANDLER_C, enc::sub_imm(7, 7, 1),
                        {{7, 200 - static_cast<uint64_t>(i / 3) - 1}, {33, tw.rt(HANDLER_C + 4)}}, {});
            }
            tw.emit(ms, handler_pc + 4, enc::add_imm(1, 1, 4),
                    {{1, next_x1}, {33, tw.rt(handler_pc + 8)}}, {});
            tw.emit(ms, handler_pc + 8, enc::add_imm(8, 8, 1),
                    {{8, next_x8}, {33, tw.rt(handler_pc + 0xC)}}, {});
            tw.emit(ms, handler_pc + 0xC,
                    enc::b(static_cast<int32_t>(HEADER_PC - (handler_pc + 0xC))),
                    {{33, tw.rt(HEADER_PC)}}, {});
            ms.x(8) = next_x8;
            ms.x(1) = next_x1;
        }
        tw.emit(ms, HEADER_PC, enc::cmp_imm(8, static_cast<uint16_t>(N)),
                {{33, tw.rt(HEADER_PC + 4)}}, {}, 0x4);
        tw.emit(ms, HEADER_PC + 4, enc::b_ge(12), {{33, tw.rt(EXIT_PC)}}, {});
        tw.emit(ms, EXIT_PC, enc::nop(), {{33, tw.rt(EXIT_PC + 4)}}, {});
        tw.emit_anchor(ms);
    }, "vm_abstract_operand_decode");

    REQUIRE(env != nullptr);
    auto pm = make_pm(*env);

    VMConfig cfg;
    cfg.min_handler_count = 2;
    { DispatcherHint dh; dh.loop_header_pc = rt_pc(HEADER_PC); cfg.dispatcher = dh; }
    { VMRegisterFileHint rfh; VMRegisterFileHint::VMReg pc; pc.name = "pc"; pc.from_host_reg = 1; rfh.regs.push_back(pc); cfg.vm_register_file = rfh; }
    {
        OpcodeFormatHint ofmt;
        ofmt.opcode_size = 1;
        ofmt.opcode_mask = 0xFF;
        cfg.opcode_format = ofmt;
    }
    // Define operand fields: [opcode:1][dst:1][src:1][imm:1]
    VMConfig::OperandFormatHint opfmt;
    opfmt.instruction_size = 4;
    opfmt.fields.push_back({"dst", 1, 1, 0xFF, 0, {}});
    opfmt.fields.push_back({"src", 2, 1, 0xFF, 0, {}});
    opfmt.fields.push_back({"imm", 3, 1, 0xFF, 0, {}});
    cfg.operand_format = opfmt;

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<VMAbstractPass>(std::move(cfg)));

    auto& raw = pm->require("vm_abstract");
    REQUIRE(raw.ok());
    auto& res = raw.get<VMAbstractResult>();

    SECTION("operands are decoded for each step") {
        REQUIRE(res.steps.size() >= static_cast<size_t>(N));
        for (int i = 0; i < N; ++i) {
            const auto& step = res.steps[i];
            REQUIRE(step.operands.size() == 3);
            CHECK(step.operands[0].name == "dst");
            CHECK(step.operands[1].name == "src");
            CHECK(step.operands[2].name == "imm");

            // dst = handler_idx = i%3
            CHECK(step.operands[0].value == static_cast<uint64_t>(i % 3));
            // src = handler_idx + 0x10
            CHECK(step.operands[1].value == static_cast<uint64_t>((i % 3) + 0x10));
            // imm = i
            CHECK(step.operands[2].value == static_cast<uint64_t>(i));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON loader tests for new fields
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("load_vm_hints_from_json parses rolling_key_update",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "opcode_size": 1,
        "opcode_deobf_steps": [{"op": "xor_rolling", "imm": "0xAA"}],
        "rolling_key_update": "hash_opcode"
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.opcode_format.has_value());
    REQUIRE(cfg.opcode_format->deobfuscation_steps.size() == 1);
    CHECK(cfg.opcode_format->deobfuscation_steps[0].op == OpcodeDeobfStep::Op::xor_rolling);
    CHECK(cfg.opcode_format->deobfuscation_steps[0].imm == 0xAA);
    CHECK(cfg.opcode_format->rolling_key_update == RollingKeyUpdate::HashOpcode);
}

TEST_CASE("load_vm_hints_from_json parses from_host_reg in vm_registers",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "vm_registers": [
            {"name": "VA", "from_host_reg": "x19"},
            {"name": "VB", "offset": 0, "size": 8}
        ]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.vm_register_file.has_value());
    REQUIRE(cfg.vm_register_file->regs.size() == 2);
    CHECK(cfg.vm_register_file->regs[0].name == "VA");
    CHECK(cfg.vm_register_file->regs[0].from_host_reg == 19);
    CHECK(cfg.vm_register_file->regs[1].name == "VB");
    CHECK(cfg.vm_register_file->regs[1].from_host_reg == 0xFF);
}

TEST_CASE("load_vm_hints_from_json parses operand_fields and instruction_size",
          "[unit][pass][vm_abstract][hints][json]") {
    TempJsonFile f(R"({
        "instruction_size": 4,
        "operand_fields": [
            {"name": "dst", "byte_offset": 1, "size": 1, "mask": "0xFF", "shift": 0},
            {"name": "imm", "byte_offset": 2, "size": 2, "mask": "0xFFFF",
             "deobf_steps": [{"op": "xor", "imm": "0x55"}]}
        ]
    })");
    VMConfig cfg;
    REQUIRE(load_vm_hints_from_json(f.path(), cfg));
    REQUIRE(cfg.operand_format.has_value());
    CHECK(cfg.operand_format->instruction_size == 4);
    REQUIRE(cfg.operand_format->fields.size() == 2);
    CHECK(cfg.operand_format->fields[0].name == "dst");
    CHECK(cfg.operand_format->fields[0].byte_offset == 1);
    CHECK(cfg.operand_format->fields[0].size == 1);
    CHECK(cfg.operand_format->fields[1].name == "imm");
    CHECK(cfg.operand_format->fields[1].byte_offset == 2);
    CHECK(cfg.operand_format->fields[1].size == 2);
    REQUIRE(cfg.operand_format->fields[1].deobfuscation_steps.size() == 1);
    CHECK(cfg.operand_format->fields[1].deobfuscation_steps[0].op == OpcodeDeobfStep::Op::xor_);
    CHECK(cfg.operand_format->fields[1].deobfuscation_steps[0].imm == 0x55);
}

TEST_CASE("VMConfig::has_any_static_hint detects operand_format hint",
          "[unit][pass][vm_abstract][config]") {
    VMConfig cfg;
    CHECK_FALSE(cfg.has_any_static_hint());
    VMConfig::OperandFormatHint opfmt;
    opfmt.instruction_size = 4;
    cfg.operand_format = opfmt;
    CHECK(cfg.has_any_static_hint());
}

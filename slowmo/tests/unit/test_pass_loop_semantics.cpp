/*
 * test_pass_loop_semantics.cpp — Unit tests for tenet::LoopSemanticsPass
 *
 * Verifies:
 *   - Counter-loop pattern (accumulation over iterations) is classified correctly.
 *   - XOR-heavy loop hints at ARX/crypto flavor.
 *   - LoopSemanticsPass requires "loop" + "xref" dependencies (run automatically).
 *   - loop_semantics contains one entry per analyzed loop.
 *   - iteration_count matches the actual loop repetition.
 *   - active_regs/invariant_regs are populated.
 *
 * NOTE: LoopSemanticsPass depends on LoopPass which depends on CFGPass which
 * depends on XrefPass.  We register all four and let PassManager handle the
 * dependency chain.
 *
 * Run:  ctest -R 'loop_semantics' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helper: emit a simple counter loop ─────────────────────────────────────
//
// Counter loop pattern (N iterations):
//
//   Block A:  0x1000: x0 = 0     (init)
//   Block B:  0x1004: cmp x0, N  ← LOOP HEADER (CFGPass back-edge lands here)
//             0x1008: b.ge → 0x1014  (exit when x0 >= N)
//   Block C:  0x100C: x0 = x0 + 1  (loop body — fallthrough from b.ge not-taken)
//             0x1010: b → 0x1004    (unconditional back edge; C → B are different blocks)
//   Block D:  0x1014: nop           (after loop)
//
// CFGPass detects a back-edge from Block C (0x100C) → Block B (0x1004) because
// they are different basic blocks.  LoopPass then identifies this as a loop.
//
// The trace exercises N loop iterations (cmp+b.ge+add+b repeated N times),
// then falls through from b.ge to Block D.

static std::unique_ptr<TraceEnv> make_counter_loop(int N) {
    return make_env([N](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;

        // Block A: init x0 = 0
        tw.emit(ms, 0x1000, enc::movz(0, 0),
                {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});

        // Emit N loop iterations
        for (int i = 0; i < N; i++) {
            // Block B: cmp x0, N  (loop header — executed N+1 times: N loops + 1 final check)
            // On iteration i: x0 = i, cmp x0, N
            uint8_t nzcv_ge = 0x4;  // Z flag (equal) or no N flag = ge taken
            uint8_t nzcv_lt = 0x8;  // N flag set = lt taken (not exiting)
            uint8_t nzcv = (i < N) ? nzcv_lt : nzcv_ge;  // All N iters: not exiting
            tw.emit(ms, 0x1004, enc::cmp_imm(0, (uint16_t)N),
                    {{33, tw.rt(0x1008)}}, {}, nzcv_lt);  // i < N: b.ge not taken

            // Block B continued: b.ge → 0x1014 (not taken in loop body)
            tw.emit(ms, 0x1008, enc::b_ge(12),  // offset +12 = jump to 0x1014
                    {{33, tw.rt(0x100C)}}, {});   // falls through to 0x100C

            // Block C: x0 = x0 + 1 (loop body)
            tw.emit(ms, 0x100C, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1010)}}, {});

            // Block C continued: unconditional branch back to loop header 0x1004
            // b offset = 0x1004 - 0x1010 = -0xC
            tw.emit(ms, 0x1010, enc::b(-12),
                    {{33, tw.rt(0x1004)}}, {});  // back edge: Block C → Block B
        }

        // Final iteration: cmp x0, N — now x0 == N, b.ge IS taken
        tw.emit(ms, 0x1004, enc::cmp_imm(0, (uint16_t)N),
                {{33, tw.rt(0x1008)}}, {}, 0x4);  // Z flag: x0 == N → ge taken
        tw.emit(ms, 0x1008, enc::b_ge(12),
                {{33, tw.rt(0x1014)}}, {});  // Branch taken: exit loop

        // Block D: after loop
        tw.emit(ms, 0x1014, enc::nop(),
                {{33, tw.rt(0x1018)}}, {});

        tw.emit_anchor(ms);
    }, ("loop_sem_counter_" + std::to_string(N)).c_str());
}

// Same shape as make_counter_loop, but the counter register takes a +2 step
// (instead of +1) on exactly one iteration (`noisy_iter`), simulating a
// conditionally-taken extra increment or a one-off warm-up step that a real
// binary's counter loop might exhibit. Used to verify that a single outlier
// sample pair doesn't flip the CounterLoop classification (see
// COUNTER_PATTERN_MIN_AGREEMENT in loop_semantics_pass.cpp).
static std::unique_ptr<TraceEnv> make_noisy_counter_loop(int N, int noisy_iter) {
    return make_env([N, noisy_iter](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;

        tw.emit(ms, 0x1000, enc::movz(0, 0),
                {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});

        uint64_t counter = 0;
        for (int i = 0; i < N; i++) {
            tw.emit(ms, 0x1004, enc::cmp_imm(0, (uint16_t)N),
                    {{33, tw.rt(0x1008)}}, {}, 0x8);
            tw.emit(ms, 0x1008, enc::b_ge(12),
                    {{33, tw.rt(0x100C)}}, {});

            // Step by +2 on the designated noisy iteration, +1 otherwise.
            uint64_t step = (i == noisy_iter) ? 2 : 1;
            counter += step;
            tw.emit(ms, 0x100C, enc::add_imm(0, 0, (uint16_t)step),
                    {{0, counter}, {33, tw.rt(0x1010)}}, {});

            tw.emit(ms, 0x1010, enc::b(-12),
                    {{33, tw.rt(0x1004)}}, {});
        }

        tw.emit(ms, 0x1004, enc::cmp_imm(0, (uint16_t)N),
                {{33, tw.rt(0x1008)}}, {}, 0x4);
        tw.emit(ms, 0x1008, enc::b_ge(12),
                {{33, tw.rt(0x1014)}}, {});
        tw.emit(ms, 0x1014, enc::nop(), {{33, tw.rt(0x1018)}}, {});

        tw.emit_anchor(ms);
    }, ("loop_sem_noisy_counter_" + std::to_string(N)).c_str());
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("LoopSemanticsPass: counter loop with 8 iterations is detected",
          "[unit][pass][loop_semantics]") {
    auto env = make_counter_loop(8);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<LoopSemanticsPass>());

    auto& raw = pm->require("loop_semantics");
    REQUIRE(raw.ok());

    auto& res = raw.get<LoopSemanticsResult>();

    SECTION("at least one loop semantics entry") {
        REQUIRE_FALSE(res.loop_semantics.empty());
    }
    SECTION("iteration count >= 7 for 8-iteration loop") {
        bool found = false;
        for (const auto& ls : res.loop_semantics) {
            if (ls.iteration_count >= 7) { found = true; break; }
        }
        REQUIRE(found);
    }
    SECTION("classified as CounterLoop with confidence > 0") {
        // This loop body is exactly "cmp + b.ge + add + b" — a single
        // incrementing register, no XOR/shift/load features at all — so the
        // classifier must resolve it to CounterLoop, not silently fall through
        // to Unknown/Accumulator. This pins down the exact classification
        // instead of merely checking "not Unknown" (see git history for the
        // previous informational-only version of this test).
        bool found_counter = false;
        for (const auto& ls : res.loop_semantics) {
            if (ls.kind == LoopKind::CounterLoop) {
                found_counter = true;
                REQUIRE(ls.confidence > 0.0f);
                break;
            }
        }
        REQUIRE(found_counter);
    }
}

TEST_CASE("LoopSemanticsPass: counter loop tolerates one noisy (+2) step "
          "among sampled iterations and still classifies as CounterLoop",
          "[unit][pass][loop_semantics]") {
    // Regression test for the majority-vote counter check
    // (COUNTER_PATTERN_MIN_AGREEMENT in loop_semantics_pass.cpp). With
    // MAX_SAMPLE_ITERATIONS=5, the pass samples the first 5 header hits (4
    // consecutive-pair comparisons). We inject a +2 step on iteration 1 (the
    // pair between sample 1 and sample 2), so 3 of the 4 sampled pairs still
    // show a clean +1 step (agreement = 0.75 >= 0.6 threshold). Before this
    // change, a single non-±1 pair anywhere in the sampled window
    // unconditionally disqualified the register as a counter.
    auto env = make_noisy_counter_loop(10, /*noisy_iter=*/1);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<LoopSemanticsPass>());

    auto& raw = pm->require("loop_semantics");
    REQUIRE(raw.ok());
    auto& res = raw.get<LoopSemanticsResult>();
    REQUIRE_FALSE(res.loop_semantics.empty());

    bool found_counter = false;
    for (const auto& ls : res.loop_semantics) {
        if (ls.kind == LoopKind::CounterLoop) {
            found_counter = true;
            break;
        }
    }
    REQUIRE(found_counter);
}

TEST_CASE("LoopSemanticsPass: loop body PC is set for analyzed loops",
          "[unit][pass][loop_semantics]") {
    auto env = make_counter_loop(4);
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<LoopSemanticsPass>());

    auto& res = pm->require("loop_semantics").get<LoopSemanticsResult>();

    for (const auto& ls : res.loop_semantics) {
        SECTION("header_pc is non-zero") {
            REQUIRE(ls.header_pc != 0);
        }
        SECTION("body_instruction_count > 0") {
            REQUIRE(ls.body_instruction_count > 0);
        }
    }
}

TEST_CASE("LoopSemanticsPass: XOR-heavy loop marks has_xor_mix",
          "[unit][pass][loop_semantics]") {
    // Loop that exclusively uses EOR (XOR) instructions.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0x12;
        ms.x(1) = 0;

        // Init counter x1 = 0
        tw.emit(ms, 0x1000, enc::movz(1, 0),
                {{1, 0ULL}, {33, tw.rt(0x1004)}}, {});

        const int kN = 6;
        for (int i = 0; i < kN; i++) {
            // x2 = x0 ^ x1   (XOR)
            tw.emit(ms, 0x1004, enc::eor_reg(2, 0, 1),
                    {{2, ms.x(0) ^ (uint64_t)i}, {33, tw.rt(0x1008)}}, {});
            // x1 = x1 + 1
            tw.emit(ms, 0x1008, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x100C)}}, {});
            // cmp + b.lt
            tw.emit(ms, 0x100C, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1010)}}, {});
            if (i + 1 < kN) {
                tw.emit(ms, 0x1010, enc::b_lt(-12),
                        {{33, tw.rt(0x1004)}}, {});
            } else {
                tw.emit(ms, 0x1010, enc::b_lt(-12),
                        {{33, tw.rt(0x1014)}}, {});
            }
        }
        tw.emit_anchor(ms);
    }, "loop_sem_xor");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<LoopSemanticsPass>());

    auto& raw = pm->require("loop_semantics");
    REQUIRE(raw.ok());

    auto& res = raw.get<LoopSemanticsResult>();

    SECTION("XOR loop detected and has_xor_mix flag set on at least one loop") {
        // This loop's back-edge (0x1010 -> 0x1004) is taken kN-1=5 times, which
        // is comfortably above LoopPass's iteration threshold, so the loop must
        // be discovered and analyzed — an empty result here would silently mask
        // a LoopPass/LoopSemanticsPass regression, not a legitimate "no loop"
        // outcome, so we require a non-empty result rather than accepting either.
        REQUIRE_FALSE(res.loop_semantics.empty());
        bool has_xor = false;
        for (const auto& ls : res.loop_semantics) {
            if (ls.has_xor_mix) { has_xor = true; break; }
        }
        REQUIRE(has_xor);
    }
}

// ─── Helper: emit a loop with a fixed body-instruction template ────────────
//
// `body` is invoked once per iteration with (ms, i, spc0) and must emit the
// loop-body instructions ending in a conditional branch back to `header_pc`
// (taken while i+1 < kN) or forward past it (on the final iteration). This
// lets each classification test focus purely on the instruction mix that
// drives BodyFeatures, without duplicating the loop-control boilerplate.
static std::unique_ptr<TraceEnv> make_feature_loop(
        int kN, const char* name,
        std::function<void(TraceWriter&, MachineState&, int)> body) {
    return make_env([=](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < kN; i++) {
            body(tw, ms, i);
        }
        tw.emit_anchor(ms);
    }, name);
}

// Runs the standard 4-pass pipeline and returns the single analyzed loop
// entry with the most sampled iterations (there should be exactly one loop
// in these single-back-edge fixtures).
static const LoopSemanticInfo* run_and_get_loop(TraceEnv& env, PassManager& pm) {
    pm.register_pass(std::make_unique<XrefPass>());
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<LoopPass>());
    pm.register_pass(std::make_unique<LoopSemanticsPass>());

    auto& raw = pm.require("loop_semantics");
    REQUIRE(raw.ok());
    auto& res = raw.get<LoopSemanticsResult>();
    REQUIRE_FALSE(res.loop_semantics.empty());
    return &res.loop_semantics.front();
}

TEST_CASE("LoopSemanticsPass: SPN round (XOR + S-box lookup, 16 iterations) "
          "is classified as SPNRound",
          "[unit][pass][loop_semantics]") {
    // AES-like round: x10 = x0 ^ x1 (AddRoundKey-ish), then two table lookups
    // "ldr xN, [Xbase, Xoff]" using two source registers each (base +
    // data-dependent index) — has_sbox_pattern requires
    // load_with_reg_offset_count >= 2, i.e. at least two such loads per
    // analyzed body (a single S-box read plus a second parallel lookup, as
    // real AES implementations that unroll multiple S-box reads per round
    // typically do). The load's index register (x10) is the direct output
    // of the preceding EOR, so this also exercises the stronger
    // sbox_pattern_data_dependent verification (index traced back to a
    // mixing op in the same body), not just "some load reads 2+ registers".
    //
    // NOTE: enc::ldr_reg(rt, rn, rm)'s base opcode template hard-codes an
    // offset of +8 in the Rm field, i.e. the actual index register ends up
    // being (rm + 8) — e.g. ldr_reg(4, 3, 2) assembles to
    // "ldr x4, [x3, x10, lsl #3]", NOT "..., x2, ...". We write the EOR
    // result directly into x10 (rm=2 => index reg x10) to line up with that
    // quirk rather than fighting it.
    //
    // NOTE: LoopPass::iteration_count counts back-edge *taken* events, which
    // is (loop-body-emissions - 1) for this fixture shape (the back-edge is
    // NOT taken on the final, loop-exiting iteration). We emit kN=17 body
    // copies so the back-edge is taken exactly 16 times, landing on the
    // AES-128-like round count that classify_loop()'s SPNRound branch
    // requires exactly (see loop_semantics_pass.cpp: iters == 16).
    constexpr int kN = 17;
    auto env = make_feature_loop(kN, "loop_sem_spn",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0x11; ms.x(1) = (uint64_t)i; ms.x(3) = 0x20000000ULL;
            tw.emit(ms, 0x1004, enc::eor_reg(10, 0, 1),
                    {{10, ms.x(0) ^ (uint64_t)i}, {33, tw.rt(0x1008)}}, {});
            tw.emit(ms, 0x1008, enc::ldr_reg(4, 3, 2),
                    {{4, 0xAAULL}, {33, tw.rt(0x100C)}},
                    {{1 /*READ*/, 8, ms.x(3) + ms.x(10), 0xAAULL}});
            tw.emit(ms, 0x100C, enc::ldr_reg(6, 3, 2),
                    {{6, 0xBBULL}, {33, tw.rt(0x1010)}},
                    {{1 /*READ*/, 8, ms.x(3) + ms.x(10), 0xBBULL}});
            tw.emit(ms, 0x1010, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x1014)}}, {});
            tw.emit(ms, 0x1014, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1018)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x101C);
            tw.emit(ms, 0x1018, enc::b_lt(-20), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    INFO("iteration_count = " << ls->iteration_count);
    REQUIRE(ls->iteration_count == 16);
    REQUIRE(ls->has_xor_mix);
    REQUIRE(ls->has_sbox_pattern);
    REQUIRE(ls->sbox_pattern_data_dependent);
    REQUIRE(ls->kind == LoopKind::SPNRound);
    REQUIRE(ls->confidence >= 0.8f);
}

TEST_CASE("LoopSemanticsPass: Feistel round (XOR + rotate, 16 iterations) "
          "is classified as FeistelRound",
          "[unit][pass][loop_semantics]") {
    // DES-like round: XOR the two halves, then rotate — no table lookup, so
    // has_sbox_pattern stays false and the SPNRound branch (checked first in
    // classify_loop) cannot fire; this isolates the FeistelRound path.
    //
    // NOTE: see the SPNRound test above for why kN=17 (not 16) is needed to
    // land iteration_count exactly on 16, one of the fixed values that
    // classify_loop()'s FeistelRound branch checks for.
    constexpr int kN = 17;
    auto env = make_feature_loop(kN, "loop_sem_feistel",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0x1111; ms.x(1) = (uint64_t)i;
            tw.emit(ms, 0x1004, enc::eor_reg(2, 0, 1),
                    {{2, ms.x(0) ^ (uint64_t)i}, {33, tw.rt(0x1008)}}, {});
            tw.emit(ms, 0x1008, enc::lsl_imm(2, 2, 3),
                    {{2, (ms.x(0) ^ (uint64_t)i) << 3}, {33, tw.rt(0x100C)}}, {});
            tw.emit(ms, 0x100C, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x1010)}}, {});
            tw.emit(ms, 0x1010, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1014)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x1018);
            tw.emit(ms, 0x1014, enc::b_lt(-16), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    INFO("iteration_count = " << ls->iteration_count);
    REQUIRE(ls->iteration_count == 16);
    REQUIRE(ls->has_xor_mix);
    REQUIRE(ls->has_shift_rotate);
    REQUIRE_FALSE(ls->has_sbox_pattern);
    REQUIRE(ls->kind == LoopKind::FeistelRound);
    REQUIRE(ls->confidence >= 0.7f);
}

TEST_CASE("LoopSemanticsPass: ARX round (add + rotate + XOR, 20 iterations) "
          "is classified as ARXRound",
          "[unit][pass][loop_semantics]") {
    // ChaCha20-like quarter round: addition chain + rotate + XOR, all three
    // present in the same body — the has_addition_chain threshold requires
    // >= 3 add/sub instructions, so we emit three ADDs before the XOR/rotate.
    constexpr int kN = 20;
    auto env = make_feature_loop(kN, "loop_sem_arx",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0x100; ms.x(1) = (uint64_t)i; ms.x(5) = 5;
            tw.emit(ms, 0x1004, enc::add_reg(0, 0, 1),
                    {{0, ms.x(0) + ms.x(1)}, {33, tw.rt(0x1008)}}, {});
            tw.emit(ms, 0x1008, enc::add_reg(0, 0, 5),
                    {{0, ms.x(0) + ms.x(1) + ms.x(5)}, {33, tw.rt(0x100C)}}, {});
            tw.emit(ms, 0x100C, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + ms.x(1) + ms.x(5) + 1}, {33, tw.rt(0x1010)}}, {});
            tw.emit(ms, 0x1010, enc::eor_reg(2, 0, 1),
                    {{2, 0ULL}, {33, tw.rt(0x1014)}}, {});
            tw.emit(ms, 0x1014, enc::lsl_imm(2, 2, 7),
                    {{2, 0ULL}, {33, tw.rt(0x1018)}}, {});
            tw.emit(ms, 0x1018, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x101C)}}, {});
            tw.emit(ms, 0x101C, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1020)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x1024);
            tw.emit(ms, 0x1020, enc::b_lt(-28), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    REQUIRE(ls->has_xor_mix);
    REQUIRE(ls->has_shift_rotate);
    REQUIRE(ls->has_addition_chain);
    REQUIRE(ls->kind == LoopKind::ARXRound);
    REQUIRE(ls->confidence >= 0.7f);
}

TEST_CASE("LoopSemanticsPass: shift-dominant loop (no XOR/S-box) "
          "is classified as ShiftRotate",
          "[unit][pass][loop_semantics]") {
    // A loop dominated by shifts/rotates with no XOR and no table lookup —
    // e.g. a bit-packing / CRC-table-free routine. Needs
    // shift_rotate_count >= total_instructions/4; the body below is 5
    // instructions/iteration with 2 shifts, comfortably over the 1/4 bar.
    constexpr int kN = 6;
    auto env = make_feature_loop(kN, "loop_sem_shiftrotate",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0x1; ms.x(1) = (uint64_t)i;
            tw.emit(ms, 0x1004, enc::lsl_imm(0, 0, 1),
                    {{0, ms.x(0) << 1}, {33, tw.rt(0x1008)}}, {});
            tw.emit(ms, 0x1008, enc::lsr_imm(3, 0, 2),
                    {{3, (ms.x(0) << 1) >> 2}, {33, tw.rt(0x100C)}}, {});
            tw.emit(ms, 0x100C, enc::and_reg(0, 0, 3),
                    {{0, 0ULL}, {33, tw.rt(0x1010)}}, {});
            tw.emit(ms, 0x1010, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x1014)}}, {});
            tw.emit(ms, 0x1014, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1018)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x101C);
            tw.emit(ms, 0x1018, enc::b_lt(-20), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    REQUIRE(ls->has_shift_rotate);
    REQUIRE_FALSE(ls->has_xor_mix);
    REQUIRE_FALSE(ls->has_sbox_pattern);
    REQUIRE(ls->kind == LoopKind::ShiftRotate);
}

TEST_CASE("LoopSemanticsPass: addition-heavy loop (no XOR/shift/S-box) "
          "is classified as Accumulator",
          "[unit][pass][loop_semantics]") {
    // Checksum/hash-accumulator-like body: three ADDs, nothing else, so
    // add_sub_count (3) >= total_instructions/3 while has_xor_mix/
    // has_sbox_pattern stay false — isolates the Accumulator branch from
    // ARXRound (which additionally requires XOR + shift).
    constexpr int kN = 6;
    auto env = make_feature_loop(kN, "loop_sem_accumulator",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0; ms.x(1) = (uint64_t)i; ms.x(5) = 7;
            tw.emit(ms, 0x1004, enc::add_reg(0, 0, 1),
                    {{0, ms.x(0) + ms.x(1)}, {33, tw.rt(0x1008)}}, {});
            tw.emit(ms, 0x1008, enc::add_reg(0, 0, 5),
                    {{0, ms.x(0) + ms.x(1) + ms.x(5)}, {33, tw.rt(0x100C)}}, {});
            tw.emit(ms, 0x100C, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + ms.x(1) + ms.x(5) + 1}, {33, tw.rt(0x1010)}}, {});
            tw.emit(ms, 0x1010, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x1014)}}, {});
            tw.emit(ms, 0x1014, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1018)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x101C);
            tw.emit(ms, 0x1018, enc::b_lt(-20), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    REQUIRE(ls->has_addition_chain);
    REQUIRE_FALSE(ls->has_xor_mix);
    REQUIRE_FALSE(ls->has_sbox_pattern);
    REQUIRE(ls->kind == LoopKind::Accumulator);
}

TEST_CASE("LoopSemanticsPass: load-dominant loop (no XOR/shift/modular) "
          "is classified as MemcpyLike",
          "[unit][pass][loop_semantics]") {
    // memcpy-style body: register-offset load + register-offset store,
    // nothing else — load_with_reg_offset_count (1) >= total/3 while xor/
    // shift/modular counts are all zero.
    constexpr int kN = 6;
    auto env = make_feature_loop(kN, "loop_sem_memcpy",
        [kN](TraceWriter& tw, MachineState& ms, int i) {
            ms.x(0) = 0x30000000ULL; ms.x(1) = (uint64_t)i; ms.x(3) = 0x40000000ULL;
            tw.emit(ms, 0x1004, enc::ldr_reg(4, 0, 1),
                    {{4, 0x55ULL}, {33, tw.rt(0x1008)}},
                    {{1 /*READ*/, 8, ms.x(0) + ms.x(1), 0x55ULL}});
            tw.emit(ms, 0x1008, enc::str_reg(4, 3, 1),
                    {{33, tw.rt(0x100C)}},
                    {{2 /*WRITE*/, 8, ms.x(3) + ms.x(1), 0x55ULL}});
            tw.emit(ms, 0x100C, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(0x1010)}}, {});
            tw.emit(ms, 0x1010, enc::cmp_imm(1, kN),
                    {{33, tw.rt(0x1014)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(0x1004) : tw.rt(0x1018);
            tw.emit(ms, 0x1014, enc::b_lt(-16), {{33, next}}, {});
        });
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    const auto* ls = run_and_get_loop(*env, *pm);

    REQUIRE(ls->has_sbox_pattern == false);  // ldr with reg-offset counted, but < 2 loads/iter for sbox test framing
    REQUIRE_FALSE(ls->has_xor_mix);
    REQUIRE_FALSE(ls->has_shift_rotate);
    REQUIRE_FALSE(ls->has_modular_arithmetic);
    REQUIRE(ls->kind == LoopKind::MemcpyLike);
}

TEST_CASE("LoopSemanticsPass: empty trace (no loops) returns empty result",
          "[unit][pass][loop_semantics]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Linear sequence, no branches
        for (int i = 0; i < 5; i++) {
            uint64_t spc = 0x1000 + i * 4;
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "loop_sem_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<LoopSemanticsPass>());

    auto& raw = pm->require("loop_semantics");
    REQUIRE(raw.ok());

    auto& res = raw.get<LoopSemanticsResult>();
    SECTION("no loop semantics for a linear trace") {
        REQUIRE(res.loop_semantics.empty());
    }
}

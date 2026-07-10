/*
 * test_core_register_file.cpp — Unit tests for tenet::RegisterFile
 *
 * Verifies: checkpoint-based state reconstruction, register diff replay,
 * state_before/state_after semantics, and edge cases (empty trace,
 * out-of-range, idempotent build, cursor factory).
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "common/types.h"
#include "infra/checkpoint_manager.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("RegisterFile reconstructs state from anchor", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.x(0) = 0x1111;
        ms.x(1) = 0x2222;
        ms.pc() = tw.rt(0x1000);
        // Emit explicit anchor with known state
        tw.emit_anchor(ms);
        // Then one instruction (no reg changes except PC)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
    }, "regfile_anchor");

    REQUIRE(env != nullptr);

    SECTION("state_before inst 0 matches anchor") {
        auto state = env->regfile->state_before(0);
        REQUIRE(state.gpr[0] == 0x1111);
        REQUIRE(state.gpr[1] == 0x2222);
        REQUIRE(state.sp() == 0x7F000000ULL);
    }
}

TEST_CASE("RegisterFile replays register diffs", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        // inst 0: x0 = 0xAAAA
        tw.emit(ms, 0x1000, enc::movz(0, 0xAAAA), {{0, 0xAAAAULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x1 = 0xBBBB
        tw.emit(ms, 0x1004, enc::movz(1, 0xBBBB), {{1, 0xBBBBULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x2 = x0 + x1
        tw.emit(ms, 0x1008, enc::add_reg(2, 0, 1), {{2, 0xAAAAULL + 0xBBBBULL}, {33, tw.rt(0x100C)}}, {});
    }, "regfile_diff");

    REQUIRE(env != nullptr);

    SECTION("state_before inst 0 has anchor values") {
        auto s = env->regfile->state_before(0);
        // TraceWriter::emit() applies diffs to ms *before* the auto-anchor
        // check (inst_count % anchor_interval == 0).  Since inst_count==0 and
        // anchor_interval==256, an auto-anchor fires that captures the
        // post-diff state (x0=0xAAAA).  nearest_anchor_before(0) returns this
        // auto-anchor (the last anchor keyed at inst_id 0), so state_before(0)
        // reflects x0=0xAAAA, not the pre-instruction value 0.
        REQUIRE(s.gpr[0] == 0xAAAAULL);  // auto-anchor captured post-diff x0
        REQUIRE(s.gpr[1] == 0);
    }

    SECTION("state_after inst 0 has new x0") {
        auto s = env->regfile->state_after(0);
        REQUIRE(s.gpr[0] == 0xAAAAULL);
        REQUIRE(s.gpr[1] == 0);  // x1 not yet set
    }

    SECTION("state_after inst 1 has both x0 and x1") {
        auto s = env->regfile->state_after(1);
        REQUIRE(s.gpr[0] == 0xAAAAULL);
        REQUIRE(s.gpr[1] == 0xBBBBULL);
    }

    SECTION("state_after inst 2 has computed x2") {
        auto s = env->regfile->state_after(2);
        REQUIRE(s.gpr[0] == 0xAAAAULL);
        REQUIRE(s.gpr[1] == 0xBBBBULL);
        REQUIRE(s.gpr[2] == 0xAAAAULL + 0xBBBBULL);
    }
}

TEST_CASE("RegisterFile handles NZCV flags", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        // subs x0, x0, #1 → sets Z flag (nzcv = 0x4)
        tw.emit(ms, 0x1000, enc::subs_imm(0, 0, 1), {{0, 0xFFFFFFFFFFFFFFFFULL}, {33, tw.rt(0x1004)}}, {}, 0x4);
    }, "regfile_nzcv");

    REQUIRE(env != nullptr);

    auto s = env->regfile->state_after(0);
    REQUIRE(s.nzcv() == 0x4);  // Z flag
}

TEST_CASE("RegisterFile PC tracking", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
    }, "regfile_pc");

    REQUIRE(env != nullptr);

    SECTION("state_before has previous PC") {
        auto s0 = env->regfile->state_before(0);
        REQUIRE(s0.pc() == rt_pc(0x1000));

        auto s1 = env->regfile->state_before(1);
        REQUIRE(s1.pc() == rt_pc(0x1004));
    }

    SECTION("state_after has next PC") {
        auto s0 = env->regfile->state_after(0);
        REQUIRE(s0.pc() == rt_pc(0x1004));

        auto s2 = env->regfile->state_after(2);
        REQUIRE(s2.pc() == rt_pc(0x100C));
    }
}

TEST_CASE("RegisterFile repeated state_before is consistent", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 1;  // anchor every instruction for fast rebuild
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "regfile_cache");

    REQUIRE(env != nullptr);

    // Two accesses to the same inst_id must return identical results.
    auto s1 = env->regfile->state_before(5);
    auto s2 = env->regfile->state_before(5);
    REQUIRE(s1.gpr[0] == s2.gpr[0]);

    // Both queries were served by the checkpoint array.
    auto stats = env->regfile->cache_stats();
    REQUIRE(stats.ckpt_queries >= 2);
}

// ─── Regression: Bug 2 — RegisterFile::rebuild never updates PC ────────
// The real qbditrace writer excludes PC (reg index 33) from reg_diffs — PC
// is captured only via ANCHOR snapshots and the INST header. Previously,
// RegisterFile::rebuild() never read the PC from INST headers during replay,
// so state_before(N).pc() returned the anchor's PC for all N, not the actual
// per-instruction PC.
//
// This test emits instructions WITHOUT PC in reg_diffs (simulating the real
// writer), uses a large anchor_interval so rebuild must walk multiple diffs,
// and verifies that PC is correct for each instruction.
TEST_CASE("RegisterFile reconstructs PC without PC in reg_diffs", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;  // large interval: rebuild must walk diffs
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);

        // Emit 5 instructions WITHOUT PC (index 33) in reg_diffs.
        // Only x0 is updated — PC must be reconstructed from the INST header.
        tw.emit(ms, 0x1000, enc::nop(), {{0, 0xAAAAULL}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{0, 0xBBBBULL}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{0, 0xCCCCULL}}, {});
        tw.emit(ms, 0x100C, enc::nop(), {{0, 0xDDDDULL}}, {});
        tw.emit(ms, 0x1010, enc::nop(), {{0, 0xEEEEULL}}, {});
        tw.emit_anchor(ms);
    }, "regfile_pc_no_diff");

    REQUIRE(env != nullptr);

    SECTION("state_before has correct PC for each instruction") {
        auto s0 = env->regfile->state_before(0);
        REQUIRE(s0.pc() == rt_pc(0x1000));

        auto s1 = env->regfile->state_before(1);
        REQUIRE(s1.pc() == rt_pc(0x1004));

        auto s2 = env->regfile->state_before(2);
        REQUIRE(s2.pc() == rt_pc(0x1008));

        auto s3 = env->regfile->state_before(3);
        REQUIRE(s3.pc() == rt_pc(0x100C));

        auto s4 = env->regfile->state_before(4);
        REQUIRE(s4.pc() == rt_pc(0x1010));
    }

    SECTION("state_after has instruction's own PC (PC not in diffs)") {
        // Since PC is excluded from reg_diffs, state_after(N).pc() equals
        // state_before(N).pc() — the instruction's own PC, not the next PC.
        auto s0 = env->regfile->state_after(0);
        REQUIRE(s0.pc() == rt_pc(0x1000));

        auto s4 = env->regfile->state_after(4);
        REQUIRE(s4.pc() == rt_pc(0x1010));
    }

    SECTION("non-PC registers are still correct") {
        auto s2 = env->regfile->state_before(2);
        REQUIRE(s2.gpr[0] == 0xBBBBULL);  // x0 after inst 1

        auto s4 = env->regfile->state_after(4);
        REQUIRE(s4.gpr[0] == 0xEEEEULL);
    }
}

// ─── Edge cases for the checkpoint-only model ──────────────────────────────

TEST_CASE("RegisterFile empty trace does not crash", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        // No instructions emitted.
    }, "regfile_empty");

    REQUIRE(env != nullptr);

    // build_checkpoints() is a no-op for an empty trace (total == 0 guard).
    // state_before(0) on empty checkpoints returns RegState{}.
    auto state = env->regfile->state_before(0);
    REQUIRE(state.gpr[0] == 0);
}

TEST_CASE("RegisterFile out-of-range returns last checkpoint state", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);
        // 10 instructions; x0 increments each.
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "regfile_oor");

    REQUIRE(env != nullptr);

    uint64_t queries_before = env->regfile->cache_stats().ckpt_queries;
    uint64_t fallbacks_before = env->regfile->cache_stats().ckpt_fallbacks;

    // An inst_id far beyond the trace + checkpoint stride triggers the
    // out-of-range branch: returns the last checkpoint state, no crash.
    auto state = env->regfile->state_before(1'000'000);

    REQUIRE(env->regfile->cache_stats().ckpt_queries == queries_before + 1);
    REQUIRE(env->regfile->cache_stats().ckpt_fallbacks == fallbacks_before + 1);
    // Returned state is a valid (non-crashing) RegState copy.
    (void)state;
}

TEST_CASE("RegisterFile ensure_checkpoints is idempotent", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "regfile_idempotent");

    REQUIRE(env != nullptr);

    // make_env already built checkpoints via RegisterFile::build_checkpoints();
    // a CheckpointManager wrapping it must observe that and treat
    // ensure_checkpoints() as a no-op (no rebuild, no counter reset).
    CheckpointManager cm(*env->regfile);
    cm.ensure_checkpoints();
    REQUIRE(cm.has_checkpoints());

    auto s1 = env->regfile->state_before(2);
    uint64_t queries_after_first = env->regfile->cache_stats().ckpt_queries;
    REQUIRE(queries_after_first >= 1);
    (void)s1;

    cm.ensure_checkpoints();  // no-op
    REQUIRE(cm.has_checkpoints());

    auto s2 = env->regfile->state_before(2);
    uint64_t queries_after_second = env->regfile->cache_stats().ckpt_queries;
    // Counter continued incrementing — the second ensure_checkpoints() did
    // not reset the array.
    REQUIRE(queries_after_second == queries_after_first + 1);
    REQUIRE(s1.gpr[0] == s2.gpr[0]);
}

TEST_CASE("RegisterFile create_cursor returns working cursor", "[unit][core][register_file]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x7F000000ULL;
        ms.pc() = tw.rt(0x1000);
        tw.emit_anchor(ms);
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "regfile_cursor");

    REQUIRE(env != nullptr);

    CheckpointManager cm(*env->regfile);
    RegisterFileCursor cursor = cm.create_cursor();

    // The cursor must reproduce the same state as state_before() for a
    // forward-only query.
    const RegState& cursor_state = cursor.advance_to(2);
    auto ref_state = env->regfile->state_before(2);
    REQUIRE(cursor_state.gpr[0] == ref_state.gpr[0]);
    REQUIRE(cursor_state.pc()  == ref_state.pc());
}

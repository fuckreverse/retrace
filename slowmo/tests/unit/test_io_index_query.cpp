/*
 * test_io_index_query.cpp — Unit tests for TraceIndex query methods.
 *
 * Tests offset_of_with_pc() and offset_of() for correctness:
 *   - Correct file offset for various inst_ids
 *   - Correct seed_pc for v5 traces
 *   - Edge cases (inst_id=0, out-of-range, with anchors)
 *   - Mixed record types (INST, ANCHOR, CODE interspersed)
 *   - Index build output correctness (inst_count, anchors, code_bytes)
 *
 * These tests guard the optimization of the linear-scan hot path in
 * offset_of_with_pc() (P1 item #5) and the Phase 0+1 build merge (#6).
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "common/types.h"

using namespace tenet;
using namespace tenet::test;

// ─── offset_of_with_pc: basic correctness (v4) ──────────────────────────────

TEST_CASE("TraceIndex offset_of returns correct offset for v4 trace",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 5 instructions at sequential PCs
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_v4_basic");

    REQUIRE(env != nullptr);

    SECTION("offset_of(0) is non-zero (past header)") {
        uint64_t off0 = env->index->offset_of(0, *env->reader);
        REQUIRE(off0 > sizeof(qbditrace::qbditrace_file_header_t));
    }

    SECTION("offset_of returns increasing offsets") {
        uint64_t off0 = env->index->offset_of(0, *env->reader);
        uint64_t off1 = env->index->offset_of(1, *env->reader);
        uint64_t off2 = env->index->offset_of(2, *env->reader);
        REQUIRE(off0 < off1);
        REQUIRE(off1 < off2);
    }

    SECTION("offset_of returns offset of an INST record") {
        uint64_t off = env->index->offset_of(2, *env->reader);
        auto rec = env->reader->record_at(off);
        REQUIRE(rec.kind == RecordKind::Inst);
    }
}

TEST_CASE("TraceIndex offset_of_with_pc returns correct seed_pc for v5",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 5 sequential instructions
        for (int i = 0; i < 5; i++) {
            tw.emit_v5(ms, 0x1000 + i * 4, enc::nop(),
                       {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_v5_seed_pc");

    REQUIRE(env != nullptr);

    SECTION("seed_pc matches expected absolute PC for each inst") {
        for (int i = 0; i < 5; i++) {
            auto result = env->index->offset_of_with_pc(i, *env->reader);
            REQUIRE(result.offset > sizeof(qbditrace::qbditrace_file_header_t));
            REQUIRE(result.seed_pc == rt_pc(0x1000 + i * 4));
        }
    }

    SECTION("record_at with seed_pc gives correct PC") {
        for (int i = 0; i < 5; i++) {
            auto result = env->index->offset_of_with_pc(i, *env->reader);
            auto rec = env->reader->record_at(result.offset, result.seed_pc);
            REQUIRE(rec.kind == RecordKind::Inst);
            auto inst = rec.as_inst();
            REQUIRE(inst.pc == rt_pc(0x1000 + i * 4));
        }
    }
}

// ─── offset_of_with_pc: edge cases ──────────────────────────────────────────

TEST_CASE("TraceIndex offset_of edge cases",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_edge");

    REQUIRE(env != nullptr);

    SECTION("inst_id 0 returns valid offset") {
        auto result = env->index->offset_of_with_pc(0, *env->reader);
        REQUIRE(result.offset > 0);
    }

    SECTION("last valid inst_id returns valid offset") {
        auto result = env->index->offset_of_with_pc(9, *env->reader);
        REQUIRE(result.offset > 0);
        auto rec = env->reader->record_at(result.offset);
        REQUIRE(rec.kind == RecordKind::Inst);
    }

    SECTION("out-of-range inst_id does not crash") {
        auto result = env->index->offset_of_with_pc(99999, *env->reader);
        // Should not crash; offset may be past file end
        (void)result;
    }
}

// ─── offset_of_with_pc: with anchors interspersed ───────────────────────────

TEST_CASE("TraceIndex offset_of works with frequent anchors",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 1;  // anchor every instruction
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_frequent_anchors");

    REQUIRE(env != nullptr);

    SECTION("all inst_ids resolve to INST records") {
        for (int i = 0; i < 5; i++) {
            uint64_t off = env->index->offset_of(i, *env->reader);
            auto rec = env->reader->record_at(off);
            REQUIRE(rec.kind == RecordKind::Inst);
            auto inst = rec.as_inst();
            REQUIRE(inst.pc == rt_pc(0x1000 + i * 4));
        }
    }
}

// ─── offset_of_with_pc: repeated queries are consistent ─────────────────────

TEST_CASE("TraceIndex offset_of repeated queries are consistent",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 20; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_repeat");

    REQUIRE(env != nullptr);

    // Query the same inst_id multiple times — must get identical results.
    auto r1 = env->index->offset_of_with_pc(10, *env->reader);
    auto r2 = env->index->offset_of_with_pc(10, *env->reader);
    REQUIRE(r1.offset == r2.offset);
    REQUIRE(r1.seed_pc == r2.seed_pc);
}

// ─── offset_of_with_pc: v5 with non-sequential PCs ──────────────────────────

TEST_CASE("TraceIndex offset_of v5 with non-sequential PCs",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Non-sequential PCs (simulating branches)
        uint64_t pcs[] = {0x1000, 0x2000, 0x1050, 0x3000, 0x1060};
        for (int i = 0; i < 5; i++) {
            tw.emit_v5(ms, pcs[i], enc::nop(),
                       {{33, tw.rt(pcs[i] + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_v5_branch");

    REQUIRE(env != nullptr);

    SECTION("seed_pc matches each non-sequential PC") {
        uint64_t expected_pcs[] = {rt_pc(0x1000), rt_pc(0x2000), rt_pc(0x1050), rt_pc(0x3000), rt_pc(0x1060)};
        for (int i = 0; i < 5; i++) {
            auto result = env->index->offset_of_with_pc(i, *env->reader);
            REQUIRE(result.seed_pc == expected_pcs[i]);
        }
    }
}

// ─── Index build output correctness ─────────────────────────────────────────

TEST_CASE("TraceIndex build produces correct inst_count",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 42; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_build_count");

    REQUIRE(env != nullptr);
    REQUIRE(env->index->inst_count() == 42);
}

TEST_CASE("TraceIndex build produces correct anchor table",
          "[unit][io][index_query]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 300 instructions → at least 2 auto-anchors (inst 0 and inst 256)
        for (int i = 0; i < 300; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_build_anchors");

    REQUIRE(env != nullptr);

    SECTION("anchor table is non-empty") {
        REQUIRE(env->index->anchor_table_size() > 0);
    }

    SECTION("nearest_anchor_before returns valid info") {
        auto info = env->index->nearest_anchor_before(100);
        REQUIRE(info.file_offset > 0);
    }
}

TEST_CASE("TraceIndex offset_of_with_pc: large trace with many instructions",
          "[unit][io][index_query]") {
    // Test with enough instructions to span multiple sparse intervals
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 600; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "idx_large");

    REQUIRE(env != nullptr);
    REQUIRE(env->index->inst_count() == 600);

    SECTION("spot-check offsets at various inst_ids") {
        // Check inst_ids at sparse interval boundaries and in between
        for (uint64_t id : {0, 1, 127, 128, 255, 256, 257, 511, 512, 599}) {
            auto result = env->index->offset_of_with_pc(id, *env->reader);
            REQUIRE(result.offset > 0);
            auto rec = env->reader->record_at(result.offset);
            REQUIRE(rec.kind == RecordKind::Inst);
            auto inst = rec.as_inst();
            REQUIRE(inst.pc == rt_pc(0x1000 + id * 4));
        }
    }
}

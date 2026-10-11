/*
 * test_pass_xref.cpp — Unit tests for tenet::XrefPass
 *
 * Verifies: PC→inst_id indexing, execution counts, unique PC tracking,
 * hottest() ranking, and has_pc queries.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("XrefPass indexes unique PCs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 3 unique PCs, each executed once
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "xref_unique");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());

    auto& result_raw = pm->require("xref");
    REQUIRE(result_raw.ok());
    auto& xr = result_raw.get<XrefResult>();

    SECTION("unique_pc_count") {
        REQUIRE(xr.unique_pc_count == 3);
    }

    SECTION("total_indexed == inst_count") {
        REQUIRE(xr.total_indexed == 3);
    }

    SECTION("each PC executed once") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x1004)) == 1);
        REQUIRE(xr.execution_count(rt_pc(0x1008)) == 1);
    }

    SECTION("has_pc") {
        REQUIRE(xr.has_pc(rt_pc(0x1000)));
        REQUIRE_FALSE(xr.has_pc(rt_pc(0x9999)));
    }
}

TEST_CASE("XrefPass tracks repeated PC execution", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // PC 0x1000 executed 5 times, PC 0x1004 executed 3 times
        for (int i = 0; i < 5; i++)
            tw.emit(ms, 0x1000, enc::add_imm(0, 0, 1), {{0, (uint64_t)(i+1)}, {33, tw.rt(0x1004)}}, {});
        for (int i = 0; i < 3; i++)
            tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, (uint64_t)(5+i)}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "xref_repeat");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("execution counts") {
        REQUIRE(xr.execution_count(rt_pc(0x1000)) == 5);
        REQUIRE(xr.execution_count(rt_pc(0x1004)) == 3);
    }

    SECTION("total_indexed") {
        REQUIRE(xr.total_indexed == 8);
    }

    SECTION("unique PCs") {
        REQUIRE(xr.unique_pc_count == 2);
    }

    SECTION("hottest PC is 0x1000") {
        auto top = xr.hottest(1);
        REQUIRE(top.size() == 1);
        REQUIRE(top[0].first == rt_pc(0x1000));
        REQUIRE(top[0].second == 5);
    }

    SECTION("hottest(2) returns both in order") {
        auto top = xr.hottest(2);
        REQUIRE(top.size() == 2);
        REQUIRE(top[0].second >= top[1].second);  // sorted descending
    }
}

TEST_CASE("XrefPass inst_ids_at returns correct IDs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0 at PC 0x1000
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // inst 1 at PC 0x1004
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1000)}}, {});
        // inst 2 at PC 0x1000 (again)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "xref_instids");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    auto ids = xr.inst_ids_at(rt_pc(0x1000));
    REQUIRE(ids.size() == 2);
    REQUIRE(ids[0] == 0);
    REQUIRE(ids[1] == 2);

    auto ids2 = xr.inst_ids_at(rt_pc(0x1004));
    REQUIRE(ids2.size() == 1);
    REQUIRE(ids2[0] == 1);
}

TEST_CASE("XrefPass empty trace", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_anchor(ms);
        // No instructions
    }, "xref_empty");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    REQUIRE(xr.unique_pc_count == 0);
    REQUIRE(xr.total_indexed == 0);
}

// ─── Regression: Bug 3 — raw_record_size missing CapiCall (kind=7) ───────
// When a CapiCall record appears between INST records, scan_shard must skip
// the entire CapiCall record (88-byte header + string captures). Previously
// raw_record_size lacked a `case 7`, returning 1 byte and desynchronising
// the scanner — all INSTs after the CapiCall were mis-indexed or lost.
TEST_CASE("XrefPass handles CapiCall records between INSTs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0 at PC 0x1000
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // inst 1 at PC 0x1004
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});

        // Interleave a CapiCall record (non-INST, kind=7)
        tw.emit_capicall(/*api_id=*/1, /*pc=*/tw.rt(0x1004),
                         /*target=*/0xDEADBEEF, {0xAAAA, 0xBBBB},
                         /*strs=*/{{0, 0, "hello"}});

        // inst 2 at PC 0x1008 — this is the one that was lost before the fix
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        // inst 3 at PC 0x100C
        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "xref_capicall");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("all 4 instructions indexed") {
        REQUIRE(xr.total_indexed == 4);
    }

    SECTION("all 4 unique PCs present") {
        REQUIRE(xr.unique_pc_count == 4);
        REQUIRE(xr.has_pc(rt_pc(0x1000)));
        REQUIRE(xr.has_pc(rt_pc(0x1004)));
        REQUIRE(xr.has_pc(rt_pc(0x1008)));
        REQUIRE(xr.has_pc(rt_pc(0x100C)));
    }

    SECTION("inst_ids_at returns correct IDs after CapiCall") {
        // inst 2 (at PC 0x1008) must be indexed as inst_id 2
        auto ids = xr.inst_ids_at(rt_pc(0x1008));
        REQUIRE(ids.size() == 1);
        REQUIRE(ids[0] == 2);

        // inst 3 (at PC 0x100C) must be indexed as inst_id 3
        auto ids3 = xr.inst_ids_at(rt_pc(0x100C));
        REQUIRE(ids3.size() == 1);
        REQUIRE(ids3[0] == 3);
    }
}

// ─── Regression: Bug 1 — v7+v5 n_fprdiff read at wrong offset ──────────
// In v7+v5 format (HF_HAS_FPR + HF_PC_DELTA), the INST head is 8 bytes:
//   kind(1) nzcv(1) n_regdiff(1) n_mem(1) pc_delta(2) n_fprdiff(1) reserved(1)
// n_fprdiff is at byte offset 6, but raw_record_size and scan_shard
// fprdiff_offset both read it from offset 5, causing wrong record sizes
// and scan desynchronisation whenever FPR diffs are present.
TEST_CASE("XrefPass handles v7+v5 format with FPR diffs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v7_v5();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        ms.pc() = tw.rt(0x1000);

        // inst 0: one GPR diff + one FPR diff
        tw.emit_v7_v5(ms, 0x1000, enc::nop(),
                      {{33, tw.rt(0x1004)}},  // GPR diff (PC)
                      {},                       // no mem acc
                      {{0, 0x4242, 0}});       // FPR diff: v0 = 0x4242
        // inst 1: no FPR diff
        tw.emit_v7_v5(ms, 0x1004, enc::nop(),
                      {{33, tw.rt(0x1008)}}, {}, {});
        // inst 2: two FPR diffs to stress n_fprdiff parsing
        tw.emit_v7_v5(ms, 0x1008, enc::nop(),
                      {{33, tw.rt(0x100C)}}, {},
                      {{1, 0x1111, 0}, {2, 0x2222, 0}});
        tw.emit_anchor_v7(ms);
    }, "xref_v7v5_fprdiff");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    SECTION("all 3 instructions indexed") {
        REQUIRE(xr.total_indexed == 3);
    }

    SECTION("all 3 unique PCs present") {
        REQUIRE(xr.unique_pc_count == 3);
        REQUIRE(xr.has_pc(rt_pc(0x1000)));
        REQUIRE(xr.has_pc(rt_pc(0x1004)));
        REQUIRE(xr.has_pc(rt_pc(0x1008)));
    }

    SECTION("inst_ids_at returns correct IDs") {
        REQUIRE(xr.inst_ids_at(rt_pc(0x1000))[0] == 0);
        REQUIRE(xr.inst_ids_at(rt_pc(0x1004))[0] == 1);
        REQUIRE(xr.inst_ids_at(rt_pc(0x1008))[0] == 2);
    }
}

// ─── v7 (non-v5) format with FPR diffs — ensures absolute-PC path works ─
TEST_CASE("XrefPass handles v7 (non-v5) format with FPR diffs", "[unit][pass][xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v7();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        ms.pc() = tw.rt(0x1000);

        tw.emit_v7(ms, 0x1000, enc::nop(),
                   {{33, tw.rt(0x1004)}}, {},
                   {{0, 0x4242, 0}});
        tw.emit_v7(ms, 0x1004, enc::nop(),
                   {{33, tw.rt(0x1008)}}, {}, {});
        tw.emit_v7(ms, 0x1008, enc::nop(),
                   {{33, tw.rt(0x100C)}}, {},
                   {{1, 0x1111, 0}, {2, 0x2222, 0}});
        tw.emit_anchor_v7(ms);
    }, "xref_v7_fprdiff");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    auto& xr = pm->require("xref").get<XrefResult>();

    REQUIRE(xr.total_indexed == 3);
    REQUIRE(xr.has_pc(rt_pc(0x1000)));
    REQUIRE(xr.has_pc(rt_pc(0x1004)));
    REQUIRE(xr.has_pc(rt_pc(0x1008)));
}

TEST_CASE("PassManager releases plain-reference results while preserving shared ownership",
          "[unit][pass][xref][lifetime]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "xref_result_lifetime");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    const auto& result = pm->require("xref").get<XrefResult>();
    REQUIRE(result.inst_ids_at(rt_pc(0x1000)).size() == 1);

    auto owned = pm->require_shared("xref");
    std::weak_ptr<const PassResult> weak = owned;
    pm.reset();
    REQUIRE_FALSE(weak.expired());
    owned.reset();
    REQUIRE(weak.expired());
}

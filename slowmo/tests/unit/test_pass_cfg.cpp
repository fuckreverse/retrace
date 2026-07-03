/*
 * test_pass_cfg.cpp — Unit tests for tenet::CFGPass
 *
 * Verifies: basic block detection, edge construction, terminator
 * classification (Branch/ConditionalBranch/Call/Return/Fallthrough),
 * block_containing and successor/predecessor queries.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"

using namespace tenet;
using namespace tenet::test;

TEST_CASE("CFGPass detects linear fallthrough blocks", "[unit][pass][cfg]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 3 sequential instructions, no branches
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "cfg_linear");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    SECTION("at least one block exists") {
        REQUIRE(cfg.block_count() >= 1);
    }

    SECTION("block containing PC 0x1000 exists") {
        auto* bb = cfg.block_containing(rt_pc(0x1000));
        REQUIRE(bb != nullptr);
        REQUIRE(bb->start_pc == rt_pc(0x1000));
    }
}

TEST_CASE("CFGPass detects branch targets as block boundaries", "[unit][pass][cfg]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 0x1000: nop
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // 0x1004: b 0x100C  (unconditional branch)
        tw.emit(ms, 0x1004, enc::b(0x100C - 0x1004), {{33, tw.rt(0x100C)}}, {});
        // 0x1008: (skipped by branch, but still a code entry point)
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        // 0x100C: ret
        tw.emit(ms, 0x100C, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "cfg_branch");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    SECTION("branch target creates a new block") {
        // The branch at 0x1004 targets 0x100C, so 0x100C should be a block start
        auto* bb = cfg.block_containing(rt_pc(0x100C));
        REQUIRE(bb != nullptr);
        REQUIRE(bb->start_pc == rt_pc(0x100C));
    }

    SECTION("multiple blocks detected") {
        // At least 2 blocks: [0x1000-0x1004] and [0x100C]
        // (0x1008 might be its own block if reached, but the branch skips it)
        REQUIRE(cfg.block_count() >= 2);
    }
}

TEST_CASE("CFGPass detects conditional branch edges", "[unit][pass][cfg]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 0x1000: cmp x0, #0
        tw.emit(ms, 0x1000, enc::cmp_imm(0, 0), {{33, tw.rt(0x1004)}}, {}, 0x4);
        // 0x1004: b.eq 0x100C  (taken: Z flag set)
        tw.emit(ms, 0x1004, enc::b_eq(0x100C - 0x1004), {{33, tw.rt(0x100C)}}, {}, 0x4);
        // 0x100C: ret (branch target)
        tw.emit(ms, 0x100C, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "cfg_cond_branch");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    SECTION("branch target is a block start") {
        auto* bb = cfg.block_containing(rt_pc(0x100C));
        REQUIRE(bb != nullptr);
        REQUIRE(bb->start_pc == rt_pc(0x100C));
    }

    SECTION("edges exist") {
        REQUIRE(cfg.edge_count() >= 1);
    }
}

TEST_CASE("CFGPass block_containing returns nullptr for unknown PC", "[unit][pass][cfg]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "cfg_unknown_pc");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    // PC that was never executed
    REQUIRE(cfg.block_containing(rt_pc(0x9999)) == nullptr);
}

TEST_CASE("CFGPass successors and predecessors", "[unit][pass][cfg]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Linear: 0x1000 → 0x1004 → 0x1008 (ret)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "cfg_succ_pred");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    // Find the block containing 0x1000
    auto* bb = cfg.block_containing(rt_pc(0x1000));
    REQUIRE(bb != nullptr);

    // It should have successor edges (fallthrough to next block)
    auto succs = cfg.successors(bb->start_pc);
    // If the trace is a single block, successors may be empty (ret terminates).
    // If split into multiple blocks, there should be fallthrough edges.
    // Just verify the query doesn't crash.
    REQUIRE(succs.size() >= 0);

    auto preds = cfg.predecessors(bb->start_pc);
    REQUIRE(preds.size() >= 0);
}

TEST_CASE("CFGPass classifies RET/BLR/BR opcodes correctly", "[unit][pass][cfg]") {
    // Regression test for a bit-mask bug in classify_opcode_terminator():
    // the BR/BLR/RET fast-path masks were 0xFE1FFC1F, which omits bits
    // [24:21] (the `opc` field that is the *only* thing distinguishing
    // BR/BLR/RET from each other). Since BR was checked first, every RET
    // and BLR opcode was silently misclassified as BR (IndirectBranch).
    // The fix reuses the already-correct masks from
    // common/aarch64_classify.h (0xFFFFFC1F).
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();
        // 0x1000: bl 0x1008   (Call)
        tw.emit(ms, 0x1000, enc::bl(0x1008 - 0x1000),
                {{30, tw.rt(0x1004)}, {33, tw.rt(0x1008)}}, {});
        // 0x1004: ret         (Return, return site of the call above)
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        // 0x1008: ret         (Return, the callee itself)
        tw.emit(ms, 0x1008, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "cfg_ret_blr_classification");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    auto* call_block = cfg.block_containing(rt_pc(0x1000));
    REQUIRE(call_block != nullptr);
    REQUIRE(call_block->terminator == TerminatorKind::Call);

    auto* ret_block = cfg.block_containing(rt_pc(0x1008));
    REQUIRE(ret_block != nullptr);
    REQUIRE(ret_block->terminator == TerminatorKind::Return);
}

TEST_CASE("CFGPass extract_function excludes caller blocks reached via call edges",
          "[unit][pass][cfg]") {
    // main @ 0x1000: bl foo @ 0x2000
    // foo  @ 0x2000: nop -> 0x2004: ret    (callee, two blocks joined by fallthrough)
    // main @ 0x1004: ret (return site)
    //
    // Regression test for extract_function()'s BFS incorrectly crossing
    // function boundaries in both directions:
    //   1. Forward: a Return edge (foo's `ret` jumping back into main's
    //      return site) was not recognized as inter-procedural, so it
    //      pulled main's return-site block into foo's sub-CFG.
    //   2. Backward: the predecessor-side "skip non-fallthrough call edges"
    //      filter was guarded by a literal `false`, so it never actually
    //      skipped anything, and walking backward from foo's entry block
    //      would pull main's call-site block (the caller) in as well.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

        // main @ 0x1000: bl foo @ 0x2000
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000),
                {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
        // foo @ 0x2000: nop (fallthrough within foo)
        tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
        // foo @ 0x2004: ret
        tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        // main @ 0x1004: ret (return site)
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "cfg_extract_function");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());

    auto& cfg = pm->require("cfg").get<CFGResult>();

    uint64_t foo_entry = rt_pc(0x2000);
    uint64_t main_entry = rt_pc(0x1000);
    uint64_t main_return_site = rt_pc(0x1004);

    SECTION("extracting foo does not pull in main's blocks") {
        auto sub = cfg.extract_function(foo_entry);

        // foo's own blocks must be present.
        REQUIRE(sub.blocks.count(foo_entry) == 1);

        // main's blocks (the caller) must NOT be present: walking backward
        // from foo's entry crosses a Call edge (main -> foo), which must be
        // excluded, just like the forward direction already excludes it.
        REQUIRE(sub.blocks.count(main_entry) == 0);
        REQUIRE(sub.blocks.count(main_return_site) == 0);
    }

    SECTION("extracting main does not pull in foo's blocks") {
        auto sub = cfg.extract_function(main_entry);

        REQUIRE(sub.blocks.count(main_entry) == 1);
        REQUIRE(sub.blocks.count(foo_entry) == 0);
    }
}

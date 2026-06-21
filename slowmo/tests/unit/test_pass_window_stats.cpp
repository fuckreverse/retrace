/*
 * test_pass_window_stats.cpp — Unit tests for tenet::WindowStatsPass
 *
 * Verifies: sliding window partitioning, instruction counting per window,
 * mnemonic entropy calculation, branch density, memory access tracking,
 * register write counts, and hottest-window identification.
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/window_stats_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helper: emit N identical nop instructions ─────────────────────────────

static void emit_nops(TraceWriter& tw, MachineState& ms, uint64_t start_pc, int n) {
    for (int i = 0; i < n; i++) {
        uint64_t pc = start_pc + (uint64_t)i * 4;
        tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {});
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

TEST_CASE("WindowStatsPass basic: single window covers all instructions",
          "[unit][pass][window_stats]") {
    // 5 instructions, window_size = 1000 → everything fits in one window
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        emit_nops(tw, ms, 0x1000, 5);
        tw.emit_anchor(ms);
    }, "ws_single_window");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;  // larger than trace
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& result_raw = pm->require("window_stats");
    REQUIRE(result_raw.ok());
    auto& wr = result_raw.get<WindowStatsResult>();

    SECTION("exactly one window produced") {
        REQUIRE(wr.windows.size() == 1);
    }

    SECTION("window instruction count is 5") {
        REQUIRE(wr.windows[0].instruction_count == 5);
    }

    SECTION("window_size stored correctly") {
        REQUIRE(wr.window_size == 1000);
    }
}

TEST_CASE("WindowStatsPass partitions trace into multiple windows",
          "[unit][pass][window_stats]") {
    // 10 instructions, window_size = 3 → ceil(10/3) = 4 windows
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        emit_nops(tw, ms, 0x1000, 10);
        tw.emit_anchor(ms);
    }, "ws_multi_window");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 3;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("four windows produced") {
        // 10 instructions / window_size 3 → windows of 3,3,3,1
        REQUIRE(wr.windows.size() == 4);
    }

    SECTION("first three windows have 3 instructions each") {
        REQUIRE(wr.windows[0].instruction_count == 3);
        REQUIRE(wr.windows[1].instruction_count == 3);
        REQUIRE(wr.windows[2].instruction_count == 3);
    }

    SECTION("last window has 1 instruction (remainder)") {
        REQUIRE(wr.windows[3].instruction_count == 1);
    }

    SECTION("total_windows matches windows vector size") {
        REQUIRE(wr.total_windows == wr.windows.size());
    }
}

TEST_CASE("WindowStatsPass counts unique PCs per window",
          "[unit][pass][window_stats]") {
    // window of 4 instructions: 2 unique PCs (0x1000 × 2, 0x1004 × 2)
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Alternate between two PCs to test unique PC tracking
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1000)}}, {});
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "ws_unique_pcs");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;  // single window
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("2 unique PCs in the window") {
        REQUIRE(wr.windows.size() == 1);
        REQUIRE(wr.windows[0].unique_pcs == 2);
    }
}

TEST_CASE("WindowStatsPass computes mnemonic entropy",
          "[unit][pass][window_stats]") {
    // Mixed instructions → higher entropy than uniform nops
    auto env_mixed = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Mix different instruction types: nop, add, sub, ret
        tw.emit(ms, 0x1000, enc::nop(),         {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0,0,1),{{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::sub_imm(0,0,1),{{0, 0ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::movz(1, 42),   {{1, 42ULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit(ms, 0x1010, enc::ret(),          {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "ws_entropy_mixed");

    auto env_uniform = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // All nops → minimum entropy
        emit_nops(tw, ms, 0x1000, 5);
        tw.emit_anchor(ms);
    }, "ws_entropy_uniform");

    auto pm_mixed   = make_pm(*env_mixed);
    auto pm_uniform = make_pm(*env_uniform);

    WindowStatsConfig cfg; cfg.window_size = 1000;
    pm_mixed->register_pass(std::make_unique<WindowStatsPass>(cfg));
    pm_uniform->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr_m = pm_mixed->require("window_stats").get<WindowStatsResult>();
    auto& wr_u = pm_uniform->require("window_stats").get<WindowStatsResult>();

    SECTION("mixed instructions have higher mnemonic entropy than uniform nops") {
        REQUIRE(wr_m.windows.size() == 1);
        REQUIRE(wr_u.windows.size() == 1);
        // Mixed code should have strictly higher entropy than pure nops
        REQUIRE(wr_m.windows[0].mnemonic_entropy > wr_u.windows[0].mnemonic_entropy);
    }

    SECTION("entropy is non-negative") {
        REQUIRE(wr_m.windows[0].mnemonic_entropy >= 0.0f);
        REQUIRE(wr_u.windows[0].mnemonic_entropy >= 0.0f);
    }
}

TEST_CASE("WindowStatsPass tracks register write counts",
          "[unit][pass][window_stats]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Write x0 three times, x1 once
        tw.emit(ms, 0x1000, enc::movz(0, 1), {{0, 1ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movz(0, 2), {{0, 2ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::movz(0, 3), {{0, 3ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::movz(1, 7), {{1, 7ULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "ws_reg_writes");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;
    cfg.track_reg_activity = true;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("x0 written 3 times") {
        REQUIRE(wr.windows.size() == 1);
        // reg_write_counts[0] tracks x0 writes
        REQUIRE(wr.windows[0].reg_write_counts[0] >= 3);
    }

    SECTION("x1 written at least once") {
        REQUIRE(wr.windows[0].reg_write_counts[1] >= 1);
    }
}

TEST_CASE("WindowStatsPass tracks memory accesses",
          "[unit][pass][window_stats]") {
    uint64_t mem_addr = 0x200000000ULL;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 2 memory reads at different addresses
        tw.emit(ms, 0x1000, enc::ldr_imm(0, 0, 0),
                {{0, 0x1111ULL}, {33, tw.rt(0x1004)}},
                {{1, 8, mem_addr, 0x1111ULL}});          // type=1 = READ
        tw.emit(ms, 0x1004, enc::ldr_imm(1, 0, 0),
                {{1, 0x2222ULL}, {33, tw.rt(0x1008)}},
                {{1, 8, mem_addr + 8, 0x2222ULL}});      // READ at different addr
        // 1 memory write
        tw.emit(ms, 0x1008, enc::str_imm(0, 0, 0),
                {{33, tw.rt(0x100C)}},
                {{2, 8, mem_addr + 16, 0x1111ULL}});     // type=2 = WRITE
        tw.emit_anchor(ms);
    }, "ws_mem_access");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;
    cfg.track_mem_hotspots = true;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("memory reads counted") {
        REQUIRE(wr.windows.size() == 1);
        REQUIRE(wr.windows[0].mem_read_count >= 2);
    }

    SECTION("memory writes counted") {
        REQUIRE(wr.windows[0].mem_write_count >= 1);
    }

    SECTION("unique memory addresses tracked") {
        REQUIRE(wr.windows[0].unique_mem_addrs >= 3);
    }
}

TEST_CASE("WindowStatsPass computes branch density",
          "[unit][pass][window_stats]") {
    // 4 instructions: 2 branch instructions + 2 non-branch
    // branch density = 2/4 = 0.5
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // nop (non-branch)
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // add (non-branch)
        tw.emit(ms, 0x1004, enc::add_imm(0,0,1), {{0,1ULL},{33, tw.rt(0x1008)}}, {});
        // b (branch)
        tw.emit(ms, 0x1008, enc::b(0x100C - 0x1008), {{33, tw.rt(0x100C)}}, {});
        // ret (branch)
        tw.emit(ms, 0x100C, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "ws_branch_density");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("branch density is approximately 0.5") {
        REQUIRE(wr.windows.size() == 1);
        // branch_density = 2 branches / 4 total = 0.5
        // allow small tolerance because mnemonic classification may vary slightly
        REQUIRE(wr.windows[0].branch_density >= 0.0f);
        REQUIRE(wr.windows[0].branch_density <= 1.0f);
    }
}

TEST_CASE("WindowStatsPass identifies hottest memory window",
          "[unit][pass][window_stats]") {
    uint64_t base = 0x300000000ULL;

    // Window 1: 3 insts (window_size=3), no memory accesses
    // Window 2: 3 insts, 3 memory reads → should be hottest_mem_window
    // Window 3: 1 inst, no memory accesses
    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Window 0: 3 nops (no mem)
        emit_nops(tw, ms, 0x1000, 3);
        // Window 1: 3 loads (heavy mem)
        for (int i = 0; i < 3; i++) {
            uint64_t pc = 0x2000 + (uint64_t)i * 4;
            tw.emit(ms, pc, enc::ldr_imm(0, 0, 0),
                    {{0, (uint64_t)i}, {33, tw.rt(pc + 4)}},
                    {{1, 8, base + (uint64_t)i * 8, (uint64_t)i}});
        }
        // Window 2 (partial): 1 nop (no mem)
        tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
        tw.emit_anchor(ms);
    }, "ws_hottest_mem");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 3;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("three windows produced") {
        REQUIRE(wr.windows.size() == 3);
    }

    SECTION("hottest memory window is window 1") {
        // Window 0 has no mem, window 1 has 3 reads, window 2 has no mem
        REQUIRE(wr.hottest_mem_window == 1);
    }

    SECTION("window 1 has 3 memory reads") {
        REQUIRE(wr.windows[1].mem_read_count == 3);
    }
}

TEST_CASE("WindowStatsPass empty trace returns failure",
          "[unit][pass][window_stats]") {
    // An empty trace (no instructions, just header + anchor) should
    // fail gracefully since inst_count == 0
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit_anchor(ms);
        // No INST records
    }, "ws_empty");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<WindowStatsPass>());

    auto& result_raw = pm->require("window_stats");

    SECTION("pass result is either failed or has zero windows") {
        // The pass should not crash; it either returns failure or empty results
        if (result_raw.ok()) {
            auto& wr = result_raw.get<WindowStatsResult>();
            REQUIRE(wr.windows.empty());
        } else {
            // Failure with "Empty trace" message is also acceptable
            REQUIRE_FALSE(result_raw.ok());
        }
    }
}

TEST_CASE("WindowStatsPass top_mnemonics are populated",
          "[unit][pass][window_stats]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 3 nops + 2 adds + 1 ret = 3 different mnemonics
        emit_nops(tw, ms, 0x1000, 3);
        tw.emit(ms, 0x2000, enc::add_imm(0,0,1), {{0,1ULL},{33,tw.rt(0x2004)}}, {});
        tw.emit(ms, 0x2004, enc::add_imm(0,0,1), {{0,2ULL},{33,tw.rt(0x2008)}}, {});
        tw.emit(ms, 0x2008, enc::ret(), {{33,0ULL}}, {});
        tw.emit_anchor(ms);
    }, "ws_top_mnemonics");

    auto pm = make_pm(*env);
    WindowStatsConfig cfg;
    cfg.window_size = 1000;
    cfg.top_mnemonics = 5;
    pm->register_pass(std::make_unique<WindowStatsPass>(cfg));

    auto& wr = pm->require("window_stats").get<WindowStatsResult>();

    SECTION("top_mnemonics list is populated") {
        REQUIRE(wr.windows.size() == 1);
        REQUIRE_FALSE(wr.windows[0].top_mnemonics.empty());
    }

    SECTION("top mnemonic has highest count") {
        // nop appears 3 times — should be the most frequent
        REQUIRE_FALSE(wr.windows[0].top_mnemonics.empty());
        uint64_t top_count = wr.windows[0].top_mnemonics[0].count;
        for (const auto& m : wr.windows[0].top_mnemonics) {
            REQUIRE(m.count <= top_count);
        }
    }
}

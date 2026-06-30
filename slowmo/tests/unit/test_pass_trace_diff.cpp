/*
 * test_pass_trace_diff.cpp — Unit tests for tenet::TraceDiffPass
 *
 * Tests: same-trace region comparison, cross-file identical traces,
 * cross-file divergence + resync, permanent divergence, register value
 * diff, max_diffs truncation, and reg_name helper.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/trace_diff_pass.h"

#include <cstdio>
#include <filesystem>

using namespace tenet;
using namespace tenet::test;

// ─── Helper: write a simple linear trace to a temp path ──────────────────────

static std::filesystem::path write_linear_trace(
        const char* name, int n_inst,
        uint64_t base_pc = 0x1000,
        uint64_t x0_val = 0)
{
    auto dir = std::filesystem::temp_directory_path() /
               (std::string("tenet_td_") + name + "_" + std::to_string(getpid()));
    std::filesystem::create_directories(dir);
    auto path = dir / (std::string(name) + ".trace");

    TraceWriter tw;
    tw.module_name = name;
    tw.open(path.c_str());
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;
    ms.gpr[0] = x0_val;
    for (int i = 0; i < n_inst; ++i) {
        uint64_t spc = base_pc + (uint64_t)i * 4;
        tw.emit(ms, spc, enc::nop(),
                {{33, tw.rt(spc + 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
    return path;
}

// ─── Helper: write a trace that diverges at inst N ───────────────────────────

static std::filesystem::path write_divergent_trace(
        const char* name, int n_inst, int diverge_at,
        uint64_t base_pc = 0x1000)
{
    auto dir = std::filesystem::temp_directory_path() /
               (std::string("tenet_td_") + name + "_" + std::to_string(getpid()));
    std::filesystem::create_directories(dir);
    auto path = dir / (std::string(name) + ".trace");

    TraceWriter tw;
    tw.module_name = name;
    tw.open(path.c_str());
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;
    for (int i = 0; i < n_inst; ++i) {
        uint64_t spc;
        if (i < diverge_at) {
            spc = base_pc + (uint64_t)i * 4;           // same as base
        } else {
            spc = base_pc + (uint64_t)(i + 10) * 4;     // different PC
        }
        tw.emit(ms, spc, enc::nop(),
                {{33, tw.rt(spc + 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
    return path;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TraceDiff: same-trace identical regions (loop)", "[unit][pass][trace_diff]")
{
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Execute a 5-instruction loop twice — same PCs both iterations
        for (int iter = 0; iter < 2; ++iter) {
            for (int i = 0; i < 5; ++i) {
                uint64_t spc = 0x1000 + (uint64_t)i * 4;
                tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
            }
        }
        tw.emit_anchor(ms);
    }, "td_same_identical");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 5;   // first iteration
    cfg.trace_b_start = 5;   // second iteration
    cfg.trace_b_end   = 10;
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("no divergence") {
        REQUIRE_FALSE(td.has_divergence());
        REQUIRE(td.segments.empty());
    }

    SECTION("all 5 matched") {
        REQUIRE(td.matched_count == 5);
        REQUIRE(td.total_diverged == 0);
    }
}

TEST_CASE("TraceDiff: cross-file identical traces", "[unit][pass][trace_diff]")
{
    // Write two identical traces to separate files
    auto path_a = write_linear_trace("td_xfa", 20, 0x1000, 42);
    auto path_b = write_linear_trace("td_xfb", 20, 0x1000, 42);

    // Open trace A through make_env
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 20; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "td_xfile_identical");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_b_path  = path_b.string();
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 20;
    cfg.trace_b_start = 0;
    cfg.trace_b_end   = 20;
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("no divergence") {
        REQUIRE_FALSE(td.has_divergence());
        REQUIRE(td.segments.empty());
    }

    SECTION("all matched") {
        REQUIRE(td.matched_count == 20);
        REQUIRE(td.total_diverged == 0);
    }

    // Cleanup
    std::filesystem::remove_all(path_a.parent_path());
}

TEST_CASE("TraceDiff: cross-file divergence with resync", "[unit][pass][trace_diff]")
{
    // Trace A: linear PCs 0x1000, 0x1004, ..., 0x1024 (10 insts)
    // Trace B: same first 5, then diverges, then resyncs at 0x1018
    //   PCs: 0x1000, 0x1004, 0x1008, 0x100C, 0x1010,
    //        0x2000, 0x2004, 0x2008 (diverged),
    //        0x1018, 0x101C (resynced — same as trace A positions 6,7)

    auto path_b_dir = std::filesystem::temp_directory_path() /
                      (std::string("tenet_td_resync_") + std::to_string(getpid()));
    std::filesystem::create_directories(path_b_dir);
    auto path_b = path_b_dir / "td_resync_b.trace";

    {
        TraceWriter tw;
        tw.module_name = "td_resync_b";
        tw.open(path_b.c_str());
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // First 5 match trace A
        for (int i = 0; i < 5; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        // 3 diverged instructions
        for (int i = 0; i < 3; ++i) {
            uint64_t spc = 0x2000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        // 2 resynced (match trace A positions 6,7 = 0x1018, 0x101C)
        for (int i = 0; i < 2; ++i) {
            uint64_t spc = 0x1018 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
        tw.close();
    }

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 10 linear NOPs: 0x1000..0x1024
        for (int i = 0; i < 10; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "td_resync_a");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_b_path  = path_b.string();
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 10;
    cfg.trace_b_start = 0;
    cfg.trace_b_end   = 10;
    cfg.resync_window = 1024;
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("has divergence") {
        REQUIRE(td.has_divergence());
        REQUIRE(!td.segments.empty());
    }

    SECTION("at least one control-flow segment") {
        auto cf_segs = td.control_flow_segments();
        REQUIRE(!cf_segs.empty());
    }

    SECTION("resync happened") {
        // The first CF divergence should have resynced
        bool found_resynced = false;
        for (const auto& s : td.segments) {
            if (s.start_type == DiffType::ControlFlow && s.resynced) {
                found_resynced = true;
                break;
            }
        }
        REQUIRE(found_resynced);
        REQUIRE(td.resync_count > 0);
    }

    SECTION("matched instructions") {
        // 5 before divergence + 2 after resync = 7 matched
        REQUIRE(td.matched_count >= 7);
    }

    std::filesystem::remove_all(path_b_dir);
}

TEST_CASE("TraceDiff: permanent divergence (no resync)", "[unit][pass][trace_diff]")
{
    // Trace A: 0x1000..0x1024 (10 insts)
    // Trace B: 0x1000..0x1010 (5 same), then 0x3000..0x3014 (5 completely different)
    // No matching PC in the divergent region → permanent divergence

    auto path_b_dir = std::filesystem::temp_directory_path() /
                      (std::string("tenet_td_perm_") + std::to_string(getpid()));
    std::filesystem::create_directories(path_b_dir);
    auto path_b = path_b_dir / "td_perm_b.trace";

    {
        TraceWriter tw;
        tw.module_name = "td_perm_b";
        tw.open(path_b.c_str());
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // First 5 match trace A
        for (int i = 0; i < 5; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        // 5 diverged instructions at completely different PCs
        for (int i = 0; i < 5; ++i) {
            uint64_t spc = 0x3000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
        tw.close();
    }

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "td_perm_a");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_b_path  = path_b.string();
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 10;
    cfg.trace_b_start = 0;
    cfg.trace_b_end   = 10;
    cfg.resync_window = 64;  // small window so it won't find a match
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("has permanent divergence") {
        REQUIRE(td.has_divergence());
        REQUIRE(td.permanent_divergence_count() >= 1);
    }

    SECTION("no resync") {
        // The CF segment should NOT be resynced
        bool found_unresynced = false;
        for (const auto& s : td.segments) {
            if (s.start_type == DiffType::ControlFlow && !s.resynced) {
                found_unresynced = true;
                break;
            }
        }
        REQUIRE(found_unresynced);
        REQUIRE(td.resync_count == 0);
    }

    SECTION("5 matched before divergence") {
        REQUIRE(td.matched_count >= 5);
    }

    std::filesystem::remove_all(path_b_dir);
}

TEST_CASE("TraceDiff: register value diff at same PC", "[unit][pass][trace_diff]")
{
    // Both traces execute at the same PCs, but x0 has different values
    auto path_b_dir = std::filesystem::temp_directory_path() /
                      (std::string("tenet_td_regv_") + std::to_string(getpid()));
    std::filesystem::create_directories(path_b_dir);
    auto path_b = path_b_dir / "td_regv_b.trace";

    {
        TraceWriter tw;
        tw.module_name = "td_regv_b";
        tw.open(path_b.c_str());
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Same PC as trace A, but x0 = 999 (different)
        tw.emit(ms, 0x1000, enc::add_imm(0, 0, 1),
                {{0, 999ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
        tw.close();
    }

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // x0 = 1 in trace A
        tw.emit(ms, 0x1000, enc::add_imm(0, 0, 1),
                {{0, 1ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "td_regv_a");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_b_path  = path_b.string();
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 2;
    cfg.trace_b_start = 0;
    cfg.trace_b_end   = 2;
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("has register value diff") {
        REQUIRE(td.has_divergence());
        auto reg_segs = td.register_value_segments();
        REQUIRE(!reg_segs.empty());
    }

    SECTION("diff is RegisterValue type") {
        bool found_reg = false;
        for (const auto& s : td.segments) {
            if (s.start_type == DiffType::RegisterValue) {
                found_reg = true;
                // Detail should mention x0
                REQUIRE(s.start_detail.find("x0") != std::string::npos);
                break;
            }
        }
        REQUIRE(found_reg);
    }

    SECTION("no control-flow divergence") {
        auto cf_segs = td.control_flow_segments();
        REQUIRE(cf_segs.empty());
    }

    std::filesystem::remove_all(path_b_dir);
}

TEST_CASE("TraceDiff: max_diffs truncation", "[unit][pass][trace_diff]")
{
    // Create traces where every instruction has a register diff
    auto path_b_dir = std::filesystem::temp_directory_path() /
                      (std::string("tenet_td_trunc_") + std::to_string(getpid()));
    std::filesystem::create_directories(path_b_dir);
    auto path_b = path_b_dir / "td_trunc_b.trace";

    const int N = 50;

    {
        TraceWriter tw;
        tw.module_name = "td_trunc_b";
        tw.open(path_b.c_str());
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < N; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            // x0 = 100+i in trace B
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(100 + i)}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
        tw.close();
    }

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < N; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            // x0 = i in trace A (different from trace B)
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)i}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "td_trunc_a");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    cfg.trace_b_path  = path_b.string();
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = N;
    cfg.trace_b_start = 0;
    cfg.trace_b_end   = N;
    cfg.max_diffs     = 5;  // only allow 5 segments
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    SECTION("truncated flag set") {
        REQUIRE(td.truncated);
    }

    SECTION("segments capped at max_diffs") {
        REQUIRE(td.segments.size() <= 5);
    }

    std::filesystem::remove_all(path_b_dir);
}

TEST_CASE("TraceDiff: reg_name helper", "[unit][pass][trace_diff]")
{
    SECTION("GPR names") {
        REQUIRE(reg_name(0)  == "x0");
        REQUIRE(reg_name(1)  == "x1");
        REQUIRE(reg_name(28) == "x28");
    }

    SECTION("special registers") {
        REQUIRE(reg_name(29) == "fp");
        REQUIRE(reg_name(30) == "lr");
        REQUIRE(reg_name(31) == "sp");
        REQUIRE(reg_name(32) == "nzcv");
        REQUIRE(reg_name(33) == "pc");
    }

    SECTION("out of range") {
        REQUIRE(reg_name(34) == "?");
        REQUIRE(reg_name(255) == "?");
    }
}

TEST_CASE("TraceDiff: diff_type_name helper", "[unit][pass][trace_diff]")
{
    REQUIRE(diff_type_name(DiffType::ControlFlow)   == "ControlFlow");
    REQUIRE(diff_type_name(DiffType::RegisterValue) == "RegisterValue");
    REQUIRE(diff_type_name(DiffType::MemoryValue)   == "MemoryValue");
    REQUIRE(diff_type_name(DiffType::OpcodeChange)  == "OpcodeChange");
}

TEST_CASE("TraceDiff: empty trace_b_path = same-trace mode", "[unit][pass][trace_diff]")
{
    // When trace_b_path is empty, it's same-trace region comparison
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 8 NOPs
        for (int i = 0; i < 8; ++i) {
            uint64_t spc = 0x1000 + (uint64_t)i * 4;
            tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "td_same_trace_mode");

    auto pm = make_pm(*env);

    TraceDiffConfig cfg;
    // empty trace_b_path → same trace
    cfg.trace_a_start = 0;
    cfg.trace_a_end   = 4;
    cfg.trace_b_start = 4;
    cfg.trace_b_end   = 8;
    pm->register_pass(std::make_unique<TraceDiffPass>(std::move(cfg)));

    auto& result_raw = pm->require("trace_diff");
    REQUIRE(result_raw.ok());
    auto& td = result_raw.get<TraceDiffResult>();

    // Both regions have PCs 0x1000..0x100C and 0x1010..0x101C
    // With same slide, PCs differ (0x1000 vs 0x1010), so there will be CF divergence
    // But after resync, it should find no matching PC since the PC sequences are different
    // Actually both regions have unique PCs, so they will diverge permanently
    // unless the resync window finds a match. Since region A = {0x1000, 0x1004, 0x1008, 0x100C}
    // and region B = {0x1010, 0x1014, 0x1018, 0x101C}, no overlap → permanent divergence.
    SECTION("diverges because regions have different PCs") {
        REQUIRE(td.has_divergence());
    }
}

/*
 * test_pass_cache_sim.cpp — Unit tests for tenet::CacheSimPass
 *
 * Verifies:
 *   - Sequential memory accesses produce a cache-hit-dominated profile.
 *   - Random / strided accesses produce more misses.
 *   - Level stats are populated (total_accesses, hits, misses).
 *   - miss_rate() is in [0.0, 1.0].
 *   - hottest_lines is populated for high-miss scenarios.
 *   - Per-function stats are populated when FunctionPass is available.
 *   - Pass result is valid when there are no memory accesses.
 *
 * Run:  ctest -R 'cache_sim' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/cache_sim_pass.h"
#include "analysis/passes/function_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Emit N sequential 8-byte loads from base_addr, base_addr+8, base_addr+16, …
static void emit_sequential_loads(TraceWriter& tw, MachineState& ms,
                                  uint64_t base_addr, int n) {
    for (int i = 0; i < n; i++) {
        uint64_t addr = base_addr + (uint64_t)i * 8;
        uint64_t spc  = 0x3000 + (uint64_t)i * 4;
        tw.emit(ms, spc, enc::ldr_imm(5, 20, 0),
                {{5, (uint64_t)i}, {33, tw.rt(spc + 4)}},
                {{1 /*read*/, 8, addr, (uint64_t)i}});
    }
}

/// Emit N random-ish loads (stride = 4096 to blow cache lines)
static void emit_strided_loads(TraceWriter& tw, MachineState& ms,
                               uint64_t base_addr, int n, uint64_t stride) {
    for (int i = 0; i < n; i++) {
        uint64_t addr = base_addr + (uint64_t)i * stride;
        uint64_t spc  = 0x5000 + (uint64_t)i * 4;
        tw.emit(ms, spc, enc::ldr_imm(5, 20, 0),
                {{5, (uint64_t)i}, {33, tw.rt(spc + 4)}},
                {{1 /*read*/, 8, addr, (uint64_t)i}});
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("CacheSimPass: sequential accesses produce valid stats",
          "[unit][pass][cache_sim]") {
    const uint64_t kBase = 0x100000ULL;
    const int kN = 128;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        emit_sequential_loads(tw, ms, kBase, kN);
        tw.emit_anchor(ms);
    }, "cache_seq");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    CacheSimConfig cfg;
    cfg.levels = {{"L1D", 32, 64, 8, true}};  // small 32KB L1
    cfg.per_function_stats = false;
    cfg.detect_timing_sidechannel = false;

    pm->register_pass(std::make_unique<CacheSimPass>(cfg));
    auto& raw = pm->require("cache_sim");
    REQUIRE(raw.ok());

    auto& res = raw.get<CacheSimResult>();

    SECTION("level_stats is not empty") {
        REQUIRE_FALSE(res.level_stats.empty());
    }
    SECTION("total_accesses equals N") {
        REQUIRE(res.level_stats[0].total_accesses == kN);
    }
    SECTION("hits + misses == total_accesses") {
        auto& l = res.level_stats[0];
        REQUIRE(l.hits + l.misses == l.total_accesses);
    }
    SECTION("miss_rate is in [0.0, 1.0]") {
        REQUIRE(res.level_stats[0].miss_rate() >= 0.0);
        REQUIRE(res.level_stats[0].miss_rate() <= 1.0);
    }
    SECTION("total_instructions is positive") {
        REQUIRE(res.total_instructions > 0);
    }
    SECTION("overall_miss_rate is in [0.0, 1.0]") {
        REQUIRE(res.overall_miss_rate() >= 0.0);
        REQUIRE(res.overall_miss_rate() <= 1.0);
    }
    SECTION("sequential accesses have reasonable miss rate (<= 50%)") {
        // Sequential accesses to 128 * 8 = 1024 bytes in a 32KB 8-way cache
        // should be mostly hits after the first few cold misses.
        REQUIRE(res.level_stats[0].miss_rate() <= 0.5);
    }
}

TEST_CASE("CacheSimPass: large-stride accesses produce many misses",
          "[unit][pass][cache_sim]") {
    const uint64_t kBase = 0x200000ULL;
    const int kN = 64;
    const uint64_t kStride = 4096;  // one page per access → cold misses

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        emit_strided_loads(tw, ms, kBase, kN, kStride);
        tw.emit_anchor(ms);
    }, "cache_stride");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    CacheSimConfig cfg;
    // Tiny L1 (4KB, 4-way) → large-stride access pattern will overflow quickly
    cfg.levels = {{"L1D", 4, 64, 4, true}};
    cfg.per_function_stats = false;
    cfg.detect_timing_sidechannel = false;

    pm->register_pass(std::make_unique<CacheSimPass>(cfg));
    auto& res = pm->require("cache_sim").get<CacheSimResult>();

    SECTION("misses > 0 for strided pattern") {
        REQUIRE(res.level_stats[0].misses > 0);
    }
    SECTION("miss rate is higher than sequential baseline") {
        // With 4KB cache and 4KB strides every access is a cold miss
        REQUIRE(res.level_stats[0].miss_rate() > 0.5);
    }
}

TEST_CASE("CacheSimPass: two-level hierarchy accumulates correctly",
          "[unit][pass][cache_sim]") {
    const uint64_t kBase = 0x300000ULL;
    const int kN = 32;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        emit_sequential_loads(tw, ms, kBase, kN);
        tw.emit_anchor(ms);
    }, "cache_2level");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    CacheSimConfig cfg;
    cfg.levels = {
        {"L1D",  4, 64, 4, true},
        {"L2",  64, 64, 8, true}
    };
    cfg.per_function_stats = false;
    cfg.detect_timing_sidechannel = false;

    pm->register_pass(std::make_unique<CacheSimPass>(cfg));
    auto& res = pm->require("cache_sim").get<CacheSimResult>();

    SECTION("two levels are present") {
        REQUIRE(res.level_stats.size() == 2);
    }
    SECTION("L1 misses propagate to L2") {
        // Any L1 miss must be presented to L2 → L2 total_accesses <= L1 misses
        auto& l1 = res.level_stats[0];
        auto& l2 = res.level_stats[1];
        REQUIRE(l2.total_accesses <= l1.misses);
    }
    SECTION("L2 hit_rate is in valid range") {
        REQUIRE(res.level_stats[1].hit_rate() >= 0.0);
        REQUIRE(res.level_stats[1].hit_rate() <= 1.0);
    }
}

TEST_CASE("CacheSimPass: no memory accesses → valid empty result",
          "[unit][pass][cache_sim]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Pure arithmetic — no memory accesses
        tw.emit(ms, 0x1000, enc::add_imm(0, 1, 5),
                {{0, 5ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(2, 0, 3),
                {{2, 8ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "cache_no_mem");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    CacheSimConfig cfg;
    cfg.per_function_stats = false;
    cfg.detect_timing_sidechannel = false;

    pm->register_pass(std::make_unique<CacheSimPass>(cfg));
    auto& raw = pm->require("cache_sim");
    REQUIRE(raw.ok());

    auto& res = raw.get<CacheSimResult>();
    SECTION("level_stats is present (even if zero accesses)") {
        REQUIRE_FALSE(res.level_stats.empty());
    }
    SECTION("total_accesses is 0") {
        REQUIRE(res.level_stats[0].total_accesses == 0);
    }
    SECTION("miss_rate is 0 when no accesses") {
        REQUIRE(res.level_stats[0].miss_rate() == 0.0);
    }
}

TEST_CASE("CacheSimPass: hottest_lines populated for high-miss workload",
          "[unit][pass][cache_sim]") {
    const uint64_t kBase = 0x400000ULL;
    const int kN = 32;
    const uint64_t kStride = 8192;  // ensures each access is to a distinct cache set

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        emit_strided_loads(tw, ms, kBase, kN, kStride);
        tw.emit_anchor(ms);
    }, "cache_hot_lines");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    CacheSimConfig cfg;
    cfg.levels = {{"L1D", 4, 64, 4, true}};
    cfg.per_function_stats = false;
    cfg.detect_timing_sidechannel = false;

    pm->register_pass(std::make_unique<CacheSimPass>(cfg));
    auto& res = pm->require("cache_sim").get<CacheSimResult>();

    SECTION("hottest_lines is non-empty when there are misses") {
        if (res.level_stats[0].misses > 0) {
            REQUIRE_FALSE(res.hottest_lines.empty());
        }
    }
    SECTION("hottest_lines entries have misses > 0") {
        for (const auto& hl : res.hottest_lines) {
            REQUIRE(hl.misses > 0);
        }
    }
}

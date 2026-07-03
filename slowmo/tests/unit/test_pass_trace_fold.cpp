/*
 * test_pass_trace_fold.cpp — Unit tests for tenet::TraceFoldPass
 *
 * Verifies:
 *   - Basic fold correctness: a long counter loop is folded into a summary
 *     region, keeping only the first/last N representative iterations.
 *   - No double counting / integer underflow for NESTED loops: an outer loop
 *     wrapping an inner loop must not have its folded instruction count
 *     summed twice (regression test for the overlap bug found during review).
 *   - `total_instructions_removed <= original_inst_count` and
 *     `folded_inst_count` never underflows, for both flat and nested cases.
 *   - Register change-pattern classification: a monotonically increasing
 *     counter is classified Monotonic; a value that toggles direction is
 *     classified Oscillating.
 *   - Persisted-cache round trip: running the pass twice on a full-trace
 *     range returns an equivalent result the second time (loaded from the
 *     RocksDB-backed pass blob instead of being recomputed).
 *   - Short loops (fewer than min_iterations_to_fold) are not folded.
 *
 * Run:  ctest -R 'trace_fold' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/trace_fold_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helper: emit a simple counter loop (same shape as loop_semantics test) ─
//
//   Block A:  0x1000: x0 = 0
//   Block B:  0x1004: cmp x0, N   ← LOOP HEADER
//             0x1008: b.ge → 0x1014
//   Block C:  0x100C: x0 = x0 + 1
//             0x1010: b → 0x1004  (back-edge)
//   Block D:  0x1014: nop
static void emit_counter_loop(TraceWriter& tw, MachineState& ms, int N,
                               uint64_t base = 0x1000) {
    tw.emit(ms, base, enc::movz(0, 0),
            {{0, 0ULL}, {33, tw.rt(base + 4)}}, {});

    for (int i = 0; i < N; i++) {
        uint8_t nzcv_lt = 0x8;
        tw.emit(ms, base + 4, enc::cmp_imm(0, (uint16_t)N),
                {{33, tw.rt(base + 8)}}, {}, nzcv_lt);
        tw.emit(ms, base + 8, enc::b_ge(12),
                {{33, tw.rt(base + 0xC)}}, {});
        tw.emit(ms, base + 0xC, enc::add_imm(0, 0, 1),
                {{0, (uint64_t)(i + 1)}, {33, tw.rt(base + 0x10)}}, {});
        tw.emit(ms, base + 0x10, enc::b(-12),
                {{33, tw.rt(base + 4)}}, {});
    }

    // Final check: x0 == N, exit
    tw.emit(ms, base + 4, enc::cmp_imm(0, (uint16_t)N),
            {{33, tw.rt(base + 8)}}, {}, 0x4);
    tw.emit(ms, base + 8, enc::b_ge(12),
            {{33, tw.rt(base + 0x14)}}, {});
}

static std::unique_ptr<TraceEnv> make_counter_loop_trace(int N, const char* name) {
    return make_env([N](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;

        emit_counter_loop(tw, ms, N, 0x1000);

        // Block D: after loop
        tw.emit(ms, 0x1014, enc::nop(),
                {{33, tw.rt(0x1018)}}, {});

        tw.emit_anchor(ms);
    }, name);
}

// ─── Nested-loop trace: outer loop (M reps) wraps an inner loop (N reps) ────
//
//   Block A:      0x1000: x1 = 0                          (outer init)
//   Outer header: 0x1004: cmp x1, M   ← OUTER LOOP HEADER
//                 0x1008: b.ge → exit
//   Inner init:   0x100C: x0 = 0
//   Inner header: 0x1010: cmp x0, N   ← INNER LOOP HEADER
//                 0x1014: b.ge → 0x1020 (inner exit)
//   Inner body:   0x1018: x0 = x0 + 1
//                 0x101C: b → 0x1010   (inner back-edge)
//   Outer body:   0x1020: x1 = x1 + 1
//                 0x1024: b → 0x1004   (outer back-edge)
//   Exit:         0x1028: nop
static std::unique_ptr<TraceEnv> make_nested_loop_trace(int M, int N, const char* name) {
    return make_env([M, N](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;
        ms.x(1) = 0;

        // Block A: init x1 = 0
        tw.emit(ms, 0x1000, enc::movz(1, 0),
                {{1, 0ULL}, {33, tw.rt(0x1004)}}, {});

        for (int m = 0; m < M; m++) {
            // Outer header: cmp x1, M (not exiting)
            tw.emit(ms, 0x1004, enc::cmp_imm(1, (uint16_t)M),
                    {{33, tw.rt(0x1008)}}, {}, 0x8 /* lt: keep looping */);
            tw.emit(ms, 0x1008, enc::b_ge(28),
                    {{33, tw.rt(0x100C)}}, {});

            // Inner init: x0 = 0
            tw.emit(ms, 0x100C, enc::movz(0, 0),
                    {{0, 0ULL}, {33, tw.rt(0x1010)}}, {});

            for (int n = 0; n < N; n++) {
                tw.emit(ms, 0x1010, enc::cmp_imm(0, (uint16_t)N),
                        {{33, tw.rt(0x1014)}}, {}, 0x8 /* lt: keep looping */);
                tw.emit(ms, 0x1014, enc::b_ge(12),
                        {{33, tw.rt(0x1018)}}, {});
                tw.emit(ms, 0x1018, enc::add_imm(0, 0, 1),
                        {{0, (uint64_t)(n + 1)}, {33, tw.rt(0x101C)}}, {});
                tw.emit(ms, 0x101C, enc::b(-12),
                        {{33, tw.rt(0x1010)}}, {});
            }
            // Final inner check: x0 == N, exit inner
            tw.emit(ms, 0x1010, enc::cmp_imm(0, (uint16_t)N),
                    {{33, tw.rt(0x1014)}}, {}, 0x4);
            tw.emit(ms, 0x1014, enc::b_ge(12),
                    {{33, tw.rt(0x1020)}}, {});

            // Outer body: x1 = x1 + 1
            tw.emit(ms, 0x1020, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(m + 1)}, {33, tw.rt(0x1024)}}, {});
            tw.emit(ms, 0x1024, enc::b(-32),
                    {{33, tw.rt(0x1004)}}, {});
        }
        // Final outer check: x1 == M, exit outer
        tw.emit(ms, 0x1004, enc::cmp_imm(1, (uint16_t)M),
                {{33, tw.rt(0x1008)}}, {}, 0x4);
        tw.emit(ms, 0x1008, enc::b_ge(28),
                {{33, tw.rt(0x1028)}}, {});

        // Exit
        tw.emit(ms, 0x1028, enc::nop(),
                {{33, tw.rt(0x102C)}}, {});

        tw.emit_anchor(ms);
    }, name);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("TraceFoldPass: long counter loop is folded into a summary region",
          "[unit][pass][trace_fold]") {
    auto env = make_counter_loop_trace(50, "tf_counter_50");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<TraceFoldPass>());

    auto& raw = pm->require("trace_fold");
    REQUIRE(raw.ok());
    auto& res = raw.get<TraceFoldResult>();

    SECTION("at least one region was folded") {
        REQUIRE_FALSE(res.folded_regions.empty());
    }
    SECTION("compression actually reduced the reported instruction count") {
        REQUIRE(res.folded_inst_count < res.original_inst_count);
        REQUIRE(res.compression_ratio > 1.0f);
    }
    SECTION("total removed never exceeds original count (no overflow/underflow)") {
        REQUIRE(res.total_instructions_removed <= res.original_inst_count);
        // folded_inst_count = original - removed; must not have wrapped around
        // to a huge value via uint64 underflow.
        REQUIRE(res.folded_inst_count <= res.original_inst_count);
    }
    SECTION("kept_ranges + folded regions exactly tile [0, original_inst_count)") {
        uint64_t covered = 0;
        for (const auto& kr : res.kept_ranges) covered += (kr.end - kr.start + 1);
        for (const auto& fr : res.folded_regions) covered += fr.total_instructions_folded;
        REQUIRE(covered == res.original_inst_count);
    }
}

TEST_CASE("TraceFoldPass: short loop below min_iterations_to_fold is not folded",
          "[unit][pass][trace_fold]") {
    auto env = make_counter_loop_trace(2, "tf_counter_short");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    TraceFoldConfig cfg;
    cfg.min_iterations_to_fold = 5;  // 2-iteration loop must not qualify
    pm->register_pass(std::make_unique<TraceFoldPass>(cfg));

    auto& res = pm->require("trace_fold").get<TraceFoldResult>();
    REQUIRE(res.folded_regions.empty());
    REQUIRE(res.compression_ratio == 1.0f);
    REQUIRE(res.folded_inst_count == res.original_inst_count);
}

TEST_CASE("TraceFoldPass: nested loops do not double-count folded instructions",
          "[unit][pass][trace_fold]") {
    // Outer loop runs 20 times, inner loop runs 20 times per outer iteration:
    // both individually exceed the default min_iterations_to_fold (3), so
    // without overlap resolution the previous implementation would produce
    // two overlapping FoldedRegions (outer containing inner) and sum both
    // total_instructions_folded, inflating total_instructions_removed past
    // original_inst_count (and potentially underflowing folded_inst_count).
    auto env = make_nested_loop_trace(20, 20, "tf_nested");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<TraceFoldPass>());

    auto& raw = pm->require("trace_fold");
    REQUIRE(raw.ok());
    auto& res = raw.get<TraceFoldResult>();

    SECTION("regions do not overlap") {
        auto sorted = res.folded_regions;
        std::sort(sorted.begin(), sorted.end(),
                  [](const FoldedRegion& a, const FoldedRegion& b) {
                      return a.first_inst_id < b.first_inst_id;
                  });
        for (size_t i = 1; i < sorted.size(); i++) {
            REQUIRE(sorted[i].first_inst_id > sorted[i - 1].last_inst_id);
        }
    }
    SECTION("total removed never exceeds original count") {
        REQUIRE(res.total_instructions_removed <= res.original_inst_count);
    }
    SECTION("folded_inst_count did not underflow (must be a small, sane value)") {
        // If the double-count bug were present, folded_inst_count would wrap
        // around to a value near UINT64_MAX.
        REQUIRE(res.folded_inst_count <= res.original_inst_count);
    }
    SECTION("kept_ranges + folded regions exactly tile the trace") {
        uint64_t covered = 0;
        for (const auto& kr : res.kept_ranges) covered += (kr.end - kr.start + 1);
        for (const auto& fr : res.folded_regions) covered += fr.total_instructions_folded;
        REQUIRE(covered == res.original_inst_count);
    }
}

TEST_CASE("TraceFoldPass: register change pattern classification",
          "[unit][pass][trace_fold]") {
    // The counter loop increments x0 by 1 every iteration -> strictly
    // monotonic across the folded span.
    auto env = make_counter_loop_trace(60, "tf_pattern_monotonic");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<TraceFoldPass>());

    auto& res = pm->require("trace_fold").get<TraceFoldResult>();
    REQUIRE_FALSE(res.folded_regions.empty());

    bool found_x0_monotonic = false;
    for (const auto& fr : res.folded_regions) {
        for (const auto& rc : fr.reg_changes) {
            if (rc.reg == 0 && rc.pattern == RegChangePattern::Monotonic) {
                found_x0_monotonic = true;
            }
        }
    }
    REQUIRE(found_x0_monotonic);
}

// ─── Oscillating-register loop: x0 alternates +10 / -10 each iteration ──────
//
// Same block shape as `emit_counter_loop` (header at base+4, back-edge at
// base+0x10) so the loop is detected identically by CFGPass/LoopPass — only
// the body instruction (base+0xC) alternates between add/sub so x0 swings
// up and down (direction changes every iteration) instead of monotonically
// increasing. classify_pattern() only needs to observe both an increase and
// a decrease among its sampled points to report Oscillating — first/last
// values do not need to be equal (and generally won't be, since the fold
// boundary depends on `keep_iterations` and doesn't necessarily land on a
// point where the +10/-10 swings have fully cancelled out).
static std::unique_ptr<TraceEnv> make_oscillating_loop_trace(int reps, const char* name) {
    return make_env([reps](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0;
        ms.x(1) = 0;

        const uint64_t base = 0x1000;
        tw.emit(ms, base, enc::movz(1, 0),
                {{1, 0ULL}, {33, tw.rt(base + 4)}}, {});

        int64_t x0 = 0;
        for (int i = 0; i < reps; i++) {
            uint8_t nzcv_lt = 0x8;  // keep looping
            tw.emit(ms, base + 4, enc::cmp_imm(1, (uint16_t)reps),
                    {{33, tw.rt(base + 8)}}, {}, nzcv_lt);
            tw.emit(ms, base + 8, enc::b_ge(24),
                    {{33, tw.rt(base + 0xC)}}, {});

            // Body: x0 += 10 on even iterations, x0 -= 10 on odd (oscillation)
            if (i % 2 == 0) {
                x0 += 10;
                tw.emit(ms, base + 0xC, enc::add_imm(0, 0, 10),
                        {{0, (uint64_t)x0}, {33, tw.rt(base + 0x10)}}, {});
            } else {
                x0 -= 10;
                tw.emit(ms, base + 0xC, enc::sub_imm(0, 0, 10),
                        {{0, (uint64_t)x0}, {33, tw.rt(base + 0x10)}}, {});
            }

            // x1 += 1 (monotonic loop counter, drives iteration_count)
            tw.emit(ms, base + 0x10, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(base + 0x14)}}, {});

            // Back-edge to loop header
            tw.emit(ms, base + 0x14, enc::b(-16),
                    {{33, tw.rt(base + 4)}}, {});
        }
        // Final header check: exit
        tw.emit(ms, base + 4, enc::cmp_imm(1, (uint16_t)reps),
                {{33, tw.rt(base + 8)}}, {}, 0x4);
        tw.emit(ms, base + 8, enc::b_ge(24),
                {{33, tw.rt(base + 0x18)}}, {});

        // Block D: after loop
        tw.emit(ms, base + 0x18, enc::nop(),
                {{33, tw.rt(base + 0x1C)}}, {});

        tw.emit_anchor(ms);
    }, name);
}

TEST_CASE("TraceFoldPass: oscillating register is classified Oscillating even with equal endpoints",
          "[unit][pass][trace_fold]") {
    // Even number of reps -> x0 returns to its starting value (endpoints
    // equal), but it visibly swings +10/-10 every iteration along the way.
    auto env = make_oscillating_loop_trace(60, "tf_pattern_oscillating");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<TraceFoldPass>());

    auto& raw = pm->require("trace_fold");
    REQUIRE(raw.ok());
    auto& res = raw.get<TraceFoldResult>();
    REQUIRE_FALSE(res.folded_regions.empty());

    bool found_x0_oscillating = false;
    bool found_x1_monotonic = false;
    for (const auto& fr : res.folded_regions) {
        for (const auto& rc : fr.reg_changes) {
            if (rc.reg == 0 && rc.pattern == RegChangePattern::Oscillating) {
                found_x0_oscillating = true;
            }
            if (rc.reg == 1 && rc.pattern == RegChangePattern::Monotonic) {
                found_x1_monotonic = true;
            }
        }
    }
    // x0 must be reported (not silently dropped as "constant") and correctly
    // classified as oscillating despite first_val == last_val.
    REQUIRE(found_x0_oscillating);
    // x1 (the loop counter) is a sanity check that monotonic classification
    // still works correctly alongside the lazy interior-sample cache.
    REQUIRE(found_x1_monotonic);
}

TEST_CASE("TraceFoldPass: persisted cache round-trip returns an equivalent result",
          "[unit][pass][trace_fold]") {
    auto env = make_counter_loop_trace(40, "tf_cache_roundtrip");
    REQUIRE(env != nullptr);

    // First run: computes and persists the cache (range is full-trace by default).
    TraceFoldResult first;
    {
        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<XrefPass>());
        pm->register_pass(std::make_unique<CFGPass>());
        pm->register_pass(std::make_unique<LoopPass>());
        pm->register_pass(std::make_unique<TraceFoldPass>());
        auto& raw = pm->require("trace_fold");
        REQUIRE(raw.ok());
        first = raw.get<TraceFoldResult>();
    }

    // Second run: a fresh PassManager sharing the same TraceIndex (and thus
    // the same RocksDB-backed pass blob store) should hit the cache path.
    {
        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<XrefPass>());
        pm->register_pass(std::make_unique<CFGPass>());
        pm->register_pass(std::make_unique<LoopPass>());
        pm->register_pass(std::make_unique<TraceFoldPass>());
        auto& raw = pm->require("trace_fold");
        REQUIRE(raw.ok());
        auto& second = raw.get<TraceFoldResult>();

        REQUIRE(second.folded_regions.size() == first.folded_regions.size());
        REQUIRE(second.original_inst_count == first.original_inst_count);
        REQUIRE(second.folded_inst_count == first.folded_inst_count);
        REQUIRE(second.total_instructions_removed == first.total_instructions_removed);
        for (size_t i = 0; i < first.folded_regions.size(); i++) {
            REQUIRE(second.folded_regions[i].header_pc == first.folded_regions[i].header_pc);
            REQUIRE(second.folded_regions[i].first_inst_id == first.folded_regions[i].first_inst_id);
            REQUIRE(second.folded_regions[i].last_inst_id == first.folded_regions[i].last_inst_id);
            REQUIRE(second.folded_regions[i].reg_changes.size() == first.folded_regions[i].reg_changes.size());
        }
    }
}

TEST_CASE("TraceFoldPass: empty/linear trace (no loops) yields no folded regions",
          "[unit][pass][trace_fold]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 5; i++) {
            uint64_t spc = 0x1000 + i * 4;
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "tf_linear");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<TraceFoldPass>());

    auto& res = pm->require("trace_fold").get<TraceFoldResult>();
    REQUIRE(res.folded_regions.empty());
    REQUIRE(res.kept_ranges.size() <= 1);
    REQUIRE(res.folded_inst_count == res.original_inst_count);
}

TEST_CASE("TraceFoldPass: keep_iterations=0 does not read out of bounds",
          "[unit][pass][trace_fold]") {
    // Regression test: with keep=0, the previous implementation computed
    // `iteration_starts[n_iters - keep]` == `iteration_starts[n_iters]`,
    // one past the end of the vector (undefined behavior / potential crash
    // or garbage inst_id under ASan/UBSan). The pass must clamp keep to >= 1
    // internally so a caller-supplied 0 is always safe.
    auto env = make_counter_loop_trace(50, "tf_keep_zero");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());

    TraceFoldConfig cfg;
    cfg.keep_iterations = 0;  // caller asks to keep nothing — must be clamped, not crash
    pm->register_pass(std::make_unique<TraceFoldPass>(cfg));

    auto& raw = pm->require("trace_fold");
    REQUIRE(raw.ok());
    auto& res = raw.get<TraceFoldResult>();

    REQUIRE_FALSE(res.folded_regions.empty());
    SECTION("region bounds stay within the trace") {
        for (const auto& fr : res.folded_regions) {
            REQUIRE(fr.first_inst_id <= fr.last_inst_id);
            REQUIRE(fr.last_inst_id < res.original_inst_count);
        }
    }
    SECTION("accounting still balances (no OOB read corrupted the counts)") {
        REQUIRE(res.total_instructions_removed <= res.original_inst_count);
        uint64_t covered = 0;
        for (const auto& kr : res.kept_ranges) covered += (kr.end - kr.start + 1);
        for (const auto& fr : res.folded_regions) covered += fr.total_instructions_folded;
        REQUIRE(covered == res.original_inst_count);
    }
}

TEST_CASE("TraceFoldPass: non-default config bypasses the persisted cache",
          "[unit][pass][trace_fold]") {
    // Regression test: the cache blob only stores results, not the config
    // that produced them. Running once with default config (populating the
    // cache) and then again with a materially different config on the same
    // TraceIndex must NOT silently return the first run's (stale) result.
    auto env = make_counter_loop_trace(40, "tf_cache_cfg_mismatch");
    REQUIRE(env != nullptr);

    TraceFoldResult default_result;
    {
        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<XrefPass>());
        pm->register_pass(std::make_unique<CFGPass>());
        pm->register_pass(std::make_unique<LoopPass>());
        pm->register_pass(std::make_unique<TraceFoldPass>());  // default config
        auto& raw = pm->require("trace_fold");
        REQUIRE(raw.ok());
        default_result = raw.get<TraceFoldResult>();
    }

    // Second run: same TraceIndex, but a much higher min_iterations_to_fold
    // that should exclude the (only) loop entirely — if the cache were
    // incorrectly reused, this would still report the default run's folded
    // region instead of an empty result.
    {
        auto pm = make_pm(*env);
        pm->register_pass(std::make_unique<XrefPass>());
        pm->register_pass(std::make_unique<CFGPass>());
        pm->register_pass(std::make_unique<LoopPass>());

        TraceFoldConfig cfg;
        cfg.min_iterations_to_fold = 1000;  // the 40-iteration loop can't qualify
        pm->register_pass(std::make_unique<TraceFoldPass>(cfg));

        auto& raw = pm->require("trace_fold");
        REQUIRE(raw.ok());
        auto& res = raw.get<TraceFoldResult>();

        REQUIRE_FALSE(default_result.folded_regions.empty());  // sanity: default did fold something
        REQUIRE(res.folded_regions.empty());                   // custom config must NOT reuse stale cache
        REQUIRE(res.folded_inst_count == res.original_inst_count);
    }
}

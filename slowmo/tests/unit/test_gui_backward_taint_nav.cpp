/*
 * test_gui_backward_taint_nav.cpp — Unit tests for backward taint navigation.
 *
 * The GUI's jump_backward_taint_next/prev methods build a sorted list of
 * contributing instruction IDs from BackwardTaintResult on every call (O(N)
 * scan over total_inst_). The optimization caches this sorted list with a
 * dirty flag, mirroring the forward taint pattern (taint_sorted_ids_).
 *
 * These tests verify the core conversion + binary-search navigation pattern:
 *   1. Roaring64Map → sorted vector<uint64_t> conversion is correct
 *   2. upper_bound / lower_bound navigation matches expected next/prev behavior
 *   3. Wrap-around (last→first, first→last) works correctly
 *
 * This guards P1 item #8.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/taint/backward_taint_pass.h"

#include <algorithm>
#include <vector>

using namespace tenet;
using namespace tenet::test;

// ─── Helper: convert Roaring64Map to sorted vector (the pattern under test) ──

static std::vector<uint64_t> roaring_to_sorted(const roaring::Roaring64Map& bm) {
    std::vector<uint64_t> ids;
    ids.reserve(bm.cardinality());
    for (uint64_t id : bm) {
        ids.push_back(id);
    }
    // Roaring64Map iteration is already sorted, but sort for safety.
    std::sort(ids.begin(), ids.end());
    return ids;
}

// ─── Helper: simulate jump_backward_taint_next (upper_bound) ─────────────────

static uint64_t jump_next(const std::vector<uint64_t>& sorted, uint64_t current) {
    if (sorted.empty()) return current;
    auto it = std::upper_bound(sorted.begin(), sorted.end(), current);
    if (it == sorted.end()) return sorted.front();  // wrap around
    return *it;
}

// ─── Helper: simulate jump_backward_taint_prev (lower_bound - 1) ─────────────

static uint64_t jump_prev(const std::vector<uint64_t>& sorted, uint64_t current) {
    if (sorted.empty()) return current;
    auto it = std::lower_bound(sorted.begin(), sorted.end(), current);
    if (it == sorted.begin()) return sorted.back();  // wrap around
    --it;
    return *it;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("BackwardTaint Roaring64Map to sorted vector conversion",
          "[unit][gui][backward_taint_nav]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // inst 0: x1 = 0x42
        tw.emit(ms, 0x1000, enc::movz(1, 0x42),
                {{1, 0x42ULL}, {33, tw.rt(0x1004)}}, {});
        // inst 1: x0 = x1 (records x1 in diff as source)
        tw.emit(ms, 0x1004, enc::mov_reg(0, 1),
                {{0, 0x42ULL}, {1, 0x42ULL}, {33, tw.rt(0x1008)}}, {});
        // inst 2: x2 = 0x99 (unrelated)
        tw.emit(ms, 0x1008, enc::movz(2, 0x99),
                {{2, 0x99ULL}, {33, tw.rt(0x100C)}}, {});
        // inst 3: x3 = x0 (records x0 in diff as source)
        tw.emit(ms, 0x100C, enc::mov_reg(3, 0),
                {{3, 0x42ULL}, {0, 0x42ULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "btnav_convert");

    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    BackwardTaintConfig cfg;
    cfg.sink_inst_id = 4;
    cfg.add_sink_reg(3);  // x3
    cfg.use_index_acceleration = false;
    cfg.build_dataflow_graph = false;

    pm->register_pass(std::make_unique<BackwardTaintPass>(std::move(cfg)));
    auto& res = pm->require("backward_taint").get<BackwardTaintResult>();

    auto sorted = roaring_to_sorted(res.contributing_inst_ids);

    SECTION("sorted vector is non-empty") {
        REQUIRE_FALSE(sorted.empty());
    }

    SECTION("sorted vector is actually sorted") {
        for (size_t i = 1; i < sorted.size(); i++) {
            REQUIRE(sorted[i - 1] < sorted[i]);
        }
    }

    SECTION("sorted vector matches is_contributing") {
        for (uint64_t id : sorted) {
            REQUIRE(res.is_contributing(id));
        }
    }

    SECTION("every contributing id is in the sorted vector") {
        for (uint64_t id = 0; id < 4; id++) {
            bool in_sorted = (std::find(sorted.begin(), sorted.end(), id) != sorted.end());
            REQUIRE(in_sorted == res.is_contributing(id));
        }
    }
}

TEST_CASE("BackwardTaint navigation: jump_next with wrap-around",
          "[unit][gui][backward_taint_nav]") {
    // Simulate a backward taint result with contributing IDs: {1, 3, 5, 7}
    roaring::Roaring64Map bm;
    bm.add(uint64_t(1));
    bm.add(uint64_t(3));
    bm.add(uint64_t(5));
    bm.add(uint64_t(7));

    auto sorted = roaring_to_sorted(bm);
    REQUIRE(sorted.size() == 4);

    SECTION("jump_next from 0 → 1") {
        REQUIRE(jump_next(sorted, 0) == 1);
    }

    SECTION("jump_next from 1 → 3") {
        REQUIRE(jump_next(sorted, 1) == 3);
    }

    SECTION("jump_next from 2 → 3") {
        REQUIRE(jump_next(sorted, 2) == 3);
    }

    SECTION("jump_next from 6 → 7") {
        REQUIRE(jump_next(sorted, 6) == 7);
    }

    SECTION("jump_next from 7 wraps to 1") {
        REQUIRE(jump_next(sorted, 7) == 1);
    }

    SECTION("jump_next from 100 wraps to 1") {
        REQUIRE(jump_next(sorted, 100) == 1);
    }
}

TEST_CASE("BackwardTaint navigation: jump_prev with wrap-around",
          "[unit][gui][backward_taint_nav]") {
    roaring::Roaring64Map bm;
    bm.add(uint64_t(1));
    bm.add(uint64_t(3));
    bm.add(uint64_t(5));
    bm.add(uint64_t(7));

    auto sorted = roaring_to_sorted(bm);

    SECTION("jump_prev from 0 wraps to 7") {
        REQUIRE(jump_prev(sorted, 0) == 7);
    }

    SECTION("jump_prev from 1 wraps to 7") {
        REQUIRE(jump_prev(sorted, 1) == 7);
    }

    SECTION("jump_prev from 2 → 1") {
        REQUIRE(jump_prev(sorted, 2) == 1);
    }

    SECTION("jump_prev from 3 → 1") {
        REQUIRE(jump_prev(sorted, 3) == 1);
    }

    SECTION("jump_prev from 7 → 5") {
        REQUIRE(jump_prev(sorted, 7) == 5);
    }

    SECTION("jump_prev from 100 → 7") {
        REQUIRE(jump_prev(sorted, 100) == 7);
    }
}

TEST_CASE("BackwardTaint navigation: empty contributing set",
          "[unit][gui][backward_taint_nav]") {
    roaring::Roaring64Map bm;  // empty
    auto sorted = roaring_to_sorted(bm);

    SECTION("jump_next on empty returns current") {
        REQUIRE(jump_next(sorted, 5) == 5);
    }

    SECTION("jump_prev on empty returns current") {
        REQUIRE(jump_prev(sorted, 5) == 5);
    }
}

TEST_CASE("BackwardTaint navigation: single contributing instruction",
          "[unit][gui][backward_taint_nav]") {
    roaring::Roaring64Map bm;
    bm.add(uint64_t(42));

    auto sorted = roaring_to_sorted(bm);
    REQUIRE(sorted.size() == 1);

    SECTION("jump_next from 0 → 42") {
        REQUIRE(jump_next(sorted, 0) == 42);
    }

    SECTION("jump_next from 42 wraps to 42") {
        REQUIRE(jump_next(sorted, 42) == 42);
    }

    SECTION("jump_prev from 42 wraps to 42") {
        REQUIRE(jump_prev(sorted, 42) == 42);
    }
}

TEST_CASE("BackwardTaint cached list: dirty flag invalidation pattern",
          "[unit][gui][backward_taint_nav]") {
    // This test models the caching pattern:
    // 1. Build sorted list from result (dirty=true → rebuild)
    // 2. Navigate using cached list (dirty=false → no rebuild)
    // 3. Result changes → dirty=true → rebuild on next access

    roaring::Roaring64Map bm1;
    bm1.add(uint64_t(1));
    bm1.add(uint64_t(3));
    bm1.add(uint64_t(5));

    bool dirty = true;
    std::vector<uint64_t> cached;

    // First access: build cache
    if (dirty) {
        cached = roaring_to_sorted(bm1);
        dirty = false;
    }
    REQUIRE(cached.size() == 3);
    REQUIRE(jump_next(cached, 0) == 1);

    // Second access: use cache (no rebuild)
    REQUIRE_FALSE(dirty);
    REQUIRE(jump_next(cached, 2) == 3);

    // Result changes → dirty
    dirty = true;
    roaring::Roaring64Map bm2;
    bm2.add(uint64_t(10));
    bm2.add(uint64_t(20));
    bm2.add(uint64_t(30));

    // Next access: rebuild cache
    if (dirty) {
        cached = roaring_to_sorted(bm2);
        dirty = false;
    }
    REQUIRE(cached.size() == 3);
    REQUIRE(jump_next(cached, 0) == 10);
    REQUIRE(jump_next(cached, 15) == 20);
}

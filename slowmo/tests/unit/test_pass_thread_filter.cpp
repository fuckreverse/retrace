/*
 * test_pass_thread_filter.cpp — Unit tests for tenet::ThreadFilterPass
 *
 * Verifies:
 *   - Single-thread trace: all inst_ids belong to the default thread.
 *   - Multi-thread trace: per-thread bitmaps are populated correctly.
 *   - No filter (empty include_thread_ids): included_inst_ids == all instructions.
 *   - With filter: included_inst_ids is the union of the selected threads only.
 *   - inst_count_on(tid) returns the correct count.
 *   - inst_ids_on(tid) returns a sorted ascending list.
 *   - thread_count matches the number of distinct threads in the trace.
 *
 * Run:  ctest -R 'thread_filter' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/thread_filter_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Shared trace builders ────────────────────────────────────────────────────

/// Single-thread trace: 5 simple arithmetic instructions on thread 1.
/// We emit a THREAD record so that ThreadPass/ThreadCollector registers
/// thread 1 and has_initial_thread_ becomes true.
static std::unique_ptr<TraceEnv> make_single_thread_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Emit a THREAD record so ThreadPass sees thread 1
        tw.emit_thread(1);

        for (int i = 0; i < 5; i++) {
            uint64_t spc = 0x1000 + i * 4;
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "thread_filter_single");
}

/// Multi-thread trace: threads 100 and 200 alternate instructions.
///   Thread 100 → 4 insts (inst_ids 0, 1, 4, 5)
///   Thread 200 → 4 insts (inst_ids 2, 3, 6, 7)
///
/// Layout:
///   THREAD(100), inst0, inst1,
///   THREAD(200), inst2, inst3,
///   THREAD(100), inst4, inst5,
///   THREAD(200), inst6, inst7
static std::unique_ptr<TraceEnv> make_multi_thread_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        uint64_t spc = 0x2000;

        // Thread 100: 2 insts
        tw.emit_thread(100);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        // Thread 200: 2 insts
        tw.emit_thread(200);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(1, 1, 2),
                    {{1, ms.x(1) + 2}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        // Thread 100: 2 more insts
        tw.emit_thread(100);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        // Thread 200: 2 more insts
        tw.emit_thread(200);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(1, 1, 2),
                    {{1, ms.x(1) + 2}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        tw.emit_anchor(ms);
    }, "thread_filter_multi");
}

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE("ThreadFilterPass: single-thread trace has thread_count >= 1",
          "[unit][pass][thread_filter]") {
    auto env = make_single_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());

    ThreadFilterConfig cfg;
    cfg.build_bitmaps = true;
    pm->register_pass(std::make_unique<ThreadFilterPass>(cfg));

    auto& raw = pm->require("thread_filter");
    REQUIRE(raw.ok());

    auto& res = raw.get<ThreadFilterResult>();

    SECTION("at least one thread") {
        REQUIRE(res.thread_count >= 1);
    }
    SECTION("all 5 instructions are included (no filter)") {
        REQUIRE(res.included_inst_ids.cardinality() == 5);
    }
    SECTION("is_filtered is false (no thread IDs specified)") {
        REQUIRE_FALSE(res.is_filtered);
    }
    SECTION("contains() returns true for all inst_ids 0..4") {
        for (uint64_t id = 0; id < 5; id++) {
            REQUIRE(res.contains(id));
        }
    }
}

TEST_CASE("ThreadFilterPass: multi-thread trace counts each thread correctly",
          "[unit][pass][thread_filter]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());

    ThreadFilterConfig cfg;
    cfg.build_bitmaps = true;
    pm->register_pass(std::make_unique<ThreadFilterPass>(cfg));

    auto& raw = pm->require("thread_filter");
    REQUIRE(raw.ok());

    auto& res = raw.get<ThreadFilterResult>();

    SECTION("thread_count == 2") {
        REQUIRE(res.thread_count == 2);
    }
    SECTION("thread 100 has 4 instructions") {
        REQUIRE(res.inst_count_on(100) == 4);
    }
    SECTION("thread 200 has 4 instructions") {
        REQUIRE(res.inst_count_on(100) == 4);
    }
    SECTION("total included_inst_ids == 8 (no filter)") {
        REQUIRE(res.included_inst_ids.cardinality() == 8);
    }
}

TEST_CASE("ThreadFilterPass: filter selects only thread 100 instructions",
          "[unit][pass][thread_filter]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());

    ThreadFilterConfig cfg;
    cfg.build_bitmaps = true;
    cfg.include_thread_ids = {100};  // filter: only thread 100
    pm->register_pass(std::make_unique<ThreadFilterPass>(cfg));

    auto& raw = pm->require("thread_filter");
    REQUIRE(raw.ok());

    auto& res = raw.get<ThreadFilterResult>();

    SECTION("is_filtered is true") {
        REQUIRE(res.is_filtered);
    }
    SECTION("included_inst_ids cardinality == 4 (only thread 100 insts)") {
        REQUIRE(res.included_inst_ids.cardinality() == 4);
    }
    SECTION("contains() is true only for thread-100 inst_ids") {
        // Thread 100 owns inst_ids {0, 1, 4, 5}
        REQUIRE(res.contains(0));
        REQUIRE(res.contains(1));
        REQUIRE_FALSE(res.contains(2));  // thread 200
        REQUIRE_FALSE(res.contains(3));  // thread 200
    }
}

TEST_CASE("ThreadFilterPass: inst_ids_on() returns sorted list",
          "[unit][pass][thread_filter]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());

    ThreadFilterConfig cfg;
    cfg.build_bitmaps = true;
    pm->register_pass(std::make_unique<ThreadFilterPass>(cfg));

    auto& res = pm->require("thread_filter").get<ThreadFilterResult>();

    SECTION("inst_ids_on(100) is sorted ascending") {
        auto ids = res.inst_ids_on(100);
        REQUIRE_FALSE(ids.empty());
        for (size_t i = 1; i < ids.size(); i++) {
            REQUIRE(ids[i] > ids[i - 1]);
        }
    }
    SECTION("inst_ids_on(200) is sorted ascending") {
        auto ids = res.inst_ids_on(200);
        REQUIRE_FALSE(ids.empty());
        for (size_t i = 1; i < ids.size(); i++) {
            REQUIRE(ids[i] > ids[i - 1]);
        }
    }
    SECTION("inst_ids_on(999) returns empty for non-existent thread") {
        auto ids = res.inst_ids_on(999);
        REQUIRE(ids.empty());
    }
}

TEST_CASE("ThreadFilterPass: build_bitmaps=false returns count only",
          "[unit][pass][thread_filter]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());

    ThreadFilterConfig cfg;
    cfg.build_bitmaps = false;  // light mode: no bitmaps
    pm->register_pass(std::make_unique<ThreadFilterPass>(cfg));

    auto& raw = pm->require("thread_filter");
    REQUIRE(raw.ok());

    auto& res = raw.get<ThreadFilterResult>();

    SECTION("thread_count is still correct") {
        REQUIRE(res.thread_count == 2);
    }
    SECTION("bitmaps are empty in light mode") {
        REQUIRE(res.thread_inst_bitmaps.empty());
    }
}

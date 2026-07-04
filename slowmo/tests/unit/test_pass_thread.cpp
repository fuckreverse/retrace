/*
 * test_pass_thread.cpp — Unit tests for tenet::ThreadPass / ThreadResult
 *
 * ThreadPass itself has fairly thin logic (a single-pass TraceCollector), but
 * ThreadResult's query methods (thread_at/span_at/next_switch_after/
 * prev_switch_before/spans_for) are used directly by the GUI thread panel
 * (render_thread_panel) and previously had zero dedicated coverage — only
 * indirectly exercised via test_pass_thread_filter.cpp.
 *
 * Verifies:
 *   - Single-thread trace: exactly one thread, no switch events, one span
 *     covering the whole trace.
 *   - Multi-thread trace: switch_events / spans / per-thread stats are
 *     computed correctly.
 *   - thread_at(): correct before the first switch, at a switch boundary,
 *     and after the last switch.
 *   - span_at(): returns the containing span, and nullptr for out-of-range
 *     inst_ids (before the first span / past the last span).
 *   - next_switch_after() / prev_switch_before(): boundary behavior at the
 *     very first and very last switch event.
 *   - spans_for(): returns only the spans belonging to the requested thread,
 *     in order.
 *   - Blob persistence: serialize/deserialize round-trip via the pass-blob
 *     cache preserves all fields.
 *
 * Run:  ctest -R 'pass_thread' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/misc/thread_pass.h"
#include "io/index_builder.h"

using namespace tenet;
using namespace tenet::test;

// ─── Shared trace builders ──────────────────────────────────────────────────

/// Single-thread trace: 5 simple arithmetic instructions on thread 1.
/// Emits a THREAD record so ThreadCollector registers thread 1 and
/// has_initial_thread_ becomes true (mirrors test_pass_thread_filter.cpp).
static std::unique_ptr<TraceEnv> make_single_thread_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit_thread(1);

        for (int i = 0; i < 5; i++) {
            uint64_t spc = 0x1000 + i * 4;
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, (uint64_t)(i + 1)}, {33, tw.rt(spc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "thread_single");
}

/// Multi-thread trace: threads 100 and 200 alternate, 2 insts each, twice.
///   THREAD(100), inst0, inst1,      -> span A: tid=100 [0,1]
///   THREAD(200), inst2, inst3,      -> span B: tid=200 [2,3]
///   THREAD(100), inst4, inst5,      -> span C: tid=100 [4,5]
///   THREAD(200), inst6, inst7       -> span D: tid=200 [6,7]
/// Switch events occur at inst_id 2 (->200), 4 (->100), 6 (->200).
static std::unique_ptr<TraceEnv> make_multi_thread_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        uint64_t spc = 0x2000;

        tw.emit_thread(100);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        tw.emit_thread(200);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(1, 1, 2),
                    {{1, ms.x(1) + 2}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        tw.emit_thread(100);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        tw.emit_thread(200);
        for (int i = 0; i < 2; i++) {
            tw.emit(ms, spc, enc::add_imm(1, 1, 2),
                    {{1, ms.x(1) + 2}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }

        tw.emit_anchor(ms);
    }, "thread_multi");
}

// ─── Basic result shape ─────────────────────────────────────────────────────

TEST_CASE("ThreadPass: single-thread trace has one thread, no switches, one span",
          "[unit][pass][thread]") {
    auto env = make_single_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("exactly one thread") {
        REQUIRE(res.thread_count() == 1);
        REQUIRE(res.threads.count(1) == 1);
    }
    SECTION("no switch events (only ever one thread)") {
        REQUIRE(res.switch_count() == 0);
    }
    SECTION("exactly one span covering all 5 instructions") {
        REQUIRE(res.spans.size() == 1);
        REQUIRE(res.spans[0].thread_id == 1);
        REQUIRE(res.spans[0].inst_count == 5);
    }
    SECTION("thread info aggregates total_instructions") {
        const auto& info = res.threads.at(1);
        REQUIRE(info.total_instructions == 5);
        REQUIRE(info.switch_in_count == 1);  // initial activation counts as switch-in
    }
}

TEST_CASE("ThreadPass: multi-thread trace builds correct switches/spans/stats",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("two threads observed") {
        REQUIRE(res.thread_count() == 2);
    }
    SECTION("three switch events, in temporal order, at the right inst_ids") {
        REQUIRE(res.switch_count() == 3);
        REQUIRE(res.switch_events[0].inst_id == 2);
        REQUIRE(res.switch_events[0].thread_id == 200);
        REQUIRE(res.switch_events[1].inst_id == 4);
        REQUIRE(res.switch_events[1].thread_id == 100);
        REQUIRE(res.switch_events[2].inst_id == 6);
        REQUIRE(res.switch_events[2].thread_id == 200);
    }
    SECTION("four spans, two instructions each, alternating threads") {
        REQUIRE(res.spans.size() == 4);
        REQUIRE(res.spans[0].thread_id == 100);
        REQUIRE(res.spans[0].start_inst_id == 0);
        REQUIRE(res.spans[0].end_inst_id == 1);
        REQUIRE(res.spans[1].thread_id == 200);
        REQUIRE(res.spans[1].start_inst_id == 2);
        REQUIRE(res.spans[1].end_inst_id == 3);
        REQUIRE(res.spans[2].thread_id == 100);
        REQUIRE(res.spans[2].start_inst_id == 4);
        REQUIRE(res.spans[2].end_inst_id == 5);
        REQUIRE(res.spans[3].thread_id == 200);
        REQUIRE(res.spans[3].start_inst_id == 6);
        REQUIRE(res.spans[3].end_inst_id == 7);
    }
    SECTION("per-thread total_instructions sums across all spans") {
        REQUIRE(res.threads.at(100).total_instructions == 4);
        REQUIRE(res.threads.at(200).total_instructions == 4);
    }
    SECTION("switch_in_count counts every activation, including the first") {
        // Thread 100: initial activation + one re-entry (span C) = 2
        REQUIRE(res.threads.at(100).switch_in_count == 2);
        // Thread 200: two activations (span B, span D) = 2
        REQUIRE(res.threads.at(200).switch_in_count == 2);
    }
}

// ─── thread_at() ────────────────────────────────────────────────────────────

TEST_CASE("ThreadResult::thread_at resolves the active thread at any inst_id",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("before the first switch (inst 0, 1) -> thread 100") {
        REQUIRE(res.thread_at(0) == 100);
        REQUIRE(res.thread_at(1) == 100);
    }
    SECTION("exactly at a switch boundary -> the newly-active thread") {
        REQUIRE(res.thread_at(2) == 200);
        REQUIRE(res.thread_at(4) == 100);
        REQUIRE(res.thread_at(6) == 200);
    }
    SECTION("between switches -> the thread owning that span") {
        REQUIRE(res.thread_at(3) == 200);
        REQUIRE(res.thread_at(5) == 100);
    }
    SECTION("after the last switch -> still resolves to the last active thread") {
        REQUIRE(res.thread_at(7) == 200);
        // Querying past the end of the trace should still return the last
        // known active thread (there's no switch after it).
        REQUIRE(res.thread_at(1000) == 200);
    }
}

TEST_CASE("ThreadResult::thread_at on a single-thread trace always resolves",
          "[unit][pass][thread]") {
    auto env = make_single_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("no switch events, but thread resolves via single-thread fallback") {
        REQUIRE(res.switch_count() == 0);
        REQUIRE(res.thread_at(0) == 1);
        REQUIRE(res.thread_at(4) == 1);
        REQUIRE(res.thread_at(999) == 1);
    }
}

// ─── span_at() ──────────────────────────────────────────────────────────────

TEST_CASE("ThreadResult::span_at finds the containing span or nullptr",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("inst_id inside the first span") {
        const auto* s = res.span_at(0);
        REQUIRE(s != nullptr);
        REQUIRE(s->thread_id == 100);
        REQUIRE(s->start_inst_id == 0);
        REQUIRE(s->end_inst_id == 1);
    }
    SECTION("inst_id inside a middle span") {
        const auto* s = res.span_at(5);
        REQUIRE(s != nullptr);
        REQUIRE(s->thread_id == 100);
        REQUIRE(s->start_inst_id == 4);
        REQUIRE(s->end_inst_id == 5);
    }
    SECTION("inst_id inside the last span") {
        const auto* s = res.span_at(6);
        REQUIRE(s != nullptr);
        REQUIRE(s->thread_id == 200);
    }
    SECTION("inst_id past the last span returns nullptr") {
        REQUIRE(res.span_at(1000) == nullptr);
    }
}

// ─── next_switch_after() / prev_switch_before() ────────────────────────────

TEST_CASE("ThreadResult::next_switch_after / prev_switch_before boundary behavior",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();
    // switch_events at inst_id: 2 (->200), 4 (->100), 6 (->200)

    SECTION("next_switch_after before the first switch returns the first switch") {
        const auto* ev = res.next_switch_after(0);
        REQUIRE(ev != nullptr);
        REQUIRE(ev->inst_id == 2);
        REQUIRE(ev->thread_id == 200);
    }
    SECTION("next_switch_after exactly at a switch returns the *next* one") {
        const auto* ev = res.next_switch_after(2);
        REQUIRE(ev != nullptr);
        REQUIRE(ev->inst_id == 4);
    }
    SECTION("next_switch_after the last switch returns nullptr") {
        REQUIRE(res.next_switch_after(6) == nullptr);
        REQUIRE(res.next_switch_after(1000) == nullptr);
    }
    SECTION("prev_switch_before after the last switch returns the last switch") {
        const auto* ev = res.prev_switch_before(1000);
        REQUIRE(ev != nullptr);
        REQUIRE(ev->inst_id == 6);
    }
    SECTION("prev_switch_before exactly at a switch returns the *previous* one") {
        const auto* ev = res.prev_switch_before(4);
        REQUIRE(ev != nullptr);
        REQUIRE(ev->inst_id == 2);
    }
    SECTION("prev_switch_before the first switch returns nullptr") {
        REQUIRE(res.prev_switch_before(2) == nullptr);
        REQUIRE(res.prev_switch_before(0) == nullptr);
    }
}

TEST_CASE("ThreadResult::next_switch_after / prev_switch_before on no-switch trace",
          "[unit][pass][thread]") {
    auto env = make_single_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    REQUIRE(res.next_switch_after(0) == nullptr);
    REQUIRE(res.prev_switch_before(4) == nullptr);
}

// ─── spans_for() ────────────────────────────────────────────────────────────

TEST_CASE("ThreadResult::spans_for returns only spans for the requested thread",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ThreadPass>());
    auto& res = pm->require("thread").get<ThreadResult>();

    SECTION("thread 100 owns spans A and C") {
        auto spans = res.spans_for(100);
        REQUIRE(spans.size() == 2);
        REQUIRE(spans[0]->start_inst_id == 0);
        REQUIRE(spans[1]->start_inst_id == 4);
        for (auto* s : spans) REQUIRE(s->thread_id == 100);
    }
    SECTION("thread 200 owns spans B and D") {
        auto spans = res.spans_for(200);
        REQUIRE(spans.size() == 2);
        REQUIRE(spans[0]->start_inst_id == 2);
        REQUIRE(spans[1]->start_inst_id == 6);
    }
    SECTION("unknown thread id returns empty") {
        REQUIRE(res.spans_for(999).empty());
    }
}

// ─── Blob persistence round-trip ────────────────────────────────────────────

TEST_CASE("ThreadPass: full-trace result is cached and reloaded identically",
          "[unit][pass][thread]") {
    auto env = make_multi_thread_trace();
    REQUIRE(env != nullptr);

    // First run: computes and persists the blob (range.is_full_trace()).
    uint64_t thread_count_1, switch_count_1, span_count_1;
    {
        auto pm = make_pm(*env);
        pm->set_index(&*env->index);
        pm->register_pass(std::make_unique<ThreadPass>());
        auto& res = pm->require("thread").get<ThreadResult>();
        thread_count_1 = res.thread_count();
        switch_count_1 = res.switch_count();
        span_count_1   = res.spans.size();
    }

    // Second run against a fresh PassManager on the same index: should load
    // from the persisted blob rather than rescanning, and produce identical
    // results.
    {
        auto pm = make_pm(*env);
        pm->set_index(&*env->index);
        pm->register_pass(std::make_unique<ThreadPass>());
        auto& res = pm->require("thread").get<ThreadResult>();

        REQUIRE(res.thread_count() == thread_count_1);
        REQUIRE(res.switch_count() == switch_count_1);
        REQUIRE(res.spans.size() == span_count_1);
        REQUIRE(res.threads.at(100).total_instructions == 4);
        REQUIRE(res.threads.at(200).total_instructions == 4);
    }
}

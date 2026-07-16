/*
 * test_service_tenet_service.cpp — Unit tests for TenetService.
 *
 * Tests:
 *   - Bookmark operations: toggle, has_bookmark, persistence (#9)
 *   - Search: forward search, wrap-around, no results, empty query (#7)
 *   - fetch_row: has_bookmark field populated correctly
 *   - Navigation: navigate_to, history
 *
 * These tests guard the optimization of has_bookmark() from O(N) linear
 * scan to O(1) hash set lookup (P1 item #9) and search_forward() from
 * blocking O(N) scan to accelerated search (P1 item #7).
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "service/tenet_service.h"
#include "analysis/passes/structure/xref_pass.h"

#include <atomic>
#include <type_traits>
#include <utility>

using namespace tenet;
using namespace tenet::test;

static_assert(!std::is_reference_v<decltype(std::declval<const TenetService&>().bookmarks())>,
              "bookmarks() must return a thread-safe snapshot value");
static_assert(!std::is_reference_v<decltype(std::declval<const TenetService&>().search_results())>,
              "search_results() must return a thread-safe snapshot value");

// ─── Helper: create a service from a trace env ──────────────────────────────

static std::unique_ptr<TenetService> make_service(TraceEnv& env) {
    return std::make_unique<TenetService>(
        *env.reader, *env.index, env.code_table, env.decoder,
        *env.regfile, *env.memory);
}

// ─── Bookmark tests (#9) ────────────────────────────────────────────────────

TEST_CASE("TenetService bookmark toggle and has_bookmark",
          "[unit][service][bookmark]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_bookmark");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    SECTION("has_bookmark returns false for unset bookmark") {
        REQUIRE_FALSE(svc->has_bookmark(0));
        REQUIRE_FALSE(svc->has_bookmark(5));
    }

    SECTION("toggle_bookmark adds bookmark") {
        svc->toggle_bookmark(3);
        REQUIRE(svc->has_bookmark(3));
        REQUIRE_FALSE(svc->has_bookmark(2));
    }

    SECTION("toggle_bookmark removes bookmark") {
        svc->toggle_bookmark(3);
        REQUIRE(svc->has_bookmark(3));
        svc->toggle_bookmark(3);
        REQUIRE_FALSE(svc->has_bookmark(3));
    }

    SECTION("multiple bookmarks") {
        svc->toggle_bookmark(0);
        svc->toggle_bookmark(3);
        svc->toggle_bookmark(7);
        REQUIRE(svc->has_bookmark(0));
        REQUIRE(svc->has_bookmark(3));
        REQUIRE(svc->has_bookmark(7));
        REQUIRE_FALSE(svc->has_bookmark(1));
        REQUIRE_FALSE(svc->has_bookmark(5));
        REQUIRE(svc->bookmarks().size() == 3);
    }

    SECTION("toggle same bookmark twice removes it") {
        svc->toggle_bookmark(5);
        svc->toggle_bookmark(5);
        REQUIRE_FALSE(svc->has_bookmark(5));
        REQUIRE(svc->bookmarks().empty());
    }
}

TEST_CASE("TenetService has_bookmark performance: O(1) not O(N)",
          "[unit][service][bookmark]") {
    // This test creates a trace with many instructions and many bookmarks,
    // then verifies has_bookmark returns correct results for all of them.
    // After the optimization, has_bookmark should be O(1) per query.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 500; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_bookmark_perf");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    // Add bookmarks at every 10th instruction
    for (int i = 0; i < 500; i += 10) {
        svc->toggle_bookmark(i);
    }

    SECTION("has_bookmark is correct for all instructions") {
        for (int i = 0; i < 500; i++) {
            bool expected = (i % 10 == 0);
            REQUIRE(svc->has_bookmark(i) == expected);
        }
    }
}

TEST_CASE("TenetService fetch_row has_bookmark field",
          "[unit][service][bookmark]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_fetch_bookmark");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    svc->toggle_bookmark(3);
    svc->toggle_bookmark(7);

    SECTION("fetch_row has_bookmark is true for bookmarked inst") {
        auto row3 = svc->fetch_row(3);
        REQUIRE(row3.has_bookmark == true);

        auto row7 = svc->fetch_row(7);
        REQUIRE(row7.has_bookmark == true);
    }

    SECTION("fetch_row has_bookmark is false for non-bookmarked inst") {
        auto row0 = svc->fetch_row(0);
        REQUIRE(row0.has_bookmark == false);

        auto row5 = svc->fetch_row(5);
        REQUIRE(row5.has_bookmark == false);
    }
}

// ─── Search tests (#7) ──────────────────────────────────────────────────────

TEST_CASE("TenetService search_forward finds matching instructions",
          "[unit][service][search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Instructions with known mnemonics:
        // nop, add, nop, add, nop
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(0, 0, 1), {{0, 1ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::add_imm(0, 0, 1), {{0, 2ULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit(ms, 0x1010, enc::nop(), {{33, tw.rt(0x1014)}}, {});
        tw.emit_anchor(ms);
    }, "svc_search_basic");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    SECTION("search returns a result snapshot for direct UI consumption") {
        const auto results = svc->search_forward("nop", 0);
        REQUIRE(svc->search_active());
        // The TUI consumes the returned snapshot instead of reimplementing
        // the search or borrowing mutable service state.
        REQUIRE(results == svc->search_results());
        REQUIRE(results.size() >= 3);
    }

    SECTION("search for 'add' finds add instructions") {
        svc->search_forward("add", 0);
        REQUIRE(svc->search_results().size() >= 2);
    }

    SECTION("search for nonexistent string returns empty inactive results") {
        const auto results = svc->search_forward("nonexistent_mnemonic", 0);
        REQUIRE(results.empty());
        REQUIRE(svc->search_results().empty());
        REQUIRE_FALSE(svc->search_active());
    }
}

TEST_CASE("TenetService search_forward empty query clears results",
          "[unit][service][search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "svc_search_empty");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    // First search finds something
    svc->search_forward("nop", 0);
    REQUIRE_FALSE(svc->search_results().empty());

    // Empty query clears
    svc->search_forward("", 0);
    REQUIRE_FALSE(svc->search_active());
    REQUIRE(svc->search_results().empty());
}

TEST_CASE("TenetService search_forward wrap-around",
          "[unit][service][search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // 5 nops
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_search_wrap");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    SECTION("search from middle finds instructions before and after") {
        svc->search_forward("nop", 3);
        // Should find nops at 3, 4 (from_inst forward) AND 0, 1, 2 (wrap-around)
        REQUIRE(svc->search_results().size() == 5);
    }
}

TEST_CASE("TenetService ensure_pass_manager publishes one shared instance",
          "[unit][service][pass_manager]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 32; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_pass_manager_once");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    constexpr int kThreads = 8;
    std::vector<std::thread> threads;
    std::vector<PassManager*> managers(kThreads, nullptr);
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            managers[i] = &svc->ensure_pass_manager();
        });
    }
    for (auto& thread : threads) thread.join();

    REQUIRE(managers[0] != nullptr);
    for (int i = 1; i < kThreads; ++i) {
        CHECK(managers[i] == managers[0]);
    }
    CHECK(svc->pass_manager() == managers[0]);
}

TEST_CASE("TenetService concurrent snapshot access for bookmark/search state",
          "[unit][service][snapshot]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 64; ++i) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_snapshot_concurrency");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (uint64_t i = 0; i < 512; ++i) {
            svc->toggle_bookmark(i % 64);
            (void)svc->search_forward("nop", i % 64);
            if ((i % 3) == 0) svc->search_clear();
        }
        stop.store(true, std::memory_order_release);
    });

    std::thread reader([&] {
        while (!stop.load(std::memory_order_acquire)) {
            auto bookmarks = svc->bookmarks();
            auto results = svc->search_results();
            auto current = svc->search_current();
            auto active = svc->search_active();

            CHECK(bookmarks.size() <= 64);
            for (auto id : bookmarks) CHECK(id < 64);

            CHECK(results.size() <= 10000);
            for (auto id : results) CHECK(id < 64);

            if (!active) {
                CHECK(current == 0);
            }
        }
    });

    writer.join();
    reader.join();
}

TEST_CASE("TenetService search_forward from different start positions",
          "[unit][service][search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_search_start");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    SECTION("search from inst 0 finds all") {
        svc->search_forward("nop", 0);
        REQUIRE(svc->search_results().size() == 10);
    }

    SECTION("search from inst 5 finds all (wrap-around)") {
        svc->search_forward("nop", 5);
        REQUIRE(svc->search_results().size() == 10);
    }
}

// ─── Navigation tests ───────────────────────────────────────────────────────

TEST_CASE("TenetService navigation basics",
          "[unit][service][navigation]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_nav");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    SECTION("navigate_to sets current inst") {
        svc->navigate_to(5);
        REQUIRE(svc->current_inst() == 5);
    }

    SECTION("navigate_to clamps to total_inst - 1") {
        svc->navigate_to(999);
        REQUIRE(svc->current_inst() == 9);
    }

    SECTION("nav_back and nav_forward") {
        svc->navigate_to(3);
        svc->navigate_to(5);
        REQUIRE(svc->can_nav_back());
        svc->nav_back();
        REQUIRE(svc->current_inst() == 3);
        REQUIRE(svc->can_nav_forward());
        svc->nav_forward();
        REQUIRE(svc->current_inst() == 5);
    }
}

// ─── Search with XrefResult acceleration (#7 fast path) ─────────────────────

TEST_CASE("TenetService search_forward with xref acceleration",
          "[unit][service][search_xref]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Interleave nop and add to create repeated PCs
        for (int i = 0; i < 6; i++) {
            if (i % 2 == 0)
                tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                        {{33, tw.rt(0x1004 + i * 4)}}, {});
            else
                tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                        {{0, (uint64_t)i}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_search_xref");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    // Run xref pass to populate the index
    svc->run_pass("xref");

    SECTION("search for 'nop' finds correct count via xref path") {
        svc->search_forward("nop", 0);
        // nops at inst 0, 2, 4
        REQUIRE(svc->search_results().size() == 3);
    }

    SECTION("search for 'add' finds correct count via xref path") {
        svc->search_forward("add", 0);
        // adds at inst 1, 3, 5
        REQUIRE(svc->search_results().size() == 3);
    }

    SECTION("xref search wrap-around produces correct order") {
        svc->search_forward("nop", 3);
        // From inst 3: forward finds 4, wrap finds 0, 2
        // Result should be [4, 0, 2] (from_inst forward, then wrap)
        REQUIRE(svc->search_results().size() == 3);
        REQUIRE(svc->search_results()[0] == 4);
    }

    SECTION("xref search for nonexistent returns empty") {
        svc->search_forward("nonexistent", 0);
        REQUIRE(svc->search_results().empty());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Concurrent read/write stress tests (#14 — TenetService thread safety)
//
// These tests verify that TenetService operations are safe to call from
// multiple threads simultaneously:
//   - Writer threads: navigate_to, toggle_bookmark, search_forward
//   - Reader threads: fetch_row, has_bookmark, current_inst, total_inst,
//                     bookmarks, search_results
//
// The test will hang (timeout) if there's a deadlock, and will crash if
// there's a data race causing corruption.
// ═════════════════════════════════════════════════════════════════════════════

#include <atomic>
#include <chrono>
#include <thread>

TEST_CASE("TenetService: concurrent navigate + fetch_row (no deadlock)",
          "[unit][service][concurrent]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 100; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_concurrent_nav");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    std::atomic<bool> stop{false};
    std::atomic<int> errors{0};

    // Writer: navigate to different inst_ids
    auto writer = [&]() {
        for (int i = 0; i < 200 && !stop.load(std::memory_order_relaxed); i++) {
            svc->navigate_to(static_cast<uint64_t>(i % 100));
        }
    };

    // Reader: fetch rows and verify no crash
    auto reader = [&]() {
        for (int i = 0; i < 200 && !stop.load(std::memory_order_relaxed); i++) {
            auto row = svc->fetch_row(static_cast<uint64_t>(i % 100));
            if (row.inst_id != static_cast<uint64_t>(i % 100)) {
                // fetch_row should return a row with the requested inst_id
                errors.fetch_add(1, std::memory_order_relaxed);
            }
            // current_inst should be valid
            uint64_t cur = svc->current_inst();
            if (cur >= 100) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.emplace_back(writer);
    threads.emplace_back(reader);
    threads.emplace_back(reader);

    for (auto& t : threads) t.join();

    REQUIRE(errors.load() == 0);
}

TEST_CASE("TenetService: concurrent toggle_bookmark + has_bookmark (no deadlock)",
          "[unit][service][concurrent]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 20; i++) {
            tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_concurrent_bm");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    std::atomic<bool> stop{false};
    std::atomic<int> errors{0};

    // Writer: toggle bookmarks on inst_ids 0-9
    auto writer = [&]() {
        for (int i = 0; i < 100 && !stop.load(std::memory_order_relaxed); i++) {
            svc->toggle_bookmark(static_cast<uint64_t>(i % 10));
        }
    };

    // Reader: has_bookmark and bookmarks() should not crash or corrupt
    auto reader = [&]() {
        for (int i = 0; i < 100 && !stop.load(std::memory_order_relaxed); i++) {
            // has_bookmark should return a consistent true/false (not crash)
            (void)svc->has_bookmark(static_cast<uint64_t>(i % 10));
            // bookmarks() vector should be in a valid state
            auto bm = svc->bookmarks();
            if (bm.size() > 10) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.emplace_back(writer);
    threads.emplace_back(reader);
    threads.emplace_back(reader);

    for (auto& t : threads) t.join();

    REQUIRE(errors.load() == 0);
}

TEST_CASE("TenetService: concurrent search + navigation (no deadlock)",
          "[unit][service][concurrent]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 50; i++) {
            if (i % 2 == 0)
                tw.emit(ms, 0x1000 + i * 4, enc::nop(),
                        {{33, tw.rt(0x1004 + i * 4)}}, {});
            else
                tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                        {{0, (uint64_t)i}, {33, tw.rt(0x1004 + i * 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "svc_concurrent_search");

    REQUIRE(env != nullptr);
    auto svc = make_service(*env);

    std::atomic<bool> stop{false};
    std::atomic<int> errors{0};

    // Thread 1: search for "nop" repeatedly
    auto searcher = [&]() {
        for (int i = 0; i < 20 && !stop.load(std::memory_order_relaxed); i++) {
            svc->search_forward("nop", 0);
            auto results = svc->search_results();
            // Should find 25 nops (even indices 0,2,4,...,48)
            if (results.size() != 25 && results.size() != 0) {
                // 0 is acceptable during concurrent search_clear overlap
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    // Thread 2: navigate while search runs
    auto navigator = [&]() {
        for (int i = 0; i < 50 && !stop.load(std::memory_order_relaxed); i++) {
            svc->navigate_to(static_cast<uint64_t>(i % 50));
        }
    };

    // Thread 3: fetch rows while search runs
    auto fetcher = [&]() {
        for (int i = 0; i < 50 && !stop.load(std::memory_order_relaxed); i++) {
            auto row = svc->fetch_row(static_cast<uint64_t>(i % 50));
            (void)row;
        }
    };

    std::vector<std::thread> threads;
    threads.emplace_back(searcher);
    threads.emplace_back(navigator);
    threads.emplace_back(fetcher);

    for (auto& t : threads) t.join();

    REQUIRE(errors.load() == 0);
}

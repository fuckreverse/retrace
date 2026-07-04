/*
 * test_pass_mem_search.cpp — Unit tests for tenet::MemSearchPass
 *
 * MemSearchPass covers two complementary search facilities:
 *   1. Byte-pattern search (`patterns`, with optional wildcards) against
 *      memory-write values and/or register diffs.
 *   2. Exact-value search (`exact_values`, formerly the standalone
 *      LiteralSearchPass) against memory-write values, register diffs, and
 *      MOVZ/MOVK instruction immediate fields, via an O(1) hash-map lookup.
 *
 * Verifies:
 *   - Byte pattern matches a memory-write value.
 *   - Byte pattern with wildcards matches partially-known sequences.
 *   - Exact-value search finds a value in a memory write.
 *   - Exact-value search finds a value in a register diff (when enabled).
 *   - Exact-value search finds a value materialized by a single MOVZ.
 *   - Exact-value search finds a value materialized by MOVZ+MOVK combined
 *     into two separate 16-bit immediate hits (each half matched on its own).
 *   - match_32bit truncation matches a 64-bit search value's low 32 bits.
 *   - max_matches caps the number of hits recorded per value/pattern.
 *   - Empty config (`patterns` and `exact_values` both empty) → Skipped.
 *   - search_immediates=false does not scan MOVZ/MOVK even if exact_values set.
 *   - Combined patterns + exact_values in a single run produce both kinds of
 *     hits, correctly attributed via `is_exact_value_match`.
 *
 * Run:  ctest -R 'mem_search' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory/mem_search_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Tests: byte-pattern search ─────────────────────────────────────────────

TEST_CASE("MemSearchPass: byte pattern matches a memory-write value",
          "[unit][pass][mem_search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // str x10, [x20] writing 0xDEADBEEFCAFEBABE
        tw.emit(ms, 0x1000, enc::str_imm(10, 20, 0),
                {{33, tw.rt(0x1004)}},
                {{2 /*write*/, 8, 0x200000, 0xDEADBEEFCAFEBABEULL}});
        tw.emit_anchor(ms);
    }, "memsearch_pattern_basic");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    // Bytes are little-endian: CAFEBABE comes first in memory.
    cfg.patterns.emplace_back(std::vector<uint8_t>{0xBE, 0xBA, 0xFE, 0xCA}, "cafebabe");

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE(res.matches.size() >= 1);
    REQUIRE(res.by_pattern.size() == 1);
    REQUIRE_FALSE(res.by_pattern[0].empty());
    const auto& m = res.matches[res.by_pattern[0][0]];
    REQUIRE(m.source == MemSearchMatch::MemWrite);
    REQUIRE_FALSE(m.is_exact_value_match);
}

TEST_CASE("MemSearchPass: wildcard pattern matches partially-known sequence",
          "[unit][pass][mem_search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(10, 20, 0),
                {{33, tw.rt(0x1004)}},
                {{2, 8, 0x200000, 0x11223344AABBCCDDULL}});
        tw.emit_anchor(ms);
    }, "memsearch_pattern_wildcard");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    // Match low 4 bytes exactly (DD CC BB AA little-endian), high 4 wildcard.
    MemSearchConfig::Pattern pat;
    pat.bytes = {0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0x00, 0x00};
    pat.mask  = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    pat.label = "wildcard_test";
    cfg.patterns.push_back(pat);

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& res = pm->require("mem_search").get<MemSearchResult>();

    REQUIRE_FALSE(res.by_pattern[0].empty());
}

TEST_CASE("MemSearchPass: empty config is skipped",
          "[unit][pass][mem_search]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "memsearch_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;  // no patterns, no exact_values

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.status == PassResult::Skipped);
}

// ─── Tests: exact-value search (formerly LiteralSearchPass) ────────────────

TEST_CASE("MemSearchPass: exact_values finds a value in a memory write",
          "[unit][pass][mem_search][exact_value]") {
    const uint64_t kValue = 0x67452301ULL;  // MD5 IV-like constant

    auto env = make_env([kValue](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::str_imm(10, 20, 0),
                {{33, tw.rt(0x1004)}},
                {{2, 8, 0x300000, kValue}});
        tw.emit_anchor(ms);
    }, "memsearch_exact_mem");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.exact_values.push_back(kValue);

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE(res.by_value.size() == 1);
    REQUIRE_FALSE(res.by_value[0].empty());
    const auto& m = res.matches[res.by_value[0][0]];
    REQUIRE(m.source == MemSearchMatch::MemWrite);
    REQUIRE(m.is_exact_value_match);
    REQUIRE(m.matched_value == kValue);
    REQUIRE(m.addr == 0x300000);
}

TEST_CASE("MemSearchPass: exact_values finds a value in a register diff when enabled",
          "[unit][pass][mem_search][exact_value]") {
    const uint64_t kValue = 0x9E3779B9ULL;  // TEA delta constant

    auto env = make_env([kValue](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // add x1, x1, x2 producing kValue in x1 (reg_diff, not mem write)
        tw.emit(ms, 0x1000, enc::add_reg(1, 1, 2),
                {{1, kValue}, {33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "memsearch_exact_reg");
    REQUIRE(env != nullptr);

    SECTION("search_reg_values=false (default) finds nothing") {
        auto pm = make_pm(*env);
        MemSearchConfig cfg;
        cfg.exact_values.push_back(kValue);
        cfg.search_reg_values = false;
        pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
        auto& res = pm->require("mem_search").get<MemSearchResult>();
        REQUIRE(res.by_value[0].empty());
    }

    SECTION("search_reg_values=true finds the reg-diff hit") {
        auto pm = make_pm(*env);
        MemSearchConfig cfg;
        cfg.exact_values.push_back(kValue);
        cfg.search_reg_values = true;
        pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
        auto& res = pm->require("mem_search").get<MemSearchResult>();
        REQUIRE_FALSE(res.by_value[0].empty());
        const auto& m = res.matches[res.by_value[0][0]];
        REQUIRE(m.source == MemSearchMatch::RegDiff);
        REQUIRE(m.is_exact_value_match);
        REQUIRE(m.matched_value == kValue);
    }
}

TEST_CASE("MemSearchPass: exact_values + search_immediates finds a MOVZ immediate",
          "[unit][pass][mem_search][exact_value][immediate]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // movz x0, #0x1234
        tw.emit(ms, 0x1000, enc::movz(0, 0x1234),
                {{0, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "memsearch_exact_imm_movz");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.exact_values.push_back(0x1234ULL);
    cfg.search_immediates = true;

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE_FALSE(res.by_value[0].empty());
    bool found_immediate = false;
    for (size_t idx : res.by_value[0]) {
        const auto& m = res.matches[idx];
        if (m.source == MemSearchMatch::Immediate) {
            found_immediate = true;
            REQUIRE(m.matched_value == 0x1234ULL);
        }
    }
    REQUIRE(found_immediate);
}

TEST_CASE("MemSearchPass: exact_values + search_immediates finds a shifted MOVK immediate",
          "[unit][pass][mem_search][exact_value][immediate]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // movz x0, #0x1234       → x0 = 0x0000000000001234
        tw.emit(ms, 0x1000, enc::movz(0, 0x1234),
                {{0, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        // movk x0, #0x5678, lsl #16 → x0 = 0x0000000056781234
        tw.emit(ms, 0x1004, enc::movk(0, 0x5678, 16),
                {{0, 0x0000000056781234ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "memsearch_exact_imm_movk");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    // Search for the MOVK's shifted contribution: 0x5678 << 16.
    cfg.exact_values.push_back(0x56780000ULL);
    cfg.search_immediates = true;

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE_FALSE(res.by_value[0].empty());
    const auto& m = res.matches[res.by_value[0][0]];
    REQUIRE(m.source == MemSearchMatch::Immediate);
    REQUIRE(m.matched_value == 0x56780000ULL);
    // The MOVK is the second instruction (static pc 0x1004); with the
    // fixture's default module_slide (0x4000) that's runtime 0x5004.
    REQUIRE(m.pc == rt_pc(0x1004));
}

TEST_CASE("MemSearchPass: search_immediates=false does not scan MOVZ/MOVK",
          "[unit][pass][mem_search][exact_value][immediate]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::movz(0, 0xABCD),
                {{0, 0xABCDULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "memsearch_no_immediates");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.exact_values.push_back(0xABCDULL);
    cfg.search_immediates = false;  // explicit: default is also false

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& res = pm->require("mem_search").get<MemSearchResult>();
    REQUIRE(res.by_value[0].empty());
}

TEST_CASE("MemSearchPass: match_32bit matches the low 32 bits of a 64-bit value",
          "[unit][pass][mem_search][exact_value]") {
    const uint64_t kSearch64 = 0x123456789ABCDEF0ULL;
    const uint32_t kLow32 = 0x9ABCDEF0u;

    auto env = make_env([kLow32](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // A 4-byte memory write containing only the low 32 bits.
        tw.emit(ms, 0x1000, enc::str_imm(10, 20, 0),
                {{33, tw.rt(0x1004)}},
                {{2, 4, 0x400000, static_cast<uint64_t>(kLow32)}});
        tw.emit_anchor(ms);
    }, "memsearch_match32");
    REQUIRE(env != nullptr);

    SECTION("match_32bit=true finds the truncated match") {
        auto pm = make_pm(*env);
        MemSearchConfig cfg;
        cfg.exact_values.push_back(kSearch64);
        cfg.match_32bit = true;
        pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
        auto& res = pm->require("mem_search").get<MemSearchResult>();
        REQUIRE_FALSE(res.by_value[0].empty());
    }

    SECTION("match_32bit=false does not match the truncated value") {
        auto pm = make_pm(*env);
        MemSearchConfig cfg;
        cfg.exact_values.push_back(kSearch64);
        cfg.match_32bit = false;
        pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
        auto& res = pm->require("mem_search").get<MemSearchResult>();
        REQUIRE(res.by_value[0].empty());
    }
}

TEST_CASE("MemSearchPass: max_matches caps hits per value",
          "[unit][pass][mem_search][exact_value]") {
    const uint64_t kValue = 0xCAFED00DULL;

    auto env = make_env([kValue](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        uint64_t spc = 0x1000;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, spc, enc::str_imm(10, 20, 0),
                    {{33, tw.rt(spc + 4)}},
                    {{2, 8, 0x500000 + (uint64_t)i * 8, kValue}});
            spc += 4;
        }
        tw.emit_anchor(ms);
    }, "memsearch_max_matches");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.exact_values.push_back(kValue);
    cfg.max_matches = 3;

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& res = pm->require("mem_search").get<MemSearchResult>();
    REQUIRE(res.by_value[0].size() == 3);
}

TEST_CASE("MemSearchPass: max_matches caps byte-pattern hits in mem writes",
          "[unit][pass][mem_search][max_matches]") {
    // Regression test: linear_scan()'s mem-write byte-pattern branch used to
    // `break` only out of the innermost `offset` loop when max_matches was
    // reached, so the same pattern kept accumulating unbounded hits across
    // subsequent mem-write events. Verify the cap is actually enforced across
    // multiple separate memory writes.
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        uint64_t spc = 0x1000;
        for (int i = 0; i < 10; i++) {
            tw.emit(ms, spc, enc::str_imm(10, 20, 0),
                    {{33, tw.rt(spc + 4)}},
                    {{2, 8, 0x700000 + (uint64_t)i * 8, 0x00000000DEADBEEFULL}});
            spc += 4;
        }
        tw.emit_anchor(ms);
    }, "memsearch_pattern_max_matches_memwrite");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.patterns.emplace_back(std::vector<uint8_t>{0xEF, 0xBE, 0xAD, 0xDE}, "deadbeef");
    cfg.max_matches = 3;

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE(res.by_pattern.size() == 1);
    REQUIRE(res.by_pattern[0].size() == 3);
}

TEST_CASE("MemSearchPass: max_matches caps byte-pattern hits in register diffs",
          "[unit][pass][mem_search][max_matches]") {
    // Regression test: linear_scan()'s reg-diff byte-pattern branch had no
    // max_matches check at all (only an unconditional `break` after the
    // first match within a single reg-diff), so a pattern occurring
    // frequently across many reg-diffs could grow unbounded.
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        uint64_t spc = 0x1000;
        for (int i = 0; i < 10; i++) {
            // add x1, x1, x2 producing the same reg-diff value each time.
            tw.emit(ms, spc, enc::add_reg(1, 1, 2),
                    {{1, 0x00000000DEADBEEFULL}, {33, tw.rt(spc + 4)}}, {});
            spc += 4;
        }
        tw.emit_anchor(ms);
    }, "memsearch_pattern_max_matches_regdiff");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.patterns.emplace_back(std::vector<uint8_t>{0xEF, 0xBE, 0xAD, 0xDE}, "deadbeef");
    cfg.search_reg_values = true;
    cfg.max_matches = 3;

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE(res.by_pattern.size() == 1);
    REQUIRE(res.by_pattern[0].size() == 3);
}

// ─── Tests: combined patterns + exact_values in one run ────────────────────

TEST_CASE("MemSearchPass: patterns and exact_values can run together",
          "[unit][pass][mem_search]") {
    const uint64_t kExact = 0x41424344ULL;  // "ABCD"

    auto env = make_env([kExact](TraceWriter& tw) {
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Write 1: contains the byte pattern DEADBEEF.
        tw.emit(ms, 0x1000, enc::str_imm(10, 20, 0),
                {{33, tw.rt(0x1004)}},
                {{2, 8, 0x600000, 0x00000000DEADBEEFULL}});
        // Write 2: contains the exact value to search for.
        tw.emit(ms, 0x1004, enc::str_imm(11, 20, 0),
                {{33, tw.rt(0x1008)}},
                {{2, 8, 0x600010, kExact}});
        tw.emit_anchor(ms);
    }, "memsearch_combined");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    MemSearchConfig cfg;
    cfg.patterns.emplace_back(std::vector<uint8_t>{0xEF, 0xBE, 0xAD, 0xDE}, "deadbeef");
    cfg.exact_values.push_back(kExact);

    pm->register_pass(std::make_unique<MemSearchPass>(std::move(cfg)));
    auto& raw = pm->require("mem_search");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemSearchResult>();
    REQUIRE(res.by_pattern.size() == 1);
    REQUIRE(res.by_value.size() == 1);
    REQUIRE_FALSE(res.by_pattern[0].empty());
    REQUIRE_FALSE(res.by_value[0].empty());

    for (size_t idx : res.by_pattern[0]) {
        REQUIRE_FALSE(res.matches[idx].is_exact_value_match);
    }
    for (size_t idx : res.by_value[0]) {
        REQUIRE(res.matches[idx].is_exact_value_match);
        REQUIRE(res.matches[idx].matched_value == kExact);
    }
}

/*
 * test_pass_pattern.cpp — Unit tests for tenet::PatternPass
 *
 * Verifies:
 *   - PatternPass runs without error on a minimal trace.
 *   - PatternResult::total() reports the correct match count.
 *   - by_category index is built correctly.
 *   - crypto_matches() and anti_debug_matches() return correct subsets.
 *   - MOVZ+MOVK constant materialization is detected as a pattern match
 *     when the loaded constants match known crypto values.
 *   - Empty trace produces zero matches (no false positives).
 *   - XOR loop detector: a tight loop body (few unique PCs, repeatedly
 *     executed) is reported at Medium confidence as "XOR loop"; dense EOR
 *     straight-line code (many unique PCs) is downgraded to Low confidence
 *     as "XOR-dense code (non-loop)".
 *   - Constant materialization (movz+movk sequences) is tracked directly by
 *     PatternCollector as part of its single trace scan (the former
 *     standalone `constant_materialization` pass was merged into "pattern" —
 *     see PatternResult::constants): sequences that match a known algorithm
 *     constant are reported as a High-confidence "Known constant: ..."
 *     match, and longer (>= 3 part) sequences that don't match anything are
 *     still surfaced at Medium confidence as an unnamed "Constant loading
 *     sequence".
 *
 * NOTE: PatternPass uses libyara (if compiled with TENET_HAS_YARA) and also
 * performs mnemonic-based detection.  These tests focus on the mnemonic-based
 * path (MOVZ+MOVK sequences) which is always active.
 *
 * Run:  ctest -R 'pass_pattern' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/crypto/pattern_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE("PatternPass: runs without error on minimal linear trace",
          "[unit][pass][pattern]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::add_imm(0, 1, 5),
                {{0, 5ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::add_imm(2, 0, 3),
                {{2, 8ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_minimal");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& raw = pm->require("pattern");
    REQUIRE(raw.ok());

    auto& res = raw.get<PatternResult>();
    SECTION("result is accessible") {
        REQUIRE_NOTHROW(res.total());
    }
}

TEST_CASE("PatternPass: empty trace produces zero matches",
          "[unit][pass][pattern]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Single NOP — no interesting patterns
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& raw = pm->require("pattern");
    REQUIRE(raw.ok());

    auto& res = raw.get<PatternResult>();
    SECTION("zero matches for NOP-only trace") {
        REQUIRE(res.total() == 0);
    }
    SECTION("zero materialized constants for NOP-only trace") {
        REQUIRE(res.constants.total() == 0);
    }
}

TEST_CASE("PatternPass: by_category index has categories only for matched patterns",
          "[unit][pass][pattern]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_bycat");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();
    SECTION("by_category size <= total matches") {
        size_t cat_total = 0;
        for (const auto& kv : res.by_category) {
            cat_total += kv.second.size();
        }
        REQUIRE(cat_total == res.total());
    }
}

TEST_CASE("PatternPass: 2-part MOVZ+MOVK sequence stays below the "
          "materialization threshold and reports no match",
          "[unit][pass][pattern]") {
    // SHA-256 initial hash value H0 = 0x6a09e667
    // Materialized as: MOVZ x3, #0xe667, LSL #0; MOVK x3, #0x6a09, LSL #16
    //
    // A 2-part sequence is recorded in PatternResult::constants (min_parts
    // defaults to 2), but finalize_constants() only emits an "unverified"
    // KeySchedule PatternMatch for sequences with >= 3 parts, so a 2-part
    // sequence produces a constants[] entry without a matching
    // "Constant loading sequence" PatternMatch unless it hits the known
    // constant table (which it does here, emitting a High-confidence
    // "Known constant" match instead — see the dedicated test below for the
    // >= 3-part "no known match" fallback shape).
    const uint64_t kSHA256_H0 = 0x6a09e667ULL;

    auto env = make_env([kSHA256_H0](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // MOVZ x3, #0xe667
        uint16_t lo = kSHA256_H0 & 0xFFFF;
        uint16_t hi = (kSHA256_H0 >> 16) & 0xFFFF;

        tw.emit(ms, 0x1000, enc::movz(3, lo),
                {{3, (uint64_t)lo}, {33, tw.rt(0x1004)}}, {});
        // MOVK x3, #0x6a09, LSL #16
        tw.emit(ms, 0x1004, enc::movk(3, hi, 16),
                {{3, kSHA256_H0}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_sha256");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& raw = pm->require("pattern");
    REQUIRE(raw.ok());

    auto& res = raw.get<PatternResult>();

    SECTION("crypto_matches() returns valid pointer vector") {
        auto matches = res.crypto_matches();
        for (const auto* m : matches) {
            REQUIRE(m != nullptr);
        }
    }
    SECTION("the 2-part sequence is recorded as a known SHA-256 constant") {
        // Even though num_parts (2) is below the >= 3 threshold for the
        // generic "unverified" fallback match, a value that hits the known
        // constant table is always identified regardless of part count.
        REQUIRE(res.constants.total() == 1);
        REQUIRE(res.constants.constants[0].value == kSHA256_H0);
        REQUIRE(res.constants.constants[0].known_match != nullptr);
    }
    SECTION("no generic unnamed 'Constant loading sequence' match is emitted") {
        bool found_generic = false;
        for (const auto& m : res.matches) {
            if (m.pattern_name == "Constant loading sequence") {
                found_generic = true;
            }
        }
        REQUIRE_FALSE(found_generic);
    }
}

TEST_CASE("PatternPass: MOVZ+MOVK+MOVK sequence with no known match is "
          "Medium confidence 'Constant loading sequence'",
          "[unit][pass][pattern]") {
    // 3-part load sequence reaches the >= 3-part threshold used by
    // finalize_constants() to emit a generic (unnamed) "Constant loading
    // sequence" PatternMatch for values that don't match anything in the
    // known-constant database.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Assemble an arbitrary 48-bit value via 3 movz/movk parts — value
        // is NOT a known crypto constant, but the shape (>=3 parts) is all
        // this fallback detector looks at.
        tw.emit(ms, 0x1000, enc::movz(4, 0x1111, 0),
                {{4, 0x1111ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(4, 0x2222, 16),
                {{4, 0x22221111ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::movk(4, 0x3333, 32),
                {{4, 0x333322221111ULL}, {33, tw.rt(0x100C)}}, {});
        // Break the sequence so it gets flushed (non-movz/movk instruction).
        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_const_generic");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* load_match = nullptr;
    for (const auto& m : res.matches) {
        if (m.pattern_name == "Constant loading sequence") {
            load_match = &m;
        }
    }
    REQUIRE(load_match != nullptr);

    SECTION("confidence is Medium (unnamed but structurally meaningful)") {
        REQUIRE(load_match->confidence == PatternConfidence::Medium);
    }
    SECTION("description mentions the movz/movk instruction count") {
        REQUIRE(load_match->description.find("movz/movk instructions") != std::string::npos);
    }
    SECTION("the constant is also present in PatternResult::constants "
            "without a known_match") {
        REQUIRE(res.constants.total() == 1);
        REQUIRE(res.constants.constants[0].known_match == nullptr);
        REQUIRE(res.constants.identified_count() == 0);
    }
}

TEST_CASE("PatternPass: known crypto constant produces a High-confidence "
          "'Known constant' match with no generic fallback",
          "[unit][pass][pattern]") {
    // Same SHA-256 H0 sequence as above. Constant materialization is now
    // tracked unconditionally as part of PatternCollector's own scan (no
    // separate pass/dependency needed), so an identified value always
    // produces a High-confidence match, and finalize_constants() skips the
    // generic "Constant loading sequence" match for any constant that has a
    // known_match.
    const uint64_t kSHA256_H0 = 0x6a09e667ULL;

    auto env = make_env([kSHA256_H0](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        uint16_t lo = kSHA256_H0 & 0xFFFF;
        uint16_t hi = (kSHA256_H0 >> 16) & 0xFFFF;

        tw.emit(ms, 0x1000, enc::movz(3, lo),
                {{3, (uint64_t)lo}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(3, hi, 16),
                {{3, kSHA256_H0}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_sha256_known");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* known_match = nullptr;
    bool any_generic_fallback = false;
    for (const auto& m : res.matches) {
        if (m.pattern_name.find("Known constant") != std::string::npos) {
            known_match = &m;
        }
        if (m.pattern_name == "Constant loading sequence") {
            any_generic_fallback = true;
        }
    }

    SECTION("a verified High-confidence match is produced") {
        REQUIRE(known_match != nullptr);
        REQUIRE(known_match->confidence == PatternConfidence::High);
    }
    SECTION("the generic fallback never fires for an identified constant") {
        REQUIRE_FALSE(any_generic_fallback);
    }
    SECTION("PatternResult::constants also reflects the identified value") {
        REQUIRE(res.constants.total() == 1);
        REQUIRE(res.constants.identified_count() == 1);
        REQUIRE(res.constants.constants[0].known_match != nullptr);
        REQUIRE(res.constants.constants[0].known_match->algorithm == "SHA-256");
    }
}

TEST_CASE("PatternPass: tight XOR loop (few unique PCs, repeated execution) "
          "stays Medium confidence and is labeled as a loop",
          "[unit][pass][pattern]") {
    // A single `eor` instruction executed repeatedly at the SAME pc is the
    // clearest possible "real loop" shape: every eor in the window shares
    // 1 unique PC, well under XOR_LOOP_MAX_UNIQUE_PCS (4). The trailing nop
    // that finally breaks the run also gets swept into the same match (the
    // detector records ALL instructions seen while the window's eor count
    // stays >= XOR_THRESHOLD, not just the eor ones) — so the run ends up
    // with exactly 2 unique PCs (the eor site + the breaking nop), which is
    // still comfortably "loop-like" and must stay Medium confidence.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0xAAAAAAAAAAAAAAAAULL;
        ms.x(1) = 0x5555555555555555ULL;

        uint64_t next_pc = 0x1000;
        // Execute the SAME eor instruction (same PC) enough times to fill
        // and exceed the detector's window (8) well past the threshold (4).
        for (int i = 0; i < 12; ++i) {
            tw.emit(ms, 0x1000, enc::eor_reg(2, 0, 1),
                    {{2, ms.x(0) ^ ms.x(1)}, {33, tw.rt(next_pc)}}, {});
        }
        // Break the run with a non-eor instruction so the match flushes.
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_xor_tight_loop");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* xor_match = nullptr;
    for (const auto& m : res.matches) {
        if (m.pattern_name == "XOR loop") {
            xor_match = &m;
        }
    }
    REQUIRE(xor_match != nullptr);

    SECTION("confidence stays Medium for a tight, repeating loop body") {
        REQUIRE(xor_match->confidence == PatternConfidence::Medium);
    }
    SECTION("description reflects a small number of unique PCs (well under "
            "XOR_LOOP_MAX_UNIQUE_PCS)") {
        REQUIRE(xor_match->description.find("2 unique PC") != std::string::npos);
    }
}

TEST_CASE("PatternPass: EOR-dense straight-line code (many unique PCs) is "
          "downgraded to Low confidence and labeled non-loop",
          "[unit][pass][pattern]") {
    // 8 DIFFERENT `eor` instructions at 8 DIFFERENT PCs, each executed once.
    // This matches the same "XOR_THRESHOLD within XOR_WINDOW_SIZE" shape as
    // a real loop, but every instruction is a distinct PC — i.e. it is
    // straight-line code marching through EORs, not a repeating loop body.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        ms.x(0) = 0x1111111111111111ULL;
        ms.x(1) = 0x2222222222222222ULL;

        uint64_t pc = 0x1000;
        for (int i = 0; i < 8; ++i) {
            uint64_t next_pc = pc + 4;
            tw.emit(ms, pc, enc::eor_reg(2, 0, 1),
                    {{2, ms.x(0) ^ ms.x(1)}, {33, tw.rt(next_pc)}}, {});
            pc = next_pc;
        }
        // Break the run with a non-eor instruction so the match flushes.
        tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_xor_dense_straightline");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* dense_match = nullptr;
    for (const auto& m : res.matches) {
        if (m.pattern_name.find("XOR-dense") != std::string::npos) {
            dense_match = &m;
        }
    }
    REQUIRE(dense_match != nullptr);

    SECTION("confidence is downgraded to Low for non-loop straight-line code") {
        REQUIRE(dense_match->confidence == PatternConfidence::Low);
    }
    SECTION("no 'XOR loop' (Medium) match is emitted for the same run") {
        bool found_medium_loop = false;
        for (const auto& m : res.matches) {
            if (m.pattern_name == "XOR loop") found_medium_loop = true;
        }
        REQUIRE_FALSE(found_medium_loop);
    }
}

TEST_CASE("PatternPass: anti_debug_matches() returns correct subset",
          "[unit][pass][pattern]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Emit an inline SVC #0x80 (ptrace-like syscall)
        // SVC #26 = PT_DENY_ATTACH on macOS (syscall 26)
        tw.emit(ms, 0x1000, enc::svc(0x80),
                {{33, tw.rt(0x1004)}}, {});
        tw.emit_svc(tw.rt(0x1000), 26);  // SVC record: syscall 26

        tw.emit(ms, 0x1004, enc::nop(),
                {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_antidebug");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& raw = pm->require("pattern");
    REQUIRE(raw.ok());

    auto& res = raw.get<PatternResult>();
    SECTION("anti_debug_matches() returns valid vector") {
        auto matches = res.anti_debug_matches();
        for (const auto* m : matches) {
            REQUIRE(m != nullptr);
            REQUIRE(m->category == PatternCategory::AntiDebug);
        }
    }
}

TEST_CASE("PatternPass: PatternResult total equals sum of by_category indices",
          "[unit][pass][pattern]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // AES key schedule constant: MOVZ+MOVK sequence
        // AES S-Box constant: 0x63637c7c (example)
        tw.emit(ms, 0x1000, enc::movz(5, 0x7c7c),
                {{5, 0x7c7cULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(5, 0x6363, 16),
                {{5, 0x63637c7cULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_sum");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    SECTION("sum of by_category indices equals total") {
        size_t cat_total = 0;
        for (const auto& kv : res.by_category) {
            cat_total += kv.second.size();
        }
        REQUIRE(cat_total == res.total());
    }
}

TEST_CASE("PatternPass: set_constants_min_parts(1) reports standalone "
          "movz-only constants",
          "[unit][pass][pattern]") {
    // A single MOVZ (no MOVK follow-up) is only recorded when
    // constants_min_parts is lowered to 1 — the default (2) requires at
    // least a movz+movk pair.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(6, 0x1234, 0),
                {{6, 0x1234ULL}, {33, tw.rt(0x1004)}}, {});
        // Break the sequence immediately so it flushes as a 1-part constant.
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "pattern_min_parts_1");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    auto pp = std::make_unique<PatternPass>();
    pp->set_constants_min_parts(1);
    pm->register_pass(std::move(pp));

    auto& res = pm->require("pattern").get<PatternResult>();

    SECTION("the standalone movz is recorded in PatternResult::constants") {
        REQUIRE(res.constants.total() == 1);
        REQUIRE(res.constants.constants[0].num_parts == 1);
        REQUIRE(res.constants.constants[0].value == 0x1234ULL);
    }
}

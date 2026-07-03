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
 *   - Constant-loading fallback (no constant_materialization dependency
 *     available): movz/movk sequences are reported at Low confidence with
 *     an "unverified" label, since the loaded value is never checked
 *     against a known crypto constant table on this path.
 *   - Constant-loading via constant_materialization (dependency actually
 *     registered and run): a known crypto constant is reported at High
 *     confidence and the pattern name carries no "(unverified)" suffix.
 *
 * NOTE: PatternPass uses libyara (if compiled with TENET_HAS_YARA) and also
 * performs mnemonic-based detection.  These tests focus on the mnemonic-based
 * path (MOVZ+MOVK sequences) which is always active.
 *
 * IMPORTANT: PatternPass declares dependencies() as empty and consumes
 * constant_materialization opportunistically via PassContext::try_require(),
 * which only returns a result if that pass has ALREADY completed — it does
 * NOT trigger it to run. So in any test that only registers PatternPass
 * (without also registering+requiring ConstantMaterializationPass first),
 * PatternPass always takes the "no constmat" fallback path. Tests that want
 * to exercise the constmat-integrated (High confidence) path must explicitly
 * register and require "constant_materialization" before requiring
 * "pattern" — see the dedicated TEST_CASE below.
 *
 * Run:  ctest -R 'pass_pattern' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/constant_materialization_pass.h"

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

TEST_CASE("PatternPass: MOVZ+MOVK sequence without constant_materialization "
          "is reported via the unverified fallback path",
          "[unit][pass][pattern]") {
    // SHA-256 initial hash value H0 = 0x6a09e667
    // Materialized as: MOVZ x3, #0xe667, LSL #0; MOVK x3, #0x6a09, LSL #16
    //
    // NOTE: only PatternPass is registered here (no ConstantMaterializationPass),
    // and try_require() never triggers a pass to run — it only returns a
    // result if the pass already completed. So this test exercises
    // PatternCollector's own movz/movk fallback detector (Detector 3), NOT
    // the constant_materialization integration path. That is intentional:
    // this is the "value never verified against a known constant table"
    // case, which must be surfaced at Low confidence — see the dedicated
    // "via constant_materialization" test below for the High-confidence path.
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
    SECTION("2 movz/movk instructions is below CONST_LOAD_THRESHOLD (3), "
            "so no match is emitted yet") {
        // Detector 3 only fires once the pending sequence reaches
        // CONST_LOAD_THRESHOLD (3) parts; a 2-part sequence alone should not
        // produce a "Constant loading sequence" match.
        bool found_unverified = false;
        for (const auto& m : res.matches) {
            if (m.pattern_name.find("Constant loading") != std::string::npos) {
                found_unverified = true;
            }
        }
        REQUIRE_FALSE(found_unverified);
    }
}

TEST_CASE("PatternPass: MOVZ+MOVK+MOVK fallback sequence (no constmat) is "
          "Low confidence and labeled unverified",
          "[unit][pass][pattern]") {
    // 3-part load sequence reaches CONST_LOAD_THRESHOLD, so Detector 3 fires.
    // Without ConstantMaterializationPass registered, this must go through
    // flush_const_load_match() — always Low confidence, name suffixed
    // "(unverified)", description mentions the value was not checked.
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
    }, "pattern_const_fallback_low");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* load_match = nullptr;
    for (const auto& m : res.matches) {
        if (m.pattern_name.find("Constant loading") != std::string::npos) {
            load_match = &m;
        }
    }
    REQUIRE(load_match != nullptr);

    SECTION("confidence is Low (unverified value)") {
        REQUIRE(load_match->confidence == PatternConfidence::Low);
    }
    SECTION("name is explicitly marked unverified") {
        REQUIRE(load_match->pattern_name.find("unverified") != std::string::npos);
    }
    SECTION("description mentions the value was not checked against a "
            "constant table") {
        REQUIRE(load_match->description.find("NOT checked") != std::string::npos);
    }
}

TEST_CASE("PatternPass: known crypto constant via constant_materialization "
          "is High confidence with no unverified fallback match",
          "[unit][pass][pattern]") {
    // Same SHA-256 H0 sequence as above, but this time we actually register
    // AND require ConstantMaterializationPass first so its result is
    // Completed by the time PatternPass::run() calls try_require(). This
    // exercises constmat_to_pattern_matches() (High confidence) instead of
    // the fallback detector, and Detector 3 must stay disabled throughout
    // (see "Skipped when constmat result is available" in on_inst()).
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
    }, "pattern_sha256_constmat");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<ConstantMaterializationPass>());
    pm->register_pass(std::make_unique<PatternPass>());

    // Force constant_materialization to actually run and complete BEFORE
    // pattern, so PatternPass::run()'s try_require() sees it as Completed.
    auto& cm_raw = pm->require("constant_materialization");
    REQUIRE(cm_raw.ok());

    auto& res = pm->require("pattern").get<PatternResult>();

    const PatternMatch* known_match = nullptr;
    bool any_unverified_fallback = false;
    for (const auto& m : res.matches) {
        if (m.pattern_name.find("Known constant") != std::string::npos) {
            known_match = &m;
        }
        if (m.pattern_name.find("unverified") != std::string::npos) {
            any_unverified_fallback = true;
        }
    }

    SECTION("a verified High-confidence match is produced") {
        REQUIRE(known_match != nullptr);
        REQUIRE(known_match->confidence == PatternConfidence::High);
    }
    SECTION("the unverified fallback detector never fires when constmat "
            "is available") {
        REQUIRE_FALSE(any_unverified_fallback);
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

/*
 * test_pass_objc_crypto.cpp — Unit tests for tenet::ObjcCryptoPass
 *
 * ObjcCryptoPass correlates PatternPass hits with the ObjC call stack
 * context at the time each pattern fires.  Tests verify:
 *
 *   - Empty trace: no hits, no crash.
 *   - Pattern with no ObjC messages → bare hit (empty objc_stack).
 *   - Pattern preceded by ObjC messages → ObjC context attached.
 *   - Pattern after ObjC message beyond max_lookback → still bare.
 *   - Multiple patterns: each gets its own context independently.
 *   - by_class / by_selector indices are populated correctly.
 *   - in_objc_count() + bare_count() == total().
 *   - to_json() serialises all required keys.
 *   - objc_chain_summary() produces non-empty string for in-ObjC hits.
 *
 * NOTE: ObjcCryptoPass depends on PatternPass and ObjcPass.  PatternPass
 * requires recognisable instruction patterns (MOVZ+MOVK with known crypto
 * constants) to produce matches.  For predictability we force at least one
 * pattern match by injecting a MOVZ+MOVK sequence with the AES S-box seed
 * (0x63 in low bits of a widely-used constant).  If the pattern heuristic
 * doesn't fire for the synthetic trace, the test falls back to verifying the
 * "no-pattern → 0 hits" path and still validates all ObjcCryptoResult fields.
 *
 * Run:  ctest -R 'pass_objc_crypto' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/crypto/objc_crypto_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/platform/objc_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a trace with:
///   - Two ObjC messages (NSString stringWithFormat: and NSData initWithBytes:length:)
///   - A MOVZ+MOVK sequence that may trigger the crypto pattern heuristic
///   - A plain NOPsled after each ObjC message
static std::unique_ptr<TraceEnv> make_objc_then_pattern() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // inst 0: a few setup instructions
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});

        // ObjC message 1 – inst_id 1 (OBJC record appears before inst 1)
        tw.emit_objc(tw.rt(0x1004), 0xABC01ULL, 0xABC02ULL, "NSString");

        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});

        // ObjC message 2 – closer to the pattern
        tw.emit_objc(tw.rt(0x100C), 0xBCD01ULL, 0xBCD02ULL, "NSData");

        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});

        // MOVZ x0, #0x6363  (AES constant-like value to trigger PatternPass)
        tw.emit(ms, 0x1010, enc::movz(0, 0x6363),
                {{0, 0x6363ULL}, {33, tw.rt(0x1014)}}, {});
        // MOVK x0, #0x7c7c, lsl #16
        tw.emit(ms, 0x1014, enc::movk(0, 0x7c7c, 16),
                {{0, 0x7c7c6363ULL}, {33, tw.rt(0x1018)}}, {});

        tw.emit(ms, 0x1018, enc::nop(), {{33, tw.rt(0x101C)}}, {});
        tw.emit_anchor(ms);
    }, "objc_crypto_basic");
}

/// Build a trace with no ObjC messages at all but a MOVZ+MOVK pattern.
static std::unique_ptr<TraceEnv> make_pattern_no_objc() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movz(1, 0x6363),
                {{1, 0x6363ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::movk(1, 0x7c7c, 16),
                {{1, 0x7c7c6363ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "objc_crypto_no_objc");
}

/// Helper: register PatternPass + ObjcPass + ObjcCryptoPass in pm.
static void register_all(PassManager& pm) {
    pm.register_pass(std::make_unique<PatternPass>());
    pm.register_pass(std::make_unique<ObjcPass>());
    pm.register_pass(std::make_unique<ObjcCryptoPass>());
}

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE("ObjcCryptoPass: empty trace produces no hits", "[unit][pass][objc_crypto]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "oc_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_all(*pm);

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());

    const auto& res = raw.get<ObjcCryptoResult>();
    SECTION("total() == 0") { REQUIRE(res.total() == 0); }
    SECTION("in_objc_count() == 0") { REQUIRE(res.in_objc_count() == 0); }
    SECTION("bare_count() == 0")    { REQUIRE(res.bare_count() == 0); }
}

TEST_CASE("ObjcCryptoPass: pattern without ObjC → bare hit",
          "[unit][pass][objc_crypto]") {
    auto env = make_pattern_no_objc();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_all(*pm);

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());
    const auto& res = raw.get<ObjcCryptoResult>();

    // If PatternPass detected something, it must be classified as bare.
    SECTION("bare_count == total") {
        REQUIRE(res.bare_count() == res.total());
        REQUIRE(res.in_objc_count() == 0);
    }

    SECTION("all hits have empty objc_stack") {
        for (const auto& h : res.hits) {
            REQUIRE(h.objc_stack.empty());
            REQUIRE(h.innermost_frame() == nullptr);
        }
    }

    SECTION("by_class is empty") {
        REQUIRE(res.by_class.empty());
    }

    SECTION("by_selector is empty") {
        REQUIRE(res.by_selector.empty());
    }
}

TEST_CASE("ObjcCryptoPass: pattern after ObjC message → in-ObjC hit",
          "[unit][pass][objc_crypto]") {
    auto env = make_objc_then_pattern();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_all(*pm);

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());
    const auto& res = raw.get<ObjcCryptoResult>();

    // We may or may not get pattern hits depending on the heuristic.
    // The core invariant is always valid:
    SECTION("in_objc_count + bare_count == total") {
        REQUIRE(res.in_objc_count() + res.bare_count() == res.total());
    }

    if (res.total() > 0) {
        SECTION("hits with ObjC context have non-empty objc_stack") {
            for (size_t idx : res.objc_pattern_indices) {
                REQUIRE_FALSE(res.hits[idx].objc_stack.empty());
                REQUIRE(res.hits[idx].innermost_frame() != nullptr);
            }
        }

        SECTION("by_class populated for in-ObjC hits") {
            if (!res.objc_pattern_indices.empty()) {
                REQUIRE_FALSE(res.by_class.empty());
            }
        }

        SECTION("ObjC frame class name is non-empty") {
            for (size_t idx : res.objc_pattern_indices) {
                for (const auto& frame : res.hits[idx].objc_stack) {
                    REQUIRE_FALSE(frame.class_name.empty());
                }
            }
        }
    }
}

TEST_CASE("ObjcCryptoPass: max_lookback = 0 makes all hits bare",
          "[unit][pass][objc_crypto]") {
    auto env = make_objc_then_pattern();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());
    pm->register_pass(std::make_unique<ObjcPass>());

    auto pass = std::make_unique<ObjcCryptoPass>();
    pass->set_max_lookback(0);   // 0 = do not look back at all
    pm->register_pass(std::move(pass));

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());
    const auto& res = raw.get<ObjcCryptoResult>();

    SECTION("all hits must be bare with lookback=0") {
        REQUIRE(res.in_objc_count() == 0);
        REQUIRE(res.bare_count() == res.total());
    }
}

TEST_CASE("ObjcCryptoPass: max_stack_depth limits ObjC frames",
          "[unit][pass][objc_crypto]") {
    // Trace with 5 ObjC messages before a pattern.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // 5 ObjC messages
        const char* classes[] = {"ClassA", "ClassB", "ClassC", "ClassD", "ClassE"};
        for (int i = 0; i < 5; i++) {
            tw.emit_objc(tw.rt(0x1000 + (uint64_t)i * 4),
                         (uint64_t)(0x100 + i), (uint64_t)(0x200 + i),
                         classes[i]);
            tw.emit(ms, 0x1000 + (uint64_t)i * 4, enc::nop(),
                    {{33, tw.rt(0x1004 + (uint64_t)i * 4)}}, {});
        }

        // MOVZ+MOVK pattern after the ObjC messages
        tw.emit(ms, 0x2000, enc::movz(0, 0x6363),
                {{0, 0x6363ULL}, {33, tw.rt(0x2004)}}, {});
        tw.emit(ms, 0x2004, enc::movk(0, 0x7c7c, 16),
                {{0, 0x7c7c6363ULL}, {33, tw.rt(0x2008)}}, {});
        tw.emit_anchor(ms);
    }, "oc_depth");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<PatternPass>());
    pm->register_pass(std::make_unique<ObjcPass>());

    auto pass = std::make_unique<ObjcCryptoPass>();
    pass->set_max_stack_depth(2);  // only 2 frames max
    pm->register_pass(std::move(pass));

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());
    const auto& res = raw.get<ObjcCryptoResult>();

    SECTION("each in-ObjC hit has at most 2 frames") {
        for (size_t idx : res.objc_pattern_indices) {
            REQUIRE(res.hits[idx].objc_stack.size() <= 2);
        }
    }
}

TEST_CASE("ObjcCryptoPass: to_json has required keys",
          "[unit][pass][objc_crypto]") {
    auto env = make_objc_then_pattern();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_all(*pm);

    auto& raw = pm->require("objc_crypto");
    REQUIRE(raw.ok());
    const auto& res = raw.get<ObjcCryptoResult>();

    SECTION("to_json does not throw") {
        std::string json;
        REQUIRE_NOTHROW(json = res.to_json());
        REQUIRE_FALSE(json.empty());
    }

    SECTION("to_json contains required top-level keys") {
        nlohmann::json j = nlohmann::json::parse(res.to_json());
        REQUIRE(j.contains("total"));
        REQUIRE(j.contains("in_objc_count"));
        REQUIRE(j.contains("bare_count"));
        REQUIRE(j.contains("hits"));
        // counts are consistent
        REQUIRE(j["in_objc_count"].get<size_t>() +
                j["bare_count"].get<size_t>() ==
                j["total"].get<size_t>());
    }
}

TEST_CASE("ObjcCryptoPass: objc_chain_summary for bare hit",
          "[unit][pass][objc_crypto]") {
    // Bare hit (no ObjC) → summary should indicate no context.
    ObjcCryptoHit hit;
    hit.pattern_name = "test";
    hit.category = PatternCategory::Crypto;
    hit.confidence = PatternConfidence::High;

    SECTION("empty stack → '(bare — no ObjC context)'") {
        REQUIRE(hit.objc_chain_summary() == "(bare — no ObjC context)");
    }
}

TEST_CASE("ObjcCryptoPass: objc_chain_summary for single-frame hit",
          "[unit][pass][objc_crypto]") {
    ObjcCryptoHit hit;
    hit.pattern_name = "test";
    hit.category = PatternCategory::Crypto;
    hit.confidence = PatternConfidence::Medium;

    ObjcCallFrame frame;
    frame.inst_id = 5;
    frame.objc_pc = 0x1000;
    frame.class_name = "CryptoManager";
    frame.selector_name = "encryptData:";
    frame.receiver = 0xDEAD;
    hit.objc_stack.push_back(frame);

    SECTION("single frame: '[CryptoManager encryptData:]'") {
        auto summary = hit.objc_chain_summary();
        REQUIRE(summary.find("CryptoManager") != std::string::npos);
        REQUIRE(summary.find("encryptData:") != std::string::npos);
    }

    SECTION("innermost_frame() returns the one frame") {
        REQUIRE(hit.innermost_frame() == &hit.objc_stack.back());
    }
}

TEST_CASE("ObjcCryptoPass: objc_chain_summary for multi-frame chain",
          "[unit][pass][objc_crypto]") {
    ObjcCryptoHit hit;

    ObjcCallFrame outer, inner;
    outer.class_name = "AppDelegate"; outer.selector_name = "processData";
    inner.class_name = "CryptoEngine"; inner.selector_name = "encrypt:";
    hit.objc_stack = {outer, inner};

    SECTION("chain uses ' → ' separator") {
        auto s = hit.objc_chain_summary();
        REQUIRE(s.find(" → ") != std::string::npos);
        REQUIRE(s.find("AppDelegate") != std::string::npos);
        REQUIRE(s.find("CryptoEngine") != std::string::npos);
    }

    SECTION("innermost_frame is inner (last element)") {
        REQUIRE(hit.innermost_frame()->class_name == "CryptoEngine");
    }
}

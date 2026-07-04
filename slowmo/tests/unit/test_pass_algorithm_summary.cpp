/*
 * test_pass_algorithm_summary.cpp — Unit tests for tenet::AlgorithmSummaryPass
 *
 * Verifies:
 *   - normalize_algorithm_name() maps known detector-name spellings to the
 *     correct AlgorithmFamily (including disambiguating SHA-1/256/384/512).
 *   - algorithm_family_structure() maps SPN/Feistel/ARX families correctly
 *     and returns Unknown for hash/MAC families with no round structure.
 *   - Evidence from different detectors (pattern match "AES instruction",
 *     known-constant "AES", and an SPN-classified loop) that all refer to
 *     the same algorithm collapse into ONE candidate instead of three,
 *     regardless of which detector produced which wording — this is the
 *     core fix replacing the old ad-hoc substring-matching cross-reference
 *     pass.
 *   - Evidence for two DIFFERENT algorithms is never merged just because
 *     both happen to be SPN-shaped (e.g. AES constants + an SM4-tagged
 *     pattern must stay as two separate candidates).
 *   - The "hot function" call-graph heuristic only fires above both the
 *     absolute (set_hot_function_min_calls) and relative
 *     (set_hot_function_min_ratio) thresholds, and any candidate it
 *     produces is flagged `is_speculative` and excluded from
 *     confirmed_candidates().
 *   - Real (pattern/constant/loop) evidence is never speculative.
 *   - Candidates are sorted by confidence descending.
 *   - With all dependencies unavailable/empty, the pass still succeeds and
 *     reports zero candidates plus a "no algorithms detected" summary.
 *   - AlgorithmSummaryResult blob round-trips through the pass_blob cache
 *     (save → reload), preserving family/is_speculative on every candidate.
 *
 * Run:  ctest -R 'algorithm_summary' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/crypto/algorithm_summary_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── AlgorithmFamily normalization: pure unit tests (no trace needed) ──────

TEST_CASE("normalize_algorithm_name: recognizes known algorithm spellings",
          "[unit][pass][algorithm_summary]") {
    // Canonical names as they appear in pattern_pass's KnownConstant db.
    REQUIRE(normalize_algorithm_name("AES") == AlgorithmFamily::AES);
    REQUIRE(normalize_algorithm_name("SM4") == AlgorithmFamily::SM4);
    REQUIRE(normalize_algorithm_name("SM3") == AlgorithmFamily::SM3);
    REQUIRE(normalize_algorithm_name("MD5") == AlgorithmFamily::MD5);
    REQUIRE(normalize_algorithm_name("DES") == AlgorithmFamily::DES);
    REQUIRE(normalize_algorithm_name("ChaCha20") == AlgorithmFamily::ChaCha);
    REQUIRE(normalize_algorithm_name("Salsa20") == AlgorithmFamily::Salsa);

    // Free-form detector wording that embeds the family name as a substring
    // (as produced by pattern_pass's PatternMatch::pattern_name).
    REQUIRE(normalize_algorithm_name("AES instruction (aese)") == AlgorithmFamily::AES);
    REQUIRE(normalize_algorithm_name("Known constant: SHA256_H0 (SHA-256)") == AlgorithmFamily::SHA256);
}

TEST_CASE("normalize_algorithm_name: disambiguates SHA digest sizes",
          "[unit][pass][algorithm_summary]") {
    // SHA-256/384/512 all share the "SHA" prefix; the rule table must check
    // the longer/more specific spellings before falling through.
    REQUIRE(normalize_algorithm_name("SHA-256") == AlgorithmFamily::SHA256);
    REQUIRE(normalize_algorithm_name("SHA256") == AlgorithmFamily::SHA256);
    REQUIRE(normalize_algorithm_name("SHA-384") == AlgorithmFamily::SHA384);
    REQUIRE(normalize_algorithm_name("SHA-512") == AlgorithmFamily::SHA512);
    REQUIRE(normalize_algorithm_name("SHA-1") == AlgorithmFamily::SHA1);
    REQUIRE(normalize_algorithm_name("SHA1") == AlgorithmFamily::SHA1);
}

TEST_CASE("normalize_algorithm_name: unrecognized text returns Unknown",
          "[unit][pass][algorithm_summary]") {
    REQUIRE(normalize_algorithm_name("XOR loop") == AlgorithmFamily::Unknown);
    REQUIRE(normalize_algorithm_name("Hot function: sub_1234") == AlgorithmFamily::Unknown);
    REQUIRE(normalize_algorithm_name("") == AlgorithmFamily::Unknown);
}

TEST_CASE("algorithm_family_structure: maps families to the correct round shape",
          "[unit][pass][algorithm_summary]") {
    REQUIRE(algorithm_family_structure(AlgorithmFamily::AES) == AlgorithmStructure::SPN);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::SM4) == AlgorithmStructure::SPN);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::DES) == AlgorithmStructure::Feistel);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::Camellia) == AlgorithmStructure::Feistel);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::ChaCha) == AlgorithmStructure::ARX);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::Salsa) == AlgorithmStructure::ARX);
    // Hash/MAC families have no iterated-round *cipher* structure recognized
    // by loop_semantics — must not accidentally alias onto SPN/Feistel/ARX.
    REQUIRE(algorithm_family_structure(AlgorithmFamily::SHA256) == AlgorithmStructure::Unknown);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::MD5) == AlgorithmStructure::Unknown);
    REQUIRE(algorithm_family_structure(AlgorithmFamily::Unknown) == AlgorithmStructure::Unknown);
}

// ─── Full-pipeline helpers ──────────────────────────────────────────────────

// Registers every (soft) dependency of AlgorithmSummaryPass plus the pass
// itself, so tests only need to build a trace fixture.
static void register_full_pipeline(PassManager& pm) {
    pm.register_pass(std::make_unique<XrefPass>());
    pm.register_pass(std::make_unique<CFGPass>());
    pm.register_pass(std::make_unique<LoopPass>());
    pm.register_pass(std::make_unique<FunctionPass>());
    pm.register_pass(std::make_unique<CallGraphPass>());
    pm.register_pass(std::make_unique<PatternPass>());
    pm.register_pass(std::make_unique<LoopSemanticsPass>());
    pm.register_pass(std::make_unique<AlgorithmSummaryPass>());
}

static const AlgorithmCandidate* find_candidate(const AlgorithmSummaryResult& res,
                                                 AlgorithmFamily fam) {
    for (const auto& c : res.candidates) {
        if (c.family == fam) return &c;
    }
    return nullptr;
}

// ─── Degenerate case: no evidence anywhere ─────────────────────────────────

TEST_CASE("AlgorithmSummaryPass: trace with no crypto signal produces zero "
          "candidates and succeeds",
          "[unit][pass][algorithm_summary]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::add_imm(0, 1, 5),
                {{0, 5ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "algosum_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& raw = pm->require("algorithm_summary");
    REQUIRE(raw.ok());
    auto& res = raw.get<AlgorithmSummaryResult>();

    REQUIRE(res.total() == 0);
    REQUIRE_FALSE(res.has_crypto());
    REQUIRE(res.confirmed_candidates().empty());
    REQUIRE(res.summary_text.find("No algorithms were detected") != std::string::npos);
    // Data-source availability must still be reported even with no matches.
    REQUIRE(res.summary_json.contains("data_sources"));
    REQUIRE(res.summary_json["data_sources"]["pattern"] == true);
}

// ─── Cross-detector merge: pattern + constant + loop → one candidate ───────

TEST_CASE("AlgorithmSummaryPass: AES known constant + SPN-classified loop "
          "merge into a single AES candidate, without absorbing an "
          "unrelated SM4 constant",
          "[unit][pass][algorithm_summary]") {
    // Two independent detectors contribute evidence here, phrased
    // differently:
    //   1. PatternPass constant-materialization -> algorithm "AES"
    //      (AES_RCON9 = 0x1B000000, a real entry in the known-constant db).
    //   2. LoopSemanticsPass SPNRound classification -> loop_kind_algorithm_hint
    //      "SPN-based cipher" (structural shape only, no algorithm name).
    // Before the AlgorithmFamily refactor these landed in 2 separate
    // accumulator buckets keyed by exact string, merged only by fragile
    // substring scans; the fix must collapse them into ONE candidate with
    // family == AES via the structural (family, AlgorithmStructure) lookup
    // in Phase 1c, not string matching.
    //
    // A second, unrelated SM4 constant (SM4_FK0) is also present, to prove
    // the merge does NOT indiscriminately fold every SPN-family constant
    // into the same bucket — AES and SM4 must remain distinct candidates.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // 1. SPN-shaped loop: EOR (AddRoundKey-ish) + two S-box-like loads,
        //    17 iterations so LoopPass sees a 16-count back-edge, matching
        //    the exact SPNRound classification threshold used elsewhere in
        //    the test suite (see test_pass_loop_semantics.cpp SPNRound test).
        constexpr int kN = 17;
        uint64_t pc = 0x1000;
        for (int i = 0; i < kN; i++) {
            ms.x(0) = 0x11; ms.x(1) = (uint64_t)i; ms.x(3) = 0x20000000ULL;
            tw.emit(ms, pc, enc::eor_reg(10, 0, 1),
                    {{10, ms.x(0) ^ (uint64_t)i}, {33, tw.rt(pc + 4)}}, {});
            tw.emit(ms, pc + 4, enc::ldr_reg(4, 3, 2),
                    {{4, 0xAAULL}, {33, tw.rt(pc + 8)}},
                    {{1, 8, ms.x(3) + ms.x(10), 0xAAULL}});
            tw.emit(ms, pc + 8, enc::ldr_reg(6, 3, 2),
                    {{6, 0xBBULL}, {33, tw.rt(pc + 12)}},
                    {{1, 8, ms.x(3) + ms.x(10), 0xBBULL}});
            tw.emit(ms, pc + 12, enc::add_imm(1, 1, 1),
                    {{1, (uint64_t)(i + 1)}, {33, tw.rt(pc + 16)}}, {});
            tw.emit(ms, pc + 16, enc::cmp_imm(1, kN),
                    {{33, tw.rt(pc + 20)}}, {});
            uint64_t next = (i + 1 < kN) ? tw.rt(pc) : tw.rt(pc + 24);
            tw.emit(ms, pc + 20, enc::b_lt(-20), {{33, next}}, {});
        }
        uint64_t after_loop = pc + 24;

        // 2. Known AES constant: AES_RCON9 = 0x1B000000. MOVZ sets the (zero)
        //    low halfword and MOVK sets the high halfword so num_parts == 2
        //    (>= PatternPass's default constants_min_parts, required for the
        //    value to be reported at all — see test_pass_pattern.cpp).
        const uint64_t kAesRcon9 = 0x1B000000ULL;
        tw.emit(ms, after_loop, enc::movz(3, 0x0000, 0),
                {{3, 0ULL}, {33, tw.rt(after_loop + 4)}}, {});
        tw.emit(ms, after_loop + 4, enc::movk(3, 0x1B00, 16),
                {{3, kAesRcon9}, {33, tw.rt(after_loop + 8)}}, {});

        // 3. Known SM4 constant: SM4_FK0 = 0xa3b1bac6 (unrelated algorithm,
        //    also SPN-shaped — must NOT merge with the AES candidate above).
        uint64_t sm4_pc = after_loop + 8;
        tw.emit(ms, sm4_pc, enc::movz(5, 0xbac6, 0),
                {{5, 0xbac6ULL}, {33, tw.rt(sm4_pc + 4)}}, {});
        tw.emit(ms, sm4_pc + 4, enc::movk(5, 0xa3b1, 16),
                {{5, 0xa3b1bac6ULL}, {33, tw.rt(sm4_pc + 8)}}, {});

        tw.emit_anchor(ms);
    }, "algosum_aes_merge");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& raw = pm->require("algorithm_summary");
    REQUIRE(raw.ok());
    auto& res = raw.get<AlgorithmSummaryResult>();

    const auto* aes = find_candidate(res, AlgorithmFamily::AES);
    REQUIRE(aes != nullptr);
    REQUIRE_FALSE(aes->is_speculative);
    // Evidence must reference both the known constant and the loop.
    REQUIRE(aes->evidence.find("AES") != std::string::npos);
    bool has_loop_evidence = aes->evidence.find("SPNRound") != std::string::npos ||
                              aes->evidence.find("Cross-referenced") != std::string::npos;
    REQUIRE(has_loop_evidence);

    const auto* sm4 = find_candidate(res, AlgorithmFamily::SM4);
    REQUIRE(sm4 != nullptr);
    REQUIRE_FALSE(sm4->is_speculative);

    // Critically: AES and SM4 must NOT have been merged into one candidate
    // even though both are SPN-shaped — the SPN loop evidence attaches to
    // only whichever accumulator existed first, and the two constants stay
    // in their own family-keyed buckets regardless.
    REQUIRE(aes != sm4);
    REQUIRE(aes->name != sm4->name);
}

// ─── Hot-function heuristic: absolute + relative thresholds, speculative flag ─

TEST_CASE("AlgorithmSummaryPass: hot function below absolute call-count "
          "floor is not reported",
          "[unit][pass][algorithm_summary]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Call foo exactly 3 times — well under the default floor (25).
        for (int i = 0; i < 3; i++) {
            uint64_t call_pc = 0x1000 + (uint64_t)i * 8;
            tw.emit(ms, call_pc, enc::bl(0x2000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x2000)}}, {});
            tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
            tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "algosum_hot_below_floor");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& res = pm->require("algorithm_summary").get<AlgorithmSummaryResult>();
    for (const auto& c : res.candidates) {
        REQUIRE(c.name.find("Hot function") == std::string::npos);
    }
}

TEST_CASE("AlgorithmSummaryPass: hot function above both thresholds is "
          "reported as speculative and excluded from confirmed_candidates",
          "[unit][pass][algorithm_summary]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 1024;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Call foo 40 times: above the default absolute floor (25) and,
        // since it is also the ONLY callee, automatically at 100% of the
        // trace's max call count (>= the default 20% relative floor too).
        for (int i = 0; i < 40; i++) {
            uint64_t call_pc = 0x1000 + (uint64_t)i * 8;
            tw.emit(ms, call_pc, enc::bl(0x2000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x2000)}}, {});
            tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
            tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "algosum_hot_above_floor");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& res = pm->require("algorithm_summary").get<AlgorithmSummaryResult>();

    const AlgorithmCandidate* hot = nullptr;
    for (const auto& c : res.candidates) {
        if (c.name.find("Hot function") != std::string::npos) hot = &c;
    }
    REQUIRE(hot != nullptr);
    REQUIRE(hot->is_speculative);
    REQUIRE(hot->family == AlgorithmFamily::Unknown);

    // confirmed_candidates() must exclude it.
    for (const auto* c : res.confirmed_candidates()) {
        REQUIRE(c->name.find("Hot function") == std::string::npos);
    }
    // has_crypto() is total()>0-based and DOES include speculative entries —
    // verify total()/confirmed size actually differ in this scenario so the
    // GUI/CLI "N confirmed, M speculative" split is meaningful here.
    REQUIRE(res.total() > res.confirmed_candidates().size());
}

TEST_CASE("AlgorithmSummaryPass: real pattern/constant evidence is never "
          "marked speculative",
          "[unit][pass][algorithm_summary]") {
    const uint64_t kSHA256_H0 = 0x6a09e667ULL;
    auto env = make_env([kSHA256_H0](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        uint16_t lo = kSHA256_H0 & 0xFFFF;
        uint16_t hi = (kSHA256_H0 >> 16) & 0xFFFF;
        tw.emit(ms, 0x1000, enc::movz(3, lo),
                {{3, (uint64_t)lo}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(3, hi, 16),
                {{3, kSHA256_H0}, {33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "algosum_sha256_confirmed");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& res = pm->require("algorithm_summary").get<AlgorithmSummaryResult>();
    const auto* sha256 = find_candidate(res, AlgorithmFamily::SHA256);
    REQUIRE(sha256 != nullptr);
    REQUIRE_FALSE(sha256->is_speculative);
    REQUIRE(sha256->confidence > 0.0f);

    // Must appear in confirmed_candidates() too.
    bool found_in_confirmed = false;
    for (const auto* c : res.confirmed_candidates()) {
        if (c->family == AlgorithmFamily::SHA256) found_in_confirmed = true;
    }
    REQUIRE(found_in_confirmed);
}

// ─── Sorting ────────────────────────────────────────────────────────────────

TEST_CASE("AlgorithmSummaryPass: candidates are sorted by confidence descending",
          "[unit][pass][algorithm_summary]") {
    const uint64_t kSHA256_H0 = 0x6a09e667ULL;
    auto env = make_env([kSHA256_H0](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;

        // Strong evidence: known SHA-256 constant (High confidence pattern match).
        uint16_t lo = kSHA256_H0 & 0xFFFF;
        uint16_t hi = (kSHA256_H0 >> 16) & 0xFFFF;
        tw.emit(ms, 0x1000, enc::movz(3, lo),
                {{3, (uint64_t)lo}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(3, hi, 16),
                {{3, kSHA256_H0}, {33, tw.rt(0x1008)}}, {});

        // Weak evidence: a hot but otherwise unremarkable function.
        for (int i = 0; i < 40; i++) {
            uint64_t call_pc = 0x2000 + (uint64_t)i * 8;
            tw.emit(ms, call_pc, enc::bl(0x3000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x3000)}}, {});
            tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
            tw.emit(ms, 0x3004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "algosum_sorted");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    register_full_pipeline(*pm);

    auto& res = pm->require("algorithm_summary").get<AlgorithmSummaryResult>();
    REQUIRE(res.candidates.size() >= 2);
    for (size_t i = 1; i < res.candidates.size(); i++) {
        REQUIRE(res.candidates[i - 1].confidence >= res.candidates[i].confidence);
    }
    // The confirmed SHA-256 (High-confidence known constant) candidate must
    // rank strictly above the speculative hot-function entry.
    const auto* sha256 = find_candidate(res, AlgorithmFamily::SHA256);
    REQUIRE(sha256 != nullptr);
    REQUIRE(res.candidates.front().family == AlgorithmFamily::SHA256);
}

// ─── Blob cache round-trip ──────────────────────────────────────────────────

TEST_CASE("AlgorithmSummaryPass: result is cached and reload preserves "
          "family/is_speculative on every candidate",
          "[unit][pass][algorithm_summary]") {
    const uint64_t kSHA256_H0 = 0x6a09e667ULL;
    auto env = make_env([kSHA256_H0](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        uint16_t lo = kSHA256_H0 & 0xFFFF;
        uint16_t hi = (kSHA256_H0 >> 16) & 0xFFFF;
        tw.emit(ms, 0x1000, enc::movz(3, lo),
                {{3, (uint64_t)lo}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movk(3, hi, 16),
                {{3, kSHA256_H0}, {33, tw.rt(0x1008)}}, {});
        // Also add a hot (speculative) function so both is_speculative
        // states are exercised across the cache round-trip.
        for (int i = 0; i < 40; i++) {
            uint64_t call_pc = 0x2000 + (uint64_t)i * 8;
            tw.emit(ms, call_pc, enc::bl(0x3000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x3000)}}, {});
            tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
            tw.emit(ms, 0x3004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "algosum_cache_roundtrip");
    REQUIRE(env != nullptr);

    // First run: computes and persists to the pass_blob cache (only
    // triggered for full-trace ranges — make_pm's default range is the full
    // trace, see fixtures/trace_fixture.h).
    uint64_t total_first = 0;
    {
        auto pm = make_pm(*env);
        register_full_pipeline(*pm);
        auto& res = pm->require("algorithm_summary").get<AlgorithmSummaryResult>();
        total_first = res.total();
        REQUIRE(total_first >= 2);  // SHA-256 (confirmed) + hot function (speculative)
    }

    // Second run: a fresh PassManager over the same env/index should hit the
    // fast-path cache load (algorithm_summary_deserialize) and reproduce
    // identical family/is_speculative flags without recomputation.
    {
        auto pm2 = make_pm(*env);
        register_full_pipeline(*pm2);
        auto& res2 = pm2->require("algorithm_summary").get<AlgorithmSummaryResult>();
        REQUIRE(res2.total() == total_first);

        const auto* sha256 = find_candidate(res2, AlgorithmFamily::SHA256);
        REQUIRE(sha256 != nullptr);
        REQUIRE_FALSE(sha256->is_speculative);

        bool found_speculative = false;
        for (const auto& c : res2.candidates) {
            if (c.is_speculative) found_speculative = true;
        }
        REQUIRE(found_speculative);
    }
}

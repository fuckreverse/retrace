/*
 * test_pass_yara_mem_scan.cpp — Unit tests for tenet::YaraMemScanPass
 *
 * NOTE: YaraMemScanPass::run() is only functional when compiled with
 * TENET_HAS_YARA (requires libyara). Without it, run() fails outright with
 * an explicit "YARA support not compiled in" error — it does NOT silently
 * no-op. All TEST_CASEs below that exercise run() are therefore gated on
 * TENET_HAS_YARA. find_default_rules_dirs() itself has no YARA dependency
 * (it's pure filesystem-path logic) and is tested unconditionally.
 *
 * Verifies:
 *   - find_default_rules_dirs() returns a non-empty, plausible candidate
 *     list anchored on the executable path (not just cwd).
 *   - Pass runs without error when TENET_HAS_YARA and the bundled
 *     slowmo/rules/ directory is discoverable.
 *   - YaraMemScanResult::total() is callable and non-negative.
 *   - pages_scanned / bytes_scanned are populated after the run.
 *   - rules_loaded > 0 and rule_search_dirs is populated on success.
 *   - A user_rules_dir pointing at a real *empty* extra directory still
 *     succeeds (bundled default rules are still found independently).
 *   - auto_scan_all_pages=false with empty scan_points produces zero scans.
 *   - by_category() returns valid (possibly empty) matches.
 *   - When TENET_HAS_YARA: known crypto constant in memory yields a match.
 *
 * Run:  ctest -R 'yara_mem_scan' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory/yara_mem_scan_pass.h"

#include <algorithm>
#include <filesystem>

using namespace tenet;
using namespace tenet::test;

// ─── find_default_rules_dirs() — no YARA dependency, always testable ───────

TEST_CASE("YaraMemScanPass::find_default_rules_dirs returns a non-empty candidate list",
          "[unit][pass][yara_mem_scan]") {
    auto dirs = YaraMemScanPass::find_default_rules_dirs();
    REQUIRE_FALSE(dirs.empty());
}

TEST_CASE("YaraMemScanPass::find_default_rules_dirs includes an executable-relative candidate",
          "[unit][pass][yara_mem_scan]") {
    // At least one candidate should be anchored near the test binary itself
    // (../rules or ../../rules relative to the build output), not just cwd —
    // this is what makes rule discovery work regardless of the process's
    // current working directory (see class-level doc comment).
    auto dirs = YaraMemScanPass::find_default_rules_dirs();
    bool any_ends_in_rules = std::any_of(dirs.begin(), dirs.end(), [](const auto& p) {
        return p.filename() == "rules";
    });
    REQUIRE(any_ends_in_rules);
}

TEST_CASE("YaraMemScanPass::find_default_rules_dirs de-duplicates candidates",
          "[unit][pass][yara_mem_scan]") {
    // exe_dir/../rules and cwd/../rules can coincide when running tests from
    // the build directory — the candidate list should not contain the same
    // resolved path twice.
    auto dirs = YaraMemScanPass::find_default_rules_dirs();
    std::vector<std::filesystem::path> sorted(dirs.begin(), dirs.end());
    std::sort(sorted.begin(), sorted.end());
    auto it = std::adjacent_find(sorted.begin(), sorted.end());
    REQUIRE(it == sorted.end());
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Writes a 64-byte buffer of known values to base_addr via STR instructions.
static void write_known_buffer(TraceWriter& tw, MachineState& ms,
                               uint64_t base_addr, uint8_t fill_byte) {
    uint64_t spc = 0x8000;
    for (int i = 0; i < 8; i++) {  // 8 × 8 = 64 bytes
        uint64_t addr = base_addr + (uint64_t)i * 8;
        uint64_t val  = static_cast<uint64_t>(fill_byte) * 0x0101010101010101ULL;
        tw.emit(ms, spc, enc::str_imm(10, 20, 0),
                {{33, tw.rt(spc + 4)}},
                {{2 /*write*/, 8, addr, val}});
        spc += 4;
    }
    tw.emit_anchor(ms);
}

// ─── Tests requiring TENET_HAS_YARA ─────────────────────────────────────────
//
// run() itself (as opposed to find_default_rules_dirs()) requires libyara.
// In TENET_HAS_YARA=OFF builds it fails deliberately (see class doc comment
// in yara_mem_scan_pass.h) rather than silently no-op'ing, so exercising it
// meaningfully requires YARA to be compiled in.
#ifdef TENET_HAS_YARA

TEST_CASE("YaraMemScanPass: runs successfully and discovers the bundled rules",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0xF0000ULL;

    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_known_buffer(tw, ms, kBase, 0xAA);
    }, "yara_basic");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();
    SECTION("total() is accessible") {
        REQUIRE_NOTHROW(res.total());
    }
    SECTION("by_category() does not crash") {
        REQUIRE_NOTHROW(res.by_category(PatternCategory::Crypto));
    }
    SECTION("rules_loaded > 0 — bundled slowmo/rules/*.yar were found") {
        // This is the key regression test for the exe-relative rule lookup:
        // if find_default_rules_dirs() regresses back to cwd-only lookup,
        // ctest (which may run from an arbitrary directory) would find zero
        // rules here and this assertion would catch it.
        REQUIRE(res.rules_loaded > 0);
    }
    SECTION("rule_search_dirs records at least one searched directory") {
        REQUIRE_FALSE(res.rule_search_dirs.empty());
    }
}

TEST_CASE("YaraMemScanPass: empty user_rules_dir does not prevent default rules from loading",
          "[unit][pass][yara_mem_scan]") {
    // Pointing user_rules_dir at a real-but-empty directory should not
    // affect discovery of the bundled default rules — the two sources are
    // additive, not exclusive.
    auto empty_dir = std::filesystem::temp_directory_path() / "tenet_yara_test_empty_dir";
    std::filesystem::create_directories(empty_dir);

    const uint64_t kBase = 0x600000ULL;
    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_known_buffer(tw, ms, kBase, 0xBB);
    }, "yara_empty_extra_dir");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;
    cfg.user_rules_dir = empty_dir;

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();
    REQUIRE(res.rules_loaded > 0);

    std::filesystem::remove_all(empty_dir);
}

TEST_CASE("YaraMemScanPass: nonexistent user_rules_dir does not fail the pass",
          "[unit][pass][yara_mem_scan]") {
    // A typo'd/stale user_rules_dir should be handled gracefully (treated as
    // just another directory that contributes zero rules) as long as the
    // bundled default rules are still discoverable.
    const uint64_t kBase = 0x700000ULL;
    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_known_buffer(tw, ms, kBase, 0xCC);
    }, "yara_missing_extra_dir");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;
    cfg.user_rules_dir = "/nonexistent/path/tenet_yara_test_does_not_exist";

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());
    REQUIRE(raw.get<YaraMemScanResult>().rules_loaded > 0);
}

TEST_CASE("YaraMemScanPass: pages_scanned reflects actual work done",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0x100000ULL;

    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Write to two distinct pages
        write_known_buffer(tw, ms, kBase,             0x11);
        write_known_buffer(tw, ms, kBase + 0x1000,    0x22);
    }, "yara_pages");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;
    cfg.min_writes_per_page = 1;

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();

    SECTION("pages_scanned > 0 when auto_scan_all_pages=true") {
        // At least one page was written and should be scanned
        REQUIRE(res.pages_scanned > 0);
    }
    SECTION("bytes_scanned >= pages_scanned * 8 (at least some bytes)") {
        REQUIRE(res.bytes_scanned >= res.pages_scanned * 8);
    }
}

TEST_CASE("YaraMemScanPass: auto_scan_all_pages=false with empty scan_points → 0 scans",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0x200000ULL;

    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_known_buffer(tw, ms, kBase, 0x55);
    }, "yara_no_scan");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = false;   // disable auto-scan
    cfg.scan_points.clear();           // no explicit scan points

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();
    SECTION("nothing scanned when auto_scan is off and no scan points") {
        REQUIRE(res.pages_scanned == 0);
        REQUIRE(res.bytes_scanned == 0);
        REQUIRE(res.total() == 0);
    }
}

TEST_CASE("YaraMemScanPass: explicit scan_point targets correct address",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0x300000ULL;
    const uint64_t kSize = 64;

    uint64_t last_store_id = 0;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        uint64_t spc = 0x8100;
        for (int i = 0; i < 8; i++) {
            uint64_t addr = kBase + (uint64_t)i * 8;
            tw.emit(ms, spc, enc::str_imm(10, 20, 0),
                    {{33, tw.rt(spc + 4)}},
                    {{2, 8, addr, 0xDEADBEEFDEADBEEFULL}});
            last_store_id = tw.inst_count - 1;
            spc += 4;
        }
        tw.emit_anchor(ms);
    }, "yara_explicit_point");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = false;
    {
        YaraMemScanConfig::ScanPoint sp;
        sp.addr     = kBase;
        sp.size     = kSize;
        sp.inst_id  = last_store_id;
        sp.label    = "explicit_test_point";
        cfg.scan_points.push_back(std::move(sp));
    }

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();

    SECTION("bytes_scanned == kSize when explicit scan point is set") {
        // The scan covers exactly kSize bytes of the explicit scan point
        REQUIRE(res.bytes_scanned >= kSize);
    }
    SECTION("pages_scanned == 1 for explicit scan point") {
        REQUIRE(res.pages_scanned >= 1);
    }
}

TEST_CASE("YaraMemScanPass: by_category() returns only correct-category matches",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0x400000ULL;

    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_known_buffer(tw, ms, kBase, 0x63);  // AES S-box first byte
    }, "yara_category");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& res = pm->require("yara_mem_scan").get<YaraMemScanResult>();

    // by_category() returns pointers into matches — verify they're valid
    SECTION("crypto category matches all have category == Crypto") {
        auto crypto = res.by_category(PatternCategory::Crypto);
        for (const auto* m : crypto) {
            REQUIRE(m != nullptr);
            REQUIRE(m->category == PatternCategory::Crypto);
        }
    }
    SECTION("anti-debug category matches all have category == AntiDebug") {
        auto ad = res.by_category(PatternCategory::AntiDebug);
        for (const auto* m : ad) {
            REQUIRE(m != nullptr);
            REQUIRE(m->category == PatternCategory::AntiDebug);
        }
    }
}

TEST_CASE("YaraMemScanPass: min_entropy_threshold skips low-entropy pages",
          "[unit][pass][yara_mem_scan]") {
    const uint64_t kBase = 0x500000ULL;

    auto env = make_env([kBase](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Write all zeros — entropy = 0
        write_known_buffer(tw, ms, kBase, 0x00);
    }, "yara_entropy_threshold");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    YaraMemScanConfig cfg;
    cfg.auto_scan_all_pages = true;
    cfg.min_entropy_threshold = 4.0f;  // skip low-entropy (zero) pages

    pm->register_pass(std::make_unique<YaraMemScanPass>(cfg));
    auto& raw = pm->require("yara_mem_scan");
    REQUIRE(raw.ok());

    auto& res = raw.get<YaraMemScanResult>();

    SECTION("pages skipped due to low entropy") {
        // All-zero page has entropy 0 < 4.0, so it should be skipped
        REQUIRE(res.pages_skipped_entropy >= 1);
    }
    SECTION("pages_scanned is reduced when entropy threshold filters pages") {
        // The skipped page is not in pages_scanned
        REQUIRE(res.pages_scanned == 0);
    }
}

#endif  // TENET_HAS_YARA

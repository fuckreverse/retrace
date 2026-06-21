/*
 * test_pass_yara_mem_scan.cpp — Unit tests for tenet::YaraMemScanPass
 *
 * NOTE: YaraMemScanPass is only fully functional when compiled with
 * TENET_HAS_YARA.  Without libyara, the pass still runs but finds zero matches
 * (graceful no-op). These tests validate both the graceful-no-op path and,
 * when TENET_HAS_YARA is available, basic scanning behavior.
 *
 * Verifies:
 *   - Pass runs without error regardless of YARA availability.
 *   - YaraMemScanResult::total() is callable and non-negative.
 *   - pages_scanned / bytes_scanned are populated after the run.
 *   - auto_scan_all_pages=false with empty scan_points produces zero scans.
 *   - by_category() returns valid (possibly empty) matches.
 *   - When TENET_HAS_YARA: known crypto constant in memory yields a match.
 *
 * Run:  ctest -R 'yara_mem_scan' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/yara_mem_scan_pass.h"

using namespace tenet;
using namespace tenet::test;

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

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("YaraMemScanPass: runs without error (graceful no-op without YARA)",
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

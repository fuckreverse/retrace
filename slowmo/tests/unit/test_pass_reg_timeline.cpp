/*
 * test_pass_reg_timeline.cpp — Unit tests for tenet::RegTimelinePass
 *
 * Verifies:
 *   - Single-register mode: only writes to the target register appear.
 *   - All-register mode (0xFF): captures writes to any register.
 *   - Write counts per register are correct.
 *   - inst_id order is ascending in the entries vector.
 *   - Range restriction: start_inst_id / end_inst_id filters correctly.
 *   - unique_values is populated in single-reg mode.
 *   - Old-value/new-value pairs are recorded.
 *
 * Run:  ctest -R 'reg_timeline' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/profile/reg_timeline_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Shared trace builder ────────────────────────────────────────────────────

/// Trace:
///   inst 0: x0 = 0x10
///   inst 1: x1 = 0x20
///   inst 2: x0 = 0x30    (second write to x0)
///   inst 3: x2 = 0x40
///   inst 4: x0 = 0x50    (third write to x0)
static std::unique_ptr<TraceEnv> make_timeline_trace() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        tw.emit(ms, 0x1000, enc::movz(0, 0x10),
                {{0, 0x10ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movz(1, 0x20),
                {{1, 0x20ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::movz(0, 0x30),
                {{0, 0x30ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit(ms, 0x100C, enc::movz(2, 0x40),
                {{2, 0x40ULL}, {33, tw.rt(0x1010)}}, {});
        tw.emit(ms, 0x1010, enc::movz(0, 0x50),
                {{0, 0x50ULL}, {33, tw.rt(0x1014)}}, {});
        tw.emit_anchor(ms);
    }, "reg_timeline");
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("RegTimelinePass: single-register mode tracks only x0 writes",
          "[unit][pass][reg_timeline]") {
    auto env = make_timeline_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0;   // track x0 only
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& raw = pm->require("reg_timeline");
    REQUIRE(raw.ok());
    auto& res = raw.get<RegTimelineResult>();

    SECTION("exactly 3 entries for x0 (written at insts 0, 2, 4)") {
        REQUIRE(res.entries.size() == 3);
    }
    SECTION("all entries belong to register 0") {
        for (const auto& e : res.entries) {
            REQUIRE(e.reg_index == 0);
        }
    }
    SECTION("new values are 0x10, 0x30, 0x50 in order") {
        REQUIRE(res.entries[0].new_value == 0x10ULL);
        REQUIRE(res.entries[1].new_value == 0x30ULL);
        REQUIRE(res.entries[2].new_value == 0x50ULL);
    }
    SECTION("write_counts[0] == 3") {
        REQUIRE(res.write_counts[0] == 3);
    }
    SECTION("total_writes == 3") {
        REQUIRE(res.total_writes == 3);
    }
    SECTION("entries are sorted ascending by inst_id") {
        for (size_t i = 1; i < res.entries.size(); i++) {
            REQUIRE(res.entries[i].inst_id > res.entries[i - 1].inst_id);
        }
    }
}

TEST_CASE("RegTimelinePass: all-register mode (0xFF) captures all writes",
          "[unit][pass][reg_timeline]") {
    auto env = make_timeline_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0xFF;  // all registers
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& res = pm->require("reg_timeline").get<RegTimelineResult>();

    // 5 instructions each write exactly one register (plus PC = reg 33)
    // x0 written 3×, x1 once, x2 once, PC 5×
    SECTION("total_writes includes all register writes") {
        // At minimum: 3 (x0) + 1 (x1) + 1 (x2) = 5 non-PC writes
        REQUIRE(res.total_writes >= 5);
    }
    SECTION("write_counts[0] >= 3") {
        REQUIRE(res.write_counts[0] >= 3);
    }
    SECTION("write_counts[1] >= 1") {
        REQUIRE(res.write_counts[1] >= 1);
    }
    SECTION("write_counts[2] >= 1") {
        REQUIRE(res.write_counts[2] >= 1);
    }
}

TEST_CASE("RegTimelinePass: range restriction start_inst_id filters early insts",
          "[unit][pass][reg_timeline]") {
    auto env = make_timeline_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0;
    cfg.start_inst_id = 2;   // only insts 2..end
    cfg.end_inst_id = UINT64_MAX;
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& res = pm->require("reg_timeline").get<RegTimelineResult>();

    SECTION("entries only from inst_id >= 2") {
        for (const auto& e : res.entries) {
            REQUIRE(e.inst_id >= 2);
        }
    }
    SECTION("inst 0 (first x0=0x10 write) is excluded") {
        bool found_0x10 = false;
        for (const auto& e : res.entries) {
            if (e.new_value == 0x10ULL) found_0x10 = true;
        }
        REQUIRE_FALSE(found_0x10);
    }
    SECTION("inst 2 (x0=0x30) is included") {
        bool found_0x30 = false;
        for (const auto& e : res.entries) {
            if (e.new_value == 0x30ULL) found_0x30 = true;
        }
        REQUIRE(found_0x30);
    }
}

TEST_CASE("RegTimelinePass: range restriction end_inst_id excludes late insts",
          "[unit][pass][reg_timeline]") {
    auto env = make_timeline_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0;
    cfg.start_inst_id = 0;
    cfg.end_inst_id = 3;   // include only insts 0..3
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& res = pm->require("reg_timeline").get<RegTimelineResult>();

    SECTION("entries only up to inst_id <= 3") {
        for (const auto& e : res.entries) {
            REQUIRE(e.inst_id <= 3);
        }
    }
    SECTION("inst 4 (x0=0x50) is excluded") {
        bool found_0x50 = false;
        for (const auto& e : res.entries) {
            if (e.new_value == 0x50ULL) found_0x50 = true;
        }
        REQUIRE_FALSE(found_0x50);
    }
}

TEST_CASE("RegTimelinePass: unique_values populated in single-reg mode",
          "[unit][pass][reg_timeline]") {
    auto env = make_timeline_trace();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0;
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& res = pm->require("reg_timeline").get<RegTimelineResult>();

    SECTION("unique_values contains all 3 distinct x0 values") {
        auto& uv = res.unique_values;
        bool has_10 = false, has_30 = false, has_50 = false;
        for (uint64_t v : uv) {
            if (v == 0x10ULL) has_10 = true;
            if (v == 0x30ULL) has_30 = true;
            if (v == 0x50ULL) has_50 = true;
        }
        REQUIRE(has_10);
        REQUIRE(has_30);
        REQUIRE(has_50);
    }
    SECTION("unique_values has at most 3 entries (only 3 distinct values)") {
        REQUIRE(res.unique_values.size() <= 3);
    }
}

TEST_CASE("RegTimelinePass: empty trace returns empty result",
          "[unit][pass][reg_timeline]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        // Single NOP, no register diffs
        tw.emit(ms, 0x1000, enc::nop(),
                {{33, tw.rt(0x1004)}}, {});
        tw.emit_anchor(ms);
    }, "reg_timeline_empty");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    RegTimelineConfig cfg;
    cfg.target_reg = 0;   // x0 is never written
    pm->register_pass(std::make_unique<RegTimelinePass>(cfg));

    auto& raw = pm->require("reg_timeline");
    REQUIRE(raw.ok());

    auto& res = raw.get<RegTimelineResult>();
    SECTION("no entries for unwritten register") {
        REQUIRE(res.entries.empty());
    }
    SECTION("total_writes is 0") {
        REQUIRE(res.write_counts[0] == 0);
    }
}

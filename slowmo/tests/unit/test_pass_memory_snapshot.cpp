/*
 * test_pass_memory_snapshot.cpp — Unit tests for tenet::MemorySnapshotPass
 *
 * MemorySnapshotPass behavior for explicit snapshot_inst_ids:
 *   When inst_id N is in snapshot_inst_ids, the pass reads the register state
 *   BEFORE instruction N and captures:
 *     1. The stack (SP-relative)
 *     2. Any x0-x7 value that looks like a pointer (>= 0x100000000)
 *   So a test must set x0..x7 to point to the address we want to snapshot.
 *
 * Run:  ctest -R 'memory_snapshot' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory_snapshot_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helper: emit stores that write `n_bytes` to `base_addr` ─────────────

/// Emits STR instructions that write 8 bytes each to consecutive addresses,
/// filling `n_bytes` total at `base_addr`.  Updates `spc` (static PC counter)
/// and `last_store_inst` with the inst_id of the final store.
static void write_buffer(TraceWriter& tw, MachineState& ms,
                         uint64_t base_addr, int n_bytes,
                         uint64_t& spc, uint64_t& last_store_inst) {
    int stores = (n_bytes + 7) / 8;
    for (int i = 0; i < stores; i++) {
        uint64_t addr  = base_addr + (uint64_t)i * 8;
        uint64_t value = static_cast<uint64_t>(i) * 0x0101010101010101ULL;
        tw.emit(ms, spc, enc::str_imm(5, 20, 0),
                {{33, tw.rt(spc + 4)}},
                {{2 /*WRITE*/, 8, addr, value}});
        last_store_inst = tw.inst_count - 1;
        spc += 4;
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("MemorySnapshotPass: explicit snapshot at specified inst_id",
          "[unit][pass][memory_snapshot]") {
    // kBase must be >= 0x100000000 so the pass recognises it as a pointer
    // (AArch64 pointer heuristic: value >= 0x100000000).
    // Use 0x1_0000_0000 (exactly 4 GB) encoded via movz x0, #1, lsl #32.
    const uint64_t kBase = 0x100000000ULL;
    const uint32_t kSnapshotSize = 32;

    uint64_t spc = 0x4000;
    uint64_t last_store = 0;
    uint64_t snap_inst = 0;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write 32 bytes to kBase
        write_buffer(tw, ms, kBase, kSnapshotSize, spc, last_store);

        // Point x0 at kBase so the explicit snapshot picks it up.
        // movz x0, #1, lsl #32  =>  x0 = 0x1_0000_0000 = kBase
        tw.emit(ms, spc, enc::movz(0, 1, 32),
                {{0, kBase}, {33, tw.rt(spc + 4)}}, {});
        spc += 4;

        // A NOP at the snapshot point — x0 already holds kBase
        tw.emit(ms, spc, enc::nop(),
                {{33, tw.rt(spc + 4)}}, {});
        snap_inst = tw.inst_count;  // snap BEFORE this inst: x0 = kBase
        spc += 4;

        tw.emit_anchor(ms);
    }, "memsnapshot_basic");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    MemorySnapshotConfig cfg;
    cfg.snapshot_at_function_calls = false;
    cfg.snapshot_size = kSnapshotSize;
    // Snapshot at snap_inst (the NOP), at which x0 = kBase
    cfg.snapshot_inst_ids = {snap_inst};

    pm->register_pass(std::make_unique<MemorySnapshotPass>(cfg));
    auto& raw = pm->require("memory_snapshot");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemorySnapshotResult>();

    SECTION("at least one snapshot was captured") {
        REQUIRE(res.total() >= 1);
    }
    SECTION("a snapshot with addr == kBase exists (from x0 register)") {
        bool found = false;
        for (const auto& snap : res.snapshots) {
            if (snap.addr == kBase) { found = true; break; }
        }
        REQUIRE(found);
    }
    SECTION("snapshot data is non-empty") {
        REQUIRE_FALSE(res.snapshots[0].data.empty());
    }
}

TEST_CASE("MemorySnapshotPass: by_inst_id lookup works",
          "[unit][pass][memory_snapshot]") {
    // kBase must be >= 0x100000000; use 0x2_0000_0000 (8 GB) to avoid
    // aliasing with the first test's kBase = 0x1_0000_0000.
    // Encoded via movz x1, #2, lsl #32.
    const uint64_t kBase = 0x200000000ULL;
    const uint32_t kSnapshotSize = 16;

    uint64_t spc = 0x4100;
    uint64_t last_store = 0;
    uint64_t snap_inst = 0;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        write_buffer(tw, ms, kBase, kSnapshotSize, spc, last_store);

        // Load kBase into x1: movz x1, #2, lsl #32  =>  x1 = 0x2_0000_0000
        tw.emit(ms, spc, enc::movz(1, 2, 32),
                {{1, kBase}, {33, tw.rt(spc + 4)}}, {});
        spc += 4;

        tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        snap_inst = tw.inst_count;
        spc += 4;

        tw.emit_anchor(ms);
    }, "memsnapshot_lookup");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    MemorySnapshotConfig cfg;
    cfg.snapshot_at_function_calls = false;
    cfg.snapshot_size = kSnapshotSize;
    cfg.snapshot_inst_ids = {snap_inst};

    pm->register_pass(std::make_unique<MemorySnapshotPass>(cfg));
    auto& res = pm->require("memory_snapshot").get<MemorySnapshotResult>();

    SECTION("snapshots_at() returns snapshots for the given inst_id") {
        auto snaps = res.snapshots_at(snap_inst);
        REQUIRE_FALSE(snaps.empty());
    }
    SECTION("snapshots_at() returns empty for a non-existent inst_id") {
        auto snaps = res.snapshots_at(9999);
        REQUIRE(snaps.empty());
    }
    SECTION("a snapshot with kBase addr exists from x1 register") {
        auto snaps = res.snapshots_at(snap_inst);
        bool found = false;
        for (const auto* s : snaps) {
            if (s->addr == kBase) { found = true; break; }
        }
        REQUIRE(found);
    }
}

TEST_CASE("MemorySnapshotPass: multiple explicit snapshots at different points",
          "[unit][pass][memory_snapshot]") {
    const uint64_t kBase1 = 0x100C0000ULL;
    const uint64_t kBase2 = 0x100C1000ULL;
    const uint32_t kSnapshotSize = 8;

    uint64_t spc = 0x4200;
    uint64_t snap1 = 0, snap2 = 0;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        // Write to kBase1
        tw.emit(ms, spc, enc::str_imm(5, 20, 0),
                {{33, tw.rt(spc + 4)}},
                {{2, 8, kBase1, 0x1111111111111111ULL}});
        spc += 4;

        // Point x0 at kBase1
        tw.emit(ms, spc, enc::movz(0, static_cast<uint16_t>((kBase1 >> 16) & 0xFFFF), 16),
                {{0, kBase1}, {33, tw.rt(spc + 4)}}, {});
        spc += 4;

        // Snapshot point 1: x0 = kBase1
        tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        snap1 = tw.inst_count;
        spc += 4;

        // Write to kBase2
        tw.emit(ms, spc, enc::str_imm(5, 21, 0),
                {{33, tw.rt(spc + 4)}},
                {{2, 8, kBase2, 0x2222222222222222ULL}});
        spc += 4;

        // Point x0 at kBase2
        tw.emit(ms, spc, enc::movz(0, static_cast<uint16_t>((kBase2 >> 16) & 0xFFFF), 16),
                {{0, kBase2}, {33, tw.rt(spc + 4)}}, {});
        spc += 4;

        // Snapshot point 2: x0 = kBase2
        tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        snap2 = tw.inst_count;
        spc += 4;

        tw.emit_anchor(ms);
    }, "memsnapshot_multi");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    MemorySnapshotConfig cfg;
    cfg.snapshot_at_function_calls = false;
    cfg.snapshot_size = kSnapshotSize;
    cfg.snapshot_inst_ids = {snap1, snap2};

    pm->register_pass(std::make_unique<MemorySnapshotPass>(cfg));
    auto& res = pm->require("memory_snapshot").get<MemorySnapshotResult>();

    SECTION("two or more snapshots were captured") {
        REQUIRE(res.total() >= 2);
    }
    SECTION("snapshots_at(snap1) is non-empty") {
        auto snaps = res.snapshots_at(snap1);
        REQUIRE_FALSE(snaps.empty());
    }
    SECTION("snapshots_at(snap2) is non-empty") {
        auto snaps = res.snapshots_at(snap2);
        REQUIRE_FALSE(snaps.empty());
    }
}

TEST_CASE("MemorySnapshotPass: max_snapshots cap is respected",
          "[unit][pass][memory_snapshot]") {
    // Each explicit snap point captures SP + potentially up to 8 pointer regs.
    // With max_snapshots=3, we should never exceed that limit.

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;

        uint64_t spc = 0x5000;
        for (int i = 0; i < 20; i++) {
            uint64_t addr = 0x200000000ULL + (uint64_t)i * 64;  // >4GB pointer
            tw.emit(ms, spc, enc::str_imm(5, 20, 0),
                    {{33, tw.rt(spc + 4)}},
                    {{2, 8, addr, (uint64_t)i}});
            spc += 4;
        }
        tw.emit_anchor(ms);
    }, "memsnapshot_maxcap");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    MemorySnapshotConfig cfg;
    cfg.snapshot_at_function_calls = false;
    cfg.snapshot_size = 8;
    cfg.max_snapshots = 3;  // strict cap

    // Provide 10 explicit snapshot inst_ids (0-indexed IDs)
    for (uint64_t id = 1; id <= 10; id++) {
        cfg.snapshot_inst_ids.push_back(id);
    }

    pm->register_pass(std::make_unique<MemorySnapshotPass>(cfg));
    auto& raw = pm->require("memory_snapshot");
    REQUIRE(raw.ok());

    auto& res = raw.get<MemorySnapshotResult>();

    SECTION("total snapshots does not exceed max_snapshots") {
        REQUIRE(res.total() <= 3);
    }
}

TEST_CASE("MemorySnapshotPass: hex_dump produces non-empty string",
          "[unit][pass][memory_snapshot]") {
    const uint64_t kBase = 0x100E0000ULL;

    uint64_t spc = 0x6000;
    uint64_t last_store = 0;
    uint64_t snap_inst = 0;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        write_buffer(tw, ms, kBase, 16, spc, last_store);

        // Point x0 at kBase
        tw.emit(ms, spc, enc::movz(0, static_cast<uint16_t>((kBase >> 16) & 0xFFFF), 16),
                {{0, kBase}, {33, tw.rt(spc + 4)}}, {});
        spc += 4;

        tw.emit(ms, spc, enc::nop(), {{33, tw.rt(spc + 4)}}, {});
        snap_inst = tw.inst_count;
        spc += 4;

        tw.emit_anchor(ms);
    }, "memsnapshot_hexdump");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    MemorySnapshotConfig cfg;
    cfg.snapshot_at_function_calls = false;
    cfg.snapshot_size = 16;
    cfg.snapshot_inst_ids = {snap_inst};

    pm->register_pass(std::make_unique<MemorySnapshotPass>(cfg));
    auto& res = pm->require("memory_snapshot").get<MemorySnapshotResult>();

    REQUIRE_FALSE(res.snapshots.empty());
    SECTION("hex_dump is non-empty") {
        std::string dump = MemorySnapshotResult::hex_dump(res.snapshots[0]);
        REQUIRE_FALSE(dump.empty());
    }
}

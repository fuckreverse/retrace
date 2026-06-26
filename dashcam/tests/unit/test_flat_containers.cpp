/*
 * test_flat_containers.cpp — Catch2 unit tests for FlatContainers.h
 *
 * Covers: WriteRegList layout, FlatPcSet insert/contains/dedup/resize,
 * FlatWriteRegCache insert/find/resize/value-integrity, edge cases
 * (aligned PC values, hash collision chains, load-factor-triggered rehash,
 * move semantics).
 *
 * Run:  ctest -R flat_containers --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <vector>

#include "FlatContainers.h"

using namespace qbditrace;

// ═══════════════════════════════════════════════════════════════════════════════
// WriteRegList
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("WriteRegList: default-constructed is empty",
          "[unit][qbditrace][flat_containers]") {
    WriteRegList wl;
    REQUIRE(wl.count == 0);
    REQUIRE(wl.fpr_count == 0);
    for (int i = 0; i < 8; ++i) {
        REQUIRE(wl.idx[i] == 0);
        REQUIRE(wl.fpr_idx[i] == 0);
    }
}

TEST_CASE("WriteRegList: stores GPR and FPR indices correctly",
          "[unit][qbditrace][flat_containers]") {
    WriteRegList wl;
    wl.count = 3;
    wl.idx[0] = 0;   // x0
    wl.idx[1] = 15;  // x15
    wl.idx[2] = 30;  // lr

    wl.fpr_count = 2;
    wl.fpr_idx[0] = 0;   // v0
    wl.fpr_idx[1] = 31;  // v31

    REQUIRE(wl.count == 3);
    REQUIRE(wl.idx[0] == 0);
    REQUIRE(wl.idx[1] == 15);
    REQUIRE(wl.idx[2] == 30);
    REQUIRE(wl.fpr_count == 2);
    REQUIRE(wl.fpr_idx[0] == 0);
    REQUIRE(wl.fpr_idx[1] == 31);
}

TEST_CASE("WriteRegList: is trivially copyable (POD-like)",
          "[unit][qbditrace][flat_containers]") {
    WriteRegList a;
    a.count = 2;
    a.idx[0] = 5;
    a.idx[1] = 10;
    a.fpr_count = 1;
    a.fpr_idx[0] = 7;

    WriteRegList b;
    std::memcpy(&b, &a, sizeof(WriteRegList));

    REQUIRE(b.count == 2);
    REQUIRE(b.idx[0] == 5);
    REQUIRE(b.idx[1] == 10);
    REQUIRE(b.fpr_count == 1);
    REQUIRE(b.fpr_idx[0] == 7);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FlatPcSet
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("FlatPcSet: default-constructed is empty",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s;
    REQUIRE(s.size() == 0);
    REQUIRE(s.capacity() >= 16);
}

TEST_CASE("FlatPcSet: custom initial capacity is rounded to power of two",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(100);
    REQUIRE(s.capacity() >= 100);
    // Must be power of two
    size_t cap = s.capacity();
    REQUIRE((cap & (cap - 1)) == 0);
}

TEST_CASE("FlatPcSet: insert returns true for new keys, false for duplicates",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(64);

    REQUIRE(s.insert(0x1000));   // new
    REQUIRE(s.insert(0x1004));   // new
    REQUIRE_FALSE(s.insert(0x1000));  // duplicate
    REQUIRE_FALSE(s.insert(0x1004));  // duplicate
    REQUIRE(s.insert(0x1008));   // new

    REQUIRE(s.size() == 3);
}

TEST_CASE("FlatPcSet: contains checks membership correctly",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(64);

    REQUIRE_FALSE(s.contains(0x2000));
    s.insert(0x2000);
    REQUIRE(s.contains(0x2000));
    REQUIRE_FALSE(s.contains(0x2004));
    REQUIRE_FALSE(s.contains(0x3000));
}

TEST_CASE("FlatPcSet: handles 4-byte-aligned AArch64 PCs well",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(64);

    // Simulate a sequence of AArch64 instruction PCs (4-byte aligned)
    for (uint64_t pc = 0x100000; pc < 0x100100; pc += 4) {
        REQUIRE(s.insert(pc));
    }
    REQUIRE(s.size() == 64);

    // All should be present
    for (uint64_t pc = 0x100000; pc < 0x100100; pc += 4) {
        REQUIRE(s.contains(pc));
    }

    // None of the +2 offset PCs should be present
    for (uint64_t pc = 0x100002; pc < 0x100100; pc += 4) {
        REQUIRE_FALSE(s.contains(pc));
    }
}

TEST_CASE("FlatPcSet: auto-resizes beyond load factor threshold",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(16);  // initial cap = 16, load threshold ~ 12

    size_t initial_cap = s.capacity();

    // Insert enough keys to trigger at least one resize
    for (uint64_t i = 1; i <= 100; ++i) {
        s.insert(i * 4);  // 4-byte aligned
    }
    REQUIRE(s.size() == 100);
    REQUIRE(s.capacity() > initial_cap);

    // All keys still findable after resize
    for (uint64_t i = 1; i <= 100; ++i) {
        REQUIRE(s.contains(i * 4));
    }
}

TEST_CASE("FlatPcSet: large-scale insert + contains (10K distinct PCs)",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(64);

    constexpr size_t N = 10000;
    constexpr uint64_t base = 0x180000000ULL;  // typical iOS ASLR base

    for (size_t i = 0; i < N; ++i) {
        uint64_t pc = base + i * 4;
        REQUIRE(s.insert(pc));
    }
    REQUIRE(s.size() == N);

    // Forward check
    for (size_t i = 0; i < N; ++i) {
        REQUIRE(s.contains(base + i * 4));
    }
    // Gaps should not be present
    for (size_t i = 0; i < N; ++i) {
        REQUIRE_FALSE(s.contains(base + i * 4 + 2));
    }
}

TEST_CASE("FlatPcSet: move constructor transfers ownership",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet a(64);
    a.insert(0x4000);
    a.insert(0x4004);
    REQUIRE(a.size() == 2);

    FlatPcSet b(std::move(a));
    REQUIRE(b.size() == 2);
    REQUIRE(b.contains(0x4000));
    REQUIRE(b.contains(0x4004));
    // Source should be empty (moved-from)
    REQUIRE(a.size() == 0);
}

TEST_CASE("FlatPcSet: move assignment transfers ownership",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet a(64);
    a.insert(0x5000);

    FlatPcSet b(64);
    b.insert(0x6000);
    b.insert(0x6004);

    b = std::move(a);
    REQUIRE(b.size() == 1);
    REQUIRE(b.contains(0x5000));
    REQUIRE_FALSE(b.contains(0x6000));  // old contents gone
}

// ═══════════════════════════════════════════════════════════════════════════════
// FlatWriteRegCache
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("FlatWriteRegCache: default-constructed is empty",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c;
    REQUIRE(c.size() == 0);
    REQUIRE(c.capacity() >= 16);
}

TEST_CASE("FlatWriteRegCache: find returns nullptr for missing key",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);
    REQUIRE(c.find(0x1000) == nullptr);
    REQUIRE(c.find(0x2000) == nullptr);
}

TEST_CASE("FlatWriteRegCache: insert + find retrieves correct value",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    WriteRegList wl;
    wl.count = 2;
    wl.idx[0] = 3;   // x3
    wl.idx[1] = 19;  // x19

    c.insert(0x1000, wl);
    REQUIRE(c.size() == 1);

    const WriteRegList *found = c.find(0x1000);
    REQUIRE(found != nullptr);
    REQUIRE(found->count == 2);
    REQUIRE(found->idx[0] == 3);
    REQUIRE(found->idx[1] == 19);
}

TEST_CASE("FlatWriteRegCache: multiple entries are independent",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    // mov x0, x1 → writes x0
    WriteRegList wl1;
    wl1.count = 1;
    wl1.idx[0] = 0;

    // ldp x3, x4, [x5] → writes x3, x4
    WriteRegList wl2;
    wl2.count = 2;
    wl2.idx[0] = 3;
    wl2.idx[1] = 4;

    // fadd v0, v1, v2 → writes v0 (FPR only)
    WriteRegList wl3;
    wl3.count = 0;
    wl3.fpr_count = 1;
    wl3.fpr_idx[0] = 0;

    c.insert(0x1000, wl1);
    c.insert(0x1004, wl2);
    c.insert(0x1008, wl3);

    REQUIRE(c.size() == 3);

    auto *r1 = c.find(0x1000);
    auto *r2 = c.find(0x1004);
    auto *r3 = c.find(0x1008);

    REQUIRE(r1 != nullptr);
    REQUIRE(r1->count == 1);
    REQUIRE(r1->idx[0] == 0);

    REQUIRE(r2 != nullptr);
    REQUIRE(r2->count == 2);
    REQUIRE(r2->idx[0] == 3);
    REQUIRE(r2->idx[1] == 4);

    REQUIRE(r3 != nullptr);
    REQUIRE(r3->count == 0);
    REQUIRE(r3->fpr_count == 1);
    REQUIRE(r3->fpr_idx[0] == 0);
}

TEST_CASE("FlatWriteRegCache: auto-resizes and preserves values",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(16);  // initial cap = 16, load threshold ~ 12
    size_t initial_cap = c.capacity();

    // Insert enough to trigger resize
    for (uint64_t i = 1; i <= 100; ++i) {
        WriteRegList wl;
        wl.count = 1;
        wl.idx[0] = (uint8_t)(i % 31);
        c.insert(i * 4, wl);
    }
    REQUIRE(c.size() == 100);
    REQUIRE(c.capacity() > initial_cap);

    // Verify all values survived the resize
    for (uint64_t i = 1; i <= 100; ++i) {
        auto *found = c.find(i * 4);
        REQUIRE(found != nullptr);
        REQUIRE(found->count == 1);
        REQUIRE(found->idx[0] == (uint8_t)(i % 31));
    }
}

TEST_CASE("FlatWriteRegCache: large-scale with typical trace PC distribution",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    constexpr size_t N = 5000;
    constexpr uint64_t base = 0x100008000ULL;  // typical Mach-O text base

    for (size_t i = 0; i < N; ++i) {
        WriteRegList wl;
        wl.count = (uint8_t)((i % 3) + 1);  // 1-3 GPRs
        for (uint8_t k = 0; k < wl.count; ++k) {
            wl.idx[k] = (uint8_t)((i + k) % 31);
        }
        wl.fpr_count = (uint8_t)(i % 2);  // 0 or 1 FPR
        if (wl.fpr_count > 0) wl.fpr_idx[0] = (uint8_t)(i % 32);

        c.insert(base + i * 4, wl);
    }
    REQUIRE(c.size() == N);

    // Spot-check first, middle, last entries
    auto *first = c.find(base);
    REQUIRE(first != nullptr);
    REQUIRE(first->count == 1);  // (0 % 3) + 1 = 1

    auto *mid = c.find(base + (N / 2) * 4);
    REQUIRE(mid != nullptr);
    REQUIRE(mid->count >= 1);

    auto *last = c.find(base + (N - 1) * 4);
    REQUIRE(last != nullptr);

    // Non-existent key
    REQUIRE(c.find(base + N * 4) == nullptr);
}

TEST_CASE("FlatWriteRegCache: insert with same key overwrites value",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    WriteRegList wl1;
    wl1.count = 1;
    wl1.idx[0] = 5;

    WriteRegList wl2;
    wl2.count = 2;
    wl2.idx[0] = 10;
    wl2.idx[1] = 20;

    c.insert(0x2000, wl1);
    REQUIRE(c.size() == 1);

    c.insert(0x2000, wl2);
    // Re-inserting same key must overwrite value WITHOUT incrementing size_
    REQUIRE(c.size() == 1);

    auto *found = c.find(0x2000);
    REQUIRE(found != nullptr);
    REQUIRE(found->count == 2);
    REQUIRE(found->idx[0] == 10);
    REQUIRE(found->idx[1] == 20);
}

TEST_CASE("FlatWriteRegCache: repeated overwrites do not inflate size",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    // Insert 3 distinct keys
    for (uint64_t pc = 0x1000; pc <= 0x1008; pc += 4) {
        WriteRegList wl;
        wl.count = 1;
        wl.idx[0] = (uint8_t)(pc & 0xFF);
        c.insert(pc, wl);
    }
    REQUIRE(c.size() == 3);

    // Overwrite each key 50 times — size must stay at 3
    for (int round = 0; round < 50; ++round) {
        for (uint64_t pc = 0x1000; pc <= 0x1008; pc += 4) {
            WriteRegList wl;
            wl.count = 2;
            wl.idx[0] = (uint8_t)(round & 0xFF);
            wl.idx[1] = (uint8_t)((round + 1) & 0xFF);
            c.insert(pc, wl);
        }
    }
    REQUIRE(c.size() == 3);

    // Values reflect the last overwrite (round 49)
    for (uint64_t pc = 0x1000; pc <= 0x1008; pc += 4) {
        auto *found = c.find(pc);
        REQUIRE(found != nullptr);
        REQUIRE(found->count == 2);
        REQUIRE(found->idx[0] == (uint8_t)(49 & 0xFF));
        REQUIRE(found->idx[1] == (uint8_t)(50 & 0xFF));
    }
}

TEST_CASE("FlatWriteRegCache: FPR fields preserved through insert/find",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    WriteRegList wl;
    wl.count = 0;
    wl.fpr_count = 4;
    wl.fpr_idx[0] = 0;
    wl.fpr_idx[1] = 8;
    wl.fpr_idx[2] = 16;
    wl.fpr_idx[3] = 31;

    c.insert(0x3000, wl);

    auto *found = c.find(0x3000);
    REQUIRE(found != nullptr);
    REQUIRE(found->count == 0);
    REQUIRE(found->fpr_count == 4);
    REQUIRE(found->fpr_idx[0] == 0);
    REQUIRE(found->fpr_idx[1] == 8);
    REQUIRE(found->fpr_idx[2] == 16);
    REQUIRE(found->fpr_idx[3] == 31);
}

TEST_CASE("FlatWriteRegCache: move constructor transfers ownership",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache a(64);

    WriteRegList wl;
    wl.count = 1;
    wl.idx[0] = 7;
    a.insert(0x4000, wl);

    FlatWriteRegCache b(std::move(a));
    REQUIRE(b.size() == 1);
    REQUIRE(b.find(0x4000) != nullptr);
    REQUIRE(b.find(0x4000)->idx[0] == 7);

    // Source should be empty
    REQUIRE(a.size() == 0);
    REQUIRE(a.find(0x4000) == nullptr);
}

TEST_CASE("FlatWriteRegCache: move assignment transfers ownership",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache a(64);
    WriteRegList wl;
    wl.count = 1;
    wl.idx[0] = 12;
    a.insert(0x5000, wl);

    FlatWriteRegCache b(64);
    WriteRegList wl2;
    wl2.count = 1;
    wl2.idx[0] = 25;
    b.insert(0x6000, wl2);

    b = std::move(a);
    REQUIRE(b.size() == 1);
    REQUIRE(b.find(0x5000) != nullptr);
    REQUIRE(b.find(0x5000)->idx[0] == 12);
    REQUIRE(b.find(0x6000) == nullptr);  // old contents gone
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hash collision / probe chain correctness
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("FlatPcSet: keys that hash to same bucket resolve correctly",
          "[unit][qbditrace][flat_containers]") {
    // With a very small table (16 slots), many keys will collide.
    // This stress-tests the linear probing.
    FlatPcSet s(16);

    std::vector<uint64_t> keys;
    // Insert 10 distinct PCs (with cap=16, max ~12 before resize)
    for (uint64_t i = 1; i <= 10; ++i) {
        keys.push_back(i * 4);
        REQUIRE(s.insert(i * 4));
    }

    // All must be found
    for (auto k : keys) {
        REQUIRE(s.contains(k));
    }

    // Duplicates must be rejected
    for (auto k : keys) {
        REQUIRE_FALSE(s.insert(k));
    }
    REQUIRE(s.size() == 10);
}

TEST_CASE("FlatWriteRegCache: keys that hash to same bucket resolve correctly",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(16);

    std::vector<uint64_t> keys;
    for (uint64_t i = 1; i <= 10; ++i) {
        keys.push_back(i * 4);
        WriteRegList wl;
        wl.count = 1;
        wl.idx[0] = (uint8_t)i;
        c.insert(i * 4, wl);
    }

    for (uint64_t i = 1; i <= 10; ++i) {
        auto *found = c.find(i * 4);
        REQUIRE(found != nullptr);
        REQUIRE(found->idx[0] == (uint8_t)i);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("FlatPcSet: high-address PCs (kernel/ASLR range)",
          "[unit][qbditrace][flat_containers]") {
    FlatPcSet s(64);

    // Simulate high kernel addresses
    uint64_t high_base = 0xFFFFFFC000000000ULL;
    for (uint64_t i = 0; i < 50; ++i) {
        REQUIRE(s.insert(high_base + i * 4));
    }
    REQUIRE(s.size() == 50);

    for (uint64_t i = 0; i < 50; ++i) {
        REQUIRE(s.contains(high_base + i * 4));
    }
}

TEST_CASE("FlatWriteRegCache: max GPR+FPR indices",
          "[unit][qbditrace][flat_containers]") {
    FlatWriteRegCache c(64);

    WriteRegList wl;
    // Fill all 8 GPR slots with max indices
    wl.count = 8;
    for (int i = 0; i < 8; ++i) wl.idx[i] = (uint8_t)(23 + i);  // x23..x30
    // Fill all 8 FPR slots
    wl.fpr_count = 8;
    for (int i = 0; i < 8; ++i) wl.fpr_idx[i] = (uint8_t)(24 + i);  // v24..v31

    c.insert(0x8000, wl);

    auto *found = c.find(0x8000);
    REQUIRE(found != nullptr);
    REQUIRE(found->count == 8);
    REQUIRE(found->fpr_count == 8);
    for (int i = 0; i < 8; ++i) {
        REQUIRE(found->idx[i] == (uint8_t)(23 + i));
        REQUIRE(found->fpr_idx[i] == (uint8_t)(24 + i));
    }
}

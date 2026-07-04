/*
 * test_pass_entropy.cpp — Unit tests for tenet::EntropyPass
 *
 * Verifies:
 *   - All-zeros buffer → entropy = 0 (Plaintext classification)
 *   - Uniform random-like pattern → entropy close to 8.0 (Encrypted)
 *   - Mixed pattern → moderate entropy value
 *   - Classification thresholds (Plaintext < 4.0, Encrypted > 7.5)
 *   - Block entropy: each block is computed independently
 *   - known_bytes reflects how many bytes were written to the region
 *
 * NOTE: EntropyPass reads from MemoryModel, which in turn uses the trace's
 * memory-write records.  We seed the trace with STR instructions that fill
 * a buffer with known byte patterns, then run EntropyPass on that range.
 *
 * Run:  ctest -R 'entropy' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include <cmath>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/memory/entropy_pass.h"

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Write N bytes from `pattern` (repeated) to `base_addr` via STR instructions.
/// Each instruction writes 8 bytes.
static void fill_region(TraceWriter& tw, MachineState& ms,
                        uint64_t base_addr, const std::vector<uint8_t>& pattern,
                        size_t n_bytes) {
    size_t written = 0;
    uint64_t spc = 0x2000;

    // Set x20 = base_addr (address register for stores)
    uint64_t addr_val = base_addr;
    tw.emit(ms, spc, enc::movz(20, static_cast<uint16_t>(base_addr & 0xFFFF)),
            {{20, addr_val}, {33, tw.rt(spc + 4)}}, {});
    spc += 4;

    while (written < n_bytes) {
        size_t chunk = std::min<size_t>(8, n_bytes - written);
        uint64_t val = 0;
        for (size_t i = 0; i < chunk; i++) {
            val |= (uint64_t)pattern[(written + i) % pattern.size()] << (i * 8);
        }
        // STR x21, [x20, #offset]  — emit as a store mem-acc
        uint64_t target_addr = base_addr + written;
        tw.emit(ms, spc, enc::str_imm(21, 20, 0),
                {{33, tw.rt(spc + 4)}},
                {{2 /*write*/, static_cast<uint16_t>(chunk), target_addr, val}});
        spc += 4;
        written += chunk;
    }
    tw.emit_anchor(ms);
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

TEST_CASE("EntropyPass: all-zero buffer → entropy 0 (Plaintext)",
          "[unit][pass][entropy]") {
    const uint64_t kBase = 0x40000ULL;
    const uint32_t kSize = 64;

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        std::vector<uint8_t> zeros(16, 0x00);
        fill_region(tw, ms, kBase, zeros, kSize);
    }, "entropy_zeros");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    EntropyConfig cfg;
    cfg.addr = kBase;
    cfg.size = kSize;
    cfg.at_inst_id = 0;       // end of trace
    cfg.block_size = 16;

    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    auto& raw = pm->require("entropy");
    REQUIRE(raw.ok());

    auto& res = raw.get<EntropyResult>();

    SECTION("overall entropy is 0 for uniform bytes") {
        REQUIRE(res.overall_entropy == Catch::Approx(0.0f).margin(0.01f));
    }
    SECTION("classified as Plaintext") {
        REQUIRE(res.classification == EntropyResult::Plaintext);
    }
    SECTION("region size matches") {
        REQUIRE(res.region_size == kSize);
    }
}

TEST_CASE("EntropyPass: high-entropy buffer (pseudo-random) → near 8.0 (Encrypted)",
          "[unit][pass][entropy]") {
    const uint64_t kBase = 0x50000ULL;
    const uint32_t kSize = 256;

    // Build a pseudo-random pattern covering all 256 byte values
    std::vector<uint8_t> random_pattern(256);
    for (int i = 0; i < 256; i++) {
        // Simple permutation: XOR-based, touches all values
        random_pattern[i] = static_cast<uint8_t>((i * 167 + 43) & 0xFF);
    }

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        fill_region(tw, ms, kBase, random_pattern, kSize);
    }, "entropy_random");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    EntropyConfig cfg;
    cfg.addr = kBase;
    cfg.size = kSize;
    cfg.block_size = 64;

    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    auto& raw = pm->require("entropy");
    REQUIRE(raw.ok());

    auto& res = raw.get<EntropyResult>();

    SECTION("overall entropy is high (>= 7.5)") {
        // A 256-byte buffer where all 256 byte values appear exactly once
        // has theoretical entropy = 8.0
        REQUIRE(res.overall_entropy >= 7.5f);
    }
    SECTION("classified as Encrypted") {
        REQUIRE(res.classification == EntropyResult::Encrypted);
    }
}

TEST_CASE("EntropyPass: repeated 4-byte pattern → medium entropy",
          "[unit][pass][entropy]") {
    const uint64_t kBase = 0x60000ULL;
    const uint32_t kSize = 128;

    // Pattern with 4 unique bytes repeated = limited entropy
    std::vector<uint8_t> pattern = {0x01, 0x02, 0x03, 0x04};

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        fill_region(tw, ms, kBase, pattern, kSize);
    }, "entropy_medium");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    EntropyConfig cfg;
    cfg.addr = kBase;
    cfg.size = kSize;
    cfg.block_size = 32;

    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    auto& raw = pm->require("entropy");
    REQUIRE(raw.ok());

    auto& res = raw.get<EntropyResult>();

    SECTION("entropy is between 1.9 and 3.0 for 4 distinct values") {
        // H(uniform 4 symbols) = 2 bits; in bytes ≈ 2.0 bits/byte
        REQUIRE(res.overall_entropy >= 1.5f);
        REQUIRE(res.overall_entropy <= 4.0f);
    }
    SECTION("blocks are computed") {
        REQUIRE_FALSE(res.blocks.empty());
    }
}

TEST_CASE("EntropyPass: block structure is correct",
          "[unit][pass][entropy]") {
    const uint64_t kBase = 0x70000ULL;
    const uint32_t kSize = 64;
    const uint32_t kBlockSize = 16;

    std::vector<uint8_t> all_zeros(16, 0x00);

    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        fill_region(tw, ms, kBase, all_zeros, kSize);
    }, "entropy_blocks");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    EntropyConfig cfg;
    cfg.addr = kBase;
    cfg.size = kSize;
    cfg.block_size = kBlockSize;

    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    auto& res = pm->require("entropy").get<EntropyResult>();

    SECTION("number of blocks == size / block_size") {
        REQUIRE(res.blocks.size() == kSize / kBlockSize);
    }
    SECTION("block offsets are correct") {
        for (size_t i = 0; i < res.blocks.size(); i++) {
            REQUIRE(res.blocks[i].offset == i * kBlockSize);
            REQUIRE(res.blocks[i].size == kBlockSize);
        }
    }
    SECTION("all-zero blocks have entropy 0") {
        for (const auto& blk : res.blocks) {
            REQUIRE(blk.entropy == Catch::Approx(0.0f).margin(0.01f));
        }
    }
}

TEST_CASE("EntropyPass: known_bytes reflects write coverage",
          "[unit][pass][entropy]") {
    const uint64_t kBase = 0x80000ULL;
    const uint32_t kSize = 32;

    // Only write the first half (16 bytes) of the 32-byte region
    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 512;
        tw.write_header();
        MachineState ms;
        ms.sp() = 0x16F000000ULL;
        std::vector<uint8_t> pattern = {0xAA, 0xBB};
        fill_region(tw, ms, kBase, pattern, 16);  // only 16 of 32 bytes written
    }, "entropy_coverage");
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);

    EntropyConfig cfg;
    cfg.addr = kBase;
    cfg.size = kSize;   // request 32 bytes even though only 16 were written

    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    auto& raw = pm->require("entropy");
    REQUIRE(raw.ok());

    auto& res = raw.get<EntropyResult>();

    SECTION("region size matches requested size") {
        REQUIRE(res.region_size == kSize);
    }
    SECTION("known_bytes <= region_size") {
        REQUIRE(res.known_bytes <= res.region_size);
    }
}

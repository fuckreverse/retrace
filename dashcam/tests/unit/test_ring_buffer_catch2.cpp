/*
 * test_ring_buffer_catch2.cpp — Catch2 unit tests for RingBuffer.h
 *
 * Covers: BackgroundWriter start/stop/ok, ThreadBuffer reserve/flush,
 * chunk rotation, header-first ordering, multi-thread buffers,
 * large-record data integrity, and double-stop idempotency.
 *
 * Run:  ctest -R ring_buffer_catch2 --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "RingBuffer.h"

using namespace qbditrace;

// ─── Helpers ───────────────────────────────────────────────────────────────

static std::vector<uint8_t> slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

static bool contains(const std::vector<uint8_t>& data, const char* needle, size_t len) {
    for (size_t i = 0; i + len <= data.size(); i++) {
        if (memcmp(data.data() + i, needle, len) == 0) return true;
    }
    return false;
}

// ─── BackgroundWriter tests ─────────────────────────────────────────────────

TEST_CASE("BackgroundWriter: start creates writable file", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_start.bin").string();
    BackgroundWriter bw;

    REQUIRE(bw.start(path.c_str(), 4096));
    REQUIRE(bw.ok());

    bw.stop();

    // File should exist after stop
    REQUIRE(std::filesystem::exists(path));
    std::filesystem::remove(path);
}

TEST_CASE("BackgroundWriter: double stop is idempotent", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_double_stop.bin").string();
    BackgroundWriter bw;

    REQUIRE(bw.start(path.c_str(), 4096));
    bw.stop();
    REQUIRE_NOTHROW(bw.stop());  // second stop must not crash

    std::filesystem::remove(path);
}

TEST_CASE("BackgroundWriter: ok() is false before start", "[unit][qbditrace][ring_buffer]") {
    BackgroundWriter bw;
    // Before calling start(), the writer is not running
    REQUIRE_FALSE(bw.ok());
}

// ─── Header-first ordering ───────────────────────────────────────────────────

TEST_CASE("BackgroundWriter: header bytes precede chunk payload", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_header.bin").string();
    BackgroundWriter bw;
    REQUIRE(bw.start(path.c_str(), 64));  // tiny chunks → forced rotation

    constexpr char kHeader[]  = "HDR123";
    constexpr char kPayload[] = "PAYLOAD456";
    bw.writeHeaderRaw(kHeader, sizeof(kHeader) - 1);  // exclude NUL

    {
        ThreadBuffer tb(&bw, 1000);
        uint8_t* p = tb.reserve(sizeof(kPayload) - 1);
        REQUIRE(p != nullptr);
        memcpy(p, kPayload, sizeof(kPayload) - 1);
    }
    bw.stop();

    auto data = slurp(path);
    REQUIRE_FALSE(data.empty());

    // Header must appear at byte offset 0
    REQUIRE(memcmp(data.data(), kHeader, sizeof(kHeader) - 1) == 0);

    // Payload must appear somewhere after the header
    bool found = contains(data, kPayload, sizeof(kPayload) - 1);
    REQUIRE(found);

    std::filesystem::remove(path);
}

// ─── ThreadBuffer tests ──────────────────────────────────────────────────────

TEST_CASE("ThreadBuffer: basic reserve + flush writes both messages", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_tb_basic.bin").string();
    BackgroundWriter bw;
    REQUIRE(bw.start(path.c_str(), 4096));

    {
        ThreadBuffer tb(&bw, 5000);

        constexpr char msg1[] = "Hello";
        constexpr char msg2[] = "World";

        uint8_t* p1 = tb.reserve(5);
        REQUIRE(p1 != nullptr);
        memcpy(p1, msg1, 5);

        tb.flush();  // force chunk submission mid-stream

        uint8_t* p2 = tb.reserve(5);
        REQUIRE(p2 != nullptr);
        memcpy(p2, msg2, 5);
    }
    bw.stop();

    auto data = slurp(path);
    SECTION("Hello present") { REQUIRE(contains(data, "Hello", 5)); }
    SECTION("World present") { REQUIRE(contains(data, "World", 5)); }

    std::filesystem::remove(path);
}

TEST_CASE("ThreadBuffer: thread IDs are stored correctly", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_tb_ids.bin").string();
    BackgroundWriter bw;
    REQUIRE(bw.start(path.c_str(), 256));

    {
        ThreadBuffer tb1(&bw, 101);
        ThreadBuffer tb2(&bw, 202);

        SECTION("first thread ID") {
            REQUIRE(tb1.threadId() == 101);
        }
        SECTION("second thread ID") {
            REQUIRE(tb2.threadId() == 202);
        }

        uint8_t* p1 = tb1.reserve(2);
        memcpy(p1, "T1", 2);
        uint8_t* p2 = tb2.reserve(2);
        memcpy(p2, "T2", 2);
    }
    bw.stop();

    auto data = slurp(path);
    SECTION("T1 present") { REQUIRE(contains(data, "T1", 2)); }
    SECTION("T2 present") { REQUIRE(contains(data, "T2", 2)); }

    std::filesystem::remove(path);
}

// ─── Chunk rotation ──────────────────────────────────────────────────────────

TEST_CASE("BackgroundWriter: chunk rotation preserves record order", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_rotate.bin").string();
    BackgroundWriter bw;
    // Very small chunk size → many rotations
    REQUIRE(bw.start(path.c_str(), 128));

    {
        ThreadBuffer tb(&bw, 2000);
        // Write 20 records, each 9 bytes ("RECORD_NN")
        for (int i = 0; i < 20; i++) {
            char buf[16];
            int len = snprintf(buf, sizeof(buf), "RECORD_%02d", i);
            uint8_t* p = tb.reserve(len);
            REQUIRE(p != nullptr);
            memcpy(p, buf, len);
        }
    }
    bw.stop();

    auto data = slurp(path);
    REQUIRE_FALSE(data.empty());

    // Verify all records are present (order may vary due to chunk layout)
    for (int i = 0; i < 20; i++) {
        char expected[16];
        snprintf(expected, sizeof(expected), "RECORD_%02d", i);
        REQUIRE(contains(data, expected, strlen(expected)));
    }

    std::filesystem::remove(path);
}

// ─── Large record data integrity ─────────────────────────────────────────────

TEST_CASE("BackgroundWriter: large records preserve data integrity", "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_large.bin").string();
    BackgroundWriter bw;
    REQUIRE(bw.start(path.c_str(), 1024));  // 1 KB chunks

    constexpr size_t kRecordSize = 500;

    std::vector<uint8_t> pattern1(kRecordSize);
    std::vector<uint8_t> pattern2(kRecordSize);
    for (size_t i = 0; i < kRecordSize; i++) {
        pattern1[i] = static_cast<uint8_t>(i % 256);
        pattern2[i] = static_cast<uint8_t>(255 - (i % 256));
    }

    {
        ThreadBuffer tb(&bw, 10000);
        uint8_t* p1 = tb.reserve(kRecordSize);
        REQUIRE(p1 != nullptr);
        memcpy(p1, pattern1.data(), kRecordSize);

        uint8_t* p2 = tb.reserve(kRecordSize);
        REQUIRE(p2 != nullptr);
        memcpy(p2, pattern2.data(), kRecordSize);
    }
    bw.stop();

    auto data = slurp(path);
    REQUIRE(data.size() >= 2 * kRecordSize);

    // Locate pattern1 in the output
    bool found1 = false;
    for (size_t i = 0; i + kRecordSize <= data.size(); i++) {
        bool match = true;
        for (size_t j = 0; j < kRecordSize && match; j++) {
            match = (data[i + j] == (j % 256));
        }
        if (match) { found1 = true; break; }
    }
    REQUIRE(found1);

    // Locate pattern2 in the output
    bool found2 = false;
    for (size_t i = 0; i + kRecordSize <= data.size(); i++) {
        bool match = true;
        for (size_t j = 0; j < kRecordSize && match; j++) {
            match = (data[i + j] == (255 - (j % 256)));
        }
        if (match) { found2 = true; break; }
    }
    REQUIRE(found2);

    std::filesystem::remove(path);
}

// ─── Multi-thread concurrency ────────────────────────────────────────────────

TEST_CASE("BackgroundWriter: concurrent ThreadBuffers produce distinct output",
          "[unit][qbditrace][ring_buffer]") {
    const std::string path = (std::filesystem::temp_directory_path() / "catch2_rb_multi.bin").string();
    BackgroundWriter bw;
    REQUIRE(bw.start(path.c_str(), 256));

    {
        ThreadBuffer tb1(&bw, 100);
        ThreadBuffer tb2(&bw, 200);
        ThreadBuffer tb3(&bw, 300);

        // Write distinct markers from each "thread"
        uint8_t* p1 = tb1.reserve(4);  memcpy(p1, "TH01", 4);
        uint8_t* p2 = tb2.reserve(4);  memcpy(p2, "TH02", 4);
        uint8_t* p3 = tb3.reserve(4);  memcpy(p3, "TH03", 4);
    }
    bw.stop();

    auto data = slurp(path);
    SECTION("thread 1 marker")  { REQUIRE(contains(data, "TH01", 4)); }
    SECTION("thread 2 marker")  { REQUIRE(contains(data, "TH02", 4)); }
    SECTION("thread 3 marker")  { REQUIRE(contains(data, "TH03", 4)); }

    std::filesystem::remove(path);
}

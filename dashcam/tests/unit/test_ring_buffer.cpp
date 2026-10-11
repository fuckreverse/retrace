/*
 * test_ring_buffer.c — Unit tests for RingBuffer.h (BackgroundWriter + ThreadBuffer)
 *
 * Verifies: BackgroundWriter start/stop, ThreadBuffer reserve/submit
 * round-trip data integrity, chunk rotation, and header-first ordering.
 *
 * Build:
 *   clang++ -std=c++17 -Wall -Wextra -I.. -o test_ring_buffer test_ring_buffer.c
 * Run:
 *   ./test_ring_buffer
 */
#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "RingBuffer.h"

using namespace qbditrace;

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  [RUN] %s ... ", #name); \
    name(); \
    printf("OK\n"); \
    tests_passed++; \
} while(0)

// ─── Helper: read entire file into a byte vector ───────────────────────────
static std::vector<uint8_t> read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(sz);
    if (sz > 0) fread(data.data(), 1, sz, f);
    fclose(f);
    return data;
}

// ─── Tests ─────────────────────────────────────────────────────────────────

static void test_background_writer_start_stop(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_start_stop.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;

    assert(bw.start(path, 4096));
    assert(bw.ok());

    // Stop should be idempotent
    bw.stop();
    bw.stop();  // double stop should not crash

    // File should exist (possibly empty)
    FILE* f = fopen(path, "rb");
    assert(f != nullptr);
    fclose(f);
    remove(path);
}

static void test_header_first_then_chunks(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_header.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;
    assert(bw.start(path, 64));  // small chunk to force rotation

    // Write header first
    const char header[] = "HEADER";
    bw.writeHeaderRaw(header, sizeof(header));

    // Then write chunk data via ThreadBuffer
    {
        ThreadBuffer tb(&bw, 1000);
        const char payload[] = "PAYLOAD_DATA";
        uint8_t* p = tb.reserve(sizeof(payload));
        assert(p != nullptr);
        memcpy(p, payload, sizeof(payload));
        // tb destructor flushes
    }

    bw.stop();

    // Read back and verify header comes first
    auto data = read_file(path);
    assert(data.size() >= sizeof("HEADER") + sizeof("PAYLOAD_DATA") - 1);
    assert(memcmp(data.data(), "HEADER", 6) == 0);

    // Find PAYLOAD_DATA somewhere after the header
    bool found = false;
    for (size_t i = 6; i + 12 <= data.size(); i++) {
        if (memcmp(data.data() + i, "PAYLOAD_DATA", 12) == 0) {
            found = true;
            break;
        }
    }
    assert(found);
    remove(path);
}

static void test_chunk_rotation(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_rotate.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;
    // Very small chunks (128 bytes) to force frequent rotation
    assert(bw.start(path, 128));

    {
        ThreadBuffer tb(&bw, 2000);

        // Write enough data to fill multiple chunks
        for (int i = 0; i < 20; i++) {
            char buf[32];
            int len = snprintf(buf, sizeof(buf), "RECORD_%02d", i);
            uint8_t* p = tb.reserve(len);
            assert(p != nullptr);
            memcpy(p, buf, len);
        }
        // tb destructor flushes remaining data
    }

    bw.stop();

    // Verify all records appear in order in the output
    auto data = read_file(path);
    assert(!data.empty());

    size_t pos = 0;
    for (int i = 0; i < 20; i++) {
        char expected[32];
        int len = snprintf(expected, sizeof(expected), "RECORD_%02d", i);
        bool found = false;
        for (size_t j = pos; j + len <= data.size(); j++) {
            if (memcmp(data.data() + j, expected, len) == 0) {
                pos = j + len;
                found = true;
                break;
            }
        }
        assert(found);
    }
    remove(path);
}

static void test_thread_buffer_reserve_and_flush(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_flush.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;
    assert(bw.start(path, 4096));

    {
        ThreadBuffer tb(&bw, 5000);

        // Write some data
        const char msg1[] = "Hello";
        const char msg2[] = "World";
        uint8_t* p1 = tb.reserve(5);
        memcpy(p1, msg1, 5);

        // Flush forces the current chunk to be submitted
        tb.flush();

        // Write more data after flush (goes into a new chunk)
        uint8_t* p2 = tb.reserve(5);
        memcpy(p2, msg2, 5);
    }

    bw.stop();

    auto data = read_file(path);
    assert(!data.empty());

    // Both messages should be present
    bool found_hello = false, found_world = false;
    for (size_t i = 0; i + 5 <= data.size(); i++) {
        if (memcmp(data.data() + i, "Hello", 5) == 0) found_hello = true;
        if (memcmp(data.data() + i, "World", 5) == 0) found_world = true;
    }
    assert(found_hello);
    assert(found_world);
    remove(path);
}

static void test_data_integrity_large_records(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_large.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;
    assert(bw.start(path, 1024));  // 1KB chunks

    {
        ThreadBuffer tb(&bw, 10000);

        // Write a 500-byte record (spans most of a chunk)
        std::vector<uint8_t> big_record(500);
        for (size_t i = 0; i < big_record.size(); i++) {
            big_record[i] = static_cast<uint8_t>(i % 256);
        }
        uint8_t* p = tb.reserve(big_record.size());
        assert(p != nullptr);
        memcpy(p, big_record.data(), big_record.size());

        // Write a second 500-byte record (forces rotation)
        std::vector<uint8_t> big_record2(500);
        for (size_t i = 0; i < big_record2.size(); i++) {
            big_record2[i] = static_cast<uint8_t>(255 - (i % 256));
        }
        p = tb.reserve(big_record2.size());
        assert(p != nullptr);
        memcpy(p, big_record2.data(), big_record2.size());
    }

    bw.stop();

    auto data = read_file(path);
    assert(data.size() >= 1000);  // two 500-byte records

    // Find and verify the first record
    bool found1 = false;
    for (size_t i = 0; i + 500 <= data.size(); i++) {
        bool match = true;
        for (size_t j = 0; j < 500; j++) {
            if (data[i + j] != j % 256) { match = false; break; }
        }
        if (match) { found1 = true; break; }
    }
    assert(found1);

    // Find and verify the second record
    bool found2 = false;
    for (size_t i = 0; i + 500 <= data.size(); i++) {
        bool match = true;
        for (size_t j = 0; j < 500; j++) {
            if (data[i + j] != 255 - (j % 256)) { match = false; break; }
        }
        if (match) { found2 = true; break; }
    }
    assert(found2);

    remove(path);
}

static void test_multiple_thread_buffers(void) {
    const std::string path_str = (std::filesystem::temp_directory_path() / "test_rb_multi.bin").string();
    const char* path = path_str.c_str();
    BackgroundWriter bw;
    assert(bw.start(path, 256));

    // Two thread buffers with different thread IDs
    {
        ThreadBuffer tb1(&bw, 100);
        ThreadBuffer tb2(&bw, 200);

        const char msg1[] = "T1";
        const char msg2[] = "T2";

        uint8_t* p1 = tb1.reserve(2);
        memcpy(p1, msg1, 2);

        uint8_t* p2 = tb2.reserve(2);
        memcpy(p2, msg2, 2);

        assert(tb1.threadId() == 100);
        assert(tb2.threadId() == 200);
    }

    bw.stop();

    auto data = read_file(path);
    assert(!data.empty());

    // Both messages should be present
    bool found_t1 = false, found_t2 = false;
    for (size_t i = 0; i + 2 <= data.size(); i++) {
        if (memcmp(data.data() + i, "T1", 2) == 0) found_t1 = true;
        if (memcmp(data.data() + i, "T2", 2) == 0) found_t2 = true;
    }
    assert(found_t1);
    assert(found_t2);

    remove(path);
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf(" test_ring_buffer — BackgroundWriter + ThreadBuffer tests\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("  Tests:\n");
    RUN_TEST(test_background_writer_start_stop);
    RUN_TEST(test_header_first_then_chunks);
    RUN_TEST(test_chunk_rotation);
    RUN_TEST(test_thread_buffer_reserve_and_flush);
    RUN_TEST(test_data_integrity_large_records);
    RUN_TEST(test_multiple_thread_buffers);

    printf("\n  ─────────────────────────────────────────\n");
    printf("  Results: %d/%d passed\n", tests_passed, tests_run);
    printf("═══════════════════════════════════════════════════════════════\n");

    return (tests_run == tests_passed) ? 0 : 1;
}

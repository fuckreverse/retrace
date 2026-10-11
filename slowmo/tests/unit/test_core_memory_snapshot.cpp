/*
 * test_core_memory_snapshot.cpp — Unit tests for v9 REC_MEMIMG snapshots.
 */
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

#include "core/memory_model.h"
#include "fixtures/trace_fixture.h"

using namespace tenet;
using namespace tenet::test;

namespace {

constexpr uint8_t kWrite = 2;
constexpr uint64_t kBase = 0x300000000ULL;

std::unique_ptr<TraceEnv> make_snapshot_env(
        std::function<void(TraceWriter&)> emit_records,
        const char* name) {
    auto env = make_env([&](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header_v9();
        emit_records(tw);
    }, name);
    if (env) env->memory->build();
    return env;
}

void check_snapshot_fallback(MemoryModel& memory, uint64_t base) {
    // Arrange
    const uint64_t missing = base + 0x100;

    // Act
    const auto got = memory.read(base, 4, 1);
    const auto got_at_zero = memory.read(base, 4, 0);
    const auto missing_at_zero = memory.read(missing, 1, 0);
    const auto missing_after_start = memory.read(missing, 16, 1);
    const auto missing_region = memory.read_region(missing, 16, 1);

    // Assert
    const std::vector<uint8_t> want{0x10, 0x20, 0x30, 0x40};
    for (size_t i = 0; i < want.size(); ++i) {
        CHECK(got.known[i]);
        CHECK(got.data[i] == want[i]);
        CHECK(got.writer_id[i] == MemoryModel::kSnapshotWriterId);
        CHECK(MemoryModel::is_snapshot_writer(got.writer_id[i]));
        CHECK(got_at_zero.known[i]);
        CHECK(got_at_zero.data[i] == want[i]);
    }
    CHECK_FALSE(missing_at_zero.known[0]);
    for (size_t i = 0; i < 16; ++i) {
        CHECK_FALSE(missing_after_start.known[i]);
        CHECK_FALSE(missing_region.known[i]);
    }
    CHECK(missing_region.known_count == 0);
    CHECK(memory.has_snapshot());
}

}  // namespace

TEST_CASE("TraceReader collects and merges v9 memory snapshot regions",
          "[unit][io][memory_snapshot][snapshot]") {
    struct TestCase {
        const char* label;
        std::function<void(TraceWriter&)> in;
        std::vector<uint64_t> want_addrs;
        std::vector<std::vector<uint8_t>> want_data;
    };

    const std::vector<TestCase> tests{
        {"single chunk",
         [](TraceWriter& tw) { tw.write_memimg(kBase, {1, 2, 3}, 7); },
         {kBase}, {{1, 2, 3}}},
        {"adjacent chunks merge after address sorting",
         [](TraceWriter& tw) {
             tw.write_memimg(kBase + 2, {3, 4}, 1);
             tw.write_memimg(kBase, {1, 2}, 0);
         },
         {kBase}, {{1, 2, 3, 4}}},
        {"a gap remains two regions",
         [](TraceWriter& tw) {
             tw.write_memimg(kBase, {1, 2}, 0);
             tw.write_memimg(kBase + 4, {5, 6}, 1);
         },
         {kBase, kBase + 4}, {{1, 2}, {5, 6}}},
        {"no MEMIMG records",
         [](TraceWriter&) {},
         {}, {}},
    };

    for (const auto& tc : tests) {
        DYNAMIC_SECTION(tc.label) {
            // Arrange
            auto env = make_snapshot_env(tc.in, "snapshot_collect");
            REQUIRE(env != nullptr);

            // Act
            const auto got = env->reader->collect_memimg_regions();

            // Assert
            REQUIRE(got.size() == tc.want_addrs.size());
            for (size_t i = 0; i < got.size(); ++i) {
                CHECK(got[i].addr == tc.want_addrs[i]);
                CHECK(got[i].data == tc.want_data[i]);
                CHECK(got[i].end() == tc.want_addrs[i] + tc.want_data[i].size());
            }
        }
    }
}

TEST_CASE("TraceReader stops collecting MEMIMG records at the first INST",
          "[unit][io][memory_snapshot][snapshot]") {
    // Arrange
    auto env = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kBase, {0xAA}, 0);
        MachineState ms;
        ms.sp() = 0x310000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.write_memimg(kBase + 1, {0xBB}, 1);
    }, "snapshot_prefix_stop");
    REQUIRE(env != nullptr);

    // Act
    const auto got = env->reader->collect_memimg_regions();

    // Assert
    REQUIRE(got.size() == 1);
    CHECK(got[0].addr == kBase);
    CHECK(got[0].data == std::vector<uint8_t>{0xAA});
}

TEST_CASE("TraceReader validates the v9 MEMIMG header contract",
          "[unit][io][memory_snapshot][snapshot]") {
    const auto temp_dir = std::filesystem::temp_directory_path() /
                          "tenet_test_snapshot_header";
    std::filesystem::remove_all(temp_dir);
    std::filesystem::create_directories(temp_dir);

    SECTION("version 9 with HF_MEMIMG is accepted") {
        // Arrange
        const auto path = temp_dir / "valid.trace";
        TraceWriter tw;
        REQUIRE(tw.open(path.c_str()));
        tw.write_header_v9();
        tw.close();

        // Act
        auto got = TraceReader::open(path);

        // Assert
        REQUIRE(got.has_value());
        CHECK(got->header().version == QBDITRACE_VERSION_V9_MEMIMG);
        CHECK(got->header().has_memimg());
    }

    SECTION("version 9 without HF_MEMIMG is rejected") {
        // Arrange
        const auto path = temp_dir / "invalid.trace";
        TraceWriter tw;
        REQUIRE(tw.open(path.c_str()));
        tw.write_header_v9(false);
        tw.close();

        // Act
        const auto got = TraceReader::open(path);

        // Assert
        CHECK_FALSE(got.has_value());
    }

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("MemoryModel falls back to snapshots in RocksDB and in-memory backends",
          "[unit][core][memory_snapshot][snapshot]") {
    // Arrange
    constexpr uint64_t kFallbackBase = kBase + 0x10000;
    auto env = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kFallbackBase, {0x10, 0x20, 0x30, 0x40});
    }, "snapshot_backend_fallback");
    REQUIRE(env != nullptr);

    SECTION("RocksDB backend") {
        check_snapshot_fallback(*env->memory, kFallbackBase);
    }

    SECTION("in-memory backend") {
        MemoryModel memory(*env->reader, *env->index);
        memory.build();
        check_snapshot_fallback(memory, kFallbackBase);
    }
}

TEST_CASE("MemoryModel write log takes precedence over snapshot bytes",
          "[unit][core][memory_snapshot][snapshot]") {
    // Arrange
    constexpr uint64_t kWriteBase = kBase + 0x20000;
    auto env = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kWriteBase, {0x11, 0x22, 0x33, 0x44});
        MachineState ms;
        ms.sp() = 0x310000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::str_imm(0, 31, 0),
                {{0, 0xAABBCCDD}, {33, tw.rt(0x1008)}},
                {{kWrite, 4, kWriteBase, 0xAABBCCDD}});
    }, "snapshot_write_precedence");
    REQUIRE(env != nullptr);

    // Act
    const auto got = env->memory->read(kWriteBase, 4, 2);

    // Assert
    const std::vector<uint8_t> want{0xDD, 0xCC, 0xBB, 0xAA};
    for (size_t i = 0; i < want.size(); ++i) {
        CHECK(got.known[i]);
        CHECK(got.data[i] == want[i]);
        // The meaningful contract is: the byte came from the write log, NOT
        // from the snapshot base layer. (The RocksDB fast path intentionally
        // leaves writer_id == 0 for log hits; exact writer inst_ids are only
        // available via last_writer().)
        CHECK_FALSE(MemoryModel::is_snapshot_writer(got.writer_id[i]));
    }
}

TEST_CASE("MemoryModel read_region preserves snapshot holes",
          "[unit][core][memory_snapshot][snapshot]") {
    // Arrange
    auto env = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kBase, {1, 2});
        tw.write_memimg(kBase + 4, {5, 6});
    }, "snapshot_region_hole");
    REQUIRE(env != nullptr);

    // Act
    const auto got = env->memory->read_region(kBase, 6, 0);

    // Assert
    const std::vector<uint8_t> want_data{1, 2, 0, 0, 5, 6};
    const std::vector<bool> want_known{true, true, false, false, true, true};
    CHECK(got.data == want_data);
    CHECK(got.known == want_known);
    CHECK(got.known_count == 4);
}

TEST_CASE("MemoryModel reports both snapshot presence states",
          "[unit][core][memory_snapshot][snapshot]") {
    // Arrange
    auto with_snapshot = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kBase, {0xAA});
    }, "snapshot_present");
    auto without_snapshot = make_snapshot_env([](TraceWriter&) {},
                                              "snapshot_absent");
    REQUIRE(with_snapshot != nullptr);
    REQUIRE(without_snapshot != nullptr);

    // Act / Assert
    CHECK(with_snapshot->memory->has_snapshot());
    CHECK_FALSE(without_snapshot->memory->has_snapshot());
}

TEST_CASE("Snapshot reads do not count as traced memory accesses",
          "[unit][core][memory_snapshot][snapshot]") {
    // Arrange
    auto env = make_snapshot_env([](TraceWriter& tw) {
        tw.write_memimg(kBase, {0xAA, 0xBB});
    }, "snapshot_not_accessed");
    REQUIRE(env != nullptr);

    // Act
    const auto read = env->memory->read(kBase, 2, 1);
    const auto pages = env->memory->active_pages();

    // Assert
    CHECK(read.known[0]);
    CHECK(read.known[1]);
    CHECK(pages.empty());
    CHECK_FALSE(env->memory->was_accessed(kBase));
}

#include "common/platform_file.h"
/*
 * test_io_trace_reader_compressed.cpp — Unit tests for compressed trace (HF_COMPRESSED)
 *
 * Verifies:
 *   - TraceReader::open() transparently decompresses a zstd-compressed trace
 *   - Header fields are preserved correctly (magic, version, flags, module_name)
 *   - HF_COMPRESSED flag is cleared in the returned header
 *   - Record iteration produces the same results as an uncompressed trace
 *   - InstView, AnchorView, CodeView parse correctly from decompressed data
 *   - Temp file is cleaned up after TraceReader::close()
 *
 * Strategy: generate a normal v4 trace with TraceWriter, then create a compressed
 * copy (header with HF_COMPRESSED + zstd-compressed body), and verify TraceReader
 * reads it identically to the uncompressed original.
 */
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "fixtures/trace_writer.h"
#include "io/trace_reader.h"
#include "common/types.h"

#if TENET_HAS_ZSTD
#include <zstd.h>
#endif

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Generate a simple v4 trace to a file and return the path.
static std::filesystem::path write_simple_trace(const std::filesystem::path& dir,
                                                 const char* name) {
    auto path = dir / (std::string(name) + ".trace");
    TraceWriter tw;
    tw.module_name = name;
    tw.anchor_interval = 256;
    REQUIRE(tw.open(path.c_str()));

    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;

    // Emit a few instructions with reg diffs and memory accesses
    tw.emit(ms, 0x1000, enc::nop(),
            {{33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::add_imm(0, 0, 42),
            {{0, 42ULL}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0),
            {{33, tw.rt(0x100C)}},
            {{2 /*write*/, 8, 0x16F000000ULL, 42ULL}});
    tw.emit(ms, 0x100C, enc::ldr_imm(1, 31, 0),
            {{1, 42ULL}, {33, tw.rt(0x1010)}},
            {{1 /*read*/, 8, 0x16F000000ULL, 42ULL}});
    tw.emit(ms, 0x1010, enc::ret(),
            {{33, tw.rt(0x1014)}}, {});
    tw.emit_anchor(ms);
    tw.close();
    return path;
}

#if TENET_HAS_ZSTD

/// Read a file into a byte vector.
static std::vector<uint8_t> read_file_bytes(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    REQUIRE(f.good());
    auto sz = f.tellg();
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

/// Create a compressed trace from an uncompressed one:
///   - Copy header with HF_COMPRESSED flag set
///   - zstd-compress everything after the header
static std::filesystem::path create_compressed_trace(
    const std::filesystem::path& uncompressed,
    const std::filesystem::path& dir) {

    auto data = read_file_bytes(uncompressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    REQUIRE(data.size() > kHdrSize);

    // Prepare header with HF_COMPRESSED set
    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, data.data(), kHdrSize);
    hdr.flags |= qbditrace::QBDITRACE_HF_COMPRESSED;

    // Compress the body (everything after header)
    const uint8_t* body = data.data() + kHdrSize;
    size_t body_size = data.size() - kHdrSize;
    size_t bound = ZSTD_compressBound(body_size);
    std::vector<uint8_t> compressed(bound);
    size_t compressed_size = ZSTD_compress(
        compressed.data(), bound,
        body, body_size,
        1 /* level */);
    REQUIRE(!ZSTD_isError(compressed_size));

    // Write compressed trace
    auto out_path = dir / "compressed.trace";
    FILE* fp = tenet::platform::open_file(out_path, "wb");
    REQUIRE(fp != nullptr);
    fwrite(&hdr, kHdrSize, 1, fp);
    fwrite(compressed.data(), compressed_size, 1, fp);
    fclose(fp);

    return out_path;
}

// ─── Tests (only when zstd is available) ─────────────────────────────────────

TEST_CASE("TraceReader: opens compressed trace and clears HF_COMPRESSED flag",
          "[unit][io][compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_compressed_1";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "comp_flag");
    auto compressed = create_compressed_trace(uncompressed, dir);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());
    auto& reader = *result;

    SECTION("HF_COMPRESSED is cleared in returned header") {
        REQUIRE_FALSE(reader.header().is_compressed());
    }
    SECTION("basic header fields match the original") {
        auto orig_result = TraceReader::open(uncompressed);
        REQUIRE(orig_result.has_value());
        auto& orig = *orig_result;

        REQUIRE(reader.header().magic == orig.header().magic);
        REQUIRE(reader.header().version == orig.header().version);
        REQUIRE(reader.header().arch == orig.header().arch);
        REQUIRE(reader.header().num_gpr == orig.header().num_gpr);
        REQUIRE(reader.header().module_base == orig.header().module_base);
        REQUIRE(reader.header().module_slide == orig.header().module_slide);
        // flags should match except HF_COMPRESSED is cleared
        REQUIRE(reader.header().flags == orig.header().flags);
    }

    reader.close();
    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader: compressed trace produces identical records",
          "[unit][io][compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_compressed_2";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "comp_records");
    auto compressed = create_compressed_trace(uncompressed, dir);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    // Collect record kinds and offsets from both
    struct RecordInfo {
        RecordKind kind;
        uint64_t pc;  // for INST/ANCHOR/CODE
    };

    auto collect = [](TraceReader& r) {
        std::vector<RecordInfo> records;
        for (auto it = r.begin(); it != r.end(); ++it) {
            auto rec = *it;
            RecordInfo info{rec.kind, 0};
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                info.pc = inst.pc;
            } else if (rec.kind == RecordKind::Anchor) {
                auto anc = rec.as_anchor(r.header().num_gpr);
                info.pc = anc.pc;
            } else if (rec.kind == RecordKind::Code) {
                auto code = rec.as_code();
                info.pc = code.pc;
            }
            records.push_back(info);
        }
        return records;
    };

    auto orig_records = collect(*orig_result);
    auto comp_records = collect(*comp_result);

    REQUIRE(orig_records.size() == comp_records.size());
    for (size_t i = 0; i < orig_records.size(); i++) {
        REQUIRE(orig_records[i].kind == comp_records[i].kind);
        REQUIRE(orig_records[i].pc == comp_records[i].pc);
    }

    comp_result->close();
    orig_result->close();
    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader: file_size() reflects decompressed size",
          "[unit][io][compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_compressed_3";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "comp_size");
    auto compressed = create_compressed_trace(uncompressed, dir);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    // Decompressed file_size should equal the original file_size
    REQUIRE(comp_result->file_size() == orig_result->file_size());

    comp_result->close();
    orig_result->close();
    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader: temp file is cleaned up after close()",
          "[unit][io][compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_compressed_4";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "comp_cleanup");
    auto compressed = create_compressed_trace(uncompressed, dir);

    // Count files before open
    auto count_decomp_files = [&dir]() {
        int count = 0;
        for (auto& e : std::filesystem::directory_iterator(dir)) {
            if (e.path().filename().string().find(".tenet-decomp-") != std::string::npos)
                count++;
        }
        return count;
    };

    REQUIRE(count_decomp_files() == 0);

    {
        auto result = TraceReader::open(compressed);
        REQUIRE(result.has_value());
        // While reader is open, temp file should exist
        REQUIRE(count_decomp_files() == 1);
        // close() is called by destructor when result goes out of scope
    }

    // After close, temp file should be cleaned up
    REQUIRE(count_decomp_files() == 0);

    std::filesystem::remove_all(dir);
}

TEST_CASE("TraceReader: InstView from compressed trace has correct reg diffs",
          "[unit][io][compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_compressed_5";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "comp_regdiff");
    auto compressed = create_compressed_trace(uncompressed, dir);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());

    // Find the ADD instruction (x0 = 42)
    bool found_add = false;
    for (auto it = result->begin(); it != result->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        // The ADD instruction sets x0 = 42
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto rd = inst.reg_diff(i);
            if (rd.index == 0 && rd.value == 42) {
                found_add = true;
                break;
            }
        }
        if (found_add) break;
    }
    REQUIRE(found_add);

    result->close();
    std::filesystem::remove_all(dir);
}

#else  // !TENET_HAS_ZSTD

TEST_CASE("TraceReader: compressed trace rejected when zstd not available",
          "[unit][io][compressed]") {
    // Without zstd, we can still test that a file with HF_COMPRESSED is rejected.
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_no_zstd";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "no_zstd");

    // Read the file, set HF_COMPRESSED in header, write it back
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    auto data = read_file_bytes(uncompressed);
    auto* hdr = reinterpret_cast<qbditrace::qbditrace_file_header_t*>(data.data());
    hdr->flags |= qbditrace::QBDITRACE_HF_COMPRESSED;

    auto fake_compressed = dir / "fake_compressed.trace";
    FILE* fp = tenet::platform::open_file(fake_compressed, "wb");
    REQUIRE(fp != nullptr);
    fwrite(data.data(), data.size(), 1, fp);
    fclose(fp);

    auto result = TraceReader::open(fake_compressed);
    REQUIRE_FALSE(result.has_value());

    std::filesystem::remove_all(dir);
}

#endif  // TENET_HAS_ZSTD

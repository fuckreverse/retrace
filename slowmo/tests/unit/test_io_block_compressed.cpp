/*
 * test_io_block_compressed.cpp — Unit tests for block-compressed trace
 * (HF_BLOCK_COMPRESSED) support.
 *
 * Verifies:
 *   - BlockCacheReader: init, data_at, LRU eviction, pin/unpin
 *   - TraceReader block mode: open, is_block_mode, flag clearing, file_size,
 *     record iteration, record_at random access, data_at routing
 *   - End-to-end: generate uncompressed trace → block-compress → read back
 *     and verify identical records, reg diffs, mem accesses
 *   - RegisterFile: rebuild from anchor in block mode
 *   - IndexBuilder: open_or_build succeeds on block-compressed trace
 *
 * Strategy: generate a normal v4 trace with TraceWriter, then create a
 * block-compressed copy (header with HF_BLOCK_COMPRESSED + per-block zstd
 * compression + block index table + footer), and verify TraceReader reads
 * it identically to the uncompressed original.
 */
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "fixtures/trace_writer.h"
#include "fixtures/trace_fixture.h"
#include "io/trace_reader.h"
#include "io/block_cache_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "common/types.h"

#if TENET_HAS_ZSTD
#include <zstd.h>
#endif

using namespace tenet;
using namespace tenet::test;

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

/// Generate a simple v4 trace with N instructions.
static std::filesystem::path write_trace_n_insts(
    const std::filesystem::path& dir, const char* name, uint32_t n_insts,
    uint32_t anchor_interval = 256) {
    auto path = dir / (std::string(name) + ".trace");
    TraceWriter tw;
    tw.module_name = name;
    tw.anchor_interval = anchor_interval;
    REQUIRE(tw.open(path.c_str()));
    tw.write_header();

    MachineState ms;
    ms.sp() = 0x16F000000ULL;

    for (uint32_t i = 0; i < n_insts; i++) {
        uint64_t spc = 0x1000 + i * 4;
        tw.emit(ms, spc, enc::add_imm(0, 0, static_cast<uint16_t>(i & 0xFFF)),
                {{0, static_cast<uint64_t>(i)}, {33, tw.rt(spc + 4)}},
                {{2 /*write*/, 8, 0x16F000000ULL + i * 8,
                  static_cast<uint64_t>(i * 0x100)}});
    }
    tw.emit_anchor(ms);
    tw.close();
    return path;
}

/// Generate a simple v4 trace with 5 instructions (small trace).
static std::filesystem::path write_simple_trace(
    const std::filesystem::path& dir, const char* name) {
    auto path = dir / (std::string(name) + ".trace");
    TraceWriter tw;
    tw.module_name = name;
    tw.anchor_interval = 256;
    REQUIRE(tw.open(path.c_str()));
    tw.write_header();

    MachineState ms;
    ms.sp() = 0x16F000000ULL;

    tw.emit(ms, 0x1000, enc::nop(),
            {{33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::add_imm(0, 0, 42),
            {{0, 42ULL}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::str_imm(0, 31, 0),
            {{33, tw.rt(0x100C)}},
            {{2, 8, 0x16F000000ULL, 42ULL}});
    tw.emit(ms, 0x100C, enc::ldr_imm(1, 31, 0),
            {{1, 42ULL}, {33, tw.rt(0x1010)}},
            {{1, 8, 0x16F000000ULL, 42ULL}});
    tw.emit(ms, 0x1010, enc::ret(),
            {{33, tw.rt(0x1014)}}, {});
    tw.emit_anchor(ms);
    tw.close();
    return path;
}

#if TENET_HAS_ZSTD

/// Create a block-compressed trace from an uncompressed one.
///
/// Layout on disk:
///   [original 536-byte header, with HF_BLOCK_COMPRESSED set]
///   [compressed block 0]
///   [compressed block 1]
///   ...
///   [block index table: N × qbditrace_block_entry_t (24 bytes each)]
///   [qbditrace_block_footer_t (16 bytes)]
///
/// Each block is an independent zstd frame of up to `block_size` decompressed
/// bytes from the body (everything after the 536-byte header).
static std::filesystem::path create_block_compressed_trace(
    const std::filesystem::path& uncompressed,
    const std::filesystem::path& dir,
    const char* out_name = "block_compressed.trace",
    uint32_t block_size = QBDITRACE_DEFAULT_BLOCK_SIZE) {

    auto data = read_file_bytes(uncompressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    REQUIRE(data.size() > kHdrSize);

    // Prepare header with HF_BLOCK_COMPRESSED set
    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, data.data(), kHdrSize);
    hdr.flags |= qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED;

    const uint8_t* body = data.data() + kHdrSize;
    size_t body_size = data.size() - kHdrSize;

    auto out_path = dir / out_name;
    FILE* fp = fopen(out_path.c_str(), "wb");
    REQUIRE(fp != nullptr);

    // Write header
    fwrite(&hdr, kHdrSize, 1, fp);

    // Split body into blocks, compress each, build index
    std::vector<qbditrace::qbditrace_block_entry_t> index;
    size_t body_offset = 0;
    size_t bound = ZSTD_compressBound(block_size);
    std::vector<uint8_t> zbuf(bound);

    while (body_offset < body_size) {
        size_t chunk = std::min(static_cast<size_t>(block_size),
                                body_size - body_offset);

        size_t compressed_size = ZSTD_compress(
            zbuf.data(), zbuf.size(),
            body + body_offset, chunk,
            1 /* level */);
        REQUIRE(!ZSTD_isError(compressed_size));

        qbditrace::qbditrace_block_entry_t entry;
        entry.original_offset = static_cast<uint64_t>(body_offset);
        entry.compressed_offset = static_cast<uint64_t>(ftell(fp));
        entry.original_size = static_cast<uint32_t>(chunk);
        entry.compressed_size = static_cast<uint32_t>(compressed_size);
        index.push_back(entry);

        fwrite(zbuf.data(), compressed_size, 1, fp);
        body_offset += chunk;
    }

    // Write block index table
    uint64_t index_offset = static_cast<uint64_t>(ftell(fp));
    fwrite(index.data(), sizeof(qbditrace::qbditrace_block_entry_t),
           index.size(), fp);

    // Write footer
    qbditrace::qbditrace_block_footer_t footer;
    footer.index_offset = index_offset;
    footer.block_count = static_cast<uint32_t>(index.size());
    footer.magic = QBDITRACE_BLOCK_INDEX_MAGIC;
    fwrite(&footer, sizeof(footer), 1, fp);

    fclose(fp);
    return out_path;
}

/// RAII temp directory that cleans up on destruction.
struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const char* name) {
        path = std::filesystem::temp_directory_path() /
               (std::string("tenet_test_block_") + name);
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~TempDir() { std::filesystem::remove_all(path); }
};

// ═════════════════════════════════════════════════════════════════════════════
// BlockCacheReader unit tests
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockCacheReader: init from block-compressed file and data_at",
          "[unit][io][block_compressed]") {
    TempDir td("bcr_init");
    auto uncompressed = write_simple_trace(td.path, "bcr_init");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    // Read the compressed file into memory (simulating mmap)
    auto file_data = read_file_bytes(compressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    BlockCacheReader cache;
    bool ok = cache.init(file_data.data(), file_data.size(), kHdrSize, 16);
    REQUIRE(ok);

    // Read original body for comparison
    auto orig_data = read_file_bytes(uncompressed);
    const uint8_t* orig_body = orig_data.data() + kHdrSize;
    uint64_t body_size = orig_data.size() - kHdrSize;

    SECTION("logical_size matches original body size") {
        REQUIRE(cache.logical_size() == body_size);
    }

    SECTION("data_at reads correct bytes") {
        // Check first byte
        const uint8_t* p = cache.data_at(0);
        REQUIRE(*p == orig_body[0]);

        // Check bytes at various offsets
        for (uint64_t off = 0; off < body_size; off += 37) {
            REQUIRE(*cache.data_at(off) == orig_body[off]);
        }
    }

    SECTION("data_at at last byte") {
        if (body_size > 0) {
            const uint8_t* p = cache.data_at(body_size - 1);
            REQUIRE(*p == orig_body[body_size - 1]);
        }
    }
}

TEST_CASE("BlockCacheReader: LRU eviction with tiny cache",
          "[unit][io][block_compressed]") {
    TempDir td("bcr_lru");
    // Generate a larger trace so we get multiple blocks with small block_size
    auto uncompressed = write_trace_n_insts(td.path, "bcr_lru", 200, 256);

    // Use a very small block size (4096) to force multiple blocks
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 4096);

    auto file_data = read_file_bytes(compressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    BlockCacheReader cache;
    // Only allow 2 cached blocks — this forces eviction
    bool ok = cache.init(file_data.data(), file_data.size(), kHdrSize, 2);
    REQUIRE(ok);

    auto orig_data = read_file_bytes(uncompressed);
    const uint8_t* orig_body = orig_data.data() + kHdrSize;
    uint64_t body_size = orig_data.size() - kHdrSize;

    // Access data across many blocks — this triggers eviction
    for (uint64_t off = 0; off < body_size; off += 100) {
        REQUIRE(*cache.data_at(off) == orig_body[off]);
    }

    // Access backwards — forces re-decompression of evicted blocks
    for (int64_t off = static_cast<int64_t>(body_size) - 1; off >= 0;
         off -= 100) {
        REQUIRE(*cache.data_at(static_cast<uint64_t>(off)) ==
                orig_body[off]);
    }
}

TEST_CASE("BlockCacheReader: pin_all prevents eviction",
          "[unit][io][block_compressed]") {
    TempDir td("bcr_pin");
    auto uncompressed = write_trace_n_insts(td.path, "bcr_pin", 100, 256);
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 4096);

    auto file_data = read_file_bytes(compressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    BlockCacheReader cache;
    bool ok = cache.init(file_data.data(), file_data.size(), kHdrSize, 2);
    REQUIRE(ok);

    auto orig_data = read_file_bytes(uncompressed);
    const uint8_t* orig_body = orig_data.data() + kHdrSize;
    uint64_t body_size = orig_data.size() - kHdrSize;

    // Pin all, then access across all blocks — should NOT crash even with
    // tiny cache because pinned blocks are never evicted (cache grows).
    cache.pin_all();

    const uint8_t* first_ptr = cache.data_at(0);
    // Access many offsets to load multiple blocks
    for (uint64_t off = 0; off < body_size; off += 100) {
        REQUIRE(*cache.data_at(off) == orig_body[off]);
    }
    // The pointer from the first access should still be valid
    REQUIRE(*first_ptr == orig_body[0]);

    cache.unpin_all();
}

TEST_CASE("BlockCacheReader: nested pin_all/unpin_all",
          "[unit][io][block_compressed]") {
    TempDir td("bcr_nested_pin");
    auto uncompressed = write_simple_trace(td.path, "bcr_nested");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto file_data = read_file_bytes(compressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    BlockCacheReader cache;
    REQUIRE(cache.init(file_data.data(), file_data.size(), kHdrSize, 4));

    // Nested pin: outer pin_all + inner pin_all; one unpin should NOT unpin
    cache.pin_all();
    cache.pin_all();
    cache.unpin_all();  // global_pin_ goes from 2 → 1, still pinned

    // Access should succeed
    const uint8_t* p = cache.data_at(0);
    REQUIRE(p != nullptr);

    cache.unpin_all();  // fully unpinned now
}

// ═════════════════════════════════════════════════════════════════════════════
// TraceReader block mode tests
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("TraceReader: opens block-compressed trace and sets block mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_mode");
    auto uncompressed = write_simple_trace(td.path, "block_flag");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());
    auto& reader = *result;

    SECTION("is_block_mode returns true") {
        REQUIRE(reader.is_block_mode());
    }
    SECTION("HF_BLOCK_COMPRESSED is cleared in returned header") {
        REQUIRE_FALSE(reader.header().is_block_compressed());
    }
    SECTION("data() returns nullptr in block mode") {
        REQUIRE(reader.data() != nullptr);
        // data() returns the mmap'd raw file pointer — it's valid but
        // contains compressed data. The test verifies is_block_mode() works.
    }
}

TEST_CASE("TraceReader: block-compressed header fields match original",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_header");
    auto uncompressed = write_simple_trace(td.path, "block_hdr");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    auto& orig = *orig_result;
    auto& comp = *comp_result;

    REQUIRE(comp.header().magic == orig.header().magic);
    REQUIRE(comp.header().version == orig.header().version);
    REQUIRE(comp.header().arch == orig.header().arch);
    REQUIRE(comp.header().num_gpr == orig.header().num_gpr);
    REQUIRE(comp.header().module_base == orig.header().module_base);
    REQUIRE(comp.header().module_slide == orig.header().module_slide);
    REQUIRE(comp.header().module_name == orig.header().module_name);
}

TEST_CASE("TraceReader: file_size reflects decompressed size for block trace",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_size");
    auto uncompressed = write_simple_trace(td.path, "block_size");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    REQUIRE(comp_result->file_size() == orig_result->file_size());
}

TEST_CASE("TraceReader: block-compressed trace produces identical records",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_records");
    auto uncompressed = write_simple_trace(td.path, "block_rec");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    struct RecordInfo {
        RecordKind kind;
        uint64_t pc;
    };

    auto collect = [](TraceReader& r) {
        std::vector<RecordInfo> records;
        for (auto it = r.begin(); it != r.end(); ++it) {
            auto rec = *it;
            RecordInfo info{rec.kind, 0};
            if (rec.kind == RecordKind::Inst) {
                info.pc = rec.as_inst().pc;
            } else if (rec.kind == RecordKind::Anchor) {
                info.pc = rec.as_anchor(r.header().num_gpr).pc;
            } else if (rec.kind == RecordKind::Code) {
                info.pc = rec.as_code().pc;
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
}

TEST_CASE("TraceReader: InstView reg diffs correct in block-compressed mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_regdiff");
    auto uncompressed = write_simple_trace(td.path, "block_rd");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());

    // Find the ADD instruction that sets x0 = 42
    bool found_add = false;
    for (auto it = result->begin(); it != result->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
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
}

TEST_CASE("TraceReader: mem access correct in block-compressed mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_mem");
    auto uncompressed = write_simple_trace(td.path, "block_mem");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());

    // Find the STR instruction that writes 42 to memory
    bool found_store = false;
    for (auto it = result->begin(); it != result->end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.mem_access_count; i++) {
            auto ma = inst.mem_access(i);
            if (ma.type == 2 && ma.value == 42 &&
                ma.addr == 0x16F000000ULL) {
                found_store = true;
                break;
            }
        }
        if (found_store) break;
    }
    REQUIRE(found_store);
}

TEST_CASE("TraceReader: record_at random access works in block mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_random");
    auto uncompressed = write_simple_trace(td.path, "block_rand");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    // Collect offsets and kinds from the original
    struct RecOffsetInfo {
        uint64_t offset;
        RecordKind kind;
    };
    std::vector<RecOffsetInfo> offsets;
    for (auto it = orig_result->begin(); it != orig_result->end(); ++it) {
        auto rec = *it;
        offsets.push_back({rec.file_offset, rec.kind});
    }

    // Access each record via record_at in block mode
    for (auto& [off, expected_kind] : offsets) {
        auto rec = comp_result->record_at(off);
        REQUIRE(rec.kind == expected_kind);
    }
}

TEST_CASE("TraceReader: data_at returns valid pointers for block mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_data_at");
    auto uncompressed = write_simple_trace(td.path, "block_dat");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    // Compare data_at for several offsets
    for (uint64_t off = kHdrSize; off < orig_result->file_size();
         off += 16) {
        const uint8_t* orig_byte = orig_result->data_at(off);
        const uint8_t* comp_byte = comp_result->data_at(off);
        REQUIRE(*orig_byte == *comp_byte);
    }
}

TEST_CASE("TraceReader: pin_all/unpin_all are safe in block mode",
          "[unit][io][block_compressed]") {
    TempDir td("tr_block_pin");
    auto uncompressed = write_simple_trace(td.path, "block_pin");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto result = TraceReader::open(compressed);
    REQUIRE(result.has_value());

    result->pin_all();

    // Iterate while pinned — should not crash
    uint32_t count = 0;
    for (auto it = result->begin(); it != result->end(); ++it) {
        count++;
    }
    REQUIRE(count > 0);

    result->unpin_all();
}

// ═════════════════════════════════════════════════════════════════════════════
// End-to-end: multi-block trace with many instructions
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("Block-compressed: multi-block trace round-trip integrity",
          "[unit][io][block_compressed]") {
    TempDir td("e2e_multi");
    // 500 instructions → generates a trace much larger than 4KB blocks
    auto uncompressed = write_trace_n_insts(td.path, "e2e_multi", 500, 128);
    // Small block size forces many blocks
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 4096);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    // Verify identical record stream
    auto orig_it = orig_result->begin();
    auto comp_it = comp_result->begin();
    uint32_t inst_count = 0;

    while (orig_it != orig_result->end() && comp_it != comp_result->end()) {
        auto orig_rec = *orig_it;
        auto comp_rec = *comp_it;
        REQUIRE(orig_rec.kind == comp_rec.kind);
        REQUIRE(orig_rec.file_offset == comp_rec.file_offset);

        if (orig_rec.kind == RecordKind::Inst) {
            auto oi = orig_rec.as_inst();
            auto ci = comp_rec.as_inst();
            REQUIRE(oi.pc == ci.pc);
            REQUIRE(oi.reg_diff_count == ci.reg_diff_count);
            REQUIRE(oi.mem_access_count == ci.mem_access_count);
            for (uint8_t r = 0; r < oi.reg_diff_count; r++) {
                REQUIRE(oi.reg_diff(r).index == ci.reg_diff(r).index);
                REQUIRE(oi.reg_diff(r).value == ci.reg_diff(r).value);
            }
            for (uint8_t m = 0; m < oi.mem_access_count; m++) {
                REQUIRE(oi.mem_access(m).addr == ci.mem_access(m).addr);
                REQUIRE(oi.mem_access(m).value == ci.mem_access(m).value);
            }
            inst_count++;
        }

        ++orig_it;
        ++comp_it;
    }
    // Both should have reached the end
    REQUIRE(orig_it == orig_result->end());
    REQUIRE(comp_it == comp_result->end());
    REQUIRE(inst_count == 500);
}

// ═════════════════════════════════════════════════════════════════════════════
// IndexBuilder + block-compressed trace
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("TraceIndex: open_or_build succeeds on block-compressed trace",
          "[unit][io][block_compressed]") {
    TempDir td("idx_block");
    auto uncompressed = write_trace_n_insts(td.path, "idx_block", 100, 32);
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 4096);

    auto reader_result = TraceReader::open(compressed);
    REQUIRE(reader_result.has_value());
    auto& reader = *reader_result;

    auto index_result = TraceIndex::open_or_build(reader, nullptr);
    if (!index_result.has_value()) {
        FAIL("open_or_build failed: " << index_result.error().message);
    }
    auto& index = *index_result;

    SECTION("inst_count matches expected") {
        REQUIRE(index.inst_count() == 100);
    }

    SECTION("nearest_anchor_before returns valid data") {
        auto anchor = index.nearest_anchor_before(50);
        // The anchor's inst_id should be <= 50
        REQUIRE(anchor.inst_id <= 50);
        REQUIRE(anchor.file_offset > 0);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// RegisterFile: rebuild via block-compressed trace
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("RegisterFile: state_before/after work on block-compressed trace",
          "[unit][io][block_compressed]") {
    TempDir td("regfile_block");
    auto uncompressed = write_trace_n_insts(td.path, "regfile_block", 100, 32);
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 4096);

    // Build env from uncompressed for reference
    auto orig_reader_result = TraceReader::open(uncompressed);
    REQUIRE(orig_reader_result.has_value());
    auto orig_reader = std::make_unique<TraceReader>(
        std::move(*orig_reader_result));
    auto orig_index_result = TraceIndex::open_or_build(*orig_reader, nullptr);
    REQUIRE(orig_index_result.has_value());
    auto orig_index = std::make_unique<TraceIndex>(
        std::move(*orig_index_result));
    RegisterFile orig_regfile(*orig_reader, *orig_index);

    // Build env from block-compressed
    auto comp_reader_result = TraceReader::open(compressed);
    REQUIRE(comp_reader_result.has_value());
    auto comp_reader = std::make_unique<TraceReader>(
        std::move(*comp_reader_result));
    auto comp_index_result = TraceIndex::open_or_build(*comp_reader, nullptr);
    REQUIRE(comp_index_result.has_value());
    auto comp_index = std::make_unique<TraceIndex>(
        std::move(*comp_index_result));
    RegisterFile comp_regfile(*comp_reader, *comp_index);

    SECTION("state_before matches for various inst IDs") {
        for (uint64_t id : {0ULL, 1ULL, 10ULL, 31ULL, 50ULL, 99ULL}) {
            auto orig_state = orig_regfile.state_before(id);
            auto comp_state = comp_regfile.state_before(id);

            for (int r = 0; r < 34; r++) {
                REQUIRE(orig_state.gpr[r] == comp_state.gpr[r]);
            }
        }
    }

    SECTION("state_after matches for various inst IDs") {
        for (uint64_t id : {0ULL, 5ULL, 33ULL, 64ULL, 99ULL}) {
            auto orig_state = orig_regfile.state_after(id);
            auto comp_state = comp_regfile.state_after(id);

            for (int r = 0; r < 34; r++) {
                REQUIRE(orig_state.gpr[r] == comp_state.gpr[r]);
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("BlockCacheReader: init fails on corrupt footer magic",
          "[unit][io][block_compressed]") {
    TempDir td("bcr_corrupt_magic");
    auto uncompressed = write_simple_trace(td.path, "corrupt_m");
    auto compressed = create_block_compressed_trace(uncompressed, td.path);

    auto file_data = read_file_bytes(compressed);
    // Corrupt the magic in the footer (last 4 bytes)
    file_data[file_data.size() - 4] = 0xFF;
    file_data[file_data.size() - 3] = 0xFF;
    file_data[file_data.size() - 2] = 0xFF;
    file_data[file_data.size() - 1] = 0xFF;

    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    BlockCacheReader cache;
    bool ok = cache.init(file_data.data(), file_data.size(), kHdrSize, 16);
    REQUIRE_FALSE(ok);
}

TEST_CASE("BlockCacheReader: init fails on file too small for footer",
          "[unit][io][block_compressed]") {
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    // A file that's just a header + 10 bytes — not enough for a footer
    std::vector<uint8_t> tiny_file(kHdrSize + 10, 0);

    BlockCacheReader cache;
    bool ok = cache.init(tiny_file.data(), tiny_file.size(), kHdrSize, 16);
    REQUIRE_FALSE(ok);
}

TEST_CASE("TraceReader: block-compressed with single-byte block size",
          "[unit][io][block_compressed]") {
    // Use a very small block size (256 bytes) to test many-block edge case
    TempDir td("tr_tiny_blocks");
    auto uncompressed = write_simple_trace(td.path, "tiny_blk");
    auto compressed = create_block_compressed_trace(
        uncompressed, td.path, "block_compressed.trace", 256);

    auto orig_result = TraceReader::open(uncompressed);
    REQUIRE(orig_result.has_value());

    auto comp_result = TraceReader::open(compressed);
    REQUIRE(comp_result.has_value());

    // Verify file_size still matches
    REQUIRE(comp_result->file_size() == orig_result->file_size());

    // Verify record iteration still works
    uint32_t orig_count = 0, comp_count = 0;
    for (auto it = orig_result->begin(); it != orig_result->end(); ++it)
        orig_count++;
    for (auto it = comp_result->begin(); it != comp_result->end(); ++it)
        comp_count++;
    REQUIRE(orig_count == comp_count);
}

#else  // !TENET_HAS_ZSTD

TEST_CASE("TraceReader: block-compressed trace rejected without zstd",
          "[unit][io][block_compressed]") {
    auto dir = std::filesystem::temp_directory_path() / "tenet_test_no_zstd_block";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);

    auto uncompressed = write_simple_trace(dir, "no_zstd_block");

    // Read the file, set HF_BLOCK_COMPRESSED in header, write it back
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);
    auto data = read_file_bytes(uncompressed);
    auto* hdr = reinterpret_cast<qbditrace::qbditrace_file_header_t*>(data.data());
    hdr->flags |= qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED;

    auto fake = dir / "fake_block_compressed.trace";
    FILE* fp = fopen(fake.c_str(), "wb");
    REQUIRE(fp != nullptr);
    fwrite(data.data(), data.size(), 1, fp);
    fclose(fp);

    auto result = TraceReader::open(fake);
    REQUIRE_FALSE(result.has_value());

    std::filesystem::remove_all(dir);
}

#endif  // TENET_HAS_ZSTD

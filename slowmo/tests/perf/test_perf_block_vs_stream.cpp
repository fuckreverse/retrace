#include "common/platform_compat.h"
#include "common/platform_file.h"
/*
 * test_perf_block_vs_stream.cpp — Comparative benchmark: block-compressed
 * (on-demand LRU decompression) vs stream-compressed (decompress to temp file).
 *
 * Generates the same synthetic trace in three formats:
 *   1. Uncompressed (baseline mmap)
 *   2. Stream-compressed (HF_COMPRESSED — single zstd frame, decompressed
 *      to a temp file at open time)
 *   3. Block-compressed (HF_BLOCK_COMPRESSED — per-block zstd with LRU
 *      cache, no temp file)
 *
 * Measures:
 *   - Open latency (ms): time to go from file-on-disk to ready-to-iterate
 *   - Sequential scan throughput (MB/s, Minst/s): full forward iteration
 *   - Index build time (ms): TraceIndex::open_or_build cold build
 *   - Random access latency (us): record_at at uniformly-sampled offsets
 *   - Compressed file size (bytes): on-disk footprint
 *
 * Run:
 *   ctest -R 'perf.*block_vs_stream' --output-on-failure
 *   # or with verbose output:
 *   ./test_perf_block_vs_stream -s
 */
#include <catch2/catch_test_macros.hpp>

#include "perf/perf_utils.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <vector>

#if TENET_HAS_ZSTD
#include <zstd.h>
#endif

using namespace tenet;
using namespace tenet::test;
using namespace tenet::test::perf;

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers — create compressed variants of an uncompressed trace
// ═══════════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> read_file_bytes(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    auto sz = f.tellg();
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

#if TENET_HAS_ZSTD

/// Create a stream-compressed (HF_COMPRESSED) copy of an uncompressed trace.
/// The entire body after the 536-byte header is compressed into a single zstd
/// frame.  The header's HF_COMPRESSED flag is set.
static fs::path create_stream_compressed_trace(
    const fs::path& uncompressed, const fs::path& dir,
    const char* out_name = "stream.trace") {

    auto data = read_file_bytes(uncompressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    // Prepare header with HF_COMPRESSED set
    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, data.data(), kHdrSize);
    hdr.flags |= qbditrace::QBDITRACE_HF_COMPRESSED;

    const uint8_t* body = data.data() + kHdrSize;
    size_t body_size = data.size() - kHdrSize;

    // Compress the entire body as a single zstd frame
    size_t bound = ZSTD_compressBound(body_size);
    std::vector<uint8_t> zbuf(bound);
    size_t compressed_size = ZSTD_compress(
        zbuf.data(), zbuf.size(), body, body_size, 1);
    REQUIRE(!ZSTD_isError(compressed_size));

    auto out_path = dir / out_name;
    FILE* fp = tenet::platform::open_file(out_path, "wb");
    REQUIRE(fp != nullptr);
    fwrite(&hdr, kHdrSize, 1, fp);
    fwrite(zbuf.data(), compressed_size, 1, fp);
    fclose(fp);
    return out_path;
}

/// Create a block-compressed (HF_BLOCK_COMPRESSED) copy of an uncompressed trace.
static fs::path create_block_compressed_trace(
    const fs::path& uncompressed, const fs::path& dir,
    const char* out_name = "block.trace",
    uint32_t block_size = QBDITRACE_DEFAULT_BLOCK_SIZE) {

    auto data = read_file_bytes(uncompressed);
    constexpr size_t kHdrSize = sizeof(qbditrace::qbditrace_file_header_t);

    qbditrace::qbditrace_file_header_t hdr;
    std::memcpy(&hdr, data.data(), kHdrSize);
    hdr.flags |= qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED;

    const uint8_t* body = data.data() + kHdrSize;
    size_t body_size = data.size() - kHdrSize;

    auto out_path = dir / out_name;
    FILE* fp = tenet::platform::open_file(out_path, "wb");
    REQUIRE(fp != nullptr);
    fwrite(&hdr, kHdrSize, 1, fp);

    std::vector<qbditrace::qbditrace_block_entry_t> index;
    size_t body_offset = 0;
    size_t bound = ZSTD_compressBound(block_size);
    std::vector<uint8_t> zbuf(bound);

    while (body_offset < body_size) {
        size_t chunk = std::min(static_cast<size_t>(block_size),
                                body_size - body_offset);

        size_t compressed_size = ZSTD_compress(
            zbuf.data(), zbuf.size(),
            body + body_offset, chunk, 1);
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

    // Write block index table + footer
    uint64_t index_offset = static_cast<uint64_t>(ftell(fp));
    fwrite(index.data(), sizeof(qbditrace::qbditrace_block_entry_t),
           index.size(), fp);

    qbditrace::qbditrace_block_footer_t footer;
    footer.index_offset = index_offset;
    footer.block_count = static_cast<uint32_t>(index.size());
    footer.magic = QBDITRACE_BLOCK_INDEX_MAGIC;
    fwrite(&footer, sizeof(footer), 1, fp);

    fclose(fp);
    return out_path;
}

#endif // TENET_HAS_ZSTD

// ═══════════════════════════════════════════════════════════════════════════════
// RAII temp directory
// ═══════════════════════════════════════════════════════════════════════════════

struct PerfTempDir {
    fs::path path;
    explicit PerfTempDir(const char* name) {
        path = fs::temp_directory_path() /
               (std::string("tenet_perf_") + name + "_" +
                std::to_string(tenet::platform::current_pid()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~PerfTempDir() { fs::remove_all(path); }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Benchmark result container
// ═══════════════════════════════════════════════════════════════════════════════

struct BenchResult {
    std::string format;
    uint64_t file_size_bytes = 0;
    double open_ms = 0;
    double scan_ms = 0;
    double scan_mbps = 0;
    double scan_minst = 0;
    uint64_t record_count = 0;
    double index_build_ms = 0;
    LatencyStats random_access;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Core benchmark routine — runs the same measurements on any TraceReader
// ═══════════════════════════════════════════════════════════════════════════════

static BenchResult run_benchmark(const fs::path& trace_path,
                                  const char* format_name,
                                  uint64_t expected_insts) {
    BenchResult res;
    res.format = format_name;
    res.file_size_bytes = fs::file_size(trace_path);

    // ── 1. Open latency ──────────────────────────────────────────────────
    Timer t_open;
    t_open.start();
    auto reader_result = TraceReader::open(trace_path);
    res.open_ms = t_open.elapsed_ms();
    REQUIRE(reader_result.has_value());
    auto reader = std::make_unique<TraceReader>(std::move(*reader_result));

    uint64_t logical_size = reader->file_size();

    // ── 2. Sequential scan (warmup + measured) ───────────────────────────
    // Warmup
    {
        uint64_t cnt = 0;
        for (auto it = reader->begin(); it != reader->end(); ++it) ++cnt;
    }

    Timer t_scan;
    t_scan.start();
    uint64_t record_count = 0;
    uint64_t inst_count = 0;
    reader->advise_sequential();
    for (auto it = reader->begin(); it != reader->end(); ++it) {
        auto rec = *it;
        ++record_count;
        if (rec.kind == RecordKind::Inst) ++inst_count;
    }
    res.scan_ms = t_scan.elapsed_ms();
    res.record_count = record_count;

    // Throughput based on logical (decompressed) size
    res.scan_mbps = (logical_size / (1024.0 * 1024.0)) / (res.scan_ms / 1000.0);
    res.scan_minst = (inst_count / 1e6) / (res.scan_ms / 1000.0);

    // ── 3. Index build (cold) ────────────────────────────────────────────
    {
        // Clean any existing index
        auto idx_path = trace_path;
        auto idx_dir = trace_path;
        idx_dir.replace_extension(".tenet_idx");
        fs::remove_all(idx_dir);

        Timer t_idx;
        t_idx.start();
        auto idx_result = TraceIndex::open_or_build(*reader);
        res.index_build_ms = t_idx.elapsed_ms();
        REQUIRE(idx_result.has_value());
        REQUIRE(idx_result->inst_count() == expected_insts);
    }

    // ── 4. Random access latency ─────────────────────────────────────────
    // Rebuild index for random access test
    {
        auto idx_result = TraceIndex::open_or_build(*reader);
        REQUIRE(idx_result.has_value());
        auto& index = *idx_result;

        // Sample random instruction offsets
        std::mt19937_64 rng(42);
        const uint64_t n_samples = 1000;
        std::uniform_int_distribution<uint64_t> dist(0, expected_insts - 1);

        std::vector<double> latencies;
        latencies.reserve(n_samples);

        reader->pin_all();

        for (uint64_t s = 0; s < n_samples; s++) {
            uint64_t inst_id = dist(rng);
            auto offset_val = index.offset_of(inst_id, *reader);
            if (offset_val == 0 && inst_id != 0) continue;

            Timer t_ra;
            t_ra.start();
            auto rv = reader->record_at(offset_val);
            // Force access to record fields to ensure decompression happens
            if (rv.kind == RecordKind::Inst) {
                auto inst = rv.as_inst();
                (void)inst.pc;
                (void)inst.reg_diff_count;
            }
            latencies.push_back(t_ra.elapsed_us());
        }

        reader->unpin_all();

        res.random_access = LatencyStats::from_samples(latencies);
    }

    return res;
}

/// Print a comparison table to INFO (visible with -s / --output-on-failure)
static void print_comparison(const std::vector<BenchResult>& results,
                              uint64_t n_insts) {
    INFO("═══ Block-Compressed vs Stream-Compressed Benchmark ═══");
    INFO("Trace size: " << n_insts << " instructions");
    INFO("");
    INFO("┌──────────────────┬──────────────┬──────────────┬──────────────┐");
    INFO("│ Metric           │ Uncompressed │ Stream       │ Block        │");
    INFO("├──────────────────┼──────────────┼──────────────┼──────────────┤");

    for (auto& r : results) {
        INFO("  [" << r.format << "]");
        INFO("    File size:          " << (r.file_size_bytes / (1024.0 * 1024.0))
             << " MB");
        INFO("    Open latency:       " << r.open_ms << " ms");
        INFO("    Scan throughput:    " << r.scan_mbps << " MB/s ("
             << r.scan_minst << " Minst/s)");
        INFO("    Scan elapsed:       " << r.scan_ms << " ms");
        INFO("    Records scanned:    " << r.record_count);
        INFO("    Index build (cold): " << r.index_build_ms << " ms");
        INFO("    Random access p50:  " << r.random_access.p50_us << " us");
        INFO("    Random access p95:  " << r.random_access.p95_us << " us");
        INFO("    Random access p99:  " << r.random_access.p99_us << " us");
        INFO("    Random access max:  " << r.random_access.max_us << " us");
        INFO("");
    }

    // Compute block vs stream speedup/ratio
    if (results.size() >= 3) {
        auto& stream = results[1];
        auto& block = results[2];
        INFO("═══ Block vs Stream comparison ═══");
        INFO("  Open latency speedup: "
             << (stream.open_ms / std::max(block.open_ms, 0.001))
             << "x faster (block " << block.open_ms
             << " ms vs stream " << stream.open_ms << " ms)");
        INFO("  Scan throughput ratio: "
             << (block.scan_mbps / std::max(stream.scan_mbps, 0.001))
             << "x (block " << block.scan_mbps
             << " MB/s vs stream " << stream.scan_mbps << " MB/s)");
        INFO("  Index build ratio: "
             << (stream.index_build_ms / std::max(block.index_build_ms, 0.001))
             << "x (block " << block.index_build_ms
             << " ms vs stream " << stream.index_build_ms << " ms)");
        INFO("  Random access p50 ratio: "
             << (block.random_access.p50_us / std::max(stream.random_access.p50_us, 0.001))
             << "x (block " << block.random_access.p50_us
             << " us vs stream " << stream.random_access.p50_us << " us)");
        INFO("  File size ratio: "
             << ((double)block.file_size_bytes / std::max((double)stream.file_size_bytes, 1.0))
             << "x (block " << (block.file_size_bytes / 1024.0)
             << " KB vs stream " << (stream.file_size_bytes / 1024.0) << " KB)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════════════════

#if TENET_HAS_ZSTD

TEST_CASE("Block vs Stream: 500K linear trace", "[perf][block_vs_stream]") {
    const uint64_t N = 500000;
    PerfTempDir dir("bvs_linear");

    // ── Generate uncompressed trace ──────────────────────────────────────
    auto uncomp_path = dir.path / "uncompressed.trace";
    {
        TraceWriter tw;
        tw.module_name = "bvs_linear";
        tw.anchor_interval = 4096;
        REQUIRE(tw.open(uncomp_path.c_str()));
        gen_linear_trace(tw, N);
        tw.close();
    }

    // ── Create compressed variants ───────────────────────────────────────
    auto stream_path = create_stream_compressed_trace(
        uncomp_path, dir.path, "stream.trace");
    auto block_path = create_block_compressed_trace(
        uncomp_path, dir.path, "block.trace");

    // ── Run benchmarks ───────────────────────────────────────────────────
    std::vector<BenchResult> results;
    results.push_back(run_benchmark(uncomp_path, "Uncompressed", N));
    results.push_back(run_benchmark(stream_path, "Stream-Compressed", N));
    results.push_back(run_benchmark(block_path, "Block-Compressed", N));

    // ── Print comparison ─────────────────────────────────────────────────
    print_comparison(results, N);

    // ── Assertions ───────────────────────────────────────────────────────
    // Block-compressed should open *much* faster than stream (no full decompression)
    CHECK(results[2].open_ms < results[1].open_ms);

    // Both compressed formats should produce identical instruction counts
    CHECK(results[1].record_count == results[0].record_count);
    CHECK(results[2].record_count == results[0].record_count);

    // Block-compressed scan should be at minimum 10 MB/s (generous threshold)
    PERF_CHECK_MBPS(results[2].scan_ms, results[2].file_size_bytes, 10);

    // Block-compressed index build should complete
    CHECK(results[2].index_build_ms > 0);

    // Random access should work (samples collected)
    CHECK(results[2].random_access.samples > 0);
}

TEST_CASE("Block vs Stream: 500K memory trace", "[perf][block_vs_stream]") {
    const uint64_t N = 500000;
    PerfTempDir dir("bvs_memory");

    // Generate uncompressed trace with memory accesses
    auto uncomp_path = dir.path / "uncompressed.trace";
    {
        TraceWriter tw;
        tw.module_name = "bvs_memory";
        tw.anchor_interval = 4096;
        REQUIRE(tw.open(uncomp_path.c_str()));
        gen_memory_trace(tw, N);
        tw.close();
    }

    auto stream_path = create_stream_compressed_trace(
        uncomp_path, dir.path, "stream.trace");
    auto block_path = create_block_compressed_trace(
        uncomp_path, dir.path, "block.trace");

    std::vector<BenchResult> results;
    results.push_back(run_benchmark(uncomp_path, "Uncompressed", N));
    results.push_back(run_benchmark(stream_path, "Stream-Compressed", N));
    results.push_back(run_benchmark(block_path, "Block-Compressed", N));

    print_comparison(results, N);

    // Block-compressed should open faster than stream
    CHECK(results[2].open_ms < results[1].open_ms);

    // Identical record counts
    CHECK(results[1].record_count == results[0].record_count);
    CHECK(results[2].record_count == results[0].record_count);
}

TEST_CASE("Block-compressed: open latency scaling", "[perf][block_vs_stream]") {
    // Block open reads block metadata; stream open decompresses the full trace.
    // Compare their median latency across increasing trace sizes.
    PerfTempDir dir("bvs_scaling");

    const uint64_t sizes[] = { 100000, 300000, 500000 };
    std::vector<double> stream_open_ms;
    std::vector<double> block_open_ms;

    for (uint64_t n : sizes) {
        auto uncomp_path = dir.path / ("uncomp_" + std::to_string(n) + ".trace");
        {
            TraceWriter tw;
            tw.module_name = "bvs_scale";
            tw.anchor_interval = 4096;
            REQUIRE(tw.open(uncomp_path.c_str()));
            gen_linear_trace(tw, n);
            tw.close();
        }

        auto stream_path = create_stream_compressed_trace(
            uncomp_path, dir.path,
            ("stream_" + std::to_string(n) + ".trace").c_str());
        auto block_path = create_block_compressed_trace(
            uncomp_path, dir.path,
            ("block_" + std::to_string(n) + ".trace").c_str());

        auto median_open = [](const std::filesystem::path& path) {
            std::vector<double> samples;
            for (int attempt = 0; attempt < 7; ++attempt) {
                Timer t;
                t.start();
                auto r = TraceReader::open(path);
                auto elapsed = t.elapsed_ms();
                REQUIRE(r.has_value());
                if (attempt > 0) samples.push_back(elapsed); // warm the filesystem cache
            }
            std::sort(samples.begin(), samples.end());
            return (samples[2] + samples[3]) / 2;
        };
        stream_open_ms.push_back(median_open(stream_path));
        block_open_ms.push_back(median_open(block_path));
        INFO("trace size: " << n);
        CHECK(block_open_ms.back() < stream_open_ms.back());
    }

    // Report scaling
    INFO("═══ Open Latency Scaling ═══");
    for (size_t i = 0; i < 3; i++) {
        INFO("  " << sizes[i] << " insts: stream=" << stream_open_ms[i]
             << " ms, block=" << block_open_ms[i] << " ms, ratio="
             << (stream_open_ms[i] / std::max(block_open_ms[i], 0.001)) << "x");
    }

    // Report growth for diagnosis. Metadata grows with the number of blocks,
    // so its growth ratio need not be lower than full decompression's ratio.
    double block_growth = block_open_ms[2] / std::max(block_open_ms[0], 0.001);
    double stream_growth = stream_open_ms[2] / std::max(stream_open_ms[0], 0.001);
    INFO("  Block open growth (500K/100K): " << block_growth << "x");
    INFO("  Stream open growth (500K/100K): " << stream_growth << "x");

}

#else // !TENET_HAS_ZSTD

TEST_CASE("Block vs Stream: skipped (no zstd)", "[perf][block_vs_stream]") {
    WARN("Skipping block vs stream benchmark: TENET_HAS_ZSTD not defined");
}

#endif // TENET_HAS_ZSTD

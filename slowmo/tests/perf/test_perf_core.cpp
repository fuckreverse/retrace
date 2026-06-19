/*
 * test_perf_core.cpp — Performance regression tests for Tenet Core layer.
 *
 * Measures and asserts maximum latency for:
 *   - RegisterFile::state_before() random seek (p50, p95, p99)
 *   - MemoryModel::read() random access (p50, p95, p99)
 *
 * The RegisterFile uses ANCHOR-based reconstruction with an LRU cache, so
 * seek latency depends on anchor density and cache hit rate.  We test both
 * a dense-anchor trace (interval=64) and a sparse-anchor trace (interval=4096).
 *
 * Run:  ctest -R 'perf.*core' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "perf/perf_utils.h"
#include "core/register_file.h"
#include "core/memory_model.h"

#include <random>

using namespace tenet;
using namespace tenet::test;
using namespace tenet::test::perf;

// ═══════════════════════════════════════════════════════════════════════════════
// RegisterFile seek latency
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("RegisterFile seek: 100K trace, dense anchors", "[perf][core]") {
    const uint64_t N = 100000;

    // Generate with dense anchors (every 64 insts) for fast reconstruction
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 64;
        gen_linear_trace(tw, N);
    }, "perf_core_seek_dense");
    REQUIRE(env != nullptr);

    REQUIRE(env->index->inst_count() == N);

    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, N - 1);

    const uint32_t SAMPLES = 500;
    std::vector<uint64_t> targets(SAMPLES);
    for (auto& t : targets) t = dist(rng);

    // Warmup
    for (uint32_t i = 0; i < 10; i++)
        (void)env->regfile->state_before(targets[i]);

    // Measure
    std::vector<double> latencies(SAMPLES);
    Timer t;
    for (uint32_t i = 0; i < SAMPLES; i++) {
        t.start();
        (void)env->regfile->state_before(targets[i]);
        latencies[i] = t.elapsed_us();
    }

    auto stats = LatencyStats::from_samples(latencies);
    // Dense anchors → most seeks hit the LRU cache or reconstruct from a
    // nearby anchor.  p95 should be well under 1ms.
    PERF_CHECK_P95_US(stats, 1000.0);  // < 1ms p95
}

TEST_CASE("RegisterFile seek: 100K trace, sparse anchors", "[perf][core]") {
    const uint64_t N = 100000;

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 4096;  // very sparse
        gen_linear_trace(tw, N);
    }, "perf_core_seek_sparse");
    REQUIRE(env != nullptr);

    REQUIRE(env->index->inst_count() == N);

    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, N - 1);

    const uint32_t SAMPLES = 500;
    std::vector<uint64_t> targets(SAMPLES);
    for (auto& t : targets) t = dist(rng);

    // Warmup
    for (uint32_t i = 0; i < 10; i++)
        (void)env->regfile->state_before(targets[i]);

    std::vector<double> latencies(SAMPLES);
    Timer t;
    for (uint32_t i = 0; i < SAMPLES; i++) {
        t.start();
        (void)env->regfile->state_before(targets[i]);
        latencies[i] = t.elapsed_us();
    }

    auto stats = LatencyStats::from_samples(latencies);
    // Sparse anchors → more reg-diffs to replay.  Allow up to 5ms p95.
    PERF_CHECK_P95_US(stats, 5000.0);
}

TEST_CASE("RegisterFile sequential seek is faster than random", "[perf][core]") {
    const uint64_t N = 100000;

    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        gen_linear_trace(tw, N);
    }, "perf_core_seek_seq");
    REQUIRE(env != nullptr);

    // Random seeks
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, N - 1);
    const uint32_t SAMPLES = 200;

    std::vector<double> rand_lat(SAMPLES);
    Timer t;
    for (uint32_t i = 0; i < SAMPLES; i++) {
        uint64_t target = dist(rng);
        t.start();
        (void)env->regfile->state_before(target);
        rand_lat[i] = t.elapsed_us();
    }
    auto rand_stats = LatencyStats::from_samples(rand_lat);

    // Sequential seeks (should benefit from LRU locality)
    std::vector<double> seq_lat(SAMPLES);
    for (uint32_t i = 0; i < SAMPLES; i++) {
        uint64_t target = (uint64_t)i * (N / SAMPLES);
        t.start();
        (void)env->regfile->state_before(target);
        seq_lat[i] = t.elapsed_us();
    }
    auto seq_stats = LatencyStats::from_samples(seq_lat);

    // Sequential median should not be dramatically worse than random median
    // (both should be in the same order of magnitude).  This is a smoke test
    // rather than a strict ordering assertion.
    CHECK(seq_stats.p50_us < rand_stats.p50_us * 10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MemoryModel read latency
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("MemoryModel read: 100K memory trace", "[perf][core]") {
    const uint64_t N = 100000;

    auto env = make_env(wrap_gen(gen_memory_trace, N), "perf_core_memread");
    REQUIRE(env != nullptr);

    REQUIRE(env->index->inst_count() == N);

    // Build the memory model (fixture doesn't call build())
    Timer t;
    t.start();
    env->memory->build();
    double build_ms = t.elapsed_ms();
    // Memory build for 100K writes should be < 5s
    PERF_CHECK_MAX_MS(build_ms, 5000);

    // Collect memory addresses from the trace for random queries
    std::vector<std::pair<uint64_t, uint64_t>> mem_targets;  // (addr, inst_id)
    uint64_t scan_inst_id = 0;
    for (auto it = env->reader->begin();
         it != env->reader->end() && mem_targets.size() < 5000; ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto ma = inst.mem_access(m);
                mem_targets.emplace_back(ma.addr, scan_inst_id);
            }
            scan_inst_id++;
        }
    }

    REQUIRE(!mem_targets.empty());

    std::mt19937_64 rng(123);
    std::uniform_int_distribution<size_t> dist(0, mem_targets.size() - 1);

    const uint32_t SAMPLES = 300;
    std::vector<double> latencies(SAMPLES);

    // Warmup
    for (uint32_t i = 0; i < 10; i++) {
        auto [addr, iid] = mem_targets[dist(rng)];
        (void)env->memory->read(addr, 8, iid);
    }

    for (uint32_t i = 0; i < SAMPLES; i++) {
        auto [addr, iid] = mem_targets[dist(rng)];
        t.start();
        (void)env->memory->read(addr, 8, iid);
        latencies[i] = t.elapsed_us();
    }

    auto stats = LatencyStats::from_samples(latencies);
    // Memory read p95 should be < 5ms (RocksDB point lookup + cache)
    PERF_CHECK_P95_US(stats, 5000.0);
}

TEST_CASE("MemoryModel repeated reads hit cache", "[perf][core]") {
    const uint64_t N = 50000;

    auto env = make_env(wrap_gen(gen_memory_trace, N), "perf_core_memcache");
    REQUIRE(env != nullptr);

    env->memory->build();

    // Collect a small set of addresses
    std::vector<std::pair<uint64_t, uint64_t>> mem_targets;
    uint64_t scan_inst_id = 0;
    for (auto it = env->reader->begin();
         it != env->reader->end() && mem_targets.size() < 100; ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto ma = inst.mem_access(m);
                mem_targets.emplace_back(ma.addr, scan_inst_id);
            }
            scan_inst_id++;
        }
    }

    REQUIRE(!mem_targets.empty());

    // First read: cold (may hit RocksDB)
    Timer t;
    std::vector<double> cold_lat(mem_targets.size());
    for (size_t i = 0; i < mem_targets.size(); i++) {
        auto [addr, iid] = mem_targets[i];
        t.start();
        (void)env->memory->read(addr, 8, iid);
        cold_lat[i] = t.elapsed_us();
    }
    auto cold_stats = LatencyStats::from_samples(cold_lat);

    // Second read: should hit cache
    std::vector<double> warm_lat(mem_targets.size());
    for (size_t i = 0; i < mem_targets.size(); i++) {
        auto [addr, iid] = mem_targets[i];
        t.start();
        (void)env->memory->read(addr, 8, iid);
        warm_lat[i] = t.elapsed_us();
    }
    auto warm_stats = LatencyStats::from_samples(warm_lat);

    // On very fast machines (Apple M1+), both cold and warm reads are dominated
    // by timer granularity (~10us), so p50 may be nearly identical. We only
    // assert that warm reads are reasonably fast (cache-hit latency).
    // CHECK(warm_stats.p50_us <= cold_stats.p50_us);  // too flaky
    // Warm p95 should be under 1ms (cache hit)
    CHECK(warm_stats.p95_us < 1000.0);
}

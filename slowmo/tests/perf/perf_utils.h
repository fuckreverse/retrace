/*
 * perf_utils.h — Shared utilities for Tenet performance regression tests.
 *
 * Provides:
 *   - Timer            : high-resolution wall-clock timer (ms / us)
 *   - LatencyStats     : min/mean/p50/p95/p99/max from a sample vector
 *   - PerfCheck        : threshold assertion helpers (env-overridable)
 *   - gen_linear_trace : generate N sequential-add instructions
 *   - gen_memory_trace : generate N load/store instructions
 *   - gen_branchy_trace: generate N instructions with conditional branches
 *
 * All thresholds default to ~1/10 of typical M1 performance to avoid CI
 * flakiness.  Override any threshold via environment variable, e.g.:
 *   TENET_PERF_IO_MBPS_MIN=200 ctest -R perf
 *
 * Usage:
 *   #include "perf/perf_utils.h"
 *   using namespace tenet::test::perf;
 *
 *   TEST_CASE("IO scan throughput", "[perf][io]") {
 *       auto env = make_env(gen_linear_trace(100000), "perf_io");
 *       Timer t; t.start();
 *       // ... scan trace ...
 *       PERF_CHECK_MBPS(t.elapsed_ms(), env->reader->file_size(), 50);
 *   }
 */
#ifndef TENET_TEST_PERF_UTILS_H
#define TENET_TEST_PERF_UTILS_H

#include "fixtures/trace_fixture.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace tenet::test::perf {

// ═══════════════════════════════════════════════════════════════════════════════
// Timer
// ═══════════════════════════════════════════════════════════════════════════════

struct Timer {
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point start_;

    void start() { start_ = Clock::now(); }

    double elapsed_ms() const {
        return std::chrono::duration<double, std::milli>(Clock::now() - start_).count();
    }

    double elapsed_us() const {
        return std::chrono::duration<double, std::micro>(Clock::now() - start_).count();
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// LatencyStats
// ═══════════════════════════════════════════════════════════════════════════════

struct LatencyStats {
    double min_us = 0;
    double max_us = 0;
    double mean_us = 0;
    double p50_us = 0;
    double p95_us = 0;
    double p99_us = 0;
    uint64_t samples = 0;

    static LatencyStats from_samples(std::vector<double>& latencies) {
        LatencyStats s;
        if (latencies.empty()) return s;

        std::sort(latencies.begin(), latencies.end());
        s.samples = latencies.size();
        s.min_us = latencies.front();
        s.max_us = latencies.back();

        double sum = 0;
        for (double v : latencies) sum += v;
        s.mean_us = sum / latencies.size();

        auto pct = [&](double p) -> double {
            size_t idx = static_cast<size_t>(p * (latencies.size() - 1));
            return latencies[idx];
        };
        s.p50_us = pct(0.50);
        s.p95_us = pct(0.95);
        s.p99_us = pct(0.99);
        return s;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Threshold helpers — env-overridable to avoid CI flakiness
// ═══════════════════════════════════════════════════════════════════════════════

/// Read an env var as double; return default if unset or unparseable.
inline double env_d(const char* name, double default_val) {
    const char* v = std::getenv(name);
    if (!v) return default_val;
    char* end = nullptr;
    double d = std::strtod(v, &end);
    if (end == v) return default_val;  // parse failed
    return d;
}

/// Assert throughput (MB/s) meets minimum threshold.
/// `elapsed_ms` is the measured time, `bytes` is the data processed.
#define PERF_CHECK_MBPS(elapsed_ms, bytes, min_mbps)                          \
    do {                                                                       \
        double _actual = (bytes) / (1024.0 * 1024.0) / ((elapsed_ms) / 1000.0); \
        double _min = tenet::test::perf::env_d("TENET_PERF_IO_MBPS_MIN",      \
                                                  (min_mbps));                 \
        INFO("throughput: " << _actual << " MB/s (min=" << _min                \
            << "), elapsed=" << (elapsed_ms) << " ms, bytes=" << (bytes));     \
        CHECK(_actual >= _min);                                                \
    } while (0)

/// Assert throughput (Millions of instructions / sec) meets minimum threshold.
#define PERF_CHECK_MINST(elapsed_ms, inst_count, min_minst)                    \
    do {                                                                       \
        double _actual = ((inst_count) / 1e6) / ((elapsed_ms) / 1000.0);      \
        double _min = tenet::test::perf::env_d("TENET_PERF_MINST_MIN",        \
                                                  (min_minst));                \
        INFO("throughput: " << _actual << " Minst/s (min=" << _min             \
            << "), elapsed=" << (elapsed_ms) << " ms, insts=" << (inst_count)); \
        CHECK(_actual >= _min);                                                \
    } while (0)

/// Assert elapsed time (ms) does not exceed maximum threshold.
#define PERF_CHECK_MAX_MS(elapsed_ms, max_ms)                                  \
    do {                                                                       \
        double _max = tenet::test::perf::env_d("TENET_PERF_MAX_MS_OVERRIDE",   \
                                                  (max_ms));                   \
        INFO("elapsed: " << (elapsed_ms) << " ms (max=" << _max << ")");       \
        CHECK((elapsed_ms) <= _max);                                           \
    } while (0)

/// Assert p95 latency (us) does not exceed maximum threshold.
#define PERF_CHECK_P95_US(stats, max_us)                                       \
    do {                                                                       \
        double _max = tenet::test::perf::env_d("TENET_PERF_P95_US_OVERRIDE",   \
                                                  (max_us));                   \
        INFO("p95 latency: " << (stats).p95_us << " us (max=" << _max          \
            << "), p50=" << (stats).p50_us << " us, samples="                  \
            << (stats).samples);                                               \
        CHECK((stats).p95_us <= _max);                                         \
    } while (0)

// ═══════════════════════════════════════════════════════════════════════════════
// Trace generators — produce moderate-scale traces for perf testing
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate `count` sequential ADD instructions (minimal per-record overhead).
/// Benchmarks: IO scan throughput, raw record parsing speed.
inline void gen_linear_trace(TraceWriter& tw, uint64_t count) {
    tw.anchor_interval = 4096;
    tw.module_name = "perf_linear";
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pc = 0x1000 + (i % 65536) * 4;
        tw.emit(ms, pc, enc::add_imm(0, 0, 1),
                {{0, i + 1}, {33, tw.rt(pc + 4)}}, {});
    }
    tw.emit_anchor(ms);
}

/// Generate `count` load/store instructions (every inst has memory access).
/// Benchmarks: MemoryModel build, XRef build with memory.
inline void gen_memory_trace(TraceWriter& tw, uint64_t count) {
    tw.anchor_interval = 4096;
    tw.module_name = "perf_memory";
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pc = 0x1000 + (i % 1024) * 4;
        uint64_t addr = data_base + (i % 8192) * 8;
        uint64_t val = i * 0x1337;
        tw.emit(ms, pc, enc::str_imm(0, 10, (int16_t)((i % 1024) * 8)),
                {{0, val}, {33, tw.rt(pc + 4)}},
                {{2, 8, addr, val}});
    }
    tw.emit_anchor(ms);
}

/// Generate `count` instructions with conditional branches (many basic blocks).
/// Benchmarks: CFGPass construction, LoopPass detection.
inline void gen_branchy_trace(TraceWriter& tw, uint64_t count) {
    tw.anchor_interval = 4096;
    tw.module_name = "perf_branchy";
    tw.write_header(0x200000);
    MachineState ms;
    ms.sp() = 0x16F000000ULL;

    const int NUM_BLOCKS = 200;
    uint64_t total = 0;
    while (total < count) {
        uint64_t block_id = (total * 6364136223846793005ULL + 1) % NUM_BLOCKS;
        uint64_t bb_base = 0x1000 + block_id * 0x40;
        for (int j = 0; j < 4 && total < count; j++) {
            uint64_t pc = bb_base + j * 4;
            tw.emit(ms, pc, enc::add_imm(0, 0, 1),
                    {{0, total + 1}, {33, tw.rt(pc + 4)}}, {});
            total++;
        }
        if (total >= count) break;
        uint64_t next_block = ((block_id + 7) * 2654435761ULL) % NUM_BLOCKS;
        uint64_t target_pc = 0x1000 + next_block * 0x40;
        tw.emit(ms, bb_base + 16, enc::b((int32_t)(target_pc - (bb_base + 16))),
                {{33, tw.rt(target_pc)}}, {});
        total++;
    }
    tw.emit_anchor(ms);
}

/// Generate a taint chain: `count` instructions with dense inter-register deps.
/// Benchmarks: TaintPass / Roaring bitmap scaling.
inline void gen_taint_trace(TraceWriter& tw, uint64_t count) {
    tw.anchor_interval = 4096;
    tw.module_name = "perf_taint";
    tw.write_header();
    MachineState ms;
    ms.sp() = 0x16F000000ULL;

    // Initialize 10 registers with unique values
    for (int i = 0; i < 10; i++) {
        tw.emit(ms, 0x1000 + i * 4, enc::movz(i, (uint16_t)(i * 111)),
                {{(uint8_t)i, (uint64_t)(i * 111)}, {33, tw.rt(0x1004 + i * 4)}}, {});
    }

    // Mix registers densely
    uint64_t pc = 0x1100;
    uint64_t remaining = (count > 10) ? count - 10 : 0;
    for (uint64_t i = 0; i < remaining; i++) {
        int dst = (int)(i % 10);
        int src1 = (int)((i + 1) % 10);
        int src2 = (int)((i + 3) % 10);
        uint64_t val = ms.x(src1) ^ ms.x(src2);
        ms.gpr[dst] = val;
        tw.emit(ms, pc, enc::eor_reg(dst, src1, src2),
                {{(uint8_t)dst, val}, {33, tw.rt(pc + 4)}}, {});
        pc = (pc + 4 - 0x1100) % 0x2000 + 0x1100;
    }
    tw.emit_anchor(ms);
}

/// Generate a call-chain trace: `count` instructions with function calls.
/// Benchmarks: FunctionPass, CallGraphPass.
inline void gen_calls_trace(TraceWriter& tw, uint64_t count) {
    tw.anchor_interval = 4096;
    tw.module_name = "perf_calls";
    tw.write_header(0x200000);
    MachineState ms;
    ms.sp() = 0x16F000000ULL;
    ms.fp() = ms.sp();

    const int DEPTH = 20;
    uint64_t total = 0;
    while (total < count) {
        for (int d = 0; d < DEPTH && total < count; d++) {
            uint64_t fn_base = 0x1000 + d * 0x20;
            ms.sp() -= 16;
            tw.emit(ms, fn_base, enc::stp_pre(29, 30, 31, -2),
                    {{31, ms.sp()}, {33, tw.rt(fn_base + 4)}},
                    {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
            total++;
            if (total >= count) break;
            tw.emit(ms, fn_base + 4, enc::mov_reg(29, 31),
                    {{29, ms.sp()}, {33, tw.rt(fn_base + 8)}}, {});
            total++;
            if (total >= count) break;
            tw.emit(ms, fn_base + 8, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(fn_base + 12)}}, {});
            total++;
            if (total >= count) break;
            uint64_t next_fn = 0x1000 + (d + 1) * 0x20;
            tw.emit(ms, fn_base + 12, enc::bl((int32_t)(next_fn - (fn_base + 12))),
                    {{30, tw.rt(fn_base + 16)}, {33, tw.rt(next_fn)}}, {});
            total++;
        }
        for (int d = DEPTH - 1; d >= 0 && total < count; d--) {
            uint64_t fn_base = 0x1000 + d * 0x20;
            ms.sp() += 16;
            tw.emit(ms, fn_base + 16, enc::ldp_post(29, 30, 31, 2),
                    {{29, ms.fp()}, {30, ms.lr()}, {31, ms.sp()},
                     {33, tw.rt(fn_base + 20)}},
                    {{1, 8, ms.sp() - 16, ms.fp()},
                     {1, 8, ms.sp() - 8, ms.lr()}});
            total++;
            if (total >= count) break;
            tw.emit(ms, fn_base + 20, enc::ret(),
                    {{33, tw.rt(fn_base - 0x20 + 16)}}, {});
            total++;
        }
    }
    tw.emit_anchor(ms);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Convenience: make_env with a generator + count
// ═══════════════════════════════════════════════════════════════════════════════

/// Wrap a generator function into the lambda expected by make_env.
inline std::function<void(TraceWriter&)> wrap_gen(
        void (*gen)(TraceWriter&, uint64_t), uint64_t count) {
    return [=](TraceWriter& tw) { gen(tw, count); };
}

} // namespace tenet::test::perf

#endif // TENET_TEST_PERF_UTILS_H

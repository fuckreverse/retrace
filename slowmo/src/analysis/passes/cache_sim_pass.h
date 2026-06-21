#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>

namespace tenet {

// ─── Cache geometry ────────────────────────────────────────────────────────

/// Describes a single cache level (e.g. L1D, L2).
struct CacheLevel {
    std::string name;        ///< "L1D", "L2", "L3"
    uint32_t size_kb;        ///< Total capacity in KiB
    uint32_t line_size;      ///< Cache line size in bytes (typically 64)
    uint32_t associativity;  ///< Set associativity (1=direct, 0=fully-assoc)
    bool write_allocate;     ///< True: on write-miss, allocate a line
};

/// Default cache geometry: Apple M1-like (L1D 128KB/8-way, L2 12MB/12-way).
inline std::vector<CacheLevel> default_apple_m1_cache() {
    return {
        {"L1D",  128,  64,  8,  true},
        {"L2",   12288, 64, 12, true},
    };
}

/// Cache replacement policy.
enum class ReplacementPolicy {
    LRU,    ///< Least-Recently Used (default)
    PLRU,   ///< Pseudo-LRU (tree-based, cheaper than true LRU)
    RAND,   ///< Random eviction
};

// ─── Configuration ─────────────────────────────────────────────────────────

struct CacheSimConfig {
    /// Cache hierarchy to simulate.
    std::vector<CacheLevel> levels = default_apple_m1_cache();

    /// Replacement policy.
    ReplacementPolicy policy = ReplacementPolicy::LRU;

    /// If non-zero, restrict simulation to this inst_id range.
    uint64_t start_inst_id = 0;
    uint64_t end_inst_id   = UINT64_MAX;

    /// Whether to simulate instruction fetch misses (I-cache) in addition to D-cache.
    bool simulate_icache = false;

    /// Generate per-function miss statistics (requires FunctionPass).
    bool per_function_stats = true;

    /// Detect potential cache timing side-channels (high miss variance across calls).
    bool detect_timing_sidechannel = true;

    /// Minimum number of calls to a function before evaluating timing side-channel.
    uint32_t min_calls_for_sidechannel = 4;

    /// Coefficient of variation threshold above which a function is flagged
    /// as a potential cache timing side-channel.
    float sidechannel_cv_threshold = 0.25f;
};

// ─── Result types ──────────────────────────────────────────────────────────

/// Per-level statistics for a single cache level.
struct CacheLevelStats {
    std::string name;
    uint64_t total_accesses = 0;  ///< Total read+write accesses presented to this level
    uint64_t hits           = 0;
    uint64_t misses         = 0;
    uint64_t read_accesses  = 0;
    uint64_t write_accesses = 0;
    uint64_t read_hits      = 0;
    uint64_t write_hits     = 0;
    uint64_t evictions      = 0;

    double miss_rate() const {
        return total_accesses ? double(misses) / double(total_accesses) : 0.0;
    }
    double hit_rate() const { return 1.0 - miss_rate(); }
};

/// Per-function cache statistics (one entry per observed function entry PC).
struct FunctionCacheStats {
    uint64_t entry_pc;
    std::string name;
    uint64_t total_calls;

    /// Per-invocation miss counts for L1D (one entry per call).
    std::vector<uint64_t> l1d_misses_per_call;

    double mean_l1d_misses() const;
    double stddev_l1d_misses() const;
    /// Coefficient of variation (stddev / mean). High = timing variance.
    double cv_l1d_misses() const;
    uint64_t max_l1d_misses() const;
    uint64_t min_l1d_misses() const;
};

/// A potential cache timing side-channel flag.
struct TimingSidechannel {
    uint64_t entry_pc;
    std::string function_name;
    double cv;                   ///< Coefficient of variation
    uint64_t min_misses;
    uint64_t max_misses;
    uint64_t total_calls;
    std::string reason;          ///< Human-readable description
};

/// Access pattern classification for diagnostic insight.
enum class AccessPattern {
    Sequential,  ///< Stride-1 sequential (cache-friendly)
    Strided,     ///< Fixed stride > 1
    Random,      ///< No discernible stride (cache-hostile)
    Repeated,    ///< Same address accessed repeatedly
};

/// Hottest cache lines (those evicted or missed most).
struct HotCacheLine {
    uint64_t addr;     ///< Cache-line-aligned address
    uint64_t misses;   ///< Times this line caused a miss
    uint64_t hits;     ///< Times this line was a hit
};

/// Full result of the CacheSimPass.
struct CacheSimResult {
    /// Per-level aggregate statistics.
    std::vector<CacheLevelStats> level_stats;

    /// Per-function statistics (populated when per_function_stats=true).
    std::vector<FunctionCacheStats> function_stats;

    /// Detected timing side-channel candidates.
    std::vector<TimingSidechannel> sidechannels;

    /// Top-N hottest (most-missed) cache lines.
    std::vector<HotCacheLine> hottest_lines;

    /// Total instruction count processed.
    uint64_t total_instructions = 0;

    /// Summary string (L1D miss rate, overall characterization).
    std::string summary() const;

    /// Overall L1D miss rate across all accesses.
    double overall_miss_rate() const {
        if (level_stats.empty()) return 0.0;
        return level_stats[0].miss_rate();
    }
};

// ─── CacheSimPass ──────────────────────────────────────────────────────────

/// Simulates a configurable set-associative cache hierarchy on the memory
/// access trace, producing per-level hit/miss statistics, per-function
/// timing variance, and cache timing side-channel detection.
///
/// The simulation uses an LRU (or PLRU/RAND) replacement policy and supports
/// both inclusive and exclusive hierarchies (currently inclusive).
///
/// Side-channel detection: for each function, collects per-invocation L1D miss
/// counts. If the coefficient of variation (CV = stddev/mean) exceeds the
/// configured threshold across multiple calls, the function is flagged as a
/// potential timing oracle — i.e., its cache behavior depends on input data.
///
/// Dependencies: optional "function" pass for per-function stats.
///
/// Result type: CacheSimResult
class CacheSimPass final : public AnalysisPass {
public:
    explicit CacheSimPass(CacheSimConfig cfg = {}) : cfg_(std::move(cfg)) {}

    std::string_view name() const override { return "cache_sim"; }
    std::string_view description() const override {
        return "Set-associative cache simulation: miss rates, hot lines, timing side-channel detection";
    }

    std::vector<std::string_view> dependencies() const override {
        // function pass is optional — we check if it ran
        return {};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }

private:
    CacheSimConfig cfg_;
};

}  // namespace tenet

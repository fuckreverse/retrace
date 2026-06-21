#include "cache_sim_pass.h"

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "analysis/passes/function_pass.h"
#include "io/trace_reader.h"
#include "core/register_file.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <cassert>
#include <fmt/core.h>

namespace tenet {

// ─── FunctionCacheStats helpers ──────────────────────────────────────────

double FunctionCacheStats::mean_l1d_misses() const {
    if (l1d_misses_per_call.empty()) return 0.0;
    double sum = 0;
    for (auto v : l1d_misses_per_call) sum += static_cast<double>(v);
    return sum / static_cast<double>(l1d_misses_per_call.size());
}

double FunctionCacheStats::stddev_l1d_misses() const {
    if (l1d_misses_per_call.size() < 2) return 0.0;
    double m = mean_l1d_misses();
    double sq = 0;
    for (auto v : l1d_misses_per_call) {
        double d = static_cast<double>(v) - m;
        sq += d * d;
    }
    return std::sqrt(sq / static_cast<double>(l1d_misses_per_call.size() - 1));
}

double FunctionCacheStats::cv_l1d_misses() const {
    double m = mean_l1d_misses();
    if (m < 1.0) return 0.0;
    return stddev_l1d_misses() / m;
}

uint64_t FunctionCacheStats::max_l1d_misses() const {
    if (l1d_misses_per_call.empty()) return 0;
    return *std::max_element(l1d_misses_per_call.begin(), l1d_misses_per_call.end());
}

uint64_t FunctionCacheStats::min_l1d_misses() const {
    if (l1d_misses_per_call.empty()) return 0;
    return *std::min_element(l1d_misses_per_call.begin(), l1d_misses_per_call.end());
}

// ─── CacheSimResult summary ───────────────────────────────────────────────

std::string CacheSimResult::summary() const {
    if (level_stats.empty()) return "no data";
    const auto& l1 = level_stats[0];
    double mr = l1.miss_rate() * 100.0;
    std::string s = fmt::format("L1D miss rate: {:.2f}% ({}/{} accesses)",
        mr, l1.misses, l1.total_accesses);
    if (!sidechannels.empty()) {
        s += fmt::format(", {} potential timing side-channels detected", sidechannels.size());
    }
    return s;
}

// ─── Internal set-associative cache model ────────────────────────────────

/// A single cache set (holds `ways` lines, each identified by tag).
struct CacheSet {
    struct Line {
        uint64_t tag   = ~0ULL;  // ~0 = invalid
        uint32_t lru   = 0;      // LRU counter (higher = more recently used)
        bool     valid = false;
    };

    std::vector<Line> lines;
    uint32_t lru_clock = 0;

    explicit CacheSet(uint32_t ways) : lines(ways) {}

    /// Access a tag. Returns true on hit.
    /// `is_write` and `write_allocate` control write-miss behavior.
    bool access(uint64_t tag, bool is_write, bool write_allocate,
                ReplacementPolicy policy) {
        // Check for hit
        for (auto& l : lines) {
            if (l.valid && l.tag == tag) {
                // Hit: update LRU
                if (policy == ReplacementPolicy::LRU) {
                    l.lru = ++lru_clock;
                }
                return true;
            }
        }
        // Miss
        if (is_write && !write_allocate) {
            return false;  // write-no-allocate: miss but don't install
        }
        // Allocate: find victim
        uint32_t victim_idx = 0;
        if (policy == ReplacementPolicy::LRU || policy == ReplacementPolicy::PLRU) {
            uint32_t min_lru = UINT32_MAX;
            for (uint32_t i = 0; i < static_cast<uint32_t>(lines.size()); i++) {
                if (!lines[i].valid) { victim_idx = i; break; }
                if (lines[i].lru < min_lru) {
                    min_lru = lines[i].lru;
                    victim_idx = i;
                }
            }
        } else {
            // RAND
            victim_idx = static_cast<uint32_t>(lru_clock) % static_cast<uint32_t>(lines.size());
        }
        lines[victim_idx].tag   = tag;
        lines[victim_idx].valid = true;
        lines[victim_idx].lru   = ++lru_clock;
        return false;
    }
};

/// One simulated cache level.
struct SimCache {
    uint32_t num_sets;
    uint32_t line_size;
    uint32_t associativity;
    bool     write_allocate;
    ReplacementPolicy policy;
    std::vector<CacheSet> sets;

    // Line/miss tracking by cache-line address
    std::unordered_map<uint64_t, uint64_t> line_miss_count;
    std::unordered_map<uint64_t, uint64_t> line_hit_count;

    CacheLevelStats stats;
    std::string name;

    SimCache(const CacheLevel& cfg, ReplacementPolicy pol)
        : num_sets((cfg.size_kb * 1024) / (cfg.line_size * cfg.associativity))
        , line_size(cfg.line_size)
        , associativity(cfg.associativity)
        , write_allocate(cfg.write_allocate)
        , policy(pol)
    {
        if (num_sets == 0) num_sets = 1;
        sets.reserve(num_sets);
        for (uint32_t i = 0; i < num_sets; i++) {
            sets.emplace_back(cfg.associativity);
        }
        stats.name = cfg.name;
        name = cfg.name;
    }

    /// Present a single byte address to this cache level.
    /// Returns true if hit.
    bool access(uint64_t addr, bool is_write) {
        uint64_t line_addr = addr / line_size;
        uint64_t set_idx   = line_addr % num_sets;
        uint64_t tag       = line_addr / num_sets;

        stats.total_accesses++;
        if (is_write) stats.write_accesses++;
        else          stats.read_accesses++;

        bool hit = sets[set_idx].access(tag, is_write, write_allocate, policy);
        if (hit) {
            stats.hits++;
            if (is_write) stats.write_hits++;
            else          stats.read_hits++;
            line_hit_count[line_addr]++;
        } else {
            stats.misses++;
            line_miss_count[line_addr]++;
        }
        return hit;
    }
};

// ─── Collector ────────────────────────────────────────────────────────────

/// Trace collector that feeds memory accesses through the cache hierarchy.
class CacheSimCollector final : public TraceCollector {
public:
    explicit CacheSimCollector(const CacheSimConfig& cfg,
                               const FunctionResult* fn_result)
        : cfg_(cfg), fn_result_(fn_result)
    {
        // Build cache hierarchy
        for (const auto& lv : cfg_.levels) {
            hierarchy_.emplace_back(lv, cfg_.policy);
        }
    }

    std::string_view name() const override { return "cache_sim_collector"; }

    bool begin(uint64_t start, uint64_t end) override {
        (void)start; (void)end;
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        if (inst_id < cfg_.start_inst_id) return;
        if (inst_id >= cfg_.end_inst_id)  return;

        total_instructions_++;

        // Track function call context for per-function stats
        if (fn_result_ && cfg_.per_function_stats) {
            // Check if a call started or ended at this inst_id
            const CallEvent* ce = fn_result_->call_at(inst_id);
            if (ce) {
                // Entering a function call: push frame
                call_stack_.push_back({ce->target_pc, ce->call_inst_id, 0ULL});
            }
            // Check return
            const CallEvent* re = fn_result_->return_at(inst_id);
            if (re && !call_stack_.empty()) {
                auto& top = call_stack_.back();
                // Record this invocation's miss count
                auto& fstats = func_stats_[top.entry_pc];
                fstats.entry_pc = top.entry_pc;
                fstats.l1d_misses_per_call.push_back(top.l1d_misses_in_call);
                call_stack_.pop_back();
            }
        }

        // Simulate I-cache access if enabled
        if (cfg_.simulate_icache) {
            simulate_access(inst.pc, false);
        }

        // Simulate D-cache accesses from memory operands
        for (uint8_t i = 0; i < inst.mem_access_count; i++) {
            auto m = inst.mem_access(i);
            // mem_type bit 1 = write, bit 0 = read
            bool is_write = (m.type & 0x02) != 0;
            uint16_t sz = m.size == 0 ? 1 : m.size;

            // Simulate each accessed cache line (one access per line touched)
            uint64_t first_line = m.addr / (hierarchy_.empty() ? 64 : hierarchy_[0].line_size);
            uint64_t last_line  = (m.addr + sz - 1) / (hierarchy_.empty() ? 64 : hierarchy_[0].line_size);
            for (uint64_t ln = first_line; ln <= last_line; ln++) {
                uint64_t line_byte_addr = ln * (hierarchy_.empty() ? 64 : hierarchy_[0].line_size);
                simulate_access(line_byte_addr, is_write);
            }
        }
    }

    void end() override {}

    // ─── Results ──────────────────────────────────────────────────────

    /// Build final result from simulation state.
    CacheSimResult build_result(const CacheSimConfig& cfg) {
        CacheSimResult r;
        r.total_instructions = total_instructions_;

        for (auto& cache : hierarchy_) {
            r.level_stats.push_back(cache.stats);
        }

        // Per-function stats
        if (cfg.per_function_stats) {
            for (auto& [pc, fs] : func_stats_) {
                if (fs.l1d_misses_per_call.empty()) continue;
                fs.total_calls = fs.l1d_misses_per_call.size();
                if (fn_result_) {
                    auto it = fn_result_->functions.find(pc);
                    if (it != fn_result_->functions.end()) {
                        fs.name = it->second.name;
                    }
                }
                if (fs.name.empty()) {
                    fs.name = fmt::format("sub_{:X}", pc);
                }
                r.function_stats.push_back(std::move(fs));
            }
            // Sort by mean L1D misses descending (hottest first)
            std::sort(r.function_stats.begin(), r.function_stats.end(),
                [](const FunctionCacheStats& a, const FunctionCacheStats& b) {
                    return a.mean_l1d_misses() > b.mean_l1d_misses();
                });
        }

        // Side-channel detection
        if (cfg.detect_timing_sidechannel) {
            for (auto& fs : r.function_stats) {
                if (fs.total_calls < cfg.min_calls_for_sidechannel) continue;
                double cv = fs.cv_l1d_misses();
                if (cv > cfg.sidechannel_cv_threshold) {
                    TimingSidechannel sc;
                    sc.entry_pc      = fs.entry_pc;
                    sc.function_name = fs.name;
                    sc.cv            = cv;
                    sc.min_misses    = fs.min_l1d_misses();
                    sc.max_misses    = fs.max_l1d_misses();
                    sc.total_calls   = fs.total_calls;
                    sc.reason = fmt::format(
                        "L1D miss CV={:.2f} across {} calls ({} - {} misses). "
                        "Cache behavior depends on input data — timing oracle risk.",
                        cv, fs.total_calls, sc.min_misses, sc.max_misses);
                    r.sidechannels.push_back(std::move(sc));
                }
            }
            // Sort by CV descending
            std::sort(r.sidechannels.begin(), r.sidechannels.end(),
                [](const TimingSidechannel& a, const TimingSidechannel& b) {
                    return a.cv > b.cv;
                });
        }

        // Hottest cache lines (from L1D, if present)
        if (!hierarchy_.empty()) {
            const auto& l1 = hierarchy_[0];
            // Collect all lines with >0 misses
            std::vector<HotCacheLine> hot_lines;
            hot_lines.reserve(l1.line_miss_count.size());
            for (const auto& [line_addr, miss_ct] : l1.line_miss_count) {
                HotCacheLine hl;
                hl.addr   = line_addr * l1.line_size;
                hl.misses = miss_ct;
                auto hit_it = l1.line_hit_count.find(line_addr);
                hl.hits = (hit_it != l1.line_hit_count.end()) ? hit_it->second : 0;
                hot_lines.push_back(hl);
            }
            // Partial sort: keep top 100
            size_t n = std::min(hot_lines.size(), size_t(100));
            std::partial_sort(hot_lines.begin(), hot_lines.begin() + static_cast<ptrdiff_t>(n),
                              hot_lines.end(),
                              [](const HotCacheLine& a, const HotCacheLine& b) {
                                  return a.misses > b.misses;
                              });
            hot_lines.resize(n);
            r.hottest_lines = std::move(hot_lines);
        }

        return r;
    }

private:
    struct CallFrame {
        uint64_t entry_pc;
        uint64_t call_inst_id;
        uint64_t l1d_misses_in_call;
    };

    void simulate_access(uint64_t addr, bool is_write) {
        bool miss = false;
        for (size_t lvl = 0; lvl < hierarchy_.size(); lvl++) {
            bool hit = hierarchy_[lvl].access(addr, is_write);
            if (hit) { miss = false; break; }
            miss = true;
        }
        // Track per-function L1D misses (outermost active frame)
        if (miss && !hierarchy_.empty() && cfg_.per_function_stats
                && !call_stack_.empty()) {
            call_stack_.back().l1d_misses_in_call++;
        }
    }

    const CacheSimConfig& cfg_;
    const FunctionResult* fn_result_;
    std::vector<SimCache> hierarchy_;
    std::vector<CallFrame> call_stack_;
    std::unordered_map<uint64_t, FunctionCacheStats> func_stats_;
    uint64_t total_instructions_ = 0;
};

// ─── CacheSimPass::run ───────────────────────────────────────────────────

PassResult CacheSimPass::run(PassContext& ctx) {
    if (cfg_.levels.empty()) {
        return PassResult::failed("CacheSimPass: no cache levels configured");
    }

    // Try to get function pass result for per-function stats
    const FunctionResult* fn_result = nullptr;
    if (cfg_.per_function_stats) {
        try {
            const auto& fn_raw = ctx.require_raw("function");
            if (fn_raw.ok()) {
                fn_result = &fn_raw.get<FunctionResult>();
            }
        } catch (...) {
            // FunctionPass not registered — skip per-function stats
        }
    }

    CacheSimCollector collector(cfg_, fn_result);

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run(cfg_.start_inst_id, cfg_.end_inst_id);
    } else {
        // Fallback: own scan
        auto& reader = ctx.reader();
        auto& index  = ctx.index();
        uint64_t inst_count = index.inst_count();

        TraceScanEngine own_engine(reader, inst_count, &index);
        own_engine.add_collector(&collector);
        own_engine.run(cfg_.start_inst_id, cfg_.end_inst_id);
    }

    CacheSimResult result = collector.build_result(cfg_);
    return PassResult::success(std::move(result));
}

}  // namespace tenet

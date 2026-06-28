#include "cache_sim_pass.h"

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "analysis/passes/function_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <cassert>
#include <cstring>
#include <fmt/core.h>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── CacheSimResult serialization helpers ─────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x43534D52 ("CSMR")
//   u32  version = 1
//   u64  total_instructions
//   u64  num_levels
//   for each CacheLevelStats:
//     u32  name_len; u8[] name
//     u64  total_accesses, hits, misses, read_accesses, write_accesses
//     u64  read_hits, write_hits, evictions
//   u64  num_function_stats
//   for each FunctionCacheStats:
//     u64  entry_pc
//     u32  name_len; u8[] name
//     u64  total_calls
//     u64  num_per_call; u64[] l1d_misses_per_call
//   u64  num_sidechannels
//   for each TimingSidechannel:
//     u64  entry_pc
//     u32  name_len; u8[] name
//     f64  cv
//     u64  min_misses, max_misses, total_calls
//     u32  reason_len; u8[] reason
//   u64  num_hottest_lines
//   for each HotCacheLine:
//     u64  addr, misses, hits

namespace {

static constexpr uint32_t CSMR_BLOB_MAGIC   = 0x43534D52u;  // "CSMR"
static constexpr uint32_t CSMR_BLOB_VERSION = 1u;

std::string cache_sim_serialize(const CacheSimResult& res) {
    size_t total = 4 + 4 + 8 + 8;  // magic, version, total_instructions, num_levels
    for (const auto& ls : res.level_stats) {
        total += 4 + ls.name.size() + 8 * 8;
    }
    total += 8;  // num_function_stats
    for (const auto& fs : res.function_stats) {
        total += 4 + fs.name.size() + 8 + 8 + 8 + fs.l1d_misses_per_call.size() * 8;
    }
    total += 8;  // num_sidechannels
    for (const auto& sc : res.sidechannels) {
        total += 8 + 4 + sc.function_name.size() + 8 + 8 + 8 + 8 + 4 + sc.reason.size();
    }
    total += 8 + res.hottest_lines.size() * (8 + 8 + 8);

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_f64 = [&](double   v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        std::memcpy(p, s.data(), s.size()); p += s.size();
    };

    write_u32(CSMR_BLOB_MAGIC);
    write_u32(CSMR_BLOB_VERSION);
    write_u64(res.total_instructions);
    write_u64(static_cast<uint64_t>(res.level_stats.size()));
    for (const auto& ls : res.level_stats) {
        write_str(ls.name);
        write_u64(ls.total_accesses);
        write_u64(ls.hits);
        write_u64(ls.misses);
        write_u64(ls.read_accesses);
        write_u64(ls.write_accesses);
        write_u64(ls.read_hits);
        write_u64(ls.write_hits);
        write_u64(ls.evictions);
    }
    write_u64(static_cast<uint64_t>(res.function_stats.size()));
    for (const auto& fs : res.function_stats) {
        write_u64(fs.entry_pc);
        write_str(fs.name);
        write_u64(fs.total_calls);
        write_u64(static_cast<uint64_t>(fs.l1d_misses_per_call.size()));
        for (uint64_t v : fs.l1d_misses_per_call) write_u64(v);
    }
    write_u64(static_cast<uint64_t>(res.sidechannels.size()));
    for (const auto& sc : res.sidechannels) {
        write_u64(sc.entry_pc);
        write_str(sc.function_name);
        write_f64(sc.cv);
        write_u64(sc.min_misses);
        write_u64(sc.max_misses);
        write_u64(sc.total_calls);
        write_str(sc.reason);
    }
    write_u64(static_cast<uint64_t>(res.hottest_lines.size()));
    for (const auto& hl : res.hottest_lines) {
        write_u64(hl.addr);
        write_u64(hl.misses);
        write_u64(hl.hits);
    }
    return buf;
}

bool cache_sim_deserialize(const std::string& blob, CacheSimResult& out) {
    if (blob.size() < 4 + 4 + 8 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_f64 = [&]() -> double   { double   v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (p + 4 > end) return false;
        uint32_t len = read_u32();
        if (p + len > end) return false;
        s.assign(p, len); p += len;
        return true;
    };

    if (read_u32() != CSMR_BLOB_MAGIC)   return false;
    if (read_u32() != CSMR_BLOB_VERSION) return false;

    out.total_instructions = read_u64();
    uint64_t n_levels = read_u64();
    out.level_stats.resize(static_cast<size_t>(n_levels));
    for (auto& ls : out.level_stats) {
        if (!read_str(ls.name)) return false;
        if (p + 8 * 8 > end) return false;
        ls.total_accesses  = read_u64();
        ls.hits            = read_u64();
        ls.misses          = read_u64();
        ls.read_accesses   = read_u64();
        ls.write_accesses  = read_u64();
        ls.read_hits       = read_u64();
        ls.write_hits      = read_u64();
        ls.evictions       = read_u64();
    }
    if (p + 8 > end) return false;
    uint64_t n_fs = read_u64();
    out.function_stats.resize(static_cast<size_t>(n_fs));
    for (auto& fs : out.function_stats) {
        if (p + 8 > end) return false;
        fs.entry_pc = read_u64();
        if (!read_str(fs.name)) return false;
        if (p + 8 + 8 > end) return false;
        fs.total_calls = read_u64();
        uint64_t n_mis = read_u64();
        if (p + n_mis * 8 > end) return false;
        fs.l1d_misses_per_call.resize(static_cast<size_t>(n_mis));
        for (auto& v : fs.l1d_misses_per_call) v = read_u64();
    }
    if (p + 8 > end) return false;
    uint64_t n_sc = read_u64();
    out.sidechannels.resize(static_cast<size_t>(n_sc));
    for (auto& sc : out.sidechannels) {
        if (p + 8 > end) return false;
        sc.entry_pc = read_u64();
        if (!read_str(sc.function_name)) return false;
        if (p + 8 + 8 + 8 + 8 > end) return false;
        sc.cv          = read_f64();
        sc.min_misses  = read_u64();
        sc.max_misses  = read_u64();
        sc.total_calls = read_u64();
        if (!read_str(sc.reason)) return false;
    }
    if (p + 8 > end) return false;
    uint64_t n_hl = read_u64();
    out.hottest_lines.resize(static_cast<size_t>(n_hl));
    for (auto& hl : out.hottest_lines) {
        if (p + 8 * 3 > end) return false;
        hl.addr   = read_u64();
        hl.misses = read_u64();
        hl.hits   = read_u64();
    }
    return true;
}

}  // anonymous namespace (cache_sim serialization)

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
    ankerl::unordered_dense::map<uint64_t, uint64_t> line_miss_count;
    ankerl::unordered_dense::map<uint64_t, uint64_t> line_hit_count;

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
        cached_line_size_ = hierarchy_.empty() ? 64 : hierarchy_[0].line_size;
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
            uint64_t first_line = m.addr / cached_line_size_;
            uint64_t last_line  = (m.addr + sz - 1) / cached_line_size_;
            for (uint64_t ln = first_line; ln <= last_line; ln++) {
                uint64_t line_byte_addr = ln * cached_line_size_;
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
    ankerl::unordered_dense::map<uint64_t, FunctionCacheStats> func_stats_;
    uint32_t cached_line_size_ = 64;
    uint64_t total_instructions_ = 0;
};

// ─── CacheSimPass::run ───────────────────────────────────────────────────

PassResult CacheSimPass::run(PassContext& ctx) {
    if (cfg_.levels.empty()) {
        return PassResult::failed("CacheSimPass: no cache levels configured");
    }

    auto& index = ctx.index();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    // Only cache when using the full trace with default start/end range,
    // since config parameters (level geometry, policy) affect results.
    bool is_default_range = (cfg_.start_inst_id == 0 && cfg_.end_inst_id == UINT64_MAX);
    if (ctx.range().is_full_trace() && is_default_range) {
        std::string blob;
        if (index.load_pass_blob("cache_sim", blob)) {
            CacheSimResult cached;
            if (cache_sim_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Cache sim: {} instructions, {} levels (from cache)",
                    cached.total_instructions, cached.level_stats.size()));
                return PassResult::success(std::move(cached));
            }
        }
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

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace() && is_default_range) {
        std::string blob = cache_sim_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("cache_sim", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet

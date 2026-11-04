#include "analysis/passes/memory/entropy_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/memory_model.h"
#include "common/entropy.h"
#include "common/memory_ranges.h"
#include <algorithm>
#include <array>
#include <cmath>

namespace tenet {
float EntropyPass::compute_entropy(const uint8_t* data, size_t len) {
    return shannon_entropy(data, len);
}
namespace {
using Histogram = std::array<uint32_t, 256>;
float entropy(const Histogram& h, uint32_t n) {
    if (!n) return 0;
    double sum = 0;
    for (auto c : h) if (c) sum += double(c) * std::log2(double(c));
    return static_cast<float>(std::log2(double(n)) - sum / n);
}
EntropyResult::Classification classify(float e, uint32_t n, uint32_t size) {
    if (n < 8) return EntropyResult::Unknown;
    if (e > 7.5f) return EntropyResult::Encrypted;
    if (e > 6.f) return EntropyResult::Compressed;
    if (e < 4.f) return EntropyResult::Plaintext;
    return size <= 64 ? EntropyResult::KeyMaterial : EntropyResult::Compressed;
}
}
PassResult EntropyPass::run(PassContext& ctx) {
    if (!cfg_.size || !cfg_.block_size || (cfg_.compute_timeline && !cfg_.timeline_interval) ||
        uint64_t(cfg_.size - 1) > UINT64_MAX - cfg_.addr)
        return PassResult::failed("Entropy requires a nonempty, non-overflowing region and nonzero intervals");
    const uint64_t working_bytes = uint64_t(cfg_.size) * (cfg_.compute_timeline ? 4 : 2) +
        ((uint64_t(cfg_.size) + cfg_.block_size - 1) / cfg_.block_size) * sizeof(EntropyBlock);
    if (ctx.memory_budget_bytes() && working_bytes > ctx.memory_budget_bytes())
        return PassResult::failed("Entropy region exceeds analysis memory budget");
    if (ctx.memory_pressure()) return PassResult::failed("Entropy RSS limit exceeded");
    auto& memory = ctx.memory();
    auto& reader = ctx.reader();
    const uint64_t at = cfg_.at_inst_id ? std::min(cfg_.at_inst_id, ctx.index().inst_count()) : ctx.index().inst_count();
    EntropyResult result;
    result.addr = cfg_.addr; result.region_size = cfg_.size;
    // One bulk historical reconstruction. Averaging page entropies would be
    // incorrect, and final-page statistics cannot answer historical queries.
    auto region = memory.read_region(cfg_.addr, cfg_.size, at);
    Histogram total{};
    for (uint32_t offset = 0; offset < cfg_.size;) {
        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        if (ctx.memory_pressure()) return PassResult::failed("Entropy RSS limit exceeded");
        const auto n = std::min(cfg_.block_size, cfg_.size - offset);
        Histogram h{}; uint32_t known = 0;
        for (uint32_t i = 0; i < n; ++i) if (region.known[offset + i]) {
            ++h[region.data[offset + i]]; ++total[region.data[offset + i]]; ++known;
        }
        result.blocks.push_back({offset, n, entropy(h, known), known == n});
        result.known_bytes += known;
        offset += n;
    }
    result.overall_entropy = entropy(total, result.known_bytes);
    result.classification = classify(result.overall_entropy, result.known_bytes, cfg_.size);
    if (cfg_.compute_timeline) {
        // Seed only the configure-time snapshot. Replay every intersecting
        // access, not just writes overlapping the first eight region bytes.
        auto initial = memory.read_region(cfg_.addr, cfg_.size, 0);
        auto data = std::move(initial.data);
        auto known = std::move(initial.known);
        Histogram h{}; uint32_t count = 0;
        for (uint32_t i = 0; i < cfg_.size; ++i) if (known[i]) { ++h[data[i]]; ++count; }
        uint64_t writes = 0, inst_id = 0, pending = UINT64_MAX;
        float previous = 0.f;
        auto sample = [&]() {
            if (pending == UINT64_MAX) return;
            const auto e = entropy(h, count);
            result.timeline.push_back({pending, e, count});
            if (previous > .01f && std::abs(e - previous) > 2.f)
                result.transitions.push_back({pending, previous, e, e - previous});
            previous = e; pending = UINT64_MAX;
        };
        auto update = [&](const MemAccessView& m, bool observation, bool old) {
            if (!m.size) return false;
            const auto last = MemoryRanges<int>::last_byte(m.addr, m.size);
            const auto lo = std::max(m.addr, cfg_.addr);
            const auto hi = std::min(last, cfg_.addr + cfg_.size - 1);
            if (lo > hi) return false;
            for (auto addr = lo;; ++addr) {
                const auto src = addr - m.addr;
                const auto dst = static_cast<size_t>(addr - cfg_.addr);
                if (src >= 16 && !observation && known[dst]) { --h[data[dst]]; known[dst] = false; --count; }
                if (src < 16 && (!observation || !known[dst])) {
                    const uint64_t value = src < 8 ? (old ? m.old_value : m.value) : (old ? m.old_value_hi : m.value_hi);
                    const auto byte = static_cast<uint8_t>(value >> (8 * (src % 8)));
                    if (known[dst]) --h[data[dst]];
                    else { known[dst] = true; ++count; }
                    data[dst] = byte; ++h[byte];
                }
                if (addr == hi) break;
            }
            return true;
        };
        auto tr = reader.create_thread_reader(2);
        for (auto it = reader.begin(tr); it != reader.end(tr) && inst_id <= at; ++it) {
            const auto rec = *it;
            if (rec.kind != RecordKind::Inst) continue;
            if ((inst_id & 4095) == 0) {
                if (ctx.cancelled()) return PassResult::failed("cancelled by user");
                if (ctx.memory_pressure()) return PassResult::failed("Entropy RSS limit exceeded");
                if (ctx.memory_budget_bytes() && working_bytes + result.timeline.capacity()*sizeof(EntropyTimelineEntry) +
                    result.transitions.capacity()*sizeof(EntropyResult::Transition) > ctx.memory_budget_bytes())
                    return PassResult::failed("Entropy timeline exceeds analysis memory budget");
            }
            const auto inst = rec.as_inst();
            // First observations are visible before this instruction in the
            // memory model. Defer the preceding sample until they are known.
            for (uint8_t i = 0; i < inst.mem_access_count; ++i) {
                const auto m = inst.mem_access(i);
                if ((m.type & 1) && !(m.type & 2)) update(m, true, false);
                if ((m.type & 2) && m.has_old_value) update(m, true, true);
            }
            sample();
            if (inst_id == at) break;
            bool touched = false;
            for (uint8_t i = 0; i < inst.mem_access_count; ++i) {
                const auto m = inst.mem_access(i);
                if (m.type & 2) touched |= update(m, false, false);
            }
            if (touched && ++writes % cfg_.timeline_interval == 0) pending = inst_id + 1;
            ++inst_id;
        }
        sample();
    }
    ctx.progress(1.f, "Entropy: complete (bulk snapshot + incremental histogram)");
    return PassResult::success(std::move(result));
}
} // namespace tenet

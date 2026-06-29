#include "analysis/passes/literal_search_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <algorithm>
#include <ankerl/unordered_dense.h>

namespace tenet {

PassResult LiteralSearchPass::run(PassContext& ctx) {
    if (cfg_.search_values.empty()) {
        return PassResult::skipped();
    }

    auto& reader = ctx.reader();
    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    LiteralSearchResult result;
    result.by_value.resize(cfg_.search_values.size());

    // ── Optimization: replace unordered_set + linear for(vi) with
    //    direct value → vector<index> maps for O(1) index lookup.
    //
    // Old: set.count(val) → for(vi=0..N) if(values[vi]==val)  → O(N) per hit
    // New: map[val] → indices                                  → O(1) per hit
    //
    // When searching 400+ crypto constants, this eliminates the O(400) inner loop.

    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> map_64;
    ankerl::unordered_dense::map<uint32_t, std::vector<size_t>> map_32;

    map_64.reserve(cfg_.search_values.size());
    for (size_t i = 0; i < cfg_.search_values.size(); i++) {
        map_64[cfg_.search_values[i]].push_back(i);
        if (cfg_.match_32bit) {
            uint32_t v32 = static_cast<uint32_t>(cfg_.search_values[i] & 0xFFFFFFFF);
            map_32[v32].push_back(i);
        }
    }

    ctx.progress(0.0f, "LiteralSearch: scanning trace for values...");

    const uint64_t progress_interval = std::max(total_insts / 100, uint64_t(1));
    uint64_t inst_id = 0;

    // Inline lambda to record a hit for all matching indices
    auto record_hit = [&](uint64_t pc, uint64_t val, uint64_t search_val,
                          size_t vi, LiteralHit::Source src,
                          uint8_t reg_or_size, uint64_t mem_addr) {
        LiteralHit hit;
        hit.inst_id = inst_id;
        hit.pc = pc;
        hit.matched_value = val;
        hit.search_value = search_val;
        hit.source = src;
        hit.reg_or_size = reg_or_size;
        hit.mem_addr = mem_addr;
        result.by_value[vi].push_back(result.hits.size());
        result.hits.push_back(hit);
    };

    reader.advise_sequential();

    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        inst_id++;

        auto inst = rec.as_inst();
        result.instructions_scanned++;

        // Search register diff values
        if (cfg_.search_reg_values) {
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                uint64_t val = diff.value;

                // O(1) lookup for 64-bit match
                auto it64 = map_64.find(val);
                if (it64 != map_64.end()) {
                    for (size_t vi : it64->second) {
                        record_hit(inst.pc, val, cfg_.search_values[vi],
                                   vi, LiteralHit::RegDiff, diff.index, 0);
                    }
                }
                // O(1) lookup for 32-bit truncated match
                else if (cfg_.match_32bit && (val >> 32) == 0) {
                    uint32_t val32 = static_cast<uint32_t>(val);
                    auto it32 = map_32.find(val32);
                    if (it32 != map_32.end()) {
                        for (size_t vi : it32->second) {
                            record_hit(inst.pc, val, cfg_.search_values[vi],
                                       vi, LiteralHit::RegDiff, diff.index, 0);
                        }
                    }
                }
            }
        }

        // Search memory write values
        if (cfg_.search_mem_values) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 0x02)) continue;  // Only writes

                uint64_t val = mem.value;

                auto it64 = map_64.find(val);
                if (it64 != map_64.end()) {
                    for (size_t vi : it64->second) {
                        record_hit(inst.pc, val, cfg_.search_values[vi],
                                   vi, LiteralHit::MemWrite,
                                   static_cast<uint8_t>(mem.size), mem.addr);
                    }
                } else if (cfg_.match_32bit && (val >> 32) == 0) {
                    uint32_t val32 = static_cast<uint32_t>(val);
                    auto it32 = map_32.find(val32);
                    if (it32 != map_32.end()) {
                        for (size_t vi : it32->second) {
                            record_hit(inst.pc, val, cfg_.search_values[vi],
                                       vi, LiteralHit::MemWrite,
                                       static_cast<uint8_t>(mem.size), mem.addr);
                        }
                    }
                }
            }
        }

        if (inst_id % progress_interval == 0) {
            ctx.progress(static_cast<float>(inst_id) / total_insts);
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    reader.advise_random();
    ctx.progress(1.0f, "LiteralSearch: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

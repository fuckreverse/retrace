#include "analysis/passes/slice_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>

namespace tenet {

PassResult SlicePass::run(PassContext& ctx) {
    // Require taint result
    const auto& taint = ctx.require<TaintResult>("taint");

    auto& reader = ctx.reader();
    auto& index = ctx.index();

    SliceResult result;
    result.target_inst_id = target_inst_id_;
    result.target_reg = target_reg_;

    // Work backward from target
    std::unordered_set<uint8_t> needed_regs;
    needed_regs.insert(target_reg_);

    // We need to scan backward through the trace.
    // Since TraceReader only supports forward iteration efficiently,
    // we'll use the index to jump to offsets and scan backward by
    // using offset_of + reading individual records.

    uint64_t current_id = target_inst_id_;
    uint64_t max_steps = 100000;  // Safety limit
    uint64_t steps = 0;

    while (current_id > 0 && steps < max_steps) {
        current_id--;
        steps++;

        uint64_t offset = index.offset_of(current_id, reader);
        auto rec = reader.record_at(offset);
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        // Check if this instruction writes any register we need
        bool contributes = false;
        std::vector<uint8_t> new_needed;

        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (needed_regs.count(diff.index) > 0) {
                // This instruction writes a needed register -> it's in the slice
                contributes = true;
                // Add its source registers to needed set
                for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                    if (i == j) continue;
                    auto src = inst.reg_diff(j);
                    if (needed_regs.count(src.index) == 0) {
                        new_needed.push_back(src.index);
                    }
                }
                break;  // Only track first match per instruction
            }
        }

        // Also check if this instruction reads from memory that was tainted
        // (memory sources in taint result)
        if (!contributes && taint.is_tainted(target_reg_)) {
            // Check if this instruction loads from a tainted memory address
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if ((mem.type & 2) == 0) {  // read
                    if (taint.is_memory_addr_tainted(mem.addr)) {
                        contributes = true;
                        break;
                    }
                }
            }
        }

        if (contributes) {
            result.slice_inst_ids.push_back(current_id);
            result.slice_set.insert(current_id);
            for (auto r : new_needed) {
                needed_regs.insert(r);
            }
        }

        // Stop if we've reached the beginning or no more needed regs
        if (needed_regs.empty()) break;
    }

    // Reverse so slice is in forward order (oldest first)
    std::reverse(result.slice_inst_ids.begin(), result.slice_inst_ids.end());

    ctx.progress(1.0f, fmt::format("Slice: {} instructions", result.slice_inst_ids.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

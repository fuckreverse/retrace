#include "analysis/passes/slice_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <algorithm>
#include <vector>

namespace tenet {

// ─── Compact per-instruction cache entry ──────────────────────────────────
// Only stores the bitmask of written registers (bit i ↔ GPR index i).
// Memory access info is carried separately via TaintResult.
struct CachedInst {
    uint64_t inst_id;
    uint64_t written_regs_mask;  // bit i = GPR i was written by reg_diff
};

PassResult SlicePass::run(PassContext& ctx) {
    // Require taint result
    const auto& taint = ctx.require<TaintResult>("taint");

    auto& reader = ctx.reader();
    auto& index = ctx.index();

    SliceResult result;
    result.target_inst_id = target_inst_id_;
    result.target_reg = target_reg_;

    constexpr uint64_t max_steps = 100000;  // Safety limit

    // ── Phase 1: Compute scan range ──────────────────────────────────────
    const uint64_t scan_start = (target_inst_id_ > max_steps)
                                    ? target_inst_id_ - max_steps
                                    : 0;
    const uint64_t scan_count = target_inst_id_ - scan_start;

    if (scan_count == 0) {
        ctx.progress(1.0f, "Slice: 0 instructions (empty range)");
        return PassResult::success(std::move(result));
    }

    // ── Phase 2: Forward scan — collect written-reg masks into buffer ────
    // Single sequential pass over mmap: O(N) with madvise(SEQUENTIAL).
    std::vector<CachedInst> buf;
    buf.reserve(scan_count);

    // Seek to scan_start
    auto [start_offset, start_seed_pc] = index.offset_of_with_pc(scan_start, reader);
    reader.advise_sequential();

    uint64_t inst_id = scan_start;
    for (auto it = TraceReader::Iterator(&reader, start_offset, start_seed_pc);
         it != reader.end() && inst_id < target_inst_id_;
         ++it)
    {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        // Build written-register bitmask from reg_diff entries
        uint64_t wmask = 0;
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            wmask |= 1ULL << inst.reg_diff(i).index;
        }

        buf.push_back({inst_id, wmask});
        inst_id++;
    }

    reader.advise_random();  // Restore default hint

    // ── Phase 3: Backward analysis over in-memory buffer ─────────────────
    // Pure memory iteration — no RocksDB / mmap random access.
    uint64_t needed_mask = 1ULL << target_reg_;

    for (auto rit = buf.rbegin(); rit != buf.rend(); ++rit) {
        const auto& ci = *rit;

        // Fast bitmask test: does this instruction write any needed register?
        uint64_t overlap = ci.written_regs_mask & needed_mask;
        bool contributes = (overlap != 0);

        if (contributes) {
            // All OTHER written regs of this instruction are potential sources.
            // (Conservative heuristic: any reg touched by the same instruction
            //  is treated as a source operand — same logic as original code.)
            uint64_t source_regs = ci.written_regs_mask & ~overlap;
            needed_mask |= source_regs;

            result.slice_inst_ids.push_back(ci.inst_id);
            result.slice_set.insert(ci.inst_id);
        }

        // Taint-based memory contribution check (same as original):
        // If target_reg is tainted and this instruction loads from tainted memory,
        // include it.  This path is rare so the extra work is acceptable.
        if (!contributes && taint.is_tainted(target_reg_)) {
            // We don't have memory access info in CachedInst (would bloat cache).
            // Re-fetch this single record only when the taint check fires.
            auto [off, spc] = index.offset_of_with_pc(ci.inst_id, reader);
            auto rec = reader.record_at(off, spc);
            if (rec.kind == RecordKind::Inst) {
                auto inst = rec.as_inst();
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto mem = inst.mem_access(m);
                    if ((mem.type & 2) == 0) {  // read
                        if (taint.is_memory_addr_tainted(mem.addr)) {
                            result.slice_inst_ids.push_back(ci.inst_id);
                            result.slice_set.insert(ci.inst_id);
                            break;
                        }
                    }
                }
            }
        }

        // Early exit if no more registers needed
        if (needed_mask == 0) break;
    }

    // Reverse so slice is in forward order (oldest first)
    std::reverse(result.slice_inst_ids.begin(), result.slice_inst_ids.end());

    ctx.progress(1.0f, fmt::format("Slice: {} instructions (scanned {} in buffer)",
                                   result.slice_inst_ids.size(), buf.size()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

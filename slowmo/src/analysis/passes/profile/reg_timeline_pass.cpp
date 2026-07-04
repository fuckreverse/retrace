#include "analysis/passes/profile/reg_timeline_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"

#include <algorithm>
#include <ankerl/unordered_dense.h>

namespace tenet {

namespace {

/// Linear scan implementation: walks every instruction in [start, end),
/// tracking the running register state so old_value/new_value pairs are
/// always accurate. This is the only viable strategy for "all registers"
/// mode (track_all == true), since every instruction may touch a different
/// register and there is no single inverted-index key to jump through.
PassResult run_linear_scan(PassContext& ctx, const RegTimelineConfig& cfg,
                            uint64_t start, uint64_t end, bool track_all) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const uint8_t target = cfg.target_reg;

    RegTimelineResult result;
    result.entries.reserve(track_all ? 65536 : 16384);

    ctx.progress(0.0f, "RegTimeline: scanning register diffs...");

    // ── Optimization: use nearest_anchor_before() to skip prefix scan ──
    //
    // Old approach: always scan from trace beginning to initialize current_regs.
    // New approach: if start > 0, use the anchor to restore register state,
    // then scan only from anchor position forward.
    //
    // This reduces startup from O(start_inst_id) to O(256) (sparse interval).

    uint64_t current_regs[34] = {};
    uint64_t scan_from_offset = 0;
    uint64_t scan_from_inst_id = 0;

    if (start > 256) {
        // Find the nearest anchor before our start point.
        // After restoring anchor state, we still need to apply reg_diffs
        // from anchor to start to get accurate old_values.
        auto anchor_info = index.nearest_anchor_before(start);
        if (anchor_info.file_offset > 0) {
            // Restore register state from anchor
            auto anchor_rec = reader.record_at(anchor_info.file_offset);
            if (anchor_rec.kind == RecordKind::Anchor) {
                auto anchor = anchor_rec.as_anchor(reader.header().num_gpr);
                for (uint32_t i = 0; i < reader.header().num_gpr && i < 34; i++) {
                    current_regs[i] = anchor.gpr_values[i];
                }
            }
            scan_from_offset = anchor_info.file_offset;
            scan_from_inst_id = anchor_info.inst_id;
        }
    }

    const uint64_t progress_interval = std::max((end - start) / 100, uint64_t(1));
    uint64_t inst_id = scan_from_inst_id;

    // Construct iterator from the anchor position (or beginning)
    auto it_start = (scan_from_offset > 0)
        ? TraceReader::Iterator(&reader, scan_from_offset)
        : reader.begin();

    // Set madvise hint for sequential scan
    reader.advise_sequential();

    for (auto it = it_start; it != reader.end(); ++it) {
        auto rec = *it;

        // Still process anchors for state recovery
        if (rec.kind == RecordKind::Anchor) {
            auto anchor = rec.as_anchor(reader.header().num_gpr);
            for (uint32_t i = 0; i < reader.header().num_gpr && i < 34; i++) {
                current_regs[i] = anchor.gpr_values[i];
            }
            continue;
        }

        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        inst_id++;

        if (inst_id < start) {
            // Still need to track state for accurate old_values
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index < 34) {
                    current_regs[diff.index] = diff.value;
                }
            }
            continue;
        }
        if (inst_id > end) break;

        // Process reg diffs
        for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
            auto diff = inst.reg_diff(d);
            if (diff.index >= 34) continue;

            if (track_all || diff.index == target) {
                RegTimelineEntry entry;
                entry.inst_id = inst_id;
                entry.pc = inst.pc;
                entry.reg_index = diff.index;
                entry.old_value = current_regs[diff.index];
                entry.new_value = diff.value;

                result.entries.push_back(entry);
                result.write_counts[diff.index]++;
                result.total_writes++;

                if (cfg.max_entries > 0 && result.entries.size() >= cfg.max_entries) {
                    goto done;
                }
            }
            current_regs[diff.index] = diff.value;
        }

        if ((inst_id - start) % progress_interval == 0) {
            ctx.progress(static_cast<float>(inst_id - start) / (end - start));
            if (ctx.cancelled()) goto done;
        }
    }

done:
    reader.advise_random();
    if (ctx.cancelled()) {
        return PassResult::failed("RegTimeline: cancelled by user");
    }

    // Build unique values for single-reg mode
    if (!track_all && target < 34) {
        ankerl::unordered_dense::set<uint64_t> unique_set;
        for (const auto& e : result.entries) {
            unique_set.insert(e.new_value);
        }
        result.unique_values.assign(unique_set.begin(), unique_set.end());
        std::sort(result.unique_values.begin(), result.unique_values.end());
    }

    ctx.progress(1.0f, "RegTimeline: complete");
    return PassResult::success(std::move(result));
}

/// Single-register fast path: uses the REG_WRITES inverted index
/// (TraceIndex::find_last_writer_of) to jump directly from one write to the
/// previous one, in O(K log N) where K is the number of times the register
/// was actually written — instead of O(N) linear scan over every
/// instruction in the range.
///
/// This is a large win for registers that are written sparsely relative to
/// the trace size (e.g. a loop counter or accumulator register touched a
/// few hundred times across a multi-million-instruction trace): the linear
/// scan pays O(N) regardless, while this pays O(K log N).
///
/// Falls back transparently: if the REG_WRITES column family is absent
/// (old index built before it was introduced), find_last_writer_of()
/// itself falls back to a linear scan per call, so correctness is
/// preserved (just without the speedup) — see index_builder.cpp.
PassResult run_indexed_single_reg(PassContext& ctx, const RegTimelineConfig& cfg,
                                   uint64_t start, uint64_t end) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const uint8_t target = cfg.target_reg;

    ctx.progress(0.0f, "RegTimeline: walking REG_WRITES index...");

    // Walk backwards from `end`, collecting write points, then reverse.
    // We stop once find_last_writer_of() returns 0 (no earlier writer) or
    // the writer falls before `start`.
    struct RawWrite { uint64_t inst_id; uint64_t pc; uint64_t new_value; };
    std::vector<RawWrite> writes;

    // find_last_writer_of(reg, before_id, ...) finds the largest writer with
    // inst_id STRICTLY LESS than before_id. The caller's range [start, end]
    // is inclusive of `end` (matches the linear-scan path's `inst_id <= end`
    // semantics), so seed the cursor at end+1 to make the first lookup able
    // to return a writer at exactly inst_id == end.
    uint64_t cursor = (end < UINT64_MAX) ? end + 1 : end;
    const uint64_t total_span = (end > start) ? (end - start) : 1;
    uint64_t iterations = 0;

    // NOTE on the inst_id==0 ambiguity: find_last_writer_of() returns 0 both
    // to mean "no earlier writer exists" AND as a legitimately valid inst_id
    // (the very first instruction in the trace, when trace indexing is
    // 0-based). We disambiguate below by explicitly checking whether
    // instruction 0 itself wrote `target` before treating a 0 return as
    // "search exhausted".
    bool checked_inst_zero = (start > 0);  // no need to special-case if start > 0
    while (cursor > start) {
        uint64_t writer_id = index.find_last_writer_of(target, cursor, reader);

        if (writer_id == 0) {
            // Ambiguous: could be "not found" or "found at inst_id 0".
            // Resolve by directly inspecting instruction 0 (only once).
            if (!checked_inst_zero) {
                checked_inst_zero = true;
                auto off0 = index.offset_of_with_pc(0, reader);
                auto rec0 = reader.record_at(off0.offset, off0.seed_pc);
                if (rec0.kind == RecordKind::Inst) {
                    auto inst0 = rec0.as_inst();
                    for (uint8_t d = 0; d < inst0.reg_diff_count; d++) {
                        auto diff = inst0.reg_diff(d);
                        if (diff.index == target) {
                            writes.push_back({0, inst0.pc, diff.value});
                            break;
                        }
                    }
                }
            }
            break;
        }
        if (writer_id < start) break;

        // Resolve the instruction at writer_id to get its PC and the new
        // value written to `target`.
        auto off = index.offset_of_with_pc(writer_id, reader);
        auto rec = reader.record_at(off.offset, off.seed_pc);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index == target) {
                    writes.push_back({writer_id, inst.pc, diff.value});
                    break;
                }
            }
        }

        cursor = writer_id;  // next lookup: strictly before this write

        if (cfg.max_entries > 0 && writes.size() >= cfg.max_entries) break;

        // Progress + cancellation: report based on how far the cursor has
        // moved through [start, end), not iteration count (K is unknown
        // up-front for a sparse register).
        if ((++iterations & 0xFFu) == 0) {
            float pct = 1.0f - static_cast<float>(cursor - start) / static_cast<float>(total_span);
            ctx.progress(std::clamp(pct, 0.0f, 0.99f));
            if (ctx.cancelled()) {
                return PassResult::failed("RegTimeline: cancelled by user");
            }
        }
    }

    // `writes` was collected newest-first; reverse to ascending inst_id order.
    std::reverse(writes.begin(), writes.end());

    RegTimelineResult result;
    result.entries.reserve(writes.size());

    // old_value for entry i is the new_value of entry i-1 (or, for the
    // first entry, the value at the start of the range as reconstructed
    // from the nearest anchor — sparse registers are usually still 0/unset
    // at trace start, and an anchor lookup here would cost another O(log N)
    // random read per single-reg query, which is not worth it for a value
    // that is purely informational; default to 0 like an uninitialized GPR).
    uint64_t prev_value = 0;
    if (!writes.empty()) {
        auto anchor_info = index.nearest_anchor_before(writes.front().inst_id);
        if (anchor_info.file_offset > 0) {
            auto anchor_rec = reader.record_at(anchor_info.file_offset);
            if (anchor_rec.kind == RecordKind::Anchor) {
                auto anchor = anchor_rec.as_anchor(reader.header().num_gpr);
                if (target < reader.header().num_gpr && target < 34) {
                    prev_value = anchor.gpr_values[target];
                }
            }
        }
    }

    for (const auto& w : writes) {
        RegTimelineEntry entry;
        entry.inst_id = w.inst_id;
        entry.pc = w.pc;
        entry.reg_index = target;
        entry.old_value = prev_value;
        entry.new_value = w.new_value;
        result.entries.push_back(entry);
        prev_value = w.new_value;
    }

    result.write_counts[target] = result.entries.size();
    result.total_writes = result.entries.size();

    // Build unique values.
    ankerl::unordered_dense::set<uint64_t> unique_set;
    for (const auto& e : result.entries) unique_set.insert(e.new_value);
    result.unique_values.assign(unique_set.begin(), unique_set.end());
    std::sort(result.unique_values.begin(), result.unique_values.end());

    ctx.progress(1.0f, "RegTimeline: complete (indexed)");
    return PassResult::success(std::move(result));
}

}  // namespace

PassResult RegTimelinePass::run(PassContext& ctx) {
    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    const uint64_t start = cfg_.start_inst_id;
    const uint64_t end = std::min(cfg_.end_inst_id, total_insts);
    if (start >= end) {
        return PassResult::success(RegTimelineResult{});
    }

    const bool track_all = (cfg_.target_reg == 0xFF);

    // Single-register queries can use the REG_WRITES inverted index to
    // avoid scanning instructions that don't touch the target register at
    // all — a large win on big traces when the register is written
    // sparsely. "All registers" mode must still visit every instruction,
    // since any of them may write any register.
    if (!track_all && cfg_.target_reg < 34) {
        return run_indexed_single_reg(ctx, cfg_, start, end);
    }

    return run_linear_scan(ctx, cfg_, start, end, track_all);
}

}  // namespace tenet

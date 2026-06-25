#include "analysis/passes/reg_timeline_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"

#include <algorithm>
#include <ankerl/unordered_dense.h>

namespace tenet {

PassResult RegTimelinePass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    const uint64_t start = cfg_.start_inst_id;
    const uint64_t end = std::min(cfg_.end_inst_id, total_insts);
    const bool track_all = (cfg_.target_reg == 0xFF);
    const uint8_t target = cfg_.target_reg;

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

                if (cfg_.max_entries > 0 && result.entries.size() >= cfg_.max_entries) {
                    goto done;
                }
            }
            current_regs[diff.index] = diff.value;
        }

        if ((inst_id - start) % progress_interval == 0) {
            ctx.progress(static_cast<float>(inst_id - start) / (end - start));
        }
    }

done:
    reader.advise_random();

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

}  // namespace tenet

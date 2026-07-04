/*
 * trace_diff_pass.cpp — Streaming lockstep + resync differential analysis.
 *
 * Algorithm overview:
 *   1. Open trace B (if cross-file mode), validate arch/gpr consistency.
 *   2. On-demand index strategy for trace B start offset (see spec §2.2).
 *   3. Create dual ThreadReaders + Iterators for lock-free sequential access.
 *   4. Lockstep comparison: advance both iterators in sync, compare at each step.
 *   5. On PC mismatch → resync via hash-table window search.
 *   6. Record DivergeSegments, report progress, honor cancellation.
 */
#include "analysis/passes/profile/trace_diff_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "common/types.h"
#include "common/logger.h"

#include <unordered_map>
#include <algorithm>
#include <cstring>

#include <fmt/format.h>

namespace tenet {

// ─── Internal helpers ─────────────────────────────────────────────────────────

namespace {

/// Result of compare_inst_data: 0, 1, or 2 diffs at a single instruction.
struct InstDataDiff {
    DiffType type;
    std::string detail;
};

/// Compare register diffs and memory accesses between two instructions at the
/// same PC.  Returns a vector of 0-2 differences.
std::vector<InstDataDiff> compare_inst_data(const InstView& a, const InstView& b) {
    std::vector<InstDataDiff> diffs;

    // ── Register comparison ──
    bool reg_differs = false;
    if (a.reg_diff_count != b.reg_diff_count) {
        reg_differs = true;
    } else {
        for (uint8_t i = 0; i < a.reg_diff_count; ++i) {
            auto ra = a.reg_diff(i);
            auto rb = b.reg_diff(i);
            if (ra.index != rb.index || ra.value != rb.value) {
                reg_differs = true;
                break;
            }
        }
    }

    if (reg_differs) {
        std::string detail;
        // Collect all differences for the detail string.
        // Build a map of reg index → value for each side.
        uint8_t max_count = std::max(a.reg_diff_count, b.reg_diff_count);
        for (uint8_t i = 0; i < max_count; ++i) {
            uint8_t idx_a = (i < a.reg_diff_count) ? a.reg_diff(i).index : 0xFF;
            uint64_t val_a = (i < a.reg_diff_count) ? a.reg_diff(i).value : 0;
            uint8_t idx_b = (i < b.reg_diff_count) ? b.reg_diff(i).index : 0xFF;
            uint64_t val_b = (i < b.reg_diff_count) ? b.reg_diff(i).value : 0;

            if (idx_a == idx_b && val_a != val_b) {
                if (!detail.empty()) detail += ", ";
                detail += fmt::format("{}(A={:#x} B={:#x})", reg_name(idx_a), val_a, val_b);
            } else if (idx_a != idx_b) {
                if (!detail.empty()) detail += ", ";
                if (idx_a != 0xFF && idx_b != 0xFF) {
                    detail += fmt::format("reg[{}] A={} B={}", i, reg_name(idx_a), reg_name(idx_b));
                } else if (idx_a != 0xFF) {
                    detail += fmt::format("{} only in A", reg_name(idx_a));
                } else {
                    detail += fmt::format("{} only in B", reg_name(idx_b));
                }
            }
        }
        if (detail.empty()) detail = "reg_diff_count differs";
        diffs.push_back({DiffType::RegisterValue, std::move(detail)});
    }

    // ── Memory comparison ──
    bool mem_differs = false;
    if (a.mem_access_count != b.mem_access_count) {
        mem_differs = true;
    } else {
        for (uint8_t i = 0; i < a.mem_access_count; ++i) {
            auto ma = a.mem_access(i);
            auto mb = b.mem_access(i);
            if (ma.addr != mb.addr || ma.value != mb.value || ma.size != mb.size) {
                mem_differs = true;
                break;
            }
        }
    }

    if (mem_differs) {
        std::string detail;
        uint8_t max_count = std::max(a.mem_access_count, b.mem_access_count);
        for (uint8_t i = 0; i < max_count && i < 4; ++i) {  // cap at 4 for readability
            if (i < a.mem_access_count && i < b.mem_access_count) {
                auto ma = a.mem_access(i);
                auto mb = b.mem_access(i);
                if (ma.addr != mb.addr || ma.value != mb.value) {
                    if (!detail.empty()) detail += ", ";
                    detail += fmt::format("[{:#x}](A={:#x} B={:#x})", ma.addr, ma.value, mb.value);
                }
            }
        }
        if (detail.empty()) detail = "mem_access_count differs";
        diffs.push_back({DiffType::MemoryValue, std::move(detail)});
    }

    return diffs;
}

/// Resync result.
struct ResyncResult {
    bool found = false;
    uint32_t skip_a = 0;  ///< Instructions to skip in trace A
    uint32_t skip_b = 0;  ///< Instructions to skip in trace B
    uint64_t pc = 0;      ///< Normalized PC at resync point
};

} // anonymous namespace

// ─── Main pass entry point ────────────────────────────────────────────────────

PassResult TraceDiffPass::run(PassContext& ctx) {
    auto& reader_a = ctx.reader();
    auto& index_a  = ctx.index();

    const auto& hdr_a = reader_a.header();
    const uint64_t slide_a = hdr_a.module_slide;
    const uint64_t inst_count_a = index_a.inst_count();

    // Resolve effective ranges for trace A.
    const uint64_t a_start = cfg_.trace_a_start;
    const uint64_t a_end   = std::min(cfg_.trace_a_end, inst_count_a);

    if (a_start >= a_end) {
        return PassResult::skipped();
    }

    // ─── Open trace B ─────────────────────────────────────────────────────
    // In cross-file mode, we open a separate reader.
    // In same-trace mode, trace B is the same reader with different range.
    std::unique_ptr<TraceReader> reader_b_owned;
    std::unique_ptr<TraceIndex>  index_b_owned;
    TraceReader* reader_b_ptr = &reader_a;
    TraceIndex*  index_b_ptr  = &index_a;
    uint64_t slide_b = slide_a;
    uint64_t inst_count_b = inst_count_a;

    const bool cross_file = !cfg_.trace_b_path.empty();

    if (cross_file) {
        // Open trace B.
        auto rb_result = TraceReader::open(cfg_.trace_b_path);
        if (!rb_result) {
            return PassResult::failed(
                fmt::format("Failed to open trace B '{}': {}",
                            cfg_.trace_b_path, rb_result.error().message));
        }
        reader_b_owned = std::make_unique<TraceReader>(std::move(*rb_result));
        reader_b_ptr = reader_b_owned.get();

        const auto& hdr_b = reader_b_ptr->header();

        // Validate arch consistency.
        if (hdr_a.arch != hdr_b.arch) {
            return PassResult::failed(
                fmt::format("Architecture mismatch: A={} B={}", hdr_a.arch, hdr_b.arch));
        }
        if (hdr_a.num_gpr != hdr_b.num_gpr) {
            return PassResult::failed(
                fmt::format("GPR count mismatch: A={} B={}", hdr_a.num_gpr, hdr_b.num_gpr));
        }

        slide_b = hdr_b.module_slide;

        // Warn if module names differ (might be comparing different binaries).
        if (hdr_a.module_name != hdr_b.module_name) {
            LOG_WARN("trace_diff: module name mismatch (A='{}', B='{}') — "
                     "results may be unreliable if comparing different binaries",
                     hdr_a.module_name, hdr_b.module_name);
        }

        // On-demand index strategy for trace B (spec §2.2):
        // Only build/load index if trace_b_start > 0.
        if (cfg_.trace_b_start > 0) {
            ctx.progress(0.01f, "Loading trace B index...");
            auto idx_result = TraceIndex::open_or_build(*reader_b_ptr, nullptr);
            if (idx_result) {
                index_b_owned = std::make_unique<TraceIndex>(std::move(*idx_result));
                index_b_ptr = index_b_owned.get();
                inst_count_b = index_b_ptr->inst_count();
            } else {
                // Fallback: linear scan (no index needed, handled below).
                LOG_WARN("trace_diff: could not load index for trace B, "
                         "will use linear scan to reach start position");
                // We'll estimate inst_count_b from file size.
                // For the range check below, use UINT64_MAX as upper bound.
                inst_count_b = UINT64_MAX;
                index_b_ptr = nullptr;
            }
        } else {
            // trace_b_start == 0: no index needed at all.
            index_b_ptr = nullptr;
            // Estimate inst_count for progress reporting.
            // We can't know without index, so use file-size heuristic.
            inst_count_b = UINT64_MAX;  // unknown, progress will be approximate
        }
    }

    const uint64_t b_start = cfg_.trace_b_start;
    const uint64_t b_end   = std::min(cfg_.trace_b_end, inst_count_b);

    if (b_start >= b_end && b_end != UINT64_MAX) {
        return PassResult::skipped();
    }

    // ─── Seek to start positions ──────────────────────────────────────────

    ctx.progress(0.03f, "Seeking to start positions...");

    // Trace A: use existing index (always available via PassContext).
    auto tr_a = reader_a.create_thread_reader();
    TraceReader::Iterator it_a = [&]() {
        if (a_start > 0) {
            auto offr = index_a.offset_of_with_pc(a_start, reader_a);
            return TraceReader::Iterator(&reader_a, offr.offset, offr.seed_pc);
        }
        return reader_a.begin(tr_a);
    }();
    auto end_a_it = reader_a.end(tr_a);

    // Trace B: on-demand offset resolution.
    auto tr_b = reader_b_ptr->create_thread_reader();
    TraceReader::Iterator it_b = [&]() {
        if (b_start == 0) {
            return reader_b_ptr->begin(tr_b);
        }
        if (index_b_ptr) {
            auto offr = index_b_ptr->offset_of_with_pc(b_start, *reader_b_ptr);
            return TraceReader::Iterator(reader_b_ptr, offr.offset, offr.seed_pc);
        }
        // Fallback: linear scan to b_start.
        auto it = reader_b_ptr->begin(tr_b);
        auto end = reader_b_ptr->end(tr_b);
        uint64_t count = 0;
        while (it != end && count < b_start) {
            auto rec = *it;
            if (rec.kind == RecordKind::Inst) ++count;
            ++it;
        }
        return it;
    }();
    auto end_b_it = reader_b_ptr->end(tr_b);

    // ─── Lockstep comparison ──────────────────────────────────────────────

    ctx.progress(0.05f, "Starting lockstep comparison...");

    TraceDiffResult result;
    uint64_t inst_id_a = a_start;
    uint64_t inst_id_b = b_start;

    const uint64_t total_est = std::min(a_end - a_start,
                                         b_end == UINT64_MAX ? UINT64_MAX : b_end - b_start);
    const uint64_t progress_interval = std::max(total_est / 200, uint64_t(10000));
    uint64_t next_progress = progress_interval;

    // Advance iterator to next INST record, return the InstView.
    // Updates inst_id on each INST record encountered.
    auto advance_to_inst = [](TraceReader::Iterator& it,
                              const TraceReader::Iterator& end) -> bool {
        while (it != end) {
            auto rec = *it;
            if (rec.kind == RecordKind::Inst) return true;
            ++it;
        }
        return false;
    };

    // Find next INST record and position iterator AT it (not past it).
    // The caller should dereference *it to get the record, then ++it to advance.

    while (true) {
        // Check cancellation periodically.
        if (inst_id_a >= a_start + next_progress) {
            float pct = 0.05f + 0.95f * float(inst_id_a - a_start) / float(total_est);
            ctx.progress(std::min(pct, 0.99f));
            next_progress += progress_interval;
            if (ctx.cancelled()) {
                result.truncated = true;
                break;
            }
        }

        // Bounds check.
        if (inst_id_a >= a_end || inst_id_b >= b_end) break;

        // Advance both to next INST.
        if (!advance_to_inst(it_a, end_a_it)) break;
        if (!advance_to_inst(it_b, end_b_it)) break;

        auto rec_a = *it_a;
        auto rec_b = *it_b;

        if (rec_a.kind != RecordKind::Inst || rec_b.kind != RecordKind::Inst) {
            // Should not happen after advance_to_inst, but be safe.
            ++it_a; ++it_b;
            continue;
        }

        auto inst_a = rec_a.as_inst();
        auto inst_b = rec_b.as_inst();

        const uint64_t pc_a = inst_a.pc - slide_a;  // normalized
        const uint64_t pc_b = inst_b.pc - slide_b;

        if (pc_a == pc_b) {
            // Same instruction — compare data.
            auto data_diffs = compare_inst_data(inst_a, inst_b);
            for (auto& dd : data_diffs) {
                if (result.segments.size() >= cfg_.max_diffs) {
                    result.truncated = true;
                    break;
                }
                DivergeSegment seg;
                seg.start_inst_a = inst_id_a;
                seg.start_inst_b = inst_id_b;
                seg.start_pc     = pc_a;
                seg.start_type   = dd.type;
                seg.start_detail = std::move(dd.detail);
                seg.resynced     = false;  // data diff, no resync needed
                seg.skip_a       = 0;
                seg.skip_b       = 0;
                result.segments.push_back(std::move(seg));
            }
            ++result.matched_count;
            ++inst_id_a;
            ++inst_id_b;
            ++it_a;
            ++it_b;
        } else {
            // ── Control-flow divergence → resync ──

            if (result.segments.size() >= cfg_.max_diffs) {
                result.truncated = true;
                break;
            }

            // Try resync with an expanding window.
            //
            // Optimization: the pc_map from trace A's window is built
            // incrementally across retries instead of being rebuilt from
            // scratch each time the window doubles. Previously, attempt N+1
            // re-scanned the entire [0, window*2) range from `it_a`
            // (including the [0, window) prefix already indexed in attempt
            // N), doing O(window) redundant work per retry — up to 3x
            // wasted scanning for the final (largest) window size. Now each
            // attempt only advances `probe_a`/`probe_id_a` over the newly
            // added tail, and `pc_map` persists across attempts.
            //
            // Trace B's probe still restarts each attempt (from `it_b`),
            // since a wider trace-A window can reveal a match at an
            // earlier trace-B position than the previous attempt covered.
            ResyncResult resync{};
            uint32_t window = cfg_.resync_window;

            std::unordered_map<uint64_t, uint32_t> pc_map;
            pc_map.reserve(window);
            auto probe_a = it_a;
            uint64_t probe_id_a = inst_id_a;
            uint32_t k_a = 0;  // number of INST records indexed into pc_map so far

            for (int attempt = 0; attempt < 3 && !resync.found; ++attempt) {
                // Extend trace A's PC→offset map up to the current window size.
                for (; k_a < window && probe_a != end_a_it; ++probe_a) {
                    auto prec = *probe_a;
                    if (prec.kind != RecordKind::Inst) continue;
                    auto pinst = prec.as_inst();
                    uint64_t norm_pc = pinst.pc - slide_a;
                    pc_map.try_emplace(norm_pc, k_a);
                    ++k_a;
                    ++probe_id_a;
                    if (probe_id_a >= a_end) break;
                }

                // Search trace B's window for a match against the (now
                // possibly larger) trace-A map.
                auto probe_b = it_b;
                uint64_t probe_id_b = inst_id_b;
                for (uint32_t k = 0; k < window && probe_b != end_b_it; ++probe_b) {
                    auto prec = *probe_b;
                    if (prec.kind != RecordKind::Inst) continue;
                    auto pinst = prec.as_inst();
                    uint64_t norm_pc = pinst.pc - slide_b;
                    auto map_it = pc_map.find(norm_pc);
                    if (map_it != pc_map.end()) {
                        resync.found = true;
                        resync.skip_a = map_it->second;
                        resync.skip_b = k;
                        resync.pc = norm_pc;
                        break;
                    }
                    ++k;
                    ++probe_id_b;
                    if (probe_id_b >= b_end) break;
                }

                if (!resync.found) {
                    window *= 2;  // expand and retry
                }
            }

            // Record the divergence segment.
            DivergeSegment seg;
            seg.start_inst_a = inst_id_a;
            seg.start_inst_b = inst_id_b;
            seg.start_pc     = pc_a;  // PC at divergence (trace A's perspective)
            seg.start_type   = DiffType::ControlFlow;
            seg.start_detail = fmt::format("PC diverged: A={:#x} B={:#x}", pc_a, pc_b);

            if (resync.found) {
                seg.resynced     = true;
                seg.skip_a       = resync.skip_a;
                seg.skip_b       = resync.skip_b;
                seg.resync_inst_a = inst_id_a + resync.skip_a;
                seg.resync_inst_b = inst_id_b + resync.skip_b;
                seg.resync_pc    = resync.pc;
                ++result.resync_count;

                // Advance iterators past the diverged region.
                for (uint32_t i = 0; i < resync.skip_a; ++i) {
                    ++it_a;
                    while (it_a != end_a_it && (*it_a).kind != RecordKind::Inst) ++it_a;
                }
                for (uint32_t i = 0; i < resync.skip_b; ++i) {
                    ++it_b;
                    while (it_b != end_b_it && (*it_b).kind != RecordKind::Inst) ++it_b;
                }
                inst_id_a += resync.skip_a;
                inst_id_b += resync.skip_b;
                result.total_diverged += resync.skip_a + resync.skip_b;
            } else {
                // Permanent divergence — cannot resync.
                seg.resynced = false;
                // Count remaining instructions as diverged.
                uint64_t remaining_a = (a_end > inst_id_a) ? a_end - inst_id_a : 0;
                uint64_t remaining_b = (b_end > inst_id_b && b_end != UINT64_MAX)
                                       ? b_end - inst_id_b : 0;
                seg.skip_a = remaining_a;
                seg.skip_b = remaining_b;
                result.total_diverged += remaining_a + remaining_b;
                result.segments.push_back(std::move(seg));
                break;  // Cannot continue after permanent divergence.
            }

            result.segments.push_back(std::move(seg));
        }
    }

    ctx.progress(1.0f, "Trace diff complete");
    LOG_INFO("trace_diff: matched={}, diverged={}, segments={}, resyncs={}, truncated={}",
             result.matched_count, result.total_diverged, result.segments.size(),
             result.resync_count, result.truncated);

    return PassResult::success(std::move(result));
}

}  // namespace tenet

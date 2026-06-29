#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"

#include <algorithm>
#include <numeric>

namespace tenet {

PassResult TraceFoldPass::run(PassContext& ctx) {
    // Get loop analysis results
    const auto& loops = ctx.require<LoopResult>("loop");
    const auto& xref = ctx.require<XrefResult>("xref");

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& regfile = ctx.regfile();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    TraceFoldResult result;
    result.original_inst_count = total_insts;

    ctx.progress(0.0f, "TraceFold: analyzing loop iteration boundaries...");

    // For each loop with enough iterations, identify fold-able regions.
    // Strategy: find loops with iteration_count >= min_iterations_to_fold,
    // then identify the inst_id ranges of each iteration by tracking back-edge crossings.
    for (const auto& loop : loops.loops) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        if (loop.iteration_count < cfg_.min_iterations_to_fold) continue;

        // Get all execution instances of the loop header
        auto header_it = xref.pc_to_inst_ids.find(loop.header_pc);
        if (header_it == xref.pc_to_inst_ids.end()) continue;

        // Get sorted inst_ids where the header was executed (= iteration starts)
        std::vector<uint64_t> iteration_starts;
        iteration_starts.reserve(loop.iteration_count + 1);
        for (uint64_t id : header_it->second) {
            iteration_starts.push_back(id);
        }
        if (!std::is_sorted(iteration_starts.begin(), iteration_starts.end())) {
            std::sort(iteration_starts.begin(), iteration_starts.end());
        }

        if (iteration_starts.size() < cfg_.min_iterations_to_fold) continue;

        // Determine which iterations to keep: first N and last N
        uint32_t keep = cfg_.keep_iterations;
        size_t n_iters = iteration_starts.size();

        // If total iterations <= 2*keep, nothing to fold
        if (n_iters <= 2 * keep) continue;

        FoldedRegion region;
        region.header_pc = loop.header_pc;
        region.total_iterations = n_iters;

        // Keep first 'keep' iterations
        for (uint32_t i = 0; i < keep && i < n_iters; i++) {
            uint64_t start = iteration_starts[i];
            uint64_t end = (i + 1 < n_iters) ? iteration_starts[i + 1] - 1 : total_insts - 1;
            region.kept_iterations.push_back({start, end});
        }

        // Keep last 'keep' iterations
        for (size_t i = n_iters - keep; i < n_iters; i++) {
            uint64_t start = iteration_starts[i];
            uint64_t end = (i + 1 < n_iters) ? iteration_starts[i + 1] - 1 : total_insts - 1;
            region.kept_iterations.push_back({start, end});
        }

        // The folded region spans from first kept end + 1 to last kept start - 1
        uint64_t fold_start = iteration_starts[keep];
        uint64_t fold_end = iteration_starts[n_iters - keep] - 1;
        region.first_inst_id = fold_start;
        region.last_inst_id = fold_end;
        region.total_instructions_folded = fold_end - fold_start + 1;

        // Calculate average body size
        if (n_iters > 1) {
            uint64_t total_body = 0;
            for (size_t i = 0; i + 1 < iteration_starts.size(); i++) {
                total_body += iteration_starts[i + 1] - iteration_starts[i];
            }
            region.instructions_per_iteration = total_body / (n_iters - 1);
        }

        // Collect register changes across the folded region
        if (cfg_.include_reg_summary && fold_start < fold_end) {
            // Sample first and last iteration registers
            auto state_first = regfile.state_before(fold_start);
            auto state_last = regfile.state_after(fold_end);

            for (uint8_t r = 0; r < 31; r++) {
                if (state_first.gpr[r] != state_last.gpr[r]) {
                    region.reg_changes.push_back({r, state_first.gpr[r], state_last.gpr[r]});
                }
            }
        }

        result.folded_regions.push_back(std::move(region));
    }

    ctx.progress(0.7f, "TraceFold: building kept-ranges list...");

    // Sort folded regions by first_inst_id
    std::sort(result.folded_regions.begin(), result.folded_regions.end(),
              [](const FoldedRegion& a, const FoldedRegion& b) {
                  return a.first_inst_id < b.first_inst_id;
              });

    // Build kept_ranges (complement of folded regions)
    uint64_t cursor = 0;
    for (const auto& fr : result.folded_regions) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        if (cursor < fr.first_inst_id) {
            result.kept_ranges.push_back({cursor, fr.first_inst_id - 1});
        }
        cursor = fr.last_inst_id + 1;
        result.total_instructions_removed += fr.total_instructions_folded;
    }
    if (cursor < total_insts) {
        result.kept_ranges.push_back({cursor, total_insts - 1});
    }

    result.folded_inst_count = total_insts - result.total_instructions_removed;
    result.compression_ratio = (result.folded_inst_count > 0)
        ? static_cast<float>(total_insts) / result.folded_inst_count
        : 1.0f;

    ctx.progress(1.0f, "TraceFold: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

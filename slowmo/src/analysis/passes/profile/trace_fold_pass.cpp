#include "analysis/passes/profile/trace_fold_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"

#include <fmt/core.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace tenet {

// ─── TraceFoldResult serialization helpers ─────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x54464C44 ("TFLD")
//   u32  version = 2
//   u64  original_inst_count
//   u64  folded_inst_count
//   u64  total_instructions_removed
//   f32  compression_ratio
//   u64  num_kept_ranges
//   for each KeptRange: u64 start, u64 end
//   u64  num_regions
//   for each FoldedRegion:
//     u64  header_pc, first_inst_id, last_inst_id
//     u64  total_iterations, instructions_per_iteration, total_instructions_folded
//     u64  num_kept_iterations; for each: u64 start, u64 end
//     u64  num_reg_changes; for each: u8 reg, u64 first_val, u64 last_val, u8 pattern
//     u64  num_fpr_changes; for each: u8 reg, u64 first_lo, u64 first_hi, u64 last_lo, u64 last_hi

namespace {

static constexpr uint32_t TFLD_BLOB_MAGIC   = 0x54464C44u;  // "TFLD"
static constexpr uint32_t TFLD_BLOB_VERSION = 2u;

std::string trace_fold_serialize(const TraceFoldResult& res) {
    size_t total = 4 + 4 + 8 + 8 + 8 + 4 + 8;
    total += res.kept_ranges.size() * (8 + 8);
    total += 8;
    for (const auto& fr : res.folded_regions) {
        total += 8 + 8 + 8;
        total += 8 + 8 + 8;
        total += 8 + fr.kept_iterations.size() * (8 + 8);
        total += 8 + fr.reg_changes.size() * (1 + 8 + 8 + 1);
        total += 8 + fr.fpr_changes.size() * (1 + 8 + 8 + 8 + 8);
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };

    write_u32(TFLD_BLOB_MAGIC);
    write_u32(TFLD_BLOB_VERSION);
    write_u64(res.original_inst_count);
    write_u64(res.folded_inst_count);
    write_u64(res.total_instructions_removed);
    write_f32(res.compression_ratio);

    write_u64(static_cast<uint64_t>(res.kept_ranges.size()));
    for (const auto& kr : res.kept_ranges) {
        write_u64(kr.start);
        write_u64(kr.end);
    }

    write_u64(static_cast<uint64_t>(res.folded_regions.size()));
    for (const auto& fr : res.folded_regions) {
        write_u64(fr.header_pc);
        write_u64(fr.first_inst_id);
        write_u64(fr.last_inst_id);
        write_u64(fr.total_iterations);
        write_u64(fr.instructions_per_iteration);
        write_u64(fr.total_instructions_folded);

        write_u64(static_cast<uint64_t>(fr.kept_iterations.size()));
        for (const auto& ir : fr.kept_iterations) {
            write_u64(ir.start);
            write_u64(ir.end);
        }

        write_u64(static_cast<uint64_t>(fr.reg_changes.size()));
        for (const auto& rc : fr.reg_changes) {
            write_u8(rc.reg);
            write_u64(rc.first_val);
            write_u64(rc.last_val);
            write_u8(static_cast<uint8_t>(rc.pattern));
        }

        write_u64(static_cast<uint64_t>(fr.fpr_changes.size()));
        for (const auto& fc : fr.fpr_changes) {
            write_u8(fc.reg);
            write_u64(fc.first_lo);
            write_u64(fc.first_hi);
            write_u64(fc.last_lo);
            write_u64(fc.last_hi);
        }
    }

    return buf;
}

bool trace_fold_deserialize(const std::string& blob, TraceFoldResult& out) {
    if (blob.size() < 4 + 4 + 8 + 8 + 8 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };

    if (read_u32() != TFLD_BLOB_MAGIC)   return false;
    if (read_u32() != TFLD_BLOB_VERSION) return false;  // reject older/newer versions

    out.original_inst_count       = read_u64();
    out.folded_inst_count         = read_u64();
    out.total_instructions_removed = read_u64();
    out.compression_ratio         = read_f32();

    if (p + 8 > end) return false;
    uint64_t n_kept = read_u64();
    out.kept_ranges.reserve(static_cast<size_t>(n_kept));
    for (uint64_t i = 0; i < n_kept; i++) {
        if (p + 8 + 8 > end) return false;
        uint64_t s = read_u64();
        uint64_t e = read_u64();
        out.kept_ranges.push_back({s, e});
    }

    if (p + 8 > end) return false;
    uint64_t n_regions = read_u64();
    out.folded_regions.reserve(static_cast<size_t>(n_regions));
    for (uint64_t i = 0; i < n_regions; i++) {
        if (p + 8 * 6 > end) return false;
        FoldedRegion fr{};
        fr.header_pc                   = read_u64();
        fr.first_inst_id               = read_u64();
        fr.last_inst_id                = read_u64();
        fr.total_iterations            = read_u64();
        fr.instructions_per_iteration  = read_u64();
        fr.total_instructions_folded   = read_u64();

        if (p + 8 > end) return false;
        uint64_t n_iter = read_u64();
        fr.kept_iterations.reserve(static_cast<size_t>(n_iter));
        for (uint64_t j = 0; j < n_iter; j++) {
            if (p + 8 + 8 > end) return false;
            uint64_t s = read_u64();
            uint64_t e = read_u64();
            fr.kept_iterations.push_back({s, e});
        }

        if (p + 8 > end) return false;
        uint64_t n_rc = read_u64();
        fr.reg_changes.reserve(static_cast<size_t>(n_rc));
        for (uint64_t j = 0; j < n_rc; j++) {
            if (p + 1 + 8 + 8 + 1 > end) return false;
            FoldedRegion::RegChange rc{};
            rc.reg       = read_u8();
            rc.first_val = read_u64();
            rc.last_val  = read_u64();
            rc.pattern   = static_cast<RegChangePattern>(read_u8());
            fr.reg_changes.push_back(rc);
        }

        if (p + 8 > end) return false;
        uint64_t n_fc = read_u64();
        fr.fpr_changes.reserve(static_cast<size_t>(n_fc));
        for (uint64_t j = 0; j < n_fc; j++) {
            if (p + 1 + 8 + 8 + 8 + 8 > end) return false;
            FoldedRegion::FprChange fc{};
            fc.reg      = read_u8();
            fc.first_lo = read_u64();
            fc.first_hi = read_u64();
            fc.last_lo  = read_u64();
            fc.last_hi  = read_u64();
            fr.fpr_changes.push_back(fc);
        }

        out.folded_regions.push_back(std::move(fr));
    }

    return true;
}

/// Classify how a register changed across `samples` (chronologically ordered
/// values, including first and last). Cheap heuristic — see RegChangePattern.
RegChangePattern classify_pattern(const std::vector<uint64_t>& samples) {
    if (samples.size() < 2) return RegChangePattern::Constant;

    bool any_change = false;
    bool saw_increase = false;
    bool saw_decrease = false;
    for (size_t i = 1; i < samples.size(); i++) {
        if (samples[i] == samples[i - 1]) continue;
        any_change = true;
        // Treat as signed deltas — most loop counters/pointers behave that way.
        int64_t delta = static_cast<int64_t>(samples[i] - samples[i - 1]);
        if (delta > 0) saw_increase = true;
        else saw_decrease = true;
    }

    if (!any_change) return RegChangePattern::Constant;
    if (saw_increase && saw_decrease) return RegChangePattern::Oscillating;
    return RegChangePattern::Monotonic;
}

}  // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════
// TraceFoldPass::run
// ═══════════════════════════════════════════════════════════════════════════

PassResult TraceFoldPass::run(PassContext& ctx) {
    // The persisted blob only stores results, not the config that produced
    // them. Every knob in TraceFoldConfig (min_iterations_to_fold,
    // keep_iterations, pattern_sample_points, include_fpr_summary) changes
    // what gets computed, so — like other parameter-aware-cached passes
    // (e.g. window_stats) — we only read/write the cache when the pass is
    // running with its default configuration. A
    // custom config (e.g. `--trace-fold-min-iter 10`) always recomputes,
    // avoiding silently returning results from a *different* configuration.
    const bool is_default_cfg = (cfg_.min_iterations_to_fold == TraceFoldConfig{}.min_iterations_to_fold &&
                                  cfg_.keep_iterations        == TraceFoldConfig{}.keep_iterations &&
                                  cfg_.include_reg_summary    == TraceFoldConfig{}.include_reg_summary &&
                                  cfg_.include_fpr_summary    == TraceFoldConfig{}.include_fpr_summary &&
                                  cfg_.pattern_sample_points  == TraceFoldConfig{}.pattern_sample_points);
    const bool use_cache = ctx.range().is_full_trace() && is_default_cfg;

    // ── Fast path: load from persisted cache ───────────────────────────────
    if (use_cache) {
        std::string blob;
        if (ctx.index().load_pass_blob("trace_fold", blob)) {
            TraceFoldResult cached;
            if (trace_fold_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "TraceFold: {} regions folded (from cache)",
                    cached.folded_regions.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // Get loop analysis results
    const auto& loops = ctx.require<LoopResult>("loop");
    const auto& xref = ctx.require<XrefResult>("xref");

    auto& index = ctx.index();
    auto& regfile = ctx.regfile();
    const auto& reader = ctx.reader();
    const bool has_fpr = cfg_.include_fpr_summary && reader.header().has_fpr();

    const uint64_t total_insts = index.inst_count();
    if (total_insts == 0) {
        return PassResult::failed("Empty trace");
    }

    TraceFoldResult result;
    result.original_inst_count = total_insts;

    ctx.progress(0.0f, "TraceFold: analyzing loop iteration boundaries...");

    // ── Step 1: Identify candidate fold-able regions per loop ──────────────
    // Strategy: find loops with iteration_count >= min_iterations_to_fold,
    // then identify the inst_id ranges of each iteration by tracking back-edge
    // crossings via the xref (PC -> inst_ids) index.
    std::vector<FoldedRegion> candidates;
    candidates.reserve(loops.loops.size());

    for (const auto& loop : loops.loops) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
        if (loop.iteration_count < cfg_.min_iterations_to_fold) continue;

        // Get all execution instances of the loop header
        if (!xref.has_pc(loop.header_pc)) continue;

        // Get sorted inst_ids where the header was executed (= iteration starts)
        std::vector<uint64_t> iteration_starts = xref.inst_ids_at(loop.header_pc);
        if (!std::is_sorted(iteration_starts.begin(), iteration_starts.end())) {
            std::sort(iteration_starts.begin(), iteration_starts.end());
        }

        if (iteration_starts.size() < cfg_.min_iterations_to_fold) continue;

        // Determine which iterations to keep: first N and last N.
        // Clamp to >= 1 — with keep=0, `iteration_starts[n_iters - keep]` below
        // would read `iteration_starts[n_iters]`, one past the end of the vector.
        // Folding away *every* iteration also isn't useful for navigation (the
        // caller always needs at least a first/last landing point), so 1 is the
        // sane floor regardless of what a caller configures.
        uint32_t keep = std::max<uint32_t>(cfg_.keep_iterations, 1);
        size_t n_iters = iteration_starts.size();

        // If total iterations <= 2*keep, nothing to fold
        if (n_iters <= 2 * static_cast<size_t>(keep)) continue;

        FoldedRegion region{};
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
        if (fold_end < fold_start) continue;  // degenerate — nothing to fold

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

        // Stash sampled header inst_ids for the interior-pattern pass below
        // (re-derived cheaply from iteration_starts, no extra xref lookups).
        candidates.push_back(std::move(region));
    }

    ctx.progress(0.3f, fmt::format(
        "TraceFold: {} candidate regions found, resolving overlaps...", candidates.size()));

    // ── Step 2: Resolve overlapping / nested regions ────────────────────────
    //
    // Nested loops produce nested FoldedRegions (e.g. an outer loop's folded
    // range fully contains an inner loop's folded range). If we naively kept
    // every region, the "complement" computation below would double count:
    // the outer region's `total_instructions_folded` already spans the inner
    // region's instructions, so the previous implementation summed both,
    // inflating `total_instructions_removed` (and could underflow
    // `folded_inst_count` for deeply nested loops).
    //
    // Fix: sort by [first_inst_id asc, span desc] and greedily keep only
    // non-overlapping regions, preferring the *outermost* (largest span) loop
    // whenever ranges overlap or nest. This mirrors how a human would read a
    // folded trace: show the outer loop's summary, not both.
    std::sort(candidates.begin(), candidates.end(),
              [](const FoldedRegion& a, const FoldedRegion& b) {
                  if (a.first_inst_id != b.first_inst_id)
                      return a.first_inst_id < b.first_inst_id;
                  // Larger span first, so it "wins" the overlap check below.
                  return (a.last_inst_id - a.first_inst_id) >
                         (b.last_inst_id - b.first_inst_id);
              });

    std::vector<FoldedRegion> selected;
    selected.reserve(candidates.size());
    uint64_t covered_until = 0;  // exclusive upper bound already claimed
    bool have_covered = false;
    for (auto& cand : candidates) {
        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        if (have_covered && cand.first_inst_id < covered_until) {
            // Fully or partially nested inside an already-selected (larger or
            // equal, earlier-sorted) region — skip to avoid double counting.
            continue;
        }
        covered_until = cand.last_inst_id + 1;
        have_covered = true;
        selected.push_back(std::move(cand));
    }

    ctx.progress(0.4f, fmt::format(
        "TraceFold: {} non-overlapping regions selected, sampling registers...",
        selected.size()));

    // ── Step 3: Pre-warm RegisterFile over all region spans ─────────────────
    //
    // Avoids O(regions) cold ANCHOR->INST replays when computing per-region
    // register/FPR diffs below (same rationale as loop_semantics_pass).
    if (cfg_.include_reg_summary && !selected.empty()) {
        constexpr uint64_t ANCHOR_INTERVAL_EST = 1000;
        constexpr uint64_t COALESCE_GAP = ANCHOR_INTERVAL_EST * 2;

        std::vector<std::pair<uint64_t, uint64_t>> spans;
        spans.reserve(selected.size());
        for (const auto& r : selected) {
            spans.emplace_back(r.first_inst_id, r.last_inst_id + 1);
        }
        std::sort(spans.begin(), spans.end());

        uint64_t span_start = spans[0].first;
        uint64_t span_end   = spans[0].second;
        auto flush_warm = [&](uint64_t s, uint64_t e) {
            regfile.warm_range(s, e, 0, nullptr);
        };
        for (size_t i = 1; i < spans.size(); ++i) {
            if (ctx.cancelled()) return PassResult::failed("cancelled by user");
            if (spans[i].first <= span_end + COALESCE_GAP) {
                span_end = std::max(span_end, spans[i].second);
            } else {
                flush_warm(span_start, span_end);
                span_start = spans[i].first;
                span_end   = spans[i].second;
            }
        }
        flush_warm(span_start, span_end);
    }

    // ── Step 4: Collect register/FPR diffs + interior change-pattern ───────
    size_t processed = 0;
    for (auto& region : selected) {
        if (ctx.cancelled()) return PassResult::failed("cancelled by user");

        const uint64_t fold_start = region.first_inst_id;
        const uint64_t fold_end   = region.last_inst_id;

        if (cfg_.include_reg_summary) {
            auto state_first = regfile.state_before(fold_start);
            auto state_last  = regfile.state_after(fold_end);

            // Interior sample points, used only for pattern classification
            // (monotonic/oscillating). Only fetched lazily below, and only
            // for registers that actually need them (see comment at the call
            // site) — replaying `regfile` state at each sample point is not
            // free even when warmed.
            //
            // Two-tier sampling to avoid aliasing on short-period signals:
            //   1. `n_samples` points evenly spaced across the whole span
            //      (catches slow drifts / long-period behavior).
            //   2. For each of those, one extra point offset by roughly half
            //      an iteration (`instructions_per_iteration / 2`) — if the
            //      register flips sign every iteration (a period-2 signal,
            //      e.g. a scratch/temp register reused as +delta/-delta),
            //      evenly-spaced samples whose stride happens to be a near
            //      multiple of the iteration period would otherwise keep
            //      landing on the same phase and look falsely monotonic/
            //      constant. The half-period companion point is guaranteed
            //      to land on the *opposite* phase whenever one exists.
            std::vector<uint64_t> sample_ids;
            uint32_t n_samples = cfg_.pattern_sample_points;
            if (n_samples > 0 && fold_end > fold_start) {
                uint64_t span = fold_end - fold_start;
                uint64_t iter_len = std::max<uint64_t>(region.instructions_per_iteration, 1);
                uint64_t half_iter = std::max<uint64_t>(iter_len / 2, 1);
                sample_ids.reserve(n_samples * 2);
                for (uint32_t s = 1; s <= n_samples; s++) {
                    uint64_t offset = (span * s) / (n_samples + 1);
                    uint64_t iid = fold_start + offset;
                    if (iid > fold_start && iid < fold_end) sample_ids.push_back(iid);

                    uint64_t companion = iid + half_iter;
                    if (companion > fold_start && companion < fold_end) {
                        sample_ids.push_back(companion);
                    }
                }
                // classify_pattern() interprets `series` as chronologically
                // ordered (direction changes are computed between adjacent
                // elements), so the interleaved evenly-spaced + companion
                // points above must be sorted back into inst_id order
                // (and de-duplicated in case a companion point happens to
                // coincide with a later evenly-spaced point).
                std::sort(sample_ids.begin(), sample_ids.end());
                sample_ids.erase(std::unique(sample_ids.begin(), sample_ids.end()), sample_ids.end());
            }

            // Cache of interior-sample GPR values, loaded at most once per
            // region regardless of how many registers end up needing them.
            // `state_before(iid)` returns the FULL register state (all GPRs)
            // per call, so fetching it once per sample point and then
            // indexing into the cached array per-register avoids N_regs
            // redundant RegisterFile lookups (each a hash-map probe even
            // when warmed) at every sample point.
            std::vector<std::array<uint64_t, 31>> sample_gprs;  // [sample_idx][reg 0..30]
            bool samples_loaded = false;
            auto ensure_samples_loaded = [&]() {
                if (samples_loaded) return;
                samples_loaded = true;
                sample_gprs.reserve(sample_ids.size());
                for (uint64_t iid : sample_ids) {
                    const auto& st = regfile.state_before(iid);
                    std::array<uint64_t, 31> gprs{};
                    std::copy(std::begin(st.gpr), std::begin(st.gpr) + 31, gprs.begin());
                    sample_gprs.push_back(gprs);
                }
            };

            for (uint8_t r = 0; r < 31; r++) {
                bool endpoints_equal = (state_first.gpr[r] == state_last.gpr[r]);
                if (endpoints_equal && sample_ids.empty()) continue;

                if (!sample_ids.empty()) ensure_samples_loaded();

                std::vector<uint64_t> series;
                series.reserve(sample_gprs.size() + 2);
                series.push_back(state_first.gpr[r]);
                for (const auto& s : sample_gprs) series.push_back(s[r]);
                series.push_back(state_last.gpr[r]);

                if (endpoints_equal &&
                    std::adjacent_find(series.begin(), series.end(), std::not_equal_to<>()) == series.end()) {
                    continue;  // truly constant throughout — not worth reporting
                }

                FoldedRegion::RegChange rc{};
                rc.reg = r;
                rc.first_val = state_first.gpr[r];
                rc.last_val = state_last.gpr[r];
                rc.pattern = classify_pattern(series);
                region.reg_changes.push_back(rc);
            }

            // FPR (NEON v0-v31) diffs — only when the trace carries FPR data.
            if (has_fpr) {
                for (uint8_t r = 0; r < 32; r++) {
                    const auto& f0 = state_first.fpr[r];
                    const auto& f1 = state_last.fpr[r];
                    if (f0.lo == f1.lo && f0.hi == f1.hi) continue;
                    FoldedRegion::FprChange fc{};
                    fc.reg = r;
                    fc.first_lo = f0.lo; fc.first_hi = f0.hi;
                    fc.last_lo  = f1.lo; fc.last_hi  = f1.hi;
                    region.fpr_changes.push_back(fc);
                }
            }
        }

        processed++;
        ctx.progress(0.4f + 0.5f * static_cast<float>(processed) / static_cast<float>(std::max<size_t>(1, selected.size())));
    }

    result.folded_regions = std::move(selected);

    ctx.progress(0.9f, "TraceFold: building kept-ranges list...");

    // Regions are already sorted by first_inst_id and non-overlapping
    // (guaranteed by Step 2), so the complement can be computed with a
    // single linear sweep without any double counting.
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

    // ── Persist cache (full-trace runs with default config only) ───────────
    if (use_cache) {
        std::string blob = trace_fold_serialize(result);
        index.save_pass_blob("trace_fold", blob.data(), blob.size());
    }

    ctx.progress(1.0f, "TraceFold: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

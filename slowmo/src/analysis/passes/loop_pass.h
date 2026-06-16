#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include <cstdint>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── Loop analysis result ─────────────────────────────────────────────────

/// Information about a single loop identified in the trace.
struct LoopInfo {
    uint64_t header_pc;          // PC of the loop header (back-edge target)
    uint64_t back_edge_pc;       // PC of the back-edge source (branch instruction)
    uint64_t iteration_count;    // How many times the back-edge was taken
    uint32_t nesting_depth;      // 0 = outermost loop, 1 = first nested, etc.

    /// All unique PCs that are part of this loop body (ordered).
    std::vector<uint64_t> body_pcs;
};

/// Result of loop analysis.
struct LoopResult {
    /// All detected loops, ordered by header_pc.
    std::vector<LoopInfo> loops;

    /// Per-PC: loop-head depth (0 = not a loop head, 1+ = deepest nesting level at that PC).
    ankerl::unordered_dense::map<uint64_t, uint32_t> pc_loop_depth;

    /// Per-PC: is this the header of a loop?
    ankerl::unordered_dense::map<uint64_t, bool> pc_is_loop_header;

    /// Per-PC: which loop index (into loops[]) contains this PC.
    /// A PC can be in multiple loops (nested); the innermost is stored.
    ankerl::unordered_dense::map<uint64_t, size_t> pc_innermost_loop;

    /// Total number of back-edges detected.
    size_t total_back_edges = 0;

    /// Maximum nesting depth observed.
    uint32_t max_nesting_depth = 0;

    // ─── Query helpers ────────────────────────────────────────────────

    /// Is this PC a loop header?
    bool is_loop_header(uint64_t pc) const {
        auto it = pc_is_loop_header.find(pc);
        return it != pc_is_loop_header.end() && it->second;
    }

    /// Is this PC inside any loop body (includes the header)?
    bool is_in_loop(uint64_t pc) const {
        return pc_loop_depth.find(pc) != pc_loop_depth.end();
    }

    /// Get the nesting depth of this PC (0 = not in a loop).
    uint32_t loop_depth_at(uint64_t pc) const {
        auto it = pc_loop_depth.find(pc);
        if (it == pc_loop_depth.end()) return 0;
        return it->second;
    }

    /// Get the innermost LoopInfo* for a PC (nullptr if not in any loop).
    const LoopInfo* innermost_loop_at(uint64_t pc) const {
        auto it = pc_innermost_loop.find(pc);
        if (it == pc_innermost_loop.end()) return nullptr;
        if (it->second >= loops.size()) return nullptr;
        return &loops[it->second];
    }
};

// ─── Loop collector (single-pass scan) ───────────────────────────────────

/// Collector that detects back-edges during a single sequential scan.
///
/// Strategy:
///   A back-edge occurs when a branch instruction jumps to a PC that is
///   strictly less than the branch's own PC AND has already been seen in
///   the trace (i.e., it is the target of a backward branch).
///
/// We track:
///   - seen_pcs: a sorted vector of all unique PCs encountered so far
///   - back_edge_map: maps header_pc → {back_edge_pc, iteration_count}
///   - For each back-edge, we also collect the set of body PCs
///     (all PCs that appear between the header and the back-edge in the trace).
class LoopCollector final : public TraceCollector {
public:
    std::string_view name() const override { return "loop_collector"; }

    bool begin(uint64_t /*start*/, uint64_t /*end*/) override {
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& inst) override {
        // Track the most recent 'active window' PC → inst_id mapping.
        // We only need: if current PC < last_pc AND it was already seen → back-edge.
        //
        // To detect "was the target PC already seen", we maintain a hash set.
        // For body PC collection, we record the sequential inst range for each
        // (header, back_edge) pair.

        uint64_t pc = inst.pc;

        // Mark as seen
        seen_pcs_.insert({pc, true});

        // Check if this PC is a back-edge target (it was seen before and
        // last instruction jumped backward to here).
        // We detect back-edges by observing that: when the previous instruction's
        // PC was > pc, and pc has been seen before — it's a backward branch target.
        if (last_pc_ != 0 && pc < last_pc_ && seen_pcs_.count(pc)) {
            // This is a backward branch: last_pc_ → pc (pc is the loop header)
            auto& be = back_edges_[pc];
            if (be.back_edge_pc == 0) {
                be.back_edge_pc = last_pc_;
                be.first_header_inst_id = inst_id;
            }
            be.iteration_count++;
            be.back_edge_pc = last_pc_;  // Update to most recent back-edge source

            // Record body window: from first_header_inst_id to current inst_id
            // We only keep the first instance for body PC collection
            if (be.body_inst_start == 0 || be.body_inst_start > be.first_header_inst_id) {
                be.body_inst_start = be.first_header_inst_id;
            }
            be.body_inst_end = inst_id;  // The back-edge instruction
        }

        last_pc_ = pc;
    }

    void end() override {
        // Sort back-edges by header_pc for deterministic output
    }

    struct BackEdgeInfo {
        uint64_t back_edge_pc = 0;
        uint64_t iteration_count = 0;
        uint64_t first_header_inst_id = 0;
        uint64_t body_inst_start = 0;
        uint64_t body_inst_end = 0;
    };

    uint64_t last_pc_ = 0;
    ankerl::unordered_dense::map<uint64_t, bool> seen_pcs_;
    ankerl::unordered_dense::map<uint64_t, BackEdgeInfo> back_edges_;
};

// ─── Loop pass ────────────────────────────────────────────────────────────

/// Detects loops in the execution trace by finding backward branches.
///
/// Algorithm:
///   Phase 1 (collect): Single-pass scan to find all backward branches.
///   Phase 2 (body PCs): Second pass to collect body PCs for each detected loop.
///   Phase 3 (nesting): Compute nesting depths by checking containment.
///
/// Result type: LoopResult
class LoopPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "loop"; }
    std::string_view description() const override {
        return "Loop detection via backward branch analysis";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // Standalone pass
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 8.0f; }
};

}  // namespace tenet

#pragma once

// ─────────────────────────────────────────────────────────────────────────
// AnnotationView — lightweight aggregation helper (NOT a pass).
//
// Formerly this lived as "symbol_annotation_pass" — a full AnalysisPass with
// its own PassEntry, dependency edges, and a persisted RocksDB blob cache.
// In practice it produced no new analytical information: it only relabelled
// already-computed results (FunctionResult / LoopResult /
// ConstantMaterializationResult / PatternResult) into a unified
// PC → Annotation view. Nothing else in the codebase depended on it as a
// pass, and the GUI never rendered its output.
//
// Because it does no analysis of its own — just a one-shot projection over
// results the caller already has in hand — it has been demoted to a plain
// helper function. Callers (CLI / MCP) `require()` the four source passes
// themselves and then call `build_annotation_view()` to get the same
// aggregated view, with no PassManager registration/caching overhead and no
// blob (de)serialization to maintain.
// ─────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <ankerl/unordered_dense.h>

namespace tenet {

struct FunctionResult;
struct LoopResult;
struct ConstantMaterializationResult;
struct PatternResult;

// ─── Annotation types ─────────────────────────────────────────────────────

/// A single annotation attached to a PC or inst_id.
struct Annotation {
    enum class Kind : uint8_t {
        Function,
        Loop,
        Constant,
        Pattern,
        String,
        Custom
    };

    Kind kind;
    std::string label;      // Short label like "SHA256_H0" or "sub_100abc"
    std::string detail;     // Longer description
    float priority;         // For display ordering (higher = more important)
};

// ─── Annotation view ──────────────────────────────────────────────────────

/// Aggregated annotation layer built on demand from other passes' results.
struct AnnotationView {
    /// Annotations keyed by PC address.
    ankerl::unordered_dense::map<uint64_t, std::vector<Annotation>> by_pc;

    /// Annotations keyed by instruction ID.
    ankerl::unordered_dense::map<uint64_t, std::vector<Annotation>> by_inst_id;

    // ─── Query helpers ────────────────────────────────────────────────

    /// Get all annotations at a given PC.
    const std::vector<Annotation>& annotations_at_pc(uint64_t pc) const {
        static const std::vector<Annotation> empty;
        auto it = by_pc.find(pc);
        return (it != by_pc.end()) ? it->second : empty;
    }

    /// Get all annotations at a given instruction ID.
    const std::vector<Annotation>& annotations_at_inst(uint64_t inst_id) const {
        static const std::vector<Annotation> empty;
        auto it = by_inst_id.find(inst_id);
        return (it != by_inst_id.end()) ? it->second : empty;
    }

    /// Get the highest-priority label for a PC, or "" if none.
    std::string label_for_pc(uint64_t pc) const {
        auto it = by_pc.find(pc);
        if (it == by_pc.end() || it->second.empty()) return "";
        return it->second.front().label;  // Sorted by priority descending
    }

    /// Check if there are any annotations at a PC.
    bool has_annotation(uint64_t pc) const {
        return by_pc.find(pc) != by_pc.end();
    }

    /// Format a PC with contextual annotation info.
    /// e.g. "sub_100abc+0x10 [SHA-256 round]"
    std::string format_pc(uint64_t pc) const;
};

// ─── Builder ──────────────────────────────────────────────────────────────

/// Build an AnnotationView from already-computed pass results. Any pointer
/// may be null (that source is simply skipped) — callers should pass
/// whichever of function/loop/constant_materialization/pattern results they
/// have available.
AnnotationView build_annotation_view(const FunctionResult* function_result,
                                      const LoopResult* loop_result,
                                      const ConstantMaterializationResult* constant_result,
                                      const PatternResult* pattern_result);

}  // namespace tenet

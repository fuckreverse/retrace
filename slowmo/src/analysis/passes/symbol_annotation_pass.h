#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <algorithm>

namespace tenet {

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

// ─── Annotation result ────────────────────────────────────────────────────

/// Aggregated annotation layer for the entire trace.
struct AnnotationResult {
    /// Annotations keyed by PC address.
    std::unordered_map<uint64_t, std::vector<Annotation>> by_pc;

    /// Annotations keyed by instruction ID.
    std::unordered_map<uint64_t, std::vector<Annotation>> by_inst_id;

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

// ─── Symbol annotation pass ───────────────────────────────────────────────

/// Aggregates annotations from all other analysis passes into a unified
/// per-PC and per-inst_id annotation layer. This makes analysis results
/// human-readable by providing rich context at any point in the trace.
///
/// Dependencies are soft: each is optional and the pass will skip gracefully
/// if a dependency failed or was not registered.
///
/// Result type: AnnotationResult
class SymbolAnnotationPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "symbol_annotation"; }
    std::string_view description() const override {
        return "Aggregate annotations from all passes into a unified annotation layer";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"function", "loop", "constant_materialization", "pattern"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }

private:
    /// Collect function annotations from FunctionResult.
    void collect_functions(const PassResult& result, AnnotationResult& out);

    /// Collect loop annotations from LoopResult.
    void collect_loops(const PassResult& result, AnnotationResult& out);

    /// Collect constant annotations from ConstantMaterializationResult.
    void collect_constants(const PassResult& result, AnnotationResult& out);

    /// Collect pattern annotations from PatternResult.
    void collect_patterns(const PassResult& result, AnnotationResult& out);

    /// Sort all annotation vectors by priority descending.
    void sort_annotations(AnnotationResult& out);
};

}  // namespace tenet

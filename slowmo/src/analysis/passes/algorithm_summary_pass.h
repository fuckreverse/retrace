#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace tenet {

// ─── Algorithm candidate ──────────────────────────────────────────────────

/// A single detected algorithm with supporting evidence.
struct AlgorithmCandidate {
    std::string name;                     // e.g. "AES-128-CBC", "SHA-256", "Custom Feistel"
    float confidence = 0.0f;              // 0.0–1.0
    std::string evidence;                 // Human-readable evidence summary
    std::vector<uint64_t> key_pcs;        // Key PCs involved
    std::vector<uint64_t> key_inst_ids;   // Key instruction IDs
    uint64_t estimated_start = 0;         // First inst_id of this algorithm
    uint64_t estimated_end = 0;           // Last inst_id
};

// ─── Algorithm summary result ─────────────────────────────────────────────

struct AlgorithmSummaryResult {
    /// Detected algorithms sorted by confidence (descending).
    std::vector<AlgorithmCandidate> candidates;

    /// Natural language summary in Markdown.
    std::string summary_text;

    /// Structured JSON version of the summary.
    nlohmann::json summary_json;

    // ─── Query helpers ──────────────────────────────────────────────────

    /// Return the top-N algorithms by confidence.
    std::vector<const AlgorithmCandidate*> top_algorithms(size_t n) const {
        std::vector<const AlgorithmCandidate*> result;
        size_t count = std::min(n, candidates.size());
        result.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            result.push_back(&candidates[i]);
        }
        return result;
    }

    /// Whether any candidate is crypto-related (confidence > 0).
    bool has_crypto() const { return !candidates.empty(); }

    /// Total number of detected algorithm candidates.
    size_t total() const { return candidates.size(); }
};

// ─── Algorithm summary pass ───────────────────────────────────────────────

/// Synthesizes a human-readable algorithm summary from all available
/// analysis results.  This is the "big picture" pass — it answers
/// "what algorithms does this trace contain?" by cross-referencing
/// pattern matches, known constants, loop semantics, function analysis,
/// and call graph data.
///
/// All dependencies are soft/optional: the pass degrades gracefully when
/// any of them is unavailable.
///
/// Result type: AlgorithmSummaryResult
class AlgorithmSummaryPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "algorithm_summary"; }
    std::string_view description() const override {
        return "Synthesize algorithm summary from pattern, constant, loop, "
               "function, and call-graph analysis";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"pattern", "constant_materialization", "loop_semantics",
                "function", "call_graph"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }
};

}  // namespace tenet

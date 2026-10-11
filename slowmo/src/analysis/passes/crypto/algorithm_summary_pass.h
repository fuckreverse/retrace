#pragma once

#include <algorithm>

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

namespace tenet {

// ─── Algorithm family (structured evidence-merge key) ─────────────────────
//
// Evidence for a candidate algorithm comes from three independent detectors
// (pattern names like "AES instruction (aese)", known-constant algorithm
// tags like "SHA-256", and loop-structure hints like "SPN-based cipher")
// that each spell out algorithm names differently. Cross-referencing them
// used to rely on ad-hoc substring matching (`name.find("AES")`), which is
// both fragile (breaks silently if a detector's wording changes) and
// order-dependent (merge only tried const→loop, never pattern→const).
//
// AlgorithmFamily gives every detector a single normalized enum to tag its
// evidence with; merging then becomes an O(1) map lookup keyed by
// (family, specific_name) instead of repeated substring scans. `Unknown`
// means "no structured family recognized" — such evidence still keeps its
// original free-form name and is reported standalone (this preserves the
// old graceful-degradation behavior for anything not in the table below).
enum class AlgorithmFamily : uint8_t {
    Unknown = 0,
    AES,
    DES,
    Blowfish,
    Camellia,
    TEA,
    SM4,
    Serpent,
    ChaCha,
    Salsa,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    MD5,
    SM3,
    RIPEMD160,
    Whirlpool,
    HMAC,
    Poly1305,
    SipHash,
    CRC32,
    ZUC,
    ECDSA,
    Ed25519,
    Curve25519,
    GCM,
};

/// Human-readable canonical name for a family (used as the final candidate
/// name so pattern/constant/loop evidence about the same algorithm always
/// renders under one heading, regardless of which detector phrased it how).
const char* algorithm_family_name(AlgorithmFamily f);

/// Broad structural shape a family belongs to (Feistel/SPN/ARX round
/// function), used to cross-reference loop_semantics' LoopKind classification
/// against a specific named algorithm. Returns Unknown for families with no
/// well-known iterated-round structure (e.g. hash functions like SHA are SPN-
/// like at the compression-function level but are intentionally left out —
/// loop_semantics does not attempt to classify them and mapping them here
/// would just create false merge opportunities).
enum class AlgorithmStructure : uint8_t { Unknown = 0, Feistel, SPN, ARX };
AlgorithmStructure algorithm_family_structure(AlgorithmFamily f);

/// Normalize a free-form algorithm/detector name (as produced by
/// ConstantMaterializationResult::by_algorithm keys, PatternMatch::pattern_name,
/// or a loop_kind_algorithm_hint() string) into a structured family tag.
/// Returns AlgorithmFamily::Unknown if the text doesn't match any known
/// family — callers should keep treating such evidence by its original name.
AlgorithmFamily normalize_algorithm_name(std::string_view text);

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

    /// Structured family this candidate was recognized as, or Unknown for
    /// free-form names with no normalized match (e.g. "Hot function: sub_1234",
    /// "XOR loop"). Serialized/exposed so downstream consumers (GUI, MCP) can
    /// group/filter/icon candidates without re-parsing `name`.
    AlgorithmFamily family = AlgorithmFamily::Unknown;

    /// True if this candidate's only evidence is the weak "hot function"
    /// call-count heuristic (no pattern/constant/loop corroboration). Such
    /// candidates are inherently speculative — surfaced explicitly instead of
    /// silently blending into the same list as verified matches.
    bool is_speculative = false;
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

    /// Candidates backed by real evidence (pattern/constant/loop), excluding
    /// speculative hot-function-only guesses. This is what most callers
    /// (summary headline, "has_crypto"-style checks) should look at first.
    std::vector<const AlgorithmCandidate*> confirmed_candidates() const {
        std::vector<const AlgorithmCandidate*> out;
        for (const auto& c : candidates) {
            if (!c.is_speculative) out.push_back(&c);
        }
        return out;
    }
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
        // constant_materialization was merged into pattern (see PatternResult::constants).
        return {"pattern", "loop_semantics", "function", "call_graph"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }

    // ─── Hot-function heuristic tuning ────────────────────────────────────
    //
    // The "hot function" detector (Phase 1d) flags call_graph callees with
    // no other corroborating evidence as *speculative* crypto-core hints.
    // It is the weakest signal this pass produces (any frequently-called
    // utility — memcpy, allocators, string helpers — looks identical to a
    // hot cipher round from call-count alone), so two knobs bound how
    // aggressively it fires:
    //
    //   - min_calls: absolute floor (a function must be called at least
    //     this many times to even be considered).
    //   - min_ratio_of_max: relative floor, as a fraction of the single
    //     hottest callee's call count. A function that is only "kind of
    //     busy" relative to the true hot spot in this trace is far less
    //     interesting than one that's comparably hot — this makes the
    //     detector self-calibrating across traces with very different
    //     absolute call volumes instead of relying on one fixed constant.
    void set_hot_function_min_calls(uint64_t n) { hot_function_min_calls_ = n; }
    void set_hot_function_min_ratio(float r) { hot_function_min_ratio_ = r; }

private:
    uint64_t hot_function_min_calls_ = 25;      // was a fixed "< 10 => skip"
    float    hot_function_min_ratio_ = 0.20f;   // must be >= 20% of the hottest callee
};

}  // namespace tenet

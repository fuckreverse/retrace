#pragma once

#include "analysis/pass_manager.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/objc_pass.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace tenet {

// ─── ObjC call frame ─────────────────────────────────────────────────────

/// A single frame in an ObjC call stack at the moment a crypto pattern fired.
struct ObjcCallFrame {
    uint64_t inst_id;           // inst_id of the ObjC message
    uint64_t objc_pc;           // PC of the objc_msgSend call
    std::string class_name;     // receiver class
    std::string selector_name;  // selector
    uint64_t receiver;          // receiver object address
};

// ─── ObjC × Pattern correlation entry ─────────────────────────────────────

/// A crypto/anti-debug pattern that was found inside an ObjC call chain.
/// Binds a PatternMatch to the ObjC call context it was discovered in.
struct ObjcCryptoHit {
    // ── Pattern side ───────────────────────────────────────────────────
    std::string pattern_name;
    PatternCategory category;
    PatternConfidence confidence;
    uint64_t pattern_start_inst;
    uint64_t pattern_end_inst;
    uint64_t anchor_pc;
    std::string description;

    // ── ObjC call stack at the time of the pattern ─────────────────────
    // Frames ordered from outermost (first ObjC call before the pattern)
    // to innermost (closest ObjC call before the pattern).
    // May be empty if the pattern was not inside any ObjC dispatch.
    std::vector<ObjcCallFrame> objc_stack;

    /// The innermost (deepest) ObjC frame — the direct ObjC entry into the
    /// code where the pattern fired.
    const ObjcCallFrame* innermost_frame() const {
        if (objc_stack.empty()) return nullptr;
        return &objc_stack.back();
    }

    /// Human-readable summary of the ObjC chain.
    /// e.g. "[CryptoEngine signWithKey:] → [HashHelper computeDigest:]"
    std::string objc_chain_summary() const;
};

// ─── ObjcCryptoResult ─────────────────────────────────────────────────────

struct ObjcCryptoResult {
    /// All correlation hits, ordered by pattern_start_inst.
    std::vector<ObjcCryptoHit> hits;

    /// Patterns not inside any ObjC call (bare algorithm functions).
    std::vector<size_t> bare_pattern_indices;   // indices into hits

    /// Patterns that ARE inside ObjC calls.
    std::vector<size_t> objc_pattern_indices;   // indices into hits

    // Index: ObjC selector_name → hit indices for quick lookup
    std::unordered_map<std::string, std::vector<size_t>> by_selector;

    // Index: class_name → hit indices
    std::unordered_map<std::string, std::vector<size_t>> by_class;

    /// Total hits.
    size_t total() const { return hits.size(); }

    /// Hits inside ObjC calls.
    size_t in_objc_count() const { return objc_pattern_indices.size(); }

    /// Hits without ObjC context.
    size_t bare_count() const { return bare_pattern_indices.size(); }

    /// Serialize to JSON string.
    std::string to_json() const;
};

// ─── ObjcCryptoPass ───────────────────────────────────────────────────────

/// Correlates crypto / anti-debug / pattern hits (from PatternPass) with the
/// ObjC call stack at the moment they occur (from ObjcPass).
///
/// This answers the critical iOS reverse engineering question:
/// "Which ObjC method chain leads to this crypto algorithm?"
///
/// For each PatternMatch, this pass finds the most recent ObjC message(s)
/// before the pattern's start_inst_id and builds a call stack annotation.
///
/// The ObjC "call stack" is reconstructed from the ordered ObjC message
/// list in ObjcResult: messages before the pattern with decreasing inst_id
/// are considered the call chain (the closest one is the innermost frame).
///
/// Result type: ObjcCryptoResult
class ObjcCryptoPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "objc_crypto"; }
    std::string_view description() const override {
        return "Correlate crypto/pattern hits with ObjC call stack context";
    }

    std::vector<std::string_view> dependencies() const override {
        return {"pattern", "objc"};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 2.0f; }

    /// Maximum number of ObjC frames to include in the call stack.
    /// Default: 8 (innermost 8 ObjC frames before the pattern).
    void set_max_stack_depth(uint32_t depth) { max_stack_depth_ = depth; }

    /// Maximum instruction gap to look back for ObjC context.
    /// If the nearest ObjC message is further back than this many instructions,
    /// the pattern is considered "bare" (not in ObjC context).
    /// Default: 500000 (allows for deep algorithm bodies).
    void set_max_lookback(uint64_t lookback) { max_lookback_ = lookback; }

private:
    uint32_t max_stack_depth_ = 8;
    uint64_t max_lookback_    = 500000;
};

}  // namespace tenet

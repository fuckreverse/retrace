#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "io/index_builder.h"
#include "common/byte_codec.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── AlgorithmFamily: canonical name / structure / normalization ───────────

const char* algorithm_family_name(AlgorithmFamily f) {
    switch (f) {
        case AlgorithmFamily::AES:        return "AES";
        case AlgorithmFamily::DES:        return "DES";
        case AlgorithmFamily::Blowfish:   return "Blowfish";
        case AlgorithmFamily::Camellia:   return "Camellia";
        case AlgorithmFamily::TEA:        return "TEA";
        case AlgorithmFamily::SM4:        return "SM4";
        case AlgorithmFamily::Serpent:    return "Serpent";
        case AlgorithmFamily::ChaCha:     return "ChaCha20";
        case AlgorithmFamily::Salsa:      return "Salsa20";
        case AlgorithmFamily::SHA1:       return "SHA-1";
        case AlgorithmFamily::SHA256:     return "SHA-256";
        case AlgorithmFamily::SHA384:     return "SHA-384";
        case AlgorithmFamily::SHA512:     return "SHA-512";
        case AlgorithmFamily::MD5:        return "MD5";
        case AlgorithmFamily::SM3:        return "SM3";
        case AlgorithmFamily::RIPEMD160:  return "RIPEMD-160";
        case AlgorithmFamily::Whirlpool:  return "Whirlpool";
        case AlgorithmFamily::HMAC:       return "HMAC";
        case AlgorithmFamily::Poly1305:   return "Poly1305";
        case AlgorithmFamily::SipHash:    return "SipHash";
        case AlgorithmFamily::CRC32:      return "CRC32";
        case AlgorithmFamily::ZUC:        return "ZUC";
        case AlgorithmFamily::ECDSA:      return "ECDSA-P256";
        case AlgorithmFamily::Ed25519:    return "Ed25519";
        case AlgorithmFamily::Curve25519: return "Curve25519";
        case AlgorithmFamily::GCM:        return "GCM";
        case AlgorithmFamily::Unknown:    break;
    }
    return "Unknown";
}

AlgorithmStructure algorithm_family_structure(AlgorithmFamily f) {
    switch (f) {
        // SPN (substitution-permutation network): fixed-width state,
        // S-box + permutation/mix-column rounds.
        case AlgorithmFamily::AES:
        case AlgorithmFamily::SM4:
        case AlgorithmFamily::Serpent:
            return AlgorithmStructure::SPN;
        // Feistel: state split in half, one half updated per round via a
        // round function keyed on the other half.
        case AlgorithmFamily::DES:
        case AlgorithmFamily::Blowfish:
        case AlgorithmFamily::Camellia:
        case AlgorithmFamily::TEA:
            return AlgorithmStructure::Feistel;
        // ARX (add-rotate-xor): stream ciphers built purely from those three
        // operations, no table lookups.
        case AlgorithmFamily::ChaCha:
        case AlgorithmFamily::Salsa:
            return AlgorithmStructure::ARX;
        default:
            return AlgorithmStructure::Unknown;
    }
}

namespace {

/// Case-insensitive substring test (small strings only — this runs at most
/// once per accumulator entry per pass invocation, not per-instruction).
bool ci_contains(std::string_view haystack, std::string_view needle) {
    if (needle.size() > haystack.size()) return false;
    auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (lower(haystack[i + j]) != lower(needle[j])) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

}  // namespace

AlgorithmFamily normalize_algorithm_name(std::string_view text) {
    // Order matters where one name is a substring of another's detector
    // wording (e.g. must check "SHA-256"/"SHA256" before the bare "SHA"
    // that could ambiguously prefix several digest sizes). Every entry here
    // corresponds 1:1 to a name that actually appears in either the known-
    // constant database (pattern_pass.cpp) or a loop_kind_algorithm_hint()
    // string, so this table only needs to grow when those do.
    struct Rule { const char* needle; AlgorithmFamily family; };
    static constexpr Rule kRules[] = {
        {"SHA-256", AlgorithmFamily::SHA256}, {"SHA256", AlgorithmFamily::SHA256},
        {"SHA-384", AlgorithmFamily::SHA384}, {"SHA384", AlgorithmFamily::SHA384},
        {"SHA-512", AlgorithmFamily::SHA512}, {"SHA512", AlgorithmFamily::SHA512},
        {"SHA-1",   AlgorithmFamily::SHA1},   {"SHA1",   AlgorithmFamily::SHA1},
        {"RIPEMD-160", AlgorithmFamily::RIPEMD160}, {"RIPEMD160", AlgorithmFamily::RIPEMD160},
        {"MD5",       AlgorithmFamily::MD5},
        {"SM3",       AlgorithmFamily::SM3},
        {"SM4",       AlgorithmFamily::SM4},
        {"AES",       AlgorithmFamily::AES},
        {"Serpent",   AlgorithmFamily::Serpent},
        {"Blowfish",  AlgorithmFamily::Blowfish},
        {"Camellia",  AlgorithmFamily::Camellia},
        {"TEA",       AlgorithmFamily::TEA},
        {"DES",       AlgorithmFamily::DES},  // after Blowfish/Camellia (no overlap, but keep DES generic-last)
        {"ChaCha",    AlgorithmFamily::ChaCha},
        {"Salsa",     AlgorithmFamily::Salsa},
        {"Whirlpool", AlgorithmFamily::Whirlpool},
        {"HMAC",      AlgorithmFamily::HMAC},
        {"Poly1305",  AlgorithmFamily::Poly1305},
        {"SipHash",   AlgorithmFamily::SipHash},
        {"CRC32",     AlgorithmFamily::CRC32},
        {"ZUC",       AlgorithmFamily::ZUC},
        {"ECDSA",     AlgorithmFamily::ECDSA},
        {"Ed25519",   AlgorithmFamily::Ed25519},
        {"Curve25519",AlgorithmFamily::Curve25519},
        {"GCM",       AlgorithmFamily::GCM},
    };
    for (const auto& r : kRules) {
        if (ci_contains(text, r.needle)) return r.family;
    }
    return AlgorithmFamily::Unknown;
}

// ─── AlgorithmSummaryResult serialization helpers ─────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x414C474F ("ALGO")
//   u32  version = 2
//   u32  summary_text_len
//   u8[] summary_text
//   u32  summary_json_len
//   u8[] summary_json (JSON string)
//   u64  num_candidates
//   for each AlgorithmCandidate:
//     u32  name_len; u8[] name
//     f32  confidence
//     u32  evidence_len; u8[] evidence
//     u64  estimated_start, estimated_end
//     u64  num_key_pcs; u64[] key_pcs
//     u64  num_key_inst_ids; u64[] key_inst_ids
//     u8   family           (v2+)
//     u8   is_speculative   (v2+)

namespace {

static constexpr uint32_t ALGO_BLOB_MAGIC   = 0x414C474Fu;  // "ALGO"
// v1: original format.
// v2: adds per-candidate `family` (u8) and `is_speculative` (u8) fields,
//     written right after key_inst_ids. Old v1 blobs are still readable
//     (just missing those two fields, which default to Unknown/false) so a
//     stale cache from before this change doesn't need to be invalidated.
static constexpr uint32_t ALGO_BLOB_VERSION = 2u;

std::string algorithm_summary_serialize(const AlgorithmSummaryResult& res) {
    // Pre-compute json string
    std::string json_str = res.summary_json.dump();

    ByteWriter w;

    w.u32(ALGO_BLOB_MAGIC);
    w.u32(ALGO_BLOB_VERSION);
    w.str(res.summary_text);
    w.str(json_str);

    w.u64(static_cast<uint64_t>(res.candidates.size()));
    for (const auto& c : res.candidates) {
        w.str(c.name);
        w.f32(c.confidence);
        w.str(c.evidence);
        w.u64(c.estimated_start);
        w.u64(c.estimated_end);
        w.u64(static_cast<uint64_t>(c.key_pcs.size()));
        for (uint64_t pc : c.key_pcs) w.u64(pc);
        w.u64(static_cast<uint64_t>(c.key_inst_ids.size()));
        for (uint64_t id : c.key_inst_ids) w.u64(id);
        w.u8(static_cast<uint8_t>(c.family));
        w.u8(c.is_speculative ? 1 : 0);
    }

    return std::move(w).take();
}

bool algorithm_summary_deserialize(const std::string& blob, AlgorithmSummaryResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != ALGO_BLOB_MAGIC) return false;
    uint32_t version = r.u32();
    if (version != 1u && version != 2u) return false;

    if (!r.str(out.summary_text)) return false;

    std::string json_str;
    if (!r.str(json_str)) return false;
    try {
        out.summary_json = nlohmann::json::parse(json_str);
    } catch (...) {
        return false;
    }

    uint64_t n_cands = r.u64();
    out.candidates.reserve(static_cast<size_t>(n_cands));
    for (uint64_t i = 0; i < n_cands; i++) {
        AlgorithmCandidate c;
        if (!r.str(c.name)) return false;
        c.confidence = r.f32();
        if (!r.str(c.evidence)) return false;
        c.estimated_start = r.u64();
        c.estimated_end   = r.u64();

        uint64_t n_pcs = r.u64();
        c.key_pcs.resize(static_cast<size_t>(n_pcs));
        for (uint64_t j = 0; j < n_pcs; j++) c.key_pcs[j] = r.u64();

        uint64_t n_ids = r.u64();
        c.key_inst_ids.resize(static_cast<size_t>(n_ids));
        for (uint64_t j = 0; j < n_ids; j++) c.key_inst_ids[j] = r.u64();

        if (version >= 2u) {
            c.family = static_cast<AlgorithmFamily>(r.u8());
            c.is_speculative = r.u8() != 0;
        }

        out.candidates.push_back(std::move(c));
    }

    return r.ok();
}

}  // anonymous namespace (algo serialization)

namespace {

// ─── Internal evidence accumulator ────────────────────────────────────────

/// Collects evidence pieces for a single algorithm candidate during analysis.
///
/// Merge key: an accumulator is keyed by family_key()/raw_key()/structure_key()
/// (see below). When `family` is recognized (!= Unknown), *all* evidence for
/// that family collapses into ONE accumulator regardless of which detector
/// (pattern/constant/loop) produced it or how it phrased the name, because
/// the key no longer depends on exact string equality. This replaces the old
/// two-pass "loop_keys vs const_keys substring scan": merging now happens
/// automatically during accumulation (Phase 1) instead of as a separate
/// cross-referencing pass (old Phase 2).
struct EvidenceAccumulator {
    std::string algorithm_name;                // display name (family canonical name, or raw name if Unknown)
    AlgorithmFamily family = AlgorithmFamily::Unknown;
    bool is_speculative = true;                // cleared by any non-hot-function evidence
    float confidence = 0.0f;
    std::vector<std::string> evidence_lines;
    std::vector<uint64_t> pcs;
    std::vector<uint64_t> inst_ids;
    uint64_t min_inst_id = UINT64_MAX;
    uint64_t max_inst_id = 0;

    /// Add real (non-speculative) evidence — pattern match, known constant,
    /// or classified loop. Clears `is_speculative` since this is stronger
    /// than a bare call-count hint.
    void add_evidence(std::string line, float boost) {
        evidence_lines.push_back(std::move(line));
        confidence = std::min(1.0f, confidence + boost);
        is_speculative = false;
    }

    /// Add hot-function evidence specifically — kept speculative (does NOT
    /// clear is_speculative) so a candidate whose *only* evidence is call
    /// count stays flagged as such even after this call.
    void add_speculative_evidence(std::string line, float boost) {
        evidence_lines.push_back(std::move(line));
        confidence = std::min(1.0f, confidence + boost);
    }

    void add_pc(uint64_t pc) {
        pcs.push_back(pc);
    }

    void add_inst_range(uint64_t start, uint64_t end) {
        if (start < min_inst_id) min_inst_id = start;
        if (end > max_inst_id) max_inst_id = end;
        inst_ids.push_back(start);
        if (end != start) inst_ids.push_back(end);
    }

    AlgorithmCandidate build() const {
        AlgorithmCandidate c;
        c.name = algorithm_name;
        c.family = family;
        c.is_speculative = is_speculative;
        c.confidence = std::min(1.0f, confidence);
        c.key_pcs = pcs;
        c.key_inst_ids = inst_ids;
        c.estimated_start = (min_inst_id == UINT64_MAX) ? 0 : min_inst_id;
        c.estimated_end = max_inst_id;

        // Build human-readable evidence string
        std::string ev;
        for (size_t i = 0; i < evidence_lines.size(); ++i) {
            if (i > 0) ev += "; ";
            ev += evidence_lines[i];
        }
        c.evidence = std::move(ev);
        return c;
    }
};

// ─── Map loop kind to a broad algorithm family ────────────────────────────

const char* loop_kind_algorithm_hint(LoopKind k) {
    switch (k) {
        case LoopKind::FeistelRound: return "Feistel-based cipher";
        case LoopKind::SPNRound:     return "SPN-based cipher";
        case LoopKind::ARXRound:     return "ARX-based cipher";
        default:                     return nullptr;
    }
}

/// Map a LoopKind directly to the AlgorithmStructure it corresponds to, for
/// merge-key purposes. Kept separate from loop_kind_algorithm_hint()
/// (display text) so the merge logic doesn't need to re-parse that string.
AlgorithmStructure loop_kind_structure(LoopKind k) {
    switch (k) {
        case LoopKind::FeistelRound: return AlgorithmStructure::Feistel;
        case LoopKind::SPNRound:     return AlgorithmStructure::SPN;
        case LoopKind::ARXRound:     return AlgorithmStructure::ARX;
        default:                     return AlgorithmStructure::Unknown;
    }
}

// ─── Confidence-level label ───────────────────────────────────────────────

const char* confidence_label(float c) {
    if (c >= 0.9f) return "Very High";
    if (c >= 0.7f) return "High";
    if (c >= 0.5f) return "Medium";
    if (c >= 0.3f) return "Low";
    return "Very Low";
}

// ─── Merge-key helpers ─────────────────────────────────────────────────────
//
// Two kinds of accumulator keys:
//   - "family:<N>"  for evidence normalized to a recognized family — the
//                     numeric family id IS the identity, so differently-
//                     worded evidence about the same algorithm (a pattern
//                     match, a known constant, an SPN-loop hint) always
//                     lands in the same bucket.
//   - "raw:<text>"  fallback for anything normalize_algorithm_name() doesn't
//                     recognize (unnamed loops, hot-function hints, etc.) —
//                     preserves the old "group by exact name" behavior.
//
// A `structure`-only key ("structure:<S>") holds an as-yet-unnamed loop of a
// given shape so a same-shape named family arriving later can still find it.

std::string family_key(AlgorithmFamily f) {
    return fmt::format("family:{}", static_cast<int>(f));
}

std::string raw_key(std::string_view text) {
    return fmt::format("raw:{}", text);
}

std::string structure_key(AlgorithmStructure s) {
    return fmt::format("structure:{}", static_cast<int>(s));
}

}  // anonymous namespace

// ─── AlgorithmSummaryPass::run ────────────────────────────────────────────

PassResult AlgorithmSummaryPass::run(PassContext& ctx) {
    auto& index = ctx.index();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("algorithm_summary", blob)) {
            AlgorithmSummaryResult cached;
            if (algorithm_summary_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "Algorithm summary: {} candidate(s) (from cache)",
                    cached.candidates.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    ctx.progress(0.0f, "Algorithm summary: collecting evidence...");

    // ── Soft-require all dependencies ────────────────────────────────────
    // Each dependency is optional; we degrade gracefully.

    const auto& pattern_raw    = ctx.require_raw("pattern");
    const auto& loop_sem_raw   = ctx.require_raw("loop_semantics");
    const auto& function_raw   = ctx.require_raw("function");
    const auto& call_graph_raw = ctx.require_raw("call_graph");

    const PatternResult* pattern_res = nullptr;
    // Constant-materialization data now lives inside PatternResult::constants
    // (the standalone constant_materialization pass was merged into pattern).
    const ConstantMaterializationResult* const_res = nullptr;
    const LoopSemanticsResult* loop_res = nullptr;
    const FunctionResult* func_res = nullptr;
    const CallGraphResult* cg_res = nullptr;

    if (pattern_raw.ok()) {
        pattern_res = &pattern_raw.get<PatternResult>();
        const_res   = &pattern_res->constants;
    }
    if (loop_sem_raw.ok())   loop_res = &loop_sem_raw.get<LoopSemanticsResult>();
    if (function_raw.ok())   func_res = &function_raw.get<FunctionResult>();
    if (call_graph_raw.ok()) cg_res   = &call_graph_raw.get<CallGraphResult>();

    // ── Phase 1: Accumulate per-algorithm evidence ───────────────────────
    //
    // Key: family_key(family) when normalize_algorithm_name() recognizes the
    // evidence's name, else raw_key(original name). Because the key is
    // derived from the SAME normalization function for pattern matches,
    // known constants, AND loop hints, evidence about the same algorithm
    // always converges on one accumulator as it streams in — no separate
    // cross-referencing pass is needed afterwards (contrast with the old
    // Phase 2 substring-matching pass this replaces).
    ankerl::unordered_dense::map<std::string, EvidenceAccumulator> accum;
    // structure → key of an accumulator holding an as-yet-unnamed loop of
    // that shape (e.g. "SPN-based cipher" with no matching named family
    // yet). Lets a later-arriving named constant/pattern find and absorb it
    // in O(1) instead of the old O(loops × consts) nested keyword scan.
    ankerl::unordered_dense::map<AlgorithmStructure, std::string> unnamed_structure_keys;

    // Get-or-create the accumulator for a recognized family, seeding its
    // display name from algorithm_family_name() on first use.
    auto get_family_accum = [&](AlgorithmFamily fam) -> EvidenceAccumulator& {
        auto& a = accum[family_key(fam)];
        if (a.algorithm_name.empty()) {
            a.algorithm_name = algorithm_family_name(fam);
            a.family = fam;
        }
        return a;
    };

    // Get-or-create the accumulator for an unrecognized/free-form name.
    auto get_raw_accum = [&](const std::string& display_name) -> EvidenceAccumulator& {
        auto& a = accum[raw_key(display_name)];
        if (a.algorithm_name.empty()) a.algorithm_name = display_name;
        return a;
    };

    // Route evidence for `raw_name` to the right accumulator: if it
    // normalizes to a known family, use/create that family's accumulator
    // (merging with anything already found for it); otherwise fall back to
    // a raw-name bucket so ungrouped evidence still degrades gracefully to
    // the old "one bucket per exact name" behavior.
    auto route = [&](const std::string& raw_name) -> EvidenceAccumulator& {
        AlgorithmFamily fam = normalize_algorithm_name(raw_name);
        if (fam != AlgorithmFamily::Unknown) return get_family_accum(fam);
        return get_raw_accum(raw_name);
    };

    ctx.progress(0.1f, "Algorithm summary: processing pattern matches...");

    // ── 1a. Pattern matches ──────────────────────────────────────────────
    if (pattern_res) {
        for (const auto& m : pattern_res->matches) {
            if (m.category != PatternCategory::Crypto &&
                m.category != PatternCategory::KeySchedule)
                continue;

            // Pattern names are like "AES instruction (aese)", "Known
            // constant: SHA256_H0 (SHA-256)", "XOR loop" — route() extracts
            // a family if one is embedded, else groups by the literal name
            // (e.g. distinct "XOR loop" occurrences all share one bucket,
            // same as before).
            auto& ea = route(m.pattern_name);

            std::string conf_str;
            switch (m.confidence) {
                case PatternConfidence::High:   conf_str = "high"; break;
                case PatternConfidence::Medium: conf_str = "medium"; break;
                case PatternConfidence::Low:    conf_str = "low"; break;
            }
            ea.add_evidence(
                fmt::format("Pattern match \"{}\" ({} confidence)", m.pattern_name, conf_str),
                (m.confidence == PatternConfidence::High)   ? 0.40f :
                (m.confidence == PatternConfidence::Medium) ? 0.25f : 0.10f);
            ea.add_pc(m.anchor_pc);
            ea.add_inst_range(m.start_inst_id, m.end_inst_id);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.3f, "Algorithm summary: processing constants...");

    // ── 1b. Known constants ──────────────────────────────────────────────
    if (const_res) {
        for (const auto& [algo_name, indices] : const_res->by_algorithm) {
            // Count how many distinct known constants for this algorithm
            // first, so we can skip routing/creating an accumulator entirely
            // when there's nothing to report.
            size_t known_count = 0;
            for (size_t idx : indices) {
                if (const_res->constants[idx].known_match) ++known_count;
            }
            if (known_count == 0) continue;

            // algo_name here is already a canonical name from pattern_pass's
            // KnownConstant database (e.g. "SHA-256", "AES") — route() will
            // normalize it to the matching AlgorithmFamily so this merges
            // with any pattern-match evidence for the same family.
            auto& ea = route(algo_name);
            for (size_t idx : indices) {
                const auto& mc = const_res->constants[idx];
                if (!mc.known_match) continue;
                ea.add_pc(mc.pc_first);
                ea.add_inst_range(mc.first_inst_id, mc.last_inst_id);
            }
            ea.add_evidence(
                fmt::format("{} known {} constant(s) identified", known_count, algo_name),
                std::min(0.45f, static_cast<float>(known_count) * 0.10f));
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.5f, "Algorithm summary: processing loop semantics...");

    // ── 1c. Crypto loops ─────────────────────────────────────────────────
    //
    // A loop's LoopKind (Feistel/SPN/ARX) only identifies a *structural
    // shape*, not a specific algorithm — many algorithms share a shape
    // (AES/SM4/Serpent are all SPN). So a classified loop never resolves to
    // a family on its own; instead it either (a) merges into an
    // *already-named* accumulator whose family has that same structure
    // (evidence from 1a/1b has already run by this point), or (b)
    // starts/extends a structure-keyed "unnamed loop" bucket.
    if (loop_res) {
        auto crypto = loop_res->crypto_loops();
        for (const auto* ls : crypto) {
            AlgorithmStructure structure = loop_kind_structure(ls->kind);
            const char* hint = loop_kind_algorithm_hint(ls->kind);
            std::string display = hint ? std::string(hint) : "Unknown crypto loop";
            std::string evidence_line = fmt::format(
                "{} at PC {:#x} ({} iterations, confidence {:.0f}%)",
                loop_kind_name(ls->kind), ls->header_pc,
                ls->iteration_count, ls->confidence * 100.0f);
            float boost = ls->confidence * 0.30f;

            // (a) Is there already a named accumulator whose family matches
            // this loop's structure? If so, this loop IS that algorithm's
            // round function — merge directly instead of creating a
            // separate "SPN-based cipher" bucket next to e.g. "AES".
            EvidenceAccumulator* target = nullptr;
            if (structure != AlgorithmStructure::Unknown) {
                for (auto& [key, ea] : accum) {
                    if (ea.family != AlgorithmFamily::Unknown &&
                        algorithm_family_structure(ea.family) == structure) {
                        target = &ea;
                        break;
                    }
                }
            }
            if (target) {
                target->add_evidence(std::move(evidence_line), boost);
                target->add_pc(ls->header_pc);
                if (ls->sample_iter_start != 0) {
                    target->add_inst_range(ls->sample_iter_start, ls->sample_iter_end);
                }
                target->add_evidence(
                    "Cross-referenced: loop structure matches constant/pattern identification",
                    0.15f);
                continue;
            }

            // (b) No named match — accumulate under a structure-keyed or raw
            // bucket so multiple loops of the same unnamed shape still merge
            // together.
            std::string key = (structure != AlgorithmStructure::Unknown)
                ? unnamed_structure_keys.try_emplace(structure, structure_key(structure)).first->second
                : raw_key(display);
            auto& ea = accum[key];
            if (ea.algorithm_name.empty()) ea.algorithm_name = display;
            ea.add_evidence(std::move(evidence_line), boost);
            ea.add_pc(ls->header_pc);
            if (ls->sample_iter_start != 0) {
                ea.add_inst_range(ls->sample_iter_start, ls->sample_iter_end);
            }
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.6f, "Algorithm summary: processing call graph...");

    // ── 1d. Hot functions from call graph (speculative corroborating hint) ─
    //
    // This is deliberately the weakest signal the pass produces: any
    // frequently-called utility (memcpy, allocators, string helpers) looks
    // identical to a hot cipher round purely from call count. Two guards
    // bound false positives (see set_hot_function_min_calls/min_ratio doc in
    // the header): an absolute floor AND a floor relative to this trace's
    // single hottest callee, so the detector self-calibrates instead of
    // using one fixed constant across traces with wildly different call
    // volumes. Matches are also explicitly flagged `is_speculative` (see
    // EvidenceAccumulator) rather than silently blending into the same
    // confidence pool as verified pattern/constant/loop evidence.
    if (cg_res) {
        auto hot = cg_res->hottest_callees(10);

        // Pre-index every PC already attributed to real evidence, once, in
        // O(total_pcs) — replaces the old O(hot × accum × pcs_per_accum)
        // nested scan that ran once per candidate hot PC.
        ankerl::unordered_dense::set<uint64_t> known_pcs;
        for (const auto& [key, ea] : accum) {
            for (uint64_t pc : ea.pcs) known_pcs.insert(pc);
        }

        uint64_t max_calls = hot.empty() ? 0 : hot.front().second;
        uint64_t ratio_floor = static_cast<uint64_t>(
            static_cast<float>(max_calls) * hot_function_min_ratio_);

        for (const auto& [pc, call_count] : hot) {
            if (call_count < hot_function_min_calls_) continue;
            if (call_count < ratio_floor) continue;
            // Root pseudo-nodes (synthetic "unknown outer caller" entries,
            // see call_graph_is_root_key()) are never real callees — skip
            // defensively in case one ever surfaces here (their
            // total_calls_received is always 0 in practice, but this guards
            // against misinterpreting a tagged call-site PC as a real
            // function address).
            if (call_graph_is_root_key(pc)) continue;
            if (known_pcs.contains(pc)) continue;

            // Try to get the function name
            std::string fname;
            auto node = cg_res->node_at(pc);
            if (node) fname = node->name;
            if (fname.empty()) fname = fmt::format("sub_{:x}", pc);

            auto& ea = get_raw_accum(fmt::format("Hot function: {}", fname));
            ea.add_speculative_evidence(
                fmt::format("Function {} called {} times (potential crypto core, "
                            "speculative — no corroborating pattern/constant/loop evidence)",
                            fname, call_count),
                0.10f);
            ea.add_pc(pc);
            known_pcs.insert(pc);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.8f, "Algorithm summary: building results...");

    // ── Phase 2: Build final candidates ──────────────────────────────────
    //
    // No separate cross-referencing pass here anymore — merging already
    // happened as evidence streamed in during Phase 1 (see `route()` and the
    // loop-structure lookup in 1c above).

    AlgorithmSummaryResult result;

    for (const auto& [key, ea] : accum) {
        // Filter out very low confidence un-attributed hot functions
        if (ea.confidence < 0.05f) continue;

        result.candidates.push_back(ea.build());
    }

    // Sort by confidence descending, then by name for stability
    std::sort(result.candidates.begin(), result.candidates.end(),
              [](const AlgorithmCandidate& a, const AlgorithmCandidate& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  return a.name < b.name;
              });

    // ── Phase 3: Generate Markdown summary ───────────────────────────────
    ctx.progress(0.85f, "Algorithm summary: generating report...");

    std::string md;
    md += "## Detected Algorithms\n\n";

    if (result.candidates.empty()) {
        md += "No algorithms were detected with sufficient confidence.\n\n";

        // Report which data sources were available
        md += "### Data Sources\n\n";
        md += fmt::format("- Pattern analysis: {}\n",
                          pattern_res ? fmt::format("{} matches", pattern_res->total()) : "unavailable");
        md += fmt::format("- Constant identification: {}\n",
                          const_res ? fmt::format("{} constants ({} identified)",
                                                  const_res->total(), const_res->identified_count())
                                    : "unavailable");
        md += fmt::format("- Loop semantics: {}\n",
                          loop_res ? fmt::format("{} loops analyzed", loop_res->loop_semantics.size())
                                   : "unavailable");
        md += fmt::format("- Function analysis: {}\n",
                          func_res ? fmt::format("{} functions", func_res->functions.size())
                                   : "unavailable");
        md += fmt::format("- Call graph: {}\n",
                          cg_res ? fmt::format("{} nodes, {} edges",
                                               cg_res->nodes.size(), cg_res->edges.size())
                                 : "unavailable");
    } else {
        for (size_t i = 0; i < result.candidates.size(); ++i) {
            const auto& c = result.candidates[i];
            md += fmt::format("{}. **{}**{} (confidence: {}% — {})\n",
                              i + 1, c.name,
                              c.is_speculative ? " *[speculative]*" : "",
                              static_cast<int>(c.confidence * 100.0f),
                              confidence_label(c.confidence));
            md += fmt::format("   - Evidence: {}\n", c.evidence);
            if (c.estimated_start != 0 || c.estimated_end != 0) {
                md += fmt::format("   - Trace range: inst {} – {}\n",
                                  c.estimated_start, c.estimated_end);
            }
            if (!c.key_pcs.empty()) {
                md += "   - Key PCs:";
                for (size_t j = 0; j < std::min(c.key_pcs.size(), size_t(8)); ++j) {
                    md += fmt::format(" {:#x}", c.key_pcs[j]);
                }
                if (c.key_pcs.size() > 8) {
                    md += fmt::format(" ... ({} more)", c.key_pcs.size() - 8);
                }
                md += "\n";
            }
            md += "\n";
        }
    }

    result.summary_text = std::move(md);

    // ── Phase 4: Generate structured JSON ────────────────────────────────
    ctx.progress(0.9f, "Algorithm summary: generating JSON...");

    nlohmann::json j;
    j["total_candidates"] = result.candidates.size();
    j["confirmed_candidates"] = result.confirmed_candidates().size();

    nlohmann::json j_candidates = nlohmann::json::array();
    for (const auto& c : result.candidates) {
        nlohmann::json jc;
        jc["name"] = c.name;
        jc["family"] = algorithm_family_name(c.family);
        jc["is_speculative"] = c.is_speculative;
        jc["confidence"] = c.confidence;
        jc["confidence_label"] = confidence_label(c.confidence);
        jc["evidence"] = c.evidence;
        jc["estimated_start"] = c.estimated_start;
        jc["estimated_end"] = c.estimated_end;

        nlohmann::json pcs = nlohmann::json::array();
        for (uint64_t pc : c.key_pcs) {
            pcs.push_back(fmt::format("{:#x}", pc));
        }
        jc["key_pcs"] = std::move(pcs);

        j_candidates.push_back(std::move(jc));
    }
    j["candidates"] = std::move(j_candidates);

    // Data source availability
    nlohmann::json sources;
    sources["pattern"]                  = pattern_res != nullptr;
    sources["constant_materialization"] = const_res   != nullptr;  // absorbed into pattern
    sources["loop_semantics"]           = loop_res    != nullptr;
    sources["function"]                 = func_res    != nullptr;
    sources["call_graph"]               = cg_res      != nullptr;
    j["data_sources"] = std::move(sources);

    result.summary_json = std::move(j);

    ctx.progress(1.0f, fmt::format("Algorithm summary: {} candidate(s) detected",
                                   result.candidates.size()));

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob = algorithm_summary_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("algorithm_summary", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet

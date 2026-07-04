#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <ankerl/unordered_dense.h>

namespace tenet {

// ─── AlgorithmSummaryResult serialization helpers ─────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x414C474F ("ALGO")
//   u32  version = 1
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

namespace {

static constexpr uint32_t ALGO_BLOB_MAGIC   = 0x414C474Fu;  // "ALGO"
static constexpr uint32_t ALGO_BLOB_VERSION = 1u;

std::string algorithm_summary_serialize(const AlgorithmSummaryResult& res) {
    // Pre-compute json string
    std::string json_str = res.summary_json.dump();

    size_t total = 4 + 4;  // magic, version
    total += 4 + res.summary_text.size();
    total += 4 + json_str.size();
    total += 8;  // num_candidates
    for (const auto& c : res.candidates) {
        total += 4 + c.name.size();
        total += 4;  // confidence (f32)
        total += 4 + c.evidence.size();
        total += 8 + 8;  // estimated_start, estimated_end
        total += 8 + c.key_pcs.size() * 8;
        total += 8 + c.key_inst_ids.size() * 8;
    }

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_f32 = [&](float    v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        std::memcpy(p, s.data(), s.size());
        p += s.size();
    };

    write_u32(ALGO_BLOB_MAGIC);
    write_u32(ALGO_BLOB_VERSION);
    write_str(res.summary_text);
    write_str(json_str);

    write_u64(static_cast<uint64_t>(res.candidates.size()));
    for (const auto& c : res.candidates) {
        write_str(c.name);
        write_f32(c.confidence);
        write_str(c.evidence);
        write_u64(c.estimated_start);
        write_u64(c.estimated_end);
        write_u64(static_cast<uint64_t>(c.key_pcs.size()));
        for (uint64_t pc : c.key_pcs) write_u64(pc);
        write_u64(static_cast<uint64_t>(c.key_inst_ids.size()));
        for (uint64_t id : c.key_inst_ids) write_u64(id);
    }

    return buf;
}

bool algorithm_summary_deserialize(const std::string& blob, AlgorithmSummaryResult& out) {
    if (blob.size() < 4 + 4) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_f32 = [&]() -> float    { float    v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (p + 4 > end) return false;
        uint32_t len = read_u32();
        if (p + len > end) return false;
        s.assign(p, len);
        p += len;
        return true;
    };

    if (read_u32() != ALGO_BLOB_MAGIC)   return false;
    if (read_u32() != ALGO_BLOB_VERSION) return false;

    if (!read_str(out.summary_text)) return false;

    std::string json_str;
    if (!read_str(json_str)) return false;
    try {
        out.summary_json = nlohmann::json::parse(json_str);
    } catch (...) {
        return false;
    }

    if (p + 8 > end) return false;
    uint64_t n_cands = read_u64();
    out.candidates.reserve(static_cast<size_t>(n_cands));
    for (uint64_t i = 0; i < n_cands; i++) {
        AlgorithmCandidate c;
        if (!read_str(c.name)) return false;
        if (p + 4 > end) return false;
        c.confidence = read_f32();
        if (!read_str(c.evidence)) return false;
        if (p + 8 + 8 > end) return false;
        c.estimated_start = read_u64();
        c.estimated_end   = read_u64();

        if (p + 8 > end) return false;
        uint64_t n_pcs = read_u64();
        if (p + n_pcs * 8 > end) return false;
        c.key_pcs.resize(static_cast<size_t>(n_pcs));
        for (uint64_t j = 0; j < n_pcs; j++) c.key_pcs[j] = read_u64();

        if (p + 8 > end) return false;
        uint64_t n_ids = read_u64();
        if (p + n_ids * 8 > end) return false;
        c.key_inst_ids.resize(static_cast<size_t>(n_ids));
        for (uint64_t j = 0; j < n_ids; j++) c.key_inst_ids[j] = read_u64();

        out.candidates.push_back(std::move(c));
    }

    return true;
}

}  // anonymous namespace (algo serialization)

namespace {

// ─── Internal evidence accumulator ────────────────────────────────────────

/// Collects evidence pieces for a single algorithm candidate during analysis.
struct EvidenceAccumulator {
    std::string algorithm_name;
    float confidence = 0.0f;
    std::vector<std::string> evidence_lines;
    std::vector<uint64_t> pcs;
    std::vector<uint64_t> inst_ids;
    uint64_t min_inst_id = UINT64_MAX;
    uint64_t max_inst_id = 0;

    void add_evidence(std::string line, float boost) {
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

// ─── Confidence-level label ───────────────────────────────────────────────

const char* confidence_label(float c) {
    if (c >= 0.9f) return "Very High";
    if (c >= 0.7f) return "High";
    if (c >= 0.5f) return "Medium";
    if (c >= 0.3f) return "Low";
    return "Very Low";
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

const auto& pattern_raw      = ctx.require_raw("pattern");
const auto& loop_sem_raw     = ctx.require_raw("loop_semantics");
const auto& function_raw     = ctx.require_raw("function");
const auto& call_graph_raw   = ctx.require_raw("call_graph");

const PatternResult*                pattern_res = nullptr;
// Constant-materialization data now lives inside PatternResult::constants
// (the standalone constant_materialization pass was merged into pattern).
const ConstantMaterializationResult* const_res  = nullptr;
const LoopSemanticsResult*          loop_res    = nullptr;
const FunctionResult*               func_res    = nullptr;
const CallGraphResult*              cg_res      = nullptr;

if (pattern_raw.ok()) {
pattern_res = &pattern_raw.get<PatternResult>();
const_res   = &pattern_res->constants;
}
if (loop_sem_raw.ok())   loop_res    = &loop_sem_raw.get<LoopSemanticsResult>();
if (function_raw.ok())   func_res    = &function_raw.get<FunctionResult>();
if (call_graph_raw.ok()) cg_res      = &call_graph_raw.get<CallGraphResult>();

    // ── Phase 1: Accumulate per-algorithm evidence ───────────────────────
    // Key: normalised algorithm name → accumulator.
    ankerl::unordered_dense::map<std::string, EvidenceAccumulator> accum;

    auto get_accum = [&](const std::string& algo) -> EvidenceAccumulator& {
        auto& a = accum[algo];
        if (a.algorithm_name.empty()) a.algorithm_name = algo;
        return a;
    };

    ctx.progress(0.1f, "Algorithm summary: processing pattern matches...");

    // ── 1a. Pattern matches ──────────────────────────────────────────────
    if (pattern_res) {
        for (const auto& m : pattern_res->matches) {
            if (m.category != PatternCategory::Crypto &&
                m.category != PatternCategory::KeySchedule)
                continue;

            // Derive algorithm name from the pattern name.
            // Pattern names are like "AES S-Box Lookup", "SHA-256 Round",
            // "ptrace anti-debug".  We use the pattern name as-is for
            // grouping; cross-referencing will merge related entries later.
            auto& ea = get_accum(m.pattern_name);

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
            auto& ea = get_accum(algo_name);

            // Count how many distinct known constants for this algorithm
            size_t known_count = 0;
            for (size_t idx : indices) {
                const auto& mc = const_res->constants[idx];
                if (mc.known_match) {
                    ++known_count;
                    ea.add_pc(mc.pc_first);
                    ea.add_inst_range(mc.first_inst_id, mc.last_inst_id);
                }
            }
            if (known_count > 0) {
                ea.add_evidence(
                    fmt::format("{} known {} constant(s) identified", known_count, algo_name),
                    std::min(0.45f, static_cast<float>(known_count) * 0.10f));
            }
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.5f, "Algorithm summary: processing loop semantics...");

    // ── 1c. Crypto loops ─────────────────────────────────────────────────
    if (loop_res) {
        auto crypto = loop_res->crypto_loops();
        for (const auto* ls : crypto) {
            const char* hint = loop_kind_algorithm_hint(ls->kind);
            std::string algo = hint ? std::string(hint) : "Unknown crypto loop";

            auto& ea = get_accum(algo);
            ea.add_evidence(
                fmt::format("{} at PC {:#x} ({} iterations, confidence {:.0f}%)",
                            loop_kind_name(ls->kind), ls->header_pc,
                            ls->iteration_count, ls->confidence * 100.0f),
                ls->confidence * 0.30f);
            ea.add_pc(ls->header_pc);
            // Use sample iteration range as an approximation
            if (ls->sample_iter_start != 0) {
                ea.add_inst_range(ls->sample_iter_start, ls->sample_iter_end);
            }
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.6f, "Algorithm summary: processing call graph...");

    // ── 1d. Hot functions from call graph (as corroborating evidence) ────
    if (cg_res) {
        auto hot = cg_res->hottest_callees(10);
        for (const auto& [pc, call_count] : hot) {
            // Only treat extremely hot leaf-like functions as crypto-core hints.
            // We look for functions called many times (≥10) that are NOT in
            // accum yet — those are un-attributed hot spots.
            if (call_count < 10) continue;
            // Root pseudo-nodes (synthetic "unknown outer caller" entries,
            // see call_graph_is_root_key()) are never real callees — skip
            // defensively in case one ever surfaces here (their
            // total_calls_received is always 0 in practice, but this guards
            // against misinterpreting a tagged call-site PC as a real
            // function address).
            if (call_graph_is_root_key(pc)) continue;

            // Check if this PC already appears in any accumulator
            bool already_known = false;
            for (const auto& [name, ea] : accum) {
                for (uint64_t kpc : ea.pcs) {
                    if (kpc == pc) { already_known = true; break; }
                }
                if (already_known) break;
            }
            if (already_known) continue;

            // Try to get the function name
            std::string fname;
            auto node = cg_res->node_at(pc);
            if (node) fname = node->name;
            if (fname.empty()) fname = fmt::format("sub_{:x}", pc);

            // Only add as a weak hint — not enough on its own
            auto& ea = get_accum(fmt::format("Hot function: {}", fname));
            ea.add_evidence(
                fmt::format("Function {} called {} times (potential crypto core)",
                            fname, call_count),
                0.10f);
            ea.add_pc(pc);
        }
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");
    ctx.progress(0.7f, "Algorithm summary: cross-referencing evidence...");

    // ── Phase 2: Cross-reference and merge related evidence ──────────────
    //
    // Heuristic merges:
    //   - If "SHA-256" constants + SPN loop → merge into "SHA-256" with boost
    //   - If "AES" constants + SPN loop → merge into "AES" with boost
    //   - If Feistel loop + any named Feistel cipher constants → merge
    //
    // We do a simple keyword-based merge: for each loop-family entry in accum,
    // see if any named-constant entry shares a keyword.

    // Collect loop-family keys and constant-family keys
    std::vector<std::string> loop_keys;
    std::vector<std::string> const_keys;
    for (const auto& [key, ea] : accum) {
        if (key.find("cipher") != std::string::npos ||
            key.find("Cipher") != std::string::npos ||
            key.find("loop") != std::string::npos) {
            loop_keys.push_back(key);
        }
    }
    if (const_res) {
        for (const auto& [algo_name, indices] : const_res->by_algorithm) {
            const_keys.push_back(algo_name);
        }
    }

    // For each named constant algorithm, check if a matching loop-family exists.
    // If so, merge the loop evidence into the constant entry (which has the
    // more specific name) and boost confidence.
    for (const auto& ckey : const_keys) {
        auto it_const = accum.find(ckey);
        if (it_const == accum.end()) continue;

        for (const auto& lkey : loop_keys) {
            // Simple match: "SPN-based cipher" merges with "AES*", "SM4*"
            // "Feistel-based cipher" merges with "DES*", "Blowfish*", "Camellia*"
            // "ARX-based cipher" merges with "ChaCha*", "Salsa*"
            bool should_merge = false;

            if (lkey.find("SPN") != std::string::npos) {
                should_merge = (ckey.find("AES") != std::string::npos ||
                                ckey.find("SM4") != std::string::npos ||
                                ckey.find("Serpent") != std::string::npos);
            } else if (lkey.find("Feistel") != std::string::npos) {
                should_merge = (ckey.find("DES") != std::string::npos ||
                                ckey.find("Blowfish") != std::string::npos ||
                                ckey.find("Camellia") != std::string::npos ||
                                ckey.find("TEA") != std::string::npos);
            } else if (lkey.find("ARX") != std::string::npos) {
                should_merge = (ckey.find("ChaCha") != std::string::npos ||
                                ckey.find("Salsa") != std::string::npos);
            }

            if (!should_merge) continue;

            auto it_loop = accum.find(lkey);
            if (it_loop == accum.end()) continue;

            // Merge loop evidence into the constant entry
            auto& dst = it_const->second;
            const auto& src = it_loop->second;
            for (const auto& ev : src.evidence_lines) {
                dst.evidence_lines.push_back(ev);
            }
            for (uint64_t pc : src.pcs) dst.add_pc(pc);
            if (src.min_inst_id < dst.min_inst_id) dst.min_inst_id = src.min_inst_id;
            if (src.max_inst_id > dst.max_inst_id) dst.max_inst_id = src.max_inst_id;
            for (uint64_t id : src.inst_ids) dst.inst_ids.push_back(id);

            // Cross-reference boost: both constants AND structural loop match
            dst.add_evidence("Cross-referenced: loop structure matches constant identification", 0.15f);

            // Remove the merged loop entry
            accum.erase(it_loop);
            break;  // loop_keys iterator invalidated, proceed to next const key
        }
    }

    // ── Phase 3: Build final candidates ──────────────────────────────────
    ctx.progress(0.8f, "Algorithm summary: building results...");

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

    // ── Phase 4: Generate Markdown summary ───────────────────────────────
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
            md += fmt::format("{}. **{}** (confidence: {}% — {})\n",
                              i + 1, c.name,
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

    // ── Phase 5: Generate structured JSON ────────────────────────────────
    ctx.progress(0.9f, "Algorithm summary: generating JSON...");

    nlohmann::json j;
    j["total_candidates"] = result.candidates.size();

    nlohmann::json j_candidates = nlohmann::json::array();
    for (const auto& c : result.candidates) {
        nlohmann::json jc;
        jc["name"] = c.name;
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

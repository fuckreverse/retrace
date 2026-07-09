#include "analysis/passes/crypto/objc_crypto_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "common/byte_codec.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>
#include <cstring>

namespace tenet {

using json = nlohmann::json;

// ─── ObjcCryptoResult serialization helpers ────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x4F43525A ("OCRZ")
//   u32  version = 1
//   u64  num_hits
//   for each ObjcCryptoHit:
//     u32  pattern_name_len; u8[] pattern_name
//     u32  category (enum)
//     u32  confidence (enum)
//     u64  pattern_start_inst, pattern_end_inst, anchor_pc
//     u32  description_len; u8[] description
//     u64  num_stack_frames
//     for each ObjcCallFrame:
//       u64  inst_id, objc_pc, receiver
//       u32  class_name_len; u8[] class_name
//       u32  selector_name_len; u8[] selector_name
//   u64  num_bare_indices; u64[] bare_pattern_indices
//   u64  num_objc_indices; u64[] objc_pattern_indices
//   (by_selector and by_class indices are rebuilt from hits after deserialization)

namespace {

static constexpr uint32_t OCRZ_BLOB_MAGIC   = 0x4F43525Au;  // "OCRZ"
static constexpr uint32_t OCRZ_BLOB_VERSION = 1u;

std::string objc_crypto_serialize(const ObjcCryptoResult& res) {
    ByteWriter w;

    w.u32(OCRZ_BLOB_MAGIC);
    w.u32(OCRZ_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.hits.size()));

    for (const auto& h : res.hits) {
        w.str(h.pattern_name);
        w.u32(static_cast<uint32_t>(h.category));
        w.u32(static_cast<uint32_t>(h.confidence));
        w.u64(h.pattern_start_inst);
        w.u64(h.pattern_end_inst);
        w.u64(h.anchor_pc);
        w.str(h.description);
        w.u64(static_cast<uint64_t>(h.objc_stack.size()));
        for (const auto& f : h.objc_stack) {
            w.u64(f.inst_id);
            w.u64(f.objc_pc);
            w.u64(f.receiver);
            w.str(f.class_name);
            w.str(f.selector_name);
        }
    }

    w.u64(static_cast<uint64_t>(res.bare_pattern_indices.size()));
    for (size_t idx : res.bare_pattern_indices) w.u64(static_cast<uint64_t>(idx));
    w.u64(static_cast<uint64_t>(res.objc_pattern_indices.size()));
    for (size_t idx : res.objc_pattern_indices) w.u64(static_cast<uint64_t>(idx));

    return std::move(w).take();
}

bool objc_crypto_deserialize(const std::string& blob, ObjcCryptoResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != OCRZ_BLOB_MAGIC)   return false;
    if (r.u32() != OCRZ_BLOB_VERSION) return false;

    uint64_t n_hits = r.u64();
    out.hits.reserve(static_cast<size_t>(n_hits));

    for (uint64_t i = 0; i < n_hits; i++) {
        ObjcCryptoHit h;
        if (!r.str(h.pattern_name)) return false;
        h.category   = static_cast<PatternCategory>(r.u32());
        h.confidence = static_cast<PatternConfidence>(r.u32());
        h.pattern_start_inst = r.u64();
        h.pattern_end_inst   = r.u64();
        h.anchor_pc          = r.u64();
        if (!r.str(h.description)) return false;
        uint64_t n_frames = r.u64();
        h.objc_stack.reserve(static_cast<size_t>(n_frames));
        for (uint64_t j = 0; j < n_frames; j++) {
            ObjcCallFrame f;
            f.inst_id  = r.u64();
            f.objc_pc  = r.u64();
            f.receiver = r.u64();
            if (!r.str(f.class_name))    return false;
            if (!r.str(f.selector_name)) return false;
            h.objc_stack.push_back(std::move(f));
        }
        out.hits.push_back(std::move(h));
    }

    uint64_t n_bare = r.u64();
    out.bare_pattern_indices.resize(static_cast<size_t>(n_bare));
    for (auto& idx : out.bare_pattern_indices) idx = static_cast<size_t>(r.u64());

    uint64_t n_objc = r.u64();
    out.objc_pattern_indices.resize(static_cast<size_t>(n_objc));
    for (auto& idx : out.objc_pattern_indices) idx = static_cast<size_t>(r.u64());

    // Rebuild by_selector and by_class indices from hits
    for (size_t hi = 0; hi < out.hits.size(); hi++) {
        const auto& h = out.hits[hi];
        if (!h.objc_stack.empty()) {
            const auto& inner = h.objc_stack.back();
            out.by_selector[inner.selector_name].push_back(hi);
            out.by_class[inner.class_name].push_back(hi);
        }
    }

    return r.ok();
}

}  // anonymous namespace (objc_crypto serialization)

// ─── ObjcCryptoHit helpers ────────────────────────────────────────────────

std::string ObjcCryptoHit::objc_chain_summary() const {
    if (objc_stack.empty()) return "(bare — no ObjC context)";
    std::string s;
    for (size_t i = 0; i < objc_stack.size(); ++i) {
        if (i > 0) s += " → ";
        const auto& f = objc_stack[i];
        s += '[';
        s += f.class_name;
        s += ' ';
        s += f.selector_name;
        s += ']';
    }
    return s;
}

// ─── ObjcCryptoResult helpers ─────────────────────────────────────────────

std::string ObjcCryptoResult::to_json() const {
    json output;

    output["total"] = hits.size();
    output["in_objc_count"] = objc_pattern_indices.size();
    output["bare_count"] = bare_pattern_indices.size();

    auto category_str = [](PatternCategory c) -> const char* {
        switch (c) {
            case PatternCategory::Crypto:      return "Crypto";
            case PatternCategory::AntiDebug:   return "AntiDebug";
            case PatternCategory::AntiTamper:  return "AntiTamper";
            case PatternCategory::Obfuscation: return "Obfuscation";
            case PatternCategory::Networking:  return "Networking";
            case PatternCategory::KeySchedule: return "KeySchedule";
        }
        return "Unknown";
    };

    auto confidence_str = [](PatternConfidence c) -> const char* {
        switch (c) {
            case PatternConfidence::Low:    return "Low";
            case PatternConfidence::Medium: return "Medium";
            case PatternConfidence::High:   return "High";
        }
        return "Unknown";
    };

    json hits_arr = json::array();
    for (const auto& h : hits) {
        json hj;
        hj["pattern_name"]  = h.pattern_name;
        hj["category"]      = category_str(h.category);
        hj["confidence"]    = confidence_str(h.confidence);
        hj["pattern_start"] = h.pattern_start_inst;
        hj["pattern_end"]   = h.pattern_end_inst;
        hj["anchor_pc"]     = fmt::format("0x{:X}", h.anchor_pc);
        hj["description"]   = h.description;
        hj["objc_chain"]    = h.objc_chain_summary();

        json stack_arr = json::array();
        for (const auto& f : h.objc_stack) {
            stack_arr.push_back({
                {"inst_id",       f.inst_id},
                {"pc",            fmt::format("0x{:X}", f.objc_pc)},
                {"class",         f.class_name},
                {"selector",      f.selector_name},
                {"receiver",      fmt::format("0x{:X}", f.receiver)}
            });
        }
        hj["objc_stack"] = std::move(stack_arr);
        hits_arr.push_back(std::move(hj));
    }
    output["hits"] = std::move(hits_arr);

    return output.dump(2);
}

// ─── ObjcCryptoPass::run ──────────────────────────────────────────────────

PassResult ObjcCryptoPass::run(PassContext& ctx) {
    // ObjC×Crypto correlation only makes sense on Darwin targets.
    auto os = ctx.reader().header().target_os;
    if (!is_darwin(os) && os != TargetOS::Unknown) {
        return PassResult::success(ObjcCryptoResult{});
    }

    auto& index = ctx.index();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("objc_crypto", blob)) {
            ObjcCryptoResult cached;
            if (objc_crypto_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "objc_crypto: {} hits ({} in ObjC, {} bare) (from cache)",
                    cached.hits.size(), cached.in_objc_count(), cached.bare_count()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    const auto& pattern_result = ctx.require<PatternResult>("pattern");
    const auto& objc_result    = ctx.require<ObjcResult>("objc");

    ObjcCryptoResult result;

    if (pattern_result.matches.empty()) {
        ctx.progress(1.0f, "objc_crypto: no pattern matches to correlate");
        return PassResult::success(std::move(result));
    }

    // ── Build a sorted list of (inst_id, message_index) from ObjcResult ──
    // ObjcResult::messages is already in trace order (inst_id ascending).
    // We build a flat array of inst_ids for binary search.
    const auto& msgs = objc_result.messages;

    // msgs[i].inst_id is the inst_id of the instruction *surrounding* the
    // OBJC record.  We use this as the "call point" in the trace.
    struct MsgRef {
        uint64_t inst_id;
        size_t   msg_idx;
    };
    std::vector<MsgRef> sorted_msgs;
    sorted_msgs.reserve(msgs.size());
    for (size_t i = 0; i < msgs.size(); ++i) {
        sorted_msgs.push_back({msgs[i].inst_id, i});
    }
    // Should already be sorted, but sort defensively.
    std::sort(sorted_msgs.begin(), sorted_msgs.end(),
              [](const MsgRef& a, const MsgRef& b) { return a.inst_id < b.inst_id; });

    ctx.progress(0.05f, fmt::format("objc_crypto: {} patterns × {} ObjC msgs",
                                     pattern_result.matches.size(), msgs.size()));

    // ── For each pattern match, build the ObjC call stack ─────────────────
    for (size_t pi = 0; pi < pattern_result.matches.size(); ++pi) {
        const auto& pm = pattern_result.matches[pi];

        ObjcCryptoHit hit;
        hit.pattern_name        = pm.pattern_name;
        hit.category            = pm.category;
        hit.confidence          = pm.confidence;
        hit.pattern_start_inst  = pm.start_inst_id;
        hit.pattern_end_inst    = pm.end_inst_id;
        hit.anchor_pc           = pm.anchor_pc;
        hit.description         = pm.description;

        if (!sorted_msgs.empty()) {
            // Find all ObjC messages with inst_id < pattern_start_inst.
            // We use upper_bound to find the first message >= pattern_start_inst,
            // then walk backwards to collect the call stack frames.
            auto it = std::lower_bound(
                sorted_msgs.begin(), sorted_msgs.end(),
                pm.start_inst_id,
                [](const MsgRef& r, uint64_t id) { return r.inst_id < id; }
            );

            // Walk backwards, collecting up to max_stack_depth_ frames,
            // stopping if the gap exceeds max_lookback_.
            size_t frames_collected = 0;
            auto rit = it;
            while (rit != sorted_msgs.begin() && frames_collected < max_stack_depth_) {
                --rit;
                const auto& msg = msgs[rit->msg_idx];

                // Gap check: don't reach back further than max_lookback_ instructions.
                if (pm.start_inst_id > rit->inst_id &&
                    (pm.start_inst_id - rit->inst_id) > max_lookback_) {
                    break;
                }

                ObjcCallFrame frame;
                frame.inst_id      = msg.inst_id;
                frame.objc_pc      = msg.pc;
                frame.class_name   = msg.class_name;
                frame.selector_name = msg.selector_name;
                frame.receiver     = msg.receiver;

                // push_back and reverse later — O(N) instead of O(N²).
                hit.objc_stack.push_back(frame);
                ++frames_collected;
            }
            std::reverse(hit.objc_stack.begin(), hit.objc_stack.end());
        }

        size_t hit_idx = result.hits.size();

        // Build by_selector and by_class indices.
        if (!hit.objc_stack.empty()) {
            result.objc_pattern_indices.push_back(hit_idx);

            // Index by innermost frame (closest to the algorithm).
            const auto& inner = hit.objc_stack.back();
            result.by_selector[inner.selector_name].push_back(hit_idx);
            result.by_class[inner.class_name].push_back(hit_idx);
        } else {
            result.bare_pattern_indices.push_back(hit_idx);
        }

        result.hits.push_back(std::move(hit));

        if (pi % 20 == 0) {
            float pct = 0.05f + 0.95f * static_cast<float>(pi) /
                        static_cast<float>(pattern_result.matches.size());
            ctx.progress(pct);
        }

        if (ctx.cancelled()) {
            return PassResult::failed("objc_crypto: cancelled");
        }
    }

    ctx.progress(1.0f, fmt::format(
        "objc_crypto: {} hits ({} in ObjC context, {} bare)",
        result.hits.size(), result.objc_pattern_indices.size(),
        result.bare_pattern_indices.size()));

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob = objc_crypto_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("objc_crypto", blob.data(), blob.size());
        }
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet

#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/objc_pass.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>

namespace tenet {

using json = nlohmann::json;

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

                // Insert at front to maintain outermost-first order.
                hit.objc_stack.insert(hit.objc_stack.begin(), frame);
                ++frames_collected;
            }
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

    return PassResult::success(std::move(result));
}

}  // namespace tenet

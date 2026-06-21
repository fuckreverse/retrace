#include "analysis/passes/taint_source_annotation_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/objc_pass.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>

namespace tenet {

using json = nlohmann::json;

// ─── TaintSourceAnnotation helpers ────────────────────────────────────────

std::string TaintSourceAnnotation::summary() const {
    switch (kind) {
        case TaintSourceKind::ObjcGetter:
        case TaintSourceKind::ObjcArg:
        case TaintSourceKind::ObjcReturnValue:
            if (!objc_label.empty()) return objc_label;
            if (objc_message.has_value()) {
                return '[' + objc_message->class_name + ' ' + objc_message->selector_name + ']';
            }
            return "(ObjC — unknown)";

        case TaintSourceKind::MemoryLoad:
            if (source_mem_addr != 0)
                return fmt::format("LDR 0x{:X} ({}B)", source_mem_addr, source_mem_size);
            return "memory load";

        case TaintSourceKind::ImmediateConstant:
            return fmt::format("constant 0x{:X}", constant_value);

        case TaintSourceKind::FunctionReturn:
            if (!callee_name.empty())
                return fmt::format("return of {}()", callee_name);
            return fmt::format("return of sub_{:X}()", callee_pc);

        default:
            return fmt::format("unknown source at inst #{}", inst_id);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

const ObjcMessage* TaintSourceAnnotationPass::find_objc_source(
    const ObjcResult& objc, uint64_t inst_id) const
{
    if (objc.messages.empty()) return nullptr;

    // Binary search for the first message with inst_id >= our target.
    // Then scan backward to find the closest message before `inst_id`.
    auto it = std::lower_bound(
        objc.messages.begin(), objc.messages.end(),
        inst_id,
        [](const ObjcMessage& m, uint64_t id) { return m.inst_id < id; }
    );

    if (it == objc.messages.begin()) return nullptr;

    // Walk backward from the lower_bound.
    --it;
    while (true) {
        if (it->inst_id <= inst_id) {
            // Check gap constraint.
            if (inst_id - it->inst_id <= config_.max_objc_gap) {
                return &(*it);
            }
            break;
        }
        if (it == objc.messages.begin()) break;
        --it;
    }
    return nullptr;
}

TaintSourceKind TaintSourceAnnotationPass::classify_source(
    const BackwardTaintEvent& ev, const ObjcMessage* objc_msg) const
{
    if (objc_msg != nullptr) {
        // Determine whether this looks like a getter vs. a general call.
        const std::string& sel = objc_msg->selector_name;

        if (!config_.require_zero_colon_getter) {
            // Accept all ObjC messages as potential sources.
            // Distinguish getter-style (no colon, doesn't start with "set")
            // vs. method-with-args vs. setter.
            bool is_getter = (sel.find(':') == std::string::npos &&
                              sel.substr(0, 3) != "set");
            if (is_getter) return TaintSourceKind::ObjcGetter;

            bool is_setter = (sel.size() > 3 && sel[0] == 's' && sel[1] == 'e' && sel[2] == 't' &&
                              sel[3] >= 'A' && sel[3] <= 'Z');
            if (is_setter) return TaintSourceKind::ObjcReturnValue;

            return TaintSourceKind::ObjcArg;
        } else {
            // Strict getter: zero colons, not starting with "set".
            bool is_getter = (sel.find(':') == std::string::npos &&
                              sel.substr(0, 3) != "set");
            if (is_getter) return TaintSourceKind::ObjcGetter;
        }
    }

    // No ObjC context: look at the event itself.
    if (ev.loads_from_memory && !ev.src_mem_addrs.empty()) {
        return TaintSourceKind::MemoryLoad;
    }

    // If the event has no source regs and no source memory, it might be a constant.
    if (ev.src_regs.empty() && ev.src_mem_addrs.empty() && !ev.loads_from_memory) {
        return TaintSourceKind::ImmediateConstant;
    }

    // If it wrote x0 and has no sources traced, could be a function return.
    // We can't perfectly detect this without call-graph data here, so
    // check if any dst_reg is x0 and there are no known sources in the taint set.
    for (uint8_t dr : ev.dst_regs) {
        if (dr == 0) return TaintSourceKind::FunctionReturn;  // x0 = return value
    }

    return TaintSourceKind::Unknown;
}

// ─── TaintSourceAnnotationPass::run ──────────────────────────────────────

PassResult TaintSourceAnnotationPass::run(PassContext& ctx) {
    const auto& bt = ctx.require<BackwardTaintResult>("backward_taint");
    const auto& objc = ctx.require<ObjcResult>("objc");

    TaintSourceAnnotationResult result;

    if (bt.events.empty()) {
        ctx.progress(1.0f, "taint_source_annotation: no backward taint events");
        return PassResult::success(std::move(result));
    }

    // ── Find leaf events ────────────────────────────────────────────────
    // A leaf event is one where:
    //   1. It loads from memory but the load address has NO prior writer in
    //      the taint contributing set.
    //   2. OR it has no src_regs that are themselves in the contributing set.
    //
    // In practice, we identify leaves as events whose src_regs are all NOT
    // in the contributing_inst_ids bitmap AND whose src_mem_addrs have no
    // matching store in the contributing set.
    //
    // Simplification: we consider an event a leaf if it has no src_regs
    // AND no src_mem_addrs in the contributing set. This is the common case:
    // the final event in each "branch" of the backward dependency tree.
    //
    // We also treat any event that loads from a memory address that was NOT
    // further traced (memory load without a contributing store) as a leaf.

    // Build set of inst_ids that are sources (src_regs producers).
    // An event is a leaf if none of its src_reg writes are in the contributing set.
    // Equivalently: an event ev is NOT a leaf if there exists another event ev2
    // in the chain such that ev.src_regs ∩ {ev2.dst_regs} != empty.
    //
    // For efficiency, we note that events[] is ordered from sink → source (newest first).
    // We just check: for each event, does it have any source reg that appears as
    // a dst_reg of an EARLIER event in the chain (i.e., a later inst_id)?

    // Build "reg → last writer inst_id" map from the events.
    std::unordered_map<uint8_t, uint64_t> reg_last_written;  // reg → latest inst_id that defines it
    for (const auto& ev : bt.events) {
        for (uint8_t dr : ev.dst_regs) {
            auto it = reg_last_written.find(dr);
            if (it == reg_last_written.end() || ev.inst_id > it->second) {
                reg_last_written[dr] = ev.inst_id;
            }
        }
    }

    ctx.progress(0.1f, fmt::format("taint_source_annotation: identifying leaf sources from {} events",
                                    bt.events.size()));

    for (size_t ei = 0; ei < bt.events.size(); ++ei) {
        const auto& ev = bt.events[ei];

        // Check if this event's src_regs are covered by any other contributing event.
        bool all_srcs_covered = false;
        if (!ev.src_regs.empty()) {
            all_srcs_covered = true;
            for (uint8_t sr : ev.src_regs) {
                // Is there another event (earlier in time = higher inst_id in our list)
                // that writes sr AND has inst_id < ev.inst_id?
                auto it = reg_last_written.find(sr);
                if (it == reg_last_written.end() || it->second >= ev.inst_id) {
                    all_srcs_covered = false;
                    break;
                }
            }
        }

        // Check memory sources: is there a contributing store that feeds this load?
        bool mem_srcs_covered = false;
        if (ev.loads_from_memory && !ev.src_mem_addrs.empty()) {
            // If any src_mem_addr was traced through a store in the contributing set,
            // this event is not a leaf. Check by looking for contributing store events.
            for (const auto& ev2 : bt.events) {
                if (ev2.inst_id >= ev.inst_id) continue;
                if (!ev2.stores_to_memory) continue;
                for (uint64_t ma : ev.src_mem_addrs) {
                    if (ma == ev2.store_addr) {
                        mem_srcs_covered = true;
                        break;
                    }
                }
                if (mem_srcs_covered) break;
            }
        }

        // Event is a leaf if:
        // - It has no src_regs covered by another contributing event, AND
        // - Any memory sources are not covered by contributing stores.
        bool is_leaf = (!all_srcs_covered && !mem_srcs_covered);

        // Also consider: events with NO sources at all (pure sinks of constant loads).
        if (ev.src_regs.empty() && !ev.loads_from_memory) {
            is_leaf = true;
        }

        if (!is_leaf && !config_.annotate_bare_sources) continue;
        if (!is_leaf) {
            // Not a leaf, skip if annotate_bare_sources is false.
            // But we still want to check if this event loads from an ObjC return value.
            // Only annotate true leaves.
            continue;
        }

        // ── Build the annotation ─────────────────────────────────────────
        TaintSourceAnnotation ann;
        ann.inst_id = ev.inst_id;
        ann.pc = ev.pc;
        ann.sink_reg = ev.dst_reg;

        // Find ObjC context.
        const ObjcMessage* objc_msg = find_objc_source(objc, ev.inst_id);
        ann.kind = classify_source(ev, objc_msg);

        if (objc_msg != nullptr &&
            (ann.kind == TaintSourceKind::ObjcGetter ||
             ann.kind == TaintSourceKind::ObjcArg ||
             ann.kind == TaintSourceKind::ObjcReturnValue)) {
            ann.objc_message = *objc_msg;
            ann.objc_label = '[' + objc_msg->class_name + ' ' + objc_msg->selector_name + ']';
        }

        if (ev.loads_from_memory && !ev.src_mem_addrs.empty()) {
            ann.source_mem_addr = ev.src_mem_addrs[0];
            ann.source_mem_size = ev.store_size;  // may be 0 if not a store
        }

        // Build indices.
        size_t src_idx = result.sources.size();

        switch (ann.kind) {
            case TaintSourceKind::ObjcGetter:
            case TaintSourceKind::ObjcArg:
            case TaintSourceKind::ObjcReturnValue:
                result.objc_source_indices.push_back(src_idx);
                if (ann.objc_message.has_value()) {
                    result.by_selector[ann.objc_message->selector_name].push_back(src_idx);
                    result.by_class[ann.objc_message->class_name].push_back(src_idx);
                }
                break;
            case TaintSourceKind::ImmediateConstant:
                result.constant_source_indices.push_back(src_idx);
                break;
            case TaintSourceKind::MemoryLoad:
                result.memory_source_indices.push_back(src_idx);
                break;
            default:
                if (config_.annotate_bare_sources) {
                    result.memory_source_indices.push_back(src_idx);
                }
                break;
        }

        result.sources.push_back(std::move(ann));

        if (ei % 100 == 0) {
            ctx.progress(0.1f + 0.9f * static_cast<float>(ei) /
                         static_cast<float>(bt.events.size()));
        }

        if (ctx.cancelled()) {
            return PassResult::failed("taint_source_annotation: cancelled");
        }
    }

    ctx.progress(1.0f, fmt::format(
        "taint_source_annotation: {} sources ({} ObjC, {} constants, {} mem)",
        result.sources.size(),
        result.objc_source_indices.size(),
        result.constant_source_indices.size(),
        result.memory_source_indices.size()));

    return PassResult::success(std::move(result));
}

// ─── TaintSourceAnnotationResult::to_json ─────────────────────────────────

static const char* taint_source_kind_str(TaintSourceKind k) {
    switch (k) {
        case TaintSourceKind::ObjcGetter:       return "ObjcGetter";
        case TaintSourceKind::ObjcArg:          return "ObjcArg";
        case TaintSourceKind::ObjcReturnValue:  return "ObjcReturnValue";
        case TaintSourceKind::MemoryLoad:       return "MemoryLoad";
        case TaintSourceKind::ImmediateConstant: return "ImmediateConstant";
        case TaintSourceKind::FunctionReturn:   return "FunctionReturn";
        default:                                return "Unknown";
    }
}

std::string TaintSourceAnnotationResult::to_json() const {
    json output;
    output["total"]          = sources.size();
    output["objc_count"]     = objc_source_indices.size();
    output["constant_count"] = constant_source_indices.size();
    output["memory_count"]   = memory_source_indices.size();

    json srcs_arr = json::array();
    for (const auto& s : sources) {
        json sj;
        sj["inst_id"] = s.inst_id;
        sj["pc"]      = fmt::format("0x{:X}", s.pc);
        sj["kind"]    = taint_source_kind_str(s.kind);
        sj["summary"] = s.summary();
        sj["sink_reg"] = s.sink_reg;

        if (s.objc_message.has_value()) {
            sj["objc"] = {
                {"class",    s.objc_message->class_name},
                {"selector", s.objc_message->selector_name},
                {"receiver", fmt::format("0x{:X}", s.objc_message->receiver)},
                {"inst_id",  s.objc_message->inst_id}
            };
        }
        if (s.source_mem_addr != 0) {
            sj["source_mem_addr"] = fmt::format("0x{:X}", s.source_mem_addr);
            if (s.source_mem_size > 0) sj["source_mem_size"] = s.source_mem_size;
        }
        if (s.kind == TaintSourceKind::ImmediateConstant && s.constant_value != 0) {
            sj["constant"] = fmt::format("0x{:X}", s.constant_value);
        }
        if (s.kind == TaintSourceKind::FunctionReturn) {
            sj["callee_pc"] = fmt::format("0x{:X}", s.callee_pc);
            if (!s.callee_name.empty()) sj["callee_name"] = s.callee_name;
        }

        srcs_arr.push_back(std::move(sj));
    }
    output["sources"] = std::move(srcs_arr);

    // ObjC index: class → selectors → count
    if (!by_class.empty()) {
        json class_idx = json::object();
        for (const auto& [cls, idxs] : by_class) {
            json sel_arr = json::array();
            for (size_t i : idxs) {
                if (sources[i].objc_message.has_value()) {
                    sel_arr.push_back(sources[i].objc_message->selector_name);
                }
            }
            class_idx[cls] = {{"count", idxs.size()}, {"selectors", std::move(sel_arr)}};
        }
        output["objc_index"] = std::move(class_idx);
    }

    return output.dump(2);
}

}  // namespace tenet

#include "common/compiler_compat.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "core/register_file.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include "ankerl/unordered_dense.h"
#include <algorithm>
#include <cstring>

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
    // Then scan backward to find the closest message at or before `inst_id`.
    auto it = std::lower_bound(
        objc.messages.begin(), objc.messages.end(),
        inst_id,
        [](const ObjcMessage& m, uint64_t id) { return m.inst_id < id; }
    );

    // lower_bound returns the first element with inst_id >= target.
    // If it points to an element with inst_id == target (gap = 0), that's
    // an exact match — return it immediately.
    if (it != objc.messages.end() && it->inst_id == inst_id) {
        return &(*it);
    }

    // Otherwise, the closest message *before* `inst_id` is the one
    // just before the lower_bound position.
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
    const BackwardTaintEvent& ev, const ObjcMessage* objc_msg,
    const FunctionResult* func) const
{
    // ── First: classify based on the event's intrinsic dataflow properties ──
    // Pure immediate loads (no src_regs, no memory) are constants regardless
    // of whether an ObjC message happens to be nearby in the instruction
    // stream — the dataflow simply does not pass through ObjC.  Similarly,
    // memory loads and function returns are dataflow-determined.

    if (ev.loads_from_memory && !ev.src_mem_addrs.empty()) {
        // Memory load takes precedence over ObjC context: if the leaf
        // genuinely loaded from memory, that's the source, even if an
        // ObjC message is nearby.  ObjC context is still attached to the
        // annotation for informational purposes (see find_objc_source()).
        // However, if the ObjC message is at the *same* inst_id (gap=0),
        // the load is part of the ObjC call's effect (e.g. [NSData bytes]
        // returns a pointer that the caller then dereferences), so ObjC
        // attribution is appropriate.
        if (objc_msg != nullptr && objc_msg->inst_id == ev.inst_id) {
            // fall through to ObjC classification below
        } else {
            return TaintSourceKind::MemoryLoad;
        }
    }

    // FunctionReturn check MUST come before the ImmediateConstant fallback
    // below: at the BackwardTaintEvent level, a "x0 = <call result>" leaf
    // (e.g. the register-diff snapshot right after a BLR/RET) looks
    // *identical* to a bare MOVZ constant load — both have empty src_regs
    // and no memory access. The only reliable signal that distinguishes
    // them is call-site adjacency: does the instruction immediately
    // preceding this leaf (inst_id - 1) appear in FunctionResult as a call
    // site? If so, this leaf is genuinely "x0 = result of that call", not
    // a hard-coded constant. (`func` is null when FunctionPass wasn't
    // registered — in that case we fall back to the constant heuristic,
    // since we have no way to tell the two apart.)
    if (func != nullptr && ev.has_dst_reg(0) && ev.inst_id > 0 &&
        func->call_at(ev.inst_id - 1) != nullptr) {
        return TaintSourceKind::FunctionReturn;
    }

    // Pure immediate loads: no src_regs, no memory.  The value was baked
    // into the instruction (MOVZ/MOVK/ADR/etc.).  However, if this leaf
    // writes x0 (the ObjC return-value register) and there is a nearby
    // ObjC message, the x0 value likely IS the ObjC return value rather
    // than a hard-coded constant — in real traces, objc_msgSend returns
    // its result in x0, which appears as a register diff with no src_regs
    // (the call's effect is not traced instruction-by-instruction).
    //
    // For other registers (x1-x28), a pure immediate load is genuinely a
    // constant and cannot have come from an ObjC message, even if one is
    // nearby — the dataflow simply does not pass through ObjC.
    if (ev.src_regs_empty() && ev.src_mem_addrs.empty() && !ev.loads_from_memory) {
        if (objc_msg != nullptr && ev.has_dst_reg(0)) {
            // x0 write with nearby ObjC message → likely an ObjC return value.
            // Fall through to ObjC classification below.
        } else if (objc_msg != nullptr && objc_msg->inst_id == ev.inst_id) {
            // Exact inst_id match (gap=0) → the leaf IS the ObjC return-value
            // instruction itself, even if it writes a register other than x0.
            // Fall through to ObjC classification below.
        } else {
            return TaintSourceKind::ImmediateConstant;
        }
    }

    // ── ObjC attribution ──────────────────────────────────────────────────
    // At this point, either the event has src_regs (reads from another
    // register that may be an ObjC return value), or it's a memory load /
    // pure-immediate that exactly coincides with an ObjC message (gap=0).
    if (objc_msg != nullptr) {
        // Determine whether this looks like a getter vs. a general call.
        const std::string& sel = objc_msg->selector_name;

        if (!config_.require_zero_colon_getter) {
            // Accept all ObjC messages as potential sources.
            // Distinguish getter-style (no colon, doesn't start with "set")
            // vs. method-with-args vs. setter.
            bool is_getter = (sel.find(':') == std::string::npos &&
                              sel.compare(0, 3, "set") != 0);
            if (is_getter) return TaintSourceKind::ObjcGetter;

            bool is_setter = (sel.size() > 3 && sel[0] == 's' && sel[1] == 'e' && sel[2] == 't' &&
                              sel[3] >= 'A' && sel[3] <= 'Z');
            if (is_setter) return TaintSourceKind::ObjcReturnValue;

            return TaintSourceKind::ObjcArg;
        } else {
            // Strict getter: zero colons, not starting with "set".
            bool is_getter = (sel.find(':') == std::string::npos &&
                              sel.compare(0, 3, "set") != 0);
            if (is_getter) return TaintSourceKind::ObjcGetter;
        }
    }

    // Fallback (func unavailable, ambiguous case): if it wrote x0 and has no
    // other sources traced, guess function return. Without FunctionResult
    // this is a coarse heuristic and may misclassify true constants.
    if (ev.has_dst_reg(0)) return TaintSourceKind::FunctionReturn;  // x0 = return value

    return TaintSourceKind::Unknown;
}

// ─── Field population helpers ─────────────────────────────────────────────
//
// classify_source() only determines *which kind* a leaf is; the kind-specific
// payload fields (constant_value / callee_pc / callee_name) are filled in
// here so run() stays focused on the leaf-detection loop.

/// Fill `ann.constant_value` for an ImmediateConstant source by reading the
/// register state right after the leaf instruction executed (state_after).
/// `sink_reg` is the register this leaf wrote that ultimately feeds the
/// backward-taint sink, so its post-execution value IS the materialized
/// constant (e.g. the immediate loaded by a MOVZ/MOVK chain, or an ADRP+ADD
/// computed address — whatever ended up in the register).
static void fill_constant_value(TaintSourceAnnotation& ann, PassContext& ctx) {
    const auto& after = ctx.regfile().state_after(ann.inst_id);
    if (ann.sink_reg < 34) {
        ann.constant_value = after.gpr[ann.sink_reg];
    }
}

/// Fill `ann.callee_pc` / `ann.callee_name` for a FunctionReturn source by
/// checking whether the instruction immediately preceding the leaf (i.e.
/// `inst_id - 1`) is a recorded call site in FunctionResult. If so, the
/// leaf is the "x0 = <call result>" instruction and callee_pc/callee_name
/// can be attributed directly to that call's target function.
///
/// `func` may be nullptr (FunctionPass didn't run / was skipped) — in that
/// case the fields are left at their default (0 / empty), and summary()
/// falls back to "return of sub_0()".
static void fill_function_return(TaintSourceAnnotation& ann, const FunctionResult* func) {
    if (func == nullptr || ann.inst_id == 0) return;

    const CallEvent* call = func->call_at(ann.inst_id - 1);
    if (call == nullptr) return;

    ann.callee_pc = call->target_pc;

    auto fit = func->functions.find(call->target_pc);
    if (fit != func->functions.end()) {
        ann.callee_name = fit->second.name;
    }
}

// ─── TaintSourceAnnotationPass::run ──────────────────────────────────────

PassResult TaintSourceAnnotationPass::run(PassContext& ctx) {
    const auto& bt = ctx.require<BackwardTaintResult>("backward_taint");
    const auto& objc = ctx.require<ObjcResult>("objc");
    // Soft dependency: used to attribute FunctionReturn sources to a callee
    // name/pc. May be nullptr if FunctionPass failed or was skipped (e.g.
    // under memory pressure) — fill_function_return() handles that case.
    const auto* func = ctx.try_require<FunctionResult>("function");

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

    // Build "reg → earliest writer inst_id" fixed array (AArch64: 34 GPR).
    // We use the *minimum* (earliest/closest-to-source) writer inst_id rather
    // than the maximum, so that when an event both reads and writes the same
    // register (e.g. MOVK x1, ... which reads x1 and writes x1), the check
    // "is there another contributing event that wrote this src_reg?" correctly
    // returns true — the other (earlier) MOVZ that also wrote x1 has a smaller
    // inst_id, and using the minimum preserves that information.  Using the
    // maximum would record the MOVK's own inst_id and make the check fail.
    static constexpr size_t kNumGPR = 34;
    uint64_t reg_earliest_writer[kNumGPR];
    std::memset(reg_earliest_writer, 0xFF, sizeof(reg_earliest_writer));  // UINT64_MAX = not written
    for (const auto& ev : bt.events) {
        if (ctx.cancelled()) {
            return PassResult::failed("taint_source_annotation: cancelled");
        }
        ev.for_each_dst_reg([&](uint8_t dr) {
            if (dr < kNumGPR && ev.inst_id < reg_earliest_writer[dr]) {
                reg_earliest_writer[dr] = ev.inst_id;
            }
        });
    }

    // Pre-build set of store addresses from contributing events → O(1) lookup.
    ankerl::unordered_dense::set<uint64_t> contributing_store_addrs;
    contributing_store_addrs.reserve(bt.events.size() / 4);
    for (const auto& ev : bt.events) {
        if (ctx.cancelled()) {
            return PassResult::failed("taint_source_annotation: cancelled");
        }
        if (ev.stores_to_memory && ev.store_addr != 0) {
            contributing_store_addrs.insert(ev.store_addr);
        }
    }

    ctx.progress(0.1f, fmt::format("taint_source_annotation: identifying leaf sources from {} events",
                                    bt.events.size()));

    for (size_t ei = 0; ei < bt.events.size(); ++ei) {
        const auto& ev = bt.events[ei];

        // Check if this event's src_regs are covered by any other contributing event.
        bool all_srcs_covered = false;
        if (!ev.src_regs_empty()) {
            all_srcs_covered = true;
            for (uint64_t m = ev.src_regs_mask; m; m &= m - 1) {
                uint8_t sr = static_cast<uint8_t>(tenet::platform::trailing_zeros(m));
                // Is there another contributing event that writes sr with
                // inst_id < ev.inst_id?  Using reg_earliest_writer (minimum
                // inst_id) ensures this works even when ev itself also writes sr
                // (e.g. MOVK reads and writes the same register).
                if (sr >= kNumGPR || reg_earliest_writer[sr] == UINT64_MAX || reg_earliest_writer[sr] >= ev.inst_id) {
                    all_srcs_covered = false;
                    break;
                }
            }
        }

        // Check memory sources: is there a contributing store that feeds this load?
        bool mem_srcs_covered = false;
        if (ev.loads_from_memory && !ev.src_mem_addrs.empty()) {
            // O(1) lookup per address in the pre-built contributing store set.
            for (uint64_t ma : ev.src_mem_addrs) {
                if (contributing_store_addrs.contains(ma)) {
                    mem_srcs_covered = true;
                    break;
                }
            }
        }

        // Event is a leaf if:
        // - It has no src_regs covered by another contributing event, AND
        // - Any memory sources are not covered by contributing stores.
        bool is_leaf = (!all_srcs_covered && !mem_srcs_covered);

        // Also consider: events with NO sources at all (pure sinks of constant loads).
        if (ev.src_regs_empty() && !ev.loads_from_memory) {
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
        ann.kind = classify_source(ev, objc_msg, func);

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

        // Populate kind-specific payload fields.
        if (ann.kind == TaintSourceKind::ImmediateConstant) {
            fill_constant_value(ann, ctx);
        } else if (ann.kind == TaintSourceKind::FunctionReturn) {
            fill_function_return(ann, func);
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

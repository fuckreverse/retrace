#include "analysis/passes/profile/call_context_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/instruction_decoder.h"

#include <algorithm>

namespace tenet {

// ─── Main pass execution ───────────────────────────────────────────────────
//
// This pass does NOT reconstruct the call stack itself. Doing so would
// duplicate "function"'s call/return state machine (which already handles
// tail calls, non-local unwinds, and is O(log N) to query via
// FunctionResult::call_stack_at()). Instead we:
//   1. Require "function" and "loop" (both cheap once cached).
//   2. Ask FunctionResult for the call stack at target_inst_id directly.
//   3. Scan only the small [target - context_before, target + context_after]
//      window to collect surrounding disassembly + loop depth.

PassResult CallContextPass::run(PassContext& ctx) {
    if (cfg_.target_inst_id == 0) {
        return PassResult::skipped();
    }

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& decoder = ctx.decoder();
    auto& code_table = ctx.code_table();
    const auto& functions = ctx.require<FunctionResult>("function");
    const auto& loops = ctx.require<LoopResult>("loop");

    const uint64_t total_insts = index.inst_count();
    if (cfg_.target_inst_id > total_insts) {
        return PassResult::failed("target_inst_id exceeds trace length");
    }

    CallContextResult result;
    result.target_inst_id = cfg_.target_inst_id;

    ctx.progress(0.0f, "CallContext: reconstructing call stack...");

    // ── Call stack: derived entirely from FunctionResult (O(log N)) ──────
    // NOTE: cfg_.target_inst_id (like the rest of this pass's instruction
    // window below) is 1-based, with inst_id 1 denoting the trace's first
    // instruction. FunctionResult::call_stack_at() and CallEvent::
    // call_inst_id/return_inst_id, however, use TraceScanEngine's 0-based
    // convention (first instruction is inst_id 0). Convert here so both
    // halves of this pass agree on which instruction is being queried.
    const uint64_t functions_inst_id = cfg_.target_inst_id - 1;
    auto stack_ptrs = functions.call_stack_at(functions_inst_id);
    result.call_stack.reserve(stack_ptrs.size());
    for (const auto* evt : stack_ptrs) {
        CallStackFrame frame;
        frame.call_site_pc   = evt->call_site_pc;
        frame.callee_pc      = evt->target_pc;
        // Convert back to this pass's 1-based inst_id convention so
        // CallStackFrame::call_inst_id/return_inst_id are directly
        // comparable to CallContextResult::instructions[].inst_id and
        // target_inst_id (0 continues to mean "did not return yet").
        frame.call_inst_id   = evt->call_inst_id + 1;
        frame.return_inst_id = (evt->return_inst_id != 0) ? evt->return_inst_id + 1 : 0;
        frame.is_tail_call   = evt->is_tail_call;
        result.call_stack.push_back(frame);
    }

    if (ctx.cancelled()) return PassResult::failed("CallContext: cancelled by user");
    ctx.progress(0.3f, "CallContext: collecting instruction window...");

    // ── Instruction window: small scan around the target ─────────────────
    // window_start is always >= 1, so window_start - 1 (the scan seed point)
    // never underflows.
    uint64_t window_start = (cfg_.target_inst_id > cfg_.context_before)
        ? cfg_.target_inst_id - cfg_.context_before : 1;
    uint64_t window_end = std::min<uint64_t>(cfg_.target_inst_id + cfg_.context_after, total_insts);

    uint64_t scan_seed = window_start - 1;
    uint64_t start_offset = (scan_seed > 0) ? index.offset_of(scan_seed, reader) : 0;
    auto it_start = (start_offset > 0)
        ? TraceReader::Iterator(&reader, start_offset)
        : reader.begin();

    uint64_t inst_id = scan_seed;
    for (auto it = it_start; it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        if (inst_id > window_end) break;
        if (inst_id < window_start) continue;

        auto inst = rec.as_inst();

        ContextInstruction ci;
        ci.inst_id = inst_id;
        ci.pc = inst.pc;
        ci.is_target = (inst_id == cfg_.target_inst_id);

        if (ci.is_target) {
            result.target_pc = inst.pc;
        }

        auto raw_opcode = code_table.opcode_at(inst.pc);
        if (raw_opcode) {
            auto dis = decoder.decode(inst.pc, *raw_opcode);
            if (dis) {
                ci.disassembly = std::string(dis->mnemonic) + " " + dis->op_str;
            }
        }

        ci.loop_depth = loops.loop_depth_at(inst.pc);

        result.instructions.push_back(std::move(ci));
    }

    if (result.target_pc == 0 && !result.instructions.empty()) {
        // Fallback: target fell outside the scanned window for some reason
        // (shouldn't normally happen since window always includes target).
        for (const auto& ci : result.instructions) {
            if (ci.is_target) { result.target_pc = ci.pc; break; }
        }
    }

    if (ctx.cancelled()) return PassResult::failed("CallContext: cancelled by user");
    ctx.progress(0.8f, "CallContext: resolving loop context...");

    // ── Loop context: which loop(s) — including all enclosing ancestors —
    // contain the target PC. LoopResult only indexes the innermost loop per
    // PC (pc_innermost_loop), so to report the full nesting chain we still
    // walk loops[] and test body_pcs membership; this is cheap (loop count
    // is typically small, tens to low hundreds even for large traces).
    if (result.target_pc != 0) {
        for (const auto& loop : loops.loops) {
            auto body_it = std::lower_bound(loop.body_pcs.begin(), loop.body_pcs.end(), result.target_pc);
            bool in_body = (body_it != loop.body_pcs.end() && *body_it == result.target_pc);
            if (!in_body) continue;
            CallContextResult::LoopContext lc;
            lc.header_pc = loop.header_pc;
            lc.nesting_depth = loop.nesting_depth;
            lc.total_iterations = loop.iteration_count;
            result.loop_contexts.push_back(lc);
        }
    }

    ctx.progress(1.0f, "CallContext: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

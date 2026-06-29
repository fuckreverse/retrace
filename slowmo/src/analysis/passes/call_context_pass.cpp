#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/loop_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"

#include <algorithm>
#include <cstring>

namespace tenet {

// ─── Call stack reconstruction (index-accelerated) ─────────────────────────
//
// Old approach: reader.begin() → scan forward to target → O(target_inst_id)
// New approach: index.offset_of(scan_start) → scan only last 100K → O(100K)

std::vector<CallStackFrame> CallContextPass::reconstruct_call_stack(
    PassContext& ctx, uint64_t target_inst_id) {

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    std::vector<CallStackFrame> stack;
    stack.reserve(cfg_.max_stack_depth);

    // Limit scan to last 100K instructions for efficiency
    uint64_t scan_start = (target_inst_id > 100000) ? target_inst_id - 100000 : 0;

    // Use index to seek directly to scan_start
    uint64_t start_offset = 0;
    if (scan_start > 0) {
        start_offset = index.offset_of(scan_start, reader);
    }

    std::vector<CallStackFrame> shadow_stack;
    shadow_stack.reserve(64);

    uint64_t inst_id = scan_start;

    auto it_start = (start_offset > 0)
        ? TraceReader::Iterator(&reader, start_offset)
        : reader.begin();

    uint64_t rs_progress_interval = std::max((target_inst_id - scan_start) / 100, uint64_t(1));
    for (auto it = it_start; it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        if (inst_id > target_inst_id) break;

        if ((inst_id - scan_start) % rs_progress_interval == 0 && ctx.cancelled()) {
            return {};  // cancelled — return empty stack
        }

        auto inst = rec.as_inst();

        // Get instruction bytes from code table
        auto raw_opcode = code_table.opcode_at(inst.pc);
        if (!raw_opcode) continue;
        uint32_t opcode = *raw_opcode;

        // Detect BL (immediate): 1001 01 [imm26]
        bool is_bl = (opcode & 0xFC000000u) == 0x94000000u;
        // Detect BLR: 1101 0110 0011 1111 0000 00 [Rn] 00000
        bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;
        // Detect RET: 1101 0110 0101 1111 0000 00 [Rn] 00000
        bool is_ret = (opcode & 0xFFFFFC1Fu) == 0xD65F0000u;

        if (is_bl || is_blr) {
            // Push call frame
            CallStackFrame frame;
            frame.call_site_pc = inst.pc;
            frame.call_inst_id = inst_id;
            frame.return_addr = inst.pc + 4;
            frame.callee_pc = 0;
            // Get LR value from reg_diff
            for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                auto diff = inst.reg_diff(d);
                if (diff.index == 30) {  // LR is index 30
                    frame.return_addr = diff.value;
                }
            }
            shadow_stack.push_back(frame);
            // Use pop_front via swap instead of erase(begin) which is O(K)
            if (shadow_stack.size() > cfg_.max_stack_depth) {
                // Shift all elements left by 1 (more efficient than erase(begin))
                shadow_stack.erase(shadow_stack.begin());
            }
        } else if (is_ret && !shadow_stack.empty()) {
            shadow_stack.pop_back();
        }
    }

    // The shadow_stack now represents the call stack at target_inst_id
    stack = std::move(shadow_stack);
    std::reverse(stack.begin(), stack.end());  // Innermost first
    return stack;
}

// ─── Main pass execution (single merged scan) ─────────────────────────────
//
// Old approach: 2 separate reader.begin() scans (window + call stack).
// New approach: single scan from index.offset_of(scan_start) that does both:
//   1. Maintains shadow call stack
//   2. Collects context window instructions
// Both in one pass.

PassResult CallContextPass::run(PassContext& ctx) {
    if (cfg_.target_inst_id == 0) {
        return PassResult::skipped();
    }

    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& decoder = ctx.decoder();
    auto& code_table = ctx.code_table();
    const auto& loops = ctx.require<LoopResult>("loop");

    const uint64_t total_insts = index.inst_count();
    if (cfg_.target_inst_id > total_insts) {
        return PassResult::failed("target_inst_id exceeds trace length");
    }

    CallContextResult result;
    result.target_inst_id = cfg_.target_inst_id;

    ctx.progress(0.0f, "CallContext: single-pass collection...");

    // Determine the earliest point we need to start scanning:
    // - For call stack: target - 100K
    // - For context window: target - context_before
    uint64_t call_stack_start = (cfg_.target_inst_id > 100000)
        ? cfg_.target_inst_id - 100000 : 0;
    uint64_t window_start = (cfg_.target_inst_id > cfg_.context_before)
        ? cfg_.target_inst_id - cfg_.context_before : 1;
    uint64_t window_end = std::min(cfg_.target_inst_id + cfg_.context_after, total_insts);

    // Scan start is the earlier of the two
    uint64_t scan_start = std::min(call_stack_start, window_start);

    // Use index to seek
    uint64_t start_offset = 0;
    if (scan_start > 0) {
        start_offset = index.offset_of(scan_start, reader);
    }

    // Shadow call stack (maintained throughout the scan)
    std::vector<CallStackFrame> shadow_stack;
    shadow_stack.reserve(64);

    uint64_t inst_id = scan_start;

    auto it_start = (start_offset > 0)
        ? TraceReader::Iterator(&reader, start_offset)
        : reader.begin();

    const uint64_t run_total = window_end - scan_start;
    const uint64_t run_interval = std::max(run_total / 100, uint64_t(1));

    for (auto it = it_start; it != reader.end(); ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        inst_id++;
        if (inst_id > window_end) break;

        if ((inst_id - scan_start) % run_interval == 0) {
            ctx.progress(static_cast<float>(inst_id - scan_start) / static_cast<float>(run_total),
                         "CallContext: single-pass collection...");
            if (ctx.cancelled()) return PassResult::failed("CallContext: cancelled by user");
        }

        auto inst = rec.as_inst();

        // ── Call stack tracking (always active) ──
        auto raw_opcode2 = code_table.opcode_at(inst.pc);
        if (raw_opcode2) {
            uint32_t opcode = *raw_opcode2;

            bool is_bl = (opcode & 0xFC000000u) == 0x94000000u;
            bool is_blr = (opcode & 0xFFFFFC1Fu) == 0xD63F0000u;
            bool is_ret = (opcode & 0xFFFFFC1Fu) == 0xD65F0000u;

            if (is_bl || is_blr) {
                CallStackFrame frame;
                frame.call_site_pc = inst.pc;
                frame.call_inst_id = inst_id;
                frame.return_addr = inst.pc + 4;
                frame.callee_pc = 0;
                for (uint8_t d = 0; d < inst.reg_diff_count; d++) {
                    auto diff = inst.reg_diff(d);
                    if (diff.index == 30) {
                        frame.return_addr = diff.value;
                    }
                }
                shadow_stack.push_back(frame);
                if (shadow_stack.size() > cfg_.max_stack_depth) {
                    shadow_stack.erase(shadow_stack.begin());
                }
            } else if (is_ret && !shadow_stack.empty()) {
                shadow_stack.pop_back();
            }
        }

        // ── Context window collection (only when in range) ──
        if (inst_id >= window_start && inst_id <= window_end) {
            ContextInstruction ci;
            ci.inst_id = inst_id;
            ci.pc = inst.pc;
            ci.is_target = (inst_id == cfg_.target_inst_id);

            if (ci.is_target) {
                result.target_pc = inst.pc;
            }

            // Disassemble
            if (raw_opcode2) {
                auto dis = decoder.decode(inst.pc, *raw_opcode2);
                if (dis) {
                    ci.disassembly = std::string(dis->mnemonic) + " " + dis->op_str;
                }
            }

            // Loop depth at this PC
            ci.loop_depth = loops.loop_depth_at(inst.pc);

            result.instructions.push_back(std::move(ci));
        }
    }

    ctx.progress(0.7f, "CallContext: finalizing...");

    // The shadow_stack at this point is the call stack at target
    result.call_stack = std::move(shadow_stack);
    std::reverse(result.call_stack.begin(), result.call_stack.end());

    // Determine loop contexts for the target
    if (result.target_pc != 0) {
        for (size_t i = 0; i < loops.loops.size(); i++) {
            const auto& loop = loops.loops[i];
            auto body_it = std::lower_bound(loop.body_pcs.begin(), loop.body_pcs.end(), result.target_pc);
            if (body_it != loop.body_pcs.end() && *body_it == result.target_pc) {
                CallContextResult::LoopContext lc;
                lc.header_pc = loop.header_pc;
                lc.nesting_depth = loop.nesting_depth;
                lc.total_iterations = loop.iteration_count;
                lc.current_iteration = 0;
                result.loop_contexts.push_back(lc);
            }
        }
    }

    ctx.progress(1.0f, "CallContext: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet

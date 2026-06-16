#include "analysis/passes/function_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <stack>
#include <unordered_set>

namespace tenet {

// ─── FunctionResult methods ───────────────────────────────────────────────

std::vector<const CallEvent*> FunctionResult::call_stack_at(uint64_t inst_id) const {
    // Reconstruct call stack: walk call_events and build stack state
    std::vector<const CallEvent*> stack;
    for (auto& evt : call_events) {
        if (evt.call_inst_id > inst_id) break;

        if (evt.call_inst_id <= inst_id) {
            stack.push_back(&evt);
        }
        if (evt.return_inst_id != 0 && evt.return_inst_id <= inst_id) {
            // This call already returned
            if (!stack.empty()) stack.pop_back();
        }
    }
    return stack;
}

const FunctionInfo* FunctionResult::function_at(uint64_t inst_id) const {
    // Find which function contains this inst_id by checking active calls
    const CallEvent* innermost = nullptr;
    for (auto& evt : call_events) {
        if (evt.call_inst_id > inst_id) break;
        if (evt.return_inst_id == 0 || evt.return_inst_id >= inst_id) {
            innermost = &evt;
        }
    }
    if (!innermost) return nullptr;
    auto it = functions.find(innermost->target_pc);
    if (it == functions.end()) return nullptr;
    return &it->second;
}

// ─── Pass implementation ──────────────────────────────────────────────────

// Known non-returning functions (common in iOS/macOS AArch64 binaries)
static const std::unordered_set<std::string> kNonReturningSymbols = {
    "exit", "_exit", "abort", "__abort",
    "__cxa_throw", "__cxa_rethrow", "objc_exception_throw",
    "longjmp", "_longjmp", "siglongjmp",
    "pthread_exit", "__pthread_exit",
    "__assert_rtn", "__assert_fail",
    "__stack_chk_fail", "__fortify_fail",
    "swift_unexpectedError", "swift_fatalError",
};

PassResult FunctionPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder = ctx.decoder();

    const auto& hdr = reader.header();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    FunctionResult result;

    // ─── Pass 1: Standard BL/BLR → RET pairing ──────────────────────────
    // Also collect candidate tail-call sites (B/BR instructions) for Pass 2.

    struct StackFrame {
        size_t call_event_idx;
        uint64_t return_pc;     // LR at time of call (pc + 4 for BL)
        uint64_t entry_sp;      // SP when this frame was pushed (0 if unknown)
    };
    std::vector<StackFrame> call_stack;

    // Track SP incrementally: each inst record contains reg_diffs,
    // so we can cheaply maintain current SP by watching IDX_SP diffs.
    uint64_t current_sp = 0;
    bool sp_valid = false;

    // Tail call candidates: (inst_id, pc_of_B, target_pc_next_inst, sp_at_jump)
    struct TailCallCandidate {
        uint64_t inst_id;
        uint64_t jump_pc;
        uint64_t target_pc;     // filled from next instruction's PC
        uint64_t sp;            // SP at time of jump
        bool sp_known;
    };
    std::vector<TailCallCandidate> tail_candidates;

    uint64_t inst_id = 0;
    uint64_t processed = 0;
    uint64_t total = end - start;
    uint64_t non_local_unwinds = 0;  // counter for forced frame closures

    // Deferred state: we often need the NEXT instruction's PC to resolve
    // the previous instruction's semantics (tail call target, RET destination).
    bool prev_was_unconditional_jump = false;
    uint64_t prev_jump_inst_id = 0;
    uint64_t prev_jump_pc = 0;
    uint64_t prev_jump_sp = 0;
    bool prev_jump_sp_known = false;

    bool prev_was_ret = false;
    uint64_t prev_ret_inst_id = 0;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Anchor) {
            // Anchors give us a full register snapshot — update SP
            auto anchor = rec.as_anchor(hdr.num_gpr);
            if (hdr.num_gpr > IDX_SP) {
                current_sp = anchor.gpr_values[IDX_SP];
                sp_valid = true;
            }
            continue;
        }
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        auto inst = rec.as_inst();
        uint64_t pc = inst.pc;

        // Update SP from reg_diffs (incremental, zero-cost)
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (diff.index == IDX_SP) {
                current_sp = diff.value;
                sp_valid = true;
            }
        }

        // ─── Deferred RET resolution ─────────────────────────────────────
        // Now we know where the previous RET actually landed (pc).
        // Search the call_stack for a frame whose return_pc matches.
        if (prev_was_ret) {
            prev_was_ret = false;
            if (!call_stack.empty()) {
                // Fast path: top of stack matches (99% of normal code)
                if (call_stack.back().return_pc == pc) {
                    auto& top = call_stack.back();
                    auto& evt = result.call_events[top.call_event_idx];
                    evt.return_inst_id = prev_ret_inst_id;
                    result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
                    call_stack.pop_back();
                } else {
                    // Slow path: scan downward for matching return_pc.
                    // Frames above the match are victims of non-local exit
                    // (longjmp, exception, non-returning call that we missed).
                    bool found = false;
                    for (int i = static_cast<int>(call_stack.size()) - 1; i >= 0; --i) {
                        if (call_stack[i].return_pc == pc) {
                            // Found the true caller. Force-close everything above it.
                            for (int j = static_cast<int>(call_stack.size()) - 1; j > i; --j) {
                                auto& zombie = result.call_events[call_stack[j].call_event_idx];
                                zombie.return_inst_id = prev_ret_inst_id;
                                // Note: we don't add these to return_site_map_ because
                                // the RET instruction logically belongs to frame[i], not them.
                                call_stack.pop_back();
                                non_local_unwinds++;
                            }
                            // Now close the matching frame itself
                            auto& evt = result.call_events[call_stack[i].call_event_idx];
                            evt.return_inst_id = prev_ret_inst_id;
                            result.return_site_map_[prev_ret_inst_id] =
                                static_cast<size_t>(call_stack[i].call_event_idx);
                            call_stack.erase(call_stack.begin() + i);
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        // No match at all — this RET returns to a frame we never
                        // saw being called (e.g., we started tracing mid-execution).
                        // Just pop top as best-effort.
                        auto& top = call_stack.back();
                        auto& evt = result.call_events[top.call_event_idx];
                        evt.return_inst_id = prev_ret_inst_id;
                        result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
                        call_stack.pop_back();
                    }
                }
            }
        }

        // ─── Deferred tail-call candidate recording ──────────────────────
        if (prev_was_unconditional_jump) {
            tail_candidates.push_back({
                prev_jump_inst_id,
                prev_jump_pc,
                pc,  // target = where we actually landed
                prev_jump_sp,
                prev_jump_sp_known
            });
            prev_was_unconditional_jump = false;
        }

        // Decode instruction to classify
        auto opcode = code_table.opcode_at(pc);
        bool is_call = false;
        bool is_ret = false;
        bool is_unconditional_jump = false;

        if (opcode) {
            auto d = decoder.decode(pc, *opcode);
            if (d) {
                std::string_view m = d->mnemonic_sv();
                is_call = (m == "bl" || m == "blr");
                is_ret = (m == "ret");
                // B (unconditional branch) and BR (unconditional branch to register)
                // Exclude conditional branches: b.eq, b.ne, etc. have a '.' in mnemonic
                is_unconditional_jump = (m == "b" || m == "br");
            }
        }

        if (is_call) {
            uint64_t return_pc = pc + 4;

            CallEvent evt;
            evt.call_inst_id = inst_id;
            evt.return_inst_id = 0;
            evt.call_site_pc = pc;
            evt.target_pc = 0;
            evt.depth = call_stack.size();
            evt.is_tail_call = false;

            size_t evt_idx = result.call_events.size();
            result.call_site_map_[inst_id] = evt_idx;
            result.call_events.push_back(evt);

            call_stack.push_back({evt_idx, return_pc, sp_valid ? current_sp : 0});
        } else if (is_ret) {
            // ─── Deferred RET: record and resolve on next instruction ─────
            // We defer because we need the next PC to know the actual return
            // destination, which allows us to match against the correct frame
            // in the call stack (handling non-local exits correctly).
            prev_was_ret = true;
            prev_ret_inst_id = inst_id;
        } else if (is_unconditional_jump) {
            // Record as candidate for Pass 2 tail-call analysis.
            // We don't know the target yet (it's the next inst's PC).
            prev_was_unconditional_jump = true;
            prev_jump_inst_id = inst_id;
            prev_jump_pc = pc;
            prev_jump_sp = current_sp;
            prev_jump_sp_known = sp_valid;
        }

        // Fill in target_pc from previous call
        if (!result.call_events.empty()) {
            auto& last_evt = result.call_events.back();
            if (last_evt.target_pc == 0 && last_evt.call_inst_id == inst_id - 1) {
                last_evt.target_pc = pc;

                // Register function
                auto& func = result.functions[pc];
                if (func.entry_pc == 0) {
                    func.entry_pc = pc;
                    uint64_t static_pc = pc - hdr.module_slide;
                    func.name = fmt::format("sub_{:x}", static_pc);
                }
                func.total_calls++;
                func.call_event_indices.push_back(result.call_events.size() - 1);
            }
        }

        inst_id++;
        processed++;

        if (processed % 50000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
            if (ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
        }
    }

    // ─── Handle trailing deferred RET (trace ended after a RET) ─────────────
    if (prev_was_ret && !call_stack.empty()) {
        auto& top = call_stack.back();
        auto& evt = result.call_events[top.call_event_idx];
        evt.return_inst_id = prev_ret_inst_id;
        result.return_site_map_[prev_ret_inst_id] = top.call_event_idx;
        call_stack.pop_back();
    }

    // ─── Pass 2: Tail-call detection (ported from angr's two-stage heuristic) ─
    //
    // angr's core idea:
    //   Stage A: "Jump target is a known function entry" → strong evidence
    //   Stage B: "SP is restored to frame-entry value" → confirms tail call
    //
    // In our trace-based context we have an advantage: we can observe both
    // conditions directly from the execution trace without static analysis.
    //
    // We iterate until convergence: newly discovered function entries from
    // tail calls may enable detection of additional tail calls in later rounds.

    uint64_t tail_calls_detected = 0;
    constexpr int kMaxIterations = 4;  // Converges in 1-2 rounds typically

    // Track which candidates have been resolved (to avoid re-processing)
    std::vector<bool> resolved(tail_candidates.size(), false);

    for (int iteration = 0; iteration < kMaxIterations; ++iteration) {
        // Build the set of known function entry PCs (refreshed each iteration)
        std::unordered_set<uint64_t> known_entries;
        known_entries.reserve(result.functions.size());
        for (auto& [entry_pc, _] : result.functions) {
            known_entries.insert(entry_pc);
        }

        uint64_t new_this_round = 0;

        for (size_t ci = 0; ci < tail_candidates.size(); ++ci) {
            if (resolved[ci]) continue;
            auto& cand = tail_candidates[ci];

            // ─── Stage A (angr heuristic 1): target is known function entry
            bool target_is_known_entry = known_entries.count(cand.target_pc) > 0;

            if (!target_is_known_entry) {
                // Heuristic: if target is far from the jump (> 4KB), it's likely
                // inter-function. This catches tail calls to functions not yet
                // in our known set (will be resolved on later iterations).
                int64_t distance = static_cast<int64_t>(cand.target_pc) -
                                   static_cast<int64_t>(cand.jump_pc);
                if (std::abs(distance) < 4096) {
                    // Likely an intra-function branch (loop, if-else, etc.)
                    resolved[ci] = true;  // Never revisit short jumps
                    continue;
                }
                // For far jumps to unknown targets, we require SP evidence
                if (!cand.sp_known) continue;  // May resolve in later iteration
            }

            // ─── Stage B (angr heuristic 2): SP restoration check ────────
            // For known entries: accept unconditionally (high confidence).
            // For unknown-but-far targets with SP evidence: accept.
            // This mirrors angr's detect_tail_calls=True aggressive mode.

            bool accept = target_is_known_entry || cand.sp_known;

            if (accept) {
                // ─── Confirmed tail call: create a synthetic CallEvent ────

                CallEvent evt;
                evt.call_inst_id = cand.inst_id;
                evt.return_inst_id = 0;  // Tail call has no explicit return
                evt.call_site_pc = cand.jump_pc;
                evt.target_pc = cand.target_pc;
                evt.depth = 0;  // Depth is not meaningful for deferred detection
                evt.is_tail_call = true;

                size_t evt_idx = result.call_events.size();
                result.call_site_map_[cand.inst_id] = evt_idx;
                result.call_events.push_back(evt);

                // Register the target as a function (if not already)
                auto& func = result.functions[cand.target_pc];
                if (func.entry_pc == 0) {
                    func.entry_pc = cand.target_pc;
                    uint64_t static_pc = cand.target_pc - hdr.module_slide;
                    func.name = fmt::format("sub_{:x}", static_pc);
                }
                func.total_calls++;
                func.call_event_indices.push_back(evt_idx);

                tail_calls_detected++;
                new_this_round++;
                resolved[ci] = true;
            }
        }

        // Converged: no new tail calls found this round
        if (new_this_round == 0) break;
    }

    // ─── Calculate total_instructions per function ────────────────────────

    for (auto& [entry_pc, func] : result.functions) {
        uint64_t total_insts = 0;
        for (auto idx : func.call_event_indices) {
            auto& evt = result.call_events[idx];
            if (evt.return_inst_id > evt.call_inst_id) {
                total_insts += evt.return_inst_id - evt.call_inst_id;
            }
        }
        func.total_instructions = total_insts;
    }

    ctx.progress(1.0f, fmt::format(
        "Functions: {} unique, {} call events, {} tail calls, {} non-local unwinds",
        result.functions.size(),
        result.call_events.size(),
        tail_calls_detected,
        non_local_unwinds));
    return PassResult::success(std::move(result));
}

}  // namespace tenet

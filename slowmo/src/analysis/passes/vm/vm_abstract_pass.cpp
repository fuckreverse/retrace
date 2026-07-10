#include "analysis/passes/vm/vm_abstract_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/xref_pass.h"
#include "common/aarch64_classify.h"
#include "common/logger.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "io/code_table.h"
#include "io/trace_reader.h"

#include <fmt/core.h>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace tenet {

// ─── Internal helpers ────────────────────────────────────────────────────────

namespace {

/// Number of dispatch iterations to sample for register state comparison.
constexpr uint32_t MAX_SAMPLE_ITERATIONS = 16;


// ─── Find indirect branches in loop body ─────────────────────────────────

/// Locate the dispatch instruction inside an ALREADY-HINTED dispatcher loop
/// (`VMConfig::dispatcher->loop_header_pc`). This is structural completion,
/// not detection: the loop itself is a caller-provided fact, and a dispatch
/// loop body has exactly one indirect branch by construction, so finding it
/// mechanically (CFG terminator lookup, falling back to a raw opcode scan)
/// is deterministic. Only used when the caller supplies `loop_header_pc` but
/// omits `indirect_branch_pc` — supplying both skips this entirely.
/// Returns the PC of the first indirect branch found, or 0 if none.
/// Sets `is_blr` to true if the found instruction is BLR (call-table dispatch).
uint64_t find_indirect_branch_in_loop(
    const LoopInfo& loop,
    const CFGResult& cfg,
    const CodeTable& code_table,
    bool& is_blr)
{
    is_blr = false;

    // Prefer CFG terminator classification (more reliable)
    for (uint64_t body_pc : loop.body_pcs) {
        auto it = cfg.blocks.find(body_pc);
        if (it == cfg.blocks.end()) continue;
        if (it->second.terminator == TerminatorKind::IndirectBranch) {
            // Check opcode to distinguish BR vs BLR
            auto code = code_table.opcode_at(it->second.end_pc);
            if (code.has_value()) {
                is_blr = aarch64::is_blr(*code);
            }
            return it->second.end_pc;
        }
    }

    // Fallback: scan raw opcode bytes for BR/BLR encoding
    for (uint64_t body_pc : loop.body_pcs) {
        auto code = code_table.opcode_at(body_pc);
        if (!code.has_value()) continue;
        uint32_t opcode = *code;
        if (aarch64::is_br(opcode)) {
            return body_pc;
        }
        if (aarch64::is_blr(opcode)) {
            is_blr = true;
            return body_pc;
        }
    }
    return 0;
}

// ─── Classify dispatcher type ────────────────────────────────────────────

/// Purely mechanical classification from the already-hinted dispatch
/// instruction's encoding — NOT a statistical heuristic. `is_blr` is a fact
/// read directly from the opcode at the (hint-provided) indirect-branch PC,
/// so "BLR → CallTable" is deterministic. When it's a plain BR, we label it
/// IndirectBranch; distinguishing a genuine WhileSwitch (compare-cascade)
/// from a jump-table IndirectBranch from trace shape alone is exactly the
/// kind of guess static analysis already answers for free — callers who
/// care about that distinction should set `VMConfig::dispatch_type_hint`
/// explicitly instead of relying on this fallback.
DispatchType classify_dispatch_type(bool is_blr) {
    return is_blr ? DispatchType::CallTable : DispatchType::IndirectBranch;
}

// ─── HandlerExecution — one VM-instruction's native span ────────────────
//
// In the unified anchor-based model, one HandlerExecution is created per
// anchor hit (one per VM instruction).  The native instruction range
// [handler_first_inst_id, handler_last_inst_id] is computed from adjacent
// anchor inst_ids — no state-machine scan is needed.

struct HandlerExecution {
    uint64_t dispatch_inst_id = 0;   // inst_id of the anchor hit
    uint64_t handler_entry_pc = 0;   // Always 0 in the unified model (no handler attribution)
    uint64_t handler_first_inst_id = 0;  // dispatch_inst_id + 1 (for post-fetch register reads)
    uint64_t handler_last_inst_id = 0;   // next_anchor_inst_id - 1 (or dispatch_inst_id for the last step)
    uint64_t regs_read_mask = 0;
    uint64_t regs_written_mask = 0;
    uint32_t mem_reads = 0;
    uint32_t mem_writes = 0;
    std::vector<uint64_t> body_pcs;  // unused in the unified model (kept for struct compatibility)
};

}  // anonymous namespace

// ─── VMAbstractPass::run ─────────────────────────────────────────────────

PassResult VMAbstractPass::run(PassContext& ctx) {
    // ── Step 1: Get dependencies ────────────────────────────────────────
    const auto& loop_result = ctx.require<LoopResult>("loop");
    const auto& cfg_result  = ctx.require<CFGResult>("cfg");
    const auto& xref        = ctx.require<XrefResult>("xref");

    auto& regfile    = ctx.regfile();
    auto& code_table = ctx.code_table();

    VMAbstractResult result;
    const auto& range = ctx.range();

    ctx.progress(0.0f, "VM abstract: scanning for dispatcher candidates...");

    // ── Step 2: Resolve anchor and collect inst_ids ──────────────────────
    //
    // The unified model: collect "anchor inst_ids" — one per VM instruction
    // — from one of three anchor forms (see DispatcherHint docs):
    //   (a) single PC  (b) PC set  (c) memory write
    // No state machine, no trace scan — the anchor hit list IS the execution
    // list.  Native instruction ranges are derived from adjacent anchors.

    std::vector<uint64_t> anchor_inst_ids;  // sorted, one per VM instruction
    uint64_t anchor_header_pc = 0;          // primary PC (for display), 0 for mem anchor
    uint64_t anchor_ibp = 0;                // indirect branch PC (for display-label auto-classification)
    bool is_mem_anchor = false;

    if (config_.dispatcher.has_value() &&
        config_.dispatcher->mem_anchor_addr != 0) {
        // ── Form (c): memory-write anchor ────────────────────────────────
        is_mem_anchor = true;
        anchor_header_pc = 0;
        auto write_ids = ctx.memory().write_history(
            config_.dispatcher->mem_anchor_addr, config_.dispatcher->mem_anchor_size);
        anchor_inst_ids.reserve(std::min<size_t>(write_ids.size(), 20000));
        for (uint64_t iid : write_ids) {
            if (iid < range.start_inst_id) continue;
            if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
            anchor_inst_ids.push_back(iid);
            if (anchor_inst_ids.size() >= 20000) break;
        }
    } else {
        // ── Form (a)/(b): PC anchor (single PC or PC set) ────────────────
        // Build the PC set from: dispatcher->anchor_pcs + loop_header_pc
        // + threaded_dispatch_pcs (deprecated alias).
        std::vector<uint64_t> pcs;
        if (config_.dispatcher.has_value()) {
            if (config_.dispatcher->loop_header_pc != 0)
                pcs.push_back(config_.dispatcher->loop_header_pc);
            for (uint64_t pc : config_.dispatcher->anchor_pcs)
                pcs.push_back(pc);
            anchor_ibp = config_.dispatcher->indirect_branch_pc;
        }
        for (uint64_t pc : config_.threaded_dispatch_pcs)
            pcs.push_back(pc);

        // Deduplicate
        std::sort(pcs.begin(), pcs.end());
        pcs.erase(std::unique(pcs.begin(), pcs.end()), pcs.end());

        anchor_header_pc = pcs.empty() ? 0 : pcs.front();

        // Collect xref hits for each PC (with slide fixup for the primary PC)
        uint64_t slide = ctx.reader().header().module_slide;
        uint64_t base  = ctx.reader().header().module_base;
        for (uint64_t pc : pcs) {
            uint64_t effective_pc = pc;
            if (!xref.has_pc(pc)) {
                uint64_t guess_plus  = pc + slide;
                uint64_t guess_minus = pc - slide;
                bool plus_hits  = xref.has_pc(guess_plus);
                bool minus_hits = xref.has_pc(guess_minus);

                if (plus_hits) {
                    if (pc == pcs.front()) {
                        LOG_WARN_M(::tenet::log::Module::Analysis,
                            "VM abstract: hinted PC {:#x} was never executed (0 xref hits), "
                            "but {:#x} (= hint + module_slide {:#x}) WAS executed {} time(s). "
                            "Your hints file almost certainly has the STATIC/file address — "
                            "use {:#x} as dispatcher_pc instead (this trace's module_base={:#x}).",
                            pc, guess_plus, slide,
                            xref.execution_count(guess_plus), guess_plus, base);
                    }
                    effective_pc = guess_plus;
                } else if (minus_hits) {
                    if (pc == pcs.front()) {
                        LOG_WARN_M(::tenet::log::Module::Analysis,
                            "VM abstract: hinted PC {:#x} was never executed (0 xref hits), "
                            "but {:#x} (= hint - module_slide {:#x}) WAS executed {} time(s). "
                            "Your hints file may have a runtime address from a DIFFERENT "
                            "trace/run (ASLR slide changes per launch) — use {:#x} as "
                            "dispatcher_pc for THIS trace instead.",
                            pc, guess_minus, slide,
                            xref.execution_count(guess_minus), guess_minus);
                    }
                    effective_pc = guess_minus;
                } else {
                    if (pc == pcs.front()) {
                        LOG_WARN_M(::tenet::log::Module::Analysis,
                            "VM abstract: hinted PC {:#x} was never executed in this trace "
                            "(0 xref hits), and neither hint+slide ({:#x}) nor hint-slide "
                            "({:#x}) was executed either — this trace's module_base={:#x} "
                            "module_slide={:#x}. Double-check the address comes from THIS "
                            "binary/run (not a stale IDA bookmark or a different trace), and "
                            "that it's inside the traced range.",
                            pc, guess_plus, guess_minus, base, slide);
                    }
                    continue;
                }
            }
            for (uint64_t iid : xref.inst_ids_at(effective_pc)) {
                if (iid < range.start_inst_id) continue;
                if (range.end_inst_id != UINT64_MAX && iid >= range.end_inst_id) break;
                anchor_inst_ids.push_back(iid);
            }
            LOG_INFO_M(::tenet::log::Module::Analysis,
                "VM abstract: anchor PC {:#x} hit in [{}, {})",
                effective_pc, range.start_inst_id,
                range.end_inst_id == UINT64_MAX ? -1 : static_cast<int64_t>(range.end_inst_id));
        }
        // Merge-sort the collected inst_ids (multiple PC streams may interleave)
        std::sort(anchor_inst_ids.begin(), anchor_inst_ids.end());
    }

    // No anchor inst_ids means the caller didn't supply a usable hint, or the
    // hinted PC(s) were never executed.  This pass never scans loops looking
    // for "VM-shaped" candidates — see VMConfig's class comment.
    if (anchor_inst_ids.empty()) {
        if (!config_.dispatcher.has_value() && config_.threaded_dispatch_pcs.empty()) {
            static constexpr const char* kMsg =
                "VM abstract: no dispatcher hint provided (set VMConfig::dispatcher "
                "with loop_header_pc / anchor_pcs / mem_anchor_addr from static analysis)";
            ctx.progress(1.0f, kMsg);
            LOG_WARN_M(::tenet::log::Module::Analysis, "{}", kMsg);
        } else {
            static constexpr const char* kMsg =
                "VM abstract: no valid VM anchor found (hinted PC(s) matched "
                "fewer than 3 times in the analysis range — see prior log lines "
                "for per-PC hit counts)";
            ctx.progress(1.0f, kMsg);
            LOG_WARN_M(::tenet::log::Module::Analysis, "{}", kMsg);
        }
        return PassResult::success(std::move(result));
    }

    if (anchor_inst_ids.size() < 3) {
        ctx.progress(1.0f, fmt::format(
            "VM abstract: only {} anchor hits (need >= 3), not a VM",
            anchor_inst_ids.size()));
        LOG_WARN_M(::tenet::log::Module::Analysis,
            "VM abstract: only {} anchor hits (need >= 3)", anchor_inst_ids.size());
        return PassResult::success(std::move(result));
    }

    if (ctx.cancelled()) return PassResult::failed("Cancelled");

    ctx.progress(0.15f, fmt::format(
        "VM abstract: anchor resolved ({} hits), building VM steps...",
        anchor_inst_ids.size()));

    // ── Step 3: Build HandlerExecution list from anchor inst_ids ────────
    //
    // One HandlerExecution per anchor hit.  The native instruction range
    // [handler_first_inst_id, handler_last_inst_id] is derived from adjacent
    // anchors: step N spans [anchor_N, anchor_{N+1}).  The last step has no
    // next anchor, so its range is just [anchor_N, anchor_N] (conservative —
    // we don't know where the final VM instruction ends).

    std::vector<HandlerExecution> executions;
    executions.reserve(anchor_inst_ids.size());
    for (size_t i = 0; i < anchor_inst_ids.size(); ++i) {
        uint64_t iid = anchor_inst_ids[i];
        HandlerExecution exec;
        exec.dispatch_inst_id      = iid;
        exec.handler_entry_pc      = 0;   // no handler attribution in unified model
        // handler_first = dispatch+1 so that opcode_from_reg reads
        // state_before(iid+1) == state_after(iid), capturing the value
        // written by the fetch instruction (e.g. LDR W1,[X8,X0]).
        exec.handler_first_inst_id = iid + 1;
        // handler_last = next_anchor - 1 (the instruction just before the
        // next fetch cycle).  For the last step, use iid itself.
        exec.handler_last_inst_id  = (i + 1 < anchor_inst_ids.size())
            ? anchor_inst_ids[i + 1] - 1
            : iid;
        executions.push_back(exec);
    }

    if (executions.empty()) {
        ctx.progress(1.0f, "VM abstract: no handler executions found");
        return PassResult::success(std::move(result));
    }

    // In the unified model there is no dynamic handler discovery —
    // handler_entry_pc is always 0.  The handler list (Step 6) is built
    // purely from config_.handler_entry_pcs hints.
    ctx.progress(0.6f, fmt::format(
        "VM abstract: {} anchor-based VM steps", executions.size()));

    // ── Step 4: Fill dispatcher info + auto-classify display label ──────

    result.dispatcher.loop_header_pc     = anchor_header_pc;
    result.dispatcher.indirect_branch_pc = anchor_ibp;
    result.dispatcher.iteration_count    = executions.size();
    result.dispatcher.confidence         = 0.9f;  // user-provided hint

    // Dispatch type: use the caller's explicit hint when available, else
    // try mechanical auto-classification (BLR → CallTable, BR → IndirectBranch)
    // for single-PC anchors with a found loop.  This is a display label only.
    if (config_.dispatch_type_hint != DispatchType::Unknown &&
        config_.dispatch_type_hint != DispatchType::FetchOnly) {
        result.dispatcher.dispatch_type = config_.dispatch_type_hint;
    } else {
        bool is_blr = false;
        uint64_t ibp = anchor_ibp;
        if (ibp == 0 && anchor_header_pc != 0 && !is_mem_anchor) {
            // Find indirect branch in the loop at anchor_header_pc
            for (size_t i = 0; i < loop_result.loops.size(); ++i) {
                if (loop_result.loops[i].header_pc == anchor_header_pc) {
                    ibp = find_indirect_branch_in_loop(
                        loop_result.loops[i], cfg_result, code_table, is_blr);
                    break;
                }
            }
        } else if (ibp != 0) {
            auto code = code_table.opcode_at(ibp);
            if (code.has_value()) is_blr = aarch64::is_blr(*code);
        }
        if (ibp != 0) {
            result.dispatcher.indirect_branch_pc = ibp;
            result.dispatcher.dispatch_type = classify_dispatch_type(is_blr);
        } else {
            result.dispatcher.dispatch_type = DispatchType::FetchOnly;
        }
    }

    // Identify state vs invariant registers across dispatch iterations
    {
        uint32_t n = std::min(static_cast<uint32_t>(anchor_inst_ids.size()),
                              MAX_SAMPLE_ITERATIONS);
        std::vector<RegState> states;
        states.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            states.push_back(regfile.state_before(anchor_inst_ids[i]));
        }
        for (uint8_t r = 0; r <= 28; ++r) {
            bool changed = false;
            for (uint32_t i = 1; i < n; ++i) {
                if (states[i].gpr[r] != states[0].gpr[r]) {
                    changed = true; break;
                }
            }
            if (changed) result.dispatcher.state_regs.push_back(r);
            else         result.dispatcher.invariant_regs.push_back(r);
        }
    }

    // ── Step 5: Identify VM-PC source ───────────────────────────────────
    //
    // VM-PC is derived from a field named "pc" or "ip" in either
    // vm_context->ctx_fields or vm_register_file->regs.  This unifies the
    // formerly separate vm_pc_reg hint with the ctx/regs definitions,
    // eliminating the duplicate "pc" definition problem.
    //
    // The field can be:
    //   (a) Host-register-backed (vm_registers with from_host_reg set) —
    //       read directly from RegisterFile.
    //   (b) Memory-backed (ctx_fields or vm_registers with offset) —
    //       read via MemoryModel at ctx_base/rf_base + offset.

    ctx.progress(0.65f, "VM abstract: identifying VM-PC source...");

    // Find the VM-PC field in ctx_fields or vm_registers.
    const VMContextHint::Field* ctx_pc_field = nullptr;
    if (config_.vm_context.has_value() && config_.vm_context->ctx_base_reg != 0xFF) {
        for (const auto& f : config_.vm_context->fields) {
            if (f.name == "pc" || f.name == "ip") {
                ctx_pc_field = &f;
                break;
            }
        }
    }
    const VMRegisterFileHint::VMReg* vmreg_pc = nullptr;
    if (config_.vm_register_file.has_value()) {
        for (const auto& r : config_.vm_register_file->regs) {
            if (r.name == "pc" || r.name == "ip") {
                vmreg_pc = &r;
                break;
            }
        }
    }
    bool has_vm_pc = (ctx_pc_field != nullptr) || (vmreg_pc != nullptr);

    // Helper: read VM-PC value at a given dispatch inst_id.
    // Returns nullopt if the value cannot be read.
    auto& memory_ref = ctx.memory();
    auto read_vm_pc = [&](uint64_t inst_id) -> std::optional<uint64_t> {
        auto state = regfile.state_before(inst_id);
        if (vmreg_pc) {
            // Mode (b): host-register-backed
            if (vmreg_pc->from_host_reg != 0xFF && vmreg_pc->from_host_reg <= 28) {
                return state.gpr[vmreg_pc->from_host_reg];
            }
            // Mode (a): memory-backed via rf_base or ctx_base
            uint64_t base = 0;
            bool base_valid = false;
            if (config_.vm_register_file->rf_base_reg != 0xFF) {
                base = state.gpr[config_.vm_register_file->rf_base_reg];
                base_valid = true;
            } else if (config_.vm_context.has_value() &&
                       config_.vm_context->ctx_base_reg != 0xFF) {
                base = state.gpr[config_.vm_context->ctx_base_reg];
                base_valid = true;
            }
            if (!base_valid) return std::nullopt;
            uint8_t sz = (vmreg_pc->size > 0 && vmreg_pc->size <= 8)
                             ? vmreg_pc->size : uint8_t(8);
            auto mem = memory_ref.read(base + vmreg_pc->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        if (ctx_pc_field && config_.vm_context->ctx_base_reg != 0xFF) {
            uint64_t base = state.gpr[config_.vm_context->ctx_base_reg];
            uint8_t sz = (ctx_pc_field->size > 0 && ctx_pc_field->size <= 8)
                             ? ctx_pc_field->size : uint8_t(8);
            auto mem = memory_ref.read(base + ctx_pc_field->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        return std::nullopt;
    };

    result.vm_pc_tracked = has_vm_pc;

    // Infer bytecode address range from observed VM-PC values.
    // Sample from the first N anchor inst_ids.
    if (has_vm_pc) {
        uint32_t n = std::min(static_cast<uint32_t>(anchor_inst_ids.size()),
                              MAX_SAMPLE_ITERATIONS);
        std::vector<uint64_t> sample_inst_ids(
            anchor_inst_ids.begin(),
            anchor_inst_ids.begin() + n);
        uint32_t n_real = static_cast<uint32_t>(sample_inst_ids.size());
        uint64_t min_vpc = UINT64_MAX, max_vpc = 0;
        for (uint32_t i = 0; i < n_real; ++i) {
            auto vpc = read_vm_pc(sample_inst_ids[i]);
            if (!vpc) continue;
            if (*vpc < min_vpc) min_vpc = *vpc;
            if (*vpc > max_vpc) max_vpc = *vpc;
        }
        if (min_vpc != UINT64_MAX) {
            result.bytecode_base = min_vpc;
            uint64_t opcode_size = 8;  // default assumption
            if (config_.opcode_format.has_value() && config_.opcode_format->opcode_size > 0) {
                opcode_size = config_.opcode_format->opcode_size;
            }
            result.bytecode_end = max_vpc + opcode_size;
        }
    }

    // ── Step 6: Build handler objects ────────────────────────────────────

    ctx.progress(0.7f, "VM abstract: building handler profiles...");

    // Merge provided handler PCs with discovered ones (deduplicated)
    ankerl::unordered_dense::set<uint64_t> handler_pc_set;
    std::vector<uint64_t> handler_pcs;
    auto add_handler_pc = [&](uint64_t pc) {
        if (handler_pc_set.insert(pc).second) handler_pcs.push_back(pc);
    };
    for (uint64_t pc : config_.handler_entry_pcs) add_handler_pc(pc);
    // In the unified model, handler_entry_pc is always 0, so there are no
    // dynamically discovered handler PCs — the handler list comes entirely
    // from config_.handler_entry_pcs (hints from static analysis).
    std::sort(handler_pcs.begin(), handler_pcs.end());

    // Group executions by handler entry PC
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> exec_by_handler;
    for (size_t i = 0; i < executions.size(); ++i) {
        exec_by_handler[executions[i].handler_entry_pc].push_back(i);
    }

    for (uint64_t hpc : handler_pcs) {
        VMHandler handler;
        handler.entry_pc = hpc;

        auto it = exec_by_handler.find(hpc);
        if (it != exec_by_handler.end()) {
            handler.execution_count = it->second.size();

            // Merge register/memory effects and body PCs from all executions
            ankerl::unordered_dense::set<uint64_t> all_body_pcs;
            all_body_pcs.insert(hpc);
            for (size_t idx : it->second) {
                const auto& exec = executions[idx];
                handler.regs_read_mask  |= exec.regs_read_mask;
                handler.regs_written_mask |= exec.regs_written_mask;
                handler.mem_reads += exec.mem_reads;
                handler.mem_writes += exec.mem_writes;
                for (uint64_t bpc : exec.body_pcs) all_body_pcs.insert(bpc);
            }

            // Build sorted body_pcs list
            handler.body_pcs.assign(all_body_pcs.begin(), all_body_pcs.end());
            std::sort(handler.body_pcs.begin(), handler.body_pcs.end());

            // exit_pc = last body PC (highest address in the handler)
            if (!handler.body_pcs.empty()) {
                handler.exit_pc = handler.body_pcs.back();
            }
        }

        // Apply semantic label from config hint
        auto label_it = config_.handler_names.find(hpc);
        if (label_it != config_.handler_names.end()) {
            handler.label = label_it->second;
        }

        result.handler_by_pc[hpc] = result.handlers.size();
        result.handlers.push_back(std::move(handler));
    }

    // ── Step 6b: VM architecture type ───────────────────────────────────
    //
    // Always taken from the hint — never inferred from handler memory-access
    // ratios. Load/store balance is a weak, easily-confounded signal (a
    // register machine handler that only reads, or a stack machine handler
    // that swaps two slots, looks identical to the "wrong" category), and
    // static analysis already knows the answer with certainty. Prefer
    // reading `vm_register_file` (has_stack()/has_regs()/is_mixed()) when
    // you need this programmatically.
    result.arch_type = config_.arch_type_hint;

    // ── Step 6c: (removed) ──
    // Previously called regfile.warm_range() to pre-populate the LRU cache.
    // Now Step 7 uses a RegisterFileCursor (forward-only sequential scan)
    // which makes warm_range unnecessary — the cursor applies each diff
    // exactly once, with zero cache lookup overhead.

    // ── Step 7: Build VM execution trace (step sequence) ────────────────
    //
    // Uses a RegisterFileCursor for O(1)-amortised register state
    // reconstruction. The cursor advances forward through the trace,
    // applying each instruction's diffs exactly once. Total cursor work
    // across all steps = O(N) where N is the trace span, regardless of
    // how many steps there are or how far apart their inst_ids are.

    ctx.progress(0.8f, "VM abstract: building VM step sequence...");

    result.steps.reserve(executions.size());

    // Create a forward-only cursor for sequential register state access.
    // anchor_inst_ids are sorted ascending, so the cursor only moves forward.
    RegisterFileCursor cursor(ctx.reader(), ctx.index());

    // Helper: read VM-PC value from a pre-fetched register state.
    // This replaces the read_vm_pc lambda (which called state_before()
    // internally) and avoids redundant register rebuilds.
    auto read_vm_pc_with_state = [&](const RegState& state,
                                      uint64_t inst_id) -> std::optional<uint64_t> {
        if (vmreg_pc) {
            if (vmreg_pc->from_host_reg != 0xFF && vmreg_pc->from_host_reg <= 28) {
                return state.gpr[vmreg_pc->from_host_reg];
            }
            uint64_t base = 0;
            bool base_valid = false;
            if (config_.vm_register_file->rf_base_reg != 0xFF) {
                base = state.gpr[config_.vm_register_file->rf_base_reg];
                base_valid = true;
            } else if (config_.vm_context.has_value() &&
                       config_.vm_context->ctx_base_reg != 0xFF) {
                base = state.gpr[config_.vm_context->ctx_base_reg];
                base_valid = true;
            }
            if (!base_valid) return std::nullopt;
            uint8_t sz = (vmreg_pc->size > 0 && vmreg_pc->size <= 8)
                             ? vmreg_pc->size : uint8_t(8);
            auto mem = memory_ref.read(base + vmreg_pc->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        if (ctx_pc_field && config_.vm_context->ctx_base_reg != 0xFF) {
            uint64_t base = state.gpr[config_.vm_context->ctx_base_reg];
            uint8_t sz = (ctx_pc_field->size > 0 && ctx_pc_field->size <= 8)
                             ? ctx_pc_field->size : uint8_t(8);
            auto mem = memory_ref.read(base + ctx_pc_field->offset, sz, inst_id);
            for (uint8_t b = 0; b < sz; ++b)
                if (!mem.known[b]) return std::nullopt;
            uint64_t val = 0;
            std::memcpy(&val, mem.data.data(), sz);
            return val;
        }
        return std::nullopt;
    };

    // ── Rolling key state ────────────────────────────────────────────────
    //
    // When the deobfuscation pipeline contains rolling-key ops (xor_rolling,
    // add_rolling, sub_rolling), their `imm` field seeds the initial key.
    // After each decoded opcode, the key is updated according to
    // `rolling_key_update`. This vector mirrors the deobfuscation_steps
    // array — rolling_keys[i] holds the CURRENT rolling key for step i
    // (only meaningful when step i is a rolling op; other entries are 0).
    std::vector<uint64_t> rolling_keys;
    if (config_.opcode_format.has_value()) {
        auto& ofmt = *config_.opcode_format;
        rolling_keys.resize(ofmt.deobfuscation_steps.size(), 0);
        for (size_t i = 0; i < ofmt.deobfuscation_steps.size(); ++i) {
            using Op = OpcodeDeobfStep::Op;
            auto op = ofmt.deobfuscation_steps[i].op;
            if (op == Op::xor_rolling || op == Op::add_rolling || op == Op::sub_rolling) {
                rolling_keys[i] = ofmt.deobfuscation_steps[i].imm;  // seed
            }
        }
    }

    // This loop (one VMStep built per handler execution — register-state
    // reconstruction via regfile.state_before(), optional memory reads for
    // Mode-A opcode decode, plus the deobfuscation pipeline below) is the
    // single most expensive part of VMAbstractPass for large traces:
    // `executions` commonly holds hundreds of thousands to millions of
    // entries, yet previously this whole block ran between the 0.8 and 1.0
    // progress marks with NO intermediate update — the UI would sit at 80%
    // for the entire duration and then jump straight to 100%, and a
    // cancellation request wasn't observed until the loop finished. Report
    // progress in batches (cheap, no string formatting) and check
    // ctx.cancelled() periodically so both the progress bar and Cancel
    // button behave responsively here too.
    const size_t total_execs = executions.size();
    constexpr size_t kProgressBatch = 4096;
    size_t exec_idx = 0;
    for (const auto& exec : executions) {
        if ((exec_idx % kProgressBatch) == 0) {
            if (ctx.cancelled()) return PassResult::failed("Cancelled");
            if (total_execs > 0) {
                ctx.progress(0.8f + 0.2f * static_cast<float>(exec_idx) /
                             static_cast<float>(total_execs));
            }
        }
        ++exec_idx;

        VMStep step;
        step.inst_id_start = exec.dispatch_inst_id;
        step.inst_id_end = exec.handler_last_inst_id;
        step.handler_entry_pc = exec.handler_entry_pc;

        // Decode VM-PC value and opcode
        //
        // Timing contract for register reads:
        //   dispatch_inst_id  = inst_id of the loop-header instruction.
        //   handler_first_inst_id = inst_id of the very first instruction of
        //                          the handler body (after the indirect branch).
        //
        //   state_before(dispatch_inst_id):  register values BEFORE the
        //       dispatcher loop body starts executing.  Good for VM-PC (which
        //       was set by the previous handler and has not been touched yet by
        //       the current dispatcher iteration).
        //
        //   state_before(handler_first_inst_id): register values just before
        //       the handler's first instruction.  This is AFTER the dispatcher
        //       has fully executed the opcode-decode stub (e.g. bl 0x885F48 for
        //       the bnlabel VMP), so any decode result in a scratch register
        //       (e.g. x0) reflects the decoded opcode for this step.
        // ── Advance cursor to dispatch_inst_id ──────────────────────────
        // This is the primary register-state query for this step.
        // The cursor advances forward from its previous position,
        // applying diffs only for the instructions in between.
        const RegState& state_dispatch = cursor.advance_to(exec.dispatch_inst_id);

        if (has_vm_pc) {
            // VM-PC: read at dispatcher entry using the cursor's state.
            auto vpc = read_vm_pc_with_state(state_dispatch, exec.dispatch_inst_id);
            if (vpc) {
                step.vm_pc_value = *vpc;
                step.vm_pc_valid = true;
            }

            if (config_.opcode_format.has_value()) {
                auto& ofmt = *config_.opcode_format;

                // ── Mode B: register snapshot after decode stub ────────────
                // The target register (e.g. x0) is set by the dispatcher's
                // opcode-decode stub which runs BETWEEN dispatch_inst_id and
                // handler_first_inst_id.  We must read it at the handler
                // boundary (state_before handler entry) — NOT at the loop
                // header where the stub hasn't run yet.
                if (ofmt.opcode_from_reg != 0xFF) {
                    if (exec.handler_first_inst_id != 0) {
                        // Advance cursor to handler_first_inst_id (forward-only,
                        // just a few instructions ahead of dispatch_inst_id).
                        const RegState& state_handler =
                            cursor.advance_to(exec.handler_first_inst_id);
                        step.opcode_value = state_handler.gpr[ofmt.opcode_from_reg];
                    } else {
                        step.opcode_value = state_dispatch.gpr[ofmt.opcode_from_reg];
                    }
                    step.opcode_valid = true;
                }
                // ── Mode A: memory read at VM-PC + deobfuscation pipeline ──
                // Read the raw opcode bytes from the bytecode buffer at the
                // address (vm_pc_value + opcode_byte_offset).  This works only
                // when the bytecode memory was written through the trace.  If
                // the bytecode is a read-only mmap'd file section with no
                // recorded writes, MemReadResult::known[] will be all-false and
                // decoding silently skips this step.
                else if (ofmt.opcode_size > 0 && ofmt.opcode_size <= 8) {
                    auto& memory = ctx.memory();
                    // Apply opcode_byte_offset: skip prefix bytes to reach the opcode field.
                    uint64_t read_addr = step.vm_pc_value +
                                        static_cast<uint64_t>(ofmt.opcode_byte_offset);
                    auto mem = memory.read(read_addr,
                                           static_cast<uint8_t>(ofmt.opcode_size),
                                           exec.dispatch_inst_id);
                    // Check that all requested bytes are known
                    bool all_known = true;
                    for (uint8_t b = 0; b < ofmt.opcode_size; ++b) {
                        if (!mem.known[b]) { all_known = false; break; }
                    }
                    if (all_known) {
                        uint64_t raw = 0;
                        std::memcpy(&raw, mem.data.data(),
                                    std::min(static_cast<size_t>(ofmt.opcode_size),
                                             sizeof(raw)));
                        // Step 1: mask + shift
                        uint64_t val = (raw & ofmt.opcode_mask) >> ofmt.opcode_shift;

                        // Step 2: apply ordered deobfuscation transforms
                        for (size_t si = 0; si < ofmt.deobfuscation_steps.size(); ++si) {
                            const auto& step_def = ofmt.deobfuscation_steps[si];
                            using Op = OpcodeDeobfStep::Op;
                            switch (step_def.op) {
                                case Op::sub:   val -= step_def.imm; break;
                                case Op::add:   val += step_def.imm; break;
                                case Op::xor_:  val ^= step_def.imm; break;
                                case Op::and_:  val &= step_def.imm; break;
                                case Op::or_:   val |= step_def.imm; break;
                                case Op::lsr:   val >>= step_def.imm; break;
                                case Op::lsl:   val <<= step_def.imm; break;
                                case Op::mul:   val *= step_def.imm; break;
                                case Op::ror: {
                                    uint8_t r = static_cast<uint8_t>(step_def.imm & 63u);
                                    if (r > 0) val = (val >> r) | (val << (64u - r));
                                    break;
                                }
                                case Op::bswap: {
                                    uint8_t w = step_def.imm ? static_cast<uint8_t>(step_def.imm) : 8u;
                                    if (w >= 8) {
                                        val = __builtin_bswap64(val);
                                    } else if (w == 4) {
                                        val = __builtin_bswap32(static_cast<uint32_t>(val));
                                    } else if (w == 2) {
                                        val = __builtin_bswap16(static_cast<uint16_t>(val));
                                    }
                                    break;
                                }
                                case Op::neg:   val = static_cast<uint64_t>(-static_cast<int64_t>(val)); break;
                                case Op::not_:  val = ~val; break;
                                // ── Rolling-key stateful ops ────────────────
                                case Op::xor_rolling: val ^= rolling_keys[si]; break;
                                case Op::add_rolling: val += rolling_keys[si]; break;
                                case Op::sub_rolling: val -= rolling_keys[si]; break;
                            }
                        }

                        step.opcode_value = val;
                        step.opcode_valid = true;

                        // Step 3: update rolling keys for the NEXT step
                        for (size_t si = 0; si < ofmt.deobfuscation_steps.size(); ++si) {
                            using Op = OpcodeDeobfStep::Op;
                            auto op = ofmt.deobfuscation_steps[si].op;
                            if (op != Op::xor_rolling && op != Op::add_rolling && op != Op::sub_rolling)
                                continue;
                            switch (ofmt.rolling_key_update) {
                                case RollingKeyUpdate::XorOpcode:
                                    rolling_keys[si] ^= val; break;
                                case RollingKeyUpdate::AddOpcode:
                                    rolling_keys[si] += val; break;
                                case RollingKeyUpdate::SubOpcode:
                                    rolling_keys[si] -= val; break;
                                case RollingKeyUpdate::HashOpcode:
                                    rolling_keys[si] = rolling_keys[si] * 31 + val; break;
                            }
                        }
                    }
                }

                // ── Record opcode→handler mapping (both modes) ─────────────
                if (step.opcode_valid) {
                    auto hit = result.handler_by_pc.find(step.handler_entry_pc);
                    if (hit != result.handler_by_pc.end()) {
                        auto& h = result.handlers[hit->second];
                        bool dup = false;
                        for (uint64_t ov : h.opcode_values) {
                            if (ov == step.opcode_value) { dup = true; break; }
                        }
                        if (!dup) h.opcode_values.push_back(step.opcode_value);
                    }
                }
            }
        }

        // ── VM context / register file snapshot ─────────────────────────
        //
        // state_dispatch (state_before dispatch_inst_id) is needed below
        // even when VM-PC is not configured.  Compute it lazily here if not
        // already computed by the VM-PC block above.
        // We use a lambda-initialized const ref to avoid the double-call cost.
        //
        // For the ctx_base and rf_base pointers: these are almost always
        // invariant registers (they point to a heap-allocated VM state struct
        // that never moves).  Reading them at dispatch_inst_id or
        // handler_first_inst_id yields the same value.  We use
        // dispatch_inst_id for consistency.
        //
        // For the MEMORY values at those pointers (vm_ctx fields, VM
        // registers, SP): we query at dispatch_inst_id.  The MemoryModel
        // returns "the last write that happened BEFORE dispatch_inst_id",
        // which is exactly the state left by the PREVIOUS handler — i.e., the
        // VM register file contents that the current step's handler will see
        // as its inputs.  This is the correct semantic for a VM-register panel.
        // state_dispatch was already obtained from the cursor above.
        // Use it directly for ctx/register/operand reads — no redundant
        // state_before() call needed.
        bool need_ctx_state = (config_.vm_context.has_value() &&
                               config_.vm_context->ctx_base_reg != 0xFF) ||
                              config_.vm_register_file.has_value() ||
                              config_.operand_format.has_value();
        const RegState* p_state_dispatch = &state_dispatch;
        (void)need_ctx_state;  // state_dispatch is always available from cursor

        // Decode VM context structure fields if hint provided
        if (config_.vm_context.has_value() && config_.vm_context->ctx_base_reg != 0xFF) {
            auto& vctx = *config_.vm_context;
            // ctx_base_reg is invariant; read it from state_before dispatch.
            uint64_t ctx_base = p_state_dispatch->gpr[vctx.ctx_base_reg];
            auto& memory = ctx.memory();

            for (const auto& field : vctx.fields) {
                // Clamp field size to [1, 8]; 0 defaults to 8.
                uint8_t fsz = (field.size > 0 && field.size <= 8) ? field.size : uint8_t(8);
                uint64_t field_addr = ctx_base + field.offset;
                auto mem = memory.read(field_addr, fsz, exec.dispatch_inst_id);
                bool known = true;
                for (uint8_t b = 0; b < fsz; ++b) {
                    if (!mem.known[b]) { known = false; break; }
                }
                if (known) {
                    uint64_t val = 0;
                    std::memcpy(&val, mem.data.data(), fsz);
                    step.ctx_fields.emplace_back(field.name, val);
                }
            }

            // ── Compute inst_file_offset (vm_pc - bytecode_base) ─────────
            // The base can come from:
            //   (a) config_.inst_file_offset_base (explicitly configured), or
            //   (b) a ctx_field named "bytecode_base" (read above into step.ctx_fields)
            if (step.vm_pc_valid) {
                uint64_t base = 0;
                bool base_found = false;
                if (config_.inst_file_offset_base_set) {
                    base = config_.inst_file_offset_base;
                    base_found = true;
                } else {
                    for (const auto& [name, val] : step.ctx_fields) {
                        if (name == "bytecode_base") {
                            base = val;
                            base_found = true;
                            break;
                        }
                    }
                }
                if (base_found && step.vm_pc_value >= base) {
                    step.inst_file_offset = step.vm_pc_value - base;
                    step.inst_file_offset_valid = true;
                }
            }
        }

        // ── VM Register File snapshot ────────────────────────────────────
        // Read named VM registers and/or VM stack from the RF base pointer.
        // Memory time-point: dispatch_inst_id (= values left by the previous
        // handler, which are the inputs to the current step).
        //
        // Register file and stack are no longer mutually exclusive: a VM may
        // have both (e.g. JVM-style mixed architecture).  When both are
        // configured, both are emitted into step.vm_regs.
        if (config_.vm_register_file.has_value()) {
            auto& rf = *config_.vm_register_file;
            auto& memory = ctx.memory();

            // Determine RF base address from an invariant host register.
            // rf_base_reg is expected to be invariant (never changed by
            // handler code); reading it from state_dispatch is correct.
            uint64_t rf_base = 0;
            bool rf_base_valid = false;
            if (rf.rf_base_reg != 0xFF) {
                rf_base = p_state_dispatch->gpr[rf.rf_base_reg];
                rf_base_valid = true;
            } else if (config_.vm_context.has_value() &&
                       config_.vm_context->ctx_base_reg != 0xFF) {
                rf_base = p_state_dispatch->gpr[config_.vm_context->ctx_base_reg];
                rf_base_valid = true;
            }

            // ── Register machine: read named VM registers ──────────────
            // Two storage modes per register:
            //   (a) Memory-backed (default): rf_base + offset → MemoryModel.
            //   (b) Host-register-backed:    from_host_reg → RegisterFile.
            // Supports up to 16 bytes (SIMD/XMM).  Values > 8 bytes are
            // stored as two adjacent uint64 entries: "V0_lo" / "V0_hi".
            for (const auto& vreg : rf.regs) {
                // ── Mode (b): host-register-backed ──
                if (vreg.from_host_reg != 0xFF && vreg.from_host_reg <= 28) {
                    step.vm_regs.emplace_back(
                        vreg.name, p_state_dispatch->gpr[vreg.from_host_reg]);
                    continue;
                }

                // ── Mode (a): memory-backed ──
                if (!rf_base_valid) continue;

                uint8_t sz = (vreg.size > 0 && vreg.size <= 16)
                                 ? vreg.size : uint8_t(8);
                uint64_t addr = rf_base + vreg.offset;

                if (sz <= 8) {
                    auto mem = memory.read(addr, sz, exec.dispatch_inst_id);
                    bool known = true;
                    for (uint8_t b = 0; b < sz; ++b) {
                        if (!mem.known[b]) { known = false; break; }
                    }
                    if (known) {
                        uint64_t val = 0;
                        std::memcpy(&val, mem.data.data(), sz);
                        step.vm_regs.emplace_back(vreg.name, val);
                    }
                } else {
                    auto mem_lo = memory.read(addr,     8, exec.dispatch_inst_id);
                    auto mem_hi = memory.read(addr + 8, 8, exec.dispatch_inst_id);
                    bool lo_ok = true, hi_ok = true;
                    for (uint8_t b = 0; b < 8; ++b) {
                        if (!mem_lo.known[b]) lo_ok = false;
                        if (!mem_hi.known[b]) hi_ok = false;
                    }
                    if (lo_ok) {
                        uint64_t lo = 0;
                        std::memcpy(&lo, mem_lo.data.data(), 8);
                        step.vm_regs.emplace_back(vreg.name + "_lo", lo);
                    }
                    if (hi_ok) {
                        uint64_t hi = 0;
                        std::memcpy(&hi, mem_hi.data.data(), 8);
                        step.vm_regs.emplace_back(vreg.name + "_hi", hi);
                    }
                }
            }

            if (rf_base_valid) {

                // ── Stack machine: read SP pointer, then stack slots ───────
                // SP lives inside the ctx/RF region at stack_sp_offset.
                // The SP value itself is a pointer into a separate stack buffer.
                //
                // Stack growth direction is configurable via rf.stack_direction:
                //
                //   Descending (default, full-descending):
                //     SP points to the last pushed item.
                //     TOS = *SP, next = *(SP + elem), ...
                //     Slot i: SP + i * elem
                //
                //   Ascending (full-ascending / empty-ascending):
                //     SP points to the next free slot.
                //     TOS = *(SP - elem), next = *(SP - 2*elem), ...
                //     Slot i: SP - (i + 1) * elem
                //
                if (rf.has_stack()) {
                    auto sp_mem = memory.read(rf_base + rf.stack_sp_offset, 8,
                                              exec.dispatch_inst_id);
                    bool sp_ok = true;
                    for (uint8_t b = 0; b < 8; ++b) {
                        if (!sp_mem.known[b]) { sp_ok = false; break; }
                    }
                    if (sp_ok) {
                        uint64_t sp = 0;
                        std::memcpy(&sp, sp_mem.data.data(), 8);
                        // Record the SP value itself for display
                        step.vm_regs.emplace_back("SP", sp);

                        uint8_t  elem  = rf.stack_elem_size > 0 ? rf.stack_elem_size : uint8_t(8);
                        uint32_t depth = rf.stack_depth     > 0 ? rf.stack_depth     : 8u;

                        using Dir = VMRegisterFileHint::StackDirection;
                        bool ascending = (rf.stack_direction == Dir::Ascending);

                        for (uint32_t si = 0; si < depth; ++si) {
                            uint64_t slot_addr;
                            if (ascending) {
                                // Ascending stack: TOS is below SP.
                                // slot 0 = *(SP - elem), slot 1 = *(SP - 2*elem), ...
                                slot_addr = sp - static_cast<uint64_t>(si + 1) * elem;
                            } else {
                                // Descending stack: TOS is at SP.
                                // slot 0 = *SP, slot 1 = *(SP + elem), ...
                                slot_addr = sp + static_cast<uint64_t>(si) * elem;
                            }
                            auto sm = memory.read(slot_addr, elem, exec.dispatch_inst_id);
                            bool sok = true;
                            for (uint8_t b = 0; b < elem; ++b) {
                                if (!sm.known[b]) { sok = false; break; }
                            }
                            if (sok) {
                                uint64_t sv = 0;
                                std::memcpy(&sv, sm.data.data(), elem);
                                step.vm_regs.emplace_back(fmt::format("S{}", si), sv);
                            }
                        }
                    }
                }
            }
        }

        // ── Operand field decoding ────────────────────────────────────
        //
        // When an OperandFormatHint is provided and we have a valid VM-PC,
        // decode each operand field from the bytecode buffer at
        // (vm_pc_value + field.byte_offset), applying the same
        // mask + shift + deobfuscation pipeline as opcode decode.
        if (config_.operand_format.has_value() && step.vm_pc_valid) {
            auto& opfmt = *config_.operand_format;
            auto& memory = ctx.memory();

            for (const auto& field : opfmt.fields) {
                if (field.size == 0 || field.size > 8) continue;

                uint64_t field_addr = step.vm_pc_value +
                                      static_cast<uint64_t>(field.byte_offset);
                auto mem = memory.read(field_addr,
                                       static_cast<uint8_t>(field.size),
                                       exec.dispatch_inst_id);
                bool all_known = true;
                for (uint8_t b = 0; b < field.size; ++b) {
                    if (!mem.known[b]) { all_known = false; break; }
                }
                if (!all_known) continue;

                uint64_t raw = 0;
                std::memcpy(&raw, mem.data.data(),
                            std::min(static_cast<size_t>(field.size), sizeof(raw)));

                uint64_t val = (raw & field.mask) >> field.shift;

                // Apply per-field deobfuscation pipeline
                for (const auto& ds : field.deobfuscation_steps) {
                    using Op = OpcodeDeobfStep::Op;
                    switch (ds.op) {
                        case Op::sub:   val -= ds.imm; break;
                        case Op::add:   val += ds.imm; break;
                        case Op::xor_:  val ^= ds.imm; break;
                        case Op::and_:  val &= ds.imm; break;
                        case Op::or_:   val |= ds.imm; break;
                        case Op::lsr:   val >>= ds.imm; break;
                        case Op::lsl:   val <<= ds.imm; break;
                        case Op::mul:   val *= ds.imm; break;
                        case Op::ror: {
                            uint8_t r = static_cast<uint8_t>(ds.imm & 63u);
                            if (r > 0) val = (val >> r) | (val << (64u - r));
                            break;
                        }
                        case Op::bswap: {
                            uint8_t w = ds.imm ? static_cast<uint8_t>(ds.imm) : 8u;
                            if (w >= 8)      val = __builtin_bswap64(val);
                            else if (w == 4) val = __builtin_bswap32(static_cast<uint32_t>(val));
                            else if (w == 2) val = __builtin_bswap16(static_cast<uint16_t>(val));
                            break;
                        }
                        case Op::neg:   val = static_cast<uint64_t>(-static_cast<int64_t>(val)); break;
                        case Op::not_:  val = ~val; break;
                        // Rolling ops are not supported for operand fields
                        // (they only make sense for opcode decode chains).
                        case Op::xor_rolling: break;
                        case Op::add_rolling: break;
                        case Op::sub_rolling: break;
                    }
                }

                VMOperand operand;
                operand.name = field.name;
                operand.value = val;
                operand.size_bytes = field.size;
                step.operands.push_back(std::move(operand));
            }
        }

        result.steps.push_back(std::move(step));
    }

    // ── Step 8: Statistics ──────────────────────────────────────────────

    result.total_vm_steps = result.steps.size();
    result.total_native_instructions = 0;
    for (const auto& step : result.steps) {
        if (step.inst_id_end > step.inst_id_start) {
            result.total_native_instructions += (step.inst_id_end - step.inst_id_start + 1);
        }
    }

    // ── Step 9: Carry hints into result for VM Workspace UI ────────────
    result.vm_register_file = config_.vm_register_file;
    result.handler_asm      = config_.handler_asm;

    std::string final_msg = fmt::format(
        "VM abstract: anchor at {:#x} ({}), {} VM steps, VM-PC={}",
        result.dispatcher.loop_header_pc,
        dispatch_type_name(result.dispatcher.dispatch_type),
        result.total_vm_steps,
        result.vm_pc_tracked ? "tracked" : "unknown");
    ctx.progress(1.0f, final_msg);
    // Always visible at the default log level (not gated behind
    // TENET_LOG=DEBUG like the generic progress-message log path) — this is
    // the single most useful line for confirming a hints file actually
    // "took": dispatcher != 0x0 and steps > 0.
    LOG_INFO_M(::tenet::log::Module::Analysis, "{}", final_msg);
    if (result.total_vm_steps == 0) {
        LOG_WARN_M(::tenet::log::Module::Analysis,
            "VM abstract: anchor was resolved but produced 0 VM steps — "
            "this usually means the anchor PC was never hit in the analysis "
            "range, or the hint has a stale/wrong address. Check "
            "loop_header_pc / anchor_pcs / mem_anchor_addr in the hints.");
    }

    return PassResult::success(std::move(result));
}

}  // namespace tenet

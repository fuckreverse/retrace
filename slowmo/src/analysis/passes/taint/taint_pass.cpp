#include "common/compiler_compat.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/taint_common.h"
#include "analysis/control_dependencies.h"
#include "analysis/passes/structure/xref_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/triton_bridge.h"
// register_file.h and memory_model.h no longer needed in run_triton_taint
// (concrete context injection removed; taint engine is self-contained)

#include <ankerl/unordered_dense.h>
#include <fmt/core.h>
#include <cstring>
#include <algorithm>

namespace tenet {

// ─── Helper: emit a PropagationStep and legacy TaintEvent ──────────────────

static void emit_step(TaintResult& result, const TaintConfig& config,
                      PropagationStep step) {
    uint64_t inst_id = step.inst_id;
    if (!result.compact_navigation && result.steps.size() + result.events.size() >= 65536) {
        result.compact_navigation = true;
        result.inst_id_to_event.clear(); result.inst_id_to_steps.clear();
    }

    // Always record in tainted_inst_ids
    result.tainted_inst_ids.add(inst_id);

    // Emit legacy TaintEvent for backward compat
    if (step.type != PropagationType::Kill) {
        TaintEvent legacy;
        legacy.inst_id = step.inst_id;
        legacy.pc = step.pc;
        legacy.dst_reg = step.dst_reg;
        legacy.src_reg_mask = step.src_reg_mask;
        legacy.src_simd_mask = step.src_simd_mask;
        legacy.is_memory_source = (step.type == PropagationType::MemToReg ||
                                   step.type == PropagationType::MemToMem);
        legacy.is_memory_sink = (step.type == PropagationType::RegToMem ||
                                 step.type == PropagationType::MemToMem);
        if (!result.compact_navigation) result.inst_id_to_event[inst_id] = result.events.size();
        result.events.push_back(std::move(legacy));
    }

    // Emit detailed PropagationStep
    if (config.emit_propagation_steps) {
        if (!result.compact_navigation) result.inst_id_to_steps[inst_id].push_back(result.steps.size());
        result.steps.push_back(std::move(step));
    }
}

// ─── Helper: check stop conditions ─────────────────────────────────────────

/// Returns non-empty string if a stop condition is met.
static std::string check_stop_conditions(const TaintResult& result,
                                         const ankerl::unordered_dense::set<uint64_t>& stop_pc_set,
                                         uint64_t pc,
                                         uint64_t processed,
                                         uint64_t max_instructions,
                                         uint32_t max_taint_width) {
    // max_instructions
    if (max_instructions > 0 && processed >= max_instructions) {
        return "max_instructions reached";
    }

    // max_taint_width
    if (max_taint_width > 0 &&
        result.tainted_reg_count() > max_taint_width) {
        return fmt::format("max_taint_width exceeded ({} > {})",
                           result.tainted_reg_count(), max_taint_width);
    }

    // stop_pcs
    if (!stop_pc_set.empty() && stop_pc_set.contains(pc)) {
        return fmt::format("stop_pc hit: 0x{:X}", pc);
    }

    return {};
}

// ─── ABI-aware call-boundary event (shared by both engines) ────────────────
//
// Detecting a BL/BLR call site (LR written) and — if any ABI argument
// register carries taint at that point — emitting a Call PropagationStep is
// identical logic regardless of how taint state is tracked, so it is
// factored out once here instead of appearing twice.

static void maybe_emit_call_event(TaintResult& result, const TaintConfig& config,
                                   uint64_t inst_id, uint64_t pc,
                                   uint64_t tainted_regs_after_write,
                                   bool triton_resolved) {
    uint64_t arg_taint = tainted_regs_after_write & 0xFFULL;  // X0-X7 = bits 0-7
    if (!arg_taint) return;

    PropagationStep step;
    step.inst_id = inst_id;
    step.pc = pc;
    step.type = PropagationType::Call;
    step.triton_resolved = triton_resolved;
    step.cross_function_pc = pc;  // resolved by the next inst (callee entry)
    step.src_reg_mask = arg_taint;
    emit_step(result, config, std::move(step));
    result.call_crossings++;
}

// ═══════════════════════════════════════════════════════════════════════════
// Common forward-scan framework (templated for inlining the per-inst step)
// ═══════════════════════════════════════════════════════════════════════════
//
// Both the Triton and heuristic engines walk the trace forward from
// config.source_inst_id, checking stop conditions / XRef-driven skip
// opportunities / cancellation identically. The only thing that differs is
// *how* a single instruction updates the taint state (StepFn) — Triton asks
// its own taint engine, the heuristic infers from reg_diff. Factoring the
// scan loop out here keeps that shared bookkeeping in one place instead of
// duplicated across run_triton_taint/run_heuristic_taint.
//
// StepFn signature:
//   void step_fn(const InstView& inst, uint64_t inst_id, TaintResult& result)
// It is responsible for mutating `result` (tainted_regs/tainted_memory) and
// emitting whatever PropagationStep events are appropriate for this one
// instruction (RegToReg/MemToReg/RegToMem/Kill/Call). The shared loop takes
// care of stop conditions, iteration, and progress reporting.

template <typename StepFn>
static PassResult run_taint_scan_common(PassContext& ctx, const TaintConfig& config,
                                         StepFn&& step_fn, const char* method_label) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = config.source_inst_id > 0 ? config.source_inst_id : range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (start > end) return PassResult::failed("Taint source is outside analysis range");

    // Pre-build stop_pc set for O(1) lookup in the hot loop
    ankerl::unordered_dense::set<uint64_t> stop_pc_set(config.stop_pcs.begin(),
                                                        config.stop_pcs.end());

    TaintResult result;
    result.config = config;
    result.events.set_resident_budget(ctx.memory_budget_bytes() / 4);
    result.steps.set_resident_budget(ctx.memory_budget_bytes() / 4);
    result.quality.engine = method_label;
    result.tainted_regs = config.source_regs;
    result.tainted_simd = config.include_simd ? config.source_simd_regs : 0;
    result.thread_taint[index.thread_at(start)] = {result.tainted_regs, result.tainted_simd};

    std::unique_ptr<ControlDependencies> control;
    roaring::Roaring64Map tainted_branches;
    if (config.include_control) {
        control = std::make_unique<ControlDependencies>(ctx);
        result.quality.unresolved_control_joins = control->unresolved_joins;
    }
    // Initialize tainted memory from config
    for (uint64_t addr : config.source_mem_addrs) {
        result.tainted_memory.add(addr);
    }

    uint64_t processed = 0;
    uint64_t total = end - start;

    // Seek directly to start position using index (avoid scanning prefix)
    uint64_t start_offset = 0, seed_pc = 0;
    uint64_t scan_inst_id = 0;
    if (start > 0) {
        auto [off, pc] = index.offset_of_with_pc(start, reader);
        start_offset = off; seed_pc = pc;
        scan_inst_id = start;
    }

    auto it_begin = (start > 0) ? TraceReader::Iterator(&reader, start_offset, seed_pc) : reader.begin();
    uint64_t inst_id = scan_inst_id;

    // Hint to the OS that we'll be reading sequentially (improves mmap readahead)
    reader.advise_sequential();

    for (auto it = it_begin; it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        const auto tid = index.thread_at(inst_id);
        auto& thread = result.thread_taint[tid];
        result.tainted_regs = thread.gpr; result.tainted_simd = thread.simd;

        // ─── Stop condition check ─────────────────────────────────────
        auto stop = check_stop_conditions(result, stop_pc_set, inst.pc, processed,
                                           config.max_instructions, config.max_taint_width);
        if (!stop.empty()) {
            result.stop_reason = std::move(stop);
            result.quality.truncated = true;
            result.quality.termination_reason = result.stop_reason;
            break;
        }

        if (ctx.cancelled() || ((processed & 4095) == 0 && ctx.memory_pressure())) {
            result.stop_reason = ctx.cancelled() ? "cancelled by user" : "RSS limit exceeded";
            result.quality.truncated = true;
            result.quality.termination_reason = result.stop_reason;
            break;
        }

        result.active_control_inst = UINT64_MAX;
        if (control && inst_id < control->parents.size()) {
            const auto parent = control->parents[inst_id];
            if (parent != UINT64_MAX && tainted_branches.contains(parent)) result.active_control_inst = parent;
            if (control->branch(inst.pc)) {
                const auto d = ctx.decoder().decode(inst.pc, ctx.code_table());
                uint64_t sources = 0;
                if (d) for (uint8_t i = 0; i < d->regs_read_count; ++i)
                    if (result.is_tainted(d->regs_read[i])) sources |= 1ULL << d->regs_read[i];
                if (sources || result.active_control_inst != UINT64_MAX) {
                    tainted_branches.add(inst_id);
                    PropagationStep step; step.inst_id = inst_id; step.pc = inst.pc;
                    step.type = PropagationType::Control; step.src_reg_mask = sources;
                    step.control_inst_id = result.active_control_inst;
                    emit_step(result, config, std::move(step));
                }
            }
        }
        // ─── Per-instruction taint update (engine-specific) ────────────
        ++result.quality.instructions_examined;
        bool skipped = step_fn(inst, inst_id, result);
        thread.gpr = result.tainted_regs; thread.simd = result.tainted_simd;
        if (skipped) {
            result.instructions_skipped_xref++;
        }

        inst_id++;
        processed++;
        result.instructions_processed = processed;

        if (processed % 10000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }
    }

    ctx.progress(1.0f, fmt::format("Taint ({}): {} events, {} steps, {} kills, "
                                     "{} skipped, {} regs, {} mem",
                                     method_label,
                                     result.events.size(),
                                     result.steps.size(),
                                     result.kill_events_count,
                                     result.instructions_skipped_xref,
                                     result.tainted_reg_count(),
                                     result.tainted_memory.cardinality()));
    return PassResult::success(std::move(result));
}

// ═══════════════════════════════════════════════════════════════════════════
// Triton-based precise taint step
// ═══════════════════════════════════════════════════════════════════════════

static PassResult run_triton_taint(PassContext& ctx, const TaintConfig& config) {
    auto& code_table = ctx.code_table();

    // Create a fresh Triton bridge for this analysis
    auto bridge_ptr = create_triton_bridge();
    if (!bridge_ptr->is_available()) {
        return PassResult::failed("Triton bridge not available");
    }

    auto* triton = dynamic_cast<TritonBridgeTaint*>(bridge_ptr.get());
    if (!triton) {
        return PassResult::failed("Triton bridge does not support taint interface");
    }

    // ── Performance: ONLY_ON_TAINTED mode means Triton's taint engine propagates
    // taint purely based on instruction semantics (data-flow graph), NOT on
    // concrete register/memory values. Therefore we do NOT call
    // set_register_context or set_memory_context per instruction — those calls
    // cost 34+ Triton API calls each and are pure overhead in taint-only mode.
    //
    // We still need concrete values only at initialization to seed taint sources;
    // after that the taint engine is self-contained.

    // Set initial taint sources (iterate bitmask)
    for (uint64_t mask = config.source_regs; mask; mask &= mask - 1) {
        uint8_t reg_idx = static_cast<uint8_t>(tenet::platform::trailing_zeros(mask));
        triton->taint_register(reg_idx);
    }

    // Taint initial memory sources
    for (uint64_t addr : config.source_mem_addrs) {
        triton->taint_memory(addr, 8);  // Assume 8-byte granularity
    }

    // step_fn captures triton/code_table/config by reference; the shared
    // scan loop calls it once per instruction.
    auto step_fn = [&](const InstView& inst, uint64_t inst_id, TaintResult& result) -> bool {
        // Get opcode bytes from code table
        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (!opcode_opt) {
            ++result.quality.missing_code;
            return false;
        }

        uint32_t opcode_val = *opcode_opt;
        auto* opcode_bytes = reinterpret_cast<const uint8_t*>(&opcode_val);

        // ── Lazy Triton Symbolization (P0 optimization) ───────────────
        // Before calling the expensive process_instruction(), do a cheap
        // O(1) pre-filter using the current tainted set:
        //
        //   • If NO registers are currently tainted AND no memory is
        //     tainted, this instruction cannot possibly propagate taint.
        //     Skip the Triton call entirely.
        //
        //   • If tainted state is non-empty, we still need Triton because
        //     even a "NOP-like" instruction might kill taint on a written reg.
        //
        // Reference: Sydr paper (Positive Technologies, 2020) reports
        // 1.2-3.5x speedup from this single optimization.
        uint64_t before_mask = triton->get_tainted_gpr_mask();

        // Fast path: nothing is tainted at all → no need to run Triton.
        if (before_mask == 0 && result.tainted_memory.isEmpty()) {
            // However, if this instruction writes a register we're tracking
            // as a *source* (i.e., we just set up initial taint sources but
            // haven't processed the source instruction yet), we can't skip.
            // Guard: only skip when we're past the source instruction.
            if (inst_id >= config.source_inst_id) {
                return true;  // skipped
            }
        }

        // Process instruction through Triton's taint engine
        bool ok = triton->process_instruction(inst.pc, opcode_bytes, 4);
        if (!ok) {
            ++result.quality.undecoded_instructions;
            return false;
        }

        uint64_t after_mask = triton->get_tainted_gpr_mask();

        // ─── Detect newly tainted registers (bitwise diff: O(1)) ──────
        uint64_t new_taint = after_mask & ~before_mask;
        while (new_taint) {
            uint8_t reg = static_cast<uint8_t>(tenet::platform::trailing_zeros(new_taint));
            new_taint &= new_taint - 1;  // clear lowest set bit

            PropagationStep step;
            step.inst_id = inst_id;
            step.pc = inst.pc;
            step.dst_reg = reg;
            step.triton_resolved = true;

            // Check if source is memory
            bool from_mem = false;
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if ((mem.type & 2) == 0 && triton->is_memory_tainted(mem.addr, mem.size)) {
                    from_mem = true;
                    step.add_src_mem(mem.addr);
                }
            }

            step.type = from_mem ? PropagationType::MemToReg : PropagationType::RegToReg;
            // Source regs: bitmask of all previously tainted regs — O(1)
            step.src_reg_mask = before_mask;

            emit_step(result, config, std::move(step));
        }

        // ─── Detect killed (untainted) registers (bitwise diff: O(1)) ──
        if (config.emit_kill_events) {
            uint64_t killed = before_mask & ~after_mask;
            while (killed) {
                uint8_t prev = static_cast<uint8_t>(tenet::platform::trailing_zeros(killed));
                killed &= killed - 1;

                PropagationStep step;
                step.inst_id = inst_id;
                step.pc = inst.pc;
                step.type = PropagationType::Kill;
                step.dst_reg = prev;
                step.triton_resolved = true;
                emit_step(result, config, std::move(step));
                result.kill_events_count++;
            }
        }

        // ─── Memory taint sinks (RegToMem) ────────────────────────────
        if (config.track_memory_sinks) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (mem.type & 2) {  // write
                    bool any_byte_tainted = false;
                    for (uint64_t off = 0; off < mem.size && off <= UINT64_MAX - mem.addr; ++off) {
                        const auto addr = mem.addr + off;
                        if (triton->is_memory_tainted(addr, 1)) {
                            result.tainted_memory.add(addr);
                            any_byte_tainted = true;
                        } else {
                            result.tainted_memory.remove(addr);
                        }
                    }
                    if (any_byte_tainted) {

                        PropagationStep step;
                        step.inst_id = inst_id;
                        step.pc = inst.pc;
                        step.type = PropagationType::RegToMem;
                        step.control_inst_id = result.active_control_inst;
                        step.dst_mem_addr = mem.addr;
                        step.dst_mem_size = static_cast<uint8_t>(mem.size);
                        step.triton_resolved = true;
                        step.src_reg_mask = before_mask;
                        emit_step(result, config, std::move(step));
                    }
                }
            }
        }

        // ─── ABI-aware call crossing ──────────────────────────────────
        // Detect BL/BLR: if LR is written (saved return address), it's a call.
        // Taint propagates to callee only through X0-X7 argument registers.
        if (config.propagate_through_calls) {
            bool is_call = false;
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                if (inst.reg_diff(i).index == kTaintRegLR) {
                    is_call = true;
                    break;
                }
            }
            if (is_call) {
                // At a call boundary: only argument registers (X0-X7) carry taint
                // into the callee. We just emit a Call event for tracking — the
                // callee's own reg_diffs (walked next in the trace) naturally
                // handle whatever clobbering/propagation happens inside it.
                maybe_emit_call_event(result, config, inst_id, inst.pc, after_mask, true);
            }
        }

        // Update tainted_regs bitmask directly from Triton state (O(1))
        result.tainted_regs = after_mask;
        return false;  // not skipped
    };

    return run_taint_scan_common(ctx, config, step_fn, "Triton");
}

// ═══════════════════════════════════════════════════════════════════════════
// Heuristic taint step (kill semantics + XRef acceleration)
// ═══════════════════════════════════════════════════════════════════════════

static PassResult run_heuristic_taint(PassContext& ctx, const TaintConfig& config) {
    // ─── Try to get XRef result for acceleration ──────────────────────
    const XrefResult* xref = nullptr;
    if (config.use_xref_acceleration) {
        try {
            const auto& xref_raw = ctx.require_raw("xref");
            if (xref_raw.ok()) {
                xref = &xref_raw.get<XrefResult>();
            }
        } catch (...) {
            // XRef not available, proceed without acceleration
        }
    }

    // Track which PCs modify which registers (learned during scan, bitmask).
    // Captured by the step lambda across calls (state must persist).
    auto pc_to_written_regs =
        std::make_shared<ankerl::unordered_dense::map<uint64_t, uint64_t>>();
    bool use_learned_map = (xref != nullptr);

    auto step_fn = [pc_to_written_regs, use_learned_map, &config, &ctx](
                       const InstView& inst, uint64_t inst_id, TaintResult& result) -> bool {
        const auto info = classify_inst_heuristic(inst, ctx.decoder(), ctx.code_table());
        result.quality.missing_code += info.missing_code;
        result.quality.undecoded_instructions += info.undecoded;
        result.quality.unsupported_register_instructions += info.unsupported_registers ||
            (!config.include_simd && (info.simd_reads || info.simd_writes));
        const uint64_t taint_before = result.tainted_regs;
        uint64_t read_mask = 0;
        for (uint8_t i = 0; i < info.n_read; i++) {
            if (info.read_regs[i] != IDX_NZCV || config.include_flags)
                read_mask |= 1ULL << info.read_regs[i];
        }

        // ─── XRef acceleration: skip if instruction cannot affect taint ─
        // Quick check: a pure control-flow instruction (B, NOP) with no
        // reg_diffs and no mem_accesses cannot propagate taint → skip.
        if (info.n_written == 0 && info.simd_writes == 0 && inst.mem_access_count == 0) {
            return true;  // skipped
        }

        // ─── Advanced XRef skip using learned PC→reg map ──────────────
        // If we've seen this PC before and it only writes registers that
        // are NOT currently tainted, AND it doesn't read any tainted register,
        // we can skip it. We only skip if the PC doesn't touch any tainted
        // register at all — conservative w.r.t. kill semantics.
        if (result.active_control_inst == UINT64_MAX && use_learned_map && inst.mem_access_count == 0 && info.simd_reads == 0 && info.simd_writes == 0) {
            auto pcwr_it = pc_to_written_regs->find(inst.pc);
            if (pcwr_it != pc_to_written_regs->end()) {
                uint64_t written_mask = pcwr_it->second;
                bool touches_tainted = (written_mask & result.tainted_regs) != 0;
                if (!touches_tainted) {
                    bool src_tainted = (read_mask & taint_before) != 0;
                    bool mem_tainted = false;
                    if (config.taint_from_memory) {
                        for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                            auto mem = inst.mem_access(m);
                            if ((mem.type & 2) == 0 &&  // read
                                mem_range_hits_tainted_set(result.tainted_memory, mem.addr, mem.size)) {
                                mem_tainted = true;
                                break;
                            }
                        }
                    }
                    if (!src_tainted && !mem_tainted) {
                        return true;  // skipped
                    }
                }
            }
        }

        // ─── Learn which registers this PC writes ─────────────────────
        uint64_t& written_mask = (*pc_to_written_regs)[inst.pc];
        for (uint8_t i = 0; i < info.n_written; i++)
            written_mask |= 1ULL << info.written_regs[i];

        // ─── Determine which source registers are tainted ─────────────
        // Read the pre-instruction snapshot so writes to one destination do
        // not become inputs to another destination of the same instruction.
        const uint64_t source_mask = info.has_decoded_operands
            ? (taint_before & read_mask) : taint_before;
        const uint32_t simd_sources = config.include_simd ? (result.tainted_simd & (info.has_decoded_operands ? info.simd_reads : UINT32_MAX)) : 0;
        bool any_src_tainted = source_mask != 0 || simd_sources != 0 || result.active_control_inst != UINT64_MAX;
        // Check memory sources — overlap-aware, so a read that partially
        // overlaps a previously-tainted store is still recognized (this
        // matches BackwardTaintPass's memory-overlap semantics rather than
        // requiring an exact starting-address match).
        bool mem_source_tainted = false;
        uint64_t tainted_mem_sources[8];
        uint8_t n_tainted_mem = 0;
        if (config.taint_from_memory) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if ((mem.type & 2) == 0 &&  // read
                    mem_range_hits_tainted_set(result.tainted_memory, mem.addr, mem.size)) {
                    mem_source_tainted = true;
                    if (n_tainted_mem < 8) {
                        tainted_mem_sources[n_tainted_mem++] = mem.addr;
                    }
                }
            }
        }

        // ─── Process each written register ────────────────────────────
        for (uint8_t i = 0; i < info.n_written; i++) {
            uint8_t reg_idx = info.written_regs[i];

            // Skip SP/PC/NZCV unless explicitly included
            if (reg_idx == IDX_NZCV && !config.include_flags) continue;
            if (reg_idx == IDX_SP) continue;
            if (reg_idx == IDX_PC) continue;

            bool was_tainted = (result.tainted_regs >> reg_idx) & 1;

            // ─── Kill semantics ───────────────────────────────────────
            // If a register is overwritten and NONE of its sources are
            // tainted, it becomes untainted (killed).
            bool has_tainted_input = false;
            const bool writeback = info.has_decoded_operands && reg_idx == info.writeback_reg;
            const uint64_t reg_sources = writeback ? (taint_before & info.writeback_reads) : source_mask;
            const bool memory_input = !writeback && mem_source_tainted;

            if (info.has_decoded_operands) {
                has_tainted_input = reg_sources != 0 || (!writeback && simd_sources != 0) || result.active_control_inst != UINT64_MAX;
            } else {
                // With no opcode, preserve the conservative reg_diff fallback.
                for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                    if (inst.reg_diff(j).index == reg_idx) continue;
                    if ((taint_before >> inst.reg_diff(j).index) & 1) {
                        has_tainted_input = true;
                        break;
                    }
                }
                if (was_tainted) has_tainted_input = true;
            }

            if (!writeback && simd_sources) has_tainted_input = true;
            // Memory source contributes taint
            if (!has_tainted_input && memory_input) {
                has_tainted_input = true;
            }

            if (has_tainted_input) {
                if (!was_tainted) {
                    result.tainted_regs |= (1ULL << reg_idx);

                    PropagationStep step;
                    step.inst_id = inst_id;
                    step.pc = inst.pc;
                    step.control_inst_id = result.active_control_inst;
                    step.dst_reg = reg_idx;
                    step.triton_resolved = false;

                    if (memory_input && reg_sources == 0 && simd_sources == 0) {
                        step.type = PropagationType::MemToReg;
                        for (uint8_t mi = 0; mi < n_tainted_mem; mi++)
                            step.add_src_mem(tainted_mem_sources[mi]);
                    } else {
                        step.type = PropagationType::RegToReg;
                        step.src_reg_mask = reg_sources;
                        step.src_simd_mask = writeback ? 0 : simd_sources;
                        if (memory_input) {
                            for (uint8_t mi = 0; mi < n_tainted_mem; mi++)
                                step.add_src_mem(tainted_mem_sources[mi]);
                        }
                    }

                    emit_step(result, config, std::move(step));
                }
            } else if (was_tainted) {
                // ─── Kill: register overwritten with non-tainted data ──
                result.tainted_regs &= ~(1ULL << reg_idx);

                if (config.emit_kill_events) {
                    PropagationStep step;
                    step.inst_id = inst_id;
                    step.pc = inst.pc;
                    step.type = PropagationType::Kill;
                    step.dst_reg = reg_idx;
                    step.triton_resolved = false;
                    emit_step(result, config, std::move(step));
                    result.kill_events_count++;
                }
            }
        }

        if (config.include_simd) for (uint32_t bits = info.simd_writes; bits; bits &= bits - 1) {
            const uint8_t reg = static_cast<uint8_t>(tenet::platform::trailing_zeros(bits));
            const uint32_t bit = uint32_t(1) << reg;
            const bool was = (result.tainted_simd & bit) != 0;
            const bool now = any_src_tainted || mem_source_tainted;
            if (now) result.tainted_simd |= bit; else result.tainted_simd &= ~bit;
            if ((!was && now) || (was && !now && config.emit_kill_events)) {
                PropagationStep step; step.inst_id = inst_id; step.pc = inst.pc; step.dst_reg = 34 + reg;
                step.control_inst_id = result.active_control_inst;
                step.type = !now ? PropagationType::Kill : (mem_source_tainted ? PropagationType::MemToReg : PropagationType::RegToReg);
                step.src_reg_mask = source_mask; step.src_simd_mask = simd_sources;
                if (mem_source_tainted) for (uint8_t m = 0; m < n_tainted_mem; ++m) step.add_src_mem(tainted_mem_sources[m]);
                if (!now) ++result.kill_events_count;
                emit_step(result, config, std::move(step));
            }
        }

        // ─── Memory sinks (RegToMem) ─────────────────────────────────
        if (config.track_memory_sinks && inst.mem_access_count > 0) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (mem.type & 2) {  // write
                    const bool tainted = any_src_tainted || mem_source_tainted;
                    for (uint64_t off = 0; off < mem.size && off <= UINT64_MAX - mem.addr; ++off) {
                        if (tainted) result.tainted_memory.add(mem.addr + off);
                        else result.tainted_memory.remove(mem.addr + off);
                    }
                    if (tainted) {

                        PropagationStep step;
                        step.inst_id = inst_id;
                        step.pc = inst.pc;
                        step.type = PropagationType::RegToMem;
                        step.dst_mem_addr = mem.addr;
                        step.dst_mem_size = static_cast<uint8_t>(mem.size);
                        step.src_reg_mask = source_mask;
                        step.src_simd_mask = simd_sources;
                        step.triton_resolved = false;
                        emit_step(result, config, std::move(step));
                    }
                }
            }
        }

        // ─── ABI-aware call boundary detection ────────────────────────
        if (config.propagate_through_calls) {
            bool is_call = false;
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                if (inst.reg_diff(i).index == kTaintRegLR) {
                    is_call = true;
                    break;
                }
            }
            if (is_call) {
                maybe_emit_call_event(result, config, inst_id, inst.pc,
                                       result.tainted_regs, false);
            }
            // Return-event detection (PC jumps back to a saved LR) is not
            // implemented in heuristic mode: we rely on the natural trace
            // flow — the caller will see X0 already tainted once the callee
            // returns, since propagation continues linearly through the trace.
        }

        return false;  // not skipped
    };

    return run_taint_scan_common(ctx, config, step_fn, "heuristic");
}

// ─── TaintPass dispatch ─────────────────────────────────────────────────────

PassResult TaintPass::run(PassContext& ctx) {
    // Try Triton-based precise taint first
#ifdef TENET_HAS_TRITON
    {
        auto probe = create_triton_bridge();
        if (probe->is_available() && !config_.include_flags && !config_.include_simd && ctx.index().thread_ids().size() <= 1) {
            return run_triton_taint(ctx, config_);
        }
    }
#endif
    // Fall back to heuristic taint with kill semantics
    return run_heuristic_taint(ctx, config_);
}

}  // namespace tenet

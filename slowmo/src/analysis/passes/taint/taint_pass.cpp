#include "analysis/passes/taint/taint_pass.h"
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

// ─── AArch64 ABI constants ─────────────────────────────────────────────────

static constexpr uint8_t ABI_ARG_FIRST = 0;   // X0
static constexpr uint8_t ABI_ARG_LAST  = 7;   // X7
static constexpr uint8_t ABI_RET_REG   = 0;   // X0 (return value)
static constexpr uint8_t REG_LR        = 30;  // X30 / LR

/// Check if a register is an ABI argument register (X0-X7).
static bool is_abi_arg_reg(uint8_t reg) {
    return reg >= ABI_ARG_FIRST && reg <= ABI_ARG_LAST;
}

// ─── Helper: emit a PropagationStep and legacy TaintEvent ──────────────────

static void emit_step(TaintResult& result, const TaintConfig& config,
                      PropagationStep step) {
    uint64_t inst_id = step.inst_id;

    // Always record in tainted_inst_ids
    result.tainted_inst_ids.add(inst_id);

    // Emit legacy TaintEvent for backward compat
    if (step.type != PropagationType::Kill) {
        TaintEvent legacy;
        legacy.inst_id = step.inst_id;
        legacy.pc = step.pc;
        legacy.dst_reg = step.dst_reg;
        legacy.src_reg_mask = step.src_reg_mask;
        legacy.is_memory_source = (step.type == PropagationType::MemToReg ||
                                   step.type == PropagationType::MemToMem);
        legacy.is_memory_sink = (step.type == PropagationType::RegToMem ||
                                 step.type == PropagationType::MemToMem);
        result.inst_id_to_event[inst_id] = result.events.size();
        result.events.push_back(std::move(legacy));
    }

    // Emit detailed PropagationStep
    if (config.emit_propagation_steps) {
        result.inst_id_to_steps[inst_id].push_back(result.steps.size());
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

// ─── XRef acceleration: find next relevant instruction ─────────────────────

/// Given the current taint state, determine if an instruction at `inst_id`
/// could possibly interact with tainted registers. Uses the XRef pass to
/// skip large blocks of instructions that don't touch any tainted register.
///
/// Returns the next inst_id that might be relevant, or `end` if none.
/// This implements "sparse propagation skip" from the article.
///
/// Strategy: For each tainted register, we know which PCs read/write it
/// (from Triton semantics or heuristic). We use the XRef PC→inst_id bitmap
/// to find the next occurrence of any relevant PC after `current_inst_id`.
///
/// Simplified approach for heuristic mode: since we don't have per-register
/// use-def chains, we skip instructions whose PC has never been seen to
/// produce a reg_diff involving any currently-tainted register. This requires
/// a pre-built "PC → set of registers it touches" map.
///
/// For now, we implement a simpler but still effective optimization:
/// If the current instruction has zero reg_diffs and zero mem_accesses,
/// it cannot propagate taint → skip it without emitting events.
/// The XRef bitmap is used for a more aggressive skip when available.

// ─── Triton-based precise taint propagation ────────────────────────────────

static PassResult run_triton_taint(PassContext& ctx, const TaintConfig& config) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();
    const auto& range = ctx.range();

    uint64_t start = config.source_inst_id > 0 ? config.source_inst_id : range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // Pre-build stop_pc set for O(1) lookup in the hot loop
    ankerl::unordered_dense::set<uint64_t> stop_pc_set(config.stop_pcs.begin(),
                                                        config.stop_pcs.end());

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
        uint8_t reg_idx = static_cast<uint8_t>(__builtin_ctzll(mask));
        triton->taint_register(reg_idx);
    }

    // Taint initial memory sources
    for (uint64_t addr : config.source_mem_addrs) {
        triton->taint_memory(addr, 8);  // Assume 8-byte granularity
    }

    TaintResult result;
    result.config = config;
    result.tainted_regs = config.source_regs;

    // Initialize tainted memory from config
    for (uint64_t addr : config.source_mem_addrs) {
        result.tainted_memory.add(addr);
    }

    uint64_t processed = 0;
    uint64_t total = end - start;

    // Seek directly to start position using index (avoid scanning prefix)
    uint64_t start_offset = 0;
    uint64_t scan_inst_id = 0;
    if (start > 0) {
        auto [off, pc] = index.offset_of_with_pc(start, reader);
        start_offset = off;
        scan_inst_id = start;
    }

    auto it_begin = (start > 0) ? TraceReader::Iterator(&reader, start_offset) : reader.begin();
    uint64_t inst_id = scan_inst_id;

    // Hint to the OS that we'll be reading sequentially (improves mmap readahead)
    reader.advise_sequential();

    for (auto it = it_begin; it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        // ─── Stop condition check ─────────────────────────────────────
        auto stop = check_stop_conditions(result, stop_pc_set, inst.pc, processed,
                                           config.max_instructions, config.max_taint_width);
        if (!stop.empty()) {
            result.stop_reason = std::move(stop);
            break;
        }

        if (ctx.cancelled()) {
            result.stop_reason = "cancelled by user";
            break;
        }

        // Get opcode bytes from code table
        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (!opcode_opt) {
            inst_id++;
            processed++;
            continue;
        }

        uint32_t opcode_val = *opcode_opt;
        auto* opcode_bytes = reinterpret_cast<const uint8_t*>(&opcode_val);

        // ── Concrete context injection removed ────────────────────────
        // In ONLY_ON_TAINTED mode, Triton propagates taint via instruction
        // semantics (getReadRegisters/getWrittenRegisters/getLoadAccess/
        // getStoreAccess), which do NOT require concrete register values to
        // be accurate. Injecting 34 register values + memory bytes per
        // instruction was the single largest CPU cost (eliminated here).

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
        // 1.2-3.5× speedup from this single optimization.
        //
        // We use the zero-allocation bitmask API (get_tainted_gpr_mask)
        // and compute the new/kill sets with O(1) bitwise diff instead of
        // the previous O(T²) nested-vector scan.
        uint64_t before_mask = triton->get_tainted_gpr_mask();

        // Fast path: nothing is tainted at all → no need to run Triton.
        if (before_mask == 0 && result.tainted_memory.isEmpty()) {
            // However, if this instruction writes a register we're tracking
            // as a *source* (i.e., we just set up initial taint sources but
            // haven't processed the source instruction yet), we can't skip.
            // Guard: only skip when we're past the source instruction.
            if (inst_id >= config.source_inst_id) {
                inst_id++;
                processed++;
                result.instructions_processed = processed;
                result.instructions_skipped_xref++;  // reuse counter for lazy skips
                continue;
            }
        }

        // Process instruction through Triton's taint engine
        bool ok = triton->process_instruction(inst.pc, opcode_bytes, 4);
        if (!ok) {
            inst_id++;
            processed++;
            continue;
        }

        uint64_t after_mask = triton->get_tainted_gpr_mask();

        // ─── Detect newly tainted registers (bitwise diff: O(1)) ──────
        uint64_t new_taint = after_mask & ~before_mask;
        while (new_taint) {
            uint8_t reg = static_cast<uint8_t>(__builtin_ctzll(new_taint));
            new_taint &= new_taint - 1;  // clear lowest set bit

            // Determine propagation type
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

            if (from_mem) {
                step.type = PropagationType::MemToReg;
            } else {
                step.type = PropagationType::RegToReg;
            }

            // Source regs: bitmask of all previously tainted regs — O(1)
            step.src_reg_mask = before_mask;

            emit_step(result, config, std::move(step));
        }

        // ─── Detect killed (untainted) registers (bitwise diff: O(1)) ──
        if (config.emit_kill_events) {
            uint64_t killed = before_mask & ~after_mask;
            while (killed) {
                uint8_t prev = static_cast<uint8_t>(__builtin_ctzll(killed));
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
                    if (triton->is_memory_tainted(mem.addr, mem.size)) {
                        result.tainted_memory.add(mem.addr);

                        PropagationStep step;
                        step.inst_id = inst_id;
                        step.pc = inst.pc;
                        step.type = PropagationType::RegToMem;
                        step.dst_mem_addr = mem.addr;
                        step.dst_mem_size = static_cast<uint8_t>(mem.size);
                        step.triton_resolved = true;
                        // Source: bitmask of all previously tainted regs — O(1)
                        step.src_reg_mask = before_mask;
                        emit_step(result, config, std::move(step));
                    }
                }
            }
        }

        // ─── Memory taint sources (MemToReg) already handled above ────

        // ─── ABI-aware call crossing ──────────────────────────────────
        // Detect BL/BLR: if LR is written (saved return address), it's a call.
        // Taint propagates to callee only through X0-X7 argument registers.
        if (config.propagate_through_calls) {
            bool is_call = false;
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                auto diff = inst.reg_diff(i);
                if (diff.index == REG_LR) {
                    is_call = true;
                    break;
                }
            }
            if (is_call) {
                // At a call boundary: only argument registers (X0-X7) carry taint
                // into the callee. Kill taint on non-argument caller-saved regs
                // that the callee might clobber (X9-X15, X16-X17).
                // However, since we're doing forward propagation through the actual
                // trace, the callee's reg_diffs will naturally handle this.
                // We just emit a Call event for tracking.
                uint64_t arg_taint = after_mask & 0xFFULL;  // X0-X7 = bits 0-7
                if (arg_taint) {
                    PropagationStep step;
                    step.inst_id = inst_id;
                    step.pc = inst.pc;
                    step.type = PropagationType::Call;
                    step.triton_resolved = true;
                    // The next PC (callee entry) from the trace
                    step.cross_function_pc = inst.pc;  // Will be resolved by next inst
                    step.src_reg_mask = arg_taint;  // bitmask of argument regs carrying taint
                    emit_step(result, config, std::move(step));
                    result.call_crossings++;
                }

                if (!config.propagate_through_calls) {
                    // Kill all taint at call boundary
                    uint64_t a = arg_taint;
                    while (a) {
                        uint8_t reg = static_cast<uint8_t>(__builtin_ctzll(a));
                        a &= a - 1;
                        triton->untaint_register(reg);
                    }
                }
            }
        }

        // Update tainted_regs bitmask directly from Triton state (O(1))
        result.tainted_regs = after_mask;

        inst_id++;
        processed++;
        result.instructions_processed = processed;

        if (processed % 10000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }
    }

    ctx.progress(1.0f, fmt::format("Taint (Triton): {} events, {} steps, {} kills, "
                                     "{} lazy-skipped, {} regs, {} mem",
                                     result.events.size(),
                                     result.steps.size(),
                                     result.kill_events_count,
                                     result.instructions_skipped_xref,
                                     result.tainted_reg_count(),
                                     result.tainted_memory.cardinality()));
    return PassResult::success(std::move(result));
}

// ─── Heuristic taint with kill semantics + XRef acceleration ───────────────

static PassResult run_heuristic_taint(PassContext& ctx, const TaintConfig& config) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = config.source_inst_id > 0 ? config.source_inst_id : range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // Pre-build stop_pc set for O(1) lookup in the hot loop
    ankerl::unordered_dense::set<uint64_t> stop_pc_set(config.stop_pcs.begin(),
                                                        config.stop_pcs.end());

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

    TaintResult result;
    result.config = config;
    result.tainted_regs = config.source_regs;

    // Initialize tainted memory from config
    for (uint64_t addr : config.source_mem_addrs) {
        result.tainted_memory.add(addr);
    }

    // ─── Build PC → registers-touched bitmask for XRef skip ──────────────
    // We'll build this incrementally: track which PCs we've seen and what
    // registers they modify (as a bitmask). If a PC never touches any
    // tainted register, we can potentially skip future occurrences.

    uint64_t processed = 0;
    uint64_t total = end - start;

    // Track which PCs modify which registers (learned during scan, bitmask)
    ankerl::unordered_dense::map<uint64_t, uint64_t> pc_to_written_regs;

    // Seek directly to start position using index (avoid scanning prefix)
    uint64_t start_offset = 0;
    uint64_t scan_inst_id = 0;
    if (start > 0) {
        auto [off, pc] = index.offset_of_with_pc(start, reader);
        start_offset = off;
        scan_inst_id = start;
    }

    auto it_begin = (start > 0) ? TraceReader::Iterator(&reader, start_offset) : reader.begin();
    uint64_t inst_id = scan_inst_id;

    for (auto it = it_begin; it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        // ─── Stop condition check ─────────────────────────────────────
        auto stop = check_stop_conditions(result, stop_pc_set, inst.pc, processed,
                                           config.max_instructions, config.max_taint_width);
        if (!stop.empty()) {
            result.stop_reason = std::move(stop);
            break;
        }

        if (ctx.cancelled()) {
            result.stop_reason = "cancelled by user";
            break;
        }

        // ─── XRef acceleration: skip if instruction cannot affect taint ─
        // An instruction can only propagate taint if:
        // 1. It reads a tainted register (src), OR
        // 2. It reads from tainted memory
        // If neither is possible, we can skip it.
        //
        // Quick check: if this instruction has no reg_diffs and no mem_accesses,
        // it's a pure control-flow instruction (B, NOP) → skip.
        if (inst.reg_diff_count == 0 && inst.mem_access_count == 0) {
            inst_id++;
            processed++;
            result.instructions_skipped_xref++;
            continue;
        }

        // ─── Advanced XRef skip using learned PC→reg map ──────────────
        // If we've seen this PC before and it only writes registers that
        // are NOT currently tainted, AND it doesn't read any tainted register,
        // we can skip it. But we need to be conservative: the instruction
        // might KILL taint (overwrite a tainted reg with non-tainted data).
        // So we only skip if the PC doesn't touch any tainted register at all.
        if (xref != nullptr) {
          auto pcwr_it = pc_to_written_regs.find(inst.pc);
          if (pcwr_it != pc_to_written_regs.end()) {
            uint64_t written_mask = pcwr_it->second;
            bool touches_tainted = (written_mask & result.tainted_regs) != 0;
            // Also check if any source reg is tainted (reads)
            if (!touches_tainted) {
                // Check reg_diffs: if none of the diff'd registers are tainted
                bool src_tainted = false;
                for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                    auto diff = inst.reg_diff(i);
                    if ((result.tainted_regs >> diff.index) & 1) {
                        src_tainted = true;
                        break;
                    }
                }
                // Check memory: if any read address is tainted
                bool mem_tainted = false;
                if (config.taint_from_memory) {
                    for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                        auto mem = inst.mem_access(m);
                        if ((mem.type & 2) == 0) {  // read
                            if (result.tainted_memory.contains(mem.addr)) {
                                mem_tainted = true;
                                break;
                            }
                        }
                    }
                }

                if (!src_tainted && !mem_tainted) {
                    inst_id++;
                    processed++;
                    result.instructions_skipped_xref++;
                    continue;
                }
            }
          }
        }

        // ─── Learn which registers this PC writes ─────────────────────
        uint64_t& written_mask = pc_to_written_regs[inst.pc];
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            written_mask |= (1ULL << inst.reg_diff(i).index);
        }

        // ─── Determine which source registers are tainted ─────────────
        // In heuristic mode, we infer data flow from reg_diffs:
        // - Registers that appear in reg_diffs but are NOT the destination
        //   are potential sources (read operands).
        // - The register that changes value is the destination.
        //
        // Improved heuristic: a register is "read" if it appears in the
        // pre-state and its value contributes to the computation. Since we
        // can't know this precisely without Triton, we use the conservative
        // assumption that ALL registers in the diff set are both read and
        // written (except for the one that actually changes).

        // Collect all registers that are modified (written)
        // ── Perf: stack-local arrays eliminate per-instruction heap alloc ──
        // For 100M+ instructions, this prevents billions of malloc/free calls.
        uint8_t written_regs[16];  // max reg_diffs per instruction
        uint8_t n_written = 0;
        for (uint8_t i = 0; i < inst.reg_diff_count && i < 16; i++) {
            written_regs[n_written++] = inst.reg_diff(i).index;
        }

        // Determine if any source is tainted
        bool any_src_tainted = (result.tainted_regs != 0);
        // Build stack-local tainted source reg list from bitmask
        uint8_t tainted_sources[64];
        uint8_t n_tainted_sources = 0;
        if (any_src_tainted) {
            uint64_t tmp = result.tainted_regs;
            while (tmp) {
                uint8_t bit = static_cast<uint8_t>(__builtin_ctzll(tmp));
                tainted_sources[n_tainted_sources++] = bit;
                tmp &= tmp - 1;  // clear lowest set bit
            }
        }

        // Check memory sources
        bool mem_source_tainted = false;
        uint64_t tainted_mem_sources[8];  // max mem accesses per inst
        uint8_t n_tainted_mem = 0;
        if (config.taint_from_memory) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if ((mem.type & 2) == 0) {  // read
                    if (result.tainted_memory.contains(mem.addr)) {
                        mem_source_tainted = true;
                        if (n_tainted_mem < 8) {
                            tainted_mem_sources[n_tainted_mem++] = mem.addr;
                        }
                    }
                }
            }
        }

        // ─── Process each written register ────────────────────────────
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            uint8_t reg_idx = diff.index;

            // Skip SP/PC/NZCV unless explicitly included
            if (reg_idx == IDX_NZCV) continue;
            if (reg_idx == IDX_SP) continue;
            if (reg_idx == IDX_PC) continue;

            bool was_tainted = (result.tainted_regs >> reg_idx) & 1;

            // ─── Kill semantics ───────────────────────────────────────
            // If a register is overwritten and NONE of its sources are tainted,
            // the register becomes untainted (killed).
            // This is the key improvement over the old heuristic mode.

            // Check if this specific write has tainted inputs
            bool has_tainted_input = false;

            // Heuristic: if any other reg in the diff set is tainted, it might
            // be a source operand (e.g., ADD X1, X2, X3 where X2 is tainted).
            for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                if (i == j) continue;
                auto src = inst.reg_diff(j);
                if ((result.tainted_regs >> src.index) & 1) {
                    has_tainted_input = true;
                    break;
                }
            }

            // Also check: if the register being written was itself tainted
            // and this looks like a read-modify-write (e.g., ADD X1, X1, X2)
            if (!has_tainted_input && was_tainted) {
                // Could be self-referencing (X1 = X1 + something)
                // In heuristic mode, we conservatively keep taint if the reg
                // was already tainted (it might be reading its own value).
                has_tainted_input = true;
            }

            // Memory source contributes taint
            if (!has_tainted_input && mem_source_tainted) {
                has_tainted_input = true;
            }

            if (has_tainted_input) {
                // ─── Taint propagation ────────────────────────────────
                if (!was_tainted) {
                    result.tainted_regs |= (1ULL << reg_idx);

                    PropagationStep step;
                    step.inst_id = inst_id;
                    step.pc = inst.pc;
                    step.dst_reg = reg_idx;
                    step.triton_resolved = false;

                    if (mem_source_tainted && !any_src_tainted) {
                        step.type = PropagationType::MemToReg;
                        for (uint8_t mi = 0; mi < n_tainted_mem; mi++)
                            step.add_src_mem(tainted_mem_sources[mi]);
                    } else {
                        step.type = PropagationType::RegToReg;
                        // Build src_reg_mask from actual tainted source regs
                        for (uint8_t j = 0; j < inst.reg_diff_count; j++) {
                            if (i == j) continue;
                            auto src = inst.reg_diff(j);
                            if ((result.tainted_regs >> src.index) & 1) {
                                step.src_reg_mask |= (1ULL << src.index);
                            }
                        }
                        if (step.src_reg_mask == 0 && was_tainted) {
                            step.src_reg_mask |= (1ULL << reg_idx);  // self-reference
                        }
                        if (mem_source_tainted) {
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

        // ─── Memory sinks (RegToMem) ─────────────────────────────────
        if (config.track_memory_sinks && inst.mem_access_count > 0) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (mem.type & 2) {  // write
                    // Check if any source register is tainted
                    bool tainted_store = false;
                    uint8_t store_sources[34];
                    uint8_t n_store_sources = 0;
                    for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                        auto diff = inst.reg_diff(i);
                        if ((result.tainted_regs >> diff.index) & 1) {
                            tainted_store = true;
                            if (n_store_sources < 34) {
                                store_sources[n_store_sources++] = diff.index;
                            }
                        }
                    }
                    // Also check if any currently-tainted reg could be the store source
                    if (!tainted_store && any_src_tainted) {
                        tainted_store = true;
                        std::memcpy(store_sources, tainted_sources, n_tainted_sources);
                        n_store_sources = n_tainted_sources;
                    }

                    if (tainted_store) {
                        result.tainted_memory.add(mem.addr);

                        PropagationStep step;
                        step.inst_id = inst_id;
                        step.pc = inst.pc;
                        step.type = PropagationType::RegToMem;
                        step.dst_mem_addr = mem.addr;
                        step.dst_mem_size = static_cast<uint8_t>(mem.size);
                        // Build src_reg_mask from store_sources
                        for (uint8_t si = 0; si < n_store_sources; si++)
                            step.src_reg_mask |= (1ULL << store_sources[si]);
                        step.triton_resolved = false;
                        emit_step(result, config, std::move(step));
                    }
                }
            }
        }

        // ─── ABI-aware call boundary detection ────────────────────────
        if (config.propagate_through_calls) {
            // Detect call: LR (X30) is written → this is a BL/BLR
            bool is_call = false;
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                if (inst.reg_diff(i).index == REG_LR) {
                    is_call = true;
                    break;
                }
            }

            if (is_call) {
                // Emit Call event if any argument register is tainted
                uint64_t arg_taint = result.tainted_regs & 0xFFULL;  // X0-X7 = bits 0-7
                if (arg_taint) {
                    PropagationStep step;
                    step.inst_id = inst_id;
                    step.pc = inst.pc;
                    step.type = PropagationType::Call;
                    step.src_reg_mask = arg_taint;  // bitmask of arg regs carrying taint
                    step.triton_resolved = false;
                    emit_step(result, config, std::move(step));
                    result.call_crossings++;
                }
            }

            // Detect return: PC changes to LR value (heuristic: if PC diff
            // matches the LR value from before). In practice, we detect RET
            // by checking if the instruction has no reg_diffs except PC
            // and the next PC equals the saved LR. Simplified: if we see
            // X0 tainted at what looks like a function exit, emit Return event.
            // For now, we rely on the natural trace flow — the caller will
            // see X0 tainted after the callee returns.
        }

        inst_id++;
        processed++;
        result.instructions_processed = processed;

        if (processed % 10000 == 0) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
        }
    }

    ctx.progress(1.0f, fmt::format("Taint (heuristic): {} events, {} steps, {} kills, "
                                     "{} skipped, {} regs, {} mem",
                                     result.events.size(),
                                     result.steps.size(),
                                     result.kill_events_count,
                                     result.instructions_skipped_xref,
                                     result.tainted_reg_count(),
                                     result.tainted_memory.cardinality()));
    return PassResult::success(std::move(result));
}

// ─── TaintPass dispatch ─────────────────────────────────────────────────────

PassResult TaintPass::run(PassContext& ctx) {
    // Try Triton-based precise taint first
#ifdef TENET_HAS_TRITON
    {
        auto probe = create_triton_bridge();
        if (probe->is_available()) {
            return run_triton_taint(ctx, config_);
        }
    }
#endif
    // Fall back to heuristic taint with kill semantics
    return run_heuristic_taint(ctx, config_);
}

}  // namespace tenet

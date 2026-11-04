#include "common/compiler_compat.h"
#include "common/memory_ranges.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/taint_common.h"
#include "analysis/control_dependencies.h"
#include "io/trace_reader.h"
#include "io/reverse_trace_window.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/triton_bridge.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <cstring>
#include <algorithm>
namespace tenet {

using json = nlohmann::json;

// AArch64 ABI constants and register-exclusion rule now live in
// taint_common.h (kTaintRegLR, TaintRegFilter) so TaintPass and
// BackwardTaintPass can't drift out of sync on what counts as "data".

// Maximum registers we track (AArch64 has 34 GPRs; 64 gives headroom).
static constexpr uint8_t MAX_TRACKED_REGS = 66;

static bool should_exclude_reg(uint8_t reg_idx, const BackwardTaintConfig& config) {
    TaintRegFilter filter;
    filter.include_sp = config.include_sp;
    filter.include_pc = config.include_pc;
    filter.include_flags = config.include_flags;
    filter.include_simd = config.include_simd;
    return filter.should_exclude(reg_idx);
}

// --- Per-sink tracking state (zero-alloc, bitmask-based) ------------------
//
// reg_to_sinks:   fixed array indexed by register ID → uint64_t tag bitmask.
//                 O(1) add/remove/query, no hash map or vector allocation.
// active_regs_mask: bitmask of which reg_to_sinks entries are non-zero,
//                    enabling fast iteration via __builtin_ctzll.
// mem_to_sinks:   disjoint byte intervals carrying per-sink bitmasks.
//                 Partial writes resolve only the bytes they overwrite.

struct PropagationState {
    struct Registers {
        uint64_t tags[66]{};
        uint64_t active_regs_mask = 0;
        uint32_t active_simd_mask = 0;
    };
    ankerl::unordered_dense::map<uint64_t, Registers> threads;
    uint64_t current_thread = 0;
    size_t active_count = 0;
    MemoryRanges<uint64_t> mem_to_sinks;
    Registers* selected = nullptr;
    void select_thread(uint64_t tid) { current_thread = tid; selected = &threads.try_emplace(tid).first->second; }
    Registers& regs() { if (!selected) select_thread(current_thread); return *selected; }
    bool has_reg(uint8_t r) { return r < 66 && regs().tags[r] != 0; }
    bool empty() const { return active_count == 0 && mem_to_sinks.empty(); }
    void add_reg(uint8_t r, uint64_t tags) {
        if (r >= 66 || !tags) return;
        auto& t = regs(); if (!t.tags[r]) ++active_count;
        t.tags[r] |= tags;
        if (r < 34) t.active_regs_mask |= 1ULL << r;
        else t.active_simd_mask |= uint32_t(1) << (r - 34);
    }
    void remove_reg(uint8_t r) {
        auto& t = regs(); if (t.tags[r]) --active_count;
        t.tags[r] = 0;
        if (r < 34) t.active_regs_mask &= ~(1ULL << r);
        else t.active_simd_mask &= ~(uint32_t(1) << (r - 34));
    }
    uint64_t get_reg_tags(uint8_t r) { return regs().tags[r]; }
    void add_mem(uint64_t addr, uint64_t size, uint64_t tags) {
        mem_to_sinks.update(addr, size, [=](uint64_t& value) { value |= tags; });
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Instruction classification interface (stack-allocated, zero malloc)
// ═══════════════════════════════════════════════════════════════════════════
//
// The backward traversal loop is identical for both Triton and heuristic paths.
// The ONLY difference is how each instruction is classified:
//   - Which registers does it WRITE? (potential definitions of needed values)
//   - Which registers does it READ? (new dependencies to propagate)
//   - Is it a BL (branch-and-link) site? (exclude LR from data tracking)
//   - Does it have a memory read? (for load propagation through memory)
//
// The shared TaintInstructionInfo (taint_common.h) uses fixed-size stack
// arrays to avoid per-instruction heap allocation in the million-instruction
// hot loop, and is also used by TaintPass's heuristic classifier — see
// classify_inst_heuristic() below for the shared heuristic strategy.
using InstructionInfo = TaintInstructionInfo;

// ═══════════════════════════════════════════════════════════════════════════
// Common backward traversal framework (templated for inlining classify)
// ═══════════════════════════════════════════════════════════════════════════

template <typename ClassifyFn>
static PassResult run_backward_taint_common(
    PassContext& ctx,
    const BackwardTaintConfig& config,
    ClassifyFn&& classify,
    const char* method_label)
{
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    BackwardTaintResult result;
    result.config = config;
    result.events.set_resident_budget(ctx.memory_budget_bytes() / 4);
    result.dataflow_edges.set_resident_budget(ctx.memory_budget_bytes() / 4);
    result.quality.engine = method_label;
    const bool multi_thread = index.thread_ids().size() > 1;

    std::unique_ptr<ControlDependencies> control;
    std::unordered_map<uint64_t, uint64_t> needed_controls;
    if (config.include_control) {
        control = std::make_unique<ControlDependencies>(ctx);
        result.quality.unresolved_control_joins = control->unresolved_joins;
    }
    // ── Initialize per-sink tags from config ─────────────────────────────
    PropagationState state;
    const auto sink_point = config.sink_inst_id ? std::min(config.sink_inst_id - 1, index.inst_count() ? index.inst_count() - 1 : 0) : 0;
    state.select_thread(index.thread_at(sink_point));
    MemoryRanges<std::vector<uint64_t>> memory_consumers;
    uint8_t tag_idx = 0;
    {
        uint64_t remaining = config.sink_regs;
        while (remaining) {
            uint8_t r = static_cast<uint8_t>(tenet::platform::trailing_zeros(remaining));
            remaining &= remaining - 1;
            if (should_exclude_reg(r, config)) continue;
            if (tag_idx >= 64) return PassResult::failed("at most 64 sinks are supported");
            SinkTag tag;
            tag.kind = SinkTag::Register;
            tag.reg_id = r;
            result.sink_tags.push_back(tag);
            state.add_reg(r, 1ULL << tag_idx);
            tag_idx++;
        }
    }
    if (config.include_simd) for (uint32_t m = config.sink_simd_regs; m; m &= m - 1) {
        if (tag_idx >= 64) return PassResult::failed("at most 64 sinks are supported");
        const uint8_t reg = 34 + static_cast<uint8_t>(tenet::platform::trailing_zeros(m));
        SinkTag tag; tag.kind = SinkTag::Register; tag.reg_id = reg;
        result.sink_tags.push_back(tag); state.add_reg(reg, 1ULL << tag_idx++);
    }
    for (uint64_t addr : config.sink_mem_addrs) {
        if (tag_idx >= 64) return PassResult::failed("at most 64 sinks are supported");
        SinkTag tag;
        tag.kind = SinkTag::Memory;
        tag.mem_addr = addr;
        result.sink_tags.push_back(tag);
        state.add_mem(addr, 8, 1ULL << tag_idx);
        tag_idx++;
    }

    result.per_sink_inst_ids.resize(result.sink_tags.size());

    if (state.empty()) {
        ctx.progress(1.0f, "Backward taint: nothing to trace (empty sink set)");
        return PassResult::success(std::move(result));
    }

    uint64_t current_id = std::min(config.sink_inst_id, index.inst_count());
    ReverseTraceWindow reverse_window(reader, index);
    uint64_t steps = 0;
    uint64_t total_estimated = std::min(current_id,
        config.max_steps > 0 ? config.max_steps : current_id);

    uint64_t index_jumps = 0;
    uint64_t index_skipped = 0;
    uint64_t dense_index_hits = 0;

    // ── Main backward traversal loop ─────────────────────────────────────
    while (current_id > 0 && (!state.empty() || !needed_controls.empty())) {
        // ── REG_WRITES Index Acceleration ─────────────────────────────────
        if ((dense_index_hits < 64 || (steps & 4095) == 0) && !config.include_control && !multi_thread && !state.regs().active_simd_mask && config.use_index_acceleration && state.mem_to_sinks.empty() &&
            state.regs().active_regs_mask != 0 &&
            !(config.include_flags && (state.regs().active_regs_mask & (1ULL << IDX_NZCV)))) {
            uint64_t best_jump = UINT64_MAX;
            for (uint64_t m = state.regs().active_regs_mask; m; m &= m - 1) {
                uint8_t reg = static_cast<uint8_t>(tenet::platform::trailing_zeros(m));
                uint64_t writer = index.find_last_writer_of(reg, current_id, reader);
                if (writer != UINT64_MAX && (best_jump == UINT64_MAX || writer > best_jump)) {
                    best_jump = writer;
                }
            }

            if (best_jump == UINT64_MAX) {
                break;  // No writer found → done
            }

            if (current_id - best_jump <= 4) ++dense_index_hits; else dense_index_hits = 0;
            if (best_jump < current_id) {
                uint64_t skipped = current_id - best_jump - 1;
                index_skipped += skipped;
                index_jumps++;
                current_id = best_jump + 1;  // Will be decremented below
            }
        }

        current_id--;
        if (config.max_steps > 0 && steps >= config.max_steps) {
            result.quality.truncated = true;
            result.quality.termination_reason = "max_steps reached";
            break;
        }
        steps++;
        if (config.max_tainted_insts > 0 &&
            result.contributing_inst_ids.cardinality() >= config.max_tainted_insts) {
            result.quality.truncated = true;
            result.quality.termination_reason = "max_tainted_insts reached";
            break;
        }
        if (ctx.cancelled()) return PassResult::failed("cancelled by user");
        if ((steps & 4095) == 0 && ctx.memory_pressure()) {
            result.quality.truncated = true; result.quality.termination_reason = "RSS limit exceeded"; break;
        }

        auto rec = reverse_window.at(current_id);
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();
        state.select_thread(index.thread_at(current_id));

        // ── Classify instruction via strategy ────────────────────────────
        ++result.quality.instructions_examined;
        auto info = classify(inst);
        result.quality.missing_code += info.missing_code;
        result.quality.undecoded_instructions += info.undecoded;
        result.quality.unsupported_register_instructions += info.unsupported_registers ||
            (!config.include_simd && (info.simd_reads || info.simd_writes));
        if (config.include_simd) {
            for (uint32_t m = info.simd_reads; m; m &= m - 1) info.add_read(34 + static_cast<uint8_t>(tenet::platform::trailing_zeros(m)));
            for (uint32_t m = info.simd_writes; m; m &= m - 1) info.add_written(34 + static_cast<uint8_t>(tenet::platform::trailing_zeros(m)));
        }
        if (!info.valid) continue;

        // --- Multi-definition: check ALL written registers vs needed set ---
        bool contributes = false;
        BackwardTaintEvent event;
        event.inst_id = current_id;
        event.pc = inst.pc;
        event.thread_id = state.current_thread;
        uint64_t resolved_tags_mask = 0;
        if (auto c = needed_controls.find(current_id); c != needed_controls.end()) {
            contributes = true; event.control_branch = true;
            resolved_tags_mask = c->second; needed_controls.erase(c);
        }

        for (uint8_t i = 0; i < info.n_written; i++) {
            uint8_t wr_reg = info.written_regs[i];
            if (should_exclude_reg(wr_reg, config)) continue;
            // Skip LR write at BL sites (it's control flow, not data)
            if (info.is_bl_site && wr_reg == kTaintRegLR) continue;

            if (state.has_reg(wr_reg)) {
                contributes = true;
                event.add_dst_reg(wr_reg);
                if (event.dst_reg == 0) event.dst_reg = wr_reg;

                // Merge tags via OR — inherently deduplicates
                resolved_tags_mask |= state.get_reg_tags(wr_reg);

                state.remove_reg(wr_reg);
                result.record_reg(wr_reg);
            }
        }

        const bool only_writeback = contributes && info.has_decoded_operands &&
            info.writeback_reg != 0xff && event.dst_simd_mask == 0 && event.dst_regs_mask == (1ULL << info.writeback_reg);
        if (contributes) {
            // Add all READ registers as new needed (source operands).
            //
            // NOTE: a register that is BOTH written and read by this same
            // instruction (read-modify-write / accumulator pattern, e.g.
            // `eor x9, x9, x21` — reads the old x9, writes a new x9) must
            // still be re-added as a dependency: the new value provably
            // depends on the OLD value of that register, which was defined
            // by an *earlier* instruction and has to keep propagating
            // backward. We used to `continue` here whenever
            // `event.has_dst_reg(sr_reg)` was true, which conflated this
            // RMW case with instructions that overwrite a register without
            // reading it (e.g. `mov x1, #imm`, which never lists x1 as a
            // read in the first place and so never hits this branch at
            // all). That conflation silently truncated backward slices at
            // every self-referencing accumulator (common in checksum/mixing
            // code), which is why real traces stopped short of memory
            // load/store chains that a step-by-step trace clearly crosses.
            for (uint8_t i = 0; i < info.n_read; i++) {
                uint8_t sr_reg = info.read_regs[i];
                if (only_writeback && (sr_reg >= 34 || !(info.writeback_reads & (1ULL << sr_reg)))) continue;
                if (should_exclude_reg(sr_reg, config)) continue;
                if (info.is_bl_site && sr_reg == kTaintRegLR) continue;

                event.add_src_reg(sr_reg);
                state.add_reg(sr_reg, resolved_tags_mask);
                result.record_reg(sr_reg);
            }
        }

        // --- Check stores to needed memory addresses ---
        if (config.propagate_through_memory && !state.mem_to_sinks.empty()) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 2)) continue;

                uint64_t store_tags = 0;
                state.mem_to_sinks.visit(mem.addr, mem.size,
                    [&](uint64_t, uint64_t, uint64_t tags) { store_tags |= tags; });
                if (!store_tags) continue;
                // Resolve only the written bytes; older stores may still
                // produce the untouched parts of this load or other sinks.
                if (config.build_dataflow_graph) {
                    ankerl::unordered_dense::set<uint64_t> consumers;
                    memory_consumers.visit(mem.addr, mem.size,
                        [&](uint64_t first, uint64_t, const std::vector<uint64_t>& readers) {
                            for (auto reader_id : readers) {
                                if (consumers.insert(reader_id).second)
                                    result.dataflow_edges.emplace_back(current_id, reader_id, 0, first);
                            }
                        });
                    memory_consumers.erase(mem.addr, mem.size);
                }
                state.mem_to_sinks.erase(mem.addr, mem.size);
                contributes = true;
                event.stores_to_memory = true;
                event.store_addr = mem.addr;
                event.store_size = static_cast<uint8_t>(mem.size);
                resolved_tags_mask |= store_tags;
                for (uint8_t i = 0; i < info.n_read; i++) {
                    uint8_t sr_reg = info.read_regs[i];
                    if (should_exclude_reg(sr_reg, config)) continue;
                    if (!event.has_src_reg(sr_reg)) event.add_src_reg(sr_reg);
                    state.add_reg(sr_reg, store_tags);
                    result.record_reg(sr_reg);
                }
                result.involved_mem_addrs.add(mem.addr);
            }
        }

        // In reverse execution, resolve writes before introducing reads of
        // the same instruction. This also supports memory-to-memory transfers.
        if (contributes && config.propagate_through_memory && info.has_memory_reads &&
            (!only_writeback || event.stores_to_memory)) {
            for (uint8_t m = 0; m < inst.mem_access_count; ++m) {
                auto mem = inst.mem_access(m);
                if (mem.type & 2) continue;
                event.loads_from_memory = true;
                event.src_mem_addrs.push_back(mem.addr);
                state.add_mem(mem.addr, mem.size, resolved_tags_mask);
                if (config.build_dataflow_graph) {
                    memory_consumers.update(mem.addr, mem.size,
                        [&](std::vector<uint64_t>& readers) { readers.push_back(current_id); });
                }
                result.involved_mem_addrs.add(mem.addr);
            }
        }

        // --- Record event ---
        if (contributes) {
            if (control && current_id < control->parents.size()) {
                const auto parent = control->parents[current_id];
                if (parent != UINT64_MAX) {
                    needed_controls[parent] |= resolved_tags_mask;
                    event.control_inst_id = parent;
                    if (config.build_dataflow_graph) result.dataflow_edges.emplace_back(parent, current_id, 0xff, 0);
                }
            }
            event.sink_tags_mask = resolved_tags_mask;
            result.contributing_inst_ids.add(current_id);
            if (result.events.size() >= 65536 && !result.compact_navigation) {
                result.compact_navigation = true; result.inst_id_to_event_.clear();
            }
            if (!result.compact_navigation) result.inst_id_to_event_[current_id] = result.events.size();

            // Per-sink attribution via bitmask iteration
            for (uint64_t m = resolved_tags_mask; m; m &= m - 1) {
                uint8_t t = static_cast<uint8_t>(tenet::platform::trailing_zeros(m));
                if (t < result.per_sink_inst_ids.size()) {
                    result.per_sink_inst_ids[t].add(current_id);
                }
            }

            result.events.push_back(std::move(event));
        }

        if (steps % 5000 == 0) {
            float pct = total_estimated > 0
                ? static_cast<float>(steps) / static_cast<float>(total_estimated)
                : 0.0f;
            ctx.progress(std::min(pct, 0.99f));
        }
    }

    // --- Build dataflow edges from event chain ---
    // Memory edges were emitted while resolving byte ranges above.
    // Reconstruct register fan-out in time proportional to events and edges.
    if (config.build_dataflow_graph && result.events.size() > 1) {
        ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint8_t, std::vector<uint64_t>>> thread_consumers;

        for (size_t i = 0; i < result.events.size(); i++) {
            if ((i % 1000) == 0) {
                if (ctx.cancelled()) return PassResult::failed("cancelled by user");
                if (ctx.memory_pressure()) return PassResult::failed("Backward graph RSS limit exceeded");
            }
            result.events.cool_before(i);
            const auto& ev = result.events[i];
            auto& reg_consumer = thread_consumers[ev.thread_id];

            ev.for_each_dst_reg([&](uint8_t dr) {
                auto cit = reg_consumer.find(dr);
                if (cit != reg_consumer.end()) {
                    for (auto consumer : cit->second)
                        result.dataflow_edges.emplace_back(ev.inst_id, consumer, dr, 0);
                    reg_consumer.erase(cit);
                }
            });
            ev.for_each_src_reg([&](uint8_t sr) {
                reg_consumer[sr].push_back(ev.inst_id);
            });

        }
    }

    result.max_depth = result.events.size();

    ctx.progress(1.0f, fmt::format(
        "Backward taint ({}): {} contributing, {} steps, "
        "{} idx-jumps, {} idx-skipped, {} edges",
        method_label,
        result.contributing_inst_ids.cardinality(), steps,
        index_jumps, index_skipped, result.dataflow_edges.size()));

    return PassResult::success(std::move(result));
}

// ═══════════════════════════════════════════════════════════════════════════
// Triton-based classifier
// ═══════════════════════════════════════════════════════════════════════════

static PassResult run_triton_backward_taint(PassContext& ctx, const BackwardTaintConfig& config) {
    auto& code_table = ctx.code_table();

    auto bridge_ptr = create_triton_bridge();
    if (!bridge_ptr->is_available()) {
        return PassResult::failed("Triton bridge not available for backward taint");
    }

    auto* triton = dynamic_cast<TritonBridgeTaint*>(bridge_ptr.get());
    if (!triton) {
        return PassResult::failed("Triton bridge does not support taint interface");
    }

    // Capture bridge_ptr and code_table for use in the classifier lambda.
    // The lambda is called once per instruction in the hot loop.
    auto classify = [&bridge_ptr, &code_table](const InstView& inst) -> InstructionInfo {
        InstructionInfo info;

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (!opcode_opt) {
            info.valid = false;
            info.missing_code = true;
            return info;
        }

        uint32_t opcode_val = *opcode_opt;
        auto* opcode_bytes = reinterpret_cast<const uint8_t*>(&opcode_val);

        // query_semantics only needs opcode bytes to determine read/write register sets
        // via Triton's instruction decoder. No register context needed.
        auto sem_result = bridge_ptr->query_semantics(inst.pc, opcode_bytes, 4);
        if (!sem_result) {
            info.valid = false;
            info.undecoded = true;
            return info;
        }

        const auto& sem = *sem_result;

        // Populate written/read registers from Triton semantics
        for (const auto& ra : sem.reg_accesses) {
            if (ra.is_written) {
                info.add_written(ra.reg_id);
                if (ra.reg_id == kTaintRegLR) {
                    info.is_bl_site = true;
                }
            }
            if (ra.is_read) {
                info.add_read(ra.reg_id);
            }
        }

        // Check semantic memory reads (Triton provides this info)
        for (const auto& ma : sem.mem_accesses) {
            if (ma.is_read) {
                info.has_memory_reads = true;
                break;
            }
        }

        return info;
    };

    return run_backward_taint_common(ctx, config, classify, "Triton");
}

// ═══════════════════════════════════════════════════════════════════════════
// Heuristic classifier (fallback)
// ═══════════════════════════════════════════════════════════════════════════

static PassResult run_heuristic_backward_taint(PassContext& ctx, const BackwardTaintConfig& config) {
    // Share decoded source operands with forward taint, retaining the
    // conservative reg_diff fallback when instruction bytes are unavailable.
    auto classify = [&ctx](const InstView& inst) -> InstructionInfo {
        return classify_inst_heuristic(inst, ctx.decoder(), ctx.code_table());
    };

    return run_backward_taint_common(ctx, config, classify, "heuristic");
}

// --- BackwardTaintPass dispatch --------------------------------------------

PassResult BackwardTaintPass::run(PassContext& ctx) {
    if (config_.sink_inst_id == 0 && config_.sink_regs == 0 && config_.sink_simd_regs == 0 && config_.sink_mem_addrs.empty()) {
        return PassResult::failed("BackwardTaintPass: no sink specified");
    }

#ifdef TENET_HAS_TRITON
    {
        auto probe = create_triton_bridge();
        if (probe->is_available() && !config_.include_flags && !config_.include_simd && ctx.index().thread_ids().size() <= 1) {
            return run_triton_backward_taint(ctx, config_);
        }
    }
#endif
    return run_heuristic_backward_taint(ctx, config_);
}

// --- BackwardTaintEvent bitmask serialization helpers ----------------------

std::vector<uint8_t> BackwardTaintEvent::dst_regs_list() const {
    std::vector<uint8_t> v;
    v.reserve(tenet::platform::population_count(dst_regs_mask));
    for_each_dst_reg([&](uint8_t r) { v.push_back(r); });
    return v;
}

std::vector<uint8_t> BackwardTaintEvent::src_regs_list() const {
    std::vector<uint8_t> v;
    v.reserve(tenet::platform::population_count(src_regs_mask));
    for_each_src_reg([&](uint8_t r) { v.push_back(r); });
    return v;
}

std::vector<uint8_t> BackwardTaintEvent::sink_tags_list() const {
    std::vector<uint8_t> v;
    v.reserve(tenet::platform::population_count(sink_tags_mask));
    for_each_sink_tag([&](uint8_t t) { v.push_back(t); });
    return v;
}

// --- Result utility methods -----------------------------------------------

std::string BackwardTaintResult::to_dot() const {
    std::string dot;
    dot += "digraph backward_taint {\n";
    dot += "  rankdir=BT;\n";
    dot += "  node [shape=box, style=filled, fillcolor=lightyellow, fontsize=10];\n";
    dot += "  edge [color=gray40];\n\n";

    for (const auto& ev : events) {
        std::string label = fmt::format("#{} pc=0x{:X}", ev.inst_id, ev.pc);
        if (!ev.dst_regs_empty()) {
            label += " def:";
            bool first = true;
            ev.for_each_dst_reg([&](uint8_t r) {
                if (!first) label += ",";
                label += fmt::format("x{}", r);
                first = false;
            });
        }
        dot += fmt::format("  n{} [label=\"{}\"];\n", ev.inst_id, label);
    }
    dot += "\n";

    for (const auto& edge : dataflow_edges) {
        std::string label;
        if (edge.via_mem_addr != 0) {
            label = fmt::format("mem:0x{:X}", edge.via_mem_addr);
        } else {
            label = edge.via_reg == 0xff ? "control" : edge.via_reg >= 34 ? fmt::format("v{}", edge.via_reg - 34) : fmt::format("x{}", edge.via_reg);
        }
        dot += fmt::format("  n{} -> n{} [label=\"{}\"];\n",
                           edge.from_inst_id, edge.to_inst_id, label);
    }

    dot += "}\n";
    return dot;
}

std::string BackwardTaintResult::to_graph_json() const {
    json output;

    json nodes_arr = json::array();
    for (const auto& ev : events) {
        json node;
        node["inst_id"] = ev.inst_id;
        node["pc"] = fmt::format("0x{:X}", ev.pc);
        if (!ev.dst_regs_empty()) node["dst_regs"] = ev.dst_regs_list();
        if (!ev.src_regs_empty()) node["src_regs"] = ev.src_regs_list();
        if (!ev.sink_tags_empty()) node["sink_tags"] = ev.sink_tags_list();
        if (ev.loads_from_memory) {
            json addrs = json::array();
            for (auto a : ev.src_mem_addrs) addrs.push_back(fmt::format("0x{:X}", a));
            node["loads_from"] = std::move(addrs);
        }
        if (ev.stores_to_memory) {
            node["stores_to"] = fmt::format("0x{:X}", ev.store_addr);
        }
        nodes_arr.push_back(std::move(node));
    }
    output["nodes"] = std::move(nodes_arr);

    json edges_arr = json::array();
    for (const auto& e : dataflow_edges) {
        json edge;
        edge["from"] = e.from_inst_id;
        edge["to"] = e.to_inst_id;
        edge["via_reg"] = e.via_reg;
        if (e.via_mem_addr != 0) {
            edge["via_mem"] = fmt::format("0x{:X}", e.via_mem_addr);
        }
        edges_arr.push_back(std::move(edge));
    }
    output["edges"] = std::move(edges_arr);

    json tags_arr = json::array();
    for (const auto& t : sink_tags) {
        json tag;
        if (t.kind == SinkTag::Register) {
            tag["kind"] = "reg";
            tag["reg"] = t.reg_id;
        } else {
            tag["kind"] = "mem";
            tag["addr"] = fmt::format("0x{:X}", t.mem_addr);
        }
        tags_arr.push_back(std::move(tag));
    }
    output["sink_tags"] = std::move(tags_arr);

    output["contributing_count"] = contributing_count();
    output["max_depth"] = max_depth;
    output["edge_count"] = dataflow_edges.size();

    return output.dump(2);
}

roaring::Roaring64Map BackwardTaintResult::critical_path(const TaintResult& forward) const {
    roaring::Roaring64Map cp = contributing_inst_ids;
    cp &= forward.tainted_inst_ids;
    return cp;
}

}  // namespace tenet

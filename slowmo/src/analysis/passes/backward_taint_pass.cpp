#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/taint_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/triton_bridge.h"
// register_file.h and memory_model.h removed: regfile no longer used in hot path

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <cstring>
#include <algorithm>
namespace tenet {

using json = nlohmann::json;

// AArch64 ABI constants
static constexpr uint8_t REG_X0  = 0;
static constexpr uint8_t REG_X7  = 7;
static constexpr uint8_t REG_X30 = 30;  // LR

// --- Helper: check if a register should be excluded from propagation ------

static bool should_exclude_reg(uint8_t reg_idx, const BackwardTaintConfig& config) {
    if (reg_idx == IDX_NZCV) return true;
    if (reg_idx == IDX_SP && !config.include_sp) return true;
    if (reg_idx == IDX_PC && !config.include_pc) return true;
    return false;
}

// --- Per-sink tracking state ----------------------------------------------

struct PropagationState {
    // reg_idx -> set of sink tag indices
    ankerl::unordered_dense::map<uint8_t, std::vector<uint8_t>> reg_to_sinks;
    // mem_addr -> (size, set of sink tag indices)
    struct MemEntry {
        uint8_t size;
        std::vector<uint8_t> sink_tags;
    };
    ankerl::unordered_dense::map<uint64_t, MemEntry> mem_to_sinks;

    bool has_reg(uint8_t r) const { return reg_to_sinks.count(r) > 0; }
    bool has_mem(uint64_t a) const { return mem_to_sinks.count(a) > 0; }
    bool empty() const { return reg_to_sinks.empty() && mem_to_sinks.empty(); }

    void add_reg(uint8_t r, const std::vector<uint8_t>& tags) {
        auto& existing = reg_to_sinks[r];
        for (auto t : tags) {
            if (std::find(existing.begin(), existing.end(), t) == existing.end())
                existing.push_back(t);
        }
    }

    void add_mem(uint64_t addr, uint8_t size, const std::vector<uint8_t>& tags) {
        auto& entry = mem_to_sinks[addr];
        entry.size = size;
        for (auto t : tags) {
            if (std::find(entry.sink_tags.begin(), entry.sink_tags.end(), t) == entry.sink_tags.end())
                entry.sink_tags.push_back(t);
        }
    }

    void remove_reg(uint8_t r) { reg_to_sinks.erase(r); }
    void remove_mem(uint64_t a) { mem_to_sinks.erase(a); }

    const std::vector<uint8_t>& get_reg_tags(uint8_t r) const {
        static const std::vector<uint8_t> empty_tags;
        auto it = reg_to_sinks.find(r);
        return it != reg_to_sinks.end() ? it->second : empty_tags;
    }
};

// --- Triton-based precise backward taint ----------------------------------

static PassResult run_triton_backward_taint(PassContext& ctx, const BackwardTaintConfig& config) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    auto& code_table = ctx.code_table();

    auto bridge_ptr = create_triton_bridge();
    if (!bridge_ptr->is_available()) {
        return PassResult::failed("Triton bridge not available for backward taint");
    }

    auto* triton = dynamic_cast<TritonBridgeTaint*>(bridge_ptr.get());
    if (!triton) {
        return PassResult::failed("Triton bridge does not support taint interface");
    }

    BackwardTaintResult result;
    result.config = config;

    // Initialize per-sink tags
    PropagationState state;
    uint8_t tag_idx = 0;
    for (uint8_t r : config.sink_regs) {
        if (should_exclude_reg(r, config)) continue;
        SinkTag tag;
        tag.kind = SinkTag::Register;
        tag.reg_id = r;
        result.sink_tags.push_back(tag);
        state.add_reg(r, {tag_idx});
        tag_idx++;
    }
    for (uint64_t addr : config.sink_mem_addrs) {
        SinkTag tag;
        tag.kind = SinkTag::Memory;
        tag.mem_addr = addr;
        result.sink_tags.push_back(tag);
        state.add_mem(addr, 8, {tag_idx});
        tag_idx++;
    }

    result.per_sink_inst_ids.resize(result.sink_tags.size());

    if (state.empty()) {
        ctx.progress(1.0f, "Backward taint: nothing to trace (empty sink set)");
        return PassResult::success(std::move(result));
    }

    uint64_t current_id = config.sink_inst_id;
    uint64_t steps = 0;
    uint64_t total_estimated = std::min(current_id,
        config.max_steps > 0 ? config.max_steps : current_id);

    // Index-acceleration counters (for progress reporting)
    uint64_t index_jumps = 0;
    uint64_t index_skipped = 0;

    while (current_id > 0 && !state.empty()) {
        // ── REG_WRITES Index Acceleration ─────────────────────────────────
        // When only register deps remain (no in-flight memory deps), jump
        // directly to the most recent writer of any needed register via the
        // REG_WRITES inverted index (O(log N) vs O(N) linear scan).
        //
        // This can skip millions of irrelevant instructions in a single step,
        // making deep backward taint traces finish in <1s instead of minutes.
        //
        // Disabled when memory deps are present (we could miss a store).
        if (config.use_index_acceleration && state.mem_to_sinks.empty() &&
            !state.reg_to_sinks.empty()) {
            uint64_t best_jump = 0;
            for (const auto& [reg, _] : state.reg_to_sinks) {
                uint64_t writer = index.find_last_writer_of(reg, current_id, reader);
                if (writer > best_jump) {
                    best_jump = writer;
                }
            }

            if (best_jump == 0) {
                break;  // No writer found → done
            }

            if (best_jump < current_id) {
                uint64_t skipped = current_id - best_jump - 1;
                index_skipped += skipped;
                index_jumps++;
                current_id = best_jump + 1;  // Will be decremented below
            }
        }

        current_id--;
        steps++;

        if (config.max_steps > 0 && steps >= config.max_steps) break;
        if (config.max_tainted_insts > 0 &&
            result.contributing_inst_ids.cardinality() >= config.max_tainted_insts) break;
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        auto [offset, seed_pc] = index.offset_of_with_pc(current_id, reader);
        auto rec = reader.record_at(offset, seed_pc);
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        auto opcode_opt = code_table.opcode_at(inst.pc);
        if (!opcode_opt) continue;

        uint32_t opcode_val = *opcode_opt;
        auto* opcode_bytes = reinterpret_cast<const uint8_t*>(&opcode_val);

        // ── Performance: query_semantics only needs opcode bytes to determine
        // read/write register sets via Triton's instruction decoder.
        // Concrete register/memory values are NOT needed for this query —
        // removing reset() + set_register_context eliminates the two most
        // expensive calls in this loop (reset() re-initializes the entire
        // Triton context; set_register_context issues 34 API calls each time).
        auto sem_result = bridge_ptr->query_semantics(inst.pc, opcode_bytes, 4);
        if (!sem_result) continue;

        const auto& sem = *sem_result;

        // --- Cross-function handling ---
        // The linear backward walk through the trace naturally handles
        // cross-function boundaries because the trace is in execution order:
        // - BL (call): backward walk enters callee instructions naturally
        // - RET: backward walk exits callee and continues in caller
        // For ABI-aware tracking: if we need X0 (return value) and encounter
        // a BL site, the callee's computation of X0 is already before us in
        // the trace; the backward walk will pick it up automatically.
        // We just need to avoid incorrectly attributing X30 (LR) writes at BL
        // sites as data-producing instructions (they're control flow only).
        bool is_bl_site = false;
        for (const auto& ra : sem.reg_accesses) {
            if (ra.is_written && ra.reg_id == REG_X30) {
                // Writing LR typically means this is a BL instruction
                is_bl_site = true;
                break;
            }
        }

        // --- Multi-definition: check ALL written registers vs needed set ---
        bool contributes = false;
        BackwardTaintEvent event;
        event.inst_id = current_id;
        event.pc = inst.pc;

        std::vector<uint8_t> resolved_tags;

        for (const auto& ra : sem.reg_accesses) {
            if (!ra.is_written) continue;
            if (should_exclude_reg(ra.reg_id, config)) continue;

            // Skip LR write at BL sites (it's control flow, not data)
            if (is_bl_site && ra.reg_id == REG_X30) continue;

            if (state.has_reg(ra.reg_id)) {
                contributes = true;
                event.dst_regs.push_back(ra.reg_id);
                if (event.dst_reg == 0) event.dst_reg = ra.reg_id;

                const auto& tags = state.get_reg_tags(ra.reg_id);
                for (auto t : tags) {
                    if (std::find(resolved_tags.begin(), resolved_tags.end(), t) == resolved_tags.end())
                        resolved_tags.push_back(t);
                }

                state.remove_reg(ra.reg_id);
                result.all_involved_regs.insert(ra.reg_id);
            }
        }

        if (contributes) {
            // Add all READ registers as new needed (source operands)
            for (const auto& src_ra : sem.reg_accesses) {
                if (!src_ra.is_read) continue;
                if (should_exclude_reg(src_ra.reg_id, config)) continue;
                bool is_dst = std::find(event.dst_regs.begin(), event.dst_regs.end(),
                                        src_ra.reg_id) != event.dst_regs.end();
                if (is_dst) continue;

                event.src_regs.push_back(src_ra.reg_id);
                state.add_reg(src_ra.reg_id, resolved_tags);
                result.all_involved_regs.insert(src_ra.reg_id);
            }

            if (config.propagate_through_memory) {
                for (const auto& ma : sem.mem_accesses) {
                    if (!ma.is_read) continue;
                    event.loads_from_memory = true;
                    event.src_mem_addrs.push_back(ma.address);
                    state.add_mem(ma.address, ma.size, resolved_tags);
                    result.involved_mem_addrs.add(ma.address);
                }
            }
        }

        // --- Check stores to needed memory addresses ---
        if (config.propagate_through_memory && !state.mem_to_sinks.empty()) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 2)) continue;

                for (auto it = state.mem_to_sinks.begin(); it != state.mem_to_sinks.end(); ) {
                    uint64_t needed_addr = it->first;
                    uint8_t needed_size = it->second.size;

                    uint64_t store_start = mem.addr;
                    uint64_t store_end = mem.addr + mem.size;
                    uint64_t need_start = needed_addr;
                    uint64_t need_end = needed_addr + needed_size;

                    if (store_start < need_end && need_start < store_end) {
                        if (!contributes) contributes = true;
                        event.stores_to_memory = true;
                        event.store_addr = mem.addr;
                        event.store_size = static_cast<uint8_t>(mem.size);

                        for (auto t : it->second.sink_tags) {
                            if (std::find(resolved_tags.begin(), resolved_tags.end(), t) == resolved_tags.end())
                                resolved_tags.push_back(t);
                        }

                        it = state.mem_to_sinks.erase(it);

                        for (const auto& src_ra : sem.reg_accesses) {
                            if (!src_ra.is_read) continue;
                            if (should_exclude_reg(src_ra.reg_id, config)) continue;
                            if (std::find(event.src_regs.begin(), event.src_regs.end(),
                                          src_ra.reg_id) == event.src_regs.end()) {
                                event.src_regs.push_back(src_ra.reg_id);
                            }
                            state.add_reg(src_ra.reg_id, resolved_tags);
                            result.all_involved_regs.insert(src_ra.reg_id);
                        }

                        result.involved_mem_addrs.add(mem.addr);
                        break;
                    } else {
                        ++it;
                    }
                }
            }
        }

        // --- Record event ---
        if (contributes) {
            event.sink_tags = resolved_tags;
            result.contributing_inst_ids.add(current_id);
            result.inst_id_to_event_[current_id] = result.events.size();

            for (auto t : resolved_tags) {
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
    if (config.build_dataflow_graph && result.events.size() > 1) {
        ankerl::unordered_dense::map<uint8_t, uint64_t> reg_consumer;

        for (size_t i = 0; i < result.events.size(); i++) {
            const auto& ev = result.events[i];

            for (uint8_t dr : ev.dst_regs) {
                auto cit = reg_consumer.find(dr);
                if (cit != reg_consumer.end()) {
                    result.dataflow_edges.emplace_back(ev.inst_id, cit->second, dr, 0);
                }
            }
            if (ev.stores_to_memory) {
                for (size_t j = 0; j < i; j++) {
                    for (auto a : result.events[j].src_mem_addrs) {
                        if (a == ev.store_addr) {
                            result.dataflow_edges.emplace_back(
                                ev.inst_id, result.events[j].inst_id, 0, ev.store_addr);
                            break;
                        }
                    }
                }
            }

            for (uint8_t sr : ev.src_regs) {
                reg_consumer[sr] = ev.inst_id;
            }
        }
    }

    result.max_depth = result.events.size();

    ctx.progress(1.0f, fmt::format(
        "Backward taint (Triton): {} contributing, {} steps, "
        "{} idx-jumps, {} idx-skipped, {} regs, {} edges",
        result.contributing_inst_ids.cardinality(), steps,
        index_jumps, index_skipped,
        result.all_involved_regs.size(), result.dataflow_edges.size()));

    return PassResult::success(std::move(result));
}

// --- Heuristic backward taint (fallback) ----------------------------------

static PassResult run_heuristic_backward_taint(PassContext& ctx, const BackwardTaintConfig& config) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    BackwardTaintResult result;
    result.config = config;

    PropagationState state;
    uint8_t tag_idx = 0;
    for (uint8_t r : config.sink_regs) {
        if (should_exclude_reg(r, config)) continue;
        SinkTag tag;
        tag.kind = SinkTag::Register;
        tag.reg_id = r;
        result.sink_tags.push_back(tag);
        state.add_reg(r, {tag_idx});
        tag_idx++;
    }
    for (uint64_t addr : config.sink_mem_addrs) {
        SinkTag tag;
        tag.kind = SinkTag::Memory;
        tag.mem_addr = addr;
        result.sink_tags.push_back(tag);
        state.add_mem(addr, 8, {tag_idx});
        tag_idx++;
    }

    result.per_sink_inst_ids.resize(result.sink_tags.size());

    if (state.empty()) {
        ctx.progress(1.0f, "Backward taint: nothing to trace");
        return PassResult::success(std::move(result));
    }

    uint64_t current_id = config.sink_inst_id;
    uint64_t steps = 0;
    uint64_t total_estimated = std::min(current_id,
        config.max_steps > 0 ? config.max_steps : current_id);

    uint64_t index_jumps = 0;
    uint64_t index_skipped = 0;

    while (current_id > 0 && !state.empty()) {
        // ── REG_WRITES Index Acceleration (heuristic path) ────────────────
        if (config.use_index_acceleration && state.mem_to_sinks.empty() &&
            !state.reg_to_sinks.empty()) {
            uint64_t best_jump = 0;
            for (const auto& [reg, _] : state.reg_to_sinks) {
                uint64_t writer = index.find_last_writer_of(reg, current_id, reader);
                if (writer > best_jump) {
                    best_jump = writer;
                }
            }

            if (best_jump == 0) {
                break;  // No writer found → done
            }

            if (best_jump < current_id) {
                uint64_t skipped = current_id - best_jump - 1;
                index_skipped += skipped;
                index_jumps++;
                current_id = best_jump + 1;
            }
        }

        current_id--;
        steps++;

        if (config.max_steps > 0 && steps >= config.max_steps) break;
        if (config.max_tainted_insts > 0 &&
            result.contributing_inst_ids.cardinality() >= config.max_tainted_insts) break;
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        auto [offset, seed_pc] = index.offset_of_with_pc(current_id, reader);
        auto rec = reader.record_at(offset, seed_pc);
        if (rec.kind != RecordKind::Inst) continue;

        auto inst = rec.as_inst();

        bool contributes = false;
        BackwardTaintEvent event;
        event.inst_id = current_id;
        event.pc = inst.pc;
        std::vector<uint8_t> resolved_tags;

        // Cross-function heuristic: detect BL by checking if X30/LR is in reg_diff
        bool is_bl_site = false;
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            if (inst.reg_diff(i).index == REG_X30) {
                is_bl_site = true;
                break;
            }
        }

        // --- Multi-definition: check ALL reg_diffs vs needed set ---
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            if (should_exclude_reg(diff.index, config)) continue;
            if (is_bl_site && diff.index == REG_X30) continue;

            if (state.has_reg(diff.index)) {
                contributes = true;
                event.dst_regs.push_back(diff.index);
                if (event.dst_reg == 0) event.dst_reg = diff.index;

                const auto& tags = state.get_reg_tags(diff.index);
                for (auto t : tags) {
                    if (std::find(resolved_tags.begin(), resolved_tags.end(), t) == resolved_tags.end())
                        resolved_tags.push_back(t);
                }

                state.remove_reg(diff.index);
                result.all_involved_regs.insert(diff.index);
            }
        }

        if (contributes) {
            // Heuristic: reg_diffs NOT in dst_regs are potential sources
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                auto diff = inst.reg_diff(i);
                if (should_exclude_reg(diff.index, config)) continue;
                if (is_bl_site && diff.index == REG_X30) continue;
                bool is_dst = std::find(event.dst_regs.begin(), event.dst_regs.end(),
                                        diff.index) != event.dst_regs.end();
                if (is_dst) continue;

                event.src_regs.push_back(diff.index);
                state.add_reg(diff.index, resolved_tags);
                result.all_involved_regs.insert(diff.index);
            }

            if (config.propagate_through_memory) {
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto mem = inst.mem_access(m);
                    if ((mem.type & 2) == 0) {
                        event.loads_from_memory = true;
                        event.src_mem_addrs.push_back(mem.addr);
                        state.add_mem(mem.addr, static_cast<uint8_t>(mem.size), resolved_tags);
                        result.involved_mem_addrs.add(mem.addr);
                    }
                }
            }
        }

        // --- Check stores to needed memory ---
        if (config.propagate_through_memory && !state.mem_to_sinks.empty()) {
            for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                auto mem = inst.mem_access(m);
                if (!(mem.type & 2)) continue;

                for (auto it = state.mem_to_sinks.begin(); it != state.mem_to_sinks.end(); ) {
                    uint64_t needed_addr = it->first;
                    uint8_t needed_size = it->second.size;

                    uint64_t store_start = mem.addr;
                    uint64_t store_end = mem.addr + mem.size;
                    uint64_t need_start = needed_addr;
                    uint64_t need_end = needed_addr + needed_size;

                    if (store_start < need_end && need_start < store_end) {
                        if (!contributes) contributes = true;
                        event.stores_to_memory = true;
                        event.store_addr = mem.addr;
                        event.store_size = static_cast<uint8_t>(mem.size);

                        for (auto t : it->second.sink_tags) {
                            if (std::find(resolved_tags.begin(), resolved_tags.end(), t) == resolved_tags.end())
                                resolved_tags.push_back(t);
                        }

                        it = state.mem_to_sinks.erase(it);

                        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                            auto diff = inst.reg_diff(i);
                            if (should_exclude_reg(diff.index, config)) continue;
                            if (std::find(event.src_regs.begin(), event.src_regs.end(),
                                          diff.index) == event.src_regs.end()) {
                                event.src_regs.push_back(diff.index);
                            }
                            state.add_reg(diff.index, resolved_tags);
                            result.all_involved_regs.insert(diff.index);
                        }

                        result.involved_mem_addrs.add(mem.addr);
                        break;
                    } else {
                        ++it;
                    }
                }
            }
        }

        if (contributes) {
            event.sink_tags = resolved_tags;
            result.contributing_inst_ids.add(current_id);
            result.inst_id_to_event_[current_id] = result.events.size();

            for (auto t : resolved_tags) {
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

    // --- Build dataflow edges ---
    if (config.build_dataflow_graph && result.events.size() > 1) {
        ankerl::unordered_dense::map<uint8_t, uint64_t> reg_consumer;

        for (size_t i = 0; i < result.events.size(); i++) {
            const auto& ev = result.events[i];

            for (uint8_t dr : ev.dst_regs) {
                auto cit = reg_consumer.find(dr);
                if (cit != reg_consumer.end()) {
                    result.dataflow_edges.emplace_back(ev.inst_id, cit->second, dr, 0);
                }
            }
            if (ev.stores_to_memory) {
                for (size_t j = 0; j < i; j++) {
                    for (auto a : result.events[j].src_mem_addrs) {
                        if (a == ev.store_addr) {
                            result.dataflow_edges.emplace_back(
                                ev.inst_id, result.events[j].inst_id, 0, ev.store_addr);
                            break;
                        }
                    }
                }
            }

            for (uint8_t sr : ev.src_regs) {
                reg_consumer[sr] = ev.inst_id;
            }
        }
    }

    result.max_depth = result.events.size();

    ctx.progress(1.0f, fmt::format(
        "Backward taint (heuristic): {} contributing, {} steps, "
        "{} idx-jumps, {} idx-skipped, {} edges",
        result.contributing_inst_ids.cardinality(), steps,
        index_jumps, index_skipped, result.dataflow_edges.size()));

    return PassResult::success(std::move(result));
}

// --- BackwardTaintPass dispatch --------------------------------------------

PassResult BackwardTaintPass::run(PassContext& ctx) {
    if (config_.sink_inst_id == 0 && config_.sink_regs.empty() && config_.sink_mem_addrs.empty()) {
        return PassResult::failed("BackwardTaintPass: no sink specified");
    }

#ifdef TENET_HAS_TRITON
    {
        auto probe = create_triton_bridge();
        if (probe->is_available()) {
            return run_triton_backward_taint(ctx, config_);
        }
    }
#endif
    return run_heuristic_backward_taint(ctx, config_);
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
        if (!ev.dst_regs.empty()) {
            label += " def:";
            for (auto r : ev.dst_regs) label += fmt::format("x{},", r);
            label.pop_back();
        }
        dot += fmt::format("  n{} [label=\"{}\"];\n", ev.inst_id, label);
    }
    dot += "\n";

    for (const auto& edge : dataflow_edges) {
        std::string label;
        if (edge.via_mem_addr != 0) {
            label = fmt::format("mem:0x{:X}", edge.via_mem_addr);
        } else {
            label = fmt::format("x{}", edge.via_reg);
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
        if (!ev.dst_regs.empty()) node["dst_regs"] = ev.dst_regs;
        if (!ev.src_regs.empty()) node["src_regs"] = ev.src_regs;
        if (!ev.sink_tags.empty()) node["sink_tags"] = ev.sink_tags;
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

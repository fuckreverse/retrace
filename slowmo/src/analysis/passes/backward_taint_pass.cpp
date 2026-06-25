#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/taint_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/triton_bridge.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <cstring>
#include <algorithm>
#include <functional>
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

// ═══════════════════════════════════════════════════════════════════════════
// Instruction classification interface
// ═══════════════════════════════════════════════════════════════════════════
//
// The backward traversal loop is identical for both Triton and heuristic paths.
// The ONLY difference is how each instruction is classified:
//   - Which registers does it WRITE? (potential definitions of needed values)
//   - Which registers does it READ? (new dependencies to propagate)
//   - Is it a BL (branch-and-link) site? (exclude LR from data tracking)
//   - Does it have a memory read? (for load propagation through memory)
//   - What are the source registers for a store instruction?
//
// We encode this as a lightweight struct of callbacks, instantiated per-path.

/// Describes the register/memory classification of one instruction.
struct InstructionInfo {
    /// All registers WRITTEN by this instruction (potential definitions).
    /// For Triton: from query_semantics.reg_accesses[is_written].
    /// For heuristic: from inst.reg_diff entries.
    struct WrittenReg {
        uint8_t reg_id;
    };
    std::vector<WrittenReg> written_regs;

    /// All registers READ by this instruction (potential sources).
    /// For Triton: from query_semantics.reg_accesses[is_read].
    /// For heuristic: reg_diff entries not in the dst set (overapproximation).
    struct ReadReg {
        uint8_t reg_id;
    };
    std::vector<ReadReg> read_regs;

    /// Whether this instruction writes LR (i.e., is a BL call site).
    bool is_bl_site = false;

    /// Whether this instruction has semantic memory reads (for load detection).
    /// Triton checks sem.mem_accesses; heuristic always true (relies on mem_access records).
    bool has_memory_reads = false;

    /// Valid: set to false if instruction could not be classified (e.g., no opcode).
    bool valid = true;
};

/// Callback type: given a decoded instruction record (and its PC), produce InstructionInfo.
/// This is the strategy injection point.
using ClassifyFn = std::function<InstructionInfo(const InstView& inst)>;

// ═══════════════════════════════════════════════════════════════════════════
// Common backward traversal framework
// ═══════════════════════════════════════════════════════════════════════════

static PassResult run_backward_taint_common(
    PassContext& ctx,
    const BackwardTaintConfig& config,
    ClassifyFn classify,
    const char* method_label)
{
    auto& reader = ctx.reader();
    auto& index = ctx.index();

    BackwardTaintResult result;
    result.config = config;

    // ── Initialize per-sink tags from config ─────────────────────────────
    PropagationState state;
    uint8_t tag_idx = 0;
    {
        uint64_t remaining = config.sink_regs;
        while (remaining) {
            uint8_t r = static_cast<uint8_t>(__builtin_ctzll(remaining));
            remaining &= remaining - 1;
            if (should_exclude_reg(r, config)) continue;
            SinkTag tag;
            tag.kind = SinkTag::Register;
            tag.reg_id = r;
            result.sink_tags.push_back(tag);
            state.add_reg(r, {tag_idx});
            tag_idx++;
        }
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

    uint64_t index_jumps = 0;
    uint64_t index_skipped = 0;

    // ── Main backward traversal loop ─────────────────────────────────────
    while (current_id > 0 && !state.empty()) {
        // ── REG_WRITES Index Acceleration ─────────────────────────────────
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

        // ── Classify instruction via strategy ────────────────────────────
        auto info = classify(inst);
        if (!info.valid) continue;

        // --- Multi-definition: check ALL written registers vs needed set ---
        bool contributes = false;
        BackwardTaintEvent event;
        event.inst_id = current_id;
        event.pc = inst.pc;
        std::vector<uint8_t> resolved_tags;

        for (const auto& wr : info.written_regs) {
            if (should_exclude_reg(wr.reg_id, config)) continue;
            // Skip LR write at BL sites (it's control flow, not data)
            if (info.is_bl_site && wr.reg_id == REG_X30) continue;

            if (state.has_reg(wr.reg_id)) {
                contributes = true;
                event.dst_regs.push_back(wr.reg_id);
                if (event.dst_reg == 0) event.dst_reg = wr.reg_id;

                const auto& tags = state.get_reg_tags(wr.reg_id);
                for (auto t : tags) {
                    if (std::find(resolved_tags.begin(), resolved_tags.end(), t) == resolved_tags.end())
                        resolved_tags.push_back(t);
                }

                state.remove_reg(wr.reg_id);
                result.all_involved_regs |= (1ULL << wr.reg_id);
            }
        }

        if (contributes) {
            // Add all READ registers as new needed (source operands)
            for (const auto& sr : info.read_regs) {
                if (should_exclude_reg(sr.reg_id, config)) continue;
                if (info.is_bl_site && sr.reg_id == REG_X30) continue;
                bool is_dst = std::find(event.dst_regs.begin(), event.dst_regs.end(),
                                        sr.reg_id) != event.dst_regs.end();
                if (is_dst) continue;

                event.src_regs.push_back(sr.reg_id);
                state.add_reg(sr.reg_id, resolved_tags);
                result.all_involved_regs |= (1ULL << sr.reg_id);
            }

            // Memory read propagation
            if (config.propagate_through_memory && info.has_memory_reads) {
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto mem = inst.mem_access(m);
                    if (mem.type & 2) continue;  // Skip WRITE records; we want READs
                    event.loads_from_memory = true;
                    event.src_mem_addrs.push_back(mem.addr);
                    state.add_mem(mem.addr, static_cast<uint8_t>(mem.size), resolved_tags);
                    result.involved_mem_addrs.add(mem.addr);
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

                        // Add source registers for the store instruction
                        for (const auto& sr : info.read_regs) {
                            if (should_exclude_reg(sr.reg_id, config)) continue;
                            if (std::find(event.src_regs.begin(), event.src_regs.end(),
                                          sr.reg_id) == event.src_regs.end()) {
                                event.src_regs.push_back(sr.reg_id);
                            }
                            state.add_reg(sr.reg_id, resolved_tags);
                            result.all_involved_regs |= (1ULL << sr.reg_id);
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
    // O(E) via incremental address→reader index.
    if (config.build_dataflow_graph && result.events.size() > 1) {
        ankerl::unordered_dense::map<uint8_t, uint64_t> reg_consumer;
        ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> addr_to_readers;

        for (size_t i = 0; i < result.events.size(); i++) {
            const auto& ev = result.events[i];

            for (uint8_t dr : ev.dst_regs) {
                auto cit = reg_consumer.find(dr);
                if (cit != reg_consumer.end()) {
                    result.dataflow_edges.emplace_back(ev.inst_id, cit->second, dr, 0);
                }
            }
            if (ev.stores_to_memory) {
                auto rit = addr_to_readers.find(ev.store_addr);
                if (rit != addr_to_readers.end()) {
                    for (size_t j : rit->second) {
                        result.dataflow_edges.emplace_back(
                            ev.inst_id, result.events[j].inst_id, 0, ev.store_addr);
                    }
                }
            }

            for (uint8_t sr : ev.src_regs) {
                reg_consumer[sr] = ev.inst_id;
            }
            for (uint64_t ma : ev.src_mem_addrs) {
                addr_to_readers[ma].push_back(i);
            }
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
            return info;
        }

        uint32_t opcode_val = *opcode_opt;
        auto* opcode_bytes = reinterpret_cast<const uint8_t*>(&opcode_val);

        // query_semantics only needs opcode bytes to determine read/write register sets
        // via Triton's instruction decoder. No register context needed.
        auto sem_result = bridge_ptr->query_semantics(inst.pc, opcode_bytes, 4);
        if (!sem_result) {
            info.valid = false;
            return info;
        }

        const auto& sem = *sem_result;

        // Populate written/read registers from Triton semantics
        for (const auto& ra : sem.reg_accesses) {
            if (ra.is_written) {
                info.written_regs.push_back({ra.reg_id});
                if (ra.reg_id == REG_X30) {
                    info.is_bl_site = true;
                }
            }
            if (ra.is_read) {
                info.read_regs.push_back({ra.reg_id});
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
    // Heuristic: uses reg_diff entries to infer written registers.
    // All reg_diff entries are treated as writes; those not in the destination set
    // become potential source dependencies (overapproximation).
    auto classify = [](const InstView& inst) -> InstructionInfo {
        InstructionInfo info;

        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            info.written_regs.push_back({diff.index});
            if (diff.index == REG_X30) {
                info.is_bl_site = true;
            }
        }

        // For heuristic: read_regs are the same reg_diff set minus dst_regs.
        // This is an overapproximation: we treat all modified registers as potential
        // sources. The traversal loop filters out actual dst_regs.
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            info.read_regs.push_back({diff.index});
        }

        // Heuristic always considers memory reads possible (relies on inst.mem_access)
        info.has_memory_reads = true;

        return info;
    };

    return run_backward_taint_common(ctx, config, classify, "heuristic");
}

// --- BackwardTaintPass dispatch --------------------------------------------

PassResult BackwardTaintPass::run(PassContext& ctx) {
    if (config_.sink_inst_id == 0 && config_.sink_regs == 0 && config_.sink_mem_addrs.empty()) {
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

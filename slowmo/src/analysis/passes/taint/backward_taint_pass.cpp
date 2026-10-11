#include "common/compiler_compat.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/taint_common.h"
#include "io/trace_reader.h"
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
static constexpr uint8_t MAX_TRACKED_REGS = 64;

static bool should_exclude_reg(uint8_t reg_idx, const BackwardTaintConfig& config) {
    TaintRegFilter filter;
    filter.include_sp = config.include_sp;
    filter.include_pc = config.include_pc;
    return filter.should_exclude(reg_idx);
}

// --- Per-sink tracking state (zero-alloc, bitmask-based) ------------------
//
// reg_to_sinks:   fixed array indexed by register ID → uint64_t tag bitmask.
//                 O(1) add/remove/query, no hash map or vector allocation.
// active_regs_mask: bitmask of which reg_to_sinks entries are non-zero,
//                    enabling fast iteration via __builtin_ctzll.
// mem_to_sinks:   hash map addr → {size, tag_mask}.  Still uses a map (addresses
//                 are arbitrary 64-bit values), but tag tracking is bitmask-based.

struct PropagationState {
    uint64_t reg_to_sinks[MAX_TRACKED_REGS] = {};
    uint64_t active_regs_mask = 0;

    struct MemEntry {
        uint8_t size;
        uint64_t tag_mask;
    };
    ankerl::unordered_dense::map<uint64_t, MemEntry> mem_to_sinks;

    bool has_reg(uint8_t r) const { return (active_regs_mask >> r) & 1; }
    bool has_mem(uint64_t a) const { return mem_to_sinks.count(a) > 0; }
    bool empty() const { return active_regs_mask == 0 && mem_to_sinks.empty(); }

    void add_reg(uint8_t r, uint64_t tags_mask) {
        reg_to_sinks[r] |= tags_mask;
        active_regs_mask |= (1ULL << r);
    }

    void add_mem(uint64_t addr, uint8_t size, uint64_t tags_mask) {
        auto& entry = mem_to_sinks[addr];
        entry.size = size;
        entry.tag_mask |= tags_mask;
    }

    void remove_reg(uint8_t r) {
        reg_to_sinks[r] = 0;
        active_regs_mask &= ~(1ULL << r);
    }

    void remove_mem(uint64_t a) { mem_to_sinks.erase(a); }

    uint64_t get_reg_tags(uint8_t r) const { return reg_to_sinks[r]; }
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

    // ── Initialize per-sink tags from config ─────────────────────────────
    PropagationState state;
    uint8_t tag_idx = 0;
    {
        uint64_t remaining = config.sink_regs;
        while (remaining) {
            uint8_t r = static_cast<uint8_t>(tenet::platform::trailing_zeros(remaining));
            remaining &= remaining - 1;
            if (should_exclude_reg(r, config)) continue;
            SinkTag tag;
            tag.kind = SinkTag::Register;
            tag.reg_id = r;
            result.sink_tags.push_back(tag);
            state.add_reg(r, 1ULL << tag_idx);
            tag_idx++;
        }
    }
    for (uint64_t addr : config.sink_mem_addrs) {
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
            state.active_regs_mask != 0) {
            uint64_t best_jump = 0;
            for (uint64_t m = state.active_regs_mask; m; m &= m - 1) {
                uint8_t reg = static_cast<uint8_t>(tenet::platform::trailing_zeros(m));
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
        uint64_t resolved_tags_mask = 0;

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
                result.all_involved_regs |= (1ULL << wr_reg);
            }
        }

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
                if (should_exclude_reg(sr_reg, config)) continue;
                if (info.is_bl_site && sr_reg == kTaintRegLR) continue;

                event.add_src_reg(sr_reg);
                state.add_reg(sr_reg, resolved_tags_mask);
                result.all_involved_regs |= (1ULL << sr_reg);
            }

            // Memory read propagation
            if (config.propagate_through_memory && info.has_memory_reads) {
                for (uint8_t m = 0; m < inst.mem_access_count; m++) {
                    auto mem = inst.mem_access(m);
                    if (mem.type & 2) continue;  // Skip WRITE records; we want READs
                    event.loads_from_memory = true;
                    event.src_mem_addrs.push_back(mem.addr);
                    state.add_mem(mem.addr, static_cast<uint8_t>(mem.size), resolved_tags_mask);
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

                    if (mem_ranges_overlap(mem.addr, mem.size, needed_addr, needed_size)) {
                        if (!contributes) contributes = true;
                        event.stores_to_memory = true;
                        event.store_addr = mem.addr;
                        event.store_size = static_cast<uint8_t>(mem.size);

                        // Merge tags via OR
                        resolved_tags_mask |= it->second.tag_mask;

                        it = state.mem_to_sinks.erase(it);

                        // Add source registers for the store instruction
                        for (uint8_t i = 0; i < info.n_read; i++) {
                            uint8_t sr_reg = info.read_regs[i];
                            if (should_exclude_reg(sr_reg, config)) continue;
                            if (!event.has_src_reg(sr_reg)) {
                                event.add_src_reg(sr_reg);
                            }
                            state.add_reg(sr_reg, resolved_tags_mask);
                            result.all_involved_regs |= (1ULL << sr_reg);
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
            event.sink_tags_mask = resolved_tags_mask;
            result.contributing_inst_ids.add(current_id);
            result.inst_id_to_event_[current_id] = result.events.size();

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
    // O(E) via incremental address→reader index.
    if (config.build_dataflow_graph && result.events.size() > 1) {
        ankerl::unordered_dense::map<uint8_t, uint64_t> reg_consumer;
        ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> addr_to_readers;

        for (size_t i = 0; i < result.events.size(); i++) {
            if ((i % 1000) == 0 && ctx.cancelled()) {
                return PassResult::failed("cancelled by user");
            }
            const auto& ev = result.events[i];

            ev.for_each_dst_reg([&](uint8_t dr) {
                auto cit = reg_consumer.find(dr);
                if (cit != reg_consumer.end()) {
                    result.dataflow_edges.emplace_back(ev.inst_id, cit->second, dr, 0);
                }
            });
            if (ev.stores_to_memory) {
                auto rit = addr_to_readers.find(ev.store_addr);
                if (rit != addr_to_readers.end()) {
                    for (size_t j : rit->second) {
                        result.dataflow_edges.emplace_back(
                            ev.inst_id, result.events[j].inst_id, 0, ev.store_addr);
                    }
                }
            }

            ev.for_each_src_reg([&](uint8_t sr) {
                reg_consumer[sr] = ev.inst_id;
            });
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

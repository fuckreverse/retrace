#include "analysis/passes/dataflow_graph_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/instruction_decoder.h"

#include <fmt/core.h>
#include <algorithm>
#include <array>

namespace tenet {

// ─── Register name helper (AArch64) ───────────────────────────────────────

static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == IDX_FP)   return "fp";
    if (idx == IDX_LR)   return "lr";
    if (idx == IDX_SP)   return "sp";
    if (idx == IDX_NZCV) return "nzcv";
    if (idx == IDX_PC)   return "pc";
    return fmt::format("r{}", idx);
}

// ─── Query helpers ────────────────────────────────────────────────────────

std::vector<DFGEdge> DataflowGraphResult::producers_of(uint64_t inst_id) const {
    std::vector<DFGEdge> result;
    for (const auto& edge : edges) {
        if (edge.to_inst_id == inst_id) {
            result.push_back(edge);
        }
    }
    return result;
}

std::vector<DFGEdge> DataflowGraphResult::consumers_of(uint64_t inst_id) const {
    std::vector<DFGEdge> result;
    for (const auto& edge : edges) {
        if (edge.from_inst_id == inst_id) {
            result.push_back(edge);
        }
    }
    return result;
}

// ─── DOT export ───────────────────────────────────────────────────────────

std::string DataflowGraphResult::to_dot() const {
    std::string out;
    out += "digraph dataflow {\n";
    out += "    rankdir=TB;\n";
    out += "    node [shape=box, style=filled, fillcolor=\"#e8e8e8\", "
           "fontname=\"Courier\", fontsize=10];\n";
    out += "    edge [fontname=\"Courier\", fontsize=9];\n\n";

    // Emit nodes
    for (const auto& node : nodes) {
        auto label = fmt::format("{} @ 0x{:X}", node.mnemonic, node.pc);
        out += fmt::format("    n{} [label=\"#{}: {}\"];\n",
                           node.inst_id, node.inst_id, label);
    }

    out += "\n";

    // Emit edges
    for (const auto& edge : edges) {
        out += fmt::format("    n{} -> n{} [label=\"{}\"];\n",
                           edge.from_inst_id, edge.to_inst_id,
                           reg_name(edge.reg_index));
    }

    out += "}\n";
    return out;
}

// ─── JSON export ──────────────────────────────────────────────────────────

/// Escape a string for JSON output (handles quotes and backslashes).
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

std::string DataflowGraphResult::to_json() const {
    std::string out;
    out += "{\n";

    // Nodes
    out += "  \"nodes\": [\n";
    for (size_t i = 0; i < nodes.size(); ++i) {
        const auto& node = nodes[i];
        out += fmt::format("    {{\"inst_id\": {}, \"pc\": {}, \"mnemonic\": \"{}\", ",
                           node.inst_id, node.pc, json_escape(node.mnemonic));

        out += "\"regs_read\": [";
        for (size_t r = 0; r < node.regs_read.size(); ++r) {
            if (r > 0) out += ", ";
            out += fmt::format("\"{}\"", reg_name(node.regs_read[r]));
        }
        out += "], \"regs_written\": [";
        for (size_t r = 0; r < node.regs_written.size(); ++r) {
            if (r > 0) out += ", ";
            out += fmt::format("\"{}\"", reg_name(node.regs_written[r]));
        }
        out += "]}";
        if (i + 1 < nodes.size()) out += ",";
        out += "\n";
    }
    out += "  ],\n";

    // Edges
    out += "  \"edges\": [\n";
    for (size_t i = 0; i < edges.size(); ++i) {
        const auto& edge = edges[i];
        out += fmt::format("    {{\"from_inst_id\": {}, \"to_inst_id\": {}, \"reg\": \"{}\"}}",
                           edge.from_inst_id, edge.to_inst_id,
                           reg_name(edge.reg_index));
        if (i + 1 < edges.size()) out += ",";
        out += "\n";
    }
    out += "  ]\n";

    out += "}\n";
    return out;
}

// ─── Pass implementation ──────────────────────────────────────────────────

PassResult DataflowGraphPass::run(PassContext& ctx) {
    auto& reader     = ctx.reader();
    auto& index      = ctx.index();
    auto& code_table = ctx.code_table();
    auto& decoder    = ctx.decoder();
    const auto& range = ctx.range();

    // Determine effective analysis range by intersecting config with context range
    uint64_t start = std::max(config_.start_inst_id, range.start_inst_id);
    uint64_t end   = std::min(config_.end_inst_id, range.end_inst_id);
    end = std::min(end, index.inst_count());
    if (end == 0) end = index.inst_count();

    if (start >= end) {
        return PassResult::failed(
            fmt::format("Empty analysis range: start={} >= end={}", start, end));
    }

    DataflowGraphResult result;

    // last_writer[reg] = inst_id of the instruction that most recently wrote `reg`.
    // We use UINT64_MAX as the sentinel meaning "no writer seen yet".
    constexpr uint64_t NO_WRITER = UINT64_MAX;
    std::array<uint64_t, AARCH64_GPR_COUNT> last_writer;
    last_writer.fill(NO_WRITER);

    uint64_t inst_id = 0;
    uint64_t nodes_added = 0;
    uint64_t total = end - start;

    for (auto it = reader.begin(); it != reader.end() && inst_id < end; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;

        if (inst_id < start) {
            inst_id++;
            continue;
        }

        if (ctx.cancelled()) {
            break;
        }

        // Enforce max_nodes to keep graph sizes practical
        if (nodes_added >= config_.max_nodes) {
            break;
        }

        auto inst = rec.as_inst();
        auto opcode = code_table.opcode_at(inst.pc);
        if (!opcode) {
            inst_id++;
            continue;
        }

        auto decoded = decoder.decode(inst.pc, *opcode);
        if (!decoded) {
            inst_id++;
            continue;
        }

        // Build the node
        DataflowNode node;
        node.inst_id = inst_id;
        node.pc = inst.pc;
        node.mnemonic = std::string(decoded->mnemonic_sv());
        node.regs_read.assign(decoded->regs_read.begin(),
                              decoded->regs_read.begin() + decoded->regs_read_count);
        node.regs_written.assign(decoded->regs_written.begin(),
                                 decoded->regs_written.begin() + decoded->regs_written_count);

        size_t node_idx = result.nodes.size();
        result.inst_to_node[inst_id] = node_idx;

        // Create edges for each register read: last_writer[reg] → this inst
        for (uint8_t i = 0; i < decoded->regs_read_count; ++i) {
            uint8_t reg = decoded->regs_read[i];
            if (reg >= AARCH64_GPR_COUNT) continue;

            uint64_t writer = last_writer[reg];
            if (writer != NO_WRITER) {
                // Only create an edge if the producer is also in the graph
                if (result.inst_to_node.count(writer) > 0) {
                    DFGEdge edge;
                    edge.from_inst_id = writer;
                    edge.to_inst_id   = inst_id;
                    edge.reg_index    = reg;
                    result.edges.push_back(edge);
                }
            }
        }

        // Update last_writer for each register written
        for (uint8_t i = 0; i < decoded->regs_written_count; ++i) {
            uint8_t reg = decoded->regs_written[i];
            if (reg >= AARCH64_GPR_COUNT) continue;
            last_writer[reg] = inst_id;
        }

        result.nodes.push_back(std::move(node));
        nodes_added++;
        inst_id++;

        // Report progress periodically
        if (nodes_added % 1000 == 0) {
            float pct = (total > 0)
                ? static_cast<float>(inst_id - start) / static_cast<float>(total)
                : 1.0f;
            ctx.progress(std::min(pct, 1.0f),
                         fmt::format("Dataflow graph: {} nodes, {} edges",
                                     result.nodes.size(), result.edges.size()));
        }
    }

    ctx.progress(1.0f,
                 fmt::format("Dataflow graph: {} nodes, {} edges",
                             result.nodes.size(), result.edges.size()));

    return PassResult::success(std::move(result));
}

}  // namespace tenet

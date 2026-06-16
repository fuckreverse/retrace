#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "core/instruction_decoder.h"
#include "io/code_table.h"

#include <fmt/core.h>
#include <sstream>

namespace tenet {

// ─── DOT generation helpers ───────────────────────────────────────────────

namespace detail {

/// Escape a string for DOT label output (replace special chars).
std::string dot_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '<':  out += "\\<";  break;
            case '>':  out += "\\>";  break;
            case '{':  out += "\\{";  break;
            case '}':  out += "\\}";  break;
            case '\n': out += "\\l";  break;
            case '\r': break;
            default:   out += c;      break;
        }
    }
    return out;
}

/// Format a PC as hex string.
std::string fmt_pc(uint64_t pc) {
    return fmt::format("0x{:x}", pc);
}

/// Build a DOT node ID from a block start PC.
std::string node_id(uint64_t block_start_pc) {
    return fmt::format("n_{:x}", block_start_pc);
}

}  // namespace detail

// ─── CFGLayoutPass implementation ──────────────────────────────────────────

PassResult CFGLayoutPass::run(PassContext& ctx) {
    const auto& cfg = ctx.require<CFGResult>("cfg");

    CFGLayoutResult result;
    result.node_count_ = cfg.blocks.size();

    if (cfg.blocks.empty()) {
        result.dot = "digraph cfg {\n}\n";
        result.dot_annotated = "digraph cfg {\n}\n";
        ctx.progress(1.0f, "CFG layout: empty CFG");
        return PassResult::success(std::move(result));
    }

    // Generate both DOT variants
    result.dot = generate_dot(cfg);

    auto& decoder = ctx.decoder();
    auto& code_table = ctx.code_table();
    result.dot_annotated = generate_dot_annotated(cfg, decoder, code_table);

    ctx.progress(1.0f, fmt::format("CFG DOT: {} nodes, {} edges",
                                    cfg.blocks.size(), cfg.edges.size()));
    return PassResult::success(std::move(result));
}

// ─── generate_dot (simple) ────────────────────────────────────────────────

std::string generate_dot(const CFGResult& cfg) {
    std::ostringstream os;
    os << "digraph cfg {\n";
    os << "    rankdir=TB;\n";
    os << "    node [shape=box, fontname=\"Courier New\", fontsize=10];\n";
    os << "    edge [fontname=\"Courier New\", fontsize=9];\n\n";

    // Nodes: simple labels with start PC and instruction count
    for (const auto& [pc, block] : cfg.blocks) {
        os << "    " << detail::node_id(pc)
           << " [label=\"" << detail::fmt_pc(pc)
           << " (" << block.instructions.size() << " insns)\"];\n";
    }
    os << "\n";

    // Edges with taken_count labels
    for (const auto& edge : cfg.edges) {
        os << "    " << detail::node_id(edge.from_block)
           << " -> " << detail::node_id(edge.to_block);

        std::string attrs;
        if (edge.taken_count > 0) {
            attrs += fmt::format("label=\"{}\"", edge.taken_count);
        }

        // Call edges are dashed
        auto src_it = cfg.blocks.find(edge.from_block);
        if (src_it != cfg.blocks.end() && src_it->second.terminator == TerminatorKind::Call) {
            if (!attrs.empty()) attrs += ", ";
            attrs += "style=dashed";
        }

        // Fallthrough edges in gray
        if (edge.is_fallthrough) {
            if (!attrs.empty()) attrs += ", ";
            attrs += "color=\"#888888\"";
        }

        if (!attrs.empty()) {
            os << " [" << attrs << "]";
        }
        os << ";\n";
    }

    os << "}\n";
    return os.str();
}

// ─── generate_dot_annotated (with disassembly) ────────────────────────────

std::string generate_dot_annotated(
    const CFGResult& cfg,
    InstructionDecoder& decoder,
    const CodeTable& code_table) {

    std::ostringstream os;
    os << "digraph cfg {\n";
    os << "    rankdir=TB;\n";
    os << "    node [shape=box, fontname=\"Courier New\", fontsize=9];\n";
    os << "    edge [fontname=\"Courier New\", fontsize=8];\n\n";

    // Nodes with full disassembly labels
    for (const auto& [pc, block] : cfg.blocks) {
        std::string label;
        for (uint64_t insn_pc : block.instructions) {
            auto opcode = code_table.opcode_at(insn_pc);
            if (opcode) {
                auto d = decoder.decode(insn_pc, *opcode);
                if (d) {
                    label += fmt::format("{:x}: {} {}\\l", insn_pc, d->mnemonic, d->op_str);
                } else {
                    label += fmt::format("{:x}: .word 0x{:08x}\\l", insn_pc, *opcode);
                }
            } else {
                label += fmt::format("{:x}: <no code>\\l", insn_pc);
            }
        }

        os << "    " << detail::node_id(pc)
           << " [label=\"" << detail::dot_escape(label) << "\"];\n";
    }
    os << "\n";

    // Edges
    for (const auto& edge : cfg.edges) {
        os << "    " << detail::node_id(edge.from_block)
           << " -> " << detail::node_id(edge.to_block);

        std::string attrs;
        if (edge.taken_count > 0) {
            attrs += fmt::format("label=\"{}\"", edge.taken_count);
        }

        auto src_it = cfg.blocks.find(edge.from_block);
        if (src_it != cfg.blocks.end() && src_it->second.terminator == TerminatorKind::Call) {
            if (!attrs.empty()) attrs += ", ";
            attrs += "style=dashed";
        }

        if (edge.is_fallthrough) {
            if (!attrs.empty()) attrs += ", ";
            attrs += "color=\"#888888\"";
        }

        if (!attrs.empty()) {
            os << " [" << attrs << "]";
        }
        os << ";\n";
    }

    os << "}\n";
    return os.str();
}

}  // namespace tenet

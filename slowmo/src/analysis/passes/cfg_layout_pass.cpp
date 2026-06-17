#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "core/instruction_decoder.h"
#include "io/code_table.h"

#include <fmt/core.h>
#include <fmt/format.h>
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

// ─── Configuration thresholds ──────────────────────────────────────────────

namespace {

// Skip annotated DOT generation for CFGs larger than this (saves O(N) decode).
// The annotated DOT can still be generated on-demand later if needed.
constexpr size_t MAX_BLOCKS_FOR_ANNOTATED_DOT = 500;

// Use simplified (Narrow) layout for very large CFGs to avoid expensive
// crossing minimization iterations.
constexpr size_t LARGE_CFG_THRESHOLD = 2000;

}  // anonymous namespace

// ─── CFGLayoutPass::run ────────────────────────────────────────────────────

PassResult CFGLayoutPass::run(PassContext& ctx) {
    const auto& cfg = ctx.require<CFGResult>("cfg");

    CFGLayoutResult result;

    if (cfg.blocks.empty()) {
        result.dot          = "digraph cfg {\n}\n";
        result.dot_annotated = "digraph cfg {\n}\n";
        ctx.progress(1.0f, "CFG layout: empty CFG");
        return PassResult::success(std::move(result));
    }

    const size_t num_blocks = cfg.blocks.size();

    // ─── Step 1: build GraphGridLayout graph ────────────────────────────

    // Estimate block pixel size based on instruction count
    Graph layout_graph;
    layout_graph.reserve(num_blocks);
    for (const auto& [pc, block] : cfg.blocks) {
        GraphBlock gb;
        gb.entry  = pc;
        gb.width  = default_block_width;
        // Height: one line per instruction, plus a header line for the PC label
        gb.height = insn_height * static_cast<int>(block.instructions.size() + 1);
        gb.height = std::max(gb.height, default_block_height);
        layout_graph[pc] = gb;
    }

    // Add edges
    for (const auto& edge : cfg.edges) {
        auto it = layout_graph.find(edge.from_block);
        if (it == layout_graph.end()) continue;
        it->second.edges.emplace_back(GraphEdge(edge.to_block));
    }

    ctx.progress(0.1f, "CFG layout: graph built");

    // ─── Step 2: run layout ──────────────────────────────────────────────

    uint64_t entry = cfg.blocks.begin()->first;

    // For very large CFGs, use Narrow layout to reduce computation
    auto effective_layout_type = layout_type;
    if (num_blocks > LARGE_CFG_THRESHOLD) {
        effective_layout_type = GraphGridLayout::LayoutType::Narrow;
    }

    GraphGridLayout layout_algo(effective_layout_type);

    // For extremely large CFGs, disable the expensive optimization pass
    if (num_blocks > LARGE_CFG_THRESHOLD) {
        layout_algo.setLayoutOptimization(false);
    }

    layout_algo.calculateLayout(layout_graph, entry,
                                result.canvas_width, result.canvas_height);

    ctx.progress(0.6f, "CFG layout: positions computed");

    // ─── Step 3: copy computed coordinates into result ───────────────────

    result.block_layouts.clear();
    for (const auto& [pc, gb] : layout_graph) {
        BlockLayout bl;
        bl.x      = gb.x;
        bl.y      = gb.y;
        bl.width  = gb.width;
        bl.height = gb.height;
        result.block_layouts[pc] = bl;
    }

    // Copy routed edge polylines
    result.edge_layouts.reserve(cfg.edges.size());
    for (const auto& [pc, gb] : layout_graph) {
        for (const auto& ge : gb.edges) {
            EdgeLayout el;
            el.from_block = pc;
            el.to_block   = ge.target;
            el.polyline   = ge.polyline;
            el.arrow      = ge.arrow;
            result.edge_layouts.push_back(std::move(el));
        }
    }

    ctx.progress(0.75f, "CFG layout: coordinates extracted");

    // ─── Step 4: DOT output ───────────────────────────────────────────────

    // Simple DOT is always generated (cheap: O(V+E) with just PC labels)
    result.dot = generate_dot(cfg);

    // Annotated DOT with full disassembly — expensive for large CFGs
    // Skip for large graphs; it can be generated on-demand if needed.
    if (num_blocks <= MAX_BLOCKS_FOR_ANNOTATED_DOT) {
        auto& decoder    = ctx.decoder();
        auto& code_table = ctx.code_table();
        result.dot_annotated = generate_dot_annotated(cfg, decoder, code_table);
    } else {
        // Provide a placeholder that indicates on-demand generation is available
        result.dot_annotated = fmt::format(
            "// Annotated DOT skipped: {} blocks exceeds threshold ({}). "
            "Generate on demand via generate_dot_annotated().\n",
            num_blocks, MAX_BLOCKS_FOR_ANNOTATED_DOT);
    }

    ctx.progress(1.0f, fmt::format(
        "CFG grid layout: {} nodes, {} edges, canvas {}x{}{}",
        num_blocks, cfg.edges.size(),
        result.canvas_width, result.canvas_height,
        num_blocks > LARGE_CFG_THRESHOLD ? " (fast mode)" : ""));

    return PassResult::success(std::move(result));
}

// ─── generate_dot (simple) ────────────────────────────────────────────────

std::string generate_dot(const CFGResult& cfg) {
    // Use fmt::memory_buffer for faster string building than ostringstream
    fmt::memory_buffer buf;
    fmt::format_to(std::back_inserter(buf), "digraph cfg {{\n");
    fmt::format_to(std::back_inserter(buf), "    rankdir=TB;\n");
    fmt::format_to(std::back_inserter(buf), "    node [shape=box, fontname=\"Courier New\", fontsize=10];\n");
    fmt::format_to(std::back_inserter(buf), "    edge [fontname=\"Courier New\", fontsize=9];\n\n");

    // Nodes
    for (const auto& [pc, block] : cfg.blocks) {
        fmt::format_to(std::back_inserter(buf),
            "    n_{:x} [label=\"0x{:x} ({} insns)\"];\n",
            pc, pc, block.instructions.size());
    }
    fmt::format_to(std::back_inserter(buf), "\n");

    // Edges
    for (const auto& edge : cfg.edges) {
        fmt::format_to(std::back_inserter(buf),
            "    n_{:x} -> n_{:x}",
            edge.from_block, edge.to_block);

        bool has_attrs = false;
        auto start_attrs = [&]() {
            if (!has_attrs) {
                fmt::format_to(std::back_inserter(buf), " [");
                has_attrs = true;
            } else {
                fmt::format_to(std::back_inserter(buf), ", ");
            }
        };

        if (edge.taken_count > 0) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "label=\"{}\"", edge.taken_count);
        }

        auto src_it = cfg.blocks.find(edge.from_block);
        if (src_it != cfg.blocks.end() &&
            src_it->second.terminator == TerminatorKind::Call) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "style=dashed");
        }

        if (edge.is_fallthrough) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "color=\"#888888\"");
        }

        if (has_attrs) {
            fmt::format_to(std::back_inserter(buf), "]");
        }
        fmt::format_to(std::back_inserter(buf), ";\n");
    }

    fmt::format_to(std::back_inserter(buf), "}}\n");
    return fmt::to_string(buf);
}

// ─── generate_dot_annotated (with disassembly) ────────────────────────────

std::string generate_dot_annotated(
    const CFGResult& cfg,
    InstructionDecoder& decoder,
    const CodeTable& code_table) {

    fmt::memory_buffer buf;
    fmt::format_to(std::back_inserter(buf), "digraph cfg {{\n");
    fmt::format_to(std::back_inserter(buf), "    rankdir=TB;\n");
    fmt::format_to(std::back_inserter(buf), "    node [shape=box, fontname=\"Courier New\", fontsize=9];\n");
    fmt::format_to(std::back_inserter(buf), "    edge [fontname=\"Courier New\", fontsize=8];\n\n");

    for (const auto& [pc, block] : cfg.blocks) {
        std::string label;
        label.reserve(block.instructions.size() * 40);  // estimate avg line length

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

        fmt::format_to(std::back_inserter(buf),
            "    n_{:x} [label=\"{}\"];\n",
            pc, detail::dot_escape(label));
    }
    fmt::format_to(std::back_inserter(buf), "\n");

    for (const auto& edge : cfg.edges) {
        fmt::format_to(std::back_inserter(buf),
            "    n_{:x} -> n_{:x}",
            edge.from_block, edge.to_block);

        bool has_attrs = false;
        auto start_attrs = [&]() {
            if (!has_attrs) {
                fmt::format_to(std::back_inserter(buf), " [");
                has_attrs = true;
            } else {
                fmt::format_to(std::back_inserter(buf), ", ");
            }
        };

        if (edge.taken_count > 0) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "label=\"{}\"", edge.taken_count);
        }

        auto src_it = cfg.blocks.find(edge.from_block);
        if (src_it != cfg.blocks.end() &&
            src_it->second.terminator == TerminatorKind::Call) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "style=dashed");
        }

        if (edge.is_fallthrough) {
            start_attrs();
            fmt::format_to(std::back_inserter(buf), "color=\"#888888\"");
        }

        if (has_attrs) {
            fmt::format_to(std::back_inserter(buf), "]");
        }
        fmt::format_to(std::back_inserter(buf), ";\n");
    }

    fmt::format_to(std::back_inserter(buf), "}}\n");
    return fmt::to_string(buf);
}

}  // namespace tenet

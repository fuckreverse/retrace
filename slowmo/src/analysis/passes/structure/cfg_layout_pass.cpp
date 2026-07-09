#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "core/instruction_decoder.h"
#include "io/code_table.h"
#include "io/index_builder.h"

#include <fmt/core.h>
#include <fmt/format.h>
#include <sstream>

#include "common/byte_codec.h"

namespace tenet {

// ─── CFGLayoutResult serialization helpers ────────────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x43464C59 ("CFLY")
//   u32  version = 1
//   s32  canvas_width
//   s32  canvas_height
//   u64  num_blocks
//   for each block:
//     u64  pc
//     s32  x, y, width, height
//   u64  num_edges
//   for each edge:
//     u64  from_block
//     u64  to_block
//     u32  arrow
//     u64  num_points
//     for each point:
//       f32  x, y
//   u32  dot_len
//   u8[] dot[dot_len]
//   u32  dot_annotated_len
//   u8[] dot_annotated[dot_annotated_len]

namespace {

static constexpr uint32_t CFLY_BLOB_MAGIC   = 0x43464C59u;  // "CFLY"
static constexpr uint32_t CFLY_BLOB_VERSION = 1u;

std::string cfg_layout_serialize(const CFGLayoutResult& res) {
    ByteWriter w;

    w.u32(CFLY_BLOB_MAGIC);
    w.u32(CFLY_BLOB_VERSION);
    w.s32(res.canvas_width);
    w.s32(res.canvas_height);

    w.u64(static_cast<uint64_t>(res.block_layouts.size()));
    for (const auto& [pc, bl] : res.block_layouts) {
        w.u64(pc);
        w.s32(bl.x);
        w.s32(bl.y);
        w.s32(bl.width);
        w.s32(bl.height);
    }

    w.u64(static_cast<uint64_t>(res.edge_layouts.size()));
    for (const auto& el : res.edge_layouts) {
        w.u64(el.from_block);
        w.u64(el.to_block);
        w.u32(static_cast<uint32_t>(el.arrow));
        w.u64(static_cast<uint64_t>(el.polyline.size()));
        for (const auto& pt : el.polyline) {
            w.f32(pt.x);
            w.f32(pt.y);
        }
    }

    w.u32(static_cast<uint32_t>(res.dot.size()));
    w.bytes(res.dot.data(), res.dot.size());

    w.u32(static_cast<uint32_t>(res.dot_annotated.size()));
    w.bytes(res.dot_annotated.data(), res.dot_annotated.size());

    return std::move(w).take();
}

bool cfg_layout_deserialize(const std::string& blob, CFGLayoutResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != CFLY_BLOB_MAGIC)   return false;
    if (r.u32() != CFLY_BLOB_VERSION) return false;

    out.canvas_width  = r.s32();
    out.canvas_height = r.s32();

    uint64_t n_blocks = r.u64();
    for (uint64_t i = 0; i < n_blocks; i++) {
        uint64_t pc = r.u64();
        BlockLayout bl;
        bl.x      = r.s32();
        bl.y      = r.s32();
        bl.width  = r.s32();
        bl.height = r.s32();
        out.block_layouts[pc] = bl;
    }

    uint64_t n_edges = r.u64();
    if (!r.ok()) return false;
    out.edge_layouts.reserve(static_cast<size_t>(n_edges));
    for (uint64_t i = 0; i < n_edges; i++) {
        EdgeLayout el;
        el.from_block = r.u64();
        el.to_block   = r.u64();
        el.arrow      = static_cast<GraphEdge::ArrowDirection>(r.u32());
        uint64_t n_pts = r.u64();
        if (!r.ok()) return false;
        el.polyline.resize(static_cast<size_t>(n_pts));
        for (uint64_t j = 0; j < n_pts; j++) {
            el.polyline[j].x = r.f32();
            el.polyline[j].y = r.f32();
        }
        out.edge_layouts.push_back(std::move(el));
    }

    uint32_t dot_len = r.u32();
    if (!r.ok() || r.remaining() < dot_len) return false;
    out.dot.resize(dot_len);
    r.bytes(out.dot.data(), dot_len);

    uint32_t dot_ann_len = r.u32();
    if (!r.ok() || r.remaining() < dot_ann_len) return false;
    out.dot_annotated.resize(dot_ann_len);
    r.bytes(out.dot_annotated.data(), dot_ann_len);

    return r.ok();
}

}  // anonymous namespace

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
    auto& index = ctx.index();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("cfg_layout", blob)) {
            CFGLayoutResult cached;
            if (cfg_layout_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "CFG layout: {} blocks, {}×{} canvas (from cache)",
                    cached.block_layouts.size(), cached.canvas_width, cached.canvas_height));
                return PassResult::success(std::move(cached));
            }
        }
    }

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
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
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
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
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
    layout_algo.setCancelCheck([&]() { return ctx.cancelled(); });

    // For extremely large CFGs, disable the expensive optimization pass
    if (num_blocks > LARGE_CFG_THRESHOLD) {
        layout_algo.setLayoutOptimization(false);
    }

    layout_algo.calculateLayout(layout_graph, entry,
                                result.canvas_width, result.canvas_height);
    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    ctx.progress(0.6f, "CFG layout: positions computed");

    // ─── Step 3: copy computed coordinates into result ───────────────────

    result.block_layouts.clear();
    for (const auto& [pc, gb] : layout_graph) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
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
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
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
    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    // Annotated DOT with full disassembly — expensive for large CFGs
    // Skip for large graphs; it can be generated on-demand if needed.
    if (num_blocks <= MAX_BLOCKS_FOR_ANNOTATED_DOT) {
        auto& decoder    = ctx.decoder();
        auto& code_table = ctx.code_table();
        result.dot_annotated = generate_dot_annotated(cfg, decoder, code_table);
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }
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

    // ─── Persist to cache ─────────────────────────────────────────────────
    if (ctx.range().is_full_trace()) {
        std::string blob = cfg_layout_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("cfg_layout", blob.data(), blob.size());
        }
    }

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
